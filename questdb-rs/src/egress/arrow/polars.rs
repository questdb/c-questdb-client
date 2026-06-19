//! Polars sub-feature: `RecordBatch ↔ DataFrame` via Arrow C Data Interface.

use arrow_array::{Array, RecordBatch};
use arrow_schema::SchemaRef;
use polars::frame::DataFrame;
use polars::prelude::{Column, IntoColumn, PlSmallStr, Series};

use crate::egress::Cursor;
use crate::egress::arrow::has_tentative_array;
use crate::egress::error::{Error, ErrorCode, Result, fmt};

// FFI cross-crate helpers in `crate::ingress::polars`.

impl Cursor<'_> {
    /// Decode one batch as a Polars [`DataFrame`]. `Ok(None)` on
    /// stream end.
    ///
    /// This is the low-level per-batch entry point and does **not**
    /// detect mid-stream Arrow schema drift; if a later batch's
    /// schema differs from earlier ones the resulting DataFrames will
    /// simply disagree on columns. Use
    /// [`Cursor::iter_polars`](crate::egress::Cursor::iter_polars)
    /// for a drift-checked iterator, or
    /// [`Cursor::fetch_all_polars`] / [`Cursor::as_arrow_reader`]
    /// for higher-level adapters that pin the schema on first batch.
    pub fn next_polars(&mut self) -> Result<Option<DataFrame>> {
        match self.next_arrow_batch_inner(None)? {
            None => Ok(None),
            Some(rb) => Ok(Some(record_batch_to_dataframe(rb)?)),
        }
    }

    /// Eagerly drain into one chunked Polars [`DataFrame`]. A stream
    /// that yields a schema but no batches becomes an empty DataFrame;
    /// only a stream without a schema (e.g. cancelled pre-prelude)
    /// errors as `NoSchema`. Drift detection is inherited from
    /// [`Cursor::iter_polars`].
    pub fn fetch_all_polars(&mut self) -> Result<DataFrame> {
        // Materialise-whole: the full result is built internally before
        // anything is handed back, so a mid-query failover replays the
        // query from `batch_seq 0` transparently. Opt into replay and
        // drop the partial accumulation when the cursor reports a reset.
        self.enable_internal_replay();
        let mut iter = self.iter_polars()?;
        let mut resets_seen = iter.failover_resets();
        let mut acc: Option<DataFrame> = None;
        loop {
            // Manual drive (not `for`/`by_ref`) so the reset counter can be
            // polled between batches without holding an iterator borrow.
            let Some(item) = iter.next() else { break };
            let df = item?;
            let resets_now = iter.failover_resets();
            if resets_now != resets_seen {
                resets_seen = resets_now;
                acc = None;
            }
            acc = Some(match acc {
                None => df,
                Some(mut prev) => {
                    if prev.height() == 0 && prev.schema() != df.schema() {
                        df
                    } else {
                        prev.vstack_mut_owned(df)
                            .map_err(|e| fmt!(ArrowExport, "polars vstack failed: {}", e))?;
                        prev
                    }
                }
            });
        }
        let schema = iter.schema();
        match acc {
            Some(df) => Ok(df),
            None => record_batch_to_dataframe(RecordBatch::new_empty(schema)),
        }
    }
}

/// Drift-checked iterator yielding Polars [`DataFrame`]s, one per
/// QWP batch. Built by [`Cursor::iter_polars`]. Snapshots the first
/// batch's Arrow schema at construction and poisons (terminates) on
/// mid-stream schema drift.
pub struct CursorPolarsIter<'r, 'c> {
    cursor: &'c mut Cursor<'r>,
    schema: SchemaRef,
    pending: Option<RecordBatch>,
    poisoned: bool,
    /// `Cursor::failover_resets()` at the point `schema` was pinned. A
    /// later batch arriving with a higher count is the first frame of a
    /// transparently-replayed query (re-read from `batch_seq 0` on a new
    /// endpoint), so the pinned schema is re-snapshotted from it rather
    /// than treated as drift. `fetch_all_polars` reads the same counter to
    /// discard its partial `vstack` accumulation.
    resets_at_pin: u32,
}

impl<'r, 'c> CursorPolarsIter<'r, 'c> {
    pub(crate) fn new(cursor: &'c mut Cursor<'r>) -> Result<Self> {
        let first = cursor.next_arrow_batch_inner(None)?.ok_or_else(|| {
            Error::new(
                ErrorCode::NoSchema,
                "no batch produced; nothing to snapshot",
            )
        })?;
        let schema = first.schema();
        let resets_at_pin = cursor.failover_resets();
        Ok(Self {
            cursor,
            schema,
            pending: Some(first),
            poisoned: false,
            resets_at_pin,
        })
    }

    /// First batch's schema. Upgrades on tentative→firm ndim
    /// (see [`has_tentative_array`]).
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
    }

    /// Reconnect count observed by the underlying cursor. `fetch_all_polars`
    /// polls this between batches: an increase means the query was replayed
    /// from scratch, so anything accumulated so far must be dropped.
    pub(crate) fn failover_resets(&self) -> u32 {
        self.cursor.failover_resets()
    }
}

impl Iterator for CursorPolarsIter<'_, '_> {
    type Item = Result<DataFrame>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }
        let rb = if let Some(rb) = self.pending.take() {
            rb
        } else {
            // A transparent mid-query failover re-reads the result from
            // `batch_seq 0` on a new endpoint, so the pinned schema is
            // re-snapshotted from the first replayed batch instead of
            // being compared against it. Pass `None` (no drift check)
            // for that frame so the new node's batch 0 isn't rejected.
            let drift_check = if self.cursor.failover_resets() == self.resets_at_pin {
                Some(&self.schema)
            } else {
                None
            };
            match self.cursor.next_arrow_batch_inner(drift_check) {
                Ok(Some(rb)) => {
                    if self.cursor.failover_resets() != self.resets_at_pin {
                        self.schema = rb.schema();
                        self.resets_at_pin = self.cursor.failover_resets();
                    } else if has_tentative_array(&self.schema) && rb.schema() != self.schema {
                        self.poisoned = true;
                        return Some(Err(Error::new(
                            ErrorCode::SchemaDrift,
                            "tentative→firm ndim upgrade mid-stream; the \
                             iterator pins the first batch's schema. Use \
                             Cursor::next_polars to handle drift explicitly",
                        )));
                    }
                    rb
                }
                Ok(None) => {
                    self.poisoned = true;
                    return None;
                }
                Err(e) => {
                    self.poisoned = true;
                    return Some(Err(e));
                }
            }
        };
        let df = record_batch_to_dataframe(rb);
        if df.is_err() {
            self.poisoned = true;
        }
        Some(df)
    }
}

/// [`RecordBatch`] → Polars [`DataFrame`] via Arrow C Data Interface.
/// Zero-copy for primitive/string/binary. [`ErrorCode::ArrowExport`] on
/// handoff failure.
pub fn record_batch_to_dataframe(rb: RecordBatch) -> Result<DataFrame> {
    let schema = rb.schema();
    let row_count = rb.num_rows();
    let mut columns: Vec<Column> = Vec::with_capacity(rb.num_columns());
    for (col, field) in rb.columns().iter().zip(schema.fields().iter()) {
        let array_data = col.to_data();
        let (rs_array, rs_schema) = arrow::ffi::to_ffi(&array_data).map_err(|e| {
            fmt!(
                ArrowExport,
                "to_ffi failed for column '{}': {}",
                field.name(),
                e
            )
        })?;
        let pa_schema = unsafe { crate::ingress::polars::rs_schema_into_pa(rs_schema) };
        let pa_array = unsafe { crate::ingress::polars::rs_array_into_pa(rs_array) };
        let pa_field =
            unsafe { polars_arrow::ffi::import_field_from_c(&pa_schema) }.map_err(|e| {
                fmt!(
                    ArrowExport,
                    "import_field_from_c('{}'): {}",
                    field.name(),
                    e
                )
            })?;
        let pa_array_box =
            unsafe { polars_arrow::ffi::import_array_from_c(pa_array, pa_field.dtype) }.map_err(
                |e| {
                    fmt!(
                        ArrowExport,
                        "import_array_from_c('{}'): {}",
                        field.name(),
                        e
                    )
                },
            )?;
        let name: PlSmallStr = field.name().as_str().into();
        let series = Series::from_arrow(name, pa_array_box)
            .map_err(|e| fmt!(ArrowExport, "Series::from_arrow('{}'): {}", field.name(), e))?;
        columns.push(series.into_column());
    }
    DataFrame::new(row_count, columns)
        .map_err(|e| fmt!(ArrowExport, "DataFrame::new failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use arrow_array::builder::{Float64Builder, Int64Builder, StringBuilder};
    use arrow_array::{ArrayRef, RecordBatch};
    use arrow_schema::{DataType, Field, Schema as ArrowSchema};

    fn rb_mixed() -> RecordBatch {
        let mut ii = Int64Builder::new();
        ii.append_value(1);
        ii.append_value(2);
        ii.append_value(3);
        let mut ff = Float64Builder::new();
        ff.append_value(1.5);
        ff.append_value(2.5);
        ff.append_value(3.5);
        let mut ss = StringBuilder::new();
        ss.append_value("a");
        ss.append_value("b");
        ss.append_value("c");
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("i", DataType::Int64, false),
            Field::new("f", DataType::Float64, false),
            Field::new("s", DataType::Utf8, false),
        ]));
        RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ii.finish()) as ArrayRef,
                Arc::new(ff.finish()) as ArrayRef,
                Arc::new(ss.finish()) as ArrayRef,
            ],
        )
        .unwrap()
    }

    #[test]
    fn record_batch_to_dataframe_preserves_column_count_and_height() {
        let rb = rb_mixed();
        let df = record_batch_to_dataframe(rb).unwrap();
        assert_eq!(df.width(), 3);
        assert_eq!(df.height(), 3);
        let cols = df.columns();
        assert_eq!(cols[0].name().as_str(), "i");
        assert_eq!(cols[1].name().as_str(), "f");
        assert_eq!(cols[2].name().as_str(), "s");
    }

    #[test]
    fn record_batch_to_dataframe_preserves_int_values() {
        let rb = rb_mixed();
        let df = record_batch_to_dataframe(rb).unwrap();
        let col = &df.columns()[0];
        let series = col.as_materialized_series();
        let i64s = series.i64().unwrap();
        assert_eq!(i64s.get(0), Some(1));
        assert_eq!(i64s.get(1), Some(2));
        assert_eq!(i64s.get(2), Some(3));
    }

    #[test]
    fn record_batch_to_dataframe_preserves_string_values() {
        let rb = rb_mixed();
        let df = record_batch_to_dataframe(rb).unwrap();
        let col = &df.columns()[2];
        let series = col.as_materialized_series();
        let s = series.str().unwrap();
        assert_eq!(s.get(0), Some("a"));
        assert_eq!(s.get(1), Some("b"));
        assert_eq!(s.get(2), Some("c"));
    }

    #[test]
    fn record_batch_to_dataframe_zero_rows_succeeds() {
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "v",
            DataType::Int64,
            false,
        )]));
        let mut ii = Int64Builder::new();
        let arr: ArrayRef = Arc::new(ii.finish());
        let rb = RecordBatch::try_new(schema, vec![arr]).unwrap();
        let df = record_batch_to_dataframe(rb).unwrap();
        assert_eq!(df.height(), 0);
        assert_eq!(df.width(), 1);
    }

    /// Every QuestDB table carries a designated TIMESTAMP, which the
    /// egress decoder maps to the tz-aware Arrow `Timestamp(Microsecond,
    /// Some("UTC"))`. Materialising that into a polars `DataFrame`
    /// requires the `dtype-datetime` + `timezones` polars features; this
    /// test guards that feature set (without them `Series::from_arrow`
    /// fails at runtime, which `fetch_all_polars` on any real result set
    /// would hit). See the `polars` feature in `Cargo.toml`.
    #[test]
    fn record_batch_to_dataframe_preserves_tz_timestamp() {
        use arrow_array::TimestampMicrosecondArray;
        let ts: ArrayRef = Arc::new(
            TimestampMicrosecondArray::from(vec![1_700_000_000_000_000i64, 1_700_000_000_000_001])
                .with_timezone("UTC"),
        );
        let schema = Arc::new(ArrowSchema::new(vec![Field::new(
            "ts",
            ts.data_type().clone(),
            false,
        )]));
        let rb = RecordBatch::try_new(schema, vec![ts]).unwrap();
        let df = record_batch_to_dataframe(rb).unwrap();
        assert_eq!(df.height(), 2);
        assert_eq!(df.width(), 1);
        // The column must round-trip as a polars Datetime, not error out.
        let series = df.columns()[0].as_materialized_series();
        assert!(
            matches!(series.dtype(), polars::prelude::DataType::Datetime(_, _)),
            "expected polars Datetime, got {:?}",
            series.dtype()
        );
    }
}
