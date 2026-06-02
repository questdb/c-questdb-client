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
        let mut iter = self.iter_polars()?;
        let mut acc: Option<DataFrame> = None;
        for item in iter.by_ref() {
            let df = item?;
            acc = Some(match acc {
                None => df,
                Some(mut prev) => {
                    // Tentative→firm schema upgrade: the prior batch was a
                    // placeholder (e.g. empty ndim=1 array column) and this
                    // batch supplied the firm dtype. vstack would reject the
                    // mismatched dtypes; replace the placeholder accumulator
                    // outright.
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
        Ok(Self {
            cursor,
            schema,
            pending: Some(first),
            poisoned: false,
        })
    }

    /// First batch's schema. Upgrades on tentative→firm ndim
    /// (see [`has_tentative_array`]).
    pub fn schema(&self) -> SchemaRef {
        self.schema.clone()
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
            match self.cursor.next_arrow_batch_inner(Some(&self.schema)) {
                Ok(Some(rb)) => {
                    if has_tentative_array(&self.schema) {
                        self.schema = rb.schema();
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
}
