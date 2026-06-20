//! Polars sub-feature: convert a [`DataFrame`] into Arrow
//! [`RecordBatch`]es for consumption by
//! [`ColumnSender::flush_arrow_batch`][crate::ingress::column_sender::ColumnSender::flush_arrow_batch].
//!
//! [`dataframe_to_batches`] is the primary entry point. It returns an
//! iterator that yields slices of at most `max_rows` rows each. Each
//! emitted slice is taken from a single polars chunk per column. The
//! conversion cost depends on the dtype:
//!
//! * **Primitive, String, Binary, Decimal at the newest compat level**:
//!   the per-chunk Arrow C Data Interface handoff is a pure refcount
//!   bump and the per-batch slice is zero-copy.
//! * **`Column::Scalar` columns**: materialised once by polars (cached
//!   in the column's `OnceLock`); subsequent batches slice that cache
//!   zero-copy. Sending a scalar as columnar data requires the value to
//!   exist in memory N times — there is no zero-copy alternative.
//! * **Polars *logical* dtypes that arrow-rs lacks natively** (Datetime,
//!   Date, Time, Duration, Categorical, Enum): incur a `cast_default`
//!   per chunk per emitted batch. The converted Arrow chunk is cached
//!   only for the lifetime of the current chunk within the iterator
//!   (not across `dataframe_to_batches` calls or across chunk
//!   boundaries within one call), so a multi-chunk DataFrame with
//!   timestamp/categorical columns re-pays the cast each time the
//!   iterator crosses a chunk boundary. Acceptable for typical batch
//!   sizes (10 K rows ≈ µs of cast vs ms of wire send) but worth
//!   knowing if you slice into many small batches.
//!
//! # Per-chunk dtype stability
//!
//! `Categorical` (and other dictionary-backed) columns may emit
//! different Arrow value dtypes across chunks (e.g. `Utf8` vs
//! `LargeUtf8`) depending on per-chunk statistics. The iterator pins
//! the first chunk's dtype as the wire schema and rejects subsequent
//! chunks whose dtype differs with [`ErrorCode::ArrowIngest`]. To
//! avoid this, rechunk via `DataFrame::rechunk()` before calling
//! `dataframe_to_batches`, or cast Categorical columns to plain
//! `String` upstream.
//!
//! [`ErrorCode::ArrowIngest`]: crate::ErrorCode::ArrowIngest
//!
//! The one-call shortcut is [`BorrowedColumnSender::flush_polars_dataframe`].
//! For full control over slicing and per-batch retry, drive the
//! iterator directly:
//!
//! ```ignore
//! for rb in questdb::ingress::polars::dataframe_to_batches(&df, None) {
//!     sender.flush_arrow_batch(table, &rb?, &[])?;
//! }
//! ```
//!
//! [`BorrowedColumnSender::flush_polars_dataframe`]: crate::ingress::column_sender::BorrowedColumnSender::flush_polars_dataframe

use std::num::NonZeroUsize;
use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{Field, Schema as ArrowSchema};
use polars::frame::DataFrame;
use polars::prelude::{Column, CompatLevel, Series};

use crate::{Result, fmt};

/// Suggested default chunk size for [`dataframe_to_batches`].
pub const DEFAULT_MAX_BATCH_ROWS: usize = 10_000;

const _: () = assert!(
    std::mem::size_of::<polars_arrow::ffi::ArrowArray>()
        == std::mem::size_of::<arrow::ffi::FFI_ArrowArray>(),
);
const _: () = assert!(
    std::mem::size_of::<polars_arrow::ffi::ArrowSchema>()
        == std::mem::size_of::<arrow::ffi::FFI_ArrowSchema>(),
);
const _: () = assert!(
    std::mem::align_of::<polars_arrow::ffi::ArrowArray>()
        == std::mem::align_of::<arrow::ffi::FFI_ArrowArray>(),
);
const _: () = assert!(
    std::mem::align_of::<polars_arrow::ffi::ArrowSchema>()
        == std::mem::align_of::<arrow::ffi::FFI_ArrowSchema>(),
);

// polars-arrow keeps its `ArrowArray`/`ArrowSchema` fields private, so a
// field-level copy is impossible. We rely on the Arrow C Data Interface
// spec to fix the `#[repr(C)]` field order across crates; `transmute`
// is sound as long as both crates implement the same spec. The
// `polars_ffi_layout_round_trip` test fires a real data roundtrip on
// every CI run to catch a spec violation in either crate before
// production.

#[inline]
unsafe fn pa_array_into_rs(pa: polars_arrow::ffi::ArrowArray) -> arrow::ffi::FFI_ArrowArray {
    unsafe { std::mem::transmute::<polars_arrow::ffi::ArrowArray, arrow::ffi::FFI_ArrowArray>(pa) }
}

#[inline]
unsafe fn pa_schema_into_rs(pa: polars_arrow::ffi::ArrowSchema) -> arrow::ffi::FFI_ArrowSchema {
    unsafe {
        std::mem::transmute::<polars_arrow::ffi::ArrowSchema, arrow::ffi::FFI_ArrowSchema>(pa)
    }
}

#[inline]
pub(crate) unsafe fn rs_array_into_pa(
    rs: arrow::ffi::FFI_ArrowArray,
) -> polars_arrow::ffi::ArrowArray {
    unsafe { std::mem::transmute::<arrow::ffi::FFI_ArrowArray, polars_arrow::ffi::ArrowArray>(rs) }
}

#[inline]
pub(crate) unsafe fn rs_schema_into_pa(
    rs: arrow::ffi::FFI_ArrowSchema,
) -> polars_arrow::ffi::ArrowSchema {
    unsafe {
        std::mem::transmute::<arrow::ffi::FFI_ArrowSchema, polars_arrow::ffi::ArrowSchema>(rs)
    }
}

/// Yield [`RecordBatch`] slices of `df`, each capped at `max_rows`
/// rows. `None` uses [`DEFAULT_MAX_BATCH_ROWS`]. Every emitted slice
/// is taken from a single polars chunk per column, so row data is
/// shared via the Arrow C Data Interface and never copied. Conversion
/// errors surface through the iterator's `Item` rather than the
/// constructor.
pub fn dataframe_to_batches(
    df: &DataFrame,
    max_rows: Option<NonZeroUsize>,
) -> DataFrameBatches<'_> {
    let max_rows = max_rows.map_or(DEFAULT_MAX_BATCH_ROWS, NonZeroUsize::get);
    let compat = CompatLevel::newest();
    let cursors: Vec<ColumnCursor<'_>> = df
        .columns()
        .iter()
        .map(|c| ColumnCursor::new(c, compat))
        .collect();
    DataFrameBatches {
        max_rows,
        compat,
        total_rows: df.height(),
        rows_emitted: 0,
        cursors,
        schema: None,
        poisoned: false,
    }
}

/// Iterator returned by [`dataframe_to_batches`]. One-shot error
/// contract: a `Some(Err(_))` poisons the iterator; subsequent
/// `next()` returns `None`.
pub struct DataFrameBatches<'a> {
    max_rows: usize,
    compat: CompatLevel,
    total_rows: usize,
    rows_emitted: usize,
    cursors: Vec<ColumnCursor<'a>>,
    schema: Option<Arc<ArrowSchema>>,
    poisoned: bool,
}

struct ColumnCursor<'a> {
    name: String,
    series: &'a Series,
    pa_field: polars_arrow::datatypes::Field,
    chunk_lengths: Vec<usize>,
    chunk_idx: usize,
    offset_in_chunk: usize,
    current: Option<Box<dyn polars_arrow::array::Array>>,
}

impl<'a> ColumnCursor<'a> {
    fn new(column: &'a Column, compat: CompatLevel) -> Self {
        let series = column.as_materialized_series();
        let pa_field = polars_arrow::datatypes::Field::new(
            series.name().clone(),
            series.dtype().to_arrow(compat),
            true,
        );
        Self {
            name: column.name().as_str().to_string(),
            series,
            pa_field,
            chunk_lengths: series.chunk_lengths().collect(),
            chunk_idx: 0,
            offset_in_chunk: 0,
            current: None,
        }
    }

    fn skip_empty_chunks(&mut self) {
        while self.chunk_idx < self.chunk_lengths.len() && self.chunk_lengths[self.chunk_idx] == 0 {
            self.chunk_idx += 1;
            self.offset_in_chunk = 0;
            self.current = None;
        }
    }

    fn remaining_in_chunk(&self) -> usize {
        if self.chunk_idx >= self.chunk_lengths.len() {
            return 0;
        }
        self.chunk_lengths[self.chunk_idx] - self.offset_in_chunk
    }

    fn current_chunk(&mut self, compat: CompatLevel) -> &dyn polars_arrow::array::Array {
        let chunk_idx = self.chunk_idx;
        let series = self.series;
        let boxed = self
            .current
            .get_or_insert_with(|| series.to_arrow(chunk_idx, compat));
        &**boxed
    }

    fn advance(&mut self, n: usize) {
        self.offset_in_chunk += n;
        if self.offset_in_chunk >= self.chunk_lengths[self.chunk_idx] {
            self.chunk_idx += 1;
            self.offset_in_chunk = 0;
            self.current = None;
        }
    }
}

impl Iterator for DataFrameBatches<'_> {
    type Item = Result<RecordBatch>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned || self.cursors.is_empty() || self.rows_emitted >= self.total_rows {
            return None;
        }
        for cursor in &mut self.cursors {
            cursor.skip_empty_chunks();
        }
        let mut seg_len = self.max_rows;
        for cursor in &self.cursors {
            seg_len = seg_len.min(cursor.remaining_in_chunk());
        }
        if seg_len == 0 {
            if self.rows_emitted < self.total_rows {
                self.poisoned = true;
                return Some(Err(fmt!(
                    ArrowIngest,
                    "internal: column chunk lengths disagree ({} of {} rows emitted)",
                    self.rows_emitted,
                    self.total_rows
                )));
            }
            return None;
        }
        let compat = self.compat;
        let need_schema = self.schema.is_none();
        let mut fields: Vec<Field> = if need_schema {
            Vec::with_capacity(self.cursors.len())
        } else {
            Vec::new()
        };
        let mut arrays: Vec<ArrayRef> = Vec::with_capacity(self.cursors.len());
        for cursor in &mut self.cursors {
            let offset = cursor.offset_in_chunk;
            let chunk = cursor.current_chunk(compat);
            let chunk_dtype = chunk.dtype().clone();
            let sliced = chunk.sliced(offset, seg_len);
            if chunk_dtype != cursor.pa_field.dtype {
                self.poisoned = true;
                return Some(Err(fmt!(
                    ArrowIngest,
                    "column '{}': per-chunk Arrow dtype {:?} differs from the pinned schema \
                     dtype {:?}; call DataFrame::rechunk() or cast the column to a stable \
                     dtype before ingest",
                    cursor.name,
                    chunk_dtype,
                    cursor.pa_field.dtype
                )));
            }
            let array_data = match ffi_polars_to_arrow_rs(&cursor.pa_field, sliced, &cursor.name) {
                Ok(d) => d,
                Err(e) => {
                    self.poisoned = true;
                    return Some(Err(e));
                }
            };
            if need_schema {
                fields.push(Field::new(
                    cursor.name.clone(),
                    array_data.data_type().clone(),
                    true,
                ));
            }
            arrays.push(arrow_array::make_array(array_data));
        }
        let schema = match &self.schema {
            Some(s) => s.clone(),
            None => {
                let s = Arc::new(ArrowSchema::new(fields));
                self.schema = Some(s.clone());
                s
            }
        };
        let rb = match RecordBatch::try_new(schema, arrays) {
            Ok(rb) => rb,
            Err(e) => {
                self.poisoned = true;
                return Some(Err(fmt!(ArrowIngest, "RecordBatch::try_new failed: {}", e)));
            }
        };
        for cursor in &mut self.cursors {
            cursor.advance(seg_len);
        }
        self.rows_emitted += seg_len;
        Some(Ok(rb))
    }
}

/// Number of batches flushed between `sync` checkpoints. The QWP in-flight
/// cap is 127 deferred frames (128 − 1 reserved for the commit frame); 64
/// stays under it, keeps the pipeline full, and bounds a failover re-drive to
/// ≈64 × `max_rows` rows.
const CHECKPOINT_BATCHES: usize = 64;

/// Optional knobs for [`BorrowedColumnSender::flush_polars_dataframe`].
///
/// Every field defaults to "off", so `PolarsIngestOptions::default()` (or
/// [`PolarsIngestOptions::new`]) reproduces the original three-argument
/// behaviour: [`DEFAULT_MAX_BATCH_ROWS`]-row batches, server-assigned
/// timestamps, and wire types derived from the Arrow schema alone.
///
/// Build with the chainable setters:
///
/// ```ignore
/// let opts = questdb::ingress::polars::PolarsIngestOptions::new()
///     .max_rows(50_000)
///     .timestamp_column(ColumnName::new("ts")?)
///     .overrides(&overrides);
/// sender.flush_polars_dataframe("trades", &df, &opts)?;
/// ```
///
/// [`BorrowedColumnSender::flush_polars_dataframe`]: crate::ingress::column_sender::BorrowedColumnSender::flush_polars_dataframe
#[derive(Clone, Copy, Default)]
pub struct PolarsIngestOptions<'a> {
    max_rows: Option<NonZeroUsize>,
    timestamp_column: Option<crate::ingress::ColumnName<'a>>,
    overrides: &'a [crate::ingress::column_sender::ArrowColumnOverride<'a>],
}

impl<'a> PolarsIngestOptions<'a> {
    /// A fresh option set with every knob defaulted to "off".
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Cap each emitted [`RecordBatch`] at `rows` rows. `0` (or never calling
    /// this) uses [`DEFAULT_MAX_BATCH_ROWS`]. Taking a plain `usize` keeps the
    /// call site free of `NonZeroUsize` ceremony.
    #[must_use]
    pub fn max_rows(mut self, rows: usize) -> Self {
        self.max_rows = NonZeroUsize::new(rows);
        self
    }

    /// Source the per-row designated timestamp from `column` (a `Timestamp(_)`
    /// column of the frame) instead of letting the server stamp each row on
    /// arrival. Mirrors `ColumnSender::flush_arrow_batch_at_column`.
    #[must_use]
    pub fn timestamp_column(mut self, column: crate::ingress::ColumnName<'a>) -> Self {
        self.timestamp_column = Some(column);
        self
    }

    /// Per-column wire-type hints, applied to every batch sliced out of the
    /// frame. Same meaning as the `overrides` argument of
    /// `ColumnSender::flush_arrow_batch` — the intended path for Polars frames
    /// built without pyarrow, whose Arrow schema carries no `questdb.*` field
    /// metadata.
    #[must_use]
    pub fn overrides(
        mut self,
        overrides: &'a [crate::ingress::column_sender::ArrowColumnOverride<'a>],
    ) -> Self {
        self.overrides = overrides;
        self
    }
}

impl crate::ingress::column_sender::BorrowedColumnSender<'_> {
    /// Slice `df` into [`RecordBatch`]es of at most `options.max_rows` rows
    /// each (defaults to [`DEFAULT_MAX_BATCH_ROWS`]), publish every slice, and
    /// `sync` to commit — re-driving transparently across a connection failure.
    ///
    /// `table` accepts anything convertible into a [`TableName`], so a bare
    /// `&str` works directly. `options` ([`PolarsIngestOptions`]) carries an
    /// optional designated-timestamp column and per-column wire-type
    /// `overrides`, both applied to every sliced batch;
    /// `PolarsIngestOptions::default()` preserves the previous behaviour
    /// (server-assigned timestamps, schema-derived wire types).
    ///
    /// Unlike `ColumnSender::flush` / `ColumnSender::flush_arrow_batch`, which
    /// leave rows uncommitted until you call `ColumnSender::sync`, this entry
    /// owns the commit (and the failover replay boundary).
    ///
    /// [`TableName`]: crate::ingress::TableName
    ///
    /// The batch loop `sync`s every [`CHECKPOINT_BATCHES`] batches; on a
    /// transient ([`ErrorCode::FailoverRetry`]) `flush`/`sync` error it
    /// re-borrows a live connection from the pool behind the same handle
    /// (rotating to a live endpoint) and re-iterates `&DataFrame` from the last
    /// committed checkpoint. The entry owns the `sync` (the replay boundary) and
    /// returns only once the whole `df` is committed.
    ///
    /// Reconnect matches the row API: the [`ReconnectPolicy`] parsed from the
    /// `reconnect_*` keys (default 300s budget), centered-jittered exponential
    /// backoff that resets on a role reject, and `AuthError` /
    /// `ProtocolVersionError` treated as terminal.
    ///
    /// Delivery is **at-least-once**: a re-driven tail can re-send frames
    /// committed but unobserved before the failure, producing **duplicate rows**
    /// unless the destination table has `DEDUP UPSERT KEYS` covering them
    /// (QuestDB keeps duplicates by default). The reconnect budget exhausting
    /// surfaces the terminal error.
    ///
    /// [`ErrorCode::FailoverRetry`]: crate::ErrorCode::FailoverRetry
    /// [`ReconnectPolicy`]: crate::ingress::ReconnectPolicy
    pub fn flush_polars_dataframe<'t, T>(
        &mut self,
        table: T,
        df: &DataFrame,
        options: &PolarsIngestOptions<'_>,
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: crate::ingress::TableName<'t> = table.try_into()?;
        let started = std::time::Instant::now();
        let deadline = started.checked_add(self.reconnect_policy().max_duration());
        // Batches confirmed by the last successful `sync`; a transient failure
        // re-drives only the tail past this.
        let mut committed = 0usize;

        loop {
            match drive_from_checkpoint(self, table, df, options, &mut committed) {
                Ok(()) => return Ok(()),
                Err(err) if err.code() != crate::ErrorCode::FailoverRetry => return Err(err),
                // Re-borrow onto a live primary (retrying the connect within the
                // budget per the row API's backoff), then re-drive the tail.
                Err(_) => self.reborrow_with_retry(deadline)?,
            }
        }
    }
}

/// Single forward pass over `df`, skipping the first `*committed` batches (the
/// tail already durable from an earlier attempt), flushing each remaining
/// batch and `sync`ing every [`CHECKPOINT_BATCHES`]. `*committed` is advanced
/// to the batch count made durable by each successful checkpoint `sync`, so on
/// a transient error the caller re-drives only the uncommitted tail.
fn drive_from_checkpoint(
    sender: &mut crate::ingress::column_sender::BorrowedColumnSender<'_>,
    table: crate::ingress::TableName<'_>,
    df: &DataFrame,
    options: &PolarsIngestOptions<'_>,
    committed: &mut usize,
) -> Result<()> {
    use crate::ingress::column_sender::AckLevel;

    let skip = *committed;
    for (idx, rb) in dataframe_to_batches(df, options.max_rows).enumerate() {
        if idx < skip {
            continue;
        }
        let rb = rb?;
        match options.timestamp_column {
            Some(ts) => sender.flush_arrow_batch_at_column(table, &rb, ts, options.overrides)?,
            None => sender.flush_arrow_batch(table, &rb, options.overrides)?,
        }
        // `idx` is 0-based; checkpoint after a full run of CHECKPOINT_BATCHES
        // (batches 63, 127, …). The sync's ack moves the replay boundary.
        if (idx + 1) % CHECKPOINT_BATCHES == 0 {
            sender.sync(AckLevel::Ok)?;
            *committed = idx + 1;
        }
    }
    sender.sync(AckLevel::Ok)
}

fn ffi_polars_to_arrow_rs(
    pa_field: &polars_arrow::datatypes::Field,
    pa_array_box: Box<dyn polars_arrow::array::Array>,
    col_name: &str,
) -> Result<arrow_data::ArrayData> {
    let pa_schema = polars_arrow::ffi::export_field_to_c(pa_field);
    let pa_array = polars_arrow::ffi::export_array_to_c(pa_array_box);
    let rs_schema = unsafe { pa_schema_into_rs(pa_schema) };
    let rs_array = unsafe { pa_array_into_rs(pa_array) };
    unsafe { arrow::ffi::from_ffi(rs_array, &rs_schema) }
        .map_err(|e| fmt!(ArrowIngest, "from_ffi('{}'): {}", col_name, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use arrow_array::Int64Array;
    use arrow_array::cast::AsArray;
    use arrow_array::types::Int64Type;
    use polars::prelude::{IntoColumn, NamedFrom, PlSmallStr, Series};

    const TWO: NonZeroUsize = NonZeroUsize::new(2).unwrap();
    const HUNDRED: NonZeroUsize = NonZeroUsize::new(100).unwrap();
    const THOUSAND: NonZeroUsize = NonZeroUsize::new(1000).unwrap();

    fn make_df() -> DataFrame {
        let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3]).into_column();
        let f = Series::new(PlSmallStr::from("f"), &[1.5f64, 2.5, 3.5]).into_column();
        let s = Series::new(PlSmallStr::from("s"), &["a", "b", "c"]).into_column();
        DataFrame::new(3, vec![i, f, s]).unwrap()
    }

    fn collect_ok(it: DataFrameBatches<'_>) -> Vec<RecordBatch> {
        it.map(|rb| rb.expect("conversion failed")).collect()
    }

    fn one_batch(df: &DataFrame) -> RecordBatch {
        let mut batches = collect_ok(dataframe_to_batches(df, None));
        assert_eq!(batches.len(), 1);
        batches.pop().unwrap()
    }

    #[test]
    fn dataframe_to_batches_preserves_columns_and_height() {
        let df = make_df();
        let rb = one_batch(&df);
        assert_eq!(rb.num_columns(), 3);
        assert_eq!(rb.num_rows(), 3);
        assert_eq!(rb.schema().field(0).name(), "i");
        assert_eq!(rb.schema().field(1).name(), "f");
        assert_eq!(rb.schema().field(2).name(), "s");
    }

    #[test]
    fn polars_ffi_layout_round_trip() {
        let s = Series::new(PlSmallStr::from("x"), &[10i64, 20, 30, 40, 50]);
        let pa_field = polars_arrow::datatypes::Field::new(
            s.name().clone(),
            s.dtype().to_arrow(CompatLevel::newest()),
            true,
        );
        let pa_arr = s.to_arrow(0, CompatLevel::newest());
        let exported_array = polars_arrow::ffi::export_array_to_c(pa_arr);
        let exported_schema = polars_arrow::ffi::export_field_to_c(&pa_field);

        let rs_array = unsafe { pa_array_into_rs(exported_array) };
        let rs_schema = unsafe { pa_schema_into_rs(exported_schema) };
        let data = unsafe { arrow::ffi::from_ffi(rs_array, &rs_schema) }
            .expect("from_ffi after polars-arrow → arrow-rs bridge");

        let arr = arrow_array::make_array(data);
        let int_arr = arr.as_primitive::<Int64Type>();
        assert_eq!(int_arr.len(), 5);
        assert_eq!(int_arr.value(0), 10);
        assert_eq!(int_arr.value(1), 20);
        assert_eq!(int_arr.value(2), 30);
        assert_eq!(int_arr.value(3), 40);
        assert_eq!(int_arr.value(4), 50);
    }

    #[test]
    fn dataframe_round_trip_int_values_match() {
        let df = make_df();
        let rb = one_batch(&df);
        let back = crate::egress::arrow::polars::record_batch_to_dataframe(rb).unwrap();
        let series = back.columns()[0].as_materialized_series();
        let i64s = series.i64().unwrap();
        assert_eq!(i64s.get(0), Some(1));
        assert_eq!(i64s.get(1), Some(2));
        assert_eq!(i64s.get(2), Some(3));
    }

    #[test]
    fn dataframe_round_trip_string_values_match() {
        let df = make_df();
        let rb = one_batch(&df);
        let back = crate::egress::arrow::polars::record_batch_to_dataframe(rb).unwrap();
        let series = back.columns()[2].as_materialized_series();
        let s = series.str().unwrap();
        assert_eq!(s.get(0), Some("a"));
        assert_eq!(s.get(1), Some("b"));
        assert_eq!(s.get(2), Some("c"));
    }

    #[test]
    fn dataframe_to_batches_yields_capped_slices() {
        let df = make_df();
        let batches = collect_ok(dataframe_to_batches(&df, Some(TWO)));
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].num_rows(), 2);
        assert_eq!(batches[1].num_rows(), 1);
    }

    #[test]
    fn dataframe_to_batches_default_max_rows_when_none() {
        let df = make_df();
        let batches = collect_ok(dataframe_to_batches(&df, None));
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].num_rows(), 3);
    }

    #[test]
    fn dataframe_to_batches_single_yield_when_under_max() {
        let df = make_df();
        let batches = collect_ok(dataframe_to_batches(&df, Some(HUNDRED)));
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].num_rows(), 3);
    }

    #[test]
    fn dataframe_to_batches_chunk_aligned_is_zero_copy() {
        let mut left = DataFrame::new(
            2,
            vec![Series::new(PlSmallStr::from("i"), &[10i64, 20]).into_column()],
        )
        .unwrap();
        let right = DataFrame::new(
            2,
            vec![Series::new(PlSmallStr::from("i"), &[30i64, 40]).into_column()],
        )
        .unwrap();
        left.vstack_mut(&right).unwrap();
        assert_eq!(left.columns()[0].n_chunks(), 2);

        let polars_chunks: Vec<*const i64> = {
            let s = left.columns()[0].as_materialized_series();
            (0..s.n_chunks())
                .map(|i| {
                    let arr = &s.chunks()[i];
                    let prim: &polars_arrow::array::PrimitiveArray<i64> =
                        arr.as_any().downcast_ref().unwrap();
                    prim.values().as_slice().as_ptr()
                })
                .collect()
        };

        let batches = collect_ok(dataframe_to_batches(&left, Some(THOUSAND)));
        assert_eq!(batches.len(), 2);
        for (idx, rb) in batches.iter().enumerate() {
            assert_eq!(rb.num_rows(), 2);
            let col: &Int64Array = rb.column(0).as_primitive::<Int64Type>();
            assert_eq!(col.values().as_ptr(), polars_chunks[idx]);
        }
    }

    #[test]
    fn dataframe_to_batches_chunk_aligned_splits_within_chunk() {
        let mut left = DataFrame::new(
            3,
            vec![Series::new(PlSmallStr::from("i"), &[1i64, 2, 3]).into_column()],
        )
        .unwrap();
        let right = DataFrame::new(
            3,
            vec![Series::new(PlSmallStr::from("i"), &[4i64, 5, 6]).into_column()],
        )
        .unwrap();
        left.vstack_mut(&right).unwrap();

        let batches = collect_ok(dataframe_to_batches(&left, Some(TWO)));
        let lens: Vec<usize> = batches.iter().map(|rb| rb.num_rows()).collect();
        assert_eq!(lens, vec![2, 1, 2, 1]);
    }

    #[test]
    fn dataframe_to_batches_misaligned_chunks_zero_copy() {
        let a1 = Series::new(PlSmallStr::from("a"), &[1i64, 2]);
        let a2 = Series::new(PlSmallStr::from("a"), &[3i64, 4]);
        let b = Series::new(PlSmallStr::from("b"), &[10i64, 20, 30, 40]);
        let mut left =
            DataFrame::new(2, vec![a1.into_column(), b.slice(0, 2).into_column()]).unwrap();
        let right = DataFrame::new(2, vec![a2.into_column(), b.slice(2, 2).into_column()]).unwrap();
        left.vstack_mut(&right).unwrap();
        left.with_column(b.into_column()).unwrap();
        assert_ne!(
            left.columns()[0]
                .as_materialized_series()
                .chunk_lengths()
                .collect::<Vec<_>>(),
            left.columns()[1]
                .as_materialized_series()
                .chunk_lengths()
                .collect::<Vec<_>>(),
        );

        let b_chunk_ptr = {
            let s = left.columns()[1].as_materialized_series();
            let arr = &s.chunks()[0];
            let prim: &polars_arrow::array::PrimitiveArray<i64> =
                arr.as_any().downcast_ref().unwrap();
            prim.values().as_slice().as_ptr()
        };

        let batches = collect_ok(dataframe_to_batches(&left, Some(THOUSAND)));
        assert_eq!(batches.len(), 2);
        let a0: &Int64Array = batches[0].column(0).as_primitive::<Int64Type>();
        let b0: &Int64Array = batches[0].column(1).as_primitive::<Int64Type>();
        let a1: &Int64Array = batches[1].column(0).as_primitive::<Int64Type>();
        let b1: &Int64Array = batches[1].column(1).as_primitive::<Int64Type>();
        assert_eq!(a0.values().as_ref(), &[1, 2]);
        assert_eq!(b0.values().as_ref(), &[10, 20]);
        assert_eq!(a1.values().as_ref(), &[3, 4]);
        assert_eq!(b1.values().as_ref(), &[30, 40]);
        assert_eq!(b0.values().as_ptr(), b_chunk_ptr);
        assert_eq!(b1.values().as_ptr(), unsafe { b_chunk_ptr.add(2) });
    }

    #[test]
    fn dataframe_to_batches_scalar_column_materialises_once() {
        use polars::prelude::Scalar;
        let values = Series::new(PlSmallStr::from("v"), &[1i64, 2, 3, 4]);
        let scalar = Column::new_scalar(PlSmallStr::from("k"), Scalar::from(7i64), 4);
        let df = DataFrame::new(4, vec![values.into_column(), scalar]).unwrap();

        let batches = collect_ok(dataframe_to_batches(&df, Some(TWO)));
        assert_eq!(batches.len(), 2);
        for rb in &batches {
            assert_eq!(rb.num_rows(), 2);
            let k: &Int64Array = rb.column(1).as_primitive::<Int64Type>();
            assert_eq!(k.values().as_ref(), &[7, 7]);
        }

        let materialised_ptr = {
            let s = df.columns()[1].as_materialized_series();
            let arr = &s.chunks()[0];
            let prim: &polars_arrow::array::PrimitiveArray<i64> =
                arr.as_any().downcast_ref().unwrap();
            prim.values().as_slice().as_ptr()
        };
        let k0: &Int64Array = batches[0].column(1).as_primitive::<Int64Type>();
        let k1: &Int64Array = batches[1].column(1).as_primitive::<Int64Type>();
        assert_eq!(k0.values().as_ptr(), materialised_ptr);
        assert_eq!(k1.values().as_ptr(), unsafe { materialised_ptr.add(2) });
    }

    #[test]
    fn polars_categorical_routes_through_dictionary() {
        use arrow_schema::DataType as ArrowDataType;
        use polars::prelude::{CategoricalPhysical, Categories, DataType as PlDataType};

        // Polars Categorical → arrow Dictionary(UInt32, LargeUtf8). The
        // downstream SYMBOL routing is covered by
        // `dict_u32_large_utf8_routes_to_symbol` in
        // `column_sender::arrow_batch::tests` — here we only verify the
        // polars→arrow translation produces a Dictionary array.
        let cats = Categories::new(
            PlSmallStr::from("syms"),
            PlSmallStr::from("test"),
            CategoricalPhysical::U32,
        );
        let mapping = cats.mapping();
        let dtype = PlDataType::Categorical(cats, mapping);

        let strings = Series::new(PlSmallStr::from("c"), &["A", "B", "A", "C"]);
        let cat_series = strings.cast(&dtype).unwrap();
        assert!(matches!(cat_series.dtype(), PlDataType::Categorical(_, _)));

        let df = DataFrame::new(4, vec![cat_series.into_column()]).unwrap();
        let batches = collect_ok(dataframe_to_batches(&df, None));
        assert_eq!(batches.len(), 1);
        let rb = &batches[0];

        assert!(
            matches!(
                rb.schema().field(0).data_type(),
                ArrowDataType::Dictionary(_, _)
            ),
            "expected Dictionary column, got {:?}",
            rb.schema().field(0).data_type()
        );
        assert_eq!(rb.num_rows(), 4);
    }
}
