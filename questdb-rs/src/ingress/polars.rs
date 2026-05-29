//! Polars sub-feature: `DataFrame → Buffer` via Arrow C Data Interface.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema as ArrowSchema};
use polars::frame::DataFrame;
use polars::prelude::CompatLevel;

use crate::ingress::{Buffer, ColumnName, TableName};
use crate::{Result, fmt};

/// Default chunk size for [`Buffer::append_polars`] /
/// [`Buffer::append_polars_at_column`].
pub const DEFAULT_MAX_BATCH_ROWS: usize = 10_000;

// `polars_arrow::ffi` and `arrow::ffi` are independent `#[repr(C)]` mirrors
// of the Arrow C Data Interface; the bridge below transmutes between them.
// Assert layout parity so a future crate bump can't silently break soundness.
const _: () = assert!(
    std::mem::size_of::<polars_arrow::ffi::ArrowArray>()
        == std::mem::size_of::<arrow::ffi::FFI_ArrowArray>(),
    "polars_arrow::ffi::ArrowArray size diverged from arrow::ffi::FFI_ArrowArray"
);
const _: () = assert!(
    std::mem::size_of::<polars_arrow::ffi::ArrowSchema>()
        == std::mem::size_of::<arrow::ffi::FFI_ArrowSchema>(),
    "polars_arrow::ffi::ArrowSchema size diverged from arrow::ffi::FFI_ArrowSchema"
);
const _: () = assert!(
    std::mem::align_of::<polars_arrow::ffi::ArrowArray>()
        == std::mem::align_of::<arrow::ffi::FFI_ArrowArray>(),
);
const _: () = assert!(
    std::mem::align_of::<polars_arrow::ffi::ArrowSchema>()
        == std::mem::align_of::<arrow::ffi::FFI_ArrowSchema>(),
);

impl Buffer {
    /// Append every row of `df`. Server stamps timestamps on arrival
    /// (see [`Buffer::append_arrow`]).
    ///
    /// `df` is converted to one Arrow RecordBatch and sliced into
    /// pieces of at most `max_batch_rows` rows. `None` uses
    /// [`DEFAULT_MAX_BATCH_ROWS`]. Caller is responsible for flushing.
    pub fn append_polars(
        &mut self,
        table: TableName<'_>,
        df: &DataFrame,
        max_batch_rows: Option<usize>,
    ) -> Result<()> {
        append_polars_chunked(self, table, df, None, max_batch_rows)
    }

    /// Same as [`Buffer::append_polars`] but the per-row designated
    /// timestamp comes from `ts_column` inside the DataFrame.
    pub fn append_polars_at_column(
        &mut self,
        table: TableName<'_>,
        df: &DataFrame,
        ts_column: ColumnName<'_>,
        max_batch_rows: Option<usize>,
    ) -> Result<()> {
        append_polars_chunked(self, table, df, Some(ts_column), max_batch_rows)
    }
}

fn append_polars_chunked(
    buf: &mut Buffer,
    table: TableName<'_>,
    df: &DataFrame,
    ts_column: Option<ColumnName<'_>>,
    max_batch_rows: Option<usize>,
) -> Result<()> {
    let max = max_batch_rows.unwrap_or(DEFAULT_MAX_BATCH_ROWS);
    for rb in dataframe_to_batches(df, max)? {
        match ts_column {
            Some(ts) => buf.append_arrow_at_column(table, &rb, ts)?,
            None => buf.append_arrow(table, &rb)?,
        }
    }
    Ok(())
}

/// Convert `df` to one Arrow RecordBatch (via the Arrow C Data Interface),
/// then yield zero-copy slices of at most `max_rows` rows each. Matches
/// the semantics of pyarrow's `Table.to_batches(max_chunksize=N)`.
pub fn dataframe_to_batches(
    df: &DataFrame,
    max_rows: usize,
) -> Result<impl Iterator<Item = RecordBatch>> {
    if max_rows == 0 {
        return Err(fmt!(ArrowIngest, "max_rows must be > 0"));
    }
    let rb = dataframe_to_record_batch(df.clone())?;
    let n = rb.num_rows();
    let mut offset = 0usize;
    Ok(std::iter::from_fn(move || {
        if offset >= n {
            return None;
        }
        let len = (n - offset).min(max_rows);
        let sub = rb.slice(offset, len);
        offset += len;
        Some(sub)
    }))
}

/// Bridge a polars [`DataFrame`] to an [`arrow_array::RecordBatch`] via
/// the Arrow C Data Interface. Re-chunks each column.
pub fn dataframe_to_record_batch(df: DataFrame) -> Result<RecordBatch> {
    let compat = CompatLevel::newest();
    let mut fields: Vec<Field> = Vec::with_capacity(df.width());
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(df.width());
    for column in df.into_columns() {
        let name = column.name().as_str().to_string();
        let pa_field = polars_arrow::datatypes::Field::new(
            column.name().clone(),
            column.dtype().to_arrow(compat),
            true,
        );
        let pa_schema = polars_arrow::ffi::export_field_to_c(&pa_field);
        let pa_array_box = column.rechunk_to_arrow(compat);
        let pa_array = polars_arrow::ffi::export_array_to_c(pa_array_box);
        let rs_schema: arrow::ffi::FFI_ArrowSchema =
            unsafe { std::mem::transmute_copy(&pa_schema) };
        std::mem::forget(pa_schema);
        let rs_array: arrow::ffi::FFI_ArrowArray = unsafe { std::mem::transmute_copy(&pa_array) };
        std::mem::forget(pa_array);
        let array_data = unsafe { arrow::ffi::from_ffi(rs_array, &rs_schema) }
            .map_err(|e| fmt!(ArrowIngest, "from_ffi('{}'): {}", name, e))?;
        let dtype: DataType = array_data.data_type().clone();
        fields.push(Field::new(name, dtype, true));
        arrays.push(arrow_array::make_array(array_data));
    }
    let schema = Arc::new(ArrowSchema::new(fields));
    RecordBatch::try_new(schema, arrays)
        .map_err(|e| fmt!(ArrowIngest, "RecordBatch::try_new failed: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use polars::prelude::{IntoColumn, NamedFrom, PlSmallStr, Series};

    fn make_df() -> DataFrame {
        let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3]).into_column();
        let f = Series::new(PlSmallStr::from("f"), &[1.5f64, 2.5, 3.5]).into_column();
        let s = Series::new(PlSmallStr::from("s"), &["a", "b", "c"]).into_column();
        DataFrame::new(3, vec![i, f, s]).unwrap()
    }

    #[test]
    fn dataframe_to_record_batch_preserves_columns_and_height() {
        let df = make_df();
        let rb = dataframe_to_record_batch(df).unwrap();
        assert_eq!(rb.num_columns(), 3);
        assert_eq!(rb.num_rows(), 3);
        assert_eq!(rb.schema().field(0).name(), "i");
        assert_eq!(rb.schema().field(1).name(), "f");
        assert_eq!(rb.schema().field(2).name(), "s");
    }

    #[test]
    fn dataframe_round_trip_int_values_match() {
        let df = make_df();
        let rb = dataframe_to_record_batch(df).unwrap();
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
        let rb = dataframe_to_record_batch(df).unwrap();
        let back = crate::egress::arrow::polars::record_batch_to_dataframe(rb).unwrap();
        let series = back.columns()[2].as_materialized_series();
        let s = series.str().unwrap();
        assert_eq!(s.get(0), Some("a"));
        assert_eq!(s.get(1), Some("b"));
        assert_eq!(s.get(2), Some("c"));
    }

    #[test]
    fn append_polars_writes_to_buffer_with_default() {
        let df = make_df();
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        let t = TableName::new("polars_test").unwrap();
        buf.append_polars(t, &df, None).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn append_polars_chunked_slices_across_max_batch() {
        let df = make_df();
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        let t = TableName::new("polars_chunked").unwrap();
        buf.append_polars(t, &df, Some(2)).unwrap();
        assert_eq!(buf.row_count(), 3);
    }

    #[test]
    fn append_polars_rejects_zero_max_batch_rows() {
        let df = make_df();
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        let t = TableName::new("polars_zero").unwrap();
        let err = buf.append_polars(t, &df, Some(0)).unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::ArrowIngest);
    }

    #[test]
    fn dataframe_to_batches_yields_capped_slices() {
        let df = make_df();
        let batches: Vec<_> = dataframe_to_batches(&df, 2).unwrap().collect();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].num_rows(), 2);
        assert_eq!(batches[1].num_rows(), 1);
    }

    #[test]
    fn dataframe_to_batches_single_yield_when_under_max() {
        let df = make_df();
        let batches: Vec<_> = dataframe_to_batches(&df, 100).unwrap().collect();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].num_rows(), 3);
    }

    #[test]
    fn dataframe_to_batches_rejects_zero_max_rows() {
        let df = make_df();
        match dataframe_to_batches(&df, 0) {
            Ok(_) => panic!("expected error"),
            Err(e) => assert_eq!(e.code(), crate::error::ErrorCode::ArrowIngest),
        }
    }
}
