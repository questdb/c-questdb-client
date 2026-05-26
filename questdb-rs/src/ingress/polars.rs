//! Polars sub-feature: `DataFrame → Buffer` via Arrow C Data Interface.

use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{DataType, Field, Schema as ArrowSchema};
use polars::frame::DataFrame;
use polars::prelude::CompatLevel;

use crate::ingress::{Buffer, DesignatedTimestamp, TableName};
use crate::{Result, fmt};

impl Buffer {
    /// Append every row of `df` to this buffer via the Arrow C Data
    /// Interface bridge. Re-chunks `df` before conversion.
    pub fn append_polars(
        &mut self,
        table: TableName<'_>,
        df: DataFrame,
        designated_timestamp: DesignatedTimestamp<'_>,
    ) -> Result<()> {
        let rb = dataframe_to_record_batch(df)?;
        self.append_arrow(table, &rb, designated_timestamp)
    }
}

pub fn dataframe_to_record_batch(df: DataFrame) -> Result<RecordBatch> {
    let height = df.height();
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
    let _ = height;
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
    fn append_polars_writes_to_buffer() {
        let df = make_df();
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        let t = TableName::new("polars_test").unwrap();
        buf.append_polars(t, df, DesignatedTimestamp::Now).unwrap();
        assert_eq!(buf.row_count(), 3);
    }
}
