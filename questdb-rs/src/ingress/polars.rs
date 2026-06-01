//! Polars sub-feature: convert a [`DataFrame`] into Arrow
//! [`RecordBatch`]es for consumption by [`Buffer::append_arrow`].
//!
//! [`dataframe_to_batches`] is the primary entry point. It returns an
//! iterator that yields slices of at most `max_rows` rows each. Each
//! emitted slice is taken from a single polars chunk per column, so
//! row data is never copied — the Arrow C Data Interface only bumps
//! refcounts. Two costs survive:
//!
//! * `Column::Scalar` columns are materialised once by polars (cached
//!   in the column's `OnceLock`); subsequent batches slice from that
//!   cache zero-copy. Sending a scalar as columnar data requires the
//!   value to actually exist in memory N times — there is no
//!   zero-copy alternative.
//! * Polars *logical* dtypes that arrow-rs does not have natively
//!   (Datetime, Date, Time, Duration, Categorical, Enum) incur a
//!   per-chunk `cast_default` at the polars→arrow conversion step.
//!   Primitive, String, Binary, and Decimal columns at the newest
//!   compat level are pure refcount bumps.
//!
//! Flushing is the caller's responsibility:
//!
//! ```ignore
//! for rb in questdb::ingress::polars::dataframe_to_batches(&df, None) {
//!     let rb = rb?;
//!     buf.append_arrow(table, &rb)?;
//!     sender.flush(&mut buf)?;
//! }
//! ```
//!
//! [`Buffer::append_arrow`]: crate::ingress::Buffer::append_arrow

use std::num::NonZeroUsize;
use std::sync::Arc;

use arrow_array::{ArrayRef, RecordBatch};
use arrow_schema::{Field, Schema as ArrowSchema};
use polars::frame::DataFrame;
use polars::prelude::{Column, CompatLevel, Series};

use crate::{Result, fmt};

/// Suggested default chunk size for [`dataframe_to_batches`].
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
    }
}

/// Iterator returned by [`dataframe_to_batches`].
pub struct DataFrameBatches<'a> {
    max_rows: usize,
    compat: CompatLevel,
    total_rows: usize,
    rows_emitted: usize,
    cursors: Vec<ColumnCursor<'a>>,
    schema: Option<Arc<ArrowSchema>>,
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
        if self.cursors.is_empty() || self.rows_emitted >= self.total_rows {
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
            let sliced = cursor.current_chunk(compat).sliced(offset, seg_len);
            let array_data = match ffi_polars_to_arrow_rs(&cursor.pa_field, sliced, &cursor.name) {
                Ok(d) => d,
                Err(e) => {
                    self.rows_emitted = self.total_rows;
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
                self.rows_emitted = self.total_rows;
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

fn ffi_polars_to_arrow_rs(
    pa_field: &polars_arrow::datatypes::Field,
    pa_array_box: Box<dyn polars_arrow::array::Array>,
    col_name: &str,
) -> Result<arrow_data::ArrayData> {
    let pa_schema = polars_arrow::ffi::export_field_to_c(pa_field);
    let pa_array = polars_arrow::ffi::export_array_to_c(pa_array_box);
    let rs_schema: arrow::ffi::FFI_ArrowSchema = unsafe { std::mem::transmute_copy(&pa_schema) };
    std::mem::forget(pa_schema);
    let rs_array: arrow::ffi::FFI_ArrowArray = unsafe { std::mem::transmute_copy(&pa_array) };
    std::mem::forget(pa_array);
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
    fn polars_categorical_routes_through_dictionary_to_symbol() {
        use crate::ingress::{Buffer, TableName};
        use arrow_schema::DataType as ArrowDataType;
        use polars::prelude::{CategoricalPhysical, Categories, DataType as PlDataType};

        // Polars Categorical → arrow Dictionary(UInt32, LargeUtf8)
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

        // Arrow side must be Dictionary-encoded for the SYMBOL routing to kick in.
        assert!(
            matches!(
                rb.schema().field(0).data_type(),
                ArrowDataType::Dictionary(_, _)
            ),
            "expected Dictionary column, got {:?}",
            rb.schema().field(0).data_type()
        );

        // Buffer::append_arrow classifies Dictionary → SymbolDict → SYMBOL wire.
        let mut buf = Buffer::qwp_ws_with_max_name_len(127);
        let t = TableName::new("polars_cat_sym").unwrap();
        buf.append_arrow(t, rb).unwrap();
        assert_eq!(buf.row_count(), 4);
    }
}
