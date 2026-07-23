//! Transport-neutral zero-copy bridges between `arrow`'s and `polars_arrow`'s
//! Arrow C Data Interface structs (identical ABI layout, so the conversion is
//! a `transmute`). Shared by the ingress polars path (`DataFrame` → `Buffer`)
//! and the egress polars path (`Cursor` → `DataFrame`); homed here so neither
//! direction has to reach into the other's module.

use polars::prelude::{Column, DataFrame, PolarsResult};

/// `DataFrame::new` changed name+signature between polars 0.52 and 0.53;
/// `into_frame` + `with_column` are stable across 0.52–0.54.
///
/// Shared by egress (non-test) and both directions' tests. In a
/// `polars-ingress`-only, non-test build (e.g. the soak `dataframe` leg)
/// it has no caller, hence the conditional `allow`.
#[cfg_attr(not(feature = "polars-egress"), allow(dead_code))]
pub(crate) fn df_from_columns(columns: Vec<Column>) -> PolarsResult<DataFrame> {
    let mut cols = columns.into_iter();
    let Some(first) = cols.next() else {
        return Ok(DataFrame::default());
    };
    let mut df = first.into_frame();
    for col in cols {
        df.with_column(col)?;
    }
    Ok(df)
}

#[cfg(feature = "polars-egress")]
#[inline]
pub(crate) unsafe fn rs_array_into_pa(
    rs: arrow::ffi::FFI_ArrowArray,
) -> polars_arrow::ffi::ArrowArray {
    unsafe { std::mem::transmute::<arrow::ffi::FFI_ArrowArray, polars_arrow::ffi::ArrowArray>(rs) }
}

#[cfg(feature = "polars-egress")]
#[inline]
pub(crate) unsafe fn rs_schema_into_pa(
    rs: arrow::ffi::FFI_ArrowSchema,
) -> polars_arrow::ffi::ArrowSchema {
    unsafe {
        std::mem::transmute::<arrow::ffi::FFI_ArrowSchema, polars_arrow::ffi::ArrowSchema>(rs)
    }
}
