//! Transport-neutral zero-copy bridges between `arrow`'s and `polars_arrow`'s
//! Arrow C Data Interface structs (identical ABI layout, so the conversion is
//! a `transmute`). Shared by the ingress polars path (`DataFrame` → `Buffer`)
//! and the egress polars path (`Cursor` → `DataFrame`); homed here so neither
//! direction has to reach into the other's module.

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
