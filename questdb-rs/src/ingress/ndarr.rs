pub(crate) const MAX_DIMS: usize = 32;

pub trait NdArrayView<T>
where
    T: ArrayElement,
{
    /// Returns the number of dimensions (rank) of the array.
    fn ndim(&self) -> usize;

    /// Returns the size of the specified dimension.
    fn dim(&self, index: usize) -> Option<usize>;

    /// Writes array data to buffer in row-major order.
    ///
    /// # Important Notes
    /// - Buffer must be pre-allocated with exact required size
    /// - No alignment assumptions should be made about buffer start
    /// - Handles both contiguous and non-contiguous memory layouts
    fn write_row_major_buf(&self, buff: &mut [u8]);
}

/// Marker trait for valid array element types.
///
/// Implemented for primitive types that can be stored in arrays.
/// Combines type information with data type classification.
pub trait ArrayElement: Copy + 'static {
    /// Returns the corresponding data type classification.
    ///
    /// This enables runtime type identification while maintaining
    /// compile-time type safety.
    fn elem_type() -> ElemDataType;
}

#[repr(u8)]
#[derive(Debug, PartialEq)]
pub enum ElemDataType {
    /// Uninitialized/placeholder type
    Undefined = 0,
    /// Boolean values (true/false)
    Boolean,
    /// 8-bit signed integer
    Byte,
    /// 16-bit signed integer
    Short,
    /// UTF-16 character
    Char,
    /// 32-bit signed integer
    Int,
    /// 64-bit signed integer
    Long,
    /// Date type (days since epoch)
    Date,
    /// Microsecond-precision timestamp
    Timestamp,
    /// 32-bit floating point
    Float,
    /// 64-bit floating point
    Double,
    /// UTF-8 string data
    String,
    /// Interned string symbol
    Symbol,
    /// 256-bit integer value
    Long256,
    /// Geospatial byte coordinates
    GeoByte,
    /// Geospatial short coordinates
    GeoShort,
    /// Geospatial integer coordinates
    GeoInt,
    /// Geospatial long coordinates
    GeoLong,
    /// Binary large object
    Binary,
    /// UUID values
    Uuid,
}

impl From<ElemDataType> for u8 {
    fn from(val: ElemDataType) -> Self {
        val as u8
    }
}

impl ArrayElement for f64 {
    /// Identifies f64 as Double type in QuestDB's type system.
    fn elem_type() -> ElemDataType {
        ElemDataType::Double
    }
}

#[cfg(feature = "ndarray")]
use ndarray::{ArrayView, Axis, Dimension};

#[cfg(feature = "ndarray")]
impl<T, D> NdArrayView<T> for ArrayView<'_, T, D>
where
    T: ArrayElement,
    D: Dimension,
{
    fn ndim(&self) -> usize {
        self.ndim()
    }

    fn dim(&self, index: usize) -> Option<usize> {
        let len = self.ndim();
        if index < len {
            Some(self.len_of(Axis(index)))
        } else {
            None
        }
    }

    fn write_row_major_buf(&self, buf: &mut [u8]) {
        let elem_size = size_of::<T>();

        if let Some(slice) = self.as_slice() {
            let byte_len = size_of_val(slice);
            let bytes =
                unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const u8, byte_len) };
            buf[..byte_len].copy_from_slice(bytes);
            return;
        }

        let mut bytes_written = 0;
        for &element in self.iter() {
            let element_bytes =
                unsafe { std::slice::from_raw_parts(&element as *const T as *const _, elem_size) };
            buf[bytes_written..bytes_written + elem_size].copy_from_slice(element_bytes);
            bytes_written += elem_size;
        }
    }
}
