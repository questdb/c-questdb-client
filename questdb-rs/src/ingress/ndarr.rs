pub trait NdArrayView<T>
where
    T: ArrayElement,
{
    /// Returns the number of dimensions (rank) of the array.
    fn ndim(&self) -> usize;

    /// Returns the size of the specified dimension.
    fn dim(&self, index: usize) -> Option<usize>;

    /// Writes array data to writer in row-major order.
    ///
    /// # Important Notes
    /// - Writer must be pre-allocated with exact required size
    /// - No alignment assumptions should be made about writer start
    /// - Handles both contiguous and non-contiguous memory layouts
    fn write_row_major<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
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

/// Defines binary format identifiers for array element types compatible with
/// QuestDB's [`ColumnType`]: https://github.com/questdb/questdb/blob/e1853db56ae586d923ca77de01a487cad44093b9/core/src/main/java/io/questdb/cairo/ColumnType.java#L67-L89.
#[repr(u8)]
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ElemDataType {
    /// 64-bit floating point
    Double = 0x0A,
}

impl From<ElemDataType> for u8 {
    fn from(val: ElemDataType) -> Self {
        val as u8
    }
}

impl TryFrom<u8> for ElemDataType {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, String> {
        match value {
            0x0A => Ok(ElemDataType::Double),
            _ => Err(format!("Unknown element type: {}", value)),
        }
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

    fn write_row_major<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        if let Some(contiguous) = self.as_slice() {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    contiguous.as_ptr() as *const u8,
                    size_of_val(contiguous),
                )
            };
            return writer.write_all(bytes);
        }

        let elem_size = size_of::<T>();
        for &element in self.iter() {
            let bytes =
                unsafe { std::slice::from_raw_parts(&element as *const T as *const _, elem_size) };
            writer.write_all(bytes)?;
        }
        Ok(())
    }
}
