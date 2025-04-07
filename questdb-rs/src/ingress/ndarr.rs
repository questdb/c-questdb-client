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

#[derive(Debug)]
pub struct ArrayViewWithStrides<'a, T> {
    dims: usize,
    shapes: &'a [usize],
    strides: &'a [isize],
    buf_len: usize,
    buf: *const u8,
    _marker: std::marker::PhantomData<T>,
}

impl<T> NdArrayView<T> for ArrayViewWithStrides<'_, T>
where
    T: ArrayElement,
{
    fn ndim(&self) -> usize {
        self.dims
    }

    fn dim(&self, index: usize) -> Option<usize> {
        if index >= self.dims {
            return None;
        }

        Some(self.shapes[index])
    }

    fn write_row_major<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        if self.is_c_major() {
            let bytes = unsafe { slice::from_raw_parts(self.buf, self.buf_len) };
            writer.write_all(bytes)?;
            Ok(())
        } else {
            let mut io_slices = Vec::new();
            for element in self.iter() {
                io_slices.push(std::io::IoSlice::new(element));
            }

            let mut io_slices: &mut [std::io::IoSlice<'_>] = io_slices.as_mut_slice();
            while !io_slices.is_empty() {
                let written = writer.write_vectored(io_slices)?;
                if written == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Failed to write all bytes",
                    ));
                }
                io_slices = &mut io_slices[written..];
            }
            Ok(())
        }
    }
}

impl<T> ArrayViewWithStrides<'_, T>
where
    T: ArrayElement,
{
    /// # Safety
    ///
    /// todo
    pub unsafe fn new(
        dims: usize,
        shapes: *const usize,
        strides: *const isize,
        data: *const u8,
        data_len: usize,
    ) -> Self {
        let shapes = slice::from_raw_parts(shapes, dims);
        let strides = slice::from_raw_parts(strides, dims);
        Self {
            dims,
            shapes,
            strides,
            buf_len: data_len,
            buf: data,
            _marker: std::marker::PhantomData::<T>,
        }
    }

    fn is_c_major(&self) -> bool {
        let mut expected_stride = size_of::<T>() as isize;
        self.strides
            .iter()
            .rev()
            .skip(1)
            .zip(self.shapes.iter().rev())
            .all(|(&actual, &dim)| {
                let expected = expected_stride;
                expected_stride *= dim as isize;
                actual.abs() == expected.abs()
            })
    }

    fn iter(&self) -> CMajorIterWithStrides<T> {
        let mut dim_products = Vec::with_capacity(self.dims);
        let mut product = 1;
        for &dim in self.shapes.iter().rev() {
            dim_products.push(product);
            product *= dim;
        }
        dim_products.reverse();

        // consider minus strides
        let base_ptr = self
            .strides
            .iter()
            .enumerate()
            .fold(self.buf, |ptr, (dim, &stride)| {
                if stride < 0 {
                    let dim_size = self.shapes[dim] as isize;
                    unsafe { ptr.offset(stride * (dim_size - 1)) }
                } else {
                    ptr
                }
            });
        CMajorIterWithStrides {
            base_ptr,
            array: self,
            dim_products,
            current_linear: 0,
            total_elements: self.shapes.iter().product(),
        }
    }
}

struct CMajorIterWithStrides<'a, T> {
    base_ptr: *const u8,
    array: &'a ArrayViewWithStrides<'a, T>,
    dim_products: Vec<usize>,
    current_linear: usize,
    total_elements: usize,
}

impl<T> CMajorIterWithStrides<'_, T> {
    fn is_ptr_valid(&self, ptr: *const u8) -> bool {
        let start = self.array.buf;
        let end = unsafe { start.add(self.array.buf_len) };
        ptr >= start && ptr < end
    }
}

impl<'a, T> Iterator for CMajorIterWithStrides<'a, T>
where
    T: ArrayElement,
{
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_linear >= self.total_elements {
            return None;
        }
        let mut index = self.current_linear;
        let mut offset = 0isize;

        for (dim, &prod) in self.dim_products.iter().enumerate() {
            let coord = index / prod;
            offset += self.array.strides[dim] * coord as isize;
            index %= prod;
        }

        self.current_linear += 1;
        unsafe {
            let ptr = self.base_ptr.offset(offset);
            if self.is_ptr_valid(ptr) {
                Some(slice::from_raw_parts(ptr, size_of::<T>()))
            } else {
                None
            }
        }
    }
}

#[cfg(feature = "ndarray")]
use ndarray::{ArrayView, Axis, Dimension};
use std::slice;

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
        let mut io_slices = Vec::new();
        for element in self.iter() {
            let bytes =
                unsafe { std::slice::from_raw_parts(element as *const T as *const _, elem_size) };
            io_slices.push(std::io::IoSlice::new(bytes));
        }

        let mut io_slices: &mut [std::io::IoSlice<'_>] = io_slices.as_mut_slice();
        while !io_slices.is_empty() {
            let written = writer.write_vectored(io_slices)?;
            if written == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "Failed to write all bytes",
                ));
            }
            io_slices = &mut io_slices[written..];
        }
        Ok(())
    }
}
