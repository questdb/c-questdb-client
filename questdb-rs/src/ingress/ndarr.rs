pub trait NdArrayView<T>
where
    T: ArrayElement,
{
    type Iter<'a>: Iterator<Item = &'a T>
    where
        Self: 'a,
        T: 'a;

    /// Returns the number of dimensions (rank) of the array.
    fn ndim(&self) -> usize;

    /// Returns the size of the specified dimension.
    fn dim(&self, index: usize) -> Option<usize>;

    /// Return the array’s data as a slice, if it is c-major-layout.
    /// Return `None` otherwise.
    fn as_slice(&self) -> Option<&[T]>;

    /// Return an iterator of references to the elements of the array.
    /// Iterator element type is `&T`.
    fn iter(&self) -> Self::Iter<'_>;

    /// Validates the data buffer size of array is consistency with array shapes.
    ///
    /// # Returns
    /// - `Ok(usize)`: Expected buffer size in bytes if valid
    /// - `Err(Error)`: Otherwise
    fn check_data_buf(&self) -> Result<usize, Error>;
}

pub fn write_array_data<W: std::io::Write, A: NdArrayView<T>, T>(
    array: &A,
    writer: &mut W,
) -> std::io::Result<()>
where
    T: ArrayElement,
{
    // First optimization path: write contiguous memory directly
    if let Some(contiguous) = array.as_slice() {
        let bytes = unsafe {
            slice::from_raw_parts(contiguous.as_ptr() as *const u8, size_of_val(contiguous))
        };
        return writer.write_all(bytes);
    }

    // Fallback path: non-contiguous memory handling
    let elem_size = size_of::<T>();
    let mut io_slices = Vec::new();
    for element in array.iter() {
        let bytes = unsafe { slice::from_raw_parts(element as *const T as *const _, elem_size) };
        io_slices.push(std::io::IoSlice::new(bytes));
    }

    let mut io_slices: &mut [IoSlice<'_>] = io_slices.as_mut_slice();
    IoSlice::advance_slices(&mut io_slices, 0);

    while !io_slices.is_empty() {
        let written = writer.write_vectored(io_slices)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "Failed to write all bytes",
            ));
        }
        IoSlice::advance_slices(&mut io_slices, written);
    }
    Ok(())
}

pub(crate) fn write_array_data_use_raw_buffer<A: NdArrayView<T>, T>(buf: &mut [u8], array: &A)
where
    T: ArrayElement,
{
    // First optimization path: write contiguous memory directly
    if let Some(contiguous) = array.as_slice() {
        let byte_len = size_of_val(contiguous);
        unsafe {
            std::ptr::copy_nonoverlapping(
                contiguous.as_ptr() as *const u8,
                buf.as_mut_ptr(),
                byte_len,
            )
        }
    }

    // Fallback path: non-contiguous memory handling
    let elem_size = size_of::<T>();
    for (i, &element) in array.iter().enumerate() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                &element as *const T as *const u8,
                buf.as_mut_ptr().add(i * elem_size),
                elem_size,
            )
        }
    }
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
/// QuestDB's ColumnType: <https://github.com/questdb/questdb/blob/e1853db56ae586d923ca77de01a487cad44093b9/core/src/main/java/io/questdb/cairo/ColumnType.java#L67-L89>.
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

/// A view into a multi-dimensional array with custom memory strides.
#[derive(Debug)]
pub struct StrideArrayView<'a, T> {
    dims: usize,
    shape: &'a [usize],
    strides: &'a [isize],
    buf_len: usize,
    buf: *const u8,
    _marker: std::marker::PhantomData<T>,
}

impl<T> NdArrayView<T> for StrideArrayView<'_, T>
where
    T: ArrayElement,
{
    type Iter<'b>
        = RowMajorIter<'b, T>
    where
        Self: 'b,
        T: 'b;

    fn ndim(&self) -> usize {
        self.dims
    }

    fn dim(&self, index: usize) -> Option<usize> {
        if index >= self.dims {
            return None;
        }

        Some(self.shape[index])
    }

    fn as_slice(&self) -> Option<&[T]> {
        if self.is_c_major() {
            Some(unsafe {
                slice::from_raw_parts(self.buf as *const T, self.buf_len / size_of::<T>())
            })
        } else {
            None
        }
    }

    fn iter(&self) -> Self::Iter<'_> {
        let mut dim_products = Vec::with_capacity(self.dims);
        let mut product = 1;
        for &dim in self.shape.iter().rev() {
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
                    let dim_size = self.shape[dim] as isize;
                    unsafe { ptr.offset(stride * (dim_size - 1)) }
                } else {
                    ptr
                }
            });
        RowMajorIter {
            base_ptr,
            array: self,
            dim_products,
            current_linear: 0,
            total_elements: self.shape.iter().product(),
        }
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        let mut size = size_of::<T>();
        for i in 0..self.dims {
            let d = self.shape[i];
            size = size.checked_mul(d).ok_or(error::fmt!(
                ArrayViewError,
                "Array total elem size overflow"
            ))?
        }
        if size != self.buf_len {
            return Err(error::fmt!(
                ArrayWriteToBufferError,
                "Array buffer length mismatch (actual: {}, expected: {})",
                self.buf_len,
                size
            ));
        }
        Ok(size)
    }
}

impl<T> StrideArrayView<'_, T>
where
    T: ArrayElement,
{
    /// Creates a new strided array view from raw components (unsafe constructor).
    ///
    /// # Safety
    /// Caller must ensure all the following conditions:
    /// - `shapes` points to a valid array of at least `dims` elements
    /// - `strides` points to a valid array of at least `dims` elements
    /// - `data` points to a valid memory block of at least `data_len` bytes
    /// - Memory layout must satisfy:
    ///   1. `data_len ≥ (shape[0]-1)*abs(strides[0]) + ... + (shape[n-1]-1)*abs(strides[n-1]) + size_of::<T>()`
    ///   2. All calculated offsets stay within `[0, data_len - size_of::<T>()]`
    /// - Lifetime `'a` must outlive the view's usage
    /// - Strides are measured in bytes (not elements)
    pub unsafe fn new(
        dims: usize,
        shape: *const usize,
        strides: *const isize,
        data: *const u8,
        data_len: usize,
    ) -> Self {
        let shapes = slice::from_raw_parts(shape, dims);
        let strides = slice::from_raw_parts(strides, dims);
        Self {
            dims,
            shape: shapes,
            strides,
            buf_len: data_len,
            buf: data,
            _marker: std::marker::PhantomData::<T>,
        }
    }

    /// Verifies if the array follows C-style row-major memory layout.
    fn is_c_major(&self) -> bool {
        if self.buf.is_null() || self.buf_len == 0 {
            return false;
        }

        let elem_size = size_of::<T>() as isize;
        if self.dims == 1 {
            return self.strides[0] == elem_size || self.shape[0] == 1;
        }

        let mut expected_stride = elem_size;
        for (dim, &stride) in self.shape.iter().zip(self.strides).rev() {
            if *dim > 1 && stride != expected_stride {
                return false;
            }
            expected_stride *= *dim as isize;
        }
        true
    }
}

/// Iterator for traversing a strided array in row-major (C-style) order.
pub struct RowMajorIter<'a, T> {
    base_ptr: *const u8,
    array: &'a StrideArrayView<'a, T>,
    dim_products: Vec<usize>,
    current_linear: usize,
    total_elements: usize,
}

impl<'a, T> Iterator for RowMajorIter<'a, T>
where
    T: ArrayElement,
{
    type Item = &'a T;
    fn next(&mut self) -> Option<Self::Item> {
        if self.current_linear >= self.total_elements {
            return None;
        }
        let mut remaining_index = self.current_linear;
        let mut offset = 0;

        for (dim, &dim_factor) in self.dim_products.iter().enumerate() {
            let coord = remaining_index / dim_factor;
            remaining_index %= dim_factor;
            let stride = self.array.strides[dim];
            let actual_coord = if stride >= 0 {
                coord
            } else {
                self.array.shape[dim] - 1 - coord
            };
            offset += actual_coord * stride.unsigned_abs();
        }

        self.current_linear += 1;
        unsafe {
            let ptr = self.base_ptr.add(offset);
            Some(&*(ptr as *const T))
        }
    }
}

/// impl NdArrayView for one dimension vector
impl<T: ArrayElement> NdArrayView<T> for Vec<T> {
    type Iter<'a>
        = std::slice::Iter<'a, T>
    where
        T: 'a;

    fn ndim(&self) -> usize {
        1
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        (idx == 0).then_some(self.len())
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(self.as_slice())
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(self.len() * std::mem::size_of::<T>())
    }
}

/// impl NdArrayView for one dimension array
impl<T: ArrayElement, const N: usize> NdArrayView<T> for [T; N] {
    type Iter<'a>
        = std::slice::Iter<'a, T>
    where
        T: 'a;

    fn ndim(&self) -> usize {
        1
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        (idx == 0).then_some(N)
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(self)
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(N * std::mem::size_of::<T>())
    }
}

/// impl NdArrayView for one dimension slice
impl<T: ArrayElement> NdArrayView<T> for &[T] {
    type Iter<'a>
        = std::slice::Iter<'a, T>
    where
        Self: 'a,
        T: 'a;

    fn ndim(&self) -> usize {
        1
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        (idx == 0).then_some(self.len())
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(self)
    }

    fn iter(&self) -> Self::Iter<'_> {
        <[T]>::iter(self)
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(std::mem::size_of_val(*self))
    }
}

/// impl NdArrayView for two dimensions vector
impl<T: ArrayElement> NdArrayView<T> for Vec<Vec<T>> {
    type Iter<'a>
        = std::iter::Flatten<std::slice::Iter<'a, Vec<T>>>
    where
        T: 'a;

    fn ndim(&self) -> usize {
        2
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        match idx {
            0 => Some(self.len()),
            1 => self.first().map(|v| v.len()),
            _ => None,
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        None
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        let row_len = self.first().map_or(0, |v| v.len());
        if self.as_slice().iter().any(|v| v.len() != row_len) {
            return Err(error::fmt!(ArrayViewError, "Irregular array shape"));
        }
        Ok(self.len() * row_len * std::mem::size_of::<T>())
    }
}

/// impl NdArrayView for two dimensions array
impl<T: ArrayElement, const M: usize, const N: usize> NdArrayView<T> for [[T; M]; N] {
    type Iter<'a>
        = std::iter::Flatten<std::slice::Iter<'a, [T; M]>>
    where
        T: 'a;

    fn ndim(&self) -> usize {
        2
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        match idx {
            0 => Some(N),
            1 => Some(M),
            _ => None,
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, N * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(N * M * std::mem::size_of::<T>())
    }
}

/// impl NdArrayView for two dimensions slices
impl<T: ArrayElement, const M: usize> NdArrayView<T> for &[[T; M]] {
    type Iter<'a>
        = std::iter::Flatten<std::slice::Iter<'a, [T; M]>>
    where
        Self: 'a,
        T: 'a;

    fn ndim(&self) -> usize {
        2
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        match idx {
            0 => Some(self.len()),
            1 => Some(M),
            _ => None,
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, self.len() * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        <[[T; M]]>::iter(self).flatten()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(self.len() * M * std::mem::size_of::<T>())
    }
}

/// impl NdArrayView for three dimensions vector
impl<T: ArrayElement> NdArrayView<T> for Vec<Vec<Vec<T>>> {
    type Iter<'a>
        = std::iter::Flatten<std::iter::Flatten<std::slice::Iter<'a, Vec<Vec<T>>>>>
    where
        T: 'a;

    fn ndim(&self) -> usize {
        3
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        match idx {
            0 => Some(self.len()),
            1 => self.first().map(|v| v.len()),
            2 => self.first().and_then(|v2| v2.first()).map(|v3| v3.len()),
            _ => None,
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        None
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten().flatten()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        let dim1 = self.first().map_or(0, |v| v.len());

        if self.as_slice().iter().any(|v2| v2.len() != dim1) {
            return Err(error::fmt!(ArrayViewError, "Irregular array shape"));
        }

        let dim2 = self
            .first()
            .and_then(|v2| v2.first())
            .map_or(0, |v3| v3.len());

        if self
            .as_slice()
            .iter()
            .flat_map(|v2| v2.as_slice().iter())
            .any(|v3| v3.len() != dim2)
        {
            return Err(error::fmt!(ArrayViewError, "Irregular array shape"));
        }

        Ok(self.len() * dim1 * dim2 * std::mem::size_of::<T>())
    }
}

/// impl NdArrayView for three dimensions array
impl<T: ArrayElement, const M: usize, const N: usize, const L: usize> NdArrayView<T>
    for [[[T; M]; N]; L]
{
    type Iter<'a>
        = std::iter::Flatten<std::iter::Flatten<std::slice::Iter<'a, [[T; M]; N]>>>
    where
        T: 'a;

    fn ndim(&self) -> usize {
        3
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        match idx {
            0 => Some(L),
            1 => Some(N),
            2 => Some(M),
            _ => None,
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, L * N * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten().flatten()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(L * N * M * std::mem::size_of::<T>())
    }
}

impl<T: ArrayElement, const M: usize, const N: usize> NdArrayView<T> for &[[[T; M]; N]] {
    type Iter<'a>
        = std::iter::Flatten<std::iter::Flatten<std::slice::Iter<'a, [[T; M]; N]>>>
    where
        Self: 'a,
        T: 'a;

    fn ndim(&self) -> usize {
        3
    }

    fn dim(&self, idx: usize) -> Option<usize> {
        match idx {
            0 => Some(self.len()),
            1 => Some(N),
            2 => Some(M),
            _ => None,
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, self.len() * N * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        <[[[T; M]; N]]>::iter(self).flatten().flatten()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(self.len() * N * M * std::mem::size_of::<T>())
    }
}

use crate::{error, Error};
#[cfg(feature = "ndarray")]
use ndarray::{ArrayView, Axis, Dimension};
use std::io::IoSlice;
use std::slice;

#[cfg(feature = "ndarray")]
impl<T, D> NdArrayView<T> for ArrayView<'_, T, D>
where
    T: ArrayElement,
    D: Dimension,
{
    type Iter<'a>
        = ndarray::iter::Iter<'a, T, D>
    where
        Self: 'a,
        T: 'a;

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

    fn iter(&self) -> Self::Iter<'_> {
        self.iter()
    }

    fn as_slice(&self) -> Option<&[T]> {
        self.as_slice()
    }

    fn check_data_buf(&self) -> Result<usize, Error> {
        Ok(self.len() * size_of::<T>())
    }
}
