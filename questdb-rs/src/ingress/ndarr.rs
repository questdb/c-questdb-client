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
    fn dim(&self, index: usize) -> Result<usize, Error>;

    /// Return the array’s data as a slice, if it is c-major-layout.
    /// Return `None` otherwise.
    fn as_slice(&self) -> Option<&[T]>;

    /// Return an iterator of references to the elements of the array.
    /// Iterator element type is `&T`.
    fn iter(&self) -> Self::Iter<'_>;
}

// TODO: We should probably agree on a significantly
//       _smaller_ limit here, since there's no way
//       we've ever tested anything that big.
//       My gut feeling is that the maximum array buffer should be
//       in the order of 100MB or so.
const MAX_ARRAY_BUFFER_SIZE: usize = i32::MAX as usize;
pub(crate) const MAX_ARRAY_DIM_LEN: usize = 0x0FFF_FFFF; // 1 << 28 - 1

pub(crate) fn write_array_data<A: NdArrayView<T>, T>(
    array: &A,
    buf: &mut [u8],
    expect_size: usize,
) -> Result<(), Error>
where
    T: ArrayElement,
{
    // When working with contiguous layout, benchmark shows `copy_from_slice` has better performance than
    // `std::ptr::copy_nonoverlapping` on both Arm(Macos) and x86(Linux) platform.
    // This may because `copy_from_slice` benefits more from compiler.
    if let Some(contiguous) = array.as_slice() {
        let bytes = unsafe {
            slice::from_raw_parts(contiguous.as_ptr() as *const u8, size_of_val(contiguous))
        };

        if bytes.len() != expect_size {
            return Err(error::fmt!(
                ArrayWriteToBufferError,
                "Array write buffer length mismatch (actual: {}, expected: {})",
                expect_size,
                bytes.len()
            ));
        }

        if buf.len() < bytes.len() {
            return Err(error::fmt!(
                ArrayWriteToBufferError,
                "Buffer capacity {} < required {}",
                buf.len(),
                bytes.len()
            ));
        }

        buf[..bytes.len()].copy_from_slice(bytes);
        return Ok(());
    }

    // For non-contiguous memory layouts, direct raw pointer operations are preferred.
    let elem_size = size_of::<T>();
    let mut total_len = 0;
    for (i, &element) in array.iter().enumerate() {
        unsafe {
            std::ptr::copy_nonoverlapping(
                &element as *const T as *const u8,
                buf.as_mut_ptr().add(i * elem_size),
                elem_size,
            )
        }
        total_len += elem_size;
    }
    if total_len != expect_size {
        return Err(error::fmt!(
            ArrayWriteToBufferError,
            "Array write buffer length mismatch (actual: {}, expected: {})",
            total_len,
            expect_size
        ));
    }
    Ok(())
}

pub(crate) fn check_and_get_array_bytes_size<A: NdArrayView<T>, T>(
    array: &A,
) -> Result<usize, Error>
where
    T: ArrayElement,
{
    let mut size = std::mem::size_of::<T>();
    for dim_index in 0..array.ndim() {
        size *= array.dim(dim_index)?;
        if size > MAX_ARRAY_BUFFER_SIZE {
            return Err(error::fmt!(
                ArrayViewError,
                "Array buffer size too big: {}, maximum: {}",
                size,
                MAX_ARRAY_BUFFER_SIZE
            ));
        }
    }
    Ok(size)
}

/// Marker trait for valid array element types.
///
/// Implemented for primitive types that can be stored in arrays.
/// Combines type information with data type classification.
pub trait ArrayElement: Copy + 'static {}

pub(crate) trait ArrayElementSealed {
    /// Returns the binary format identifier for array element types compatible
    /// with QuestDB's io.questdb.cairo.ColumnType numeric type constants.
    fn type_tag() -> u8;
}

impl ArrayElement for f64 {}

impl ArrayElementSealed for f64 {
    fn type_tag() -> u8 {
        10 // Double
    }
}

/// A view into a multidimensional array with custom memory strides.
// TODO: We are currently evaluating whether to use StrideArrayView or ndarray's view.
//       Current benchmarks show that StrideArrayView's iter implementation underperforms(2x)
//       compared to ndarray's. If we proceed with StrideArrayView, we need to
//       optimize the iter traversal pattern
#[derive(Debug)]
pub struct StrideArrayView<'a, T> {
    dims: usize,
    shape: &'a [usize],
    strides: &'a [isize],
    data: Option<&'a [u8]>,
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

    fn dim(&self, index: usize) -> Result<usize, Error> {
        if index >= self.dims {
            return Err(error::fmt!(
                ArrayViewError,
                "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                index,
                self.dims
            ));
        }
        Ok(self.shape[index])
    }

    fn as_slice(&self) -> Option<&[T]> {
        unsafe {
            self.is_c_major().then_some(self.data.map(|data| {
                slice::from_raw_parts(data.as_ptr() as *const T, data.len() / size_of::<T>())
            })?)
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
        let base_ptr = match self.data {
            None => std::ptr::null(),
            Some(data) => {
                self.strides
                    .iter()
                    .enumerate()
                    .fold(data.as_ptr(), |ptr, (dim, &stride)| {
                        if stride < 0 {
                            let dim_size = self.shape[dim] as isize;
                            unsafe { ptr.offset(stride * (dim_size - 1)) }
                        } else {
                            ptr
                        }
                    })
            }
        };

        RowMajorIter {
            base_ptr,
            array: self,
            dim_products,
            current_linear: 0,
            total_elements: self.shape.iter().product(),
        }
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
    ) -> Result<Self, Error> {
        let shapes = slice::from_raw_parts(shape, dims);
        let size = shapes
            .iter()
            .try_fold(std::mem::size_of::<T>(), |acc, &dim| {
                acc.checked_mul(dim)
                    .ok_or_else(|| error::fmt!(ArrayViewError, "Array total elem size overflow"))
            })?;
        if size != data_len {
            return Err(error::fmt!(
                ArrayViewError,
                "Array buffer length mismatch (actual: {}, expected: {})",
                data_len,
                size
            ));
        }
        let strides = slice::from_raw_parts(strides, dims);
        let mut slice = None;
        if data_len != 0 {
            slice = Some(slice::from_raw_parts(data, data_len));
        }
        Ok(Self {
            dims,
            shape: shapes,
            strides,
            data: slice,
            _marker: std::marker::PhantomData::<T>,
        })
    }

    /// Verifies if the array follows C-style row-major memory layout.
    fn is_c_major(&self) -> bool {
        match self.data {
            None => false,
            Some(data) => {
                if data.is_empty() {
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
    }
}

/// Iterator for traversing a stride array in row-major (C-style) order.
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        if idx == 0 {
            Ok(self.len())
        } else {
            Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    1
                ))
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(self.as_slice())
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        if idx == 0 {
            Ok(N)
        } else {
            Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    1
                ))
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(self)
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter()
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        if idx == 0 {
            Ok(self.len())
        } else {
            Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    1
                ))
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(self)
    }

    fn iter(&self) -> Self::Iter<'_> {
        <[T]>::iter(self)
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        match idx {
            0 => Ok(self.len()),
            1 => {
                let dim1 = self.first().map_or(0, |v| v.len());
                if self.as_slice().iter().any(|v2| v2.len() != dim1) {
                    return Err(error::fmt!(ArrayViewError, "Irregular array shape"));
                }
                Ok(dim1)
            }
            _ => Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    2
                )),
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        None
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten()
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        match idx {
            0 => Ok(N),
            1 => Ok(M),
            _ => Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    2
                )),
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, N * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten()
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        match idx {
            0 => Ok(self.len()),
            1 => Ok(M),
            _ => Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    2
                )),
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, self.len() * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        <[[T; M]]>::iter(self).flatten()
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        match idx {
            0 => Ok(self.len()),
            1 => {
                let dim1 = self.first().map_or(0, |v| v.len());
                if self.as_slice().iter().any(|v2| v2.len() != dim1) {
                    return Err(error::fmt!(ArrayViewError, "Irregular array shape"));
                }
                Ok(dim1)
            }
            2 => {
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
                Ok(dim2)
            }
            _ => Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    3
                )),
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        None
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten().flatten()
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        match idx {
            0 => Ok(L),
            1 => Ok(N),
            2 => Ok(M),
            _ => Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    3
                )),
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, L * N * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.as_slice().iter().flatten().flatten()
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

    fn dim(&self, idx: usize) -> Result<usize, Error> {
        match idx {
            0 => Ok(self.len()),
            1 => Ok(N),
            2 => Ok(M),
            _ => Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    idx,
                    3
                )),
        }
    }

    fn as_slice(&self) -> Option<&[T]> {
        Some(unsafe { std::slice::from_raw_parts(self.as_ptr() as *const T, self.len() * N * M) })
    }

    fn iter(&self) -> Self::Iter<'_> {
        <[[[T; M]; N]]>::iter(self).flatten().flatten()
    }
}

use crate::{error, Error};
#[cfg(feature = "ndarray")]
use ndarray::{ArrayView, Axis, Dimension};
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

    fn dim(&self, index: usize) -> Result<usize, Error> {
        let len = self.ndim();
        if index < len {
            Ok(self.len_of(Axis(index)))
        } else {
            Err(error::fmt!(
                    ArrayViewError,
                    "Dimension index out of bounds. Requested axis {}, but array only has {} dimension(s)",
                    index,
                    3
                ))
        }
    }

    fn iter(&self) -> Self::Iter<'_> {
        self.iter()
    }

    fn as_slice(&self) -> Option<&[T]> {
        self.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_f64_element_type() {
        assert_eq!(<f64 as ArrayElementSealed>::type_tag(), 10);
    }
}
