/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

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
                ArrayError,
                "Array write buffer length mismatch (actual: {}, expected: {})",
                expect_size,
                bytes.len()
            ));
        }

        if buf.len() < bytes.len() {
            return Err(error::fmt!(
                ArrayError,
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
            ArrayError,
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
        let dim = array.dim(dim_index)?;
        if dim > MAX_ARRAY_DIM_LEN {
            return Err(error::fmt!(
                ArrayError,
                "dimension length out of range: dim {}, dim length {}, max length {}",
                dim_index,
                dim,
                MAX_ARRAY_DIM_LEN
            ));
        }
        // following dimension's length may be zero, so check the size in out of loop
        size *= dim;
    }

    if size > MAX_ARRAY_BUFFER_SIZE {
        return Err(error::fmt!(
            ArrayError,
            "Array buffer size too big: {}, maximum: {}",
            size,
            MAX_ARRAY_BUFFER_SIZE
        ));
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
                    ArrayError,
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
                    ArrayError,
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
                    ArrayError,
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
                    return Err(error::fmt!(ArrayError, "Irregular array shape"));
                }
                Ok(dim1)
            }
            _ => Err(error::fmt!(
                    ArrayError,
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
                    ArrayError,
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
                    ArrayError,
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
                    return Err(error::fmt!(ArrayError, "Irregular array shape"));
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
                    return Err(error::fmt!(ArrayError, "Irregular array shape"));
                }
                Ok(dim2)
            }
            _ => Err(error::fmt!(
                    ArrayError,
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
                    ArrayError,
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
                    ArrayError,
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

use super::{MAX_ARRAY_BUFFER_SIZE, MAX_ARRAY_DIM_LEN};

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
                    ArrayError,
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
