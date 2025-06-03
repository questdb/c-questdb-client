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

use questdb::ingress::ArrayElement;
use questdb::ingress::NdArrayView;
use questdb::ingress::MAX_ARRAY_BUFFER_SIZE;
use questdb::Error;
use std::mem::size_of;
use std::slice;

macro_rules! fmt_error {
    ($code:ident, $($arg:tt)*) => {
        questdb::Error::new(
            questdb::ErrorCode::$code,
            format!($($arg)*))
    }
}

/// A view into a multidimensional array with custom memory strides.
// TODO: We are currently evaluating whether to use StrideArrayView or ndarray's view.
//       Current benchmarks show that StrideArrayView's iter implementation underperforms(2x)
//       compared to ndarray's.
//       We should optimise this implementation to be competitive.
//       Unfortunately, the `ndarray` crate does not support negative strides
//       which we need to support in this FFI crate for efficient iteration of
//       numpy arrays coming from Python without copying the data.
#[derive(Debug)]
pub struct StrideArrayView<'a, T, const N: isize> {
    dims: usize,
    shape: &'a [usize],
    strides: &'a [isize],
    data: Option<&'a [u8]>,
    _marker: std::marker::PhantomData<T>,
}

impl<T, const N: isize> NdArrayView<T> for StrideArrayView<'_, T, N>
where
    T: ArrayElement,
{
    type Iter<'b>
        = RowMajorIter<'b, T, N>
    where
        Self: 'b,
        T: 'b;

    fn ndim(&self) -> usize {
        self.dims
    }

    fn dim(&self, index: usize) -> Result<usize, Error> {
        if index >= self.dims {
            return Err(fmt_error!(
                ArrayError,
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
                        let stride_bytes_size = stride * N;
                        if stride_bytes_size < 0 {
                            let dim_size = self.shape[dim] as isize;
                            unsafe { ptr.offset(stride_bytes_size * (dim_size - 1)) }
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

impl<T, const N: isize> StrideArrayView<'_, T, N>
where
    T: ArrayElement,
{
    /// Creates a new strided array view from raw components (unsafe constructor).
    ///
    /// # Safety
    /// Caller must ensure all the following conditions:
    /// - `shape` points to a valid array of at least `dims` elements
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
        if dims == 0 {
            return Err(fmt_error!(
                ArrayError,
                "Zero-dimensional arrays are not supported",
            ));
        }
        if data_len > MAX_ARRAY_BUFFER_SIZE {
            return Err(fmt_error!(
                ArrayError,
                "Array buffer size too big: {}, maximum: {}",
                data_len,
                MAX_ARRAY_BUFFER_SIZE
            ));
        }
        let shape = slice::from_raw_parts(shape, dims);
        let size = shape
            .iter()
            .try_fold(std::mem::size_of::<T>(), |acc, &dim| {
                acc.checked_mul(dim)
                    .ok_or_else(|| fmt_error!(ArrayError, "Array buffer size too big"))
            })?;

        if size != data_len {
            return Err(fmt_error!(
                ArrayError,
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
            shape,
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
                    return self.strides[0] * N == elem_size || self.shape[0] == 1;
                }

                let mut expected_stride = elem_size;
                for (dim, &stride) in self.shape.iter().zip(self.strides).rev() {
                    if *dim > 1 && stride * N != expected_stride {
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
pub struct RowMajorIter<'a, T, const N: isize> {
    base_ptr: *const u8,
    array: &'a StrideArrayView<'a, T, N>,
    dim_products: Vec<usize>,
    current_linear: usize,
    total_elements: usize,
}

impl<'a, T, const N: isize> Iterator for RowMajorIter<'a, T, N>
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
            let stride = self.array.strides[dim] * N;
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

#[cfg(test)]
mod tests {
    use super::*;
    use questdb::ingress::*;
    use questdb::{Error, ErrorCode};
    use std::ptr;
    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn to_bytes<T: Copy>(data: &[T]) -> Vec<u8> {
        data.iter()
            .flat_map(|x| {
                let bytes = unsafe {
                    std::slice::from_raw_parts(x as *const T as *const u8, size_of::<T>())
                };
                bytes.to_vec()
            })
            .collect()
    }

    // Duplicated from `questdb::ingress::ndarr::write_array_data` to avoid leaking it to the public API.
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
                return Err(fmt_error!(
                    ArrayError,
                    "Array write buffer length mismatch (actual: {}, expected: {})",
                    expect_size,
                    bytes.len()
                ));
            }

            if buf.len() < bytes.len() {
                return Err(fmt_error!(
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
            return Err(fmt_error!(
                ArrayError,
                "Array write buffer length mismatch (actual: {}, expected: {})",
                total_len,
                expect_size
            ));
        }
        Ok(())
    }

    #[test]
    fn test_buffer_basic_write() -> TestResult {
        let elem_size = std::mem::size_of::<f64>() as isize;

        let test_data = [1.1, 2.2, 3.3, 4.4];
        let array_view: StrideArrayView<'_, f64, 1> = unsafe {
            StrideArrayView::new(
                2,
                [2, 2].as_ptr(),
                [2 * elem_size, elem_size].as_ptr(),
                test_data.as_ptr() as *const u8,
                test_data.len() * elem_size as usize,
            )
        }?;
        let mut buffer = Buffer::new(ProtocolVersion::V2);
        buffer.table("my_test")?;
        buffer.column_arr("temperature", &array_view)?;
        let data = buffer.as_bytes();
        assert_eq!(&data[0..7], b"my_test");
        assert_eq!(&data[8..19], b"temperature");
        assert_eq!(
            &data[19..24],
            &[
                b'=', b'=', 14u8, // ARRAY_BINARY_FORMAT_TYPE
                10u8, // ArrayColumnTypeTag::Double.into()
                2u8
            ]
        );
        assert_eq!(
            &data[24..32],
            [2i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
        );
        assert_eq!(
            &data[32..64],
            &[
                1.1f64.to_ne_bytes(),
                2.2f64.to_le_bytes(),
                3.3f64.to_le_bytes(),
                4.4f64.to_le_bytes(),
            ]
            .concat()
        );
        Ok(())
    }

    #[test]
    fn test_buffer_basic_write_with_elem_strides() -> TestResult {
        let elem_size = std::mem::size_of::<f64>() as isize;

        let test_data = [1.1, 2.2, 3.3, 4.4];
        let array_view: StrideArrayView<'_, f64, 8> = unsafe {
            StrideArrayView::new(
                2,
                [2, 2].as_ptr(),
                [2, 1].as_ptr(),
                test_data.as_ptr() as *const u8,
                test_data.len() * elem_size as usize,
            )
        }?;
        let mut buffer = Buffer::new(ProtocolVersion::V2);
        buffer.table("my_test")?;
        buffer.column_arr("temperature", &array_view)?;
        let data = buffer.as_bytes();
        assert_eq!(&data[0..7], b"my_test");
        assert_eq!(&data[8..19], b"temperature");
        assert_eq!(
            &data[19..24],
            &[
                b'=', b'=', 14u8, // ARRAY_BINARY_FORMAT_TYPE
                10u8, // ArrayColumnTypeTag::Double.into()
                2u8
            ]
        );
        assert_eq!(
            &data[24..32],
            [2i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
        );
        assert_eq!(
            &data[32..64],
            &[
                1.1f64.to_ne_bytes(),
                2.2f64.to_le_bytes(),
                3.3f64.to_le_bytes(),
                4.4f64.to_le_bytes(),
            ]
            .concat()
        );
        Ok(())
    }

    #[test]
    fn test_stride_array_size_overflow() -> TestResult {
        let result = unsafe {
            StrideArrayView::<f64, 1>::new(
                2,
                [u32::MAX as usize, u32::MAX as usize].as_ptr(),
                [8, 8].as_ptr(),
                ptr::null(),
                0,
            )
        };
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrayError);
        assert!(err.msg().contains("Array buffer size too big"));
        Ok(())
    }

    #[test]
    fn test_stride_view_length_mismatch() -> TestResult {
        let elem_size = size_of::<f64>() as isize;
        let under_data = [1.1];
        let result: Result<StrideArrayView<'_, f64, 1>, Error> = unsafe {
            StrideArrayView::new(
                2,
                [1, 2].as_ptr(),
                [elem_size, elem_size].as_ptr(),
                under_data.as_ptr() as *const u8,
                under_data.len() * elem_size as usize,
            )
        };
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrayError);
        assert!(err
            .msg()
            .contains("Array buffer length mismatch (actual: 8, expected: 16)"));

        let over_data = [1.1, 2.2, 3.3];
        let result: Result<StrideArrayView<'_, f64, 1>, Error> = unsafe {
            StrideArrayView::new(
                2,
                [1, 2].as_ptr(),
                [elem_size, elem_size].as_ptr(),
                over_data.as_ptr() as *const u8,
                over_data.len() * elem_size as usize,
            )
        };

        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrayError);
        assert!(err
            .msg()
            .contains("Array buffer length mismatch (actual: 24, expected: 16)"));
        Ok(())
    }

    #[test]
    fn test_stride_view_length_mismatch_with_elem_strides() -> TestResult {
        let elem_size = size_of::<f64>() as isize;
        let under_data = [1.1];
        let result: Result<StrideArrayView<'_, f64, 8>, Error> = unsafe {
            StrideArrayView::new(
                2,
                [1, 2].as_ptr(),
                [1, 1].as_ptr(),
                under_data.as_ptr() as *const u8,
                under_data.len() * elem_size as usize,
            )
        };
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrayError);
        assert!(err
            .msg()
            .contains("Array buffer length mismatch (actual: 8, expected: 16)"));

        let over_data = [1.1, 2.2, 3.3];
        let result: Result<StrideArrayView<'_, f64, 1>, Error> = unsafe {
            StrideArrayView::new(
                2,
                [1, 2].as_ptr(),
                [elem_size, elem_size].as_ptr(),
                over_data.as_ptr() as *const u8,
                over_data.len() * elem_size as usize,
            )
        };

        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrayError);
        assert!(err
            .msg()
            .contains("Array buffer length mismatch (actual: 24, expected: 16)"));
        Ok(())
    }

    #[test]
    fn test_strided_non_contiguous() -> TestResult {
        let elem_size = size_of::<f64>() as isize;
        let col_major_data = [1.0, 3.0, 5.0, 2.0, 4.0, 6.0];
        let shape = [3usize, 2];
        let strides = [elem_size, shape[0] as isize * elem_size];

        let array_view: StrideArrayView<'_, f64, 1> = unsafe {
            StrideArrayView::new(
                shape.len(),
                shape.as_ptr(),
                strides.as_ptr(),
                col_major_data.as_ptr() as *const u8,
                col_major_data.len() * elem_size as usize,
            )
        }?;

        assert_eq!(array_view.ndim(), 2);
        assert_eq!(array_view.dim(0), Ok(3));
        assert_eq!(array_view.dim(1), Ok(2));
        assert!(array_view.dim(2).is_err());
        assert!(array_view.as_slice().is_none());

        let mut buffer = vec![0u8; 48];
        write_array_data(&array_view, &mut buffer, 48)?;

        let expected_data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let expected_bytes = unsafe {
            std::slice::from_raw_parts(
                expected_data.as_ptr() as *const u8,
                expected_data.len() * elem_size as usize,
            )
        };
        assert_eq!(buffer, expected_bytes);
        Ok(())
    }

    #[test]
    fn test_strided_non_contiguous_with_elem_strides() -> TestResult {
        let elem_size = size_of::<f64>() as isize;
        let col_major_data = [1.0, 3.0, 5.0, 2.0, 4.0, 6.0];
        let shape = [3usize, 2];
        let strides = [1, shape[0] as isize];

        let array_view: StrideArrayView<'_, f64, 8> = unsafe {
            StrideArrayView::new(
                shape.len(),
                shape.as_ptr(),
                strides.as_ptr(),
                col_major_data.as_ptr() as *const u8,
                col_major_data.len() * elem_size as usize,
            )
        }?;

        assert_eq!(array_view.ndim(), 2);
        assert_eq!(array_view.dim(0), Ok(3));
        assert_eq!(array_view.dim(1), Ok(2));
        assert!(array_view.dim(2).is_err());
        assert!(array_view.as_slice().is_none());

        let mut buffer = vec![0u8; 48];
        write_array_data(&array_view, &mut buffer, 48)?;

        let expected_data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let expected_bytes = unsafe {
            std::slice::from_raw_parts(
                expected_data.as_ptr() as *const u8,
                expected_data.len() * elem_size as usize,
            )
        };
        assert_eq!(buffer, expected_bytes);
        Ok(())
    }

    #[test]
    fn test_negative_strides() -> TestResult {
        let elem_size = size_of::<f64>();
        let data = [1f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0];
        let view = unsafe {
            StrideArrayView::<f64, 1>::new(
                2,
                &[3usize, 3] as *const usize,
                &[-24isize, 8] as *const isize,
                (data.as_ptr() as *const u8).add(48),
                data.len() * elem_size,
            )
        }?;
        let collected: Vec<_> = view.iter().copied().collect();
        assert!(view.as_slice().is_none());
        let expected_data = vec![7.0, 8.0, 9.0, 4.0, 5.0, 6.0, 1.0, 2.0, 3.0];
        assert_eq!(collected, expected_data);
        let mut buffer = vec![0u8; 72];
        write_array_data(&view, &mut buffer, 72)?;
        let expected_bytes = unsafe {
            std::slice::from_raw_parts(
                expected_data.as_ptr() as *const u8,
                expected_data.len() * elem_size,
            )
        };
        assert_eq!(buffer, expected_bytes);
        Ok(())
    }

    #[test]
    fn test_negative_strides_with_elem_strides() -> TestResult {
        let elem_size = size_of::<f64>();
        let data = [1f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0];
        let view = unsafe {
            StrideArrayView::<f64, 8>::new(
                2,
                &[3usize, 3] as *const usize,
                &[-3isize, 1] as *const isize,
                (data.as_ptr() as *const u8).add(48),
                data.len() * elem_size,
            )
        }?;
        let collected: Vec<_> = view.iter().copied().collect();
        assert!(view.as_slice().is_none());
        let expected_data = vec![7.0, 8.0, 9.0, 4.0, 5.0, 6.0, 1.0, 2.0, 3.0];
        assert_eq!(collected, expected_data);
        let mut buffer = vec![0u8; 72];
        write_array_data(&view, &mut buffer, 72)?;
        let expected_bytes = unsafe {
            std::slice::from_raw_parts(
                expected_data.as_ptr() as *const u8,
                expected_data.len() * elem_size,
            )
        };
        assert_eq!(buffer, expected_bytes);
        Ok(())
    }

    #[test]
    fn test_basic_edge_cases() -> TestResult {
        // empty array
        let elem_size = std::mem::size_of::<f64>() as isize;
        let empty_view: StrideArrayView<'_, f64, 1> =
            unsafe { StrideArrayView::new(2, [0, 0].as_ptr(), [0, 0].as_ptr(), ptr::null(), 0)? };
        assert_eq!(empty_view.ndim(), 2);
        assert_eq!(empty_view.dim(0), Ok(0));
        assert_eq!(empty_view.dim(1), Ok(0));

        // single element array
        let single_data = [42.0];
        let single_view: StrideArrayView<'_, f64, 1> = unsafe {
            StrideArrayView::new(
                1,
                [1].as_ptr(),
                [elem_size].as_ptr(),
                single_data.as_ptr() as *const u8,
                elem_size as usize,
            )
        }?;
        let mut buf = vec![0u8; 8];
        write_array_data(&single_view, &mut buf, 8).unwrap();
        assert_eq!(buf, 42.0f64.to_ne_bytes());
        Ok(())
    }

    #[test]
    fn test_stride_array_view() -> TestResult {
        // contiguous layout
        let test_data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let shape = [2usize, 3];
        let strides = [
            (shape[1] * size_of::<f64>()) as isize,
            size_of::<f64>() as isize,
        ];
        let array = unsafe {
            StrideArrayView::<f64, 1>::new(
                shape.len(),
                shape.as_ptr(),
                strides.as_ptr(),
                test_data.as_ptr() as *const u8,
                test_data.len() * size_of::<f64>(),
            )
        }?;

        assert_eq!(array.ndim(), 2);
        assert_eq!(array.dim(0), Ok(2));
        assert_eq!(array.dim(1), Ok(3));
        assert!(array.dim(2).is_err());
        assert!(array.as_slice().is_some());
        let mut buf = vec![0u8; 48];
        write_array_data(&array, &mut buf, 48).unwrap();
        let expected = to_bytes(&test_data);
        assert_eq!(buf, expected);
        Ok(())
    }

    #[test]
    fn test_stride_array_view_strides_with_elem_strides() -> TestResult {
        // contiguous layout
        let test_data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let shape = [2usize, 3];
        let strides = [shape[1] as isize, 1];
        let array = unsafe {
            StrideArrayView::<f64, { std::mem::size_of::<f64>() as isize }>::new(
                shape.len(),
                shape.as_ptr(),
                strides.as_ptr(),
                test_data.as_ptr() as *const u8,
                test_data.len() * size_of::<f64>(),
            )
        }?;

        assert_eq!(array.ndim(), 2);
        assert_eq!(array.dim(0), Ok(2));
        assert_eq!(array.dim(1), Ok(3));
        assert!(array.dim(2).is_err());
        assert!(array.as_slice().is_some());
        let mut buf = vec![0u8; 48];
        write_array_data(&array, &mut buf, 48).unwrap();
        let expected = to_bytes(&test_data);
        assert_eq!(buf, expected);
        Ok(())
    }

    #[test]
    fn test_stride_minus_non_contiguous_strides_array() -> TestResult {
        let test_data = [
            1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0,
        ];
        let shape = [2usize, 2];
        let strides = [-8, -2];
        let array = unsafe {
            StrideArrayView::<f64, { std::mem::size_of::<f64>() as isize }>::new(
                shape.len(),
                shape.as_ptr(),
                strides.as_ptr(),
                test_data.as_ptr().add(11) as *const u8,
                4 * size_of::<f64>(),
            )
        }?;

        let test_data1 = vec![12.0f64, 10.0, 4.0, 2.0];
        let mut buf = vec![0u8; 32];
        write_array_data(&array, &mut buf, 32).unwrap();
        let expected = to_bytes(&test_data1);
        assert_eq!(buf, expected);
        Ok(())
    }
}
