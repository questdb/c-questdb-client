#[cfg(feature = "ndarray")]
use crate::ingress::MAX_DIMS;
use crate::ingress::{ArrayElement, Buffer, ElemDataType, NdArrayView, ARRAY_BINARY_FORMAT_TYPE};
use crate::tests::TestResult;
use crate::ErrorCode;

#[cfg(feature = "ndarray")]
use ndarray::{arr1, arr2, arr3, s, ArrayD};
#[cfg(feature = "ndarray")]
use std::iter;
use std::marker::PhantomData;

#[test]
fn test_f64_element_type() {
    assert_eq!(<f64 as ArrayElement>::elem_type(), ElemDataType::Double);
    assert_eq!(u8::from(ElemDataType::Double), 10);
}

struct Array2D<T> {
    data: Vec<T>,
    rows: usize,
    cols: usize,
    contiguous: bool,
}

impl<T: ArrayElement> Array2D<T> {
    fn new(data: Vec<T>, rows: usize, cols: usize, contiguous: bool) -> Self {
        Self {
            data,
            rows,
            cols,
            contiguous,
        }
    }
}

impl<T: ArrayElement> NdArrayView<T> for Array2D<T> {
    fn ndim(&self) -> usize {
        2
    }

    fn dim(&self, index: usize) -> Option<usize> {
        match index {
            0 => Some(self.rows),
            1 => Some(self.cols),
            _ => None,
        }
    }

    fn write_row_major<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        if self.contiguous {
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    self.data.as_ptr() as *const u8,
                    self.data.len() * std::mem::size_of::<T>(),
                )
            };
            return writer.write_all(bytes);
        }

        for chunk in self.data.chunks(self.cols) {
            let bytes = unsafe {
                std::slice::from_raw_parts(chunk.as_ptr() as *const u8, size_of_val(chunk))
            };
            writer.write_all(bytes)?;
        }
        Ok(())
    }
}

fn to_bytes<T: Copy>(data: &[T]) -> Vec<u8> {
    data.iter()
        .flat_map(|x| {
            let bytes =
                unsafe { std::slice::from_raw_parts(x as *const T as *const u8, size_of::<T>()) };
            bytes.to_vec()
        })
        .collect()
}

#[test]
fn test_basic_array_view() {
    // contiguous layout
    let test_data = vec![1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0];
    let array = Array2D::new(test_data.clone(), 2, 3, true);
    assert_eq!(array.ndim(), 2);
    assert_eq!(array.dim(0), Some(2));
    assert_eq!(array.dim(1), Some(3));
    assert_eq!(array.dim(2), None);
    let mut buf = vec![];
    array.write_row_major(&mut buf).unwrap();
    let expected = to_bytes(&test_data);
    assert_eq!(buf, expected);

    // non-contiguous layout
    let test_data = vec![vec![1.0, 2.0], vec![3.0, 4.0], vec![5.0, 6.0]]
        .into_iter()
        .flatten()
        .collect();
    let array_non_contig = Array2D::new(test_data, 3, 2, false);
    let mut buf_non_contig = vec![];
    array_non_contig
        .write_row_major(&mut buf_non_contig)
        .unwrap();
    let expected_non_contig = to_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
    assert_eq!(buf_non_contig, expected_non_contig);
}

#[test]
fn test_basic_edge_cases() {
    // empty array
    let empty_array = Array2D::<f64>::new(vec![], 0, 0, false);
    assert_eq!(empty_array.ndim(), 2);
    assert_eq!(empty_array.dim(0), Some(0));
    assert_eq!(empty_array.dim(1), Some(0));

    // single element array
    let single = Array2D::new(vec![42.0], 1, 1, true);
    let mut buf = vec![];
    single.write_row_major(&mut buf).unwrap();
    assert_eq!(buf, 42.0f64.to_ne_bytes().to_vec());
}

#[test]
fn test_buffer_basic_write() -> TestResult {
    let test_data = vec![1.1f64, 2.2, 3.3, 4.4];
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let array_2d = Array2D::<f64>::new(test_data, 2, 2, true);
    buffer.column_arr("temperature", &array_2d)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ElemDataType::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[24..32],
        [2i32.to_le_bytes().as_slice(), 2i32.to_le_bytes().as_slice()].concat()
    );
    Ok(())
}

#[test]
fn test_invalid_dimension() -> TestResult {
    struct InvalidDimArray;
    impl NdArrayView<f64> for InvalidDimArray {
        fn ndim(&self) -> usize {
            2
        }
        fn dim(&self, _: usize) -> Option<usize> {
            None
        }
        fn write_row_major<W: std::io::Write>(&self, _: &mut W) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let result = buffer.column_arr("arr1", &InvalidDimArray);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err
        .msg()
        .contains("Can not get correct dimensions for dim 0"));
    Ok(())
}

#[test]
fn test_size_overflow() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let data = vec![1.0f64];
    let arr = Array2D::<f64> {
        data,
        rows: usize::MAX,
        cols: usize::MAX,
        contiguous: false,
    };

    let result = buffer.column_arr("arr1", &arr);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err.msg().contains("Array total elem size overflow"));
    Ok(())
}

#[test]
fn test_write_failure() -> TestResult {
    struct FaultyArray<T>(PhantomData<T>);
    impl<T: ArrayElement> NdArrayView<T> for FaultyArray<T> {
        fn ndim(&self) -> usize {
            2
        }
        fn dim(&self, _: usize) -> Option<usize> {
            Some(1)
        }
        fn write_row_major<W: std::io::Write>(&self, _: &mut W) -> std::io::Result<()> {
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "mock write error",
            ))
        }
    }
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let result = buffer.column_arr("arr1", &FaultyArray(PhantomData::<f64>));
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayWriteToBufferError);
    assert!(err
        .msg()
        .contains("Can not write row major to writer: mock write error"));
    Ok(())
}

#[test]
fn test_array_length_mismatch() -> TestResult {
    // actual data length is larger than shapes
    let test_data = vec![1.1f64, 2.2, 3.3, 4.4];
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let array_2d = Array2D::<f64>::new(test_data, 1, 2, true);
    let result = buffer.column_arr("arr1", &array_2d);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayWriteToBufferError);
    assert!(err
        .msg()
        .contains("Can not write row major to writer: failed to write whole buffer"));
    buffer.clear();

    // actual data length is less than shapes
    let test_data = vec![1.1f64];
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let array_2d = Array2D::<f64>::new(test_data, 1, 2, true);
    let result = buffer.column_arr("arr1", &array_2d);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayWriteToBufferError);
    assert!(err
        .msg()
        .contains("Array write buffer length mismatch (actual: 8, expected: 16)"));
    buffer.clear();

    // non-contiguous layout
    let test_data = vec![1.1f64];
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let array_2d = Array2D::<f64>::new(test_data, 1, 2, false);
    let result = buffer.column_arr("arr1", &array_2d);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayWriteToBufferError);
    assert!(err
        .msg()
        .contains("Array write buffer length mismatch (actual: 8, expected: 16)"));
    Ok(())
}

#[cfg(feature = "ndarray")]
#[test]
fn test_1d_contiguous_ndarray_buffer() -> TestResult {
    let array = arr1(&[1.0, 2.0, 3.0, 4.0]);
    let view = array.view();
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    view.write_row_major(&mut &mut buf[0..])?;
    let expected: Vec<u8> = array
        .iter()
        .flat_map(|&x| x.to_ne_bytes().to_vec())
        .collect();
    assert_eq!(buf, expected);
    Ok(())
}

#[cfg(feature = "ndarray")]
#[test]
fn test_2d_non_contiguous_ndarray_buffer() -> TestResult {
    let array = arr2(&[[1.0, 2.0], [3.0, 4.0]]);
    let transposed = array.view().reversed_axes();
    assert!(!transposed.is_standard_layout());
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    transposed.write_row_major(&mut &mut buf[0..])?;
    let expected = [1.0f64, 3.0, 2.0, 4.0]
        .iter()
        .flat_map(|&x| x.to_ne_bytes())
        .collect::<Vec<_>>();
    assert_eq!(buf, expected);
    Ok(())
}

#[cfg(feature = "ndarray")]
#[test]
fn test_strided_ndarray_layout() -> TestResult {
    let array = arr2(&[
        [1.0, 2.0, 3.0, 4.0],
        [5.0, 6.0, 7.0, 8.0],
        [9.0, 10.0, 11.0, 12.0],
        [13.0, 14.0, 15.0, 16.0],
    ]);
    let strided_view = array.slice(s![1..;2, 1..;2]);
    assert_eq!(strided_view.dim(), (2, 2));
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    strided_view.write_row_major(&mut &mut buf[0..])?;

    // expect：6.0, 8.0, 14.0, 16.0
    let expected = [6.0f64, 8.0, 14.0, 16.0]
        .iter()
        .flat_map(|&x| x.to_ne_bytes())
        .collect::<Vec<_>>();

    assert_eq!(buf, expected);
    Ok(())
}

#[cfg(feature = "ndarray")]
#[test]
fn test_1d_dimension_ndarray_info() {
    let array = arr1(&[1.0, 2.0, 3.0]);
    let view = array.view();

    assert_eq!(NdArrayView::ndim(&view), 1);
    assert_eq!(NdArrayView::dim(&view, 0), Some(3));
    assert_eq!(NdArrayView::dim(&view, 1), None);
}

#[cfg(feature = "ndarray")]
#[test]
fn test_complex_ndarray_dimensions() {
    let array = arr3(&[[[1.0], [2.0]], [[3.0], [4.0]]]);
    let view = array.view();

    assert_eq!(NdArrayView::ndim(&view), 3);
    assert_eq!(NdArrayView::dim(&view, 0), Some(2));
    assert_eq!(NdArrayView::dim(&view, 1), Some(2));
    assert_eq!(NdArrayView::dim(&view, 2), Some(1));
}

#[cfg(feature = "ndarray")]
#[test]
fn test_buffer_ndarray_write() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let array_2d = arr2(&[[1.1, 2.2], [3.3, 4.4]]);
    buffer.column_arr("temperature", &array_2d.view())?;

    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ElemDataType::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[24..32],
        [2i32.to_le_bytes().as_slice(), 2i32.to_le_bytes().as_slice()].concat()
    );
    Ok(())
}

#[cfg(feature = "ndarray")]
#[test]
fn test_buffer_write_ndarray_max_dimensions() -> TestResult {
    let mut buffer = Buffer::new();
    buffer.table("nd_test")?;
    let shape: Vec<usize> = iter::repeat(1).take(MAX_DIMS).collect();
    let array = ArrayD::<f64>::zeros(shape.clone());
    buffer.column_arr("max_dim", &array.view())?;
    let data = buffer.as_bytes();
    assert_eq!(data[19], MAX_DIMS as u8);

    // 33 dims error
    let shape_invalid: Vec<_> = iter::repeat(1).take(MAX_DIMS + 1).collect();
    let array_invalid = ArrayD::<f64>::zeros(shape_invalid);
    let result = buffer.column_arr("invalid", &array_invalid.view());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayHasTooManyDims);
    Ok(())
}
