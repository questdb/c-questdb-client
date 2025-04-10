#[cfg(feature = "ndarray")]
use crate::ingress::MAX_DIMS;
use crate::ingress::{
    ArrayElement, Buffer, ElemDataType, NdArrayView, StridedArrayView, ARRAY_BINARY_FORMAT_TYPE,
};
use crate::tests::TestResult;
use crate::ErrorCode;

use crate::ingress::ndarr::write_array_data;
#[cfg(feature = "ndarray")]
use ndarray::{arr1, arr2, arr3, s, ArrayD};
#[cfg(feature = "ndarray")]
use std::iter;
use std::ptr;

#[test]
fn test_f64_element_type() {
    assert_eq!(<f64 as ArrayElement>::elem_type(), ElemDataType::Double);
    assert_eq!(u8::from(ElemDataType::Double), 10);
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
fn test_strided_array_view() -> TestResult {
    // contiguous layout
    let test_data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
    let shapes = [2u32, 3];
    let strides = [
        (shapes[1] * size_of::<f64>() as u32) as i32,
        size_of::<f64>() as i32,
    ];
    let array = unsafe {
        StridedArrayView::<f64>::new(
            shapes.len(),
            shapes.as_ptr(),
            strides.as_ptr(),
            test_data.as_ptr() as *const u8,
            test_data.len() * size_of::<f64>(),
        )
    };

    assert_eq!(array.ndim(), 2);
    assert_eq!(array.dim(0), Some(2));
    assert_eq!(array.dim(1), Some(3));
    assert_eq!(array.dim(2), None);
    assert!(array.as_slice().is_some());
    let mut buf = vec![];
    write_array_data(&array, &mut buf).unwrap();
    let expected = to_bytes(&test_data);
    assert_eq!(buf, expected);
    Ok(())
}

#[test]
fn test_strided_non_contiguous() -> TestResult {
    let elem_size = size_of::<f64>() as i32;
    let col_major_data = [1.0, 3.0, 5.0, 2.0, 4.0, 6.0];
    let shapes = [3u32, 2];
    let strides = [elem_size, shapes[0] as i32 * elem_size];

    let array_view: StridedArrayView<'_, f64> = unsafe {
        StridedArrayView::new(
            shapes.len(),
            shapes.as_ptr(),
            strides.as_ptr(),
            col_major_data.as_ptr() as *const u8,
            col_major_data.len() * elem_size as usize,
        )
    };

    assert_eq!(array_view.ndim(), 2);
    assert_eq!(array_view.dim(0), Some(3));
    assert_eq!(array_view.dim(1), Some(2));
    assert_eq!(array_view.dim(2), None);
    assert!(array_view.as_slice().is_none());
    let mut buffer = Vec::new();
    write_array_data(&array_view, &mut buffer)?;

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
        StridedArrayView::<f64>::new(
            2,
            &[3u32, 3] as *const u32,
            &[-24i32, 8] as *const i32,
            (data.as_ptr() as *const u8).add(48),
            data.len() * elem_size,
        )
    };
    let collected: Vec<_> = view.iter().copied().collect();
    assert!(view.as_slice().is_none());
    let expected_data = vec![7.0, 8.0, 9.0, 4.0, 5.0, 6.0, 1.0, 2.0, 3.0];
    assert_eq!(collected, expected_data);
    let mut buffer = Vec::new();
    write_array_data(&view, &mut buffer)?;
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
fn test_basic_edge_cases() {
    // empty array
    let elem_size = std::mem::size_of::<f64>() as i32;
    let empty_view: StridedArrayView<'_, f64> =
        unsafe { StridedArrayView::new(2, [0, 0].as_ptr(), [0, 0].as_ptr(), ptr::null(), 0) };
    assert_eq!(empty_view.ndim(), 2);
    assert_eq!(empty_view.dim(0), Some(0));
    assert_eq!(empty_view.dim(1), Some(0));

    // single element array
    let single_data = [42.0];
    let single_view: StridedArrayView<'_, f64> = unsafe {
        StridedArrayView::new(
            2,
            [1, 1].as_ptr(),
            [elem_size, elem_size].as_ptr(),
            single_data.as_ptr() as *const u8,
            elem_size as usize,
        )
    };
    let mut buf = vec![];
    write_array_data(&single_view, &mut buf).unwrap();
    assert_eq!(buf, 42.0f64.to_ne_bytes());
}

#[test]
fn test_buffer_basic_write() -> TestResult {
    let elem_size = std::mem::size_of::<f64>() as i32;

    let test_data = [1.1, 2.2, 3.3, 4.4];
    let array_view: StridedArrayView<'_, f64> = unsafe {
        StridedArrayView::new(
            2,
            [2, 2].as_ptr(),
            [2 * elem_size, elem_size].as_ptr(),
            test_data.as_ptr() as *const u8,
            test_data.len() * elem_size as usize,
        )
    };
    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    buffer.column_arr("temperature", &array_view)?;
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
fn test_size_overflow() -> TestResult {
    let overflow_view = unsafe {
        StridedArrayView::<f64>::new(
            2,
            [u32::MAX, u32::MAX].as_ptr(),
            [8, 8].as_ptr(),
            ptr::null(),
            0,
        )
    };

    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let result = buffer.column_arr("arr1", &overflow_view);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err.msg().contains("Array total elem size overflow"));
    Ok(())
}

#[test]
fn test_array_length_mismatch() -> TestResult {
    let elem_size = size_of::<f64>() as i32;
    let under_data = [1.1];
    let under_view: StridedArrayView<'_, f64> = unsafe {
        StridedArrayView::new(
            2,
            [1, 2].as_ptr(),
            [elem_size, elem_size].as_ptr(),
            under_data.as_ptr() as *const u8,
            under_data.len() * elem_size as usize,
        )
    };

    let mut buffer = Buffer::new();
    buffer.table("my_test")?;
    let result = buffer.column_arr("arr1", &under_view);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayWriteToBufferError);
    assert!(err
        .msg()
        .contains("Array buffer length mismatch (actual: 8, expected: 16)"));

    let over_data = [1.1, 2.2, 3.3];
    let over_view: StridedArrayView<'_, f64> = unsafe {
        StridedArrayView::new(
            2,
            [1, 2].as_ptr(),
            [elem_size, elem_size].as_ptr(),
            over_data.as_ptr() as *const u8,
            over_data.len() * elem_size as usize,
        )
    };

    buffer.clear();
    buffer.table("my_test")?;
    let result = buffer.column_arr("arr1", &over_view);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayWriteToBufferError);
    assert!(err
        .msg()
        .contains("Array buffer length mismatch (actual: 24, expected: 16)"));
    Ok(())
}

#[cfg(feature = "ndarray")]
#[test]
fn test_1d_contiguous_ndarray_buffer() -> TestResult {
    let array = arr1(&[1.0, 2.0, 3.0, 4.0]);
    let view = array.view();
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    write_array_data(&view, &mut &mut buf[0..])?;
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
    write_array_data(&transposed, &mut &mut buf[0..])?;
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
    write_array_data(&strided_view, &mut &mut buf[0..])?;

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
    let shape: Vec<usize> = iter::repeat_n(1, MAX_DIMS).collect();
    let array = ArrayD::<f64>::zeros(shape.clone());
    buffer.column_arr("max_dim", &array.view())?;
    let data = buffer.as_bytes();
    assert_eq!(data[19], MAX_DIMS as u8);

    // 33 dims error
    let shape_invalid: Vec<_> = iter::repeat_n(1, MAX_DIMS + 1).collect();
    let array_invalid = ArrayD::<f64>::zeros(shape_invalid);
    let result = buffer.column_arr("invalid", &array_invalid.view());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayHasTooManyDims);
    Ok(())
}
