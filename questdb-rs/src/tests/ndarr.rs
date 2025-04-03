use crate::ingress::ndarr::{ElemDataType, NdArrayView, MAX_DIMS};
use crate::ingress::{ndarr, Buffer};
use crate::tests::TestResult;
use crate::{ingress, ErrorCode};
use ndarray::{arr1, arr2, arr3, s, ArrayD};
use std::iter;

#[test]
fn test_f64_element_type() {
    assert_eq!(
        <f64 as ndarr::ArrayElement>::elem_type(),
        ndarr::ElemDataType::Double
    );
    assert_eq!(u8::from(ndarr::ElemDataType::Double), 10);
}

#[test]
fn test_1d_contiguous_buffer() {
    let array = arr1(&[1.0, 2.0, 3.0, 4.0]);
    let view = array.view();
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    view.write_row_major_buf(&mut buf);
    let expected: Vec<u8> = array
        .iter()
        .flat_map(|&x| x.to_ne_bytes().to_vec())
        .collect();
    assert_eq!(buf, expected);
}

#[test]
fn test_2d_non_contiguous_buffer() {
    let array = arr2(&[[1.0, 2.0], [3.0, 4.0]]);
    let transposed = array.view().reversed_axes();
    assert!(!transposed.is_standard_layout());
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    transposed.write_row_major_buf(&mut buf);
    let expected = [1.0f64, 3.0, 2.0, 4.0]
        .iter()
        .flat_map(|&x| x.to_ne_bytes())
        .collect::<Vec<_>>();
    assert_eq!(buf, expected);
}

#[test]
fn test_strided_layout() {
    let array = arr2(&[
        [1.0, 2.0, 3.0, 4.0],
        [5.0, 6.0, 7.0, 8.0],
        [9.0, 10.0, 11.0, 12.0],
        [13.0, 14.0, 15.0, 16.0],
    ]);
    let strided_view = array.slice(s![1..;2, 1..;2]);
    assert_eq!(strided_view.dim(), (2, 2));
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    strided_view.write_row_major_buf(&mut buf);

    // expect：6.0, 8.0, 14.0, 16.0
    let expected = [6.0f64, 8.0, 14.0, 16.0]
        .iter()
        .flat_map(|&x| x.to_ne_bytes())
        .collect::<Vec<_>>();

    assert_eq!(buf, expected);
}

#[test]
fn test_1d_dimension_info() {
    let array = arr1(&[1.0, 2.0, 3.0]);
    let view = array.view();

    assert_eq!(NdArrayView::ndim(&view), 1);
    assert_eq!(NdArrayView::dim(&view, 0), Some(3));
    assert_eq!(NdArrayView::dim(&view, 1), None);
}

#[test]
fn test_complex_dimensions() {
    let array = arr3(&[[[1.0], [2.0]], [[3.0], [4.0]]]);
    let view = array.view();

    assert_eq!(NdArrayView::ndim(&view), 3);
    assert_eq!(NdArrayView::dim(&view, 0), Some(2));
    assert_eq!(NdArrayView::dim(&view, 1), Some(2));
    assert_eq!(NdArrayView::dim(&view, 2), Some(1));
}

#[test]
fn test_buffer_array_write() -> TestResult {
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
            ingress::ARRAY_BINARY_FORMAT_TYPE,
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
fn test_buffer_write_max_dimensions() -> TestResult {
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
