use crate::ingress::ndarr;
use crate::ingress::ndarr::NdArrayView;
use ndarray::{arr1, arr2, arr3, s};

#[test]
fn test_f64_element_type() {
    assert_eq!(<f64 as ndarr::ArrayElement>::elem_type(), ndarr::ElemDataType::Double);
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
        [13.0, 14.0, 15.0, 16.0]
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
