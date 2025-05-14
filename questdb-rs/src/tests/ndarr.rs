#[cfg(feature = "ndarray")]
use crate::ingress::MAX_ARRAY_DIMS;
use crate::ingress::{
    Buffer, NdArrayView, ProtocolVersion, StrideArrayView, ARRAY_BINARY_FORMAT_TYPE,
};
use crate::tests::TestResult;
use crate::{Error, ErrorCode};

use crate::ingress::ndarr::write_array_data;
#[cfg(feature = "ndarray")]
use ndarray::{arr1, arr2, arr3, s, ArrayD};
#[cfg(feature = "ndarray")]
use std::iter;
use std::ptr;

/// QuestDB column type tags that are supported as array element types.
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum ArrayColumnTypeTag {
    Double = 10,
}

impl ArrayColumnTypeTag {
    pub fn size(&self) -> usize {
        match self {
            ArrayColumnTypeTag::Double => std::mem::size_of::<f64>(),
        }
    }
}

impl From<ArrayColumnTypeTag> for u8 {
    fn from(tag: ArrayColumnTypeTag) -> Self {
        tag as u8
    }
}

impl TryFrom<u8> for ArrayColumnTypeTag {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            10 => Ok(ArrayColumnTypeTag::Double),
            _ => Err(format!("Unsupported column type tag {} for arrays", value)),
        }
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
fn test_stride_array_view() -> TestResult {
    // contiguous layout
    let test_data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
    let shapes = [2usize, 3];
    let strides = [
        (shapes[1] * size_of::<f64>()) as isize,
        size_of::<f64>() as isize,
    ];
    let array = unsafe {
        StrideArrayView::<f64>::new(
            shapes.len(),
            shapes.as_ptr(),
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
fn test_strided_non_contiguous() -> TestResult {
    let elem_size = size_of::<f64>() as isize;
    let col_major_data = [1.0, 3.0, 5.0, 2.0, 4.0, 6.0];
    let shapes = [3usize, 2];
    let strides = [elem_size, shapes[0] as isize * elem_size];

    let array_view: StrideArrayView<'_, f64> = unsafe {
        StrideArrayView::new(
            shapes.len(),
            shapes.as_ptr(),
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
        StrideArrayView::<f64>::new(
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
fn test_basic_edge_cases() -> TestResult {
    // empty array
    let elem_size = std::mem::size_of::<f64>() as isize;
    let empty_view: StrideArrayView<'_, f64> =
        unsafe { StrideArrayView::new(2, [0, 0].as_ptr(), [0, 0].as_ptr(), ptr::null(), 0)? };
    assert_eq!(empty_view.ndim(), 2);
    assert_eq!(empty_view.dim(0), Ok(0));
    assert_eq!(empty_view.dim(1), Ok(0));

    // single element array
    let single_data = [42.0];
    let single_view: StrideArrayView<'_, f64> = unsafe {
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
fn test_buffer_basic_write() -> TestResult {
    let elem_size = std::mem::size_of::<f64>() as isize;

    let test_data = [1.1, 2.2, 3.3, 4.4];
    let array_view: StrideArrayView<'_, f64> = unsafe {
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
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
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
        StrideArrayView::<f64>::new(
            2,
            [u32::MAX as usize, u32::MAX as usize].as_ptr(),
            [8, 8].as_ptr(),
            ptr::null(),
            0,
        )
    };
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err.msg().contains("Array total elem size overflow"));
    Ok(())
}

#[test]
fn test_stride_view_length_mismatch() -> TestResult {
    let elem_size = size_of::<f64>() as isize;
    let under_data = [1.1];
    let result: Result<StrideArrayView<'_, f64>, Error> = unsafe {
        StrideArrayView::new(
            2,
            [1, 2].as_ptr(),
            [elem_size, elem_size].as_ptr(),
            under_data.as_ptr() as *const u8,
            under_data.len() * elem_size as usize,
        )
    };
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err
        .msg()
        .contains("Array buffer length mismatch (actual: 8, expected: 16)"));

    let over_data = [1.1, 2.2, 3.3];
    let result: Result<StrideArrayView<'_, f64>, Error> = unsafe {
        StrideArrayView::new(
            2,
            [1, 2].as_ptr(),
            [elem_size, elem_size].as_ptr(),
            over_data.as_ptr() as *const u8,
            over_data.len() * elem_size as usize,
        )
    };

    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err
        .msg()
        .contains("Array buffer length mismatch (actual: 24, expected: 16)"));
    Ok(())
}

#[test]
fn test_build_in_1d_array_normal() -> TestResult {
    let arr = [1.0f64, 2.0, 3.0, 4.0];
    assert_eq!(arr.ndim(), 1);
    assert_eq!(arr.dim(0), Ok(4));
    assert!(arr.dim(1).is_err());
    assert_eq!(NdArrayView::as_slice(&arr), Some(&[1.0, 2.0, 3.0, 4.0][..]));
    let collected: Vec<_> = NdArrayView::iter(&arr).copied().collect();
    assert_eq!(collected, vec![1.0, 2.0, 3.0, 4.0]);

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("temperature", &arr)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            1u8
        ]
    );
    assert_eq!(&data[24..28], [4i32.to_le_bytes()].concat());
    assert_eq!(
        &data[28..60],
        &[
            1.0f64.to_ne_bytes(),
            2.0f64.to_le_bytes(),
            3.0f64.to_le_bytes(),
            4.0f64.to_le_bytes(),
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_build_in_1d_array_empty() -> TestResult {
    let arr: [f64; 0] = [];
    assert_eq!(arr.ndim(), 1);
    assert_eq!(arr.dim(0), Ok(0));
    assert_eq!(NdArrayView::as_slice(&arr), Some(&[][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("temperature", &arr)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            1u8
        ]
    );
    assert_eq!(&data[24..28], [0i32.to_le_bytes()].concat());
    Ok(())
}

#[test]
fn test_build_in_1d_vec_normal() -> TestResult {
    let vec = vec![5.0f64, 6.0, 7.0];
    assert_eq!(vec.ndim(), 1);
    assert_eq!(vec.dim(0), Ok(3));
    assert_eq!(NdArrayView::as_slice(&vec), Some(&[5.0, 6.0, 7.0][..]));
    let collected: Vec<_> = NdArrayView::iter(&vec).copied().collect();
    assert_eq!(collected, vec![5.0, 6.0, 7.0]);

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("temperature", &vec)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            1u8
        ]
    );
    assert_eq!(&data[24..28], [3i32.to_le_bytes()].concat());
    assert_eq!(
        &data[28..52],
        &[
            5.0f64.to_le_bytes(),
            6.0f64.to_le_bytes(),
            7.0f64.to_le_bytes(),
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_build_in_1d_vec_empty() -> TestResult {
    let vec: Vec<f64> = Vec::new();
    assert_eq!(vec.ndim(), 1);
    assert_eq!(vec.dim(0), Ok(0));
    assert_eq!(NdArrayView::as_slice(&vec), Some(&[][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("temperature", &vec)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            1u8
        ]
    );
    assert_eq!(&data[24..28], [0i32.to_le_bytes()].concat());
    Ok(())
}

#[test]
fn test_build_in_1d_slice_normal() -> TestResult {
    let data = [10.0f64, 20.0, 30.0, 40.0];
    let slice = &data[1..3];
    assert_eq!(slice.ndim(), 1);
    assert_eq!(slice.dim(0), Ok(2));
    assert_eq!(NdArrayView::as_slice(&slice), Some(&[20.0, 30.0][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("temperature", &slice)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            1u8
        ]
    );
    assert_eq!(&data[24..28], [2i32.to_le_bytes()].concat());
    assert_eq!(
        &data[28..44],
        &[20.0f64.to_le_bytes(), 30.0f64.to_le_bytes(),].concat()
    );
    Ok(())
}

#[test]
fn test_build_in_1d_slice_empty() -> TestResult {
    let data = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
    let slice = &data[2..2];
    assert_eq!(slice.ndim(), 1);
    assert_eq!(slice.dim(0), Ok(0));
    assert_eq!(NdArrayView::as_slice(&slice), Some(&[][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("temperature", &slice)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..19], b"temperature");
    assert_eq!(
        &data[19..24],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            1u8
        ]
    );
    assert_eq!(&data[24..28], [0i32.to_le_bytes()].concat());
    Ok(())
}

#[test]
fn test_build_in_2d_array_normal() -> TestResult {
    let arr = [[1.0f64, 2.0], [3.0, 4.0], [5.0, 6.0]];
    assert_eq!(arr.ndim(), 2);
    assert_eq!(arr.dim(0), Ok(3));
    assert_eq!(arr.dim(1), Ok(2));
    assert_eq!(
        NdArrayView::as_slice(&arr),
        Some(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0][..])
    );
    let collected: Vec<_> = NdArrayView::iter(&arr).copied().collect();
    assert_eq!(collected, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("2darray", &arr)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"2darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[20..28],
        [3i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    assert_eq!(
        &data[28..76],
        &[
            1.0f64.to_le_bytes(),
            2.0f64.to_le_bytes(),
            3.0f64.to_le_bytes(),
            4.0f64.to_le_bytes(),
            5.0f64.to_le_bytes(),
            6.0f64.to_le_bytes(),
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_build_in_2d_array_empty() -> TestResult {
    let arr: [[f64; 0]; 0] = [];
    assert_eq!(arr.ndim(), 2);
    assert_eq!(arr.dim(0), Ok(0));
    assert_eq!(arr.dim(1), Ok(0));
    assert_eq!(NdArrayView::as_slice(&arr), Some(&[][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("2darray", &arr)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"2darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[20..28],
        [0i32.to_le_bytes(), 0i32.to_le_bytes()].concat()
    );
    Ok(())
}

#[test]
fn test_build_in_2d_vec_normal() -> TestResult {
    let vec = vec![vec![1.0f64, 2.0], vec![3.0, 4.0], vec![5.0, 6.0]];
    assert_eq!(vec.ndim(), 2);
    assert_eq!(vec.dim(0), Ok(3));
    assert_eq!(vec.dim(1), Ok(2));
    assert!(NdArrayView::as_slice(&vec).is_none());
    let collected: Vec<_> = NdArrayView::iter(&vec).copied().collect();
    assert_eq!(collected, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("2darray", &vec)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"2darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[20..28],
        [3i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    assert_eq!(
        &data[28..76],
        &[
            1.0f64.to_le_bytes(),
            2.0f64.to_le_bytes(),
            3.0f64.to_le_bytes(),
            4.0f64.to_le_bytes(),
            5.0f64.to_le_bytes(),
            6.0f64.to_le_bytes(),
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_build_in_2d_vec_irregular_shape() -> TestResult {
    let irregular_vec = vec![vec![1.0, 2.0], vec![3.0], vec![4.0, 5.0]];
    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    let result = buffer.column_arr("arr", &irregular_vec);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err.msg().contains("Irregular array shape"));
    Ok(())
}

#[test]
fn test_build_in_2d_vec_empty() -> TestResult {
    let vec: Vec<Vec<f64>> = vec![vec![], vec![], vec![]];
    assert_eq!(vec.ndim(), 2);
    assert_eq!(vec.dim(0), Ok(3));
    assert_eq!(vec.dim(1), Ok(0));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("2darray", &vec)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"2darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[20..28],
        [3i32.to_le_bytes(), 0i32.to_le_bytes()].concat()
    );
    Ok(())
}

#[test]
fn test_build_in_2d_slice_normal() -> TestResult {
    let data = [[1.0f64, 2.0], [3.0, 4.0], [5.0, 6.0]];
    let slice = &data[..2];
    assert_eq!(slice.ndim(), 2);
    assert_eq!(slice.dim(0), Ok(2));
    assert_eq!(slice.dim(1), Ok(2));
    assert_eq!(
        NdArrayView::as_slice(&slice),
        Some(&[1.0, 2.0, 3.0, 4.0][..])
    );

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("2darray", &slice)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"2darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[20..28],
        [2i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    assert_eq!(
        &data[28..60],
        &[
            1.0f64.to_le_bytes(),
            2.0f64.to_le_bytes(),
            3.0f64.to_le_bytes(),
            4.0f64.to_le_bytes(),
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_build_in_2d_slice_empty() -> TestResult {
    let data = [[1.0f64, 2.0], [3.0, 4.0], [5.0, 6.0]];
    let slice = &data[2..2];
    assert_eq!(slice.ndim(), 2);
    assert_eq!(slice.dim(0), Ok(0));
    assert_eq!(slice.dim(1), Ok(2));
    assert_eq!(NdArrayView::as_slice(&slice), Some(&[][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("2darray", &slice)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"2darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            2u8
        ]
    );
    assert_eq!(
        &data[20..28],
        [0i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    Ok(())
}

#[test]
fn test_build_in_3d_array_normal() -> TestResult {
    let arr = [[[1.0f64, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]];
    assert_eq!(arr.ndim(), 3);
    assert_eq!(arr.dim(0), Ok(2));
    assert_eq!(arr.dim(1), Ok(2));
    assert_eq!(arr.dim(2), Ok(2));
    assert_eq!(
        NdArrayView::as_slice(&arr),
        Some(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0][..])
    );
    let collected: Vec<_> = NdArrayView::iter(&arr).copied().collect();
    assert_eq!(collected, vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]);

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("3darray", &arr)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"3darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            3u8
        ]
    );
    assert_eq!(
        &data[20..32],
        [2i32.to_le_bytes(), 2i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    assert_eq!(
        &data[32..96],
        &[
            1.0f64.to_le_bytes(),
            2.0f64.to_le_bytes(),
            3.0f64.to_le_bytes(),
            4.0f64.to_le_bytes(),
            5.0f64.to_le_bytes(),
            6.0f64.to_le_bytes(),
            7.0f64.to_le_bytes(),
            8.0f64.to_le_bytes()
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_build_in_3d_array_empty() -> TestResult {
    let arr: [[[f64; 2]; 0]; 0] = [];
    assert_eq!(arr.ndim(), 3);
    assert_eq!(arr.dim(0), Ok(0));
    assert_eq!(arr.dim(1), Ok(0));
    assert_eq!(arr.dim(2), Ok(2));
    assert_eq!(NdArrayView::as_slice(&arr), Some(&[][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("3darray", &arr)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"3darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            3u8
        ]
    );
    assert_eq!(
        &data[20..32],
        [0i32.to_le_bytes(), 0i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    Ok(())
}

#[test]
fn test_build_in_3d_vec_normal() -> TestResult {
    let vec = vec![
        vec![vec![1.0, 2.0, 3.0], vec![4.0, 5.0, 6.0]],
        vec![vec![7.0, 8.0, 9.0], vec![10.0, 11.0, 12.0]],
    ];
    assert_eq!(vec.ndim(), 3);
    assert_eq!(vec.dim(0), Ok(2));
    assert_eq!(vec.dim(1), Ok(2));
    assert_eq!(vec.dim(2), Ok(3));
    assert!(NdArrayView::as_slice(&vec).is_none());
    let collected: Vec<_> = NdArrayView::iter(&vec).copied().collect();
    assert_eq!(
        collected,
        vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0, 12.0]
    );

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("3darray", &vec)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"3darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            3u8
        ]
    );
    assert_eq!(
        &data[20..32],
        [2i32.to_le_bytes(), 2i32.to_le_bytes(), 3i32.to_le_bytes()].concat()
    );
    assert_eq!(
        &data[32..128],
        &[
            1.0f64.to_le_bytes(),
            2.0f64.to_le_bytes(),
            3.0f64.to_le_bytes(),
            4.0f64.to_le_bytes(),
            5.0f64.to_le_bytes(),
            6.0f64.to_le_bytes(),
            7.0f64.to_le_bytes(),
            8.0f64.to_le_bytes(),
            9.0f64.to_le_bytes(),
            10.0f64.to_le_bytes(),
            11.0f64.to_le_bytes(),
            12.0f64.to_le_bytes(),
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_build_in_3d_vec_empty() -> TestResult {
    let vec: Vec<Vec<Vec<f64>>> = vec![vec![vec![], vec![]], vec![vec![], vec![]]];
    assert_eq!(vec.ndim(), 3);
    assert_eq!(vec.dim(0), Ok(2));
    assert_eq!(vec.dim(1), Ok(2));
    assert_eq!(vec.dim(2), Ok(0));
    assert!(NdArrayView::as_slice(&vec).is_none());

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("3darray", &vec)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"3darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            3u8
        ]
    );
    assert_eq!(
        &data[20..32],
        [2i32.to_le_bytes(), 2i32.to_le_bytes(), 0i32.to_le_bytes()].concat()
    );
    Ok(())
}

#[test]
fn test_build_in_3d_vec_irregular_shape() -> TestResult {
    let irregular1 = vec![vec![vec![1.0, 2.0], vec![3.0, 4.0]], vec![vec![5.0, 6.0]]];

    let irregular2 = vec![
        vec![vec![1.0, 2.0], vec![3.0, 4.0, 5.0]],
        vec![vec![6.0, 7.0], vec![8.0, 9.0]],
    ];

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    let result = buffer.column_arr("arr", &irregular1);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err.msg().contains("Irregular array shape"));

    let result = buffer.column_arr("arr", &irregular2);
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayViewError);
    assert!(err.msg().contains("Irregular array shape"));
    Ok(())
}

#[test]
fn test_3d_slice_normal() -> TestResult {
    let data = [[[1f64, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]];
    let slice = &data[..1];
    assert_eq!(slice.ndim(), 3);
    assert_eq!(slice.dim(0), Ok(1));
    assert_eq!(slice.dim(1), Ok(2));
    assert_eq!(slice.dim(2), Ok(2));
    assert_eq!(
        NdArrayView::as_slice(&slice),
        Some(&[1.0, 2.0, 3.0, 4.0][..])
    );

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("3darray", &slice)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"3darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            3u8
        ]
    );
    assert_eq!(
        &data[20..32],
        [1i32.to_le_bytes(), 2i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    assert_eq!(
        &data[32..64],
        &[
            1.0f64.to_le_bytes(),
            2.0f64.to_le_bytes(),
            3.0f64.to_le_bytes(),
            4.0f64.to_le_bytes(),
        ]
        .concat()
    );
    Ok(())
}

#[test]
fn test_3d_slice_empty() -> TestResult {
    let data = [[[1f64, 2.0], [3.0, 4.0]], [[5.0, 6.0], [7.0, 8.0]]];
    let slice = &data[1..1];
    assert_eq!(slice.ndim(), 3);
    assert_eq!(slice.dim(0), Ok(0));
    assert_eq!(slice.dim(1), Ok(2));
    assert_eq!(slice.dim(2), Ok(2));
    assert_eq!(NdArrayView::as_slice(&slice), Some(&[][..]));

    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("my_test")?;
    buffer.column_arr("3darray", &slice)?;
    let data = buffer.as_bytes();
    assert_eq!(&data[0..7], b"my_test");
    assert_eq!(&data[8..15], b"3darray");
    assert_eq!(
        &data[15..20],
        &[
            b'=',
            b'=',
            ARRAY_BINARY_FORMAT_TYPE,
            ArrayColumnTypeTag::Double.into(),
            3u8
        ]
    );
    assert_eq!(
        &data[20..32],
        [0i32.to_le_bytes(), 2i32.to_le_bytes(), 2i32.to_le_bytes()].concat()
    );
    Ok(())
}

#[cfg(feature = "ndarray")]
#[test]
fn test_1d_contiguous_ndarray_buffer() -> TestResult {
    let array = arr1(&[1.0, 2.0, 3.0, 4.0]);
    let view = array.view();
    let mut buf = vec![0u8; 4 * size_of::<f64>()];
    write_array_data(&view, &mut buf[0..], 32)?;
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
    write_array_data(&transposed, &mut buf[0..], 32)?;
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
    write_array_data(&strided_view, &mut buf[0..], 32)?;

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
    assert_eq!(NdArrayView::dim(&view, 0), Ok(3));
    assert!(NdArrayView::dim(&view, 1).is_err());
}

#[cfg(feature = "ndarray")]
#[test]
fn test_complex_ndarray_dimensions() {
    let array = arr3(&[[[1.0], [2.0]], [[3.0], [4.0]]]);
    let view = array.view();

    assert_eq!(NdArrayView::ndim(&view), 3);
    assert_eq!(NdArrayView::dim(&view, 0), Ok(2));
    assert_eq!(NdArrayView::dim(&view, 1), Ok(2));
    assert_eq!(NdArrayView::dim(&view, 2), Ok(1));
}

#[cfg(feature = "ndarray")]
#[test]
fn test_buffer_ndarray_write() -> TestResult {
    let mut buffer = Buffer::new(ProtocolVersion::V2);
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
            ArrayColumnTypeTag::Double.into(),
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
    let mut buffer = Buffer::new(ProtocolVersion::V2);
    buffer.table("nd_test")?;
    let shape: Vec<usize> = iter::repeat_n(1, MAX_ARRAY_DIMS).collect();
    let array = ArrayD::<f64>::zeros(shape.clone());
    buffer.column_arr("max_dim", &array.view())?;
    let data = buffer.as_bytes();
    assert_eq!(data[19], MAX_ARRAY_DIMS as u8);

    // 33 dims error
    let shape_invalid: Vec<_> = iter::repeat_n(1, MAX_ARRAY_DIMS + 1).collect();
    let array_invalid = ArrayD::<f64>::zeros(shape_invalid);
    let result = buffer.column_arr("invalid", &array_invalid.view());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.code(), ErrorCode::ArrayHasTooManyDims);
    Ok(())
}
