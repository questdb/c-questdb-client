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

#[cfg(feature = "ndarray")]
use crate::ingress::MAX_ARRAY_DIMS;
use crate::ingress::{Buffer, NdArrayView, ProtocolVersion, ARRAY_BINARY_FORMAT_TYPE};
use crate::tests::TestResult;
use crate::ErrorCode;

#[cfg(feature = "ndarray")]
use ndarray::{arr1, arr2, arr3, s, ArrayD};
#[cfg(feature = "ndarray")]
use std::iter;

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
