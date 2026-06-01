use std::sync::Arc;

use arrow_array::Array;
use arrow_schema::{DataType, TimeUnit};
use bytes::Bytes;

use super::*;
use crate::egress::column_kind::ColumnKind;
use crate::egress::decoder::{ArrayBuffers, ColumnBuffer, DecodedBatch, DecodedColumn};
use crate::egress::schema::{Schema, SchemaColumn};
use crate::egress::symbol_dict::SymbolDict;

fn buf(values: Vec<u8>, validity: Option<Vec<u8>>) -> ColumnBuffer {
    ColumnBuffer {
        values: Bytes::from(values),
        validity: validity.map(Bytes::from),
    }
}

fn schema_of(cols: &[(&str, ColumnKind)]) -> Schema {
    Schema::from_columns(
        cols.iter()
            .map(|(n, k)| SchemaColumn {
                name: (*n).into(),
                kind: *k,
            })
            .collect(),
    )
}

fn decoded_of(row_count: usize, columns: Vec<DecodedColumn>) -> DecodedBatch {
    DecodedBatch {
        request_id: 1,
        batch_seq: 0,
        schema_id: 7,
        row_count,
        columns,
        flags: 0,
    }
}

#[test]
fn long_column_roundtrip() {
    let mut values = Vec::with_capacity(24);
    for v in [1i64, -2, 0x0102_0304_0506_0708] {
        values.extend_from_slice(&v.to_le_bytes());
    }
    let s = schema_of(&[("v", ColumnKind::Long)]);
    let b = decoded_of(3, vec![DecodedColumn::Long(buf(values, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Int64);
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    assert_eq!(rb.num_rows(), 3);
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::Int64Array>()
        .unwrap();
    assert_eq!(col.value(0), 1);
    assert_eq!(col.value(1), -2);
    assert_eq!(col.value(2), 0x0102_0304_0506_0708);
}

#[test]
fn validity_inversion_runs_on_export() {
    let mut values = Vec::with_capacity(32);
    for v in [10i64, 20, 30, 40] {
        values.extend_from_slice(&v.to_le_bytes());
    }
    let qwp_bitmap = vec![0b0000_0010u8];
    let s = schema_of(&[("v", ColumnKind::Long)]);
    let b = decoded_of(4, vec![DecodedColumn::Long(buf(values, Some(qwp_bitmap)))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::Int64Array>()
        .unwrap();
    assert!(col.is_valid(0));
    assert!(col.is_null(1));
    assert!(col.is_valid(2));
    assert!(col.is_valid(3));
}

#[test]
fn boolean_bit_packs_on_export() {
    let values = vec![0u8, 1, 0, 1, 1];
    let s = schema_of(&[("b", ColumnKind::Boolean)]);
    let b = decoded_of(5, vec![DecodedColumn::Boolean(buf(values, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Boolean);
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::BooleanArray>()
        .unwrap();
    assert!(!col.value(0));
    assert!(col.value(1));
    assert!(!col.value(2));
    assert!(col.value(3));
    assert!(col.value(4));
}

#[test]
fn timestamp_micros_carries_timezone() {
    let mut values = Vec::with_capacity(16);
    for v in [1_700_000_000_000_000i64, 1_700_000_000_001_000] {
        values.extend_from_slice(&v.to_le_bytes());
    }
    let s = schema_of(&[("ts", ColumnKind::Timestamp)]);
    let b = decoded_of(2, vec![DecodedColumn::Timestamp(buf(values, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::Timestamp(TimeUnit::Microsecond, tz) => {
            assert_eq!(tz.as_deref(), Some("UTC"));
        }
        other => panic!("expected Timestamp(µs, UTC), got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn varchar_zero_copy_path_under_2gb() {
    let strings = ["hi", "", "yo"];
    let mut data = Vec::new();
    let mut offsets: Vec<u32> = vec![0];
    for s in &strings {
        data.extend_from_slice(s.as_bytes());
        offsets.push(data.len() as u32);
    }
    let s = schema_of(&[("v", ColumnKind::Varchar)]);
    let b = decoded_of(
        3,
        vec![DecodedColumn::Varchar {
            offsets,
            data: Bytes::from(data),
            validity: None,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Utf8);
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::StringArray>()
        .unwrap();
    assert_eq!(col.value(0), "hi");
    assert_eq!(col.value(1), "");
    assert_eq!(col.value(2), "yo");
}

#[test]
fn binary_zero_copy_path_under_2gb() {
    let blobs: &[&[u8]] = &[&[1, 2, 3], &[], &[0xFF, 0x00]];
    let mut data = Vec::new();
    let mut offsets: Vec<u32> = vec![0];
    for b in blobs {
        data.extend_from_slice(b);
        offsets.push(data.len() as u32);
    }
    let s = schema_of(&[("b", ColumnKind::Binary)]);
    let batch = decoded_of(
        3,
        vec![DecodedColumn::Binary {
            offsets,
            data: Bytes::from(data),
            validity: None,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &batch).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Binary);
    let rb = batch_to_record_batch(arrow_schema, &s, batch, &SymbolDict::new()).unwrap();
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::BinaryArray>()
        .unwrap();
    assert_eq!(col.value(0), &[1, 2, 3]);
    assert_eq!(col.value(1), &[] as &[u8]);
    assert_eq!(col.value(2), &[0xFF, 0x00]);
}

#[test]
fn uuid_field_carries_arrow_uuid_extension() {
    let raw: Vec<u8> = (0..32u8).collect();
    let s = schema_of(&[("id", ColumnKind::Uuid)]);
    let b = decoded_of(2, vec![DecodedColumn::Uuid(buf(raw, None))]);
    let arrow_schema = batch_arrow_schema(&s, &b).unwrap();
    let field = arrow_schema.field(0);
    assert_eq!(field.data_type(), &DataType::FixedSizeBinary(16));
    assert_eq!(
        field
            .metadata()
            .get(metadata::ARROW_EXTENSION_NAME)
            .map(String::as_str),
        Some("arrow.uuid")
    );
    assert_eq!(
        field
            .metadata()
            .get(metadata::COLUMN_TYPE)
            .map(String::as_str),
        Some("uuid")
    );
}

#[test]
fn symbol_built_with_union_dict_per_batch() {
    let mut dict = SymbolDict::new();
    dict.apply_delta(
        0,
        [b"AAPL".as_slice(), b"MSFT".as_slice(), b"GOOG".as_slice()],
    )
    .unwrap();
    let codes: Vec<u32> = vec![0, 2, 0, 1];
    let s = schema_of(&[("sym", ColumnKind::Symbol)]);
    let b = decoded_of(
        4,
        vec![DecodedColumn::Symbol {
            codes,
            validity: None,
            local_dict: None,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::Dictionary(k, v) => {
            assert_eq!(**k, DataType::UInt32);
            assert_eq!(**v, DataType::Utf8);
        }
        other => panic!("expected Dictionary(UInt32, Utf8), got {:?}", other),
    }
    let rb = batch_to_record_batch(arrow_schema, &s, b, &dict).unwrap();
    let dict_arr = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::DictionaryArray<arrow_array::types::UInt32Type>>()
        .unwrap();
    let values = dict_arr
        .values()
        .as_any()
        .downcast_ref::<arrow_array::StringArray>()
        .unwrap();
    assert_eq!(values.len(), 3);
    let mut decoded: Vec<String> = (0..dict_arr.len())
        .map(|r| {
            let key = dict_arr.keys().value(r);
            values.value(key as usize).to_string()
        })
        .collect();
    decoded.sort_by_key(|s| match s.as_str() {
        "AAPL" => 0,
        "GOOG" => 1,
        "MSFT" => 2,
        _ => 99,
    });
    decoded.dedup();
    let names: Vec<&str> = decoded.iter().map(String::as_str).collect();
    assert!(names.contains(&"AAPL"));
    assert!(names.contains(&"GOOG"));
    assert!(names.contains(&"MSFT"));
}

#[test]
fn geohash_widens_to_target_arrow_width() {
    let raw = vec![0xABu8, 0xCD, 0x12, 0x34];
    let s = schema_of(&[("g", ColumnKind::Geohash)]);
    let b = decoded_of(
        4,
        vec![DecodedColumn::Geohash {
            buffer: buf(raw, None),
            byte_width: 1,
            precision_bits: 6,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Int8);
    assert_eq!(
        arrow_schema
            .field(0)
            .metadata()
            .get(metadata::GEOHASH_BITS)
            .map(String::as_str),
        Some("6")
    );
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn array_2d_double_builds_nested_list() {
    let mut data = Vec::new();
    for v in [1.0_f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let buffers = ArrayBuffers {
        data_offsets: vec![0, 48, 64],
        data: Bytes::from(data),
        shapes: vec![2, 3, 1, 2],
        shape_offsets: vec![0, 2, 4],
        validity: None,
    };
    let s = schema_of(&[("a", ColumnKind::DoubleArray)]);
    let b = decoded_of(2, vec![DecodedColumn::DoubleArray(buffers)]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let dt = arrow_schema.field(0).data_type();
    match dt {
        DataType::List(outer) => match outer.data_type() {
            DataType::List(inner) => assert_eq!(inner.data_type(), &DataType::Float64),
            other => panic!("expected inner List(Float64), got {:?}", other),
        },
        other => panic!("expected nested List, got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn schemas_equal_ignores_nullability_when_metadata_matches() {
    let a = batch_arrow_schema(
        &schema_of(&[("v", ColumnKind::Long)]),
        &decoded_of(0, vec![DecodedColumn::Long(buf(Vec::new(), None))]),
    )
    .unwrap();
    let b = batch_arrow_schema(
        &schema_of(&[("v", ColumnKind::Long)]),
        &decoded_of(0, vec![DecodedColumn::Long(buf(Vec::new(), None))]),
    )
    .unwrap();
    assert!(schemas_equal(&a, &b));
}

fn le_bytes_of<T>(values: &[T]) -> Vec<u8>
where
    T: Copy + AsLeBytes,
{
    let mut out = Vec::with_capacity(std::mem::size_of_val(values));
    for v in values {
        out.extend_from_slice(&v.as_le_slice());
    }
    out
}

trait AsLeBytes: Copy {
    fn as_le_slice(self) -> Vec<u8>;
}

macro_rules! impl_as_le {
    ($t:ty) => {
        impl AsLeBytes for $t {
            fn as_le_slice(self) -> Vec<u8> {
                self.to_le_bytes().to_vec()
            }
        }
    };
}
impl_as_le!(i8);
impl_as_le!(i16);
impl_as_le!(i32);
impl_as_le!(i64);
impl_as_le!(u16);
impl_as_le!(u32);
impl_as_le!(f32);
impl_as_le!(f64);

#[test]
fn byte_column_passes_through_int8() {
    let raw = le_bytes_of(&[1i8, -1, 127, -128]);
    let s = schema_of(&[("b", ColumnKind::Byte)]);
    let b = decoded_of(4, vec![DecodedColumn::Byte(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Int8);
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::Int8Array>()
        .unwrap();
    assert_eq!(col.values(), &[1i8, -1, 127, -128]);
}

#[test]
fn short_column_passes_through_int16() {
    let raw = le_bytes_of(&[1i16, -1, i16::MAX, i16::MIN]);
    let s = schema_of(&[("s", ColumnKind::Short)]);
    let b = decoded_of(4, vec![DecodedColumn::Short(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Int16);
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn int_column_passes_through_int32() {
    let raw = le_bytes_of(&[1i32, -1, i32::MAX]);
    let s = schema_of(&[("i", ColumnKind::Int)]);
    let b = decoded_of(3, vec![DecodedColumn::Int(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Int32);
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn float_column_passes_through_float32() {
    let raw = le_bytes_of(&[1.5f32, -2.5, std::f32::consts::PI]);
    let s = schema_of(&[("f", ColumnKind::Float)]);
    let b = decoded_of(3, vec![DecodedColumn::Float(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Float32);
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn double_column_passes_through_float64() {
    let raw = le_bytes_of(&[1.5f64, -2.5, std::f64::consts::PI]);
    let s = schema_of(&[("d", ColumnKind::Double)]);
    let b = decoded_of(3, vec![DecodedColumn::Double(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::Float64);
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn date_column_is_timestamp_millis_utc() {
    let raw = le_bytes_of(&[1_700_000_000_000i64, 1_700_000_001_000]);
    let s = schema_of(&[("d", ColumnKind::Date)]);
    let b = decoded_of(2, vec![DecodedColumn::Date(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::Timestamp(TimeUnit::Millisecond, tz) => {
            assert_eq!(tz.as_deref(), Some("UTC"));
        }
        other => panic!("expected Timestamp(ms, UTC), got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn timestamp_nanos_is_timestamp_nanosecond_utc() {
    let raw = le_bytes_of(&[1_700_000_000_000_000_000i64, 1_700_000_000_000_000_001]);
    let s = schema_of(&[("ts", ColumnKind::TimestampNanos)]);
    let b = decoded_of(2, vec![DecodedColumn::TimestampNanos(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::Timestamp(TimeUnit::Nanosecond, tz) => {
            assert_eq!(tz.as_deref(), Some("UTC"));
        }
        other => panic!("expected Timestamp(ns, UTC), got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn char_column_is_uint16_with_metadata() {
    let raw = le_bytes_of(&[0x41u16, 0x42, 0x43]);
    let s = schema_of(&[("c", ColumnKind::Char)]);
    let b = decoded_of(3, vec![DecodedColumn::Char(buf(raw, None))]);
    let arrow_schema = batch_arrow_schema(&s, &b).unwrap();
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::UInt16);
    assert_eq!(
        arrow_schema
            .field(0)
            .metadata()
            .get(metadata::COLUMN_TYPE)
            .map(String::as_str),
        Some("char")
    );
}

#[test]
fn ipv4_column_is_uint32_with_metadata() {
    let raw = le_bytes_of(&[0x0100_007Fu32, 0x0101_A8C0]);
    let s = schema_of(&[("ip", ColumnKind::Ipv4)]);
    let b = decoded_of(2, vec![DecodedColumn::Ipv4(buf(raw, None))]);
    let arrow_schema = batch_arrow_schema(&s, &b).unwrap();
    assert_eq!(arrow_schema.field(0).data_type(), &DataType::UInt32);
    assert_eq!(
        arrow_schema
            .field(0)
            .metadata()
            .get(metadata::COLUMN_TYPE)
            .map(String::as_str),
        Some("ipv4")
    );
}

#[test]
fn long256_is_fixed_size_binary_32() {
    let raw: Vec<u8> = (0..64u8).collect();
    let s = schema_of(&[("l", ColumnKind::Long256)]);
    let b = decoded_of(2, vec![DecodedColumn::Long256(buf(raw, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    assert_eq!(
        arrow_schema.field(0).data_type(),
        &DataType::FixedSizeBinary(32)
    );
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn decimal64_carries_precision_and_scale() {
    let raw = le_bytes_of(&[12345i64, 6789]);
    let s = schema_of(&[("d", ColumnKind::Decimal64)]);
    let b = decoded_of(
        2,
        vec![DecodedColumn::Decimal64 {
            buffer: buf(raw, None),
            scale: 3,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::Decimal64(precision, scale) => {
            assert_eq!(*precision, 18);
            assert_eq!(*scale, 3);
        }
        other => panic!("expected Decimal64(_, _), got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn decimal128_carries_precision_and_scale() {
    let raw = bytes::Bytes::from(vec![0u8; 32]);
    let s = schema_of(&[("d", ColumnKind::Decimal128)]);
    let b = decoded_of(
        2,
        vec![DecodedColumn::Decimal128 {
            buffer: ColumnBuffer {
                values: raw,
                validity: None,
            },
            scale: 5,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::Decimal128(precision, scale) => {
            assert_eq!(*precision, 38);
            assert_eq!(*scale, 5);
        }
        other => panic!("expected Decimal128(_, _), got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn decimal256_carries_precision_and_scale() {
    let raw = bytes::Bytes::from(vec![0u8; 64]);
    let s = schema_of(&[("d", ColumnKind::Decimal256)]);
    let b = decoded_of(
        2,
        vec![DecodedColumn::Decimal256 {
            buffer: ColumnBuffer {
                values: raw,
                validity: None,
            },
            scale: 7,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::Decimal256(precision, scale) => {
            assert_eq!(*precision, 76);
            assert_eq!(*scale, 7);
        }
        other => panic!("expected Decimal256(_, _), got {:?}", other),
    }
}

#[test]
fn long_array_builds_nested_list_int64() {
    let mut data = Vec::new();
    for v in [10i64, 20, 30, 40, 50, 60] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 24, 48],
        data: bytes::Bytes::from(data),
        shapes: vec![3, 3],
        shape_offsets: vec![0, 1, 2],
        validity: None,
    };
    let s = schema_of(&[("la", ColumnKind::LongArray)]);
    let b = decoded_of(2, vec![DecodedColumn::LongArray(buffers)]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::List(inner) => {
            assert_eq!(inner.data_type(), &DataType::Int64);
        }
        other => panic!("expected List(Int64), got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn array_1d_double_builds_single_list_level() {
    let mut data = Vec::new();
    for v in [1.0f64, 2.0, 3.0, 4.0, 5.0] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 16, 40],
        data: bytes::Bytes::from(data),
        shapes: vec![2, 3],
        shape_offsets: vec![0, 1, 2],
        validity: None,
    };
    let s = schema_of(&[("a", ColumnKind::DoubleArray)]);
    let b = decoded_of(2, vec![DecodedColumn::DoubleArray(buffers)]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    match arrow_schema.field(0).data_type() {
        DataType::List(inner) => {
            assert_eq!(inner.data_type(), &DataType::Float64);
        }
        other => panic!("expected single List(Float64), got {:?}", other),
    }
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn array_3d_double_builds_three_list_levels() {
    let mut data = Vec::new();
    for v in [1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 64],
        data: bytes::Bytes::from(data),
        shapes: vec![2, 2, 2],
        shape_offsets: vec![0, 3],
        validity: None,
    };
    let s = schema_of(&[("a", ColumnKind::DoubleArray)]);
    let b = decoded_of(1, vec![DecodedColumn::DoubleArray(buffers)]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    fn depth(dt: &DataType) -> usize {
        match dt {
            DataType::List(inner) => 1 + depth(inner.data_type()),
            _ => 0,
        }
    }
    assert_eq!(depth(arrow_schema.field(0).data_type()), 3);
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
}

#[test]
fn array_with_null_row_skips_shape() {
    let mut data = Vec::new();
    for v in [1.0f64, 2.0, 3.0] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 24, 24],
        data: bytes::Bytes::from(data),
        shapes: vec![3],
        shape_offsets: vec![0, 1, 1],
        validity: Some(bytes::Bytes::from(vec![0b0000_0010u8])),
    };
    let s = schema_of(&[("a", ColumnKind::DoubleArray)]);
    let b = decoded_of(2, vec![DecodedColumn::DoubleArray(buffers)]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::ListArray>()
        .unwrap();
    assert!(col.is_valid(0));
    assert!(col.is_null(1));
}

#[test]
fn symbol_with_local_dict_overrides_connection_dict() {
    let mut local = SymbolDict::new();
    local
        .apply_delta(0, [b"L0".as_slice(), b"L1".as_slice()])
        .unwrap();
    let connection = SymbolDict::new();
    let s = schema_of(&[("sym", ColumnKind::Symbol)]);
    let b = decoded_of(
        2,
        vec![DecodedColumn::Symbol {
            codes: vec![0, 1],
            validity: None,
            local_dict: Some(local),
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let rb = batch_to_record_batch(arrow_schema, &s, b, &connection).unwrap();
    let dict_arr = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::DictionaryArray<arrow_array::types::UInt32Type>>()
        .unwrap();
    let values = dict_arr
        .values()
        .as_any()
        .downcast_ref::<arrow_array::StringArray>()
        .unwrap();
    assert_eq!(values.len(), 2);
}

#[test]
fn empty_batch_produces_zero_row_record_batch() {
    let s = schema_of(&[("v", ColumnKind::Long)]);
    let b = decoded_of(0, vec![DecodedColumn::Long(buf(Vec::new(), None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    assert_eq!(rb.num_rows(), 0);
    assert_eq!(rb.num_columns(), 1);
}

#[test]
fn ffi_round_trip_preserves_record_batch() {
    let mut data = Vec::new();
    for v in [1i64, 2, 3] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let s = schema_of(&[("v", ColumnKind::Long)]);
    let batch = decoded_of(3, vec![DecodedColumn::Long(buf(data, None))]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &batch).unwrap());
    let rb = batch_to_record_batch(arrow_schema.clone(), &s, batch, &SymbolDict::new()).unwrap();
    let struct_array: arrow_array::StructArray = rb.into();
    let data = struct_array.into_data();
    let (ffi_array, ffi_schema) = arrow::ffi::to_ffi(&data).unwrap();
    let imported = unsafe { arrow::ffi::from_ffi(ffi_array, &ffi_schema) }.unwrap();
    let restored: arrow_array::StructArray = imported.into();
    assert_eq!(restored.len(), 3);
    assert_eq!(restored.num_columns(), 1);
}

#[test]
fn schemas_equal_detects_dtype_drift() {
    let a = batch_arrow_schema(
        &schema_of(&[("v", ColumnKind::Long)]),
        &decoded_of(0, vec![DecodedColumn::Long(buf(Vec::new(), None))]),
    )
    .unwrap();
    let b = batch_arrow_schema(
        &schema_of(&[("v", ColumnKind::Int)]),
        &decoded_of(0, vec![DecodedColumn::Int(buf(Vec::new(), None))]),
    )
    .unwrap();
    assert!(!schemas_equal(&a, &b));
}
