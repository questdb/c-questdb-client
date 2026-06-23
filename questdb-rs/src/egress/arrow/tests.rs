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
fn varchar_multibyte_and_nulls_round_trip() {
    // Guards the `build_unchecked` path: multibyte codepoints (offsets land on
    // char boundaries) plus a null row must round-trip without Arrow's UTF-8
    // re-validation. "café" = 5 bytes, "日本" = 6 bytes, "x" = 1 byte.
    let mut data = Vec::new();
    for s in ["café", "日本", "x"] {
        data.extend_from_slice(s.as_bytes());
    }
    // 4 rows, row 2 null; the dense null row repeats the previous boundary.
    let offsets: Vec<u32> = vec![0, 5, 11, 11, 12];
    let qwp_bitmap = vec![0b0000_0100u8]; // row 2 null
    let s = schema_of(&[("v", ColumnKind::Varchar)]);
    let b = decoded_of(
        4,
        vec![DecodedColumn::Varchar {
            offsets,
            data: Bytes::from(data),
            validity: Some(Bytes::from(qwp_bitmap)),
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    let col = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::StringArray>()
        .unwrap();
    assert_eq!(col.value(0), "café");
    assert_eq!(col.value(1), "日本");
    assert!(col.is_null(2));
    assert_eq!(col.value(3), "x");
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
fn symbol_uses_global_codes_against_full_dict() {
    // Aggressive build: the Arrow keys are the decoder's global codes verbatim
    // (no per-batch compaction) and the values are the full active dict in dict
    // order.
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
    // Full dict, in dict order — not a first-seen compaction.
    let dict_strs: Vec<&str> = (0..values.len()).map(|i| values.value(i)).collect();
    assert_eq!(dict_strs, vec!["AAPL", "MSFT", "GOOG"]);
    // Keys are the global codes verbatim.
    let keys: Vec<u32> = dict_arr.keys().values().iter().copied().collect();
    assert_eq!(keys, vec![0u32, 2, 0, 1]);
    let resolved: Vec<&str> = (0..dict_arr.len())
        .map(|r| values.value(dict_arr.keys().value(r) as usize))
        .collect();
    assert_eq!(resolved, vec!["AAPL", "GOOG", "AAPL", "MSFT"]);
}

#[test]
fn symbol_carries_full_dict_with_unused_entries_and_nulls() {
    // The active dict has more entries than the batch references; the aggressive
    // build still emits the whole dict as values and indexes it by global code.
    // A null row holds code 0 in `codes` but is masked by the null buffer.
    let mut dict = SymbolDict::new();
    dict.apply_delta(
        0,
        [
            b"zero".as_slice(),
            b"one".as_slice(),
            b"two".as_slice(),
            b"three".as_slice(),
        ],
    )
    .unwrap();
    // rows: code 3, null, code 1. The decoder leaves the null row's code at 0.
    let codes: Vec<u32> = vec![3, 0, 1];
    let qwp_bitmap = vec![0b0000_0010u8]; // row 1 null
    let s = schema_of(&[("sym", ColumnKind::Symbol)]);
    let b = decoded_of(
        3,
        vec![DecodedColumn::Symbol {
            codes,
            validity: Some(Bytes::from(qwp_bitmap)),
            local_dict: None,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
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
    assert_eq!(values.len(), 4); // full dict, including unused "zero"/"two"
    assert!(dict_arr.is_valid(0));
    assert!(dict_arr.is_null(1));
    assert!(dict_arr.is_valid(2));
    assert_eq!(values.value(dict_arr.keys().value(0) as usize), "three");
    assert_eq!(values.value(dict_arr.keys().value(2) as usize), "one");
}

#[test]
fn symbol_values_cache_reuses_then_rebuilds_on_growth() {
    use arrow_array::types::UInt32Type;
    use arrow_array::{DictionaryArray, RecordBatch, StringArray};

    fn resolve(rb: &RecordBatch) -> Vec<String> {
        let d = rb
            .column(0)
            .as_any()
            .downcast_ref::<DictionaryArray<UInt32Type>>()
            .unwrap();
        let v = d.values().as_any().downcast_ref::<StringArray>().unwrap();
        (0..d.len())
            .map(|i| v.value(d.keys().value(i) as usize).to_owned())
            .collect()
    }
    fn sym_batch(codes: Vec<u32>) -> DecodedBatch {
        let n = codes.len();
        decoded_of(
            n,
            vec![DecodedColumn::Symbol {
                codes,
                validity: None,
                local_dict: None,
            }],
        )
    }

    let s = schema_of(&[("sym", ColumnKind::Symbol)]);
    let mut dict = SymbolDict::new();
    dict.apply_delta(0, [b"a".as_slice(), b"b".as_slice()])
        .unwrap();
    let mut cache = SymbolValuesCache::default();

    let b1 = sym_batch(vec![0, 1]);
    let sch = Arc::new(batch_arrow_schema(&s, &b1).unwrap());
    let rb1 = batch_to_record_batch_with(sch.clone(), &s, b1, &dict, &mut cache).unwrap();
    assert_eq!(resolve(&rb1), vec!["a", "b"]);

    // Same dict → cached values reused; still correct.
    let rb2 = batch_to_record_batch_with(sch.clone(), &s, sym_batch(vec![1, 0]), &dict, &mut cache)
        .unwrap();
    assert_eq!(resolve(&rb2), vec!["b", "a"]);

    // Dict grows → cache rebuilds; the new code resolves.
    dict.apply_delta(2, [b"c".as_slice()]).unwrap();
    let rb3 =
        batch_to_record_batch_with(sch, &s, sym_batch(vec![2, 0]), &dict, &mut cache).unwrap();
    assert_eq!(resolve(&rb3), vec!["c", "a"]);
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
    let _ = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
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
fn array_2d_with_leading_null_row_preserves_values() {
    // Regression: a null outer row before a non-null multi-dim row must not
    // shift the inner-list offsets. Row 0 is null; row 1 is [[1,2,3],[4,5,6]].
    let mut data = Vec::new();
    for v in [1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 0, 48],
        data: bytes::Bytes::from(data),
        shapes: vec![2, 3],
        shape_offsets: vec![0, 0, 2],
        validity: Some(bytes::Bytes::from(vec![0b0000_0001u8])),
    };
    let s = schema_of(&[("a", ColumnKind::DoubleArray)]);
    let b = decoded_of(2, vec![DecodedColumn::DoubleArray(buffers)]);
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let rb = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new()).unwrap();
    let outer = rb
        .column(0)
        .as_any()
        .downcast_ref::<arrow_array::ListArray>()
        .unwrap();
    assert!(outer.is_null(0));
    assert!(outer.is_valid(1));
    let row1 = outer.value(1);
    let inner = row1
        .as_any()
        .downcast_ref::<arrow_array::ListArray>()
        .unwrap();
    assert_eq!(inner.len(), 2);
    let first = inner.value(0);
    assert_eq!(
        first
            .as_any()
            .downcast_ref::<arrow_array::Float64Array>()
            .unwrap()
            .values(),
        &[1.0, 2.0, 3.0]
    );
    let second = inner.value(1);
    assert_eq!(
        second
            .as_any()
            .downcast_ref::<arrow_array::Float64Array>()
            .unwrap()
            .values(),
        &[4.0, 5.0, 6.0]
    );
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

#[test]
fn empty_array_batch_emits_tentative_ndim_marker() {
    let buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![],
        data: bytes::Bytes::new(),
        shapes: vec![],
        shape_offsets: vec![],
        validity: None,
    };
    let s = schema_of(&[("a", ColumnKind::DoubleArray)]);
    let b = decoded_of(0, vec![DecodedColumn::DoubleArray(buffers)]);
    let arrow_schema = batch_arrow_schema(&s, &b).unwrap();
    let md = arrow_schema.field(0).metadata();
    assert_eq!(
        md.get(crate::egress::arrow::metadata::ARRAY_DIM_TENTATIVE)
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn firm_array_batch_has_no_tentative_marker() {
    let mut data = Vec::new();
    for v in [1.0f64, 2.0, 3.0] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 24],
        data: bytes::Bytes::from(data),
        shapes: vec![3],
        shape_offsets: vec![0, 1],
        validity: None,
    };
    let s = schema_of(&[("a", ColumnKind::DoubleArray)]);
    let b = decoded_of(1, vec![DecodedColumn::DoubleArray(buffers)]);
    let arrow_schema = batch_arrow_schema(&s, &b).unwrap();
    let md = arrow_schema.field(0).metadata();
    assert!(
        md.get(crate::egress::arrow::metadata::ARRAY_DIM_TENTATIVE)
            .is_none()
    );
}

#[test]
fn schemas_equal_accepts_tentative_to_firm_array_upgrade() {
    let empty_buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![],
        data: bytes::Bytes::new(),
        shapes: vec![],
        shape_offsets: vec![],
        validity: None,
    };
    let tentative = batch_arrow_schema(
        &schema_of(&[("a", ColumnKind::DoubleArray)]),
        &decoded_of(0, vec![DecodedColumn::DoubleArray(empty_buffers)]),
    )
    .unwrap();

    let mut data = Vec::new();
    for v in [1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    let firm_buffers = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 64],
        data: bytes::Bytes::from(data),
        shapes: vec![2, 2, 2],
        shape_offsets: vec![0, 3],
        validity: None,
    };
    let firm = batch_arrow_schema(
        &schema_of(&[("a", ColumnKind::DoubleArray)]),
        &decoded_of(1, vec![DecodedColumn::DoubleArray(firm_buffers)]),
    )
    .unwrap();

    assert!(schemas_equal(&tentative, &firm));
    assert!(schemas_equal(&firm, &tentative));
}

#[test]
fn schemas_equal_detects_array_dim_drift_when_both_firm() {
    let mut data1 = Vec::new();
    for v in [1.0f64, 2.0, 3.0] {
        data1.extend_from_slice(&v.to_le_bytes());
    }
    let b1 = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 24],
        data: bytes::Bytes::from(data1),
        shapes: vec![3],
        shape_offsets: vec![0, 1],
        validity: None,
    };
    let s1 = batch_arrow_schema(
        &schema_of(&[("a", ColumnKind::DoubleArray)]),
        &decoded_of(1, vec![DecodedColumn::DoubleArray(b1)]),
    )
    .unwrap();
    let mut data2 = Vec::new();
    for v in [1.0f64, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0] {
        data2.extend_from_slice(&v.to_le_bytes());
    }
    let b2 = crate::egress::decoder::ArrayBuffers {
        data_offsets: vec![0, 64],
        data: bytes::Bytes::from(data2),
        shapes: vec![2, 2, 2],
        shape_offsets: vec![0, 3],
        validity: None,
    };
    let s2 = batch_arrow_schema(
        &schema_of(&[("a", ColumnKind::DoubleArray)]),
        &decoded_of(1, vec![DecodedColumn::DoubleArray(b2)]),
    )
    .unwrap();
    assert!(!schemas_equal(&s1, &s2));
}

// Force `ArrayDataBuilder::build()` to reject a malformed Decimal64
// payload (10 rows promised, only 8 bytes supplied — one row's worth)
// and verify the failure surfaces as `ErrorCode::ArrowExport` through
// `batch_to_record_batch`. Regression guard against the export wrap
// being dropped on a future refactor: without it, the underlying
// arrow-rs error would propagate as a different code (or panic under
// `panic = "abort"`).
#[test]
fn arrow_export_surfaces_on_malformed_decimal64() {
    use crate::egress::error::ErrorCode;
    let values = vec![0u8; 8];
    let s = schema_of(&[("d", ColumnKind::Decimal64)]);
    let b = decoded_of(
        10,
        vec![DecodedColumn::Decimal64 {
            buffer: buf(values, None),
            scale: 2,
        }],
    );
    let arrow_schema = Arc::new(batch_arrow_schema(&s, &b).unwrap());
    let err = batch_to_record_batch(arrow_schema, &s, b, &SymbolDict::new())
        .expect_err("malformed Decimal64 must error, not panic");
    assert_eq!(err.code(), ErrorCode::ArrowExport);
}
