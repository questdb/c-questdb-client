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

//! `RecordBatch → QWP/WebSocket frame` ingress, 1-copy. Walks an Arrow
//! `RecordBatch` once, writing column bodies straight into the
//! connection's outbound buffer — no intermediate per-column staging.
//!
//! The per-Arrow-type wire-body writers (`write_arrow_column_body`,
//! `write_arrow_designated_ts_body`) and the symbol pre-pass
//! (`resolve_arrow_symbols`) are factored so a follow-up patch can drive
//! the per-column chunk appender from the same code.

use arrow_array::{
    Array, ArrayRef, BinaryArray, BinaryViewArray, BooleanArray, Date32Array, Date64Array,
    Decimal32Array, Decimal64Array, Decimal128Array, Decimal256Array, DictionaryArray,
    DurationMicrosecondArray, DurationMillisecondArray, DurationNanosecondArray,
    DurationSecondArray, FixedSizeBinaryArray, FixedSizeListArray, Float16Array, Float32Array,
    Float64Array, Int8Array, Int16Array, Int32Array, Int64Array, LargeBinaryArray, LargeListArray,
    LargeStringArray, ListArray, RecordBatch, StringArray, StringViewArray, Time32MillisecondArray,
    Time32SecondArray, Time64MicrosecondArray, Time64NanosecondArray, TimestampMicrosecondArray,
    TimestampMillisecondArray, TimestampNanosecondArray, TimestampSecondArray, UInt8Array,
    UInt16Array, UInt32Array, UInt64Array,
    types::{UInt8Type, UInt16Type, UInt32Type},
};
use arrow_buffer::NullBuffer;
use arrow_schema::{DataType, Field, Schema as ArrowSchema, SchemaRef, TimeUnit};
use std::sync::Arc;

use crate::error::{Error, ErrorCode};
use crate::ingress::buffer::SymbolGlobalDict;
use crate::ingress::{ColumnName, TableName};
use crate::{Result, fmt};

use super::wire::{
    QWP_FLAG_DEFER_COMMIT, QWP_FLAG_DELTA_SYMBOL_DICT, QWP_HEADER_LEN, QWP_MAGIC, QWP_TYPE_BINARY,
    QWP_TYPE_BOOLEAN, QWP_TYPE_BYTE, QWP_TYPE_CHAR, QWP_TYPE_DATE, QWP_TYPE_DECIMAL64,
    QWP_TYPE_DECIMAL128, QWP_TYPE_DECIMAL256, QWP_TYPE_DOUBLE, QWP_TYPE_DOUBLE_ARRAY,
    QWP_TYPE_FLOAT, QWP_TYPE_GEOHASH, QWP_TYPE_INT, QWP_TYPE_IPV4, QWP_TYPE_LONG, QWP_TYPE_LONG256,
    QWP_TYPE_SHORT, QWP_TYPE_SYMBOL, QWP_TYPE_TIMESTAMP, QWP_TYPE_TIMESTAMP_NANOS, QWP_TYPE_UUID,
    QWP_TYPE_VARCHAR, QWP_VERSION_1, validate_name, write_qwp_bytes, write_qwp_varint,
};

use super::MAX_CHUNK_ROWS as MAX_ARROW_INGEST_ROWS;
const COLUMN_ERR_PREFIX: &str = "[column='";

use crate::ingress::buffer::QWP_DECIMAL_MAX_SCALE;

/// Per-column wire-type hint that overrides what `classify()` would
/// otherwise derive from the Arrow `Field`'s data type alone. Useful
/// when the Arrow source has no `questdb.*` Field metadata to carry
/// the hint (e.g. Polars frames built without pyarrow).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum ArrowColumnOverride<'a> {
    /// Treat a UTF-8 / LargeUtf8 / Utf8View column as `SYMBOL`.
    Symbol { column: &'a str },
    /// Force a Dictionary(*, Utf8 / LargeUtf8) column to `VARCHAR`
    /// wire, decoding the dictionary on emit. No-op on non-dictionary
    /// columns (plain Utf8 is VARCHAR by default).
    NotSymbol { column: &'a str },
    /// Treat a UInt32 column as `IPV4`.
    Ipv4 { column: &'a str },
    /// Treat a UInt16 column as `CHAR`.
    Char { column: &'a str },
    /// Treat an Int8/16/32/64 column as `GEOHASH(bits)`. `bits` must
    /// be in `1..=60`.
    Geohash { column: &'a str, bits: u8 },
}

impl<'a> ArrowColumnOverride<'a> {
    /// Name of the column this override applies to.
    pub fn column(&self) -> &'a str {
        match *self {
            Self::Symbol { column }
            | Self::NotSymbol { column }
            | Self::Ipv4 { column }
            | Self::Char { column }
            | Self::Geohash { column, .. } => column,
        }
    }
}

// We patch field metadata up-front rather than extending `classify`'s
// signature: it keeps the per-column hot loop unchanged and lets the
// override path reuse every existing metadata-driven branch.
pub(crate) fn apply_overrides(
    schema: &SchemaRef,
    overrides: &[ArrowColumnOverride<'_>],
) -> Result<SchemaRef> {
    use std::collections::HashMap;

    let mut by_name: HashMap<&str, &ArrowColumnOverride<'_>> =
        HashMap::with_capacity(overrides.len());
    for ov in overrides {
        if by_name.insert(ov.column(), ov).is_some() {
            return Err(fmt!(
                ArrowIngest,
                "duplicate arrow override for column '{}'",
                ov.column()
            ));
        }
    }

    for ov in overrides {
        if !schema.fields().iter().any(|f| f.name() == ov.column()) {
            return Err(fmt!(
                ArrowIngest,
                "override targets unknown column '{}'",
                ov.column()
            ));
        }
        if let ArrowColumnOverride::Geohash { bits, column } = *ov
            && (bits == 0 || bits > 60)
        {
            return Err(fmt!(
                ArrowIngest,
                "override for column '{}' has invalid geohash bits {} (must be 1..=60)",
                column,
                bits
            ));
        }
    }

    let mut patched_fields: Vec<Arc<Field>> = Vec::with_capacity(schema.fields().len());
    let mut any_changed = false;
    for field in schema.fields().iter() {
        let Some(ov) = by_name.get(field.name().as_str()) else {
            patched_fields.push(field.clone());
            continue;
        };
        let mut md = field.metadata().clone();
        match **ov {
            ArrowColumnOverride::Symbol { .. } => {
                md.insert(
                    crate::egress::arrow::metadata::COLUMN_TYPE.to_string(),
                    "symbol".to_string(),
                );
                md.insert(
                    crate::egress::arrow::metadata::SYMBOL.to_string(),
                    "true".to_string(),
                );
            }
            ArrowColumnOverride::NotSymbol { .. } => {
                md.insert(
                    crate::egress::arrow::metadata::SYMBOL.to_string(),
                    "false".to_string(),
                );
            }
            ArrowColumnOverride::Ipv4 { .. } => {
                md.insert(
                    crate::egress::arrow::metadata::COLUMN_TYPE.to_string(),
                    "ipv4".to_string(),
                );
            }
            ArrowColumnOverride::Char { .. } => {
                md.insert(
                    crate::egress::arrow::metadata::COLUMN_TYPE.to_string(),
                    "char".to_string(),
                );
            }
            ArrowColumnOverride::Geohash { bits, .. } => {
                md.insert(
                    crate::egress::arrow::metadata::GEOHASH_BITS.to_string(),
                    bits.to_string(),
                );
            }
        }
        if md == *field.metadata() {
            patched_fields.push(field.clone());
        } else {
            any_changed = true;
            let new_field = Field::new(
                field.name().clone(),
                field.data_type().clone(),
                field.is_nullable(),
            )
            .with_metadata(md);
            patched_fields.push(Arc::new(new_field));
        }
    }

    if !any_changed {
        return Ok(schema.clone());
    }
    let new_schema = ArrowSchema::new_with_metadata(patched_fields, schema.metadata().clone());
    Ok(Arc::new(new_schema))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DictKey {
    I8,
    I16,
    I32,
    U8,
    U16,
    U32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DictValue {
    Utf8,
    LargeUtf8,
    Utf8View,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ColumnKind {
    Bool,
    I8,
    I16,
    I32,
    I64,
    F16ToF32,
    F32,
    F64,
    Char,
    Ipv4,
    I8WidenToI32,
    I16WidenToI32,
    I32WidenToI64,
    U8WidenToI32,
    U16WidenToI32,
    U32WidenToI64,
    U64WidenToI64Checked,
    TimestampSecondToMicros,
    TimestampMicros,
    TimestampNanos,
    Date,
    Date32Days,
    Date64Ms,
    TimeAsLong(TimeUnit),
    DurationAsLong(TimeUnit),
    Utf8,
    LargeUtf8,
    Utf8View,
    SymbolUtf8,
    SymbolLargeUtf8,
    SymbolUtf8View,
    Binary,
    LargeBinary,
    BinaryView,
    Uuid,
    Long256,
    Geohash(u8),
    SymbolDict { key: DictKey, value: DictValue },
    DictToVarchar { key: DictKey, value: DictValue },
    Decimal32WidenToDecimal64,
    Decimal64,
    Decimal128,
    Decimal256,
    ArrayDouble(usize),
}

pub(crate) fn classify(field: &Field, _array: &dyn Array) -> Result<ColumnKind> {
    let md_type = field
        .metadata()
        .get(crate::egress::arrow::metadata::COLUMN_TYPE)
        .map(String::as_str);
    let md_ext = field
        .metadata()
        .get(crate::egress::arrow::metadata::ARROW_EXTENSION_NAME)
        .map(String::as_str);
    let md_geo_bits = field
        .metadata()
        .get(crate::egress::arrow::metadata::GEOHASH_BITS)
        .and_then(|s| s.parse::<u8>().ok());
    let wants_symbol = md_type == Some("symbol")
        || field
            .metadata()
            .get(crate::egress::arrow::metadata::SYMBOL)
            .is_some_and(|v| v == "true");
    let wants_not_symbol = field
        .metadata()
        .get(crate::egress::arrow::metadata::SYMBOL)
        .is_some_and(|v| v == "false");
    let check_geohash_width = |bits: u8, max_bits: u8, dtype_name: &str| -> Result<u8> {
        if bits == 0 || bits > max_bits {
            return Err(fmt!(
                ArrowIngest,
                "geohash precision_bits {} out of range for {} column (must be 1..={})",
                bits,
                dtype_name,
                max_bits
            ));
        }
        Ok(bits)
    };
    if md_geo_bits.is_some()
        && let Some(t) = md_type
        && !t.starts_with("geohash")
    {
        return Err(fmt!(
            ArrowIngest,
            "column '{}' carries 'questdb.geohash_bits' but column_type='{}'; \
             drop one of the hints or set column_type='geohash'",
            field.name(),
            t
        ));
    }
    Ok(match (field.data_type(), md_type, md_ext) {
        (DataType::Boolean, _, _) => ColumnKind::Bool,
        (DataType::Int8, Some("byte"), _) => ColumnKind::I8,
        (DataType::Int8, Some(name), _) if name.starts_with("geohash") => {
            let bits = md_geo_bits.ok_or_else(|| {
                fmt!(
                    ArrowIngest,
                    "column '{}' has column_type='{}' but missing or invalid 'questdb.geohash_bits' metadata (1..=60 expected)",
                    field.name(),
                    name
                )
            })?;
            ColumnKind::Geohash(check_geohash_width(bits, 8, "Int8")?)
        }
        (DataType::Int8, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 8, "Int8")?)
        }
        (DataType::Int8, _, _) => ColumnKind::I8WidenToI32,
        (DataType::Int16, Some("short"), _) => ColumnKind::I16,
        (DataType::Int16, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 16, "Int16")?)
        }
        (DataType::Int16, _, _) => ColumnKind::I16WidenToI32,
        (DataType::Int32, Some("int"), _) => ColumnKind::I32,
        (DataType::Int32, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 32, "Int32")?)
        }
        (DataType::Int32, _, _) => ColumnKind::I32WidenToI64,
        (DataType::Int64, _, _) if md_geo_bits.is_some() => {
            ColumnKind::Geohash(check_geohash_width(md_geo_bits.unwrap(), 60, "Int64")?)
        }
        (DataType::Int64, _, _) => ColumnKind::I64,
        (DataType::Float16, _, _) => ColumnKind::F16ToF32,
        (DataType::Float32, _, _) => ColumnKind::F32,
        (DataType::Float64, _, _) => ColumnKind::F64,
        (DataType::UInt8, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt8"));
        }
        (DataType::UInt8, _, _) => ColumnKind::U8WidenToI32,
        (DataType::UInt16, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt16"));
        }
        (DataType::UInt16, Some("char"), _) => ColumnKind::Char,
        (DataType::UInt16, _, _) => ColumnKind::U16WidenToI32,
        (DataType::UInt32, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt32"));
        }
        (DataType::UInt32, Some("ipv4"), _) => ColumnKind::Ipv4,
        (DataType::UInt32, _, _) => ColumnKind::U32WidenToI64,
        (DataType::UInt64, _, _) if md_geo_bits.is_some() => {
            return Err(geohash_on_unsigned_error(field, "UInt64"));
        }
        (DataType::UInt64, _, _) => ColumnKind::U64WidenToI64Checked,
        (DataType::Timestamp(TimeUnit::Second, _), _, _) => ColumnKind::TimestampSecondToMicros,
        (DataType::Timestamp(TimeUnit::Microsecond, _), _, _) => ColumnKind::TimestampMicros,
        (DataType::Timestamp(TimeUnit::Nanosecond, _), _, _) => ColumnKind::TimestampNanos,
        (DataType::Timestamp(TimeUnit::Millisecond, _), _, _) => ColumnKind::Date,
        (DataType::Date32, _, _) => ColumnKind::Date32Days,
        (DataType::Date64, _, _) => ColumnKind::Date64Ms,
        (DataType::Time32(unit @ (TimeUnit::Second | TimeUnit::Millisecond)), _, _) => {
            ColumnKind::TimeAsLong(*unit)
        }
        (DataType::Time32(unit), _, _) => {
            return Err(fmt!(
                ArrowIngest,
                "column '{}': Time32({:?}) is not a valid Arrow type; \
                 Time32 only permits Second or Millisecond",
                field.name(),
                unit
            ));
        }
        (DataType::Time64(unit @ (TimeUnit::Microsecond | TimeUnit::Nanosecond)), _, _) => {
            ColumnKind::TimeAsLong(*unit)
        }
        (DataType::Time64(unit), _, _) => {
            return Err(fmt!(
                ArrowIngest,
                "column '{}': Time64({:?}) is not a valid Arrow type; \
                 Time64 only permits Microsecond or Nanosecond",
                field.name(),
                unit
            ));
        }
        (DataType::Duration(unit), _, _) => ColumnKind::DurationAsLong(*unit),
        (DataType::Utf8, _, _) if wants_symbol => ColumnKind::SymbolUtf8,
        (DataType::Utf8, _, _) => ColumnKind::Utf8,
        (DataType::LargeUtf8, _, _) if wants_symbol => ColumnKind::SymbolLargeUtf8,
        (DataType::LargeUtf8, _, _) => ColumnKind::LargeUtf8,
        (DataType::Utf8View, _, _) if wants_symbol => ColumnKind::SymbolUtf8View,
        (DataType::Utf8View, _, _) => ColumnKind::Utf8View,
        (DataType::Binary, _, _) => ColumnKind::Binary,
        (DataType::LargeBinary, _, _) => ColumnKind::LargeBinary,
        (DataType::BinaryView, _, _) => ColumnKind::BinaryView,
        (DataType::FixedSizeBinary(16), _, _) => ColumnKind::Uuid,
        (DataType::FixedSizeBinary(32), _, _) => ColumnKind::Long256,
        (DataType::Dictionary(key, value), _, _)
            if dict_key_for(key).is_some() && dict_value_for(value).is_some() =>
        {
            let k = dict_key_for(key).unwrap();
            let v = dict_value_for(value).unwrap();
            if wants_not_symbol {
                ColumnKind::DictToVarchar { key: k, value: v }
            } else {
                ColumnKind::SymbolDict { key: k, value: v }
            }
        }
        (DataType::Decimal32(_, _), _, _) => ColumnKind::Decimal32WidenToDecimal64,
        (DataType::Decimal64(_, _), _, _) => ColumnKind::Decimal64,
        (DataType::Decimal128(_, _), _, _) => ColumnKind::Decimal128,
        (DataType::Decimal256(_, _), _, _) => ColumnKind::Decimal256,
        (DataType::List(_) | DataType::LargeList(_) | DataType::FixedSizeList(_, _), _, _) => {
            let (leaf, ndim) = walk_list_leaf(field.data_type());
            if ndim > crate::ingress::MAX_ARRAY_DIMS {
                return Err(Error::new(
                    ErrorCode::ArrowUnsupportedColumnKind,
                    format!(
                        "Arrow nested-list column '{}' nesting depth {} exceeds MAX_ARRAY_DIMS ({})",
                        field.name(),
                        ndim,
                        crate::ingress::MAX_ARRAY_DIMS
                    ),
                ));
            }
            match leaf {
                DataType::Float64 => ColumnKind::ArrayDouble(ndim),
                other => {
                    return Err(Error::new(
                        ErrorCode::ArrowUnsupportedColumnKind,
                        format!(
                            "Arrow nested-list column '{}' leaf {:?} is not supported; QuestDB ARRAY ingress requires Float64 leaf",
                            field.name(),
                            other
                        ),
                    ));
                }
            }
        }
        (other, _, _) => {
            return Err(Error::new(
                ErrorCode::ArrowUnsupportedColumnKind,
                format!(
                    "Arrow type {:?} on column '{}' is not supported by flush_arrow_batch",
                    other,
                    field.name()
                ),
            ));
        }
    })
}

fn walk_list_leaf(dt: &DataType) -> (DataType, usize) {
    let mut depth = 1usize;
    let mut current = dt.clone();
    loop {
        let inner = match &current {
            DataType::List(field) | DataType::LargeList(field) => field.data_type().clone(),
            DataType::FixedSizeList(field, _) => field.data_type().clone(),
            other => return (other.clone(), depth),
        };
        if matches!(
            inner,
            DataType::List(_) | DataType::LargeList(_) | DataType::FixedSizeList(_, _)
        ) {
            depth += 1;
            current = inner;
        } else {
            return (inner, depth);
        }
    }
}

fn dict_key_for(dt: &DataType) -> Option<DictKey> {
    Some(match dt {
        DataType::Int8 => DictKey::I8,
        DataType::Int16 => DictKey::I16,
        DataType::Int32 => DictKey::I32,
        DataType::UInt8 => DictKey::U8,
        DataType::UInt16 => DictKey::U16,
        DataType::UInt32 => DictKey::U32,
        _ => return None,
    })
}

fn dict_value_for(dt: &DataType) -> Option<DictValue> {
    Some(match dt {
        DataType::Utf8 => DictValue::Utf8,
        DataType::LargeUtf8 => DictValue::LargeUtf8,
        DataType::Utf8View => DictValue::Utf8View,
        _ => return None,
    })
}

fn geohash_on_unsigned_error(field: &Field, dtype_name: &str) -> Error {
    Error::new(
        ErrorCode::ArrowIngest,
        format!(
            "column '{}': geohash on unsigned Arrow type {} is not supported; widen to a signed type",
            field.name(),
            dtype_name
        ),
    )
}

// ===========================================================================
// Wire-type byte mapping
// ===========================================================================

pub(crate) fn wire_type_byte(kind: ColumnKind, _has_nulls: bool) -> u8 {
    match kind {
        ColumnKind::Bool => QWP_TYPE_BOOLEAN,
        ColumnKind::I8 => QWP_TYPE_BYTE,
        ColumnKind::I16 => QWP_TYPE_SHORT,
        ColumnKind::I32
        | ColumnKind::I8WidenToI32
        | ColumnKind::I16WidenToI32
        | ColumnKind::U8WidenToI32
        | ColumnKind::U16WidenToI32 => QWP_TYPE_INT,
        ColumnKind::I64
        | ColumnKind::I32WidenToI64
        | ColumnKind::U32WidenToI64
        | ColumnKind::U64WidenToI64Checked
        | ColumnKind::TimeAsLong(_)
        | ColumnKind::DurationAsLong(_) => QWP_TYPE_LONG,
        ColumnKind::F16ToF32 | ColumnKind::F32 => QWP_TYPE_FLOAT,
        ColumnKind::F64 => QWP_TYPE_DOUBLE,
        ColumnKind::Char => QWP_TYPE_CHAR,
        ColumnKind::Ipv4 => QWP_TYPE_IPV4,
        ColumnKind::TimestampSecondToMicros | ColumnKind::TimestampMicros => QWP_TYPE_TIMESTAMP,
        ColumnKind::TimestampNanos => QWP_TYPE_TIMESTAMP_NANOS,
        ColumnKind::Date | ColumnKind::Date32Days | ColumnKind::Date64Ms => QWP_TYPE_DATE,
        ColumnKind::Utf8
        | ColumnKind::LargeUtf8
        | ColumnKind::Utf8View
        | ColumnKind::DictToVarchar { .. } => QWP_TYPE_VARCHAR,
        ColumnKind::SymbolUtf8
        | ColumnKind::SymbolLargeUtf8
        | ColumnKind::SymbolUtf8View
        | ColumnKind::SymbolDict { .. } => QWP_TYPE_SYMBOL,
        ColumnKind::Binary | ColumnKind::LargeBinary | ColumnKind::BinaryView => QWP_TYPE_BINARY,
        ColumnKind::Uuid => QWP_TYPE_UUID,
        ColumnKind::Long256 => QWP_TYPE_LONG256,
        ColumnKind::Geohash(_) => QWP_TYPE_GEOHASH,
        ColumnKind::Decimal32WidenToDecimal64 | ColumnKind::Decimal64 => QWP_TYPE_DECIMAL64,
        ColumnKind::Decimal128 => QWP_TYPE_DECIMAL128,
        ColumnKind::Decimal256 => QWP_TYPE_DECIMAL256,
        ColumnKind::ArrayDouble(_) => QWP_TYPE_DOUBLE_ARRAY,
    }
}

fn kind_supports_sparse_nulls(kind: ColumnKind) -> bool {
    matches!(
        kind,
        ColumnKind::Ipv4
            | ColumnKind::TimestampSecondToMicros
            | ColumnKind::TimestampMicros
            | ColumnKind::TimestampNanos
            | ColumnKind::Date
            | ColumnKind::Date32Days
            | ColumnKind::Date64Ms
            | ColumnKind::Utf8
            | ColumnKind::LargeUtf8
            | ColumnKind::Utf8View
            | ColumnKind::SymbolUtf8
            | ColumnKind::SymbolLargeUtf8
            | ColumnKind::SymbolUtf8View
            | ColumnKind::SymbolDict { .. }
            | ColumnKind::DictToVarchar { .. }
            | ColumnKind::Binary
            | ColumnKind::LargeBinary
            | ColumnKind::BinaryView
            | ColumnKind::Uuid
            | ColumnKind::Long256
            | ColumnKind::Geohash(_)
            | ColumnKind::Decimal32WidenToDecimal64
            | ColumnKind::Decimal64
            | ColumnKind::Decimal128
            | ColumnKind::Decimal256
            | ColumnKind::ArrayDouble(_)
    )
}

fn try_reserve_bytes(out: &mut Vec<u8>, additional: usize, label: &str) -> Result<()> {
    out.try_reserve(additional).map_err(|_| {
        fmt!(
            ArrowIngest,
            "{}: allocator could not reserve {} bytes",
            label,
            additional
        )
    })
}

fn extend_le_bytes_checked(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    try_reserve_bytes(out, bytes.len(), "primitive LE fast-path")?;
    out.extend_from_slice(bytes);
    Ok(())
}

#[inline]
unsafe fn typed_slice_as_le_bytes<T: Copy>(slice: &[T]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(slice.as_ptr() as *const u8, std::mem::size_of_val(slice)) }
}

fn non_null_count(arr: &dyn Array, label: &str) -> Result<usize> {
    let row_count = arr.len();
    let null_count = arr.null_count();
    if null_count > row_count {
        return Err(fmt!(
            ArrowIngest,
            "{}: null_count {} exceeds len {}; inconsistent Arrow buffer",
            label,
            null_count,
            row_count
        ));
    }
    Ok(row_count - null_count)
}

fn write_qwp_bitmap_from_arrow(out: &mut Vec<u8>, nulls: &NullBuffer) -> Result<()> {
    let bits = nulls.len();
    let total_bytes = bits.div_ceil(8);
    try_reserve_bytes(out, total_bytes, "QWP bitmap")?;
    let arrow_offset = nulls.offset();
    let src = nulls.inner().values();
    let full_bytes = bits / 8;
    let trailing_bits = bits % 8;
    let dst_start = out.len();
    out.resize(dst_start + total_bytes, 0);
    let dst = &mut out[dst_start..dst_start + total_bytes];
    if arrow_offset.is_multiple_of(8) {
        let src_off = arrow_offset / 8;
        let src_slice = &src[src_off..src_off + full_bytes];
        let dst_slice = &mut dst[..full_bytes];
        let word_bytes = (full_bytes / 8) * 8;
        let (src_words, src_rem) = src_slice.split_at(word_bytes);
        let (dst_words, dst_rem) = dst_slice.split_at_mut(word_bytes);
        for (dchunk, schunk) in dst_words.chunks_exact_mut(8).zip(src_words.chunks_exact(8)) {
            let w = u64::from_ne_bytes(schunk.try_into().unwrap());
            dchunk.copy_from_slice(&(!w).to_ne_bytes());
        }
        for (d, &s) in dst_rem.iter_mut().zip(src_rem) {
            *d = !s;
        }
        if trailing_bits != 0 {
            let mask = (1u8 << trailing_bits) - 1;
            dst[full_bytes] = (!src[src_off + full_bytes]) & mask;
        }
    } else {
        // Byte-stride shift fallback. Read two adjacent source bytes,
        // shift+OR to reconstruct the byte-aligned bits, then NOT for
        // the QWP convention (1 = null). 8× faster than the per-bit
        // loop and matches semantics exactly.
        let shift = (arrow_offset % 8) as u32;
        let first_byte = arrow_offset / 8;
        let inv_shift = 8 - shift;
        let src_len = src.len();
        for (i, d) in dst[..full_bytes].iter_mut().enumerate() {
            let lo_idx = first_byte + i;
            let lo = if lo_idx < src_len { src[lo_idx] } else { 0 };
            let hi_idx = lo_idx + 1;
            let hi = if hi_idx < src_len { src[hi_idx] } else { 0 };
            *d = !((lo >> shift) | (hi << inv_shift));
        }
        if trailing_bits != 0 {
            let lo_idx = first_byte + full_bytes;
            let lo = if lo_idx < src_len { src[lo_idx] } else { 0 };
            let hi_idx = lo_idx + 1;
            let hi = if hi_idx < src_len { src[hi_idx] } else { 0 };
            let mask = (1u8 << trailing_bits) - 1;
            dst[full_bytes] = (!((lo >> shift) | (hi << inv_shift))) & mask;
        }
    }
    Ok(())
}

fn full_with_sentinel<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    sentinel: [u8; N],
    mut get: impl FnMut(usize) -> [u8; N],
) -> Result<()> {
    let row_count = arr.len();
    let bytes = row_count.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "primitive column: row_count {} * elem {} overflows usize",
            row_count,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    match arr.nulls() {
        None => {
            for row in 0..row_count {
                out.extend_from_slice(&get(row));
            }
        }
        Some(nulls) => {
            for row in 0..row_count {
                if nulls.is_null(row) {
                    out.extend_from_slice(&sentinel);
                } else {
                    out.extend_from_slice(&get(row));
                }
            }
        }
    }
    Ok(())
}

/// Nullable LE same-width fast path: memcpy the typed value slab as-is,
/// then walk the null bitmap and overwrite null slots with the sentinel.
/// Only valid for LE targets where `T`'s in-memory layout matches the
/// QWP wire encoding. The Arrow buffer's null-slot values are
/// undefined-but-readable (Arrow guarantees the value buffer is fully
/// allocated even where the null mask says "missing"), so the memcpy of
/// garbage is safe; we overwrite each null slot before any downstream
/// consumer sees it.
fn nullable_le_memcpy_patch<const N: usize>(
    out: &mut Vec<u8>,
    values_le: &[u8],
    nulls: &NullBuffer,
    sentinel: [u8; N],
) -> Result<()> {
    debug_assert_eq!(values_le.len(), nulls.len() * N);
    let dst_start = out.len();
    try_reserve_bytes(out, values_le.len(), "primitive column memcpy+patch")?;
    out.extend_from_slice(values_le);
    let row_count = nulls.len();
    let inner = nulls.inner();
    let offset = inner.offset();
    let bits = inner.values();
    let mut row = 0usize;
    while row < row_count {
        let abs_bit = offset + row;
        let byte_idx = abs_bit / 8;
        let bit_off = abs_bit % 8;
        if bit_off == 0 && row + 8 <= row_count {
            let v = bits[byte_idx];
            if v == 0xFF {
                row += 8;
                continue;
            }
            if v == 0 {
                let slab_start = dst_start + row * N;
                for slot in 0..8 {
                    let off = slab_start + slot * N;
                    out[off..off + N].copy_from_slice(&sentinel);
                }
                row += 8;
                continue;
            }
            for slot in 0..8 {
                if (v >> slot) & 1 == 0 {
                    let off = dst_start + (row + slot) * N;
                    out[off..off + N].copy_from_slice(&sentinel);
                }
            }
            row += 8;
        } else {
            if (bits[byte_idx] >> bit_off) & 1 == 0 {
                let off = dst_start + row * N;
                out[off..off + N].copy_from_slice(&sentinel);
            }
            row += 1;
        }
    }
    Ok(())
}

fn try_full_with_sentinel<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    sentinel: [u8; N],
    mut get: impl FnMut(usize) -> Result<[u8; N]>,
) -> Result<()> {
    let row_count = arr.len();
    let bytes = row_count.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "primitive column: row_count {} * elem {} overflows usize",
            row_count,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    match arr.nulls() {
        None => {
            for row in 0..row_count {
                out.extend_from_slice(&get(row)?);
            }
        }
        Some(nulls) => {
            for row in 0..row_count {
                if nulls.is_null(row) {
                    out.extend_from_slice(&sentinel);
                } else {
                    out.extend_from_slice(&get(row)?);
                }
            }
        }
    }
    Ok(())
}

fn non_null_le<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    mut get: impl FnMut(usize) -> [u8; N],
) -> Result<()> {
    let non_null = non_null_count(arr, "primitive column")?;
    let row_count = arr.len();
    let bytes = non_null.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "primitive column: non_null {} * elem {} overflows usize",
            non_null,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    match arr.nulls() {
        None => {
            for row in 0..row_count {
                out.extend_from_slice(&get(row));
            }
        }
        Some(nulls) => {
            for row in 0..row_count {
                if nulls.is_null(row) {
                    continue;
                }
                out.extend_from_slice(&get(row));
            }
        }
    }
    Ok(())
}

fn try_non_null_le<const N: usize>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    mut get: impl FnMut(usize) -> Result<[u8; N]>,
) -> Result<()> {
    let non_null = non_null_count(arr, "primitive column")?;
    let row_count = arr.len();
    let bytes = non_null.checked_mul(N).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "primitive column: non_null {} * elem {} overflows usize",
            non_null,
            N
        )
    })?;
    try_reserve_bytes(out, bytes, "primitive column")?;
    match arr.nulls() {
        None => {
            for row in 0..row_count {
                out.extend_from_slice(&get(row)?);
            }
        }
        Some(nulls) => {
            for row in 0..row_count {
                if nulls.is_null(row) {
                    continue;
                }
                out.extend_from_slice(&get(row)?);
            }
        }
    }
    Ok(())
}

fn u64_to_i64_le_checked(v: u64, row: usize) -> Result<[u8; 8]> {
    if v > i64::MAX as u64 {
        return Err(fmt!(
            ArrowIngest,
            "UInt64 value {} at row {} does not fit QuestDB LONG (max i64::MAX)",
            v,
            row
        ));
    }
    Ok((v as i64).to_le_bytes())
}

fn non_null_fsb(out: &mut Vec<u8>, arr: &FixedSizeBinaryArray, size: usize) -> Result<()> {
    let non_null = non_null_count(arr, "FixedSizeBinary column")?;
    let row_count = arr.len();
    let bytes = non_null.checked_mul(size).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "FixedSizeBinary column: non_null {} * elem {} overflows usize",
            non_null,
            size
        )
    })?;
    try_reserve_bytes(out, bytes, "FixedSizeBinary column")?;
    match arr.nulls() {
        None => {
            for row in 0..row_count {
                out.extend_from_slice(arr.value(row));
            }
        }
        Some(nulls) => {
            for row in 0..row_count {
                if nulls.is_null(row) {
                    continue;
                }
                out.extend_from_slice(arr.value(row));
            }
        }
    }
    Ok(())
}

// ----- Bool payload (packed bits LSB-first; nulls coerce to 0) -----

fn write_bool_payload(out: &mut Vec<u8>, arr: &BooleanArray) -> Result<()> {
    let row_count = arr.len();
    let total_bytes = row_count.div_ceil(8);
    try_reserve_bytes(out, total_bytes, "BOOL column")?;
    let start = out.len();
    out.resize(start + total_bytes, 0);
    let value_buf = arr.values();
    let null_buf = arr.nulls();
    let nulls_aligned = null_buf.is_none_or(|nb| nb.offset().is_multiple_of(8));
    if value_buf.offset().is_multiple_of(8) && nulls_aligned {
        let n_bytes = row_count.div_ceil(8);
        let v_start = value_buf.offset() / 8;
        let v_end = v_start.checked_add(n_bytes).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "BOOL pack: value-buffer end offset overflow (start={}, n_bytes={})",
                v_start,
                n_bytes
            )
        })?;
        let raw = value_buf.values();
        if v_end > raw.len() {
            return Err(fmt!(
                ArrowIngest,
                "BOOL pack: value buffer {} bytes shorter than required {} bytes",
                raw.len(),
                v_end
            ));
        }
        let full_bytes = row_count / 8;
        out[start..start + full_bytes].copy_from_slice(&raw[v_start..v_start + full_bytes]);
        let trailing = row_count % 8;
        if trailing != 0 {
            let mask = (1u8 << trailing) - 1;
            out[start + full_bytes] |= raw[v_start + full_bytes] & mask;
        }
        if let Some(nb) = null_buf {
            let n_start = nb.offset() / 8;
            let n_end = n_start.checked_add(n_bytes).ok_or_else(|| {
                fmt!(
                    ArrowIngest,
                    "BOOL pack: null-buffer end offset overflow (start={}, n_bytes={})",
                    n_start,
                    n_bytes
                )
            })?;
            let null_raw = nb.buffer().as_slice();
            if n_end > null_raw.len() {
                return Err(fmt!(
                    ArrowIngest,
                    "BOOL pack: null buffer {} bytes shorter than required {} bytes",
                    null_raw.len(),
                    n_end
                ));
            }
            for (p, &v) in out[start..start + full_bytes]
                .iter_mut()
                .zip(&null_raw[n_start..n_start + full_bytes])
            {
                *p &= v;
            }
            if trailing != 0 {
                let mask = (1u8 << trailing) - 1;
                out[start + full_bytes] &= null_raw[n_start + full_bytes] | !mask;
            }
        }
        return Ok(());
    }
    for row in 0..row_count {
        if !arr.is_null(row) && arr.value(row) {
            let target = row;
            out[start + target / 8] |= 1 << (target % 8);
        }
    }
    Ok(())
}

fn write_varlen_u32_offsets_no_null(
    out: &mut Vec<u8>,
    arr_offsets: &[i32],
    arr_data: &[u8],
    row_count: usize,
    label: &str,
) -> Result<()> {
    if arr_offsets.len() < row_count + 1 {
        return Err(fmt!(
            ArrowIngest,
            "{}: offsets buffer {} shorter than required {}",
            label,
            arr_offsets.len(),
            row_count + 1
        ));
    }
    let base = arr_offsets[0];
    if base < 0 {
        return Err(fmt!(ArrowIngest, "{}: negative offset {}", label, base));
    }
    let end = arr_offsets[row_count];
    if end < base {
        return Err(fmt!(
            ArrowIngest,
            "{}: offset end {} < base {}",
            label,
            end,
            base
        ));
    }
    let used = (end - base) as usize;
    if base as usize + used > arr_data.len() {
        return Err(fmt!(
            ArrowIngest,
            "{}: data slice out of bounds (base={}, used={}, data_len={})",
            label,
            base,
            used,
            arr_data.len()
        ));
    }
    let offsets_bytes = 4usize.checked_mul(row_count + 1).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "{}: offset table size overflow ({} rows)",
            label,
            row_count
        )
    })?;
    try_reserve_bytes(out, offsets_bytes + used, label)?;
    if base == 0 && cfg!(target_endian = "little") {
        let bytes =
            unsafe { std::slice::from_raw_parts(arr_offsets.as_ptr() as *const u8, offsets_bytes) };
        out.extend_from_slice(bytes);
    } else {
        for &off in &arr_offsets[..row_count + 1] {
            let normalized = (off - base) as u32;
            out.extend_from_slice(&normalized.to_le_bytes());
        }
    }
    out.extend_from_slice(&arr_data[base as usize..base as usize + used]);
    Ok(())
}

/// `bytes_upper_bound`, when `Some`, is the exact (or worst-case) byte
/// total the `emit_row` closure will append across all non-null rows.
/// It is reserved up front so the closure can do raw `extend_from_slice`
/// without paying a per-row checked allocation. Pass `None` when no
/// tight upper bound is known; the closure is then responsible for its
/// own `try_reserve_bytes` calls.
fn write_varlen_u32_offsets_with_bitmap<F>(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    label: &str,
    bytes_upper_bound: Option<usize>,
    mut emit_row: F,
) -> Result<()>
where
    F: FnMut(&mut Vec<u8>, usize) -> Result<u32>,
{
    let row_count = arr.len();
    let non_null = non_null_count(arr, label)?;
    let offsets_bytes = 4usize.checked_mul(non_null + 1).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "{}: offset table size overflow ({} non-null rows)",
            label,
            non_null
        )
    })?;
    let offsets_start = out.len();
    let reserve = match bytes_upper_bound {
        Some(b) => offsets_bytes
            .checked_add(b)
            .ok_or_else(|| fmt!(ArrowIngest, "{}: offsets+bytes reservation overflow", label))?,
        None => offsets_bytes,
    };
    try_reserve_bytes(out, reserve, label)?;
    out.resize(offsets_start + offsets_bytes, 0);
    out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());
    let mut cumulative: u32 = 0;
    let mut next_offset_idx = 1usize;
    let bytes_anchor = out.len();
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let written = emit_row(out, row)?;
        let next = cumulative.checked_add(written).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "{}: cumulative offset overflow at row {}",
                label,
                row
            )
        })?;
        cumulative = next;
        let pos = offsets_start + 4 * next_offset_idx;
        out[pos..pos + 4].copy_from_slice(&cumulative.to_le_bytes());
        next_offset_idx += 1;
    }
    debug_assert_eq!(next_offset_idx - 1, non_null);
    debug_assert_eq!(out.len() - bytes_anchor, cumulative as usize);
    Ok(())
}

/// Per-row emit closure with a per-row `try_reserve_bytes` probe. Use
/// when the outer caller did NOT reserve up front (i.e. passed
/// `bytes_upper_bound = None` to `write_varlen_u32_offsets_with_bitmap`).
fn emit_str_row<S: StrSource>(arr: &S) -> impl FnMut(&mut Vec<u8>, usize) -> Result<u32> + '_ {
    move |out, row| {
        let bytes = arr.value_bytes(row);
        try_reserve_bytes(out, bytes.len(), "VARCHAR column")?;
        out.extend_from_slice(bytes);
        u32::try_from(bytes.len()).map_err(|_| {
            fmt!(
                ArrowIngest,
                "VARCHAR column: row {} exceeds u32::MAX bytes",
                row
            )
        })
    }
}

/// Per-row emit closure without the per-row reserve probe. Caller MUST
/// have reserved enough capacity up front (via `bytes_upper_bound`) so
/// every `extend_from_slice` fits without reallocation.
fn emit_str_row_no_reserve<S: StrSource>(
    arr: &S,
) -> impl FnMut(&mut Vec<u8>, usize) -> Result<u32> + '_ {
    move |out, row| {
        let bytes = arr.value_bytes(row);
        out.extend_from_slice(bytes);
        u32::try_from(bytes.len()).map_err(|_| {
            fmt!(
                ArrowIngest,
                "VARCHAR column: row {} exceeds u32::MAX bytes",
                row
            )
        })
    }
}

fn emit_bytes_row<'a, F>(get: F) -> impl FnMut(&mut Vec<u8>, usize) -> Result<u32> + 'a
where
    F: Fn(usize) -> &'a [u8] + 'a,
{
    move |out, row| {
        let bytes = get(row);
        try_reserve_bytes(out, bytes.len(), "BINARY column")?;
        out.extend_from_slice(bytes);
        u32::try_from(bytes.len()).map_err(|_| {
            fmt!(
                ArrowIngest,
                "BINARY column: row {} exceeds u32::MAX bytes",
                row
            )
        })
    }
}

fn emit_bytes_row_no_reserve<'a, F>(get: F) -> impl FnMut(&mut Vec<u8>, usize) -> Result<u32> + 'a
where
    F: Fn(usize) -> &'a [u8] + 'a,
{
    move |out, row| {
        let bytes = get(row);
        out.extend_from_slice(bytes);
        u32::try_from(bytes.len()).map_err(|_| {
            fmt!(
                ArrowIngest,
                "BINARY column: row {} exceeds u32::MAX bytes",
                row
            )
        })
    }
}

fn write_string_payload(out: &mut Vec<u8>, arr: &StringArray, use_bitmap: bool) -> Result<()> {
    if use_bitmap {
        let bound = Some(arr.value_data().len());
        write_varlen_u32_offsets_with_bitmap(
            out,
            arr,
            "VARCHAR column",
            bound,
            emit_str_row_no_reserve(arr),
        )
    } else {
        write_varlen_u32_offsets_no_null(
            out,
            arr.value_offsets(),
            arr.value_data(),
            arr.len(),
            "VARCHAR column",
        )
    }
}

fn write_large_string_payload(
    out: &mut Vec<u8>,
    arr: &LargeStringArray,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        let bound = Some(arr.value_data().len());
        write_varlen_u32_offsets_with_bitmap(
            out,
            arr,
            "VARCHAR column",
            bound,
            emit_str_row_no_reserve(arr),
        )
    } else {
        write_varlen_large_offsets_no_null(out, arr.value_offsets(), arr.value_data(), arr.len())
    }
}

fn write_string_view_payload(
    out: &mut Vec<u8>,
    arr: &StringViewArray,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        write_varlen_u32_offsets_with_bitmap(out, arr, "VARCHAR column", None, emit_str_row(arr))
    } else {
        write_varlen_view_no_null(out, arr.len(), emit_str_row(arr))
    }
}

fn write_binary_payload(out: &mut Vec<u8>, arr: &BinaryArray, use_bitmap: bool) -> Result<()> {
    if use_bitmap {
        let bound = Some(arr.value_data().len());
        write_varlen_u32_offsets_with_bitmap(
            out,
            arr,
            "BINARY column",
            bound,
            emit_bytes_row_no_reserve(|row| arr.value(row)),
        )
    } else {
        write_varlen_u32_offsets_no_null(
            out,
            arr.value_offsets(),
            arr.value_data(),
            arr.len(),
            "BINARY column",
        )
    }
}

fn write_large_binary_payload(
    out: &mut Vec<u8>,
    arr: &LargeBinaryArray,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        let bound = Some(arr.value_data().len());
        write_varlen_u32_offsets_with_bitmap(
            out,
            arr,
            "BINARY column",
            bound,
            emit_bytes_row_no_reserve(|row| arr.value(row)),
        )
    } else {
        write_varlen_large_offsets_no_null(out, arr.value_offsets(), arr.value_data(), arr.len())
    }
}

fn write_binary_view_payload(
    out: &mut Vec<u8>,
    arr: &BinaryViewArray,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        write_varlen_u32_offsets_with_bitmap(
            out,
            arr,
            "BINARY column",
            None,
            emit_bytes_row(|row| arr.value(row)),
        )
    } else {
        write_varlen_view_no_null(out, arr.len(), emit_bytes_row(|row| arr.value(row)))
    }
}

fn write_varlen_large_offsets_no_null(
    out: &mut Vec<u8>,
    arr_offsets: &[i64],
    arr_data: &[u8],
    row_count: usize,
) -> Result<()> {
    if arr_offsets.len() < row_count + 1 {
        return Err(fmt!(
            ArrowIngest,
            "VARCHAR column: offsets buffer {} shorter than required {}",
            arr_offsets.len(),
            row_count + 1
        ));
    }
    let base = arr_offsets[0];
    if base < 0 {
        return Err(fmt!(
            ArrowIngest,
            "VARCHAR column: negative offset {}",
            base
        ));
    }
    let end = arr_offsets[row_count];
    if end < base {
        return Err(fmt!(
            ArrowIngest,
            "VARCHAR column: end offset {} below base {}",
            end,
            base
        ));
    }
    let used = (end - base) as usize;
    if base as usize + used > arr_data.len() {
        return Err(fmt!(
            ArrowIngest,
            "VARCHAR column: data slice out of bounds (base={}, used={}, data_len={})",
            base,
            used,
            arr_data.len()
        ));
    }
    let offsets_bytes = 4usize.checked_mul(row_count + 1).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "VARCHAR column: offset table size overflow ({} rows)",
            row_count
        )
    })?;
    try_reserve_bytes(out, offsets_bytes + used, "VARCHAR column")?;
    for &off in &arr_offsets[..row_count + 1] {
        let normalized = u32::try_from(off - base).map_err(|_| {
            fmt!(
                ArrowIngest,
                "VARCHAR column: cumulative offset exceeds u32::MAX at row >={}",
                row_count
            )
        })?;
        out.extend_from_slice(&normalized.to_le_bytes());
    }
    out.extend_from_slice(&arr_data[base as usize..base as usize + used]);
    Ok(())
}

fn write_varlen_view_no_null<F>(out: &mut Vec<u8>, row_count: usize, mut emit_row: F) -> Result<()>
where
    F: FnMut(&mut Vec<u8>, usize) -> Result<u32>,
{
    let offsets_bytes = 4usize.checked_mul(row_count + 1).ok_or_else(|| {
        fmt!(
            ArrowIngest,
            "VARCHAR column: offset table size overflow ({} rows)",
            row_count
        )
    })?;
    let offsets_start = out.len();
    try_reserve_bytes(out, offsets_bytes, "VARCHAR column")?;
    out.resize(offsets_start + offsets_bytes, 0);
    out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());
    let mut cumulative: u32 = 0;
    for row in 0..row_count {
        let written = emit_row(out, row)?;
        let next = cumulative.checked_add(written).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "VARCHAR column: cumulative offset overflow at row {}",
                row
            )
        })?;
        cumulative = next;
        let pos = offsets_start + 4 * (row + 1);
        out[pos..pos + 4].copy_from_slice(&cumulative.to_le_bytes());
    }
    Ok(())
}

// ----- Decimals -----

fn decimal_scale_u8(scale_i8: i8, label: &str, max_scale: u8) -> Result<u8> {
    if scale_i8 < 0 {
        return Err(fmt!(
            ArrowIngest,
            "{}: negative decimal scale {} is not supported",
            label,
            scale_i8
        ));
    }
    let scale = scale_i8 as u8;
    if scale > max_scale {
        return Err(fmt!(
            ArrowIngest,
            "{}: decimal scale {} exceeds max {}",
            label,
            scale,
            max_scale
        ));
    }
    Ok(scale)
}

fn write_decimal32_widen_to_64_payload(
    out: &mut Vec<u8>,
    arr: &Decimal32Array,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        try_non_null_le::<8>(out, arr, |row| Ok((arr.value(row) as i64).to_le_bytes()))
    } else {
        let row_count = arr.len();
        try_reserve_bytes(out, row_count * 8, "DECIMAL32 column")?;
        for &v in arr.values() {
            out.extend_from_slice(&(v as i64).to_le_bytes());
        }
        Ok(())
    }
}

fn write_decimal64_payload(
    out: &mut Vec<u8>,
    arr: &Decimal64Array,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        non_null_le::<8>(out, arr, |row| arr.value(row).to_le_bytes())
    } else if cfg!(target_endian = "little") {
        // SAFETY: i64 has no padding; LE target → wire-format bytes.
        extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(arr.values()) })
    } else {
        let row_count = arr.len();
        try_reserve_bytes(out, row_count * 8, "DECIMAL64 column")?;
        for &v in arr.values() {
            out.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }
}

fn write_decimal128_payload(
    out: &mut Vec<u8>,
    arr: &Decimal128Array,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        non_null_le::<16>(out, arr, |row| arr.value(row).to_le_bytes())
    } else if cfg!(target_endian = "little") {
        extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(arr.values()) })
    } else {
        let row_count = arr.len();
        try_reserve_bytes(out, row_count * 16, "DECIMAL128 column")?;
        for &v in arr.values() {
            out.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }
}

fn write_decimal256_payload(
    out: &mut Vec<u8>,
    arr: &Decimal256Array,
    use_bitmap: bool,
) -> Result<()> {
    if use_bitmap {
        let row_count = arr.len();
        let non_null = non_null_count(arr, "DECIMAL256 column")?;
        try_reserve_bytes(out, non_null * 32, "DECIMAL256 column")?;
        for row in 0..row_count {
            if arr.is_null(row) {
                continue;
            }
            out.extend_from_slice(&arr.value(row).to_le_bytes());
        }
        Ok(())
    } else if cfg!(target_endian = "little") {
        const _: () = {
            assert!(std::mem::size_of::<arrow_buffer::i256>() == 32);
            assert!(std::mem::align_of::<arrow_buffer::i256>() <= 32);
        };
        extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(arr.values()) })
    } else {
        let row_count = arr.len();
        try_reserve_bytes(out, row_count * 32, "DECIMAL256 column")?;
        for &v in arr.values() {
            out.extend_from_slice(&v.to_le_bytes());
        }
        Ok(())
    }
}

// ----- Time / Duration → i64 -----

fn write_time_as_long_payload(out: &mut Vec<u8>, arr: &dyn Array, unit: TimeUnit) -> Result<()> {
    full_with_sentinel::<8>(out, arr, i64::MIN.to_le_bytes(), |row| match unit {
        TimeUnit::Second => {
            let a = arr.as_any().downcast_ref::<Time32SecondArray>().unwrap();
            (a.value(row) as i64).to_le_bytes()
        }
        TimeUnit::Millisecond => {
            let a = arr
                .as_any()
                .downcast_ref::<Time32MillisecondArray>()
                .unwrap();
            (a.value(row) as i64).to_le_bytes()
        }
        TimeUnit::Microsecond => {
            let a = arr
                .as_any()
                .downcast_ref::<Time64MicrosecondArray>()
                .unwrap();
            a.value(row).to_le_bytes()
        }
        TimeUnit::Nanosecond => {
            let a = arr
                .as_any()
                .downcast_ref::<Time64NanosecondArray>()
                .unwrap();
            a.value(row).to_le_bytes()
        }
    })
}

fn write_duration_as_long_payload(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    unit: TimeUnit,
) -> Result<()> {
    full_with_sentinel::<8>(out, arr, i64::MIN.to_le_bytes(), |row| match unit {
        TimeUnit::Second => {
            let a = arr.as_any().downcast_ref::<DurationSecondArray>().unwrap();
            a.value(row).to_le_bytes()
        }
        TimeUnit::Millisecond => {
            let a = arr
                .as_any()
                .downcast_ref::<DurationMillisecondArray>()
                .unwrap();
            a.value(row).to_le_bytes()
        }
        TimeUnit::Microsecond => {
            let a = arr
                .as_any()
                .downcast_ref::<DurationMicrosecondArray>()
                .unwrap();
            a.value(row).to_le_bytes()
        }
        TimeUnit::Nanosecond => {
            let a = arr
                .as_any()
                .downcast_ref::<DurationNanosecondArray>()
                .unwrap();
            a.value(row).to_le_bytes()
        }
    })
}

fn geohash_bytes_per_value(bits: u8) -> usize {
    (bits as usize).div_ceil(8)
}

fn write_geohash_payload(out: &mut Vec<u8>, arr: &dyn Array, bits: u8) -> Result<()> {
    let elem = geohash_bytes_per_value(bits);
    let row_count = arr.len();
    let non_null = non_null_count(arr, "GEOHASH column")?;
    let label = "GEOHASH column";
    try_reserve_bytes(out, 1 + non_null * elem, label)?;
    write_qwp_varint(out, bits as u64);
    let dt = arr.data_type();
    match dt {
        DataType::Int8 => {
            let a = arr.as_any().downcast_ref::<Int8Array>().unwrap();
            for row in 0..row_count {
                if arr.is_null(row) {
                    continue;
                }
                let v = a.value(row) as u64;
                out.extend_from_slice(&v.to_le_bytes()[..elem]);
            }
        }
        DataType::Int16 => {
            let a = arr.as_any().downcast_ref::<Int16Array>().unwrap();
            for row in 0..row_count {
                if arr.is_null(row) {
                    continue;
                }
                let v = a.value(row) as u64;
                out.extend_from_slice(&v.to_le_bytes()[..elem]);
            }
        }
        DataType::Int32 => {
            let a = arr.as_any().downcast_ref::<Int32Array>().unwrap();
            for row in 0..row_count {
                if arr.is_null(row) {
                    continue;
                }
                let v = a.value(row) as u64;
                out.extend_from_slice(&v.to_le_bytes()[..elem]);
            }
        }
        DataType::Int64 => {
            let a = arr.as_any().downcast_ref::<Int64Array>().unwrap();
            for row in 0..row_count {
                if arr.is_null(row) {
                    continue;
                }
                let v = a.value(row) as u64;
                out.extend_from_slice(&v.to_le_bytes()[..elem]);
            }
        }
        other => {
            return Err(fmt!(
                ArrowIngest,
                "GEOHASH column: unsupported Arrow type {:?}",
                other
            ));
        }
    }
    Ok(())
}

fn write_array_double_payload(out: &mut Vec<u8>, arr: &dyn Array, ndim: usize) -> Result<()> {
    let row_count = arr.len();
    let ndim_u8 =
        u8::try_from(ndim).map_err(|_| fmt!(ArrowIngest, "ARRAY ndim {} exceeds u8::MAX", ndim))?;
    let mut levels: Vec<ArrayRef> = Vec::with_capacity(ndim);
    let mut current: ArrayRef = list_values(arr)?;
    levels.push(current.clone());
    for _ in 1..ndim {
        let next = list_values(&*current)?;
        levels.push(next.clone());
        current = next;
    }
    let leaf_array = levels[ndim - 1]
        .as_any()
        .downcast_ref::<Float64Array>()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::ArrowUnsupportedColumnKind,
                format!(
                    "ARRAY leaf must be Float64, got {:?}",
                    levels[ndim - 1].data_type()
                ),
            )
        })?;
    // List `value_offsets` index into the child's underlying buffer (raw,
    // not slice-aware). `leaf_array.values()` returns the LOGICAL slice
    // `[leaf_offset .. leaf_offset+len]` of that buffer, so the inbound
    // indices must be rebased by `leaf_offset` before use.
    let leaf_offset = leaf_array.offset();
    let leaf_values_all = leaf_array.values();
    // List/LargeList keep absolute child offsets across a slice but
    // FixedSizeList rebases its child; a sliced intermediate level mixes the
    // two conventions and would mis-index the leaf. The outer level and the
    // leaf are already slice-aware.
    for (level_idx, level) in levels[..ndim - 1].iter().enumerate() {
        if level.offset() != 0 {
            return Err(fmt!(
                ArrowIngest,
                "ARRAY ingest does not support a sliced intermediate list level \
                 (level {} has offset {}); copy the array before ingest",
                level_idx,
                level.offset()
            ));
        }
    }
    // The QWP ARRAY(DOUBLE) wire format is dense with no per-element null
    // channel: a NULL leaf element would ship the undefined value-buffer slot
    // as a real double (silent corruption). Reject it. Checked per emitted
    // range below so null *rows* (handled by the column validity bitmap) are
    // not mistaken for null elements.
    let leaf_has_nulls = leaf_array.null_count() > 0;
    let mut shape: Vec<usize> = Vec::with_capacity(ndim);
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        shape.clear();
        let (mut start, mut end) = list_row_range(arr, row)?;
        shape.push(end - start);
        for level_idx in 1..ndim {
            let level_arr: &dyn Array = &*levels[level_idx - 1];
            let (level_start, level_end, level_dim) =
                list_level_descend_offsets(level_arr, start, end)?;
            shape.push(level_dim);
            start = level_start;
            end = level_end;
        }
        let local_start = start.checked_sub(leaf_offset).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY leaf index {} below leaf array offset {}",
                start,
                leaf_offset
            )
        })?;
        let local_end = end.checked_sub(leaf_offset).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY leaf index {} below leaf array offset {}",
                end,
                leaf_offset
            )
        })?;
        if local_end > leaf_values_all.len() {
            return Err(fmt!(
                ArrowIngest,
                "ARRAY leaf slice [{},{}) out of bounds for leaf len {}",
                local_start,
                local_end,
                leaf_values_all.len()
            ));
        }
        if leaf_has_nulls {
            for k in local_start..local_end {
                if leaf_array.is_null(k) {
                    return Err(fmt!(
                        ArrowUnsupportedColumnKind,
                        "ARRAY column has a NULL element; QuestDB ARRAY(DOUBLE) \
                         ingress does not support NULL array elements"
                    ));
                }
            }
        }
        let leaf_values = &leaf_values_all[local_start..local_end];
        try_reserve_bytes(
            out,
            1 + 4 * ndim + 8 * leaf_values.len(),
            "ARRAY DOUBLE column",
        )?;
        out.push(ndim_u8);
        for &dim in shape.iter() {
            let dim_u32 = u32::try_from(dim)
                .map_err(|_| fmt!(ArrowIngest, "ARRAY dimension {} exceeds u32::MAX", dim))?;
            out.extend_from_slice(&dim_u32.to_le_bytes());
        }
        if cfg!(target_endian = "little") {
            out.extend_from_slice(unsafe { typed_slice_as_le_bytes(leaf_values) });
        } else {
            for &v in leaf_values {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    Ok(())
}

fn checked_offset_i32(off: i32, idx: usize) -> Result<usize> {
    if off < 0 {
        return Err(fmt!(
            ArrowIngest,
            "ARRAY List offset[{}] = {} is negative",
            idx,
            off
        ));
    }
    Ok(off as usize)
}

fn checked_offset_i64(off: i64, idx: usize) -> Result<usize> {
    if off < 0 {
        return Err(fmt!(
            ArrowIngest,
            "ARRAY LargeList offset[{}] = {} is negative",
            idx,
            off
        ));
    }
    usize::try_from(off).map_err(|_| {
        fmt!(
            ArrowIngest,
            "ARRAY LargeList offset[{}] = {} exceeds usize::MAX",
            idx,
            off
        )
    })
}

fn list_row_range(arr: &dyn Array, row: usize) -> Result<(usize, usize)> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        let offsets = la.offsets();
        let start = checked_offset_i32(offsets[row], row)?;
        let end = checked_offset_i32(offsets[row + 1], row + 1)?;
        if end < start {
            return Err(fmt!(
                ArrowIngest,
                "ARRAY List outer offsets non-monotonic at row {} (start={}, end={})",
                row,
                start,
                end
            ));
        }
        Ok((start, end))
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        let offsets = la.offsets();
        let start = checked_offset_i64(offsets[row], row)?;
        let end = checked_offset_i64(offsets[row + 1], row + 1)?;
        if end < start {
            return Err(fmt!(
                ArrowIngest,
                "ARRAY LargeList outer offsets non-monotonic at row {} (start={}, end={})",
                row,
                start,
                end
            ));
        }
        Ok((start, end))
    } else if let Some(la) = arr.as_any().downcast_ref::<FixedSizeListArray>() {
        let stride = la.value_length() as usize;
        let start = row.checked_mul(stride).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY FixedSizeList row {} * stride {} overflows usize",
                row,
                stride
            )
        })?;
        let end = row
            .checked_add(1)
            .and_then(|n| n.checked_mul(stride))
            .ok_or_else(|| {
                fmt!(
                    ArrowIngest,
                    "ARRAY FixedSizeList row {} * stride {} overflows usize",
                    row + 1,
                    stride
                )
            })?;
        Ok((start, end))
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList / FixedSizeList at outer ARRAY level, got {:?}",
            arr.data_type()
        ))
    }
}

fn list_values(arr: &dyn Array) -> Result<ArrayRef> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        Ok(la.values().clone())
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        Ok(la.values().clone())
    } else if let Some(la) = arr.as_any().downcast_ref::<FixedSizeListArray>() {
        Ok(la.values().clone())
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList / FixedSizeList, got {:?}",
            arr.data_type()
        ))
    }
}

fn list_level_descend_offsets(
    arr: &dyn Array,
    start: usize,
    end: usize,
) -> Result<(usize, usize, usize)> {
    if let Some(la) = arr.as_any().downcast_ref::<ListArray>() {
        let offsets = la.offsets();
        if end <= start {
            return Ok((0, 0, 0));
        }
        let next_start = checked_offset_i32(offsets[start], start)?;
        let first_end = checked_offset_i32(offsets[start + 1], start + 1)?;
        let dim = first_end.checked_sub(next_start).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY List inner offsets non-monotonic at row {}",
                start
            )
        })?;
        let next_end = checked_offset_i32(offsets[end], end)?;
        if next_end.checked_sub(next_start) != dim.checked_mul(end - start) {
            return Err(ragged_inner_error_i32(&offsets[..], start, end, dim));
        }
        Ok((next_start, next_end, dim))
    } else if let Some(la) = arr.as_any().downcast_ref::<LargeListArray>() {
        let offsets = la.offsets();
        if end <= start {
            return Ok((0, 0, 0));
        }
        let next_start = checked_offset_i64(offsets[start], start)?;
        let first_end = checked_offset_i64(offsets[start + 1], start + 1)?;
        let dim = first_end.checked_sub(next_start).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY LargeList inner offsets non-monotonic at row {}",
                start
            )
        })?;
        let next_end = checked_offset_i64(offsets[end], end)?;
        if next_end.checked_sub(next_start) != dim.checked_mul(end - start) {
            return Err(ragged_inner_error_i64(&offsets[..], start, end, dim));
        }
        Ok((next_start, next_end, dim))
    } else if let Some(la) = arr.as_any().downcast_ref::<FixedSizeListArray>() {
        let stride = la.value_length() as usize;
        if end <= start {
            return Ok((0, 0, 0));
        }
        let next_start = start.checked_mul(stride).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY FixedSizeList descent start {} * stride {} overflows usize",
                start,
                stride
            )
        })?;
        let next_end = end.checked_mul(stride).ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "ARRAY FixedSizeList descent end {} * stride {} overflows usize",
                end,
                stride
            )
        })?;
        Ok((next_start, next_end, stride))
    } else {
        Err(fmt!(
            ArrowIngest,
            "expected List / LargeList / FixedSizeList in ARRAY descent, got {:?}",
            arr.data_type()
        ))
    }
}

#[cold]
#[inline(never)]
fn ragged_inner_error_i32(offsets: &[i32], start: usize, end: usize, dim: usize) -> Error {
    for i in start..end {
        let sz = (offsets[i + 1] - offsets[i]) as usize;
        if sz != dim {
            return fmt!(
                ArrowIngest,
                "ARRAY row has ragged inner-list sizes: inner #{} has size {} but row's first inner is {}; N-dim ARRAY ingest requires uniform inner sizes per row",
                i - start,
                sz,
                dim
            );
        }
    }
    fmt!(
        ArrowIngest,
        "ARRAY row has ragged inner-list sizes (could not isolate diverging inner)"
    )
}

#[cold]
#[inline(never)]
fn ragged_inner_error_i64(offsets: &[i64], start: usize, end: usize, dim: usize) -> Error {
    for i in start..end {
        let sz = (offsets[i + 1] - offsets[i]) as usize;
        if sz != dim {
            return fmt!(
                ArrowIngest,
                "ARRAY row has ragged inner-list sizes: inner #{} has size {} but row's first inner is {}; N-dim ARRAY ingest requires uniform inner sizes per row",
                i - start,
                sz,
                dim
            );
        }
    }
    fmt!(
        ArrowIngest,
        "ARRAY row has ragged inner-list sizes (could not isolate diverging inner)"
    )
}

#[derive(Default)]
pub(crate) struct ArrowResolvedSymbolColumn {
    /// One entry per *non-null* row, in row order. The body writer
    /// emits exactly these varints.
    pub gids: Vec<u64>,
}

pub(crate) struct ArrowSymbolResolution {
    pub delta_start: u64,
    pub new_symbols: Vec<Vec<u8>>,
    pub per_column: Vec<Option<ArrowResolvedSymbolColumn>>,
}

pub(crate) fn resolve_arrow_symbols(
    classified: &[ClassifiedColumn<'_>],
    symbol_dict: &mut SymbolGlobalDict,
) -> Result<ArrowSymbolResolution> {
    let delta_start = symbol_dict.next_id();
    let mut new_symbols: Vec<Vec<u8>> = Vec::new();
    let mut per_column: Vec<Option<ArrowResolvedSymbolColumn>> =
        Vec::with_capacity(classified.len());
    for col in classified {
        per_column.push(resolve_arrow_symbol_column(
            col.arr,
            col.kind,
            symbol_dict,
            &mut new_symbols,
        )?);
    }
    Ok(ArrowSymbolResolution {
        delta_start,
        new_symbols,
        per_column,
    })
}

/// Resolve a single Arrow symbol column against the global dict. Yields
/// `None` for non-symbol kinds so callers can store per-column entries
/// in a positional vec without branching.
pub(crate) fn resolve_arrow_symbol_column(
    arr: &dyn Array,
    kind: ColumnKind,
    symbol_dict: &mut SymbolGlobalDict,
    new_symbols: &mut Vec<Vec<u8>>,
) -> Result<Option<ArrowResolvedSymbolColumn>> {
    let resolved = match kind {
        ColumnKind::SymbolUtf8 => resolve_symbol_strings(
            arr,
            arr.as_any().downcast_ref::<StringArray>().unwrap(),
            symbol_dict,
            new_symbols,
        )?,
        ColumnKind::SymbolLargeUtf8 => resolve_symbol_strings(
            arr,
            arr.as_any().downcast_ref::<LargeStringArray>().unwrap(),
            symbol_dict,
            new_symbols,
        )?,
        ColumnKind::SymbolUtf8View => resolve_symbol_strings(
            arr,
            arr.as_any().downcast_ref::<StringViewArray>().unwrap(),
            symbol_dict,
            new_symbols,
        )?,
        ColumnKind::SymbolDict { key, value } => {
            resolve_symbol_dict(arr, key, value, symbol_dict, new_symbols)?
        }
        _ => return Ok(None),
    };
    Ok(Some(resolved))
}

trait StrSource {
    fn value_bytes(&self, row: usize) -> &[u8];
}

impl StrSource for StringArray {
    fn value_bytes(&self, row: usize) -> &[u8] {
        self.value(row).as_bytes()
    }
}

impl StrSource for LargeStringArray {
    fn value_bytes(&self, row: usize) -> &[u8] {
        self.value(row).as_bytes()
    }
}

impl StrSource for StringViewArray {
    fn value_bytes(&self, row: usize) -> &[u8] {
        self.value(row).as_bytes()
    }
}

fn resolve_symbol_strings<S: StrSource>(
    arr: &dyn Array,
    source: &S,
    symbol_dict: &mut SymbolGlobalDict,
    new_symbols: &mut Vec<Vec<u8>>,
) -> Result<ArrowResolvedSymbolColumn> {
    use std::collections::HashMap;
    let row_count = arr.len();
    let non_null = non_null_count(arr, "SYMBOL column")?;
    let mut gids = Vec::with_capacity(non_null);
    // Dedup within the column so the global dict is hit once per distinct
    // value rather than once per row — matching the dictionary path and the
    // row API's bulk-intern.
    let mut seen: HashMap<&[u8], u64> = HashMap::new();
    for row in 0..row_count {
        if arr.is_null(row) {
            continue;
        }
        let bytes = source.value_bytes(row);
        let gid = match seen.get(bytes) {
            Some(&gid) => gid,
            None => {
                let (gid, is_new) = symbol_dict.intern(bytes)?;
                if is_new {
                    new_symbols.push(bytes.to_vec());
                }
                seen.insert(bytes, gid);
                gid
            }
        };
        gids.push(gid);
    }
    Ok(ArrowResolvedSymbolColumn { gids })
}

fn resolve_symbol_dict(
    arr: &dyn Array,
    key: DictKey,
    value: DictValue,
    symbol_dict: &mut SymbolGlobalDict,
    new_symbols: &mut Vec<Vec<u8>>,
) -> Result<ArrowResolvedSymbolColumn> {
    let non_null = non_null_count(arr, "SYMBOL dictionary column")?;

    fn run<K, V>(
        arr: &dyn Array,
        non_null: usize,
        symbol_dict: &mut SymbolGlobalDict,
        new_symbols: &mut Vec<Vec<u8>>,
        get_slot: impl Fn(&DictionaryArray<K::ArrowType>, usize) -> usize,
        get_value_bytes: impl Fn(&V, usize) -> &[u8],
    ) -> Result<ArrowResolvedSymbolColumn>
    where
        K: DictKeyTag,
        V: 'static,
    {
        let dict_arr = arr
            .as_any()
            .downcast_ref::<DictionaryArray<K::ArrowType>>()
            .unwrap();
        let values_arr = dict_arr.values();
        let values_typed = values_arr.as_any().downcast_ref::<V>().ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "SYMBOL dictionary column: dict values downcast failed"
            )
        })?;
        let dict_len = values_arr.len();
        let row_count = arr.len();
        let mut referenced = vec![false; dict_len];
        for row in 0..row_count {
            if arr.is_null(row) {
                continue;
            }
            let slot = get_slot(dict_arr, row);
            if slot >= dict_len {
                return Err(fmt!(
                    ArrowIngest,
                    "SYMBOL dictionary column: code {} out of range (dict_len={})",
                    slot,
                    dict_len
                ));
            }
            referenced[slot] = true;
        }
        let mut slot_to_gid = vec![u64::MAX; dict_len];
        for (slot, marked) in referenced.iter().enumerate() {
            if !*marked {
                continue;
            }
            if values_arr.is_null(slot) {
                return Err(fmt!(
                    ArrowIngest,
                    "SYMBOL dictionary column: referenced dictionary values slot {} is null",
                    slot
                ));
            }
            let bytes = get_value_bytes(values_typed, slot);
            let (gid, is_new) = symbol_dict.intern(bytes)?;
            if is_new {
                new_symbols.push(bytes.to_vec());
            }
            slot_to_gid[slot] = gid;
        }
        let mut gids = Vec::with_capacity(non_null);
        for row in 0..row_count {
            if arr.is_null(row) {
                continue;
            }
            let slot = get_slot(dict_arr, row);
            let gid = slot_to_gid[slot];
            debug_assert_ne!(gid, u64::MAX);
            gids.push(gid);
        }
        Ok(ArrowResolvedSymbolColumn { gids })
    }

    match (key, value) {
        (DictKey::I8, DictValue::Utf8) => run::<I8KeyTag, StringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I8, DictValue::LargeUtf8) => run::<I8KeyTag, LargeStringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I8, DictValue::Utf8View) => run::<I8KeyTag, StringViewArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I16, DictValue::Utf8) => run::<I16KeyTag, StringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I16, DictValue::LargeUtf8) => run::<I16KeyTag, LargeStringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I16, DictValue::Utf8View) => run::<I16KeyTag, StringViewArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I32, DictValue::Utf8) => run::<I32KeyTag, StringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I32, DictValue::LargeUtf8) => run::<I32KeyTag, LargeStringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I32, DictValue::Utf8View) => run::<I32KeyTag, StringViewArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U8, DictValue::Utf8) => run::<U8KeyTag, StringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U8, DictValue::LargeUtf8) => run::<U8KeyTag, LargeStringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U8, DictValue::Utf8View) => run::<U8KeyTag, StringViewArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U16, DictValue::Utf8) => run::<U16KeyTag, StringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U16, DictValue::LargeUtf8) => run::<U16KeyTag, LargeStringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U16, DictValue::Utf8View) => run::<U16KeyTag, StringViewArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U32, DictValue::Utf8) => run::<U32KeyTag, StringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U32, DictValue::LargeUtf8) => run::<U32KeyTag, LargeStringArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U32, DictValue::Utf8View) => run::<U32KeyTag, StringViewArray>(
            arr,
            non_null,
            symbol_dict,
            new_symbols,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
    }
}

trait DictKeyTag {
    type ArrowType: arrow_array::types::ArrowDictionaryKeyType;
}

struct I8KeyTag;
impl DictKeyTag for I8KeyTag {
    type ArrowType = arrow_array::types::Int8Type;
}
struct I16KeyTag;
impl DictKeyTag for I16KeyTag {
    type ArrowType = arrow_array::types::Int16Type;
}
struct I32KeyTag;
impl DictKeyTag for I32KeyTag {
    type ArrowType = arrow_array::types::Int32Type;
}
struct U8KeyTag;
impl DictKeyTag for U8KeyTag {
    type ArrowType = UInt8Type;
}
struct U16KeyTag;
impl DictKeyTag for U16KeyTag {
    type ArrowType = UInt16Type;
}
struct U32KeyTag;
impl DictKeyTag for U32KeyTag {
    type ArrowType = UInt32Type;
}

fn write_symbol_payload(out: &mut Vec<u8>, resolved: &ArrowResolvedSymbolColumn) -> Result<()> {
    for &gid in &resolved.gids {
        write_qwp_varint(out, gid);
    }
    Ok(())
}

fn write_dict_to_varchar_payload(
    out: &mut Vec<u8>,
    arr: &dyn Array,
    key: DictKey,
    value: DictValue,
) -> Result<()> {
    fn run<K, V>(
        out: &mut Vec<u8>,
        arr: &dyn Array,
        get_slot: impl Fn(&DictionaryArray<K::ArrowType>, usize) -> usize,
        get_value_bytes: impl Fn(&V, usize) -> &[u8],
    ) -> Result<()>
    where
        K: DictKeyTag,
        V: 'static,
    {
        let dict_arr = arr
            .as_any()
            .downcast_ref::<DictionaryArray<K::ArrowType>>()
            .unwrap();
        let values_arr = dict_arr.values();
        let values_typed = values_arr
            .as_any()
            .downcast_ref::<V>()
            .ok_or_else(|| fmt!(ArrowIngest, "DictToVarchar: dict values downcast failed"))?;
        let dict_len = values_arr.len();
        write_varlen_u32_offsets_with_bitmap(out, dict_arr, "VARCHAR column", None, |out, row| {
            let slot = get_slot(dict_arr, row);
            if slot >= dict_len {
                return Err(fmt!(
                    ArrowIngest,
                    "DictToVarchar: index {} out of range (dict_len={})",
                    slot,
                    dict_len
                ));
            }
            if values_arr.is_null(slot) {
                return Err(fmt!(
                    ArrowIngest,
                    "DictToVarchar: referenced dict value at slot {} is null",
                    slot
                ));
            }
            let bytes = get_value_bytes(values_typed, slot);
            try_reserve_bytes(out, bytes.len(), "VARCHAR column")?;
            out.extend_from_slice(bytes);
            u32::try_from(bytes.len()).map_err(|_| {
                fmt!(
                    ArrowIngest,
                    "VARCHAR column: row {} exceeds u32::MAX bytes",
                    row
                )
            })
        })
    }

    match (key, value) {
        (DictKey::I8, DictValue::Utf8) => run::<I8KeyTag, StringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I8, DictValue::LargeUtf8) => run::<I8KeyTag, LargeStringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I8, DictValue::Utf8View) => run::<I8KeyTag, StringViewArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I16, DictValue::Utf8) => run::<I16KeyTag, StringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I16, DictValue::LargeUtf8) => run::<I16KeyTag, LargeStringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I16, DictValue::Utf8View) => run::<I16KeyTag, StringViewArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I32, DictValue::Utf8) => run::<I32KeyTag, StringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I32, DictValue::LargeUtf8) => run::<I32KeyTag, LargeStringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::I32, DictValue::Utf8View) => run::<I32KeyTag, StringViewArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U8, DictValue::Utf8) => run::<U8KeyTag, StringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U8, DictValue::LargeUtf8) => run::<U8KeyTag, LargeStringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U8, DictValue::Utf8View) => run::<U8KeyTag, StringViewArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U16, DictValue::Utf8) => run::<U16KeyTag, StringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U16, DictValue::LargeUtf8) => run::<U16KeyTag, LargeStringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U16, DictValue::Utf8View) => run::<U16KeyTag, StringViewArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U32, DictValue::Utf8) => run::<U32KeyTag, StringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U32, DictValue::LargeUtf8) => run::<U32KeyTag, LargeStringArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
        (DictKey::U32, DictValue::Utf8View) => run::<U32KeyTag, StringViewArray>(
            out,
            arr,
            |d, r| d.keys().value(r) as usize,
            |v, s| v.value(s).as_bytes(),
        ),
    }
}

pub(crate) fn write_arrow_column_body(
    out: &mut Vec<u8>,
    kind: ColumnKind,
    arr: &dyn Array,
    sym_resolution: Option<&ArrowResolvedSymbolColumn>,
) -> Result<()> {
    let null_count = arr.null_count();
    let use_bitmap = kind_supports_sparse_nulls(kind) && null_count > 0;
    out.push(u8::from(use_bitmap));
    if use_bitmap {
        let nulls = arr.nulls().ok_or_else(|| {
            fmt!(
                ArrowIngest,
                "column: validity-bitmap encoding required but Arrow array reports no NullBuffer"
            )
        })?;
        write_qwp_bitmap_from_arrow(out, nulls)?;
    }
    let le_target = cfg!(target_endian = "little");
    let le_no_nulls = le_target && null_count == 0;
    match kind {
        ColumnKind::Bool => {
            let a = arr.as_any().downcast_ref::<BooleanArray>().unwrap();
            write_bool_payload(out, a)
        }
        ColumnKind::I8 => {
            let a = arr.as_any().downcast_ref::<Int8Array>().unwrap();
            if null_count == 0 {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else if let Some(nulls) = arr.nulls() {
                nullable_le_memcpy_patch::<1>(
                    out,
                    unsafe { typed_slice_as_le_bytes(a.values()) },
                    nulls,
                    [0u8; 1],
                )
            } else {
                full_with_sentinel::<1>(out, arr, [0u8; 1], |row| [a.value(row) as u8])
            }
        }
        ColumnKind::I16 => {
            let a = arr.as_any().downcast_ref::<Int16Array>().unwrap();
            if le_no_nulls {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else if le_target && let Some(nulls) = arr.nulls() {
                nullable_le_memcpy_patch::<2>(
                    out,
                    unsafe { typed_slice_as_le_bytes(a.values()) },
                    nulls,
                    0i16.to_le_bytes(),
                )
            } else {
                full_with_sentinel::<2>(out, arr, 0i16.to_le_bytes(), |row| {
                    a.value(row).to_le_bytes()
                })
            }
        }
        ColumnKind::I32 => {
            let a = arr.as_any().downcast_ref::<Int32Array>().unwrap();
            if le_no_nulls {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else if le_target && let Some(nulls) = arr.nulls() {
                nullable_le_memcpy_patch::<4>(
                    out,
                    unsafe { typed_slice_as_le_bytes(a.values()) },
                    nulls,
                    i32::MIN.to_le_bytes(),
                )
            } else {
                full_with_sentinel::<4>(out, arr, i32::MIN.to_le_bytes(), |row| {
                    a.value(row).to_le_bytes()
                })
            }
        }
        ColumnKind::I64 => {
            let a = arr.as_any().downcast_ref::<Int64Array>().unwrap();
            if le_no_nulls {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else if le_target && let Some(nulls) = arr.nulls() {
                nullable_le_memcpy_patch::<8>(
                    out,
                    unsafe { typed_slice_as_le_bytes(a.values()) },
                    nulls,
                    i64::MIN.to_le_bytes(),
                )
            } else {
                full_with_sentinel::<8>(out, arr, i64::MIN.to_le_bytes(), |row| {
                    a.value(row).to_le_bytes()
                })
            }
        }
        ColumnKind::I8WidenToI32 => {
            let a = arr.as_any().downcast_ref::<Int8Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 4, "I8 widen column")?;
                for &v in a.values() {
                    out.extend_from_slice(&(v as i32).to_le_bytes());
                }
                Ok(())
            } else {
                full_with_sentinel::<4>(out, arr, i32::MIN.to_le_bytes(), |row| {
                    (a.value(row) as i32).to_le_bytes()
                })
            }
        }
        ColumnKind::I16WidenToI32 => {
            let a = arr.as_any().downcast_ref::<Int16Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 4, "I16 widen column")?;
                for &v in a.values() {
                    out.extend_from_slice(&(v as i32).to_le_bytes());
                }
                Ok(())
            } else {
                full_with_sentinel::<4>(out, arr, i32::MIN.to_le_bytes(), |row| {
                    (a.value(row) as i32).to_le_bytes()
                })
            }
        }
        ColumnKind::I32WidenToI64 => {
            let a = arr.as_any().downcast_ref::<Int32Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 8, "I32 widen column")?;
                for &v in a.values() {
                    out.extend_from_slice(&(v as i64).to_le_bytes());
                }
                Ok(())
            } else {
                full_with_sentinel::<8>(out, arr, i64::MIN.to_le_bytes(), |row| {
                    (a.value(row) as i64).to_le_bytes()
                })
            }
        }
        ColumnKind::F16ToF32 => {
            let a = arr.as_any().downcast_ref::<Float16Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 4, "Float16 column")?;
                for &h in a.values() {
                    out.extend_from_slice(&h.to_f32().to_le_bytes());
                }
                Ok(())
            } else {
                full_with_sentinel::<4>(out, arr, f32::NAN.to_le_bytes(), |row| {
                    a.value(row).to_f32().to_le_bytes()
                })
            }
        }
        ColumnKind::F32 => {
            let a = arr.as_any().downcast_ref::<Float32Array>().unwrap();
            if le_no_nulls {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else if le_target && let Some(nulls) = arr.nulls() {
                nullable_le_memcpy_patch::<4>(
                    out,
                    unsafe { typed_slice_as_le_bytes(a.values()) },
                    nulls,
                    f32::NAN.to_le_bytes(),
                )
            } else {
                full_with_sentinel::<4>(out, arr, f32::NAN.to_le_bytes(), |row| {
                    a.value(row).to_le_bytes()
                })
            }
        }
        ColumnKind::F64 => {
            let a = arr.as_any().downcast_ref::<Float64Array>().unwrap();
            if le_no_nulls {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else if le_target && let Some(nulls) = arr.nulls() {
                nullable_le_memcpy_patch::<8>(
                    out,
                    unsafe { typed_slice_as_le_bytes(a.values()) },
                    nulls,
                    f64::NAN.to_le_bytes(),
                )
            } else {
                full_with_sentinel::<8>(out, arr, f64::NAN.to_le_bytes(), |row| {
                    a.value(row).to_le_bytes()
                })
            }
        }
        ColumnKind::Char => {
            let a = arr.as_any().downcast_ref::<UInt16Array>().unwrap();
            if le_no_nulls {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else if le_target && let Some(nulls) = arr.nulls() {
                nullable_le_memcpy_patch::<2>(
                    out,
                    unsafe { typed_slice_as_le_bytes(a.values()) },
                    nulls,
                    0u16.to_le_bytes(),
                )
            } else {
                full_with_sentinel::<2>(out, arr, 0u16.to_le_bytes(), |row| {
                    a.value(row).to_le_bytes()
                })
            }
        }
        ColumnKind::Ipv4 => {
            let a = arr.as_any().downcast_ref::<UInt32Array>().unwrap();
            if !use_bitmap && cfg!(target_endian = "little") {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else {
                non_null_le::<4>(out, arr, |row| a.value(row).to_le_bytes())
            }
        }
        ColumnKind::U8WidenToI32 => {
            let a = arr.as_any().downcast_ref::<UInt8Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 4, "U8 widen column")?;
                for &v in a.values() {
                    out.extend_from_slice(&(v as i32).to_le_bytes());
                }
                Ok(())
            } else {
                full_with_sentinel::<4>(out, arr, i32::MIN.to_le_bytes(), |row| {
                    (a.value(row) as i32).to_le_bytes()
                })
            }
        }
        ColumnKind::U16WidenToI32 => {
            let a = arr.as_any().downcast_ref::<UInt16Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 4, "U16 widen column")?;
                for &v in a.values() {
                    out.extend_from_slice(&(v as i32).to_le_bytes());
                }
                Ok(())
            } else {
                full_with_sentinel::<4>(out, arr, i32::MIN.to_le_bytes(), |row| {
                    (a.value(row) as i32).to_le_bytes()
                })
            }
        }
        ColumnKind::U32WidenToI64 => {
            let a = arr.as_any().downcast_ref::<UInt32Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 8, "U32 widen column")?;
                for &v in a.values() {
                    out.extend_from_slice(&(v as i64).to_le_bytes());
                }
                Ok(())
            } else {
                full_with_sentinel::<8>(out, arr, i64::MIN.to_le_bytes(), |row| {
                    (a.value(row) as i64).to_le_bytes()
                })
            }
        }
        ColumnKind::U64WidenToI64Checked => {
            let a = arr.as_any().downcast_ref::<UInt64Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 8, "U64 widen column")?;
                for (row, &v) in a.values().iter().enumerate() {
                    out.extend_from_slice(&u64_to_i64_le_checked(v, row)?);
                }
                Ok(())
            } else {
                try_full_with_sentinel::<8>(out, arr, i64::MIN.to_le_bytes(), |row| {
                    u64_to_i64_le_checked(a.value(row), row)
                })
            }
        }
        ColumnKind::TimestampSecondToMicros => {
            let a = arr.as_any().downcast_ref::<TimestampSecondArray>().unwrap();
            ensure_timestamp_no_nulls(arr, "timestamp field column")?;
            ensure_timestamp_values_non_negative(arr, a.values(), "timestamp field column")?;
            try_non_null_le::<8>(out, arr, |row| {
                let v = a.value(row);
                let widened = v.checked_mul(1_000_000).ok_or_else(|| {
                    fmt!(
                        ArrowIngest,
                        "Timestamp s→µs overflow at row {} (value {})",
                        row,
                        v
                    )
                })?;
                Ok(widened.to_le_bytes())
            })
        }
        ColumnKind::TimestampMicros => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            ensure_timestamp_no_nulls(arr, "timestamp field column")?;
            ensure_timestamp_values_non_negative(arr, a.values(), "timestamp field column")?;
            if !use_bitmap && cfg!(target_endian = "little") {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else {
                non_null_le::<8>(out, arr, |row| a.value(row).to_le_bytes())
            }
        }
        ColumnKind::TimestampNanos => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .unwrap();
            ensure_timestamp_no_nulls(arr, "timestamp field column")?;
            ensure_timestamp_values_non_negative(arr, a.values(), "timestamp field column")?;
            if !use_bitmap && cfg!(target_endian = "little") {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else {
                non_null_le::<8>(out, arr, |row| a.value(row).to_le_bytes())
            }
        }
        ColumnKind::Date => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMillisecondArray>()
                .unwrap();
            if !use_bitmap && cfg!(target_endian = "little") {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else {
                non_null_le::<8>(out, arr, |row| a.value(row).to_le_bytes())
            }
        }
        ColumnKind::Date32Days => {
            let a = arr.as_any().downcast_ref::<Date32Array>().unwrap();
            if null_count == 0 {
                try_reserve_bytes(out, a.values().len() * 8, "Date32 column")?;
                for (row, &d) in a.values().iter().enumerate() {
                    let ms = (d as i64).checked_mul(86_400_000).ok_or_else(|| {
                        fmt!(
                            ArrowIngest,
                            "Date32 days→ms overflow at row {} (value {})",
                            row,
                            d
                        )
                    })?;
                    out.extend_from_slice(&ms.to_le_bytes());
                }
                Ok(())
            } else {
                try_non_null_le::<8>(out, arr, |row| {
                    let days = a.value(row) as i64;
                    days.checked_mul(86_400_000)
                        .map(i64::to_le_bytes)
                        .ok_or_else(|| {
                            fmt!(
                                ArrowIngest,
                                "Date32 days→ms overflow at row {} (value {})",
                                row,
                                days
                            )
                        })
                })
            }
        }
        ColumnKind::Date64Ms => {
            let a = arr.as_any().downcast_ref::<Date64Array>().unwrap();
            if !use_bitmap && cfg!(target_endian = "little") {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else {
                non_null_le::<8>(out, arr, |row| a.value(row).to_le_bytes())
            }
        }
        ColumnKind::TimeAsLong(unit) => write_time_as_long_payload(out, arr, unit),
        ColumnKind::DurationAsLong(unit) => write_duration_as_long_payload(out, arr, unit),
        ColumnKind::Utf8 => write_string_payload(
            out,
            arr.as_any().downcast_ref::<StringArray>().unwrap(),
            use_bitmap,
        ),
        ColumnKind::LargeUtf8 => write_large_string_payload(
            out,
            arr.as_any().downcast_ref::<LargeStringArray>().unwrap(),
            use_bitmap,
        ),
        ColumnKind::Utf8View => write_string_view_payload(
            out,
            arr.as_any().downcast_ref::<StringViewArray>().unwrap(),
            use_bitmap,
        ),
        ColumnKind::Binary => write_binary_payload(
            out,
            arr.as_any().downcast_ref::<BinaryArray>().unwrap(),
            use_bitmap,
        ),
        ColumnKind::LargeBinary => write_large_binary_payload(
            out,
            arr.as_any().downcast_ref::<LargeBinaryArray>().unwrap(),
            use_bitmap,
        ),
        ColumnKind::BinaryView => write_binary_view_payload(
            out,
            arr.as_any().downcast_ref::<BinaryViewArray>().unwrap(),
            use_bitmap,
        ),
        ColumnKind::SymbolUtf8
        | ColumnKind::SymbolLargeUtf8
        | ColumnKind::SymbolUtf8View
        | ColumnKind::SymbolDict { .. } => {
            let res = sym_resolution.ok_or_else(|| {
                fmt!(
                    ArrowIngest,
                    "symbol column body writer requires pre-pass resolution"
                )
            })?;
            write_symbol_payload(out, res)
        }
        ColumnKind::DictToVarchar { key, value } => {
            write_dict_to_varchar_payload(out, arr, key, value)
        }
        ColumnKind::Uuid => {
            let a = arr.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
            let elem = a.value_length() as usize;
            if null_count == 0 {
                let start = a.offset() * elem;
                let len = a.len() * elem;
                try_reserve_bytes(out, len, "UUID column")?;
                out.extend_from_slice(&a.value_data()[start..start + len]);
                Ok(())
            } else {
                non_null_fsb(out, a, elem)
            }
        }
        ColumnKind::Long256 => {
            let a = arr.as_any().downcast_ref::<FixedSizeBinaryArray>().unwrap();
            let elem = a.value_length() as usize;
            if null_count == 0 {
                let start = a.offset() * elem;
                let len = a.len() * elem;
                try_reserve_bytes(out, len, "LONG256 column")?;
                out.extend_from_slice(&a.value_data()[start..start + len]);
                Ok(())
            } else {
                non_null_fsb(out, a, elem)
            }
        }
        ColumnKind::Geohash(bits) => write_geohash_payload(out, arr, bits),
        ColumnKind::Decimal32WidenToDecimal64 => {
            let a = arr.as_any().downcast_ref::<Decimal32Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal32", 9)?;
            try_reserve_bytes(out, 1, "DECIMAL64 column")?;
            out.push(scale);
            write_decimal32_widen_to_64_payload(out, a, use_bitmap)
        }
        ColumnKind::Decimal64 => {
            let a = arr.as_any().downcast_ref::<Decimal64Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal64", 18)?;
            try_reserve_bytes(out, 1, "DECIMAL64 column")?;
            out.push(scale);
            write_decimal64_payload(out, a, use_bitmap)
        }
        ColumnKind::Decimal128 => {
            let a = arr.as_any().downcast_ref::<Decimal128Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal128", 38)?;
            try_reserve_bytes(out, 1, "DECIMAL128 column")?;
            out.push(scale);
            write_decimal128_payload(out, a, use_bitmap)
        }
        ColumnKind::Decimal256 => {
            let a = arr.as_any().downcast_ref::<Decimal256Array>().unwrap();
            let scale = decimal_scale_u8(a.scale(), "Decimal256", QWP_DECIMAL_MAX_SCALE)?;
            try_reserve_bytes(out, 1, "DECIMAL256 column")?;
            out.push(scale);
            write_decimal256_payload(out, a, use_bitmap)
        }
        ColumnKind::ArrayDouble(ndim) => write_array_double_payload(out, arr, ndim),
    }
}

pub(crate) fn write_arrow_designated_ts_body(
    out: &mut Vec<u8>,
    dtype: &DataType,
    arr: &dyn Array,
) -> Result<()> {
    let label = "designated timestamp column";
    ensure_timestamp_no_nulls(arr, label)?;
    out.push(0);
    let le = cfg!(target_endian = "little");
    match dtype {
        DataType::Timestamp(TimeUnit::Microsecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMicrosecondArray>()
                .unwrap();
            ensure_timestamp_values_non_negative(arr, a.values(), label)?;
            if le {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else {
                full_with_sentinel::<8>(out, arr, [0u8; 8], |row| a.value(row).to_le_bytes())
            }
        }
        DataType::Timestamp(TimeUnit::Nanosecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampNanosecondArray>()
                .unwrap();
            ensure_timestamp_values_non_negative(arr, a.values(), label)?;
            if le {
                extend_le_bytes_checked(out, unsafe { typed_slice_as_le_bytes(a.values()) })
            } else {
                full_with_sentinel::<8>(out, arr, [0u8; 8], |row| a.value(row).to_le_bytes())
            }
        }
        DataType::Timestamp(TimeUnit::Millisecond, _) => {
            let a = arr
                .as_any()
                .downcast_ref::<TimestampMillisecondArray>()
                .unwrap();
            ensure_timestamp_values_non_negative(arr, a.values(), label)?;
            try_full_with_sentinel::<8>(out, arr, [0u8; 8], |row| {
                let v = a.value(row);
                v.checked_mul(1_000).map(i64::to_le_bytes).ok_or_else(|| {
                    fmt!(
                        ArrowIngest,
                        "designated timestamp ms→µs overflow at row {} (value {})",
                        row,
                        v
                    )
                })
            })
        }
        DataType::Timestamp(TimeUnit::Second, _) => {
            let a = arr.as_any().downcast_ref::<TimestampSecondArray>().unwrap();
            ensure_timestamp_values_non_negative(arr, a.values(), label)?;
            try_full_with_sentinel::<8>(out, arr, [0u8; 8], |row| {
                let v = a.value(row);
                v.checked_mul(1_000_000)
                    .map(i64::to_le_bytes)
                    .ok_or_else(|| {
                        fmt!(
                            ArrowIngest,
                            "designated timestamp s→µs overflow at row {} (value {})",
                            row,
                            v
                        )
                    })
            })
        }
        other => Err(fmt!(
            ArrowIngest,
            "designated timestamp column has unsupported Arrow type {:?}",
            other
        )),
    }
}

fn ensure_timestamp_no_nulls(arr: &dyn Array, label: &str) -> Result<()> {
    if arr.null_count() > 0 {
        return Err(fmt!(ArrowIngest, "{} must have no null rows", label));
    }
    Ok(())
}

fn ensure_timestamp_values_non_negative(
    arr: &dyn Array,
    values: &[i64],
    label: &str,
) -> Result<()> {
    for (row, &value) in values.iter().enumerate() {
        if arr.is_null(row) {
            continue;
        }
        if value < 0 {
            return Err(fmt!(
                ArrowIngest,
                "{} cannot contain timestamps before the Unix epoch at row {} (value {})",
                label,
                row,
                value
            ));
        }
    }
    Ok(())
}

fn decorate_column(err: Error, column_name: &str) -> Error {
    if err.msg().starts_with(COLUMN_ERR_PREFIX) {
        return err;
    }
    Error::new(
        err.code(),
        format!("{}{}'] {}", COLUMN_ERR_PREFIX, column_name, err.msg()),
    )
}

pub(crate) fn resolve_ts_column(batch: &RecordBatch, name: ColumnName<'_>) -> Result<usize> {
    let target = name.as_ref();
    for (idx, field) in batch.schema().fields().iter().enumerate() {
        if field.name() == target {
            if !matches!(field.data_type(), DataType::Timestamp(_, _)) {
                return Err(fmt!(
                    ArrowIngest,
                    "designated timestamp column '{}' is not Timestamp(_), got {:?}",
                    target,
                    field.data_type()
                ));
            }
            return Ok(idx);
        }
    }
    Err(fmt!(
        ArrowIngest,
        "designated timestamp column '{}' not found in RecordBatch schema",
        target
    ))
}

fn check_array_data_bounds(arr: &dyn Array) -> Result<()> {
    // Value- and offset-buffer bounds are validated by the FFI entry
    // point (`arrow_ffi_import_*` runs `ArrayData::validate_full`) and by
    // arrow-rs's safe builders on the native path. `from_ffi` itself does
    // NOT validate, so this is a cheap structural cross-check only — do
    // not rely on it for buffer-length safety.
    let null_count = arr.null_count();
    let row_count = arr.len();
    if null_count > row_count {
        return Err(fmt!(
            ArrowIngest,
            "Arrow array reports null_count {} > len {} (inconsistent buffer)",
            null_count,
            row_count
        ));
    }
    Ok(())
}

fn check_batch_data_bounds(batch: &RecordBatch) -> Result<()> {
    for (idx, col) in batch.columns().iter().enumerate() {
        check_array_data_bounds(col.as_ref())
            .map_err(|e| decorate_column(e, batch.schema().field(idx).name()))?;
    }
    Ok(())
}

pub(crate) struct ClassifiedColumn<'a> {
    pub name: ColumnName<'a>,
    pub kind: ColumnKind,
    pub arr: &'a dyn Array,
}

fn emit_header_only_frame(out: &mut Vec<u8>, defer_commit: bool) {
    let frame_start = out.len();
    write_header_placeholder(out, 0, defer_commit);
    let payload_start = out.len();
    write_qwp_varint(out, 0);
    write_qwp_varint(out, 0);
    let payload_len = (out.len() - payload_start) as u32;
    out[frame_start + 8..frame_start + 12].copy_from_slice(&payload_len.to_le_bytes());
}

fn write_header_placeholder(out: &mut Vec<u8>, table_count: u16, defer_commit: bool) {
    let start = out.len();
    out.extend_from_slice(&QWP_MAGIC);
    out.push(QWP_VERSION_1);
    let mut flags = QWP_FLAG_DELTA_SYMBOL_DICT;
    if defer_commit {
        flags |= QWP_FLAG_DEFER_COMMIT;
    }
    out.push(flags);
    out.extend_from_slice(&table_count.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(out.len() - start, QWP_HEADER_LEN);
}

pub(crate) fn encode_arrow_batch_into(
    out: &mut Vec<u8>,
    table: TableName<'_>,
    batch: &RecordBatch,
    ts_col_idx: Option<usize>,
    overrides: &[ArrowColumnOverride<'_>],
    symbol_dict: &mut SymbolGlobalDict,
    defer_commit: bool,
) -> Result<()> {
    let schema = batch.schema();
    let schema = if overrides.is_empty() {
        schema
    } else {
        apply_overrides(&schema, overrides)?
    };
    let row_count = batch.num_rows();
    let total_cols = batch.num_columns();
    if schema.fields().len() != total_cols {
        return Err(fmt!(
            ArrowIngest,
            "RecordBatch schema/columns mismatch: schema={} columns={}",
            schema.fields().len(),
            total_cols
        ));
    }
    if row_count == 0 {
        emit_header_only_frame(out, defer_commit);
        return Ok(());
    }
    if row_count > MAX_ARROW_INGEST_ROWS {
        return Err(fmt!(
            ArrowIngest,
            "row count {} exceeds maximum {} for a single flush_arrow_batch call",
            row_count,
            MAX_ARROW_INGEST_ROWS
        ));
    }
    check_batch_data_bounds(batch)?;
    validate_name("table", table.as_ref())?;
    let user_col_count = total_cols - if ts_col_idx.is_some() { 1 } else { 0 };
    if user_col_count == 0 {
        return Err(fmt!(
            ArrowIngest,
            "RecordBatch must have at least one non-timestamp column when row_count > 0"
        ));
    }
    let _ = u32::try_from(row_count)
        .map_err(|_| fmt!(ArrowIngest, "row count {} exceeds u32::MAX", row_count))?;

    let mut classified: Vec<ClassifiedColumn<'_>> = Vec::with_capacity(user_col_count);
    for (idx, field) in schema.fields().iter().enumerate() {
        if Some(idx) == ts_col_idx {
            continue;
        }
        let col_name =
            ColumnName::new(field.name()).map_err(|e| decorate_column(e, field.name()))?;
        let kind = classify(field, batch.column(idx).as_ref())
            .map_err(|e| decorate_column(e, field.name()))?;
        classified.push(ClassifiedColumn {
            name: col_name,
            kind,
            arr: batch.column(idx).as_ref(),
        });
    }

    let dict_mark = symbol_dict.mark();
    let resolution = match resolve_arrow_symbols(&classified, symbol_dict) {
        Ok(r) => r,
        Err(e) => {
            symbol_dict.rollback(dict_mark);
            return Err(e);
        }
    };

    let designated_dtype = ts_col_idx.map(|idx| schema.field(idx).data_type().clone());
    let ts_wire_type = match designated_dtype.as_ref() {
        Some(DataType::Timestamp(TimeUnit::Nanosecond, _)) => Some(QWP_TYPE_TIMESTAMP_NANOS),
        Some(DataType::Timestamp(TimeUnit::Microsecond, _))
        | Some(DataType::Timestamp(TimeUnit::Millisecond, _))
        | Some(DataType::Timestamp(TimeUnit::Second, _)) => Some(QWP_TYPE_TIMESTAMP),
        Some(other) => {
            symbol_dict.rollback(dict_mark);
            return Err(fmt!(
                ArrowIngest,
                "designated timestamp column has unsupported Arrow type {:?}",
                other
            ));
        }
        None => None,
    };

    let column_count = classified.len() + if ts_wire_type.is_some() { 1 } else { 0 };
    let mut signature: Vec<u8> = Vec::with_capacity(column_count * 16);
    for col in &classified {
        let has_nulls = col.arr.null_count() > 0;
        write_qwp_bytes(&mut signature, col.name.as_ref().as_bytes());
        signature.push(wire_type_byte(col.kind, has_nulls));
    }
    if let Some(ts_byte) = ts_wire_type {
        write_qwp_bytes(&mut signature, &[]);
        signature.push(ts_byte);
    }
    let frame_start = out.len();
    let estimated = estimate_frame_size(&classified, &resolution, ts_col_idx, row_count, table);
    if let Err(_e) = out.try_reserve(estimated) {
        symbol_dict.rollback(dict_mark);
        return Err(fmt!(
            ArrowIngest,
            "allocator could not reserve {} bytes for QWP frame",
            estimated
        ));
    }

    write_header_placeholder(out, 1, defer_commit);
    let payload_start = out.len();

    write_qwp_varint(out, resolution.delta_start);
    write_qwp_varint(out, resolution.new_symbols.len() as u64);
    for bytes in &resolution.new_symbols {
        write_qwp_bytes(out, bytes);
    }

    write_qwp_bytes(out, table.as_ref().as_bytes());
    write_qwp_varint(out, row_count as u64);
    write_qwp_varint(out, column_count as u64);
    out.extend_from_slice(&signature);

    let rollback_on_err = |out: &mut Vec<u8>, dict: &mut SymbolGlobalDict, e: Error| -> Error {
        out.truncate(frame_start);
        dict.rollback(dict_mark);
        e
    };

    for (col_idx, col) in classified.iter().enumerate() {
        let sym_res = resolution.per_column[col_idx].as_ref();
        if let Err(e) = write_arrow_column_body(out, col.kind, col.arr, sym_res) {
            let col_name = col.name.as_ref().to_string();
            return Err(rollback_on_err(
                out,
                symbol_dict,
                decorate_column(e, &col_name),
            ));
        }
    }

    if let Some(idx) = ts_col_idx {
        let arr = batch.column(idx);
        let field_name = schema.field(idx).name().to_string();
        let dtype = designated_dtype.as_ref().unwrap();
        if let Err(e) = write_arrow_designated_ts_body(out, dtype, arr.as_ref()) {
            return Err(rollback_on_err(
                out,
                symbol_dict,
                decorate_column(e, &field_name),
            ));
        }
    }

    let payload_len_usize = out.len() - payload_start;
    let payload_len = match u32::try_from(payload_len_usize) {
        Ok(v) => v,
        Err(_) => {
            return Err(rollback_on_err(
                out,
                symbol_dict,
                fmt!(
                    ArrowIngest,
                    "QWP frame payload size {} bytes exceeds u32::MAX; \
                     reduce row_count or split into multiple batches",
                    payload_len_usize
                ),
            ));
        }
    };
    let header = &mut out[frame_start..payload_start];
    header[8..12].copy_from_slice(&payload_len.to_le_bytes());

    Ok(())
}

fn estimate_frame_size(
    classified: &[ClassifiedColumn<'_>],
    resolution: &ArrowSymbolResolution,
    ts_col_idx: Option<usize>,
    row_count: usize,
    table: TableName<'_>,
) -> usize {
    let mut total = QWP_HEADER_LEN;
    total += 10 + 10;
    for s in &resolution.new_symbols {
        total += 10 + s.len();
    }
    total += 10 + table.as_ref().len() + 10 + 10;
    total += 1 + 10;
    for col in classified {
        total += 10 + col.name.as_ref().len() + 1;
        total += 1;
        total += row_count.div_ceil(8);
        total += match col.kind {
            ColumnKind::Bool => row_count.div_ceil(8),
            ColumnKind::I8 => row_count,
            ColumnKind::I16 | ColumnKind::Char => 2 * row_count,
            ColumnKind::I32
            | ColumnKind::F32
            | ColumnKind::F16ToF32
            | ColumnKind::Ipv4
            | ColumnKind::I8WidenToI32
            | ColumnKind::I16WidenToI32
            | ColumnKind::U8WidenToI32
            | ColumnKind::U16WidenToI32 => 4 * row_count,
            ColumnKind::I64
            | ColumnKind::F64
            | ColumnKind::I32WidenToI64
            | ColumnKind::U32WidenToI64
            | ColumnKind::U64WidenToI64Checked
            | ColumnKind::TimestampSecondToMicros
            | ColumnKind::TimestampMicros
            | ColumnKind::TimestampNanos
            | ColumnKind::Date
            | ColumnKind::Date32Days
            | ColumnKind::Date64Ms
            | ColumnKind::TimeAsLong(_)
            | ColumnKind::DurationAsLong(_) => 8 * row_count,
            ColumnKind::Uuid => 16 * row_count,
            ColumnKind::Long256 => 32 * row_count,
            ColumnKind::Utf8
            | ColumnKind::LargeUtf8
            | ColumnKind::Utf8View
            | ColumnKind::DictToVarchar { .. } => 4 * (row_count + 1) + 16 * row_count,
            ColumnKind::Binary | ColumnKind::LargeBinary | ColumnKind::BinaryView => {
                4 * (row_count + 1) + 16 * row_count
            }
            ColumnKind::SymbolUtf8
            | ColumnKind::SymbolLargeUtf8
            | ColumnKind::SymbolUtf8View
            | ColumnKind::SymbolDict { .. } => 5 * row_count,
            ColumnKind::Geohash(_) => 1 + 8 * row_count,
            ColumnKind::Decimal32WidenToDecimal64 | ColumnKind::Decimal64 => 1 + 8 * row_count,
            ColumnKind::Decimal128 => 1 + 16 * row_count,
            ColumnKind::Decimal256 => 1 + 32 * row_count,
            ColumnKind::ArrayDouble(ndim) => row_count.saturating_mul(1 + 4 * ndim + 8 * 32),
        };
    }
    if ts_col_idx.is_some() {
        total += 10 + 1;
        total += 1 + 8 * row_count;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use arrow_array::builder::{
        BinaryBuilder, Decimal64Builder, Decimal128Builder, FixedSizeBinaryBuilder, Float64Builder,
        Int8Builder, Int16Builder, Int32Builder, Int64Builder, ListBuilder, StringBuilder,
        StringDictionaryBuilder, TimestampMicrosecondBuilder, TimestampMillisecondBuilder,
        TimestampNanosecondBuilder, TimestampSecondBuilder, UInt8Builder, UInt16Builder,
        UInt32Builder, UInt64Builder,
    };
    use arrow_array::types::UInt32Type as DictU32;
    use arrow_schema::{Field, Schema as ArrowSchema};

    fn tbl(name: &str) -> TableName<'_> {
        TableName::new(name).unwrap()
    }

    fn col_name(name: &str) -> ColumnName<'_> {
        ColumnName::new(name).unwrap()
    }

    fn arrow_schema_with(field: Field) -> Arc<ArrowSchema> {
        Arc::new(ArrowSchema::new(vec![field]))
    }

    fn single_col_batch<A: Array + 'static>(field: Field, arr: A) -> RecordBatch {
        let arr_ref: ArrayRef = Arc::new(arr);
        RecordBatch::try_new(arrow_schema_with(field), vec![arr_ref]).unwrap()
    }

    /// Encode `batch` for `table` (no designated ts), returning the wire
    /// bytes. Each call uses a fresh `SymbolGlobalDict` so tests are
    /// independent.
    fn encode(batch: &RecordBatch) -> Vec<u8> {
        encode_with_table(batch, "t")
    }

    fn encode_with_table(batch: &RecordBatch, table_name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(
            &mut out,
            tbl(table_name),
            batch,
            None,
            &[],
            &mut dict,
            false,
        )
        .unwrap();
        out
    }

    /// Encode `batch` with a designated ts column at index `ts_idx`,
    /// returning the wire bytes.
    fn encode_at_ts(batch: &RecordBatch, ts_idx: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(
            &mut out,
            tbl("t"),
            batch,
            Some(ts_idx),
            &[],
            &mut dict,
            false,
        )
        .unwrap();
        out
    }

    fn encode_err(batch: &RecordBatch) -> Error {
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(&mut out, tbl("t"), batch, None, &[], &mut dict, false).unwrap_err()
    }

    fn encode_err_at_ts(batch: &RecordBatch, ts_idx: usize) -> Error {
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(
            &mut out,
            tbl("t"),
            batch,
            Some(ts_idx),
            &[],
            &mut dict,
            false,
        )
        .unwrap_err()
    }

    fn assert_qwp_header(out: &[u8], table_count: u16) {
        assert!(out.len() >= QWP_HEADER_LEN);
        assert_eq!(&out[..4], b"QWP1");
        assert_eq!(out[4], QWP_VERSION_1);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), table_count);
        let payload_len = u32::from_le_bytes([out[8], out[9], out[10], out[11]]) as usize;
        assert_eq!(payload_len + QWP_HEADER_LEN, out.len());
    }

    fn assert_ok_with_table_count(batch: &RecordBatch, expected_table_count: u16) {
        let out = encode(batch);
        assert_qwp_header(&out, expected_table_count);
    }

    fn assert_classify_rejects(batch: &RecordBatch) {
        let err = encode_err(batch);
        assert!(
            matches!(err.code(), ErrorCode::ArrowUnsupportedColumnKind),
            "expected ArrowUnsupportedColumnKind, got {:?}: {}",
            err.code(),
            err.msg()
        );
    }

    #[test]
    fn empty_batch_encodes_to_header_only_frame() {
        let f = Field::new("c", DataType::Int64, true);
        let arr: ArrayRef = Arc::new(Int64Builder::new().finish());
        let batch = RecordBatch::try_new(arrow_schema_with(f), vec![arr]).unwrap();
        let out = encode(&batch);
        assert_qwp_header(&out, 0);
        assert_eq!(out[5], QWP_FLAG_DELTA_SYMBOL_DICT);
    }

    #[test]
    fn single_i64_column_no_ts_encodes() {
        let mut b = Int64Builder::new();
        b.append_value(1);
        b.append_value(2);
        b.append_value(3);
        let rb = single_col_batch(Field::new("c", DataType::Int64, false), b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn timestamp_at_column_writes_designated_ts() {
        let mut payload = Float64Builder::new();
        payload.append_value(1.0);
        payload.append_value(2.0);
        let mut ts = TimestampNanosecondBuilder::new();
        ts.append_value(1_000_000_000);
        ts.append_value(2_000_000_000);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("price", DataType::Float64, false),
            Field::new("ts", DataType::Timestamp(TimeUnit::Nanosecond, None), false),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(payload.finish()) as ArrayRef,
                Arc::new(ts.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let out = encode_at_ts(&batch, 1);
        assert_qwp_header(&out, 1);
    }

    #[test]
    fn symbol_column_interns_into_global_dict() {
        let mut sb = StringBuilder::new();
        sb.append_value("AAPL");
        sb.append_value("GOOG");
        sb.append_value("AAPL");
        let mut md = std::collections::HashMap::new();
        md.insert(
            crate::egress::arrow::metadata::COLUMN_TYPE.to_string(),
            "symbol".to_string(),
        );
        let f = Field::new("sym", DataType::Utf8, false).with_metadata(md);
        let rb = single_col_batch(f, sb.finish());
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(&mut out, tbl("t"), &rb, None, &[], &mut dict, false).unwrap();
        assert_qwp_header(&out, 1);
        assert_eq!(dict.next_id(), 2);
    }

    #[test]
    fn classify_rejects_unsupported_type() {
        let arr: ArrayRef = Arc::new(arrow_array::NullArray::new(3));
        let f = Field::new("c", DataType::Null, true);
        let rb = RecordBatch::try_new(arrow_schema_with(f), vec![arr]).unwrap();
        assert_classify_rejects(&rb);
    }

    // -----------------------------------------------------------------
    // Migrated from former `ingress/arrow.rs` tests. The buffer-specific
    // tests (multi-batch accumulation, ILP-mode rejection, mid-batch
    // mixing with row-by-row writes, buffer-clear behaviour) have no
    // equivalent on the conn-level path and are intentionally dropped.
    // -----------------------------------------------------------------

    fn metadata(pairs: &[(&str, &str)]) -> std::collections::HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn int_family_appends_through_widening_dispatch() {
        let mut i8b = Int8Builder::new();
        i8b.append_value(1);
        i8b.append_value(-1);
        let mut i16b = Int16Builder::new();
        i16b.append_value(2);
        i16b.append_value(-2);
        let mut i32b = Int32Builder::new();
        i32b.append_value(3);
        i32b.append_value(-3);
        let mut i64b = Int64Builder::new();
        i64b.append_value(4);
        i64b.append_value(-4);
        let mut u16b = UInt16Builder::new();
        u16b.append_value(0x41);
        u16b.append_value(0x42);
        let mut u32b = UInt32Builder::new();
        u32b.append_value(0x0100_007F);
        u32b.append_value(0x0101_A8C0);
        let cols: Vec<ArrayRef> = vec![
            Arc::new(i8b.finish()),
            Arc::new(i16b.finish()),
            Arc::new(i32b.finish()),
            Arc::new(i64b.finish()),
            Arc::new(u16b.finish()),
            Arc::new(u32b.finish()),
        ];
        let fields = vec![
            Field::new("byte", DataType::Int8, true),
            Field::new("short", DataType::Int16, true),
            Field::new("int", DataType::Int32, true),
            Field::new("long", DataType::Int64, true),
            Field::new("char_u16", DataType::UInt16, true).with_metadata(metadata(&[(
                crate::egress::arrow::metadata::COLUMN_TYPE,
                "char",
            )])),
            Field::new("ipv4", DataType::UInt32, true).with_metadata(metadata(&[(
                crate::egress::arrow::metadata::COLUMN_TYPE,
                "ipv4",
            )])),
        ];
        let rb = RecordBatch::try_new(Arc::new(ArrowSchema::new(fields)), cols).unwrap();
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn float_double_columns_append() {
        let mut f64b = Float64Builder::new();
        f64b.append_value(1.5);
        f64b.append_value(-2.5);
        let rb = single_col_batch(Field::new("d", DataType::Float64, true), f64b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn timestamp_columns_route_to_correct_setter() {
        let mut us = TimestampMicrosecondBuilder::new();
        us.append_value(1_700_000_000_000_000);
        let mut ns = TimestampNanosecondBuilder::new();
        ns.append_value(1_700_000_000_000_000_000);
        let mut ms = TimestampMillisecondBuilder::new();
        ms.append_value(1_700_000_000_000);
        let cols: Vec<ArrayRef> = vec![
            Arc::new(us.finish()),
            Arc::new(ns.finish()),
            Arc::new(ms.finish()),
        ];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new(
                "ts_us",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                true,
            ),
            Field::new(
                "ts_ns",
                DataType::Timestamp(TimeUnit::Nanosecond, None),
                true,
            ),
            Field::new(
                "ts_ms",
                DataType::Timestamp(TimeUnit::Millisecond, None),
                true,
            ),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn utf8_and_binary_append() {
        let mut s = StringBuilder::new();
        s.append_value("hello");
        s.append_value("");
        s.append_value("yo");
        let mut bin = BinaryBuilder::new();
        bin.append_value([1u8, 2, 3]);
        bin.append_value([]);
        bin.append_value([0xFFu8]);
        let cols: Vec<ArrayRef> = vec![Arc::new(s.finish()), Arc::new(bin.finish())];
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("name", DataType::Utf8, true),
            Field::new("blob", DataType::Binary, true),
        ]));
        let rb = RecordBatch::try_new(schema, cols).unwrap();
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn uuid_with_arrow_uuid_extension_routes_to_column_uuid() {
        let mut b = FixedSizeBinaryBuilder::new(16);
        b.append_value([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ])
        .unwrap();
        let field =
            Field::new("id", DataType::FixedSizeBinary(16), true).with_metadata(metadata(&[(
                crate::egress::arrow::metadata::ARROW_EXTENSION_NAME,
                "arrow.uuid",
            )]));
        let rb = single_col_batch(field, b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn uuid_without_metadata_routes_to_column_uuid() {
        let mut b = FixedSizeBinaryBuilder::new(16);
        b.append_value([0u8; 16]).unwrap();
        let field = Field::new("id", DataType::FixedSizeBinary(16), true);
        let rb = single_col_batch(field, b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn long256_routes_to_column_long256() {
        let mut b = FixedSizeBinaryBuilder::new(32);
        b.append_value([0u8; 32]).unwrap();
        let field = Field::new("l", DataType::FixedSizeBinary(32), true);
        let rb = single_col_batch(field, b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn symbol_dictionary_routes_to_symbol_setter() {
        let mut b = StringDictionaryBuilder::<DictU32>::new();
        b.append("AAPL").unwrap();
        b.append("MSFT").unwrap();
        b.append("AAPL").unwrap();
        let field = Field::new(
            "sym",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )
        .with_metadata(metadata(&[(
            crate::egress::arrow::metadata::SYMBOL,
            "true",
        )]));
        let rb = single_col_batch(field, b.finish());
        let out = encode(&rb);
        assert_qwp_header(&out, 1);
    }

    #[test]
    fn dictionary_without_metadata_routes_to_symbol() {
        let mut b = StringDictionaryBuilder::<DictU32>::new();
        b.append("x").unwrap();
        b.append("y").unwrap();
        let field = Field::new(
            "v",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn geohash_routes_via_metadata() {
        let mut b = Int32Builder::new();
        b.append_value(0x0001_FFFF);
        let field = Field::new("g", DataType::Int32, true).with_metadata(metadata(&[(
            crate::egress::arrow::metadata::GEOHASH_BITS,
            "20",
        )]));
        let rb = single_col_batch(field, b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn decimal64_payload_is_le_twos_complement() {
        let mut b = Decimal64Builder::new();
        b.append_value(12345);
        b.append_value(-2);
        let arr = b.finish().with_precision_and_scale(18, 2).unwrap();
        let mut out = Vec::new();
        write_decimal64_payload(&mut out, &arr, false).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&12345_i64.to_le_bytes());
        expected.extend_from_slice(&(-2_i64).to_le_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn decimal128_payload_is_le_twos_complement() {
        let mut b = Decimal128Builder::new();
        b.append_value(67890_i128);
        b.append_value(-1_i128);
        let arr = b.finish().with_precision_and_scale(38, 3).unwrap();
        let mut out = Vec::new();
        write_decimal128_payload(&mut out, &arr, false).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&67890_i128.to_le_bytes());
        expected.extend_from_slice(&(-1_i128).to_le_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn decimal256_payload_is_le_twos_complement() {
        use arrow_array::builder::Decimal256Builder;
        use arrow_buffer::i256;
        let mut b = Decimal256Builder::new();
        b.append_value(i256::from_i128(67890));
        b.append_value(i256::from_i128(-3));
        let arr = b.finish().with_precision_and_scale(40, 3).unwrap();
        let mut out = Vec::new();
        write_decimal256_payload(&mut out, &arr, false).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(&i256::from_i128(67890).to_le_bytes());
        expected.extend_from_slice(&i256::from_i128(-3).to_le_bytes());
        assert_eq!(out, expected);
    }

    #[test]
    fn decimal32_widens_to_le_i64_payload() {
        use arrow_array::builder::Decimal32Builder;
        let mut b = Decimal32Builder::new();
        b.append_value(-5_i32);
        let arr = b.finish().with_precision_and_scale(9, 2).unwrap();
        let mut out = Vec::new();
        write_decimal32_widen_to_64_payload(&mut out, &arr, false).unwrap();
        assert_eq!(out, (-5_i64).to_le_bytes());
    }

    // QWP convention: a set bit == null.
    fn decode_qwp_nulls(bytes: &[u8], rows: usize) -> Vec<bool> {
        (0..rows)
            .map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1)
            .collect()
    }

    #[test]
    fn qwp_bitmap_aligned_trailing_bits() {
        use arrow_buffer::BooleanBuffer;
        // 13 rows, byte-aligned offset → word/byte NOT path plus the
        // trailing-bit mask (13 % 8 == 5).
        let valid: Vec<bool> = vec![
            true, false, true, true, false, true, false, true, // byte 0
            true, false, true, false, true, // 5 trailing rows
        ];
        let nulls = NullBuffer::new(BooleanBuffer::from(valid.clone()));
        let mut out = Vec::new();
        write_qwp_bitmap_from_arrow(&mut out, &nulls).unwrap();
        let expected: Vec<bool> = valid.iter().map(|v| !v).collect();
        assert_eq!(decode_qwp_nulls(&out, valid.len()), expected);
        assert_eq!(out.len(), 2);
        assert_eq!(out[1] >> 5, 0, "trailing bits beyond row count must be 0");
    }

    #[test]
    fn qwp_bitmap_unaligned_sliced_fallback() {
        use arrow_buffer::BooleanBuffer;
        // Slice at a non-byte-aligned offset with a non-multiple-of-8
        // length to drive the shift+OR fallback and its trailing mask.
        let valid: Vec<bool> = vec![
            true, false, true, true, // bits 0..3, dropped by the slice
            false, true, false, true, true, false, true, // window rows 0..6
            false, true, // padding past the window
        ];
        let nulls = NullBuffer::new(BooleanBuffer::from(valid.clone()).slice(4, 7));
        assert_eq!(nulls.offset() % 8, 4, "must exercise the unaligned path");
        let mut out = Vec::new();
        write_qwp_bitmap_from_arrow(&mut out, &nulls).unwrap();
        let expected: Vec<bool> = valid[4..11].iter().map(|v| !v).collect();
        assert_eq!(decode_qwp_nulls(&out, 7), expected);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0] >> 7, 0, "trailing bit beyond row count must be 0");
    }

    #[test]
    fn qwp_bitmap_unaligned_all_null_and_all_valid() {
        use arrow_buffer::BooleanBuffer;
        let all_valid = vec![true; 12];
        let nulls = NullBuffer::new(BooleanBuffer::from(all_valid).slice(3, 6));
        let mut out = Vec::new();
        write_qwp_bitmap_from_arrow(&mut out, &nulls).unwrap();
        assert_eq!(decode_qwp_nulls(&out, 6), vec![false; 6]);

        let all_null = vec![false; 12];
        let nulls = NullBuffer::new(BooleanBuffer::from(all_null).slice(3, 6));
        let mut out = Vec::new();
        write_qwp_bitmap_from_arrow(&mut out, &nulls).unwrap();
        assert_eq!(decode_qwp_nulls(&out, 6), vec![true; 6]);
        assert_eq!(out[0] >> 6, 0, "trailing bits beyond row count must be 0");
    }

    #[test]
    fn designated_timestamp_column_picks_per_row_value() {
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(1_700_000_000_000_000);
        ts.append_value(1_700_000_000_000_001);
        let ts_arr = ts.finish().with_timezone("UTC");
        let mut v = Int64Builder::new();
        v.append_value(10);
        v.append_value(20);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, Some("UTC".into())),
                false,
            ),
            Field::new("v", DataType::Int64, false),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ts_arr) as ArrayRef,
                Arc::new(v.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let out = encode_at_ts(&rb, 0);
        assert_qwp_header(&out, 1);
    }

    #[test]
    fn ts_column_not_found_returns_arrow_ingest_error() {
        let mut v = Int64Builder::new();
        v.append_value(10);
        let rb = single_col_batch(Field::new("v", DataType::Int64, false), v.finish());
        let err = resolve_ts_column(&rb, col_name("missing_ts")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn ts_column_wrong_dtype_returns_arrow_ingest_error() {
        let mut v = Int64Builder::new();
        v.append_value(10);
        let rb = single_col_batch(Field::new("v", DataType::Int64, false), v.finish());
        let err = resolve_ts_column(&rb, col_name("v")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn nested_int_list_rejected_as_unsupported() {
        let mut single = ListBuilder::new(Int64Builder::new());
        single.values().append_value(1);
        single.append(true);
        let field = Field::new(
            "a",
            DataType::List(Arc::new(Field::new("item", DataType::Int64, true))),
            true,
        );
        let rb = single_col_batch(field, single.finish());
        assert_classify_rejects(&rb);
    }

    #[test]
    fn empty_batch_is_noop() {
        let mut v = Int64Builder::new();
        let rb = single_col_batch(Field::new("v", DataType::Int64, false), v.finish());
        let out = encode(&rb);
        // empty batch → header-only frame, table_count = 0
        assert_qwp_header(&out, 0);
    }

    #[test]
    fn i32_arrow_uses_min_sentinel_for_null_rows() {
        let mut b = Int32Builder::new();
        b.append_value(7);
        b.append_null();
        b.append_value(-3);
        let rb = single_col_batch(Field::new("n", DataType::Int32, true), b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn f64_arrow_uses_nan_sentinel_for_null_rows() {
        let mut b = Float64Builder::new();
        b.append_value(1.0);
        b.append_null();
        b.append_value(2.0);
        let rb = single_col_batch(Field::new("f", DataType::Float64, true), b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn designated_timestamp_arrow_nulls_are_rejected() {
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(1);
        ts.append_null();
        let rb = single_col_batch(
            Field::new("t", DataType::Timestamp(TimeUnit::Microsecond, None), true),
            ts.finish(),
        );
        let err = encode_err_at_ts(&rb, 0);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn timestamp_arrow_negative_values_are_rejected() {
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(-1);
        let rb = single_col_batch(
            Field::new("t", DataType::Timestamp(TimeUnit::Microsecond, None), false),
            ts.finish(),
        );
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn timestamp_field_nulls_are_rejected() {
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(1);
        ts.append_null();
        let rb = single_col_batch(
            Field::new("t", DataType::Timestamp(TimeUnit::Microsecond, None), true),
            ts.finish(),
        );
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn varchar_arrow_encodes_null_rows() {
        let mut s = StringBuilder::new();
        s.append_value("a");
        s.append_null();
        s.append_value("c");
        let rb = single_col_batch(Field::new("s", DataType::Utf8, true), s.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn symbol_arrow_builds_dict_and_dedups_keys() {
        let mut sb = StringBuilder::new();
        sb.append_value("A");
        sb.append_value("B");
        sb.append_value("A");
        sb.append_value("B");
        let field = Field::new("s", DataType::Utf8, false).with_metadata(metadata(&[(
            crate::egress::arrow::metadata::COLUMN_TYPE,
            "symbol",
        )]));
        let rb = single_col_batch(field, sb.finish());
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(&mut out, tbl("t"), &rb, None, &[], &mut dict, false).unwrap();
        // 4 rows, only 2 unique values → dict has 2 entries.
        assert_eq!(dict.next_id(), 2);
    }

    #[test]
    fn utf8_with_symbol_metadata_builds_symbol_dictionary() {
        let mut sb = StringBuilder::new();
        sb.append_value("x");
        sb.append_value("y");
        let field = Field::new("s", DataType::Utf8, false).with_metadata(metadata(&[(
            crate::egress::arrow::metadata::SYMBOL,
            "true",
        )]));
        let rb = single_col_batch(field, sb.finish());
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(&mut out, tbl("t"), &rb, None, &[], &mut dict, false).unwrap();
        assert_eq!(dict.next_id(), 2);
    }

    #[test]
    fn decimal128_arrow_propagates_scale() {
        let mut b = Decimal128Builder::new();
        b.append_value(42_i128);
        let arr = b.finish().with_precision_and_scale(10, 4).unwrap();
        let rb = single_col_batch(Field::new("d", DataType::Decimal128(10, 4), true), arr);
        let out = encode(&rb);
        assert_qwp_header(&out, 1);
    }

    #[test]
    fn geohash_arrow_encodes_null_rows_via_bitmap() {
        let mut b = Int32Builder::new();
        b.append_value(0x1234);
        b.append_null();
        let field = Field::new("g", DataType::Int32, true).with_metadata(metadata(&[(
            crate::egress::arrow::metadata::GEOHASH_BITS,
            "20",
        )]));
        let rb = single_col_batch(field, b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn designated_ts_with_null_rejects() {
        let mut payload = Int64Builder::new();
        payload.append_value(1);
        payload.append_value(2);
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(1_700_000_000_000_000);
        ts.append_null();
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("v", DataType::Int64, false),
            Field::new("ts", DataType::Timestamp(TimeUnit::Microsecond, None), true),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(payload.finish()) as ArrayRef,
                Arc::new(ts.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let err = encode_err_at_ts(&rb, 1);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn designated_ts_with_negative_value_rejects() {
        let mut payload = Int64Builder::new();
        payload.append_value(1);
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(-1);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("v", DataType::Int64, false),
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(payload.finish()) as ArrayRef,
                Arc::new(ts.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let err = encode_err_at_ts(&rb, 1);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn uint8_widens_to_int_appends() {
        let mut b = UInt8Builder::new();
        b.append_value(255);
        b.append_value(0);
        let rb = single_col_batch(Field::new("u", DataType::UInt8, true), b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn int8_widens_to_int_classifier() {
        let field = Field::new("v", DataType::Int8, true);
        let arr = arrow_array::Int8Array::from(vec![0i8, -1, 127]);
        let kind = classify(&field, &arr).unwrap();
        assert!(matches!(kind, ColumnKind::I8WidenToI32));
        assert_eq!(wire_type_byte(kind, false), QWP_TYPE_INT);
    }

    #[test]
    fn int16_widens_to_int_classifier() {
        let field = Field::new("v", DataType::Int16, true);
        let arr = arrow_array::Int16Array::from(vec![0i16, -1, i16::MAX]);
        let kind = classify(&field, &arr).unwrap();
        assert!(matches!(kind, ColumnKind::I16WidenToI32));
        assert_eq!(wire_type_byte(kind, false), QWP_TYPE_INT);
    }

    #[test]
    fn int32_widens_to_long_classifier() {
        let field = Field::new("v", DataType::Int32, true);
        let arr = arrow_array::Int32Array::from(vec![0i32, -1, i32::MAX]);
        let kind = classify(&field, &arr).unwrap();
        assert!(matches!(kind, ColumnKind::I32WidenToI64));
        assert_eq!(wire_type_byte(kind, false), QWP_TYPE_LONG);
    }

    #[test]
    fn int8_byte_metadata_override_preserves_byte_wire() {
        let field = Field::new("v", DataType::Int8, true).with_metadata(metadata(&[(
            crate::egress::arrow::metadata::COLUMN_TYPE,
            "byte",
        )]));
        let arr = arrow_array::Int8Array::from(vec![1i8, 2, 3]);
        let kind = classify(&field, &arr).unwrap();
        assert!(matches!(kind, ColumnKind::I8));
        assert_eq!(wire_type_byte(kind, false), QWP_TYPE_BYTE);
    }

    #[test]
    fn int16_short_metadata_override_preserves_short_wire() {
        let field = Field::new("v", DataType::Int16, true).with_metadata(metadata(&[(
            crate::egress::arrow::metadata::COLUMN_TYPE,
            "short",
        )]));
        let arr = arrow_array::Int16Array::from(vec![1i16, 2, 3]);
        let kind = classify(&field, &arr).unwrap();
        assert!(matches!(kind, ColumnKind::I16));
        assert_eq!(wire_type_byte(kind, false), QWP_TYPE_SHORT);
    }

    #[test]
    fn int32_int_metadata_override_preserves_int_wire() {
        let field = Field::new("v", DataType::Int32, true).with_metadata(metadata(&[(
            crate::egress::arrow::metadata::COLUMN_TYPE,
            "int",
        )]));
        let arr = arrow_array::Int32Array::from(vec![1i32, 2, 3]);
        let kind = classify(&field, &arr).unwrap();
        assert!(matches!(kind, ColumnKind::I32));
        assert_eq!(wire_type_byte(kind, false), QWP_TYPE_INT);
    }

    #[test]
    fn uint64_within_i64_range_appends() {
        let mut b = UInt64Builder::new();
        b.append_value(42);
        b.append_value(i64::MAX as u64);
        let rb = single_col_batch(Field::new("u", DataType::UInt64, true), b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn uint64_above_i64_max_rejects() {
        let mut b = UInt64Builder::new();
        let v: u64 = i64::MAX as u64 + 1;
        b.append_value(v);
        let rb = single_col_batch(Field::new("u", DataType::UInt64, true), b.finish());
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("does not fit QuestDB LONG"),
            "{}",
            err.msg()
        );
    }

    #[test]
    fn nullable_uint64_above_i64_max_rejects() {
        let mut b = UInt64Builder::new();
        b.append_null();
        b.append_value(u64::MAX);
        let rb = single_col_batch(Field::new("u", DataType::UInt64, true), b.finish());
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("does not fit QuestDB LONG"),
            "{}",
            err.msg()
        );
    }

    #[test]
    fn timestamp_second_widens_to_micros() {
        let mut b = TimestampSecondBuilder::new();
        b.append_value(1);
        let rb = single_col_batch(
            Field::new("t", DataType::Timestamp(TimeUnit::Second, None), false),
            b.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // Dictionary key/value matrix
    // -----------------------------------------------------------------

    #[test]
    fn dict_u32_large_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let dict = DictionaryArray::<UInt32Type>::from_iter(
            ["AAPL", "MSFT", "AAPL"].into_iter().map(Some),
        );
        let large_values = LargeStringArray::from(vec!["AAPL", "MSFT"]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(dict.keys().clone(), Arc::new(large_values))
                .unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::LargeUtf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn dict_u8_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt8Type;
        let dict = DictionaryArray::<UInt8Type>::from_iter(
            ["red", "green", "blue", "red"].into_iter().map(Some),
        );
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn dict_u32_utf8_view_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let dict = DictionaryArray::<UInt32Type>::from_iter(
            ["AAPL", "MSFT", "AAPL"].into_iter().map(Some),
        );
        let view_values = StringViewArray::from(vec!["AAPL", "MSFT"]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(dict.keys().clone(), Arc::new(view_values))
                .unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8View)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn dict_u16_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt16Type;
        let dict =
            DictionaryArray::<UInt16Type>::from_iter(["x", "y", "x", "z"].into_iter().map(Some));
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt16), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn dict_u8_large_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt8Type;
        let keys = arrow_array::UInt8Array::from(vec![0u8, 1, 0, 1]);
        let values = LargeStringArray::from(vec!["alpha", "beta"]);
        let dict = DictionaryArray::<UInt8Type>::try_new(keys, Arc::new(values)).unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::LargeUtf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn symbol_dict_with_metadata_still_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let dict = DictionaryArray::<UInt32Type>::from_iter(["A", "B", "A"].into_iter().map(Some));
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )
        .with_metadata(metadata(&[(
            crate::egress::arrow::metadata::SYMBOL,
            "true",
        )]));
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // Signed dictionary keys (Int8 / Int16 / Int32)
    // -----------------------------------------------------------------

    #[test]
    fn dict_i8_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::Int8Type;
        let keys = arrow_array::Int8Array::from(vec![0i8, 1, 0, 1]);
        let values = StringArray::from(vec!["red", "green"]);
        let dict = DictionaryArray::<Int8Type>::try_new(keys, Arc::new(values)).unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::Int8), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn dict_i16_large_utf8_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::Int16Type;
        let keys = arrow_array::Int16Array::from(vec![0i16, 1, 1]);
        let values = LargeStringArray::from(vec!["AAPL", "MSFT"]);
        let dict = DictionaryArray::<Int16Type>::try_new(keys, Arc::new(values)).unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::Int16), Box::new(DataType::LargeUtf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn dict_i32_utf8_view_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::Int32Type;
        let keys = arrow_array::Int32Array::from(vec![0i32, 1, 0]);
        let values = StringViewArray::from(vec!["x", "y"]);
        let dict = DictionaryArray::<Int32Type>::try_new(keys, Arc::new(values)).unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::Int32), Box::new(DataType::Utf8View)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn dict_i8_dedups_and_assigns_gids() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::Int8Type;
        // 4 rows reference 2 distinct slots → exactly 2 global ids.
        let keys = arrow_array::Int8Array::from(vec![1i8, 0, 1, 0]);
        let values = StringArray::from(vec!["A", "B"]);
        let dict = DictionaryArray::<Int8Type>::try_new(keys, Arc::new(values)).unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::Int8), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        let mut out = Vec::new();
        let mut gd = SymbolGlobalDict::new();
        encode_arrow_batch_into(&mut out, tbl("t"), &rb, None, &[], &mut gd, false).unwrap();
        assert_eq!(gd.next_id(), 2);
    }

    #[test]
    fn dict_i16_null_keys_skip_intern() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::Int16Type;
        // Null rows must not be interned; only the one referenced slot is.
        let keys = arrow_array::Int16Array::from(vec![Some(0i16), None, Some(0)]);
        let values = StringArray::from(vec!["only"]);
        let dict = DictionaryArray::<Int16Type>::try_new(keys, Arc::new(values)).unwrap();
        let field = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::Int16), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        let mut out = Vec::new();
        let mut gd = SymbolGlobalDict::new();
        encode_arrow_batch_into(&mut out, tbl("t"), &rb, None, &[], &mut gd, false).unwrap();
        assert_eq!(gd.next_id(), 1);
    }

    // -----------------------------------------------------------------
    // LargeUtf8 / LargeBinary bulk-memcpy + slow-path
    // -----------------------------------------------------------------

    #[test]
    fn large_utf8_no_null_takes_bulk_memcpy_path() {
        let a = LargeStringArray::from(vec!["AAPL", "MSFT", "GOOG"]);
        let b = LargeStringArray::from(vec!["alpha", "beta", "gamma"]);
        let rb = RecordBatch::try_new(
            Arc::new(ArrowSchema::new(vec![
                Field::new("a", DataType::LargeUtf8, true),
                Field::new("b", DataType::LargeUtf8, true),
            ])),
            vec![Arc::new(a) as ArrayRef, Arc::new(b) as ArrayRef],
        )
        .unwrap();
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn large_binary_no_null_takes_bulk_memcpy_path() {
        let rows: Vec<&[u8]> = vec![b"\x00\x01", b"\xff", b"\x02\x03\x04"];
        let a = LargeBinaryArray::from_iter_values(rows);
        let rb = single_col_batch(Field::new("a", DataType::LargeBinary, true), a);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn large_utf8_with_nulls_still_works_via_slow_path() {
        let a = LargeStringArray::from(vec![Some("x"), None, Some("yz")]);
        let rb = single_col_batch(Field::new("a", DataType::LargeUtf8, true), a);
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // Time + Duration variants
    // -----------------------------------------------------------------

    #[test]
    fn time32_seconds_appends() {
        use arrow_array::builder::Time32SecondBuilder;
        let mut t = Time32SecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399);
        let rb = single_col_batch(
            Field::new("t", DataType::Time32(TimeUnit::Second), true),
            t.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn time32_milliseconds_appends() {
        use arrow_array::builder::Time32MillisecondBuilder;
        let mut t = Time32MillisecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399_999);
        t.append_null();
        let rb = single_col_batch(
            Field::new("t", DataType::Time32(TimeUnit::Millisecond), true),
            t.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn time64_microseconds_appends() {
        use arrow_array::builder::Time64MicrosecondBuilder;
        let mut t = Time64MicrosecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399_999_999);
        let rb = single_col_batch(
            Field::new("t", DataType::Time64(TimeUnit::Microsecond), true),
            t.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn time64_nanoseconds_appends() {
        use arrow_array::builder::Time64NanosecondBuilder;
        let mut t = Time64NanosecondBuilder::new();
        t.append_value(0);
        t.append_value(86_399 * 1_000_000_000);
        let rb = single_col_batch(
            Field::new("t", DataType::Time64(TimeUnit::Nanosecond), true),
            t.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn duration_seconds_appends() {
        use arrow_array::builder::DurationSecondBuilder;
        let mut d = DurationSecondBuilder::new();
        d.append_value(0);
        d.append_value(-3600);
        d.append_value(86_400);
        let rb = single_col_batch(
            Field::new("d", DataType::Duration(TimeUnit::Second), true),
            d.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn duration_milliseconds_appends() {
        use arrow_array::builder::DurationMillisecondBuilder;
        let mut d = DurationMillisecondBuilder::new();
        d.append_value(1_500);
        d.append_value(0);
        let rb = single_col_batch(
            Field::new("d", DataType::Duration(TimeUnit::Millisecond), true),
            d.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn duration_microseconds_appends() {
        use arrow_array::builder::DurationMicrosecondBuilder;
        let mut d = DurationMicrosecondBuilder::new();
        d.append_value(1_000_000);
        d.append_value(-1);
        d.append_null();
        let rb = single_col_batch(
            Field::new("d", DataType::Duration(TimeUnit::Microsecond), true),
            d.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn duration_nanoseconds_appends() {
        use arrow_array::builder::DurationNanosecondBuilder;
        let mut d = DurationNanosecondBuilder::new();
        d.append_value(0);
        d.append_value(1_500_000_000);
        let rb = single_col_batch(
            Field::new("d", DataType::Duration(TimeUnit::Nanosecond), true),
            d.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // Float16 / Date variants
    // -----------------------------------------------------------------

    #[test]
    fn float16_appends_as_double() {
        use arrow_array::builder::Float16Builder;
        use half::f16;
        let mut b = Float16Builder::new();
        b.append_value(f16::from_f32(1.5));
        b.append_value(f16::from_f32(-2.5));
        b.append_null();
        let rb = single_col_batch(Field::new("h", DataType::Float16, true), b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn date32_days_appends_as_date_ms() {
        use arrow_array::builder::Date32Builder;
        let mut d = Date32Builder::new();
        d.append_value(0);
        d.append_value(19_675);
        d.append_null();
        let rb = single_col_batch(Field::new("d", DataType::Date32, true), d.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn date32_all_null_appends() {
        use arrow_array::builder::Date32Builder;
        let mut d = Date32Builder::new();
        d.append_null();
        d.append_null();
        let rb = single_col_batch(Field::new("d", DataType::Date32, true), d.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn date64_ms_appends_as_date() {
        use arrow_array::builder::Date64Builder;
        let mut d = Date64Builder::new();
        d.append_value(0);
        d.append_value(1_700_000_000_000);
        d.append_null();
        let rb = single_col_batch(Field::new("d", DataType::Date64, true), d.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn time64_ns_all_null_appends() {
        use arrow_array::builder::Time64NanosecondBuilder;
        let mut t = Time64NanosecondBuilder::new();
        t.append_null();
        t.append_null();
        t.append_null();
        let rb = single_col_batch(
            Field::new("t", DataType::Time64(TimeUnit::Nanosecond), true),
            t.finish(),
        );
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // Decimal widening / scale enforcement
    // -----------------------------------------------------------------

    #[test]
    fn decimal32_widens_to_decimal64() {
        use arrow_array::builder::Decimal32Builder;
        let mut b = Decimal32Builder::new();
        b.append_value(12345);
        b.append_value(-678);
        b.append_null();
        let arr = b.finish().with_precision_and_scale(9, 2).unwrap();
        let rb = single_col_batch(Field::new("d", DataType::Decimal32(9, 2), true), arr);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn decimal32_negative_scale_errors() {
        use arrow_array::builder::Decimal32Builder;
        let mut b = Decimal32Builder::new();
        b.append_value(1);
        let arr = b.finish().with_precision_and_scale(9, -2).unwrap();
        let rb = single_col_batch(Field::new("d", DataType::Decimal32(9, -2), true), arr);
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn decimal_scale_u8_enforces_per_width_caps() {
        assert!(decimal_scale_u8(9, "Decimal32", 9).is_ok());
        let err = decimal_scale_u8(10, "Decimal32", 9).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(err.msg().contains("Decimal32"));
        assert!(err.msg().contains("scale 10"));

        assert!(decimal_scale_u8(18, "Decimal64", 18).is_ok());
        assert!(decimal_scale_u8(19, "Decimal64", 18).is_err());

        assert!(decimal_scale_u8(38, "Decimal128", 38).is_ok());
        assert!(decimal_scale_u8(39, "Decimal128", 38).is_err());

        assert!(
            decimal_scale_u8(
                QWP_DECIMAL_MAX_SCALE as i8,
                "Decimal256",
                QWP_DECIMAL_MAX_SCALE
            )
            .is_ok()
        );
        assert!(
            decimal_scale_u8(
                (QWP_DECIMAL_MAX_SCALE as i8).saturating_add(1),
                "Decimal256",
                QWP_DECIMAL_MAX_SCALE,
            )
            .is_err()
        );

        let err = decimal_scale_u8(-1, "Decimal64", 18).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(err.msg().contains("negative"));
    }

    #[test]
    fn decimal256_negative_scale_rejected() {
        use arrow_array::builder::Decimal256Builder;
        use arrow_buffer::i256;
        let mut b = Decimal256Builder::new()
            .with_precision_and_scale(76, -1)
            .unwrap();
        b.append_value(i256::ZERO);
        let rb = single_col_batch(
            Field::new("d", DataType::Decimal256(76, -1), false),
            b.finish(),
        );
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(err.msg().to_lowercase().contains("negative"));
    }

    // -----------------------------------------------------------------
    // Unsupported-column classify rejections
    // -----------------------------------------------------------------

    fn assert_unsupported_column_with(field: Field, arr: ArrayRef) {
        let rb = RecordBatch::try_new(arrow_schema_with(field), vec![arr]).unwrap();
        let err = encode_err(&rb);
        assert!(
            matches!(err.code(), ErrorCode::ArrowUnsupportedColumnKind),
            "expected ArrowUnsupportedColumnKind, got {:?}: {}",
            err.code(),
            err.msg()
        );
    }

    #[test]
    fn interval_year_month_rejected_as_unsupported() {
        use arrow_array::builder::IntervalYearMonthBuilder;
        use arrow_schema::IntervalUnit;
        let mut b = IntervalYearMonthBuilder::new();
        b.append_value(12);
        assert_unsupported_column_with(
            Field::new("c", DataType::Interval(IntervalUnit::YearMonth), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn interval_day_time_rejected_as_unsupported() {
        use arrow_array::builder::IntervalDayTimeBuilder;
        use arrow_array::types::IntervalDayTime;
        use arrow_schema::IntervalUnit;
        let mut b = IntervalDayTimeBuilder::new();
        b.append_value(IntervalDayTime::new(1, 0));
        assert_unsupported_column_with(
            Field::new("c", DataType::Interval(IntervalUnit::DayTime), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn interval_month_day_nano_rejected_as_unsupported() {
        use arrow_array::builder::IntervalMonthDayNanoBuilder;
        use arrow_array::types::IntervalMonthDayNano;
        use arrow_schema::IntervalUnit;
        let mut b = IntervalMonthDayNanoBuilder::new();
        b.append_value(IntervalMonthDayNano::new(1, 1, 1));
        assert_unsupported_column_with(
            Field::new("c", DataType::Interval(IntervalUnit::MonthDayNano), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn fixed_size_binary_arbitrary_width_rejected_as_unsupported() {
        let mut b = FixedSizeBinaryBuilder::new(8);
        b.append_value([0u8; 8]).unwrap();
        assert_unsupported_column_with(
            Field::new("c", DataType::FixedSizeBinary(8), true),
            Arc::new(b.finish()) as ArrayRef,
        );
    }

    #[test]
    fn null_column_rejected_as_unsupported() {
        let arr = arrow_array::NullArray::new(3);
        assert_unsupported_column_with(
            Field::new("c", DataType::Null, true),
            Arc::new(arr) as ArrayRef,
        );
    }

    #[test]
    fn struct_column_rejected_as_unsupported() {
        use arrow_array::StructArray;
        let mut inner = Int32Builder::new();
        inner.append_value(1);
        let inner_arr = Arc::new(inner.finish()) as ArrayRef;
        let inner_field = Arc::new(Field::new("v", DataType::Int32, true));
        let arr = StructArray::from(vec![(inner_field.clone(), inner_arr)]);
        assert_unsupported_column_with(
            Field::new("c", DataType::Struct(vec![inner_field].into()), true),
            Arc::new(arr) as ArrayRef,
        );
    }

    #[test]
    fn map_column_rejected_as_unsupported() {
        use arrow_array::builder::MapBuilder;
        let mut b = MapBuilder::new(None, StringBuilder::new(), Int32Builder::new());
        b.keys().append_value("k");
        b.values().append_value(1);
        b.append(true).unwrap();
        let arr = b.finish();
        let dtype = arr.data_type().clone();
        assert_unsupported_column_with(Field::new("c", dtype, true), Arc::new(arr) as ArrayRef);
    }

    #[test]
    fn run_end_encoded_column_rejected_as_unsupported() {
        use arrow_array::builder::PrimitiveRunBuilder;
        use arrow_array::types::{Int32Type, Int64Type};
        let mut b = PrimitiveRunBuilder::<Int32Type, Int64Type>::new();
        b.append_value(42);
        b.append_value(42);
        b.append_value(7);
        let arr = b.finish();
        let dtype = arr.data_type().clone();
        assert_unsupported_column_with(Field::new("c", dtype, true), Arc::new(arr) as ArrayRef);
    }

    // -----------------------------------------------------------------
    // Dictionary null-entry edge cases
    // -----------------------------------------------------------------

    #[test]
    fn referenced_null_dict_entry_rejected_for_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        vb.append_value("c");
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 1, 2]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
        let field = Field::new(
            "sym",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )
        .with_metadata(metadata(&[(
            crate::egress::arrow::metadata::SYMBOL,
            "true",
        )]));
        let rb = single_col_batch(field, dict);
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(err.msg().contains("slot"));
    }

    #[test]
    fn referenced_null_dict_entry_rejected() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 1]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
        let field = Field::new(
            "v",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
    }

    #[test]
    fn unreferenced_null_dict_entry_accepted_for_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        vb.append_value("c");
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 2, 0]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
        let field = Field::new(
            "sym",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        )
        .with_metadata(metadata(&[(
            crate::egress::arrow::metadata::SYMBOL,
            "true",
        )]));
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn unreferenced_null_dict_entry_accepted() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let mut vb = StringBuilder::new();
        vb.append_value("a");
        vb.append_null();
        let values = vb.finish();
        let keys = arrow_array::UInt32Array::from(vec![0u32, 0]);
        let dict =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
        let field = Field::new(
            "v",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(field, dict);
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // Timestamp overflow paths (ms→µs / s→µs)
    // -----------------------------------------------------------------

    #[test]
    fn timestamp_ms_designated_overflow_rejected() {
        let mut ts = TimestampMillisecondBuilder::new();
        ts.append_value(i64::MAX / 1000 + 1);
        ts.append_value(0);
        let mut v = Int64Builder::new();
        v.append_value(1);
        v.append_value(2);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Millisecond, None),
                false,
            ),
            Field::new("v", DataType::Int64, false),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ts.finish()) as ArrayRef,
                Arc::new(v.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let err = encode_err_at_ts(&rb, 0);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("ms→µs overflow"),
            "expected overflow message, got: {}",
            err.msg()
        );
    }

    #[test]
    fn timestamp_second_to_micros_overflow_rejected() {
        let mut b = TimestampSecondBuilder::new();
        b.append_value(i64::MAX / 1_000_000 + 1);
        let rb = single_col_batch(
            Field::new("t", DataType::Timestamp(TimeUnit::Second, None), true),
            b.finish(),
        );
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("s→µs overflow"),
            "expected overflow message, got: {}",
            err.msg()
        );
    }

    #[test]
    fn timestamp_second_designated_writes_ts() {
        let mut payload = Float64Builder::new();
        payload.append_value(1.0);
        payload.append_value(2.0);
        let mut ts = TimestampSecondBuilder::new();
        ts.append_value(1);
        ts.append_value(2);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("price", DataType::Float64, false),
            Field::new("ts", DataType::Timestamp(TimeUnit::Second, None), false),
        ]));
        let batch = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(payload.finish()) as ArrayRef,
                Arc::new(ts.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let out = encode_at_ts(&batch, 1);
        assert_qwp_header(&out, 1);
    }

    #[test]
    fn timestamp_second_designated_overflow_rejected() {
        let mut ts = TimestampSecondBuilder::new();
        ts.append_value(i64::MAX / 1_000_000 + 1);
        ts.append_value(0);
        let mut v = Int64Builder::new();
        v.append_value(1);
        v.append_value(2);
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("ts", DataType::Timestamp(TimeUnit::Second, None), false),
            Field::new("v", DataType::Int64, false),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(ts.finish()) as ArrayRef,
                Arc::new(v.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let err = encode_err_at_ts(&rb, 0);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("s→µs overflow"),
            "expected overflow message, got: {}",
            err.msg()
        );
    }

    // -----------------------------------------------------------------
    // Rollback + column-name error decoration
    // -----------------------------------------------------------------

    #[test]
    fn encode_error_rolls_back_out_and_dict() {
        use arrow_array::builder::MapBuilder;
        // First column: valid Int64. Second column: Map (unsupported).
        // Encoder must reject and leave `out` truncated to its original
        // length, dict at its mark.
        let mut col1 = Int64Builder::new();
        col1.append_value(11);
        col1.append_value(22);
        let mut map = MapBuilder::new(None, StringBuilder::new(), Int32Builder::new());
        map.keys().append_value("k1");
        map.values().append_value(1);
        map.append(true).unwrap();
        map.keys().append_value("k2");
        map.values().append_value(2);
        map.append(true).unwrap();
        let map_arr = map.finish();
        let map_dtype = map_arr.data_type().clone();
        let schema = Arc::new(ArrowSchema::new(vec![
            Field::new("good", DataType::Int64, false),
            Field::new("bad", map_dtype, true),
        ]));
        let rb = RecordBatch::try_new(
            schema,
            vec![
                Arc::new(col1.finish()) as ArrayRef,
                Arc::new(map_arr) as ArrayRef,
            ],
        )
        .unwrap();
        let mut out = Vec::from(b"PREFIX");
        let prior_len = out.len();
        let mut dict = SymbolGlobalDict::new();
        let err = encode_arrow_batch_into(&mut out, tbl("t"), &rb, None, &[], &mut dict, false)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ArrowUnsupportedColumnKind);
        assert_eq!(
            out.len(),
            prior_len,
            "encoder must truncate out to prior length"
        );
        assert_eq!(dict.next_id(), 0, "no symbols should have leaked into dict");
    }

    #[test]
    fn error_message_carries_column_name() {
        let inner_field = Arc::new(Field::new("x", DataType::Int32, true));
        let mut b = Int32Builder::new();
        b.append_value(1);
        let struct_arr = arrow_array::StructArray::from(vec![(
            inner_field.clone(),
            Arc::new(b.finish()) as ArrayRef,
        )]);
        let rb = single_col_batch(
            Field::new(
                "my_struct_col",
                DataType::Struct(vec![inner_field].into()),
                true,
            ),
            struct_arr,
        );
        let err = encode_err(&rb);
        assert!(
            err.msg().contains("my_struct_col"),
            "column name missing from error: {}",
            err.msg()
        );
    }

    // -----------------------------------------------------------------
    // Sliced arrays
    // -----------------------------------------------------------------

    #[test]
    fn sliced_int32_array_emits_sliced_window_only() {
        let mut b = Int32Builder::new();
        for v in 0..8 {
            b.append_value(v);
        }
        let full = b.finish();
        let sliced = full.slice(2, 4);
        assert_eq!(sliced.len(), 4);
        let rb = single_col_batch(Field::new("v", DataType::Int32, false), sliced);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn sliced_utf8_array_emits_sliced_window_only() {
        let mut b = StringBuilder::new();
        for s in ["a", "bb", "ccc", "dddd", "eeeee"] {
            b.append_value(s);
        }
        let full = b.finish();
        let sliced = full.slice(1, 3);
        let rb = single_col_batch(Field::new("s", DataType::Utf8, false), sliced);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn sliced_bool_array_with_offset_emits_sliced_window() {
        use arrow_array::builder::BooleanBuilder;
        let mut b = BooleanBuilder::new();
        for v in [true, false, true, false, true, false, true, false, true] {
            b.append_value(v);
        }
        let full = b.finish();
        let sliced = full.slice(3, 5);
        let rb = single_col_batch(Field::new("flag", DataType::Boolean, false), sliced);
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // Geohash precision / single-row / no-user-columns edges
    // -----------------------------------------------------------------

    #[test]
    fn geohash_int8_precision_above_8_rejected() {
        let mut b = Int8Builder::new();
        b.append_value(0);
        let mut md = std::collections::HashMap::new();
        md.insert("questdb.geohash_bits".to_string(), "20".to_string());
        let field = Field::new("g", DataType::Int8, true).with_metadata(md);
        let rb = single_col_batch(field, b.finish());
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(err.msg().contains("geohash"));
    }

    #[test]
    fn varlen_no_user_columns_rejected() {
        let mut ts = TimestampMicrosecondBuilder::new();
        ts.append_value(0);
        let rb = single_col_batch(
            Field::new(
                "ts",
                DataType::Timestamp(TimeUnit::Microsecond, None),
                false,
            ),
            ts.finish(),
        );
        let err = encode_err_at_ts(&rb, 0);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(err.msg().contains("non-timestamp column"));
    }

    #[test]
    fn single_row_int64_appends_one_row() {
        let mut b = Int64Builder::new();
        b.append_value(0);
        let rb = single_col_batch(Field::new("v", DataType::Int64, false), b.finish());
        assert_ok_with_table_count(&rb, 1);
    }

    // -----------------------------------------------------------------
    // ArrayDouble (Float64 list / fixed-size list)
    // -----------------------------------------------------------------

    #[test]
    fn nested_double_list_routes_to_column_arr() {
        let mut single = ListBuilder::new(Float64Builder::new());
        single.values().append_value(1.0);
        single.values().append_value(2.0);
        single.values().append_value(3.0);
        single.append(true);
        let arr = single.finish();
        let field = Field::new(
            "a",
            DataType::List(Arc::new(Field::new("item", DataType::Float64, true))),
            true,
        );
        let rb = single_col_batch(field, arr);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn nested_double_list_with_null_leaf_rejected() {
        let mut single = ListBuilder::new(Float64Builder::new());
        single.values().append_value(1.0);
        single.values().append_null();
        single.values().append_value(3.0);
        single.append(true);
        let arr = single.finish();
        let field = Field::new(
            "a",
            DataType::List(Arc::new(Field::new("item", DataType::Float64, true))),
            true,
        );
        let rb = single_col_batch(field, arr);
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowUnsupportedColumnKind);
        assert!(
            err.msg().contains("does not support NULL array element"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn array_double_2d_arrow_encodes_per_row_blobs() {
        let mut outer = ListBuilder::new(ListBuilder::new(Float64Builder::new()));
        {
            let mid = outer.values();
            mid.values().append_value(1.0);
            mid.values().append_value(2.0);
            mid.append(true);
            mid.values().append_value(3.0);
            mid.values().append_value(4.0);
            mid.append(true);
        }
        outer.append(true);
        {
            let mid = outer.values();
            mid.values().append_value(5.0);
            mid.append(true);
        }
        outer.append(true);
        let arr = outer.finish();
        let inner_field = Arc::new(Field::new(
            "item",
            DataType::List(Arc::new(Field::new("item", DataType::Float64, true))),
            true,
        ));
        let field = Field::new("a", DataType::List(inner_field), true);
        let rb = single_col_batch(field, arr);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn fixed_size_list_float64_appends_as_array_1d() {
        use arrow_array::builder::FixedSizeListBuilder;
        let mut b = FixedSizeListBuilder::new(Float64Builder::new(), 3);
        b.values().append_value(1.0);
        b.values().append_value(2.0);
        b.values().append_value(3.0);
        b.append(true);
        b.values().append_value(4.0);
        b.values().append_value(5.0);
        b.values().append_value(6.0);
        b.append(true);
        let arr = b.finish();
        let field = Field::new("a", arr.data_type().clone(), true);
        let rb = single_col_batch(field, arr);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn large_list_nested_float64_appends_as_array_2d() {
        use arrow_array::builder::LargeListBuilder;
        let mut outer = LargeListBuilder::new(LargeListBuilder::new(Float64Builder::new()));
        for v in [1.0, 2.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        for v in [3.0, 4.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        outer.append(true);
        for v in [5.0, 6.0, 7.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        for v in [8.0, 9.0, 10.0] {
            outer.values().values().append_value(v);
        }
        outer.values().append(true);
        outer.append(true);
        let arr = outer.finish();
        let field = Field::new("a", arr.data_type().clone(), true);
        let rb = single_col_batch(field, arr);
        assert_ok_with_table_count(&rb, 1);
    }

    #[test]
    fn nested_list_ragged_inner_within_row_errors() {
        let mut outer = ListBuilder::new(ListBuilder::new(Float64Builder::new()));
        outer.values().values().append_value(1.0);
        outer.values().values().append_value(2.0);
        outer.values().append(true);
        outer.values().values().append_value(3.0);
        outer.values().append(true);
        outer.append(true);
        let arr = outer.finish();
        let field = Field::new("a", arr.data_type().clone(), true);
        let rb = single_col_batch(field, arr);
        let err = encode_err(&rb);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg().contains("ragged inner-list sizes"),
            "unexpected error: {}",
            err.msg()
        );
    }

    // -----------------------------------------------------------------
    // arrow_overrides
    // -----------------------------------------------------------------

    fn encode_with_overrides(
        batch: &RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<(Vec<u8>, SymbolGlobalDict)> {
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        encode_arrow_batch_into(&mut out, tbl("t"), batch, None, overrides, &mut dict, false)?;
        Ok((out, dict))
    }

    fn encode_with_overrides_err(
        batch: &RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Error {
        encode_with_overrides(batch, overrides).unwrap_err()
    }

    #[test]
    fn flush_arrow_batch_overrides_symbol_promotes_utf8() {
        let mut sb = StringBuilder::new();
        sb.append_value("EU");
        sb.append_value("US");
        sb.append_value("EU");
        let f = Field::new("region", DataType::Utf8, false);
        let rb = single_col_batch(f, sb.finish());
        let (out, dict) =
            encode_with_overrides(&rb, &[ArrowColumnOverride::Symbol { column: "region" }])
                .unwrap();
        assert_qwp_header(&out, 1);
        assert_eq!(dict.next_id(), 2);
        assert!(
            out.contains(&QWP_TYPE_SYMBOL),
            "wire output missing QWP_TYPE_SYMBOL byte"
        );
    }

    #[test]
    fn flush_arrow_batch_overrides_ipv4_on_uint32() {
        let mut b = UInt32Builder::new();
        b.append_value(0x0100_007F);
        b.append_value(0x0101_A8C0);
        let f = Field::new("addr", DataType::UInt32, true);
        let rb = single_col_batch(f, b.finish());
        let (out, _dict) =
            encode_with_overrides(&rb, &[ArrowColumnOverride::Ipv4 { column: "addr" }]).unwrap();
        assert_qwp_header(&out, 1);
        assert!(
            out.contains(&QWP_TYPE_IPV4),
            "wire output missing QWP_TYPE_IPV4 byte"
        );
    }

    #[test]
    fn flush_arrow_batch_overrides_unknown_column_rejected() {
        let mut b = Int64Builder::new();
        b.append_value(1);
        let rb = single_col_batch(Field::new("c", DataType::Int64, false), b.finish());
        let err =
            encode_with_overrides_err(&rb, &[ArrowColumnOverride::Symbol { column: "missing" }]);
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg()
                .contains("override targets unknown column 'missing'"),
            "unexpected error: {}",
            err.msg()
        );
    }

    #[test]
    fn flush_arrow_batch_overrides_duplicate_rejected() {
        let mut sb = StringBuilder::new();
        sb.append_value("x");
        let rb = single_col_batch(Field::new("s", DataType::Utf8, false), sb.finish());
        let err = encode_with_overrides_err(
            &rb,
            &[
                ArrowColumnOverride::Symbol { column: "s" },
                ArrowColumnOverride::Symbol { column: "s" },
            ],
        );
        assert_eq!(err.code(), ErrorCode::ArrowIngest);
        assert!(
            err.msg()
                .contains("duplicate arrow override for column 's'"),
            "unexpected error: {}",
            err.msg()
        );
    }

    #[test]
    fn flush_arrow_batch_overrides_geohash_bits_validated() {
        let mut b = Int32Builder::new();
        b.append_value(0);
        let rb = single_col_batch(Field::new("g", DataType::Int32, true), b.finish());
        let err_zero = encode_with_overrides_err(
            &rb,
            &[ArrowColumnOverride::Geohash {
                column: "g",
                bits: 0,
            }],
        );
        assert_eq!(err_zero.code(), ErrorCode::ArrowIngest);
        assert!(
            err_zero.msg().contains("invalid geohash bits 0"),
            "unexpected error: {}",
            err_zero.msg()
        );
        let err_over = encode_with_overrides_err(
            &rb,
            &[ArrowColumnOverride::Geohash {
                column: "g",
                bits: 61,
            }],
        );
        assert_eq!(err_over.code(), ErrorCode::ArrowIngest);
        assert!(
            err_over.msg().contains("invalid geohash bits 61"),
            "unexpected error: {}",
            err_over.msg()
        );
    }

    #[test]
    fn flush_arrow_batch_overrides_preserves_existing_metadata() {
        let mut b = Int64Builder::new();
        b.append_value(1);
        let mut sb = StringBuilder::new();
        sb.append_value("AAPL");
        let id_md = metadata(&[(
            crate::egress::arrow::metadata::ARROW_EXTENSION_NAME,
            "arrow.uuid",
        )]);
        let id_field = Field::new("id", DataType::Int64, true).with_metadata(id_md);
        let sym_field = Field::new("sym", DataType::Utf8, false);
        let schema = Arc::new(ArrowSchema::new(vec![id_field, sym_field]));
        let rb = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(b.finish()) as ArrayRef,
                Arc::new(sb.finish()) as ArrayRef,
            ],
        )
        .unwrap();
        let patched =
            apply_overrides(&schema, &[ArrowColumnOverride::Symbol { column: "sym" }]).unwrap();
        let id_after = patched.field(0);
        assert_eq!(
            id_after
                .metadata()
                .get(crate::egress::arrow::metadata::ARROW_EXTENSION_NAME)
                .map(String::as_str),
            Some("arrow.uuid"),
            "unrelated extension metadata stripped: {:?}",
            id_after.metadata()
        );
        let sym_after = patched.field(1);
        assert_eq!(
            sym_after
                .metadata()
                .get(crate::egress::arrow::metadata::SYMBOL)
                .map(String::as_str),
            Some("true")
        );
        let (_out, _dict) =
            encode_with_overrides(&rb, &[ArrowColumnOverride::Symbol { column: "sym" }]).unwrap();
    }

    #[test]
    fn not_symbol_override_decodes_dict_to_varchar_u8_utf8() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt8Type;
        let dict = DictionaryArray::<UInt8Type>::from_iter(
            ["foo", "bar", "foo", "baz"].into_iter().map(Some),
        );
        let f = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(f, dict);
        let (out, dict_global) =
            encode_with_overrides(&rb, &[ArrowColumnOverride::NotSymbol { column: "s" }]).unwrap();
        assert_qwp_header(&out, 1);
        // SymbolDict route would populate the global symbol dictionary.
        // DictToVarchar must not.
        assert_eq!(dict_global.next_id(), 0);
        for s in ["foo", "bar", "baz"] {
            assert!(out.windows(s.len()).any(|w| w == s.as_bytes()));
        }
    }

    #[test]
    fn not_symbol_override_decodes_dict_to_varchar_u32_large_utf8() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt32Type;
        let keys = arrow_array::UInt32Array::from(vec![0u32, 1, 0]);
        let values = LargeStringArray::from(vec!["alpha", "beta"]);
        let dict = DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values)).unwrap();
        let f = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::LargeUtf8)),
            true,
        );
        let rb = single_col_batch(f, dict);
        let (out, dict_global) =
            encode_with_overrides(&rb, &[ArrowColumnOverride::NotSymbol { column: "s" }]).unwrap();
        assert_eq!(dict_global.next_id(), 0);
        for s in ["alpha", "beta"] {
            assert!(out.windows(s.len()).any(|w| w == s.as_bytes()));
        }
    }

    #[test]
    fn not_symbol_override_decodes_dict_with_nulls() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::Int16Type;
        let dict = DictionaryArray::<Int16Type>::from_iter(
            [Some("x"), None, Some("y"), Some("x")].into_iter(),
        );
        let f = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::Int16), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(f, dict);
        let (out, dict_global) =
            encode_with_overrides(&rb, &[ArrowColumnOverride::NotSymbol { column: "s" }]).unwrap();
        assert_eq!(dict_global.next_id(), 0);
        for s in ["x", "y"] {
            assert!(out.windows(s.len()).any(|w| w == s.as_bytes()));
        }
    }

    #[test]
    fn not_symbol_override_on_plain_utf8_keeps_varchar() {
        let mut sb = StringBuilder::new();
        sb.append_value("hi");
        sb.append_value("yo");
        let f = Field::new("s", DataType::Utf8, false);
        let rb = single_col_batch(f, sb.finish());
        let (_out, dict_global) =
            encode_with_overrides(&rb, &[ArrowColumnOverride::NotSymbol { column: "s" }]).unwrap();
        assert_eq!(dict_global.next_id(), 0);
    }

    #[test]
    fn dict_without_not_symbol_override_still_routes_to_symbol() {
        use arrow_array::DictionaryArray;
        use arrow_array::types::UInt8Type;
        let dict = DictionaryArray::<UInt8Type>::from_iter(["a", "b", "a"].into_iter().map(Some));
        let f = Field::new(
            "s",
            DataType::Dictionary(Box::new(DataType::UInt8), Box::new(DataType::Utf8)),
            true,
        );
        let rb = single_col_batch(f, dict);
        let (_out, dict_global) = encode_with_overrides(&rb, &[]).unwrap();
        assert_eq!(dict_global.next_id(), 2);
    }
}
