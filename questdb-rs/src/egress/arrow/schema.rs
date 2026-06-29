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

//! Arrow schema construction from `Schema` + first `DecodedBatch`.

use std::collections::HashMap;
use std::sync::Arc;

use arrow_schema::{DataType, Field, Schema as ArrowSchema, TimeUnit};

use crate::egress::arrow::metadata::*;
use crate::egress::column_kind::ColumnKind;
use crate::egress::decoder::{DecodedBatch, DecodedColumn};
use crate::egress::error::{Error, ErrorCode, Result, fmt};
use crate::egress::schema::Schema;

pub(crate) fn batch_arrow_schema(schema: &Schema, batch: &DecodedBatch) -> Result<ArrowSchema> {
    if schema.len() != batch.columns.len() {
        return Err(fmt!(
            ProtocolError,
            "schema/batch column count mismatch: schema={} batch={}",
            schema.len(),
            batch.columns.len()
        ));
    }
    let mut fields = Vec::with_capacity(schema.len());
    for (idx, col) in schema.columns().iter().enumerate() {
        let decoded = &batch.columns[idx];
        fields.push(arrow_field(&col.name, col.kind, decoded)?);
    }
    Ok(ArrowSchema::new(fields))
}

pub(crate) fn schemas_equal(a: &ArrowSchema, b: &ArrowSchema) -> bool {
    if a.fields().len() != b.fields().len() {
        return false;
    }
    for (fa, fb) in a.fields().iter().zip(b.fields().iter()) {
        if fa.name() != fb.name() || fa.is_nullable() != fb.is_nullable() {
            return false;
        }
        let tentative_a = is_tentative_array(fa);
        let tentative_b = is_tentative_array(fb);
        if !tentative_a && !tentative_b && fa.data_type() != fb.data_type() {
            return false;
        }
        for key in [COLUMN_TYPE, GEOHASH_BITS, SYMBOL, ARROW_EXTENSION_NAME] {
            if fa.metadata().get(key) != fb.metadata().get(key) {
                return false;
            }
        }
        if !tentative_a
            && !tentative_b
            && fa.metadata().get(ARRAY_DIM) != fb.metadata().get(ARRAY_DIM)
        {
            return false;
        }
    }
    true
}

fn is_tentative_array(f: &Field) -> bool {
    f.metadata()
        .get(ARRAY_DIM_TENTATIVE)
        .is_some_and(|v| v == "true")
}

fn arrow_field(name: &str, kind: ColumnKind, decoded: &DecodedColumn) -> Result<Field> {
    let (dtype, mut md) = match (kind, decoded) {
        (ColumnKind::Boolean, _) => (DataType::Boolean, md_for(kind)),
        (ColumnKind::Byte, _) => (DataType::Int8, md_for(kind)),
        (ColumnKind::Short, _) => (DataType::Int16, md_for(kind)),
        (ColumnKind::Int, _) => (DataType::Int32, md_for(kind)),
        (ColumnKind::Long, _) => (DataType::Int64, md_for(kind)),
        (ColumnKind::Float, _) => (DataType::Float32, md_for(kind)),
        (ColumnKind::Double, _) => (DataType::Float64, md_for(kind)),
        (ColumnKind::Char, _) => (DataType::UInt16, md_for(kind)),
        (ColumnKind::Ipv4, _) => (DataType::UInt32, md_for(kind)),
        (ColumnKind::Timestamp, _) => (
            DataType::Timestamp(TimeUnit::Microsecond, Some(Arc::from("UTC"))),
            md_for(kind),
        ),
        (ColumnKind::TimestampNanos, _) => (
            DataType::Timestamp(TimeUnit::Nanosecond, Some(Arc::from("UTC"))),
            md_for(kind),
        ),
        (ColumnKind::Date, _) => (
            DataType::Timestamp(TimeUnit::Millisecond, Some(Arc::from("UTC"))),
            md_for(kind),
        ),
        (ColumnKind::Uuid, _) => {
            let mut m = md_for(kind);
            m.insert(ARROW_EXTENSION_NAME.into(), EXT_ARROW_UUID.into());
            (DataType::FixedSizeBinary(16), m)
        }
        (ColumnKind::Long256, _) => (DataType::FixedSizeBinary(32), md_for(kind)),
        (ColumnKind::Symbol, _) => {
            let mut m = md_for(kind);
            m.insert(SYMBOL.into(), "true".into());
            (
                DataType::Dictionary(Box::new(DataType::UInt32), Box::new(DataType::Utf8)),
                m,
            )
        }
        (ColumnKind::Varchar, DecodedColumn::Varchar { .. }) => (DataType::Utf8, md_for(kind)),
        (ColumnKind::Binary, DecodedColumn::Binary { .. }) => (DataType::Binary, md_for(kind)),
        (
            ColumnKind::Geohash,
            DecodedColumn::Geohash {
                buffer: _,
                byte_width: _,
                precision_bits,
            },
        ) => {
            let dtype = geohash_dtype_for_precision(*precision_bits).ok_or_else(|| {
                fmt!(
                    ProtocolError,
                    "geohash precision_bits {} not in 1..=60 for column '{}'",
                    precision_bits,
                    name
                )
            })?;
            let mut m = md_for(kind);
            m.insert(GEOHASH_BITS.into(), precision_bits.to_string());
            (dtype, m)
        }
        (ColumnKind::Decimal64, DecodedColumn::Decimal64 { scale, .. }) => {
            (DataType::Decimal64(18, *scale), md_for(kind))
        }
        (ColumnKind::Decimal128, DecodedColumn::Decimal128 { scale, .. }) => {
            (DataType::Decimal128(38, *scale), md_for(kind))
        }
        (ColumnKind::Decimal256, DecodedColumn::Decimal256 { scale, .. }) => {
            (DataType::Decimal256(76, *scale), md_for(kind))
        }
        (ColumnKind::DoubleArray, DecodedColumn::DoubleArray(buf)) => build_array_field(
            name,
            kind,
            DataType::Float64,
            &buf.shapes,
            &buf.shape_offsets,
        )?,
        (ColumnKind::LongArray, DecodedColumn::LongArray(buf)) => {
            build_array_field(name, kind, DataType::Int64, &buf.shapes, &buf.shape_offsets)?
        }
        (other, _) => {
            return Err(fmt!(
                ProtocolError,
                "arrow_field: column '{}' kind {:?} does not match decoded column variant",
                name,
                other
            ));
        }
    };
    md.insert(COLUMN_TYPE.into(), kind.name().into());
    Ok(Field::new(name, dtype, true).with_metadata(md))
}

fn md_for(_kind: ColumnKind) -> HashMap<String, String> {
    HashMap::new()
}

fn geohash_dtype_for_precision(precision_bits: u8) -> Option<DataType> {
    Some(match precision_bits {
        1..=7 => DataType::Int8,
        8..=15 => DataType::Int16,
        16..=31 => DataType::Int32,
        32..=60 => DataType::Int64,
        _ => return None,
    })
}

fn build_array_field(
    name: &str,
    kind: ColumnKind,
    leaf: DataType,
    shapes: &[u32],
    shape_offsets: &[u32],
) -> Result<(DataType, HashMap<String, String>)> {
    let (ndim, tentative) = match ndim_from_shapes(shapes, shape_offsets)? {
        Some(n) => (n, false),
        None => (1, true),
    };
    if ndim == 0 {
        return Err(fmt!(
            ProtocolError,
            "array column '{}' has ndim=0; QuestDB ARRAY is always at least 1-D",
            name
        ));
    }
    let mut dtype = leaf;
    for _ in 0..ndim {
        dtype = DataType::List(Arc::new(Field::new("item", dtype, true)));
    }
    let mut md = md_for(kind);
    md.insert(ARRAY_DIM.into(), ndim.to_string());
    if tentative {
        md.insert(ARRAY_DIM_TENTATIVE.into(), "true".into());
    }
    Ok((dtype, md))
}

fn ndim_from_shapes(shapes: &[u32], shape_offsets: &[u32]) -> Result<Option<usize>> {
    if shape_offsets.len() < 2 {
        return Ok(None);
    }
    for w in shape_offsets.windows(2) {
        let dims = w[1].checked_sub(w[0]).ok_or_else(|| {
            fmt!(
                ProtocolError,
                "shape_offsets not monotonic: {} < {}",
                w[1],
                w[0]
            )
        })? as usize;
        if dims > 0 {
            if w[1] as usize > shapes.len() {
                return Err(fmt!(
                    ProtocolError,
                    "shape_offsets points past shapes buffer (end={}, shapes.len()={})",
                    w[1],
                    shapes.len()
                ));
            }
            return Ok(Some(dims));
        }
    }
    Ok(None)
}

pub(crate) fn to_arrow_export(msg: impl Into<String>) -> Error {
    Error::new(ErrorCode::ArrowExport, msg.into())
}
