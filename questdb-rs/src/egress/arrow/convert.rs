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

//! `DecodedBatch` → `arrow_array::RecordBatch` conversion.

use std::collections::HashMap;
use std::sync::Arc;

use aligned_vec::{AVec, ConstAlign};
use arrow_array::{
    Array, ArrayRef, BinaryArray, BooleanArray, Decimal64Array, Decimal128Array, Decimal256Array,
    DictionaryArray, FixedSizeBinaryArray, Int8Array, Int16Array, Int32Array, Int64Array,
    ListArray, RecordBatch, StringArray, TimestampMicrosecondArray, TimestampMillisecondArray,
    TimestampNanosecondArray,
};
use arrow_buffer::{Buffer, NullBuffer};
use arrow_data::ArrayDataBuilder;
use arrow_schema::{ArrowError, DataType, Field, Schema as ArrowSchema, TimeUnit};
use bytes::Bytes;

use crate::egress::arrow::schema::to_arrow_export;
use crate::egress::column_kind::ColumnKind;
use crate::egress::decoder::{ArrayBuffers, ColumnBuffer, DecodedBatch, DecodedColumn};
use crate::egress::error::{Error, Result, fmt};
use crate::egress::schema::Schema;
use crate::egress::symbol_dict::SymbolDict;

type ABytes = AVec<u8, ConstAlign<64>>;

// `Bytes::from_owner` requires the owner to be `Send + Sync + 'static`.
// arrow-rs's RecordBatch can be dropped on any thread (Python consumers
// release on a worker pool), so the AVec we hand it must satisfy these
// bounds. A future aligned-vec release that adds a !Send field would
// silently break the FFI export path — this static check fails to
// compile if that happens.
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<ABytes>();
};

/// Working buffers reused across SYMBOL columns in one batch. Reuses the
/// remap HashMap allocation per `batch_to_record_batch` call so a wide
/// batch with N SYMBOL columns does not pay N independent `HashMap::new()`
/// costs. The hasher is `std::collections::hash_map::RandomState` —
/// changing to a u32-tuned hasher is a follow-up.
#[derive(Default)]
struct SymbolBuildScratch {
    remap: HashMap<u32, u32>,
}

pub(crate) fn batch_to_record_batch(
    schema_ref: Arc<ArrowSchema>,
    egress_schema: &Schema,
    batch: DecodedBatch,
    dict: &SymbolDict,
) -> Result<RecordBatch> {
    let DecodedBatch {
        row_count, columns, ..
    } = batch;
    if columns.len() != schema_ref.fields().len() {
        return Err(fmt!(
            ProtocolError,
            "schema/batch column count mismatch: schema={} batch={}",
            schema_ref.fields().len(),
            columns.len()
        ));
    }
    let mut arrays: Vec<ArrayRef> = Vec::with_capacity(columns.len());
    let mut sym_scratch = SymbolBuildScratch::default();
    for (idx, decoded) in columns.into_iter().enumerate() {
        let field = schema_ref.field(idx);
        let kind = egress_schema
            .column(idx)
            .map(|c| c.kind)
            .ok_or_else(|| fmt!(InvalidApiCall, "egress schema missing column {}", idx))?;
        arrays.push(column_to_array(
            field,
            kind,
            decoded,
            row_count,
            dict,
            &mut sym_scratch,
        )?);
    }
    RecordBatch::try_new(schema_ref, arrays).map_err(|e| to_arrow_export(e.to_string()))
}

fn column_to_array(
    field: &Field,
    kind: ColumnKind,
    decoded: DecodedColumn,
    row_count: usize,
    dict: &SymbolDict,
    sym_scratch: &mut SymbolBuildScratch,
) -> Result<ArrayRef> {
    Ok(match (kind, decoded) {
        (ColumnKind::Boolean, DecodedColumn::Boolean(buf)) => {
            boolean_array(buf, row_count).map(|a| Arc::new(a) as ArrayRef)?
        }
        (ColumnKind::Byte, DecodedColumn::Byte(buf)) => {
            primitive_array(buf, row_count, DataType::Int8)?
        }
        (ColumnKind::Short, DecodedColumn::Short(buf)) => {
            primitive_array(buf, row_count, DataType::Int16)?
        }
        (ColumnKind::Int, DecodedColumn::Int(buf)) => {
            primitive_array(buf, row_count, DataType::Int32)?
        }
        (ColumnKind::Long, DecodedColumn::Long(buf)) => {
            primitive_array(buf, row_count, DataType::Int64)?
        }
        (ColumnKind::Float, DecodedColumn::Float(buf)) => {
            primitive_array(buf, row_count, DataType::Float32)?
        }
        (ColumnKind::Double, DecodedColumn::Double(buf)) => {
            primitive_array(buf, row_count, DataType::Float64)?
        }
        (ColumnKind::Char, DecodedColumn::Char(buf)) => {
            primitive_array(buf, row_count, DataType::UInt16)?
        }
        (ColumnKind::Ipv4, DecodedColumn::Ipv4(buf)) => {
            primitive_array(buf, row_count, DataType::UInt32)?
        }
        (ColumnKind::Timestamp, DecodedColumn::Timestamp(buf)) => {
            timestamp_array(buf, row_count, TimeUnit::Microsecond)?
        }
        (ColumnKind::TimestampNanos, DecodedColumn::TimestampNanos(buf)) => {
            timestamp_array(buf, row_count, TimeUnit::Nanosecond)?
        }
        (ColumnKind::Date, DecodedColumn::Date(buf)) => {
            timestamp_array(buf, row_count, TimeUnit::Millisecond)?
        }
        (ColumnKind::Uuid, DecodedColumn::Uuid(buf)) => fixed_bytes_array(buf, row_count, 16)?,
        (ColumnKind::Long256, DecodedColumn::Long256(buf)) => {
            fixed_bytes_array(buf, row_count, 32)?
        }
        (ColumnKind::Decimal64, DecodedColumn::Decimal64 { buffer, scale }) => {
            decimal_array(buffer, row_count, DataType::Decimal64(18, scale))?
        }
        (ColumnKind::Decimal128, DecodedColumn::Decimal128 { buffer, scale }) => {
            decimal_array(buffer, row_count, DataType::Decimal128(38, scale))?
        }
        (ColumnKind::Decimal256, DecodedColumn::Decimal256 { buffer, scale }) => {
            decimal_array(buffer, row_count, DataType::Decimal256(76, scale))?
        }
        (
            ColumnKind::Varchar,
            DecodedColumn::Varchar {
                offsets,
                data,
                validity,
            },
        ) => varlen_string_array(field, offsets, data, validity, row_count)?,
        (
            ColumnKind::Binary,
            DecodedColumn::Binary {
                offsets,
                data,
                validity,
            },
        ) => varlen_binary_array(field, offsets, data, validity, row_count)?,
        (
            ColumnKind::Geohash,
            DecodedColumn::Geohash {
                buffer,
                byte_width,
                precision_bits,
            },
        ) => geohash_array(buffer, byte_width, precision_bits, row_count)?,
        (
            ColumnKind::Symbol,
            DecodedColumn::Symbol {
                codes,
                validity,
                local_dict,
            },
        ) => {
            let active = local_dict.as_ref().unwrap_or(dict);
            symbol_array(codes, validity, active, row_count, sym_scratch)?
        }
        (ColumnKind::DoubleArray, DecodedColumn::DoubleArray(b)) => {
            array_column_to_arrow(field, b, row_count, ArrayLeaf::Float64)?
        }
        (ColumnKind::LongArray, DecodedColumn::LongArray(b)) => {
            array_column_to_arrow(field, b, row_count, ArrayLeaf::Int64)?
        }
        (kind, decoded) => {
            return Err(fmt!(
                ProtocolError,
                "kind/decoded mismatch: kind={:?} variant={:?}",
                kind,
                decoded
            ));
        }
    })
}

fn primitive_array(buf: ColumnBuffer, row_count: usize, dtype: DataType) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&buf.validity, row_count)?;
    let values = buffer_to_arrow(&buf.values);
    let data = ArrayDataBuilder::new(dtype)
        .len(row_count)
        .add_buffer(values)
        .nulls(nulls)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(arrow_array::make_array(data))
}

fn decimal_array(buf: ColumnBuffer, row_count: usize, dtype: DataType) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&buf.validity, row_count)?;
    let values = buffer_to_arrow(&buf.values);
    let data = ArrayDataBuilder::new(dtype.clone())
        .len(row_count)
        .add_buffer(values)
        .nulls(nulls)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(match dtype {
        DataType::Decimal64(_, _) => Arc::new(Decimal64Array::from(data)) as ArrayRef,
        DataType::Decimal128(_, _) => Arc::new(Decimal128Array::from(data)) as ArrayRef,
        DataType::Decimal256(_, _) => Arc::new(Decimal256Array::from(data)) as ArrayRef,
        _ => unreachable!(),
    })
}

fn timestamp_array(buf: ColumnBuffer, row_count: usize, unit: TimeUnit) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&buf.validity, row_count)?;
    let values = buffer_to_arrow(&buf.values);
    let dtype = DataType::Timestamp(unit, Some(Arc::from("UTC")));
    let data = ArrayDataBuilder::new(dtype)
        .len(row_count)
        .add_buffer(values)
        .nulls(nulls)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    let arr: ArrayRef = match unit {
        TimeUnit::Microsecond => Arc::new(TimestampMicrosecondArray::from(data)),
        TimeUnit::Nanosecond => Arc::new(TimestampNanosecondArray::from(data)),
        TimeUnit::Millisecond => Arc::new(TimestampMillisecondArray::from(data)),
        other => {
            return Err(fmt!(
                ProtocolError,
                "unsupported timestamp TimeUnit on egress: {:?}",
                other
            ));
        }
    };
    Ok(arr)
}

fn fixed_bytes_array(buf: ColumnBuffer, row_count: usize, n: i32) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&buf.validity, row_count)?;
    let values = buffer_to_arrow(&buf.values);
    let data = ArrayDataBuilder::new(DataType::FixedSizeBinary(n))
        .len(row_count)
        .add_buffer(values)
        .nulls(nulls)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(Arc::new(FixedSizeBinaryArray::from(data)) as ArrayRef)
}

fn varlen_string_array(
    _field: &Field,
    offsets: Vec<u32>,
    data: Bytes,
    validity: Option<Bytes>,
    row_count: usize,
) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&validity, row_count)?;
    let off = offsets_i32(&offsets)?;
    let data = ArrayDataBuilder::new(DataType::Utf8)
        .len(row_count)
        .add_buffer(Buffer::from(bytes_from_avec(off)))
        .add_buffer(bytes_to_arrow(data))
        .nulls(nulls)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(Arc::new(StringArray::from(data)) as ArrayRef)
}

fn varlen_binary_array(
    _field: &Field,
    offsets: Vec<u32>,
    data: Bytes,
    validity: Option<Bytes>,
    row_count: usize,
) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&validity, row_count)?;
    let off = offsets_i32(&offsets)?;
    let data = ArrayDataBuilder::new(DataType::Binary)
        .len(row_count)
        .add_buffer(Buffer::from(bytes_from_avec(off)))
        .add_buffer(bytes_to_arrow(data))
        .nulls(nulls)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(Arc::new(BinaryArray::from(data)) as ArrayRef)
}

fn boolean_array(buf: ColumnBuffer, row_count: usize) -> Result<BooleanArray> {
    let nulls = bytes_null_buffer(&buf.validity, row_count)?;
    if buf.values.len() < row_count {
        return Err(fmt!(
            ProtocolError,
            "boolean wire payload truncated: have {} bytes, need {}",
            buf.values.len(),
            row_count
        ));
    }
    let mut packed = ABytes::with_capacity(64, row_count.div_ceil(8));
    packed.resize(row_count.div_ceil(8), 0);
    for (i, &b) in buf.values.iter().take(row_count).enumerate() {
        if b != 0 {
            packed[i >> 3] |= 1u8 << (i & 7);
        }
    }
    let buf = Buffer::from(bytes_from_avec(packed));
    let data = ArrayDataBuilder::new(DataType::Boolean)
        .len(row_count)
        .add_buffer(buf)
        .nulls(nulls)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(BooleanArray::from(data))
}

fn geohash_array(
    buf: ColumnBuffer,
    byte_width: u8,
    precision_bits: u8,
    row_count: usize,
) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&buf.validity, row_count)?;
    let (dtype, target_width) = match precision_bits {
        1..=7 => (DataType::Int8, 1usize),
        8..=15 => (DataType::Int16, 2),
        16..=31 => (DataType::Int32, 4),
        32..=60 => (DataType::Int64, 8),
        other => {
            return Err(fmt!(
                ProtocolError,
                "geohash precision_bits {} not in 1..=60",
                other
            ));
        }
    };
    let bw = byte_width as usize;
    let required = row_count
        .checked_mul(bw)
        .ok_or_else(|| fmt!(ProtocolError, "geohash payload size overflows usize"))?;
    if buf.values.len() < required {
        return Err(fmt!(
            ProtocolError,
            "geohash wire payload truncated: have {} bytes, need row_count={} * byte_width={} = {}",
            buf.values.len(),
            row_count,
            bw,
            required
        ));
    }
    let values_buf = if bw == target_width {
        buffer_to_arrow(&buf.values)
    } else if bw < target_width {
        widen_zero_extend(&buf.values, bw, target_width, row_count)
    } else {
        return Err(fmt!(
            ProtocolError,
            "geohash wire byte_width {} exceeds Arrow target width {} for precision_bits {}",
            byte_width,
            target_width,
            precision_bits
        ));
    };
    let data = ArrayDataBuilder::new(dtype.clone())
        .len(row_count)
        .add_buffer(values_buf)
        .nulls(nulls)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(match dtype {
        DataType::Int8 => Arc::new(Int8Array::from(data)) as ArrayRef,
        DataType::Int16 => Arc::new(Int16Array::from(data)) as ArrayRef,
        DataType::Int32 => Arc::new(Int32Array::from(data)) as ArrayRef,
        DataType::Int64 => Arc::new(Int64Array::from(data)) as ArrayRef,
        _ => unreachable!(),
    })
}

fn widen_zero_extend(src: &Bytes, src_width: usize, dst_width: usize, row_count: usize) -> Buffer {
    let mut out = ABytes::with_capacity(64, row_count * dst_width);
    out.resize(row_count * dst_width, 0);
    for r in 0..row_count {
        let s = r * src_width;
        let d = r * dst_width;
        out[d..d + src_width].copy_from_slice(&src[s..s + src_width]);
    }
    Buffer::from(bytes_from_avec(out))
}

fn symbol_array(
    codes: Vec<u32>,
    validity: Option<Bytes>,
    dict: &SymbolDict,
    row_count: usize,
    scratch: &mut SymbolBuildScratch,
) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&validity, row_count)?;
    scratch.remap.clear();
    if scratch.remap.capacity() < codes.len().min(64) {
        scratch
            .remap
            .reserve(codes.len().min(64) - scratch.remap.capacity());
    }
    let remap = &mut scratch.remap;
    let mut union_offsets: Vec<i32> = Vec::with_capacity(codes.len().min(64) + 1);
    union_offsets.push(0);
    let mut union_bytes: ABytes = ABytes::new(64);
    let mut dense = ABytes::with_capacity(64, codes.len() * 4);
    dense.resize(codes.len() * 4, 0);

    fn resolve(
        code: u32,
        remap: &mut HashMap<u32, u32>,
        union_offsets: &mut Vec<i32>,
        union_bytes: &mut ABytes,
        dict: &SymbolDict,
    ) -> Result<u32> {
        if let Some(&dense_code) = remap.get(&code) {
            return Ok(dense_code);
        }
        let s = dict
            .get(code)
            .ok_or_else(|| fmt!(ProtocolError, "symbol code {} not in dict", code))?;
        union_bytes.extend_from_slice(s.as_bytes());
        let next_off = union_bytes.len() as i32;
        union_offsets.push(next_off);
        let assigned = (union_offsets.len() - 2) as u32;
        remap.insert(code, assigned);
        Ok(assigned)
    }

    match nulls.as_ref() {
        None => {
            for (row, &code) in codes.iter().enumerate() {
                let dense_code = resolve(
                    code,
                    &mut *remap,
                    &mut union_offsets,
                    &mut union_bytes,
                    dict,
                )?;
                let base = row * 4;
                dense[base..base + 4].copy_from_slice(&dense_code.to_le_bytes());
            }
        }
        Some(n) => {
            for row in n.valid_indices() {
                let code = codes[row];
                let dense_code = resolve(
                    code,
                    &mut *remap,
                    &mut union_offsets,
                    &mut union_bytes,
                    dict,
                )?;
                let base = row * 4;
                dense[base..base + 4].copy_from_slice(&dense_code.to_le_bytes());
            }
        }
    }

    let mut union_offsets_avec = ABytes::with_capacity(64, union_offsets.len() * 4);
    for off in &union_offsets {
        union_offsets_avec.extend_from_slice(&off.to_le_bytes());
    }
    let values_data = ArrayDataBuilder::new(DataType::Utf8)
        .len(union_offsets.len() - 1)
        .add_buffer(Buffer::from(bytes_from_avec(union_offsets_avec)))
        .add_buffer(Buffer::from(bytes_from_avec(union_bytes)))
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    let values = arrow_array::StringArray::from(values_data);
    let keys_buf = Buffer::from(bytes_from_avec(dense));
    let dict_data = ArrayDataBuilder::new(DataType::Dictionary(
        Box::new(DataType::UInt32),
        Box::new(DataType::Utf8),
    ))
    .len(row_count)
    .add_buffer(keys_buf)
    .add_child_data(values.into_data())
    .nulls(nulls)
    .build()
    .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(
        Arc::new(DictionaryArray::<arrow_array::types::UInt32Type>::from(
            dict_data,
        )) as ArrayRef,
    )
}

#[derive(Clone, Copy)]
enum ArrayLeaf {
    Float64,
    Int64,
}

fn array_column_to_arrow(
    field: &Field,
    b: ArrayBuffers,
    row_count: usize,
    leaf: ArrayLeaf,
) -> Result<ArrayRef> {
    let ArrayBuffers {
        data_offsets,
        data,
        shapes,
        shape_offsets,
        validity,
    } = b;
    let nulls = bytes_null_buffer(&validity, row_count)?;
    let leaf_dtype = match leaf {
        ArrayLeaf::Float64 => DataType::Float64,
        ArrayLeaf::Int64 => DataType::Int64,
    };
    let elem_size = 8usize;
    if !data.len().is_multiple_of(elem_size) {
        return Err(to_arrow_export(format!(
            "ARRAY wire data length {} not a multiple of element size {}",
            data.len(),
            elem_size
        )));
    }
    let total_elements = data.len() / elem_size;
    if let Some(&last_off) = data_offsets.last()
        && last_off as usize != data.len()
    {
        return Err(to_arrow_export(format!(
            "ARRAY data_offsets tail {} disagrees with data length {}",
            last_off,
            data.len()
        )));
    }
    let ndim = ndim_from_field(field)?;
    let leaf_buf = bytes_to_arrow(data);
    let leaf_data = ArrayDataBuilder::new(leaf_dtype)
        .len(total_elements)
        .add_buffer(leaf_buf)
        .align_buffers(true)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    let leaf_array: ArrayRef = match leaf {
        ArrayLeaf::Float64 => Arc::new(arrow_array::Float64Array::from(leaf_data)),
        ArrayLeaf::Int64 => Arc::new(arrow_array::Int64Array::from(leaf_data)),
    };
    let per_level_counts = compute_per_level_counts(&shapes, &shape_offsets, ndim, row_count)?;
    nest_lists(field, leaf_array, per_level_counts, nulls, ndim)
}

fn ndim_from_field(field: &Field) -> Result<usize> {
    fn depth(dt: &DataType, acc: usize) -> usize {
        match dt {
            DataType::List(inner) | DataType::LargeList(inner) => depth(inner.data_type(), acc + 1),
            _ => acc,
        }
    }
    let d = depth(field.data_type(), 0);
    if d == 0 {
        return Err(fmt!(
            InvalidApiCall,
            "expected nested list field, got {:?}",
            field.data_type()
        ));
    }
    Ok(d)
}

fn compute_per_level_counts(
    shapes: &[u32],
    shape_offsets: &[u32],
    ndim: usize,
    row_count: usize,
) -> Result<Vec<Vec<u32>>> {
    let mut levels: Vec<Vec<u32>> = vec![Vec::new(); ndim];
    for row in 0..row_count {
        let lo = *shape_offsets
            .get(row)
            .ok_or_else(|| fmt!(ProtocolError, "shape_offsets missing row {}", row))?
            as usize;
        let hi = *shape_offsets.get(row + 1).ok_or_else(|| {
            fmt!(
                ProtocolError,
                "shape_offsets missing row {} terminator",
                row
            )
        })? as usize;
        if hi < lo || hi > shapes.len() {
            return Err(fmt!(
                ProtocolError,
                "row {} shape range [{}, {}) out of shapes len {}",
                row,
                lo,
                hi,
                shapes.len()
            ));
        }
        let span = hi - lo;
        if span == 0 {
            for level in &mut levels {
                level.push(0);
            }
            continue;
        }
        if span != ndim {
            return Err(fmt!(
                ProtocolError,
                "row {} has shape len {} expected ndim {}",
                row,
                span,
                ndim
            ));
        }
        let row_shape = &shapes[lo..hi];
        let mut group_count: u32 = 1;
        for (level, &dim) in row_shape.iter().enumerate() {
            if level == 0 {
                levels[0].push(dim);
            } else {
                for _ in 0..group_count {
                    levels[level].push(dim);
                }
            }
            group_count = group_count.checked_mul(dim).ok_or_else(|| {
                fmt!(
                    ProtocolError,
                    "row {} shape product overflows u32 at level {}",
                    row,
                    level
                )
            })?;
        }
    }
    Ok(levels)
}

fn nest_lists(
    field: &Field,
    leaf: ArrayRef,
    per_level_counts: Vec<Vec<u32>>,
    outer_nulls: Option<NullBuffer>,
    ndim: usize,
) -> Result<ArrayRef> {
    let mut current = leaf;
    let mut current_dtype = leaf_dtype_at_depth(field.data_type(), ndim);
    for level in (1..ndim).rev() {
        let counts = &per_level_counts[level];
        let offsets = counts_to_offsets_i32(counts)?;
        let next_field = Arc::new(Field::new("item", current_dtype, true));
        let dtype = DataType::List(next_field);
        let data = ArrayDataBuilder::new(dtype.clone())
            .len(counts.len())
            .add_buffer(Buffer::from(bytes_from_avec(offsets)))
            .add_child_data(current.to_data())
            .build()
            .map_err(|e| to_arrow_export(e.to_string()))?;
        current = Arc::new(ListArray::from(data)) as ArrayRef;
        current_dtype = dtype;
    }
    let counts0 = &per_level_counts[0];
    let outer_offsets = counts_to_offsets_i32(counts0)?;
    let outer_field = Arc::new(Field::new("item", current_dtype, true));
    let outer_dtype = DataType::List(outer_field);
    let data = ArrayDataBuilder::new(outer_dtype)
        .len(counts0.len())
        .add_buffer(Buffer::from(bytes_from_avec(outer_offsets)))
        .add_child_data(current.to_data())
        .nulls(outer_nulls)
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(Arc::new(ListArray::from(data)) as ArrayRef)
}

fn leaf_dtype_at_depth(dt: &DataType, depth: usize) -> DataType {
    if depth == 0 {
        return dt.clone();
    }
    match dt {
        DataType::List(inner) | DataType::LargeList(inner) => {
            leaf_dtype_at_depth(inner.data_type(), depth - 1)
        }
        _ => dt.clone(),
    }
}

/// Returns Err on overflow. Per the server-side per-batch wire cap
/// (`MAX_BATCH_WIRE_BYTES = MAX_ZSTD_DECOMPRESSED = 64 MiB`) and
/// `MAX_ARRAY_ELEMENTS_PER_ROW = 16M`, the cumulative element count for
/// any List level in a single batch is bounded by ~8M, far below
/// i32::MAX. The error path is defensive.
fn counts_to_offsets_i32(counts: &[u32]) -> Result<ABytes> {
    let mut out = ABytes::with_capacity(64, (counts.len() + 1) * 4);
    let mut running: i32 = 0;
    out.extend_from_slice(&running.to_le_bytes());
    for &c in counts {
        running = running
            .checked_add(c as i32)
            .ok_or_else(|| fmt!(ProtocolError, "List offset overflows i32"))?;
        out.extend_from_slice(&running.to_le_bytes());
    }
    Ok(out)
}

fn offsets_i32(offsets: &[u32]) -> Result<ABytes> {
    let mut out = ABytes::with_capacity(64, offsets.len() * 4);
    for &o in offsets {
        if o > i32::MAX as u32 {
            return Err(fmt!(ProtocolError, "varlen offset {} exceeds i32::MAX", o));
        }
        out.extend_from_slice(&(o as i32).to_le_bytes());
    }
    Ok(out)
}

fn buffer_to_arrow(b: &Bytes) -> Buffer {
    Buffer::from(b.clone())
}

fn bytes_to_arrow(b: Bytes) -> Buffer {
    Buffer::from(b)
}

fn bytes_from_avec(v: ABytes) -> Bytes {
    Bytes::from_owner(v)
}

fn bytes_null_buffer(validity: &Option<Bytes>, row_count: usize) -> Result<Option<NullBuffer>> {
    let bytes = match validity {
        None => return Ok(None),
        Some(b) => b,
    };
    let needed = row_count.div_ceil(8);
    if bytes.len() < needed {
        return Err(fmt!(
            ProtocolError,
            "validity bitmap is {} bytes but row_count={} needs at least {}",
            bytes.len(),
            row_count,
            needed
        ));
    }
    let mut inverted = ABytes::with_capacity(64, needed);
    inverted.extend_from_slice(&bytes[..needed]);
    for b in inverted.iter_mut() {
        *b = !*b;
    }
    // Mask post-inversion trailing bits — pads were 0, would flip to 1
    // (=valid) and pollute downstream raw-bitmap hashers/copiers.
    let trailing_bits = row_count % 8;
    if trailing_bits != 0
        && let Some(last) = inverted.last_mut()
    {
        *last &= (1u8 << trailing_bits) - 1;
    }
    Ok(Some(NullBuffer::new(arrow_buffer::BooleanBuffer::new(
        Buffer::from(bytes_from_avec(inverted)),
        0,
        row_count,
    ))))
}

/// Boxes a QuestDB [`Error`] as an [`ArrowError::ExternalError`].
/// Recover via [`try_downcast_questdb`](super::reader::try_downcast_questdb).
pub fn external_arrow_error(e: Error) -> ArrowError {
    ArrowError::ExternalError(Box::new(e))
}
