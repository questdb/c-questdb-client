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

/// Per-cursor cache of the connection dict's `Utf8` values array, keyed on dict
/// length: the dict is append-only and shared by every delta-mode SYMBOL column,
/// so the array is interned once and reused (cheap `Arc` clone) until it grows.
#[derive(Default)]
pub(crate) struct SymbolValuesCache {
    len: usize,
    values: Option<StringArray>,
}

pub(crate) fn batch_to_record_batch(
    schema_ref: Arc<ArrowSchema>,
    egress_schema: &Schema,
    batch: DecodedBatch,
    dict: &SymbolDict,
) -> Result<RecordBatch> {
    let mut sym_values = SymbolValuesCache::default();
    batch_to_record_batch_with(schema_ref, egress_schema, batch, dict, &mut sym_values)
}

/// As [`batch_to_record_batch`] but reuses a caller-owned [`SymbolValuesCache`]
/// so a streaming cursor interns the connection dict once across batches.
pub(crate) fn batch_to_record_batch_with(
    schema_ref: Arc<ArrowSchema>,
    egress_schema: &Schema,
    batch: DecodedBatch,
    dict: &SymbolDict,
    sym_values: &mut SymbolValuesCache,
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
    // Single degenerate-list slack pool shared by every array column in this
    // batch. Threading one budget (rather than re-granting it per column) stops
    // a wide batch of `[huge, 0]` columns from multiplying offset-buffer
    // allocation by the column count: total degenerate expansion per batch is
    // capped at ~64 MiB regardless of how many array columns the batch carries.
    let mut degenerate_node_slack = MAX_DEGENERATE_LIST_NODES;
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
            sym_values,
            &mut degenerate_node_slack,
        )?);
    }
    RecordBatch::try_new(schema_ref, arrays)
        .map_err(|e| fmt!(ProtocolError, "failed to assemble record batch: {}", e))
}

fn column_to_array(
    field: &Field,
    kind: ColumnKind,
    decoded: DecodedColumn,
    row_count: usize,
    dict: &SymbolDict,
    sym_values: &mut SymbolValuesCache,
    degenerate_node_slack: &mut usize,
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
            // Delta columns share the connection dict → one cached values array.
            // A column-local dict is per-batch, so it builds fresh (uncached).
            match local_dict.as_ref() {
                None => symbol_array(codes, validity, dict, row_count, Some(sym_values))?,
                Some(local) => symbol_array(codes, validity, local, row_count, None)?,
            }
        }
        (ColumnKind::DoubleArray, DecodedColumn::DoubleArray(b)) => array_column_to_arrow(
            field,
            b,
            row_count,
            ArrayLeaf::Float64,
            degenerate_node_slack,
        )?,
        (ColumnKind::LongArray, DecodedColumn::LongArray(b)) => {
            array_column_to_arrow(field, b, row_count, ArrayLeaf::Int64, degenerate_node_slack)?
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
    let off = offsets_to_arrow_buffer(offsets)?;
    // `decode_varlen` (utf8 = true) already validated the data buffer as UTF-8
    // with every offset on a codepoint boundary, so Arrow's `build()` would
    // re-run an O(data) UTF-8 scan for nothing — skip it with `build_unchecked`.
    // `align_buffers(true)` is still honored (it is independent of validation).
    //
    // SAFETY: per `decoder::decode_varlen`, the offsets are monotonic, start at
    // 0, end at `data.len()`, and every offset lies on a UTF-8 codepoint
    // boundary; `bytes_null_buffer` yields a `row_count`-bit null buffer and the
    // offset buffer has `row_count + 1` entries — exactly the `Utf8` layout.
    let data = unsafe {
        ArrayDataBuilder::new(DataType::Utf8)
            .len(row_count)
            .add_buffer(off)
            .add_buffer(bytes_to_arrow(data))
            .nulls(nulls)
            .align_buffers(true)
            .build_unchecked()
    };
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
    let off = offsets_to_arrow_buffer(offsets)?;
    let data = ArrayDataBuilder::new(DataType::Binary)
        .len(row_count)
        .add_buffer(off)
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
        .align_buffers(true)
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
        widen_zero_extend(&buf.values, bw, target_width, row_count)?
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

fn widen_zero_extend(
    src: &Bytes,
    src_width: usize,
    dst_width: usize,
    row_count: usize,
) -> Result<Buffer> {
    let dst_len = row_count.checked_mul(dst_width).ok_or_else(|| {
        fmt!(
            ProtocolError,
            "widen_zero_extend output size overflows usize"
        )
    })?;
    let mut out = ABytes::with_capacity(64, dst_len);
    out.resize(dst_len, 0);
    for r in 0..row_count {
        let s = r * src_width;
        let d = r * dst_width;
        out[d..d + src_width].copy_from_slice(&src[s..s + src_width]);
    }
    Ok(Buffer::from(bytes_from_avec(out)))
}

/// Build a SYMBOL column as `Dictionary(UInt32, Utf8)` by adopting the
/// decoder's global codes directly as the Arrow keys and the full active dict
/// as the values — no per-row remap. `decode_symbol` bounds-checks every
/// non-null code against the active dict size (`= dict.len()`) and leaves null
/// rows at code `0`, so each key is a valid index into `values` and the null
/// buffer masks the null rows. With `cache`, the values array is reused across
/// columns/batches and only rebuilt when the dict grows.
fn symbol_array(
    codes: Vec<u32>,
    validity: Option<Bytes>,
    dict: &SymbolDict,
    row_count: usize,
    cache: Option<&mut SymbolValuesCache>,
) -> Result<ArrayRef> {
    let nulls = bytes_null_buffer(&validity, row_count)?;
    let values = match cache {
        Some(c) if c.len == dict.len() && c.values.is_some() => c.values.clone().unwrap(),
        Some(c) => {
            let v = symbol_dict_values(dict)?;
            c.len = dict.len();
            c.values = Some(v.clone());
            v
        }
        None => symbol_dict_values(dict)?,
    };
    // `codes` already holds one `u32` global code per row; adopt its allocation
    // as the key buffer with no copy.
    let keys_buf = Buffer::from_vec(codes);
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

/// The active dict's strings as a `Utf8` array, one entry per code. The dict's
/// arena is the entries' UTF-8 bytes back-to-back, so its offsets are the
/// entry offsets plus the arena length as the final terminator.
fn symbol_dict_values(dict: &SymbolDict) -> Result<StringArray> {
    let entries = dict.entries();
    let arena = dict.arena();
    let mut offsets: Vec<i32> = Vec::with_capacity(entries.len() + 1);
    for e in entries {
        offsets.push(i32::try_from(e.offset).map_err(|_| {
            fmt!(
                ProtocolError,
                "symbol dict offset {} exceeds i32::MAX",
                e.offset
            )
        })?);
    }
    offsets.push(i32::try_from(arena.len()).map_err(|_| {
        fmt!(
            ProtocolError,
            "symbol dict heap is {} bytes, exceeds i32::MAX",
            arena.len()
        )
    })?);
    let values_data = ArrayDataBuilder::new(DataType::Utf8)
        .len(entries.len())
        .add_buffer(Buffer::from_vec(offsets))
        .add_buffer(Buffer::from(arena.to_vec()))
        .build()
        .map_err(|e| to_arrow_export(e.to_string()))?;
    Ok(StringArray::from(values_data))
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
    degenerate_node_slack: &mut usize,
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
        return Err(fmt!(
            ProtocolError,
            "ARRAY wire data length {} not a multiple of element size {}",
            data.len(),
            elem_size
        ));
    }
    let total_elements = data.len() / elem_size;
    if let Some(&last_off) = data_offsets.last()
        && last_off as usize != data.len()
    {
        return Err(fmt!(
            ProtocolError,
            "ARRAY data_offsets tail {} disagrees with data length {}",
            last_off,
            data.len()
        ));
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
    let per_level_counts = compute_per_level_counts(
        &shapes,
        &shape_offsets,
        ndim,
        row_count,
        total_elements,
        degenerate_node_slack,
    )?;
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

/// Initial value of the per-batch list-node *slack* pool, so genuinely empty
/// shapes (`[3, 0]`) decode. This is not re-granted per column: a single budget
/// seeded with this value is shared across every array column in a batch (see
/// `batch_to_record_batch`), so a wide batch of degenerate `[huge, 0]` columns
/// expands to at most ~64 MiB of offset buffers *in total*, not ~64 MiB *per
/// column*. The bound is per batch, not stream-global: a consumer that retains
/// every decoded batch still accumulates memory, which is inherent to holding
/// unbounded batches and is bounded per batch by the transport's
/// `MAX_BATCH_WIRE_BYTES` cap.
const MAX_DEGENERATE_LIST_NODES: usize = 16 * 1024 * 1024;

fn compute_per_level_counts(
    shapes: &[u32],
    shape_offsets: &[u32],
    ndim: usize,
    row_count: usize,
    leaf_elements: usize,
    degenerate_node_slack: &mut usize,
) -> Result<Vec<Vec<u32>>> {
    // Cap total list-node expansion: a degenerate `[huge, 0]` shape carries a
    // tiny payload yet asks for billions of empty inner lists. Valid dense
    // data needs at most `ndim * leaf + row_count` nodes and is always granted
    // per column; the *slack* covers genuine empty shapes like `[3, 0]` and is
    // drawn from `degenerate_node_slack`, a single pool shared across every
    // column in the batch, so the column count cannot multiply the degenerate
    // bound.
    let legit_nodes = leaf_elements.saturating_mul(ndim).saturating_add(row_count);
    let mut node_budget = legit_nodes.saturating_add(*degenerate_node_slack);
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
            // A null / empty outer row is one empty list at level 0 and
            // contributes zero parent elements, hence zero entries at every
            // inner level. Pushing to inner levels would shift their offsets
            // and silently misalign every following non-null row.
            node_budget = node_budget
                .checked_sub(1)
                .ok_or_else(|| array_expansion_exceeded(row))?;
            levels[0].push(0);
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
            let push_count = if level == 0 { 1 } else { group_count as usize };
            node_budget = node_budget
                .checked_sub(push_count)
                .ok_or_else(|| array_expansion_exceeded(row))?;
            for _ in 0..push_count {
                levels[level].push(dim);
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
    // Debit the shared pool by the slack this column actually spent. Expansion
    // beyond the legitimate, payload-backed allowance comes out of the slack, so
    // the remainder `node_budget` is exactly the slack left when this column dug
    // into it; when it did not, `node_budget >= *degenerate_node_slack` and the
    // pool is unchanged. `min` captures both cases.
    *degenerate_node_slack = (*degenerate_node_slack).min(node_budget);
    Ok(levels)
}

fn array_expansion_exceeded(row: usize) -> Error {
    fmt!(
        ProtocolError,
        "array row {} list expansion exceeds the per-batch element budget",
        row
    )
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
        let c = i32::try_from(c)
            .map_err(|_| fmt!(ProtocolError, "List child count {} exceeds i32::MAX", c))?;
        running = running
            .checked_add(c)
            .ok_or_else(|| fmt!(ProtocolError, "List offset overflows i32"))?;
        out.extend_from_slice(&running.to_le_bytes());
    }
    Ok(out)
}

/// Adopt the decoder's `u32` varlen offsets as Arrow's `i32` offset buffer
/// with no copy. Offsets are monotonic, so checking `last` bounds the slice.
fn offsets_to_arrow_buffer(offsets: Vec<u32>) -> Result<Buffer> {
    if let Some(&last) = offsets.last()
        && last > i32::MAX as u32
    {
        return Err(fmt!(
            ProtocolError,
            "varlen offset {} exceeds i32::MAX",
            last
        ));
    }
    let mut offsets = std::mem::ManuallyDrop::new(offsets);
    let ptr = offsets.as_mut_ptr() as *mut i32;
    let len = offsets.len();
    let cap = offsets.capacity();
    // SAFETY: `u32`/`i32` share layout and every value is `<= i32::MAX`
    // (checked); `offsets` is leaked so the allocation has a single owner.
    let offsets_i32 = unsafe { Vec::from_raw_parts(ptr, len, cap) };
    Ok(Buffer::from_vec(offsets_i32))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;

    #[test]
    fn per_level_counts_rejects_degenerate_expansion() {
        let shapes = [1u32 << 24, 0, 1u32 << 24, 0];
        let shape_offsets = [0u32, 2, 4];
        let mut slack = MAX_DEGENERATE_LIST_NODES;
        let err =
            compute_per_level_counts(&shapes, &shape_offsets, 2, 2, 0, &mut slack).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn per_level_counts_slack_is_shared_across_columns() {
        // Two array columns in one batch, each a single degenerate `[16M, 0]`
        // row, sharing one slack pool. The first column drains the pool; the
        // second is then rejected. This caps per-batch degenerate expansion at
        // ~64 MiB no matter how many such columns the batch carries (the old
        // per-column reset allowed ~64 MiB * column_count).
        let shapes = [1u32 << 24, 0];
        let shape_offsets = [0u32, 2];
        let mut slack = MAX_DEGENERATE_LIST_NODES;

        let counts =
            compute_per_level_counts(&shapes, &shape_offsets, 2, 1, 0, &mut slack).unwrap();
        assert_eq!(counts[0], vec![1u32 << 24]);
        assert_eq!(slack, 0, "first degenerate column should drain the pool");

        let err =
            compute_per_level_counts(&shapes, &shape_offsets, 2, 1, 0, &mut slack).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn per_level_counts_accepts_genuine_empty_shape() {
        let shapes = [3u32, 0];
        let shape_offsets = [0u32, 2];
        let mut slack = MAX_DEGENERATE_LIST_NODES;
        let counts =
            compute_per_level_counts(&shapes, &shape_offsets, 2, 1, 0, &mut slack).unwrap();
        assert_eq!(counts[0], vec![3]);
        assert_eq!(counts[1], vec![0, 0, 0]);
    }

    #[test]
    fn per_level_counts_accepts_dense_shape() {
        let shapes = [2u32, 3];
        let shape_offsets = [0u32, 2];
        let mut slack = MAX_DEGENERATE_LIST_NODES;
        let counts =
            compute_per_level_counts(&shapes, &shape_offsets, 2, 1, 6, &mut slack).unwrap();
        assert_eq!(counts[0], vec![2]);
        assert_eq!(counts[1], vec![3, 3]);
    }

    #[test]
    fn per_level_counts_dense_does_not_drain_slack() {
        // Legitimate, payload-backed dense data is granted per column and must
        // not consume the shared degenerate pool, so it never starves sibling
        // columns in the same batch.
        let shapes = [2u32, 3];
        let shape_offsets = [0u32, 2];
        let mut slack = MAX_DEGENERATE_LIST_NODES;
        let _ = compute_per_level_counts(&shapes, &shape_offsets, 2, 1, 6, &mut slack).unwrap();
        assert_eq!(slack, MAX_DEGENERATE_LIST_NODES);
    }
}
