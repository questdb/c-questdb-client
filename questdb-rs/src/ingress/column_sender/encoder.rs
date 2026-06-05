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

//! Column-sender QWP/WebSocket frame encoder.
//!
//! Writes the QWP frame body for a `Chunk` directly into the connection's
//! reusable outbound buffer — no allocation per flush, no per-column
//! aggregation copy. The no-null hot path for fixed-width columns is a
//! single `extend_from_slice` (memcpy) straight from the caller's buffer.
//!
//! See `doc/COLUMN_SENDER_PLAN.md` for the design rationale.

use std::collections::HashMap;
use std::slice;

use crate::ingress::buffer::SymbolGlobalDict;
use crate::{Result, error};

#[cfg(feature = "arrow")]
use super::arrow_batch;
use super::chunk::{
    Chunk, ColumnDescriptor, ColumnKind, DesignatedTsDescriptor, SymbolCodesPtr, ValidityDescriptor,
};
use super::numpy_wire;
use super::wire::{
    F32_NULL, F64_NULL, I8_NULL, I16_NULL, I32_NULL, I64_NULL, MAX_NAME_LEN, QWP_FLAG_DEFER_COMMIT,
    QWP_FLAG_DELTA_SYMBOL_DICT, QWP_HEADER_LEN, QWP_MAGIC, QWP_SCHEMA_MODE_FULL,
    QWP_SCHEMA_MODE_REFERENCE, QWP_VERSION_1, validate_name, write_qwp_bytes, write_qwp_varint,
};

/// Connection-scoped table-schema interner.
///
/// Each unique signature gets a sequentially-assigned `u64` id. The first
/// emit uses `QWP_SCHEMA_MODE_FULL`; subsequent emits reuse the id under
/// `QWP_SCHEMA_MODE_REFERENCE`. Both sides of the wire build the same id
/// mapping by first-emit order; on reconnect both sides reset.
#[derive(Debug, Default)]
pub(crate) struct SchemaRegistry {
    by_signature: HashMap<Vec<u8>, u64>,
    next_id: u64,
}

impl SchemaRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(super) fn intern(&mut self, signature: &[u8]) -> (u64, bool) {
        if let Some(&id) = self.by_signature.get(signature) {
            return (id, false);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.by_signature.insert(signature.to_vec(), id);
        (id, true)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_signature.len()
    }
}

/// Per-sender reusable scratch state for one flush. The contained `Vec`s
/// are cleared (not reallocated) between flushes so a long-lived
/// connection pays at most one allocation per growth point per Vec.
#[derive(Default)]
pub(crate) struct EncodeScratch {
    pub(crate) signature: Vec<u8>,
    pub(crate) new_symbols: Vec<Vec<u8>>,
    pub(crate) per_column: Vec<Option<ResolvedColumn>>,
}

impl EncodeScratch {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn reset(&mut self) {
        self.signature.clear();
        self.new_symbols.clear();
        self.per_column.clear();
    }
}

/// Encode `chunk` into `out` as a complete QWP/WebSocket frame body. The
/// caller has already reserved any prefix bytes it needs in `out` (the
/// connection layer reserves the WS header); the encoder appends QWP
/// bytes only.
pub(crate) fn encode_chunk_into(
    out: &mut Vec<u8>,
    chunk: &Chunk<'_>,
    schema_registry: &mut SchemaRegistry,
    symbol_dict: &mut SymbolGlobalDict,
    scratch: &mut EncodeScratch,
    defer_commit: bool,
) -> Result<()> {
    scratch.reset();
    if chunk.is_empty() {
        emit_header_only_frame(out, defer_commit);
        return Ok(());
    }
    if chunk.designated_ts.is_none() {
        return Err(error::fmt!(
            InvalidApiCall,
            "Chunk has no designated timestamp; \
             call designated_timestamp_micros or designated_timestamp_nanos before flush."
        ));
    }
    let row_count = chunk.row_count();
    if row_count == 0 {
        return Err(error::fmt!(
            InvalidApiCall,
            "Chunk row_count is 0; flush at least one row or hand back an empty chunk."
        ));
    }
    validate_name("table", &chunk.table)?;

    let table_bytes = chunk.table.as_bytes();
    if table_bytes.len() > MAX_NAME_LEN {
        return Err(error::fmt!(
            InvalidName,
            "table name is too long: {} bytes (max {})",
            table_bytes.len(),
            MAX_NAME_LEN
        ));
    }

    let designated = chunk
        .designated_ts
        .as_ref()
        .expect("guarded by is_none() check above");

    // --- Pass 1: resolve symbol columns against the connection-scoped
    // global dict. We snapshot the dict so we can roll back if encoding
    // later fails — symbol entries that never hit the wire must not be
    // remembered. ---
    let dict_mark = symbol_dict.mark();
    let delta_start = match resolve_symbols(
        chunk,
        symbol_dict,
        &mut scratch.new_symbols,
        &mut scratch.per_column,
    ) {
        Ok(d) => d,
        Err(e) => {
            symbol_dict.rollback(dict_mark);
            return Err(e);
        }
    };

    // --- Schema signature ---
    let column_count = chunk.columns.len() + 1; // +1 for designated timestamp
    scratch.signature.reserve(column_count * 8);
    for col in &chunk.columns {
        write_qwp_bytes(&mut scratch.signature, col.name.as_bytes());
        scratch.signature.push(col.wire_type);
    }
    write_qwp_bytes(&mut scratch.signature, &[]); // designated_ts has empty name
    scratch.signature.push(designated.wire_type);

    let (schema_id, is_new_schema) = schema_registry.intern(&scratch.signature);

    let estimated = estimate_frame_size(
        chunk,
        row_count,
        &scratch.signature,
        &scratch.new_symbols,
        &scratch.per_column,
    );
    out.reserve(estimated);

    // --- Reserve frame header placeholder ---
    let frame_start = out.len();
    write_header_placeholder(out, /* table_count = */ 1, defer_commit);
    let payload_start = out.len();

    write_qwp_varint(out, delta_start);
    write_qwp_varint(out, scratch.new_symbols.len() as u64);
    for bytes in &scratch.new_symbols {
        write_qwp_bytes(out, bytes);
    }

    write_qwp_bytes(out, table_bytes);
    write_qwp_varint(out, row_count as u64);
    write_qwp_varint(out, column_count as u64);

    if is_new_schema {
        out.push(QWP_SCHEMA_MODE_FULL);
        write_qwp_varint(out, schema_id);
        out.extend_from_slice(&scratch.signature);
    } else {
        out.push(QWP_SCHEMA_MODE_REFERENCE);
        write_qwp_varint(out, schema_id);
    }

    for (col_idx, col) in chunk.columns.iter().enumerate() {
        unsafe {
            encode_column(out, col, row_count, col_idx, &scratch.per_column)?;
        }
    }

    // --- Designated timestamp ---
    encode_designated_ts(out, designated, row_count);

    let payload_len_usize = out.len() - payload_start;
    let payload_len = u32::try_from(payload_len_usize).map_err(|_| {
        error::fmt!(
            InvalidApiCall,
            "QWP frame payload size {} bytes exceeds u32::MAX; \
             split into smaller chunks",
            payload_len_usize
        )
    })?;
    let header = &mut out[frame_start..payload_start];
    header[8..12].copy_from_slice(&payload_len.to_le_bytes());

    Ok(())
}

/// Conservative byte estimate of the encoded QWP frame body. Used to
/// `reserve()` write_buf in one shot before the encode loop — avoids
/// the geometric-growth memcpy pattern when total payload runs into
/// MBs. Walks descriptors once, no actual data reads.
fn estimate_frame_size(
    chunk: &Chunk<'_>,
    row_count: usize,
    signature: &[u8],
    new_symbols: &[Vec<u8>],
    _per_column: &[Option<ResolvedColumn>],
) -> usize {
    let mut total = QWP_HEADER_LEN;
    total += 10 + 10; // delta_start + new_symbols_count varints
    for s in new_symbols {
        total += 10 + s.len();
    }
    // table block header + schema section
    total += 10 + chunk.table.len() + 10 + 10; // table name + row + col count varints
    total += 1 + 10 + signature.len(); // schema mode + id varint + signature (full case)

    let bitmap_bytes = row_count.div_ceil(8);
    for col in &chunk.columns {
        let null_overhead = 1 + if col.validity.is_some() {
            bitmap_bytes
        } else {
            0
        };
        let payload_size = match col.kind {
            ColumnKind::Byte { .. } => row_count,
            ColumnKind::Short { .. } => 2 * row_count,
            ColumnKind::Int { .. } | ColumnKind::Float { .. } | ColumnKind::Ipv4 { .. } => {
                4 * row_count
            }
            ColumnKind::Long { .. }
            | ColumnKind::Double { .. }
            | ColumnKind::TsNanos { .. }
            | ColumnKind::TsMicros { .. }
            | ColumnKind::DateMillis { .. } => 8 * row_count,
            ColumnKind::Bool { .. } => bitmap_bytes,
            ColumnKind::Uuid { .. } => 16 * row_count,
            ColumnKind::Long256 { .. } => 32 * row_count,
            ColumnKind::Varchar { bytes_len, .. }
            | ColumnKind::VarcharLarge { bytes_len, .. }
            | ColumnKind::Binary { bytes_len, .. } => 4 * (row_count + 1) + bytes_len,
            ColumnKind::Symbol { .. } => 5 * row_count, // varint upper bound
            // Conservative upper bound covering the widest Arrow body
            // (Decimal256 = scale + 32 B/row, ARRAY DOUBLE per-row blob).
            // Under-estimation only costs a Vec realloc inside the
            // encoder; over-estimation costs a one-shot reservation.
            #[cfg(feature = "arrow")]
            ColumnKind::ArrowDeferred { .. } => 64 * row_count,
            ColumnKind::NumpyDeferred { dtype, .. } => dtype.bytes_per_row() * row_count,
        };
        total += null_overhead + payload_size;
    }
    // designated timestamp
    total += 1 + 8 * row_count;
    total
}

fn emit_header_only_frame(out: &mut Vec<u8>, defer_commit: bool) {
    let frame_start = out.len();
    write_header_placeholder(out, 0, defer_commit);
    let payload_start = out.len();
    write_qwp_varint(out, 0); // delta_start
    write_qwp_varint(out, 0); // new_symbols_count
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
    out.extend_from_slice(&0u32.to_le_bytes()); // payload_len placeholder
    debug_assert_eq!(out.len() - start, QWP_HEADER_LEN);
}

// ===========================================================================
// Symbol resolution (pre-pass)
// ===========================================================================

pub(crate) enum ResolvedColumn {
    /// Row-by-row `ColumnKind::Symbol`: slot → global-id table plus
    /// the non-null row count used to size the dense varint output.
    Row(RowResolvedSymbol),
    /// `ColumnKind::ArrowDeferred` whose `arrow_kind` is a symbol
    /// variant. Per-non-null-row global ids are pre-computed.
    #[cfg(feature = "arrow")]
    Arrow(arrow_batch::ArrowResolvedSymbolColumn),
}

pub(crate) struct RowResolvedSymbol {
    /// Indexed by dict slot. `u64::MAX` for slots the column never
    /// references (we only intern referenced slots).
    pub(crate) local_to_global: Vec<u64>,
    pub(crate) non_null_count: usize,
}

/// Walk symbol columns, intern referenced entries against the
/// connection-scoped global dict, and emit one [`ResolvedColumn`] per
/// chunk column into `per_column` (length == `chunk.columns.len()`).
/// Non-symbol columns push `None`. Returns the `delta_start` watermark
/// the encoder writes into the frame's delta-dict prefix.
fn resolve_symbols(
    chunk: &Chunk<'_>,
    symbol_dict: &mut SymbolGlobalDict,
    new_symbols: &mut Vec<Vec<u8>>,
    per_column: &mut Vec<Option<ResolvedColumn>>,
) -> Result<u64> {
    let delta_start = symbol_dict.next_id();
    per_column.reserve(chunk.columns.len());
    let row_count = chunk.row_count();

    for col in &chunk.columns {
        match col.kind {
            ColumnKind::Symbol {
                codes,
                dict_offsets,
                dict_offsets_len,
                dict_bytes,
                dict_bytes_len,
            } => {
                let dict_len = dict_offsets_len - 1;
                let dict_bytes_slice = unsafe { slice::from_raw_parts(dict_bytes, dict_bytes_len) };
                let mut referenced = vec![false; dict_len];
                let mut non_null_count = 0usize;
                for i in 0..row_count {
                    if !is_valid_row(col.validity.as_ref(), i) {
                        continue;
                    }
                    let slot = unsafe { codes.read_i64(i) } as usize;
                    referenced[slot] = true;
                    non_null_count += 1;
                }
                let mut local_to_global = vec![u64::MAX; dict_len];
                for (slot, mark) in referenced.iter().enumerate() {
                    if !*mark {
                        continue;
                    }
                    let start = unsafe { dict_offsets.read_i64(slot) } as usize;
                    let end = unsafe { dict_offsets.read_i64(slot + 1) } as usize;
                    let entry_bytes = &dict_bytes_slice[start..end];
                    let (gid, is_new) = symbol_dict.intern(entry_bytes)?;
                    if is_new {
                        new_symbols.push(entry_bytes.to_vec());
                    }
                    local_to_global[slot] = gid;
                }
                per_column.push(Some(ResolvedColumn::Row(RowResolvedSymbol {
                    local_to_global,
                    non_null_count,
                })));
            }
            #[cfg(feature = "arrow")]
            ColumnKind::ArrowDeferred {
                arrow_kind,
                ref arr,
            } => {
                let resolved = arrow_batch::resolve_arrow_symbol_column(
                    arr.as_ref(),
                    arrow_kind,
                    symbol_dict,
                    new_symbols,
                )?;
                per_column.push(resolved.map(ResolvedColumn::Arrow));
            }
            _ => per_column.push(None),
        }
    }
    Ok(delta_start)
}

// ===========================================================================
// Column encoders
// ===========================================================================

/// Encode column `col` into `out`. SAFETY: caller buffers referenced by
/// `col` must still be alive (see `Chunk` lifetime contract).
unsafe fn encode_column(
    out: &mut Vec<u8>,
    col: &ColumnDescriptor,
    row_count: usize,
    col_idx: usize,
    per_column: &[Option<ResolvedColumn>],
) -> Result<()> {
    let validity = col.validity.as_ref();
    match col.kind {
        ColumnKind::Byte { data } => unsafe {
            encode_sentinel_le::<i8, 1>(out, data, row_count, validity, I8_NULL, |v| [v as u8])
        },
        ColumnKind::Short { data } => unsafe {
            encode_sentinel_le::<i16, 2>(out, data, row_count, validity, I16_NULL, i16::to_le_bytes)
        },
        ColumnKind::Int { data } => unsafe {
            encode_sentinel_le::<i32, 4>(out, data, row_count, validity, I32_NULL, i32::to_le_bytes)
        },
        ColumnKind::Long { data } => unsafe {
            encode_sentinel_le::<i64, 8>(out, data, row_count, validity, I64_NULL, i64::to_le_bytes)
        },
        ColumnKind::Float { data } => unsafe {
            encode_sentinel_le::<f32, 4>(out, data, row_count, validity, F32_NULL, f32::to_le_bytes)
        },
        ColumnKind::Double { data } => unsafe {
            encode_sentinel_le::<f64, 8>(out, data, row_count, validity, F64_NULL, f64::to_le_bytes)
        },
        ColumnKind::Bool { bits } => unsafe {
            encode_bool(out, bits, row_count, validity);
        },
        ColumnKind::Ipv4 { data } => unsafe {
            encode_bitmap_le::<u32, 4>(out, data, row_count, validity, u32::to_le_bytes);
        },
        ColumnKind::TsNanos { data }
        | ColumnKind::TsMicros { data }
        | ColumnKind::DateMillis { data } => unsafe {
            encode_bitmap_le::<i64, 8>(out, data, row_count, validity, i64::to_le_bytes);
        },
        ColumnKind::Uuid { data } => unsafe {
            encode_fixed_width_bitmap::<16>(out, data as *const u8, row_count, validity);
        },
        ColumnKind::Long256 { data } => unsafe {
            encode_fixed_width_bitmap::<32>(out, data as *const u8, row_count, validity);
        },
        ColumnKind::Varchar {
            offsets,
            offsets_len,
            bytes,
            bytes_len,
        } => unsafe {
            encode_varchar(
                out,
                offsets,
                offsets_len,
                bytes,
                bytes_len,
                row_count,
                validity,
            );
        },
        ColumnKind::VarcharLarge {
            offsets,
            offsets_len,
            bytes,
            bytes_len,
        } => unsafe {
            encode_varchar_large(
                out,
                offsets,
                offsets_len,
                bytes,
                bytes_len,
                row_count,
                validity,
            );
        },
        ColumnKind::Binary {
            offsets,
            offsets_len,
            bytes,
            bytes_len,
        } => unsafe {
            encode_varchar(
                out,
                offsets,
                offsets_len,
                bytes,
                bytes_len,
                row_count,
                validity,
            );
        },
        ColumnKind::Symbol { codes, .. } => {
            let resolved = match per_column[col_idx].as_ref() {
                Some(ResolvedColumn::Row(r)) => r,
                _ => {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "internal: row-based symbol resolution missing for ColumnKind::Symbol \
                         at column index {col_idx}"
                    ));
                }
            };
            unsafe {
                encode_symbol(out, codes, resolved, row_count, validity);
            }
        }
        #[cfg(feature = "arrow")]
        ColumnKind::ArrowDeferred {
            arrow_kind,
            ref arr,
        } => {
            let sym_res = match per_column.get(col_idx).and_then(Option::as_ref) {
                Some(ResolvedColumn::Arrow(r)) => Some(r),
                Some(ResolvedColumn::Row(_)) => {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "internal: arrow symbol resolution missing for ArrowDeferred column \
                         at column index {col_idx}"
                    ));
                }
                None => None,
            };
            arrow_batch::write_arrow_column_body(out, arrow_kind, arr.as_ref(), sym_res)?;
        }
        ColumnKind::NumpyDeferred {
            dtype,
            data,
            row_count: numpy_rows,
        } => {
            debug_assert_eq!(numpy_rows, row_count);
            unsafe { numpy_wire::emit_into_wire(out, dtype, data, numpy_rows, validity)? };
        }
    }
    Ok(())
}

/// Sentinel-null path: no validity bitmap, single null_flag byte + dense
/// data. `T` is read directly from caller memory and converted to LE
/// bytes; nulls are sentinel-encoded with `null_value`.
unsafe fn encode_sentinel_le<T, const N: usize>(
    out: &mut Vec<u8>,
    data: *const T,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    null_value: T,
    to_le: impl Fn(T) -> [u8; N],
) where
    T: Copy,
{
    out.push(0); // null_flag = 0x00 (sentinel encoding)
    out.reserve(N * row_count);
    match validity {
        None => {
            // Hot path: contiguous typed buffer → bulk memcpy via byte
            // reinterpret. POD numerics, any byte pattern is sound.
            let bytes = unsafe { slice::from_raw_parts(data as *const u8, row_count * N) };
            out.extend_from_slice(bytes);
        }
        Some(v) => {
            for i in 0..row_count {
                let value = if unsafe { v.is_valid(i) } {
                    unsafe { *data.add(i) }
                } else {
                    null_value
                };
                out.extend_from_slice(&to_le(value));
            }
        }
    }
}

/// Bitmap-style fixed-width path: null_flag + optional QWP bitmap +
/// dense values for non-null rows only.
unsafe fn encode_bitmap_le<T, const N: usize>(
    out: &mut Vec<u8>,
    data: *const T,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    to_le: impl Fn(T) -> [u8; N],
) where
    T: Copy,
{
    match validity {
        None => {
            out.push(0);
            out.reserve(N * row_count);
            let bytes = unsafe { slice::from_raw_parts(data as *const u8, row_count * N) };
            out.extend_from_slice(bytes);
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            out.reserve(N * v.non_null_count);
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let value = unsafe { *data.add(i) };
                    out.extend_from_slice(&to_le(value));
                }
            }
        }
    }
}

/// Bitmap-style fixed-width binary column (UUID, LONG256). `data`
/// points at row 0 of an `[u8; N]` block.
unsafe fn encode_fixed_width_bitmap<const N: usize>(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    match validity {
        None => {
            out.push(0);
            out.reserve(N * row_count);
            let bytes = unsafe { slice::from_raw_parts(data, N * row_count) };
            out.extend_from_slice(bytes);
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            out.reserve(N * v.non_null_count);
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let row_start = unsafe { data.add(i * N) };
                    let row = unsafe { slice::from_raw_parts(row_start, N) };
                    out.extend_from_slice(row);
                }
            }
        }
    }
}

unsafe fn encode_bool(
    out: &mut Vec<u8>,
    bits: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    out.push(0); // bool always sentinel-encoded
    let mut packed = 0u8;
    let mut bit_idx = 0u8;
    for i in 0..row_count {
        let byte_idx = i / 8;
        let bit_off = i % 8;
        let bit = (unsafe { *bits.add(byte_idx) } >> bit_off) & 1;
        let valid = validity.is_none_or(|v| unsafe { v.is_valid(i) });
        if bit == 1 && valid {
            packed |= 1u8 << bit_idx;
        }
        bit_idx += 1;
        if bit_idx == 8 {
            out.push(packed);
            packed = 0;
            bit_idx = 0;
        }
    }
    if bit_idx != 0 {
        out.push(packed);
    }
}

unsafe fn encode_varchar(
    out: &mut Vec<u8>,
    offsets: *const i32,
    offsets_len: usize,
    bytes: *const u8,
    bytes_len: usize,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    let offsets_slice = unsafe { slice::from_raw_parts(offsets, offsets_len) };
    let bytes_slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

    match validity {
        None => {
            out.push(0); // null_flag
            out.reserve(4 * (row_count + 1) + bytes_len);
            let base = offsets_slice[0];
            if base == 0 {
                // Hot path: offset table is bit-identical to LE u32 for
                // non-negative i32; memcpy both halves.
                let offset_bytes = unsafe {
                    slice::from_raw_parts(
                        offsets as *const u8,
                        offsets_len * std::mem::size_of::<i32>(),
                    )
                };
                out.extend_from_slice(offset_bytes);
                let used = offsets_slice[row_count] as usize;
                out.extend_from_slice(&bytes_slice[..used]);
            } else {
                for &off in offsets_slice {
                    let normalized = (off - base) as u32;
                    out.extend_from_slice(&normalized.to_le_bytes());
                }
                let start = base as usize;
                let end = offsets_slice[row_count] as usize;
                out.extend_from_slice(&bytes_slice[start..end]);
            }
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            let non_null = v.non_null_count;
            let offsets_start = out.len();
            out.resize(offsets_start + 4 * (non_null + 1), 0);
            out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());
            let mut cumulative: u32 = 0;
            let mut next_offset_idx = 1usize;
            let bytes_anchor = out.len();
            for i in 0..row_count {
                if !unsafe { v.is_valid(i) } {
                    continue;
                }
                let start = offsets_slice[i] as usize;
                let end = offsets_slice[i + 1] as usize;
                let len = end - start;
                out.extend_from_slice(&bytes_slice[start..end]);
                cumulative = cumulative.saturating_add(len as u32);
                let off = offsets_start + 4 * next_offset_idx;
                out[off..off + 4].copy_from_slice(&cumulative.to_le_bytes());
                next_offset_idx += 1;
            }
            debug_assert_eq!(next_offset_idx - 1, non_null);
            debug_assert_eq!(out.len() - bytes_anchor, cumulative as usize);
        }
    }
}

/// Same wire output as [`encode_varchar`], but reads `int64` offsets
/// (Arrow LargeUtf8 layout) and narrows each to `u32` in-place while
/// writing — no intermediate `Vec<i32>` allocation. Per-offset
/// `u32::MAX` overflow has already been rejected at chunk-build time by
/// [`validate_varchar_offsets_i64`](super::chunk::validate_varchar_offsets_i64),
/// so the narrowing here is always lossless.
unsafe fn encode_varchar_large(
    out: &mut Vec<u8>,
    offsets: *const i64,
    offsets_len: usize,
    bytes: *const u8,
    bytes_len: usize,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    let offsets_slice = unsafe { slice::from_raw_parts(offsets, offsets_len) };
    let bytes_slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

    match validity {
        None => {
            out.push(0); // null_flag
            out.reserve(4 * (row_count + 1) + bytes_len);
            let base = offsets_slice[0];
            for &off in offsets_slice {
                let normalized = (off - base) as u32;
                out.extend_from_slice(&normalized.to_le_bytes());
            }
            let start = base as usize;
            let end = offsets_slice[row_count] as usize;
            out.extend_from_slice(&bytes_slice[start..end]);
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            let non_null = v.non_null_count;
            let offsets_start = out.len();
            out.resize(offsets_start + 4 * (non_null + 1), 0);
            out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());
            let mut cumulative: u32 = 0;
            let mut next_offset_idx = 1usize;
            let bytes_anchor = out.len();
            for i in 0..row_count {
                if !unsafe { v.is_valid(i) } {
                    continue;
                }
                let start = offsets_slice[i] as usize;
                let end = offsets_slice[i + 1] as usize;
                let len = end - start;
                out.extend_from_slice(&bytes_slice[start..end]);
                cumulative = cumulative.saturating_add(len as u32);
                let off = offsets_start + 4 * next_offset_idx;
                out[off..off + 4].copy_from_slice(&cumulative.to_le_bytes());
                next_offset_idx += 1;
            }
            debug_assert_eq!(next_offset_idx - 1, non_null);
            debug_assert_eq!(out.len() - bytes_anchor, cumulative as usize);
        }
    }
}

unsafe fn encode_symbol(
    out: &mut Vec<u8>,
    codes: SymbolCodesPtr,
    resolved: &RowResolvedSymbol,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    match validity {
        None => out.push(0),
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
        }
    }
    out.reserve(resolved.non_null_count * 4);
    // Specialise on the code's bit width so the per-row loop is a
    // straight read + table lookup + varint write (~1 ns/row). The
    // dispatch overhead is amortised across the whole column.
    match codes {
        SymbolCodesPtr::I8(p) => unsafe {
            emit_symbol_rows(out, p, row_count, validity, &resolved.local_to_global);
        },
        SymbolCodesPtr::I16(p) => unsafe {
            emit_symbol_rows(out, p, row_count, validity, &resolved.local_to_global);
        },
        SymbolCodesPtr::I32(p) => unsafe {
            emit_symbol_rows(out, p, row_count, validity, &resolved.local_to_global);
        },
    }
}

unsafe fn emit_symbol_rows<T>(
    out: &mut Vec<u8>,
    codes: *const T,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    local_to_global: &[u64],
) where
    T: Copy + Into<i64>,
{
    for i in 0..row_count {
        let valid = validity.is_none_or(|v| unsafe { v.is_valid(i) });
        if !valid {
            continue;
        }
        let slot = unsafe { (*codes.add(i)).into() } as usize;
        let gid = local_to_global[slot];
        debug_assert_ne!(gid, u64::MAX, "referenced symbol slot has no global id");
        write_qwp_varint(out, gid);
    }
}

fn encode_designated_ts(out: &mut Vec<u8>, ts: &DesignatedTsDescriptor, row_count: usize) {
    out.push(0); // designated_ts is always non-null
    out.reserve(8 * row_count);
    // SAFETY: caller buffer lifetime is the chunk's `'a`.
    let bytes = unsafe {
        slice::from_raw_parts(ts.data as *const u8, row_count * std::mem::size_of::<i64>())
    };
    out.extend_from_slice(bytes);
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Write `validity` as a QWP-shape (bit = 1 NULL) bitmap appended to
/// `out`. The high bits past `bit_len` in the last byte are masked.
unsafe fn write_qwp_bitmap_from_validity(out: &mut Vec<u8>, v: &ValidityDescriptor) {
    let full_bytes = v.bit_len / 8;
    let trailing_bits = v.bit_len % 8;
    let src = unsafe { slice::from_raw_parts(v.bits, v.byte_len()) };
    let bitmap_bytes = full_bytes + usize::from(trailing_bits != 0);
    let dst_start = out.len();
    out.resize(dst_start + bitmap_bytes, 0);
    let dst = &mut out[dst_start..dst_start + bitmap_bytes];
    for (d, &s) in dst[..full_bytes].iter_mut().zip(&src[..full_bytes]) {
        *d = !s;
    }
    if trailing_bits != 0 {
        let mask = (1u8 << trailing_bits) - 1;
        dst[full_bytes] = (!src[full_bytes]) & mask;
    }
}

#[inline]
fn is_valid_row(validity: Option<&ValidityDescriptor>, i: usize) -> bool {
    match validity {
        None => true,
        // SAFETY: bit_len was checked == row_count at append time, so
        // `i < row_count` ⇒ `i < bit_len`.
        Some(v) => unsafe { v.is_valid(i) },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::column_sender::Validity;

    fn make_chunk_i64(name: &str, data: &[i64]) -> Vec<u8> {
        let mut chunk = Chunk::new("trades");
        chunk.column_i64(name, data, None).unwrap();
        chunk.designated_timestamp_nanos(data).unwrap();
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();
        out
    }

    #[test]
    fn empty_chunk_encodes_to_14_bytes() {
        let chunk = Chunk::new("trades");
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(out.len(), 14);
        assert_eq!(&out[0..4], b"QWP1");
        assert_eq!(out[5], QWP_FLAG_DELTA_SYMBOL_DICT);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), 0);
    }

    #[test]
    fn defer_commit_flag_is_set_when_requested() {
        let chunk = Chunk::new("trades");
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, true).unwrap();
        assert_eq!(out[5] & QWP_FLAG_DEFER_COMMIT, QWP_FLAG_DEFER_COMMIT);
        assert_eq!(
            out[5] & QWP_FLAG_DELTA_SYMBOL_DICT,
            QWP_FLAG_DELTA_SYMBOL_DICT
        );
    }

    #[test]
    fn non_empty_chunk_without_designated_ts_errors() {
        let mut chunk = Chunk::new("trades");
        let data = [1i64, 2, 3];
        chunk.column_i64("a", &data, None).unwrap();
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let err = encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("designated"));
    }

    #[test]
    fn second_encode_with_same_schema_uses_reference() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();

        let p1 = [1i64, 2];
        let mut c1 = Chunk::new("trades");
        c1.column_i64("price", &p1, None).unwrap();
        c1.designated_timestamp_nanos(&p1).unwrap();
        let mut out1 = Vec::new();
        encode_chunk_into(&mut out1, &c1, &mut reg, &mut dict, &mut scratch, false).unwrap();

        let p2 = [3i64, 4];
        let mut c2 = Chunk::new("trades");
        c2.column_i64("price", &p2, None).unwrap();
        c2.designated_timestamp_nanos(&p2).unwrap();
        let mut out2 = Vec::new();
        encode_chunk_into(&mut out2, &c2, &mut reg, &mut dict, &mut scratch, false).unwrap();

        assert!(out2.len() < out1.len());
        assert_eq!(reg.len(), 1, "schema signature interned once");

        let schema_mode_offset = 12 + 1 + 1 + 1 + "trades".len() + 1 + 1;
        assert_eq!(out1[schema_mode_offset], QWP_SCHEMA_MODE_FULL);
        assert_eq!(out2[schema_mode_offset], QWP_SCHEMA_MODE_REFERENCE);
    }

    #[test]
    fn distinct_schemas_get_distinct_ids() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let x = [1i64];
        let mut a = Chunk::new("a");
        a.column_i64("x", &x, None).unwrap();
        a.designated_timestamp_nanos(&x).unwrap();
        let mut oa = Vec::new();
        encode_chunk_into(&mut oa, &a, &mut reg, &mut dict, &mut scratch, false).unwrap();

        let y = [1.0f64];
        let ts = [1i64];
        let mut b = Chunk::new("b");
        b.column_f64("y", &y, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let mut ob = Vec::new();
        encode_chunk_into(&mut ob, &b, &mut reg, &mut dict, &mut scratch, false).unwrap();

        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn frame_size_grows_with_column_payloads() {
        let p = [1i64, 2, 3, 4];
        let bits = [0xFFu8];
        let v = Validity::from_bitmap(&bits, 4).unwrap();
        let mut chunk = Chunk::new("trades");
        chunk.column_i64("price", &p, Some(&v)).unwrap();
        chunk.designated_timestamp_nanos(&p).unwrap();
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();
        assert!(out.len() > 32);
    }

    #[test]
    fn symbol_dict_emits_only_referenced_entries() {
        let codes = [0i32, 2, 0, 2];
        let dict_offsets = [0i32, 5, 9, 14];
        let dict_bytes = b"alphabetagamma";
        let ts = [1i64, 2, 3, 4];
        let mut chunk = Chunk::new("trades");
        chunk
            .symbol_dict_i32("sym", &codes, &dict_offsets, dict_bytes, None)
            .unwrap();
        chunk.designated_timestamp_nanos(&ts).unwrap();
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 2, "alpha + gamma only, beta unsent");
    }

    #[test]
    fn symbol_dict_large_utf8_emits_only_referenced_entries() {
        let codes = [0i32, 2, 0, 2];
        let dict_offsets = [0i64, 5, 9, 14];
        let dict_bytes = b"alphabetagamma";
        let ts = [1i64, 2, 3, 4];
        let mut chunk = Chunk::new("trades");
        chunk
            .symbol_dict_large_i32("sym", &codes, &dict_offsets, dict_bytes, None)
            .unwrap();
        chunk.designated_timestamp_nanos(&ts).unwrap();
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 2, "alpha + gamma only, beta unsent");
    }

    #[test]
    fn symbol_dict_second_frame_resends_only_new_entries() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let dict_offsets = [0i32, 5, 9, 14];
        let dict_bytes = b"alphabetagamma";

        let codes1 = [0i32, 1];
        let ts1 = [1i64, 2];
        let mut c1 = Chunk::new("trades");
        c1.symbol_dict_i32("sym", &codes1, &dict_offsets, dict_bytes, None)
            .unwrap();
        c1.designated_timestamp_nanos(&ts1).unwrap();
        let mut out1 = Vec::new();
        encode_chunk_into(&mut out1, &c1, &mut reg, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 2);

        let codes2 = [0i32, 2];
        let ts2 = [3i64, 4];
        let mut c2 = Chunk::new("trades");
        c2.symbol_dict_i32("sym", &codes2, &dict_offsets, dict_bytes, None)
            .unwrap();
        c2.designated_timestamp_nanos(&ts2).unwrap();
        let mut out2 = Vec::new();
        encode_chunk_into(&mut out2, &c2, &mut reg, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 3, "gamma added on second frame");
    }

    #[test]
    fn i64_no_null_round_trip_wire_bytes() {
        let bytes = make_chunk_i64("price", &[10, 20, 30]);
        // Frame contains: header(12) + delta_dict(2) + table_block + schema +
        // column data + designated_ts data. The exact byte layout is asserted
        // implicitly via the other tests; here we just ensure the payload_len
        // patched correctly.
        let payload_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
        assert_eq!(12 + payload_len, bytes.len());
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn arrow_deferred_i64_column_matches_row_by_row() {
        use crate::ingress::column_sender::arrow_batch;
        use arrow_array::{ArrayRef, Int64Array};
        use std::sync::Arc;

        let values = [10i64, 20, 30];

        let row_by_row = make_chunk_i64("price", &values);

        let arr: ArrayRef = Arc::new(Int64Array::from(values.to_vec()));
        let mut chunk = Chunk::new("trades");
        chunk
            .push_arrow_deferred("price", arrow_batch::ColumnKind::I64, arr)
            .unwrap();
        chunk.designated_timestamp_nanos(&values).unwrap();
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();

        assert_eq!(
            row_by_row, out,
            "ArrowDeferred I64 must produce byte-identical wire to column_i64"
        );
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn arrow_deferred_symbol_column_interns_into_shared_dict() {
        use crate::ingress::column_sender::arrow_batch;
        use arrow_array::{ArrayRef, StringArray};
        use std::sync::Arc;

        let sym = StringArray::from(vec!["AAPL", "MSFT", "AAPL"]);
        let ts = [1i64, 2, 3];
        let arr: ArrayRef = Arc::new(sym);
        let mut chunk = Chunk::new("trades");
        chunk
            .push_arrow_deferred("sym", arrow_batch::ColumnKind::SymbolUtf8, arr)
            .unwrap();
        chunk.designated_timestamp_nanos(&ts).unwrap();

        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();

        assert_eq!(&out[..4], b"QWP1");
        assert_eq!(dict.next_id(), 2, "two unique symbols interned");
    }

    #[cfg(feature = "arrow")]
    #[test]
    fn arrow_deferred_symbol_failure_rolls_back_dict() {
        use crate::ingress::column_sender::arrow_batch;
        use arrow_array::types::UInt32Type;
        use arrow_array::{ArrayRef, DictionaryArray, UInt32Array};
        use std::sync::Arc;

        let mut vb = arrow_array::builder::StringBuilder::new();
        vb.append_value("alpha");
        vb.append_null();
        let values = vb.finish();
        let keys = UInt32Array::from(vec![0u32, 1]);
        let dict_arr =
            DictionaryArray::<UInt32Type>::try_new(keys, Arc::new(values) as ArrayRef).unwrap();
        let arr: ArrayRef = Arc::new(dict_arr);
        let kind = arrow_batch::ColumnKind::SymbolDict {
            key: arrow_batch::DictKey::U32,
            value: arrow_batch::DictValue::Utf8,
        };

        let ts = [1i64, 2];
        let mut chunk = Chunk::new("trades");
        chunk.push_arrow_deferred("sym", kind, arr).unwrap();
        chunk.designated_timestamp_nanos(&ts).unwrap();

        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let prior_next = dict.next_id();
        let err = encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::ArrowIngest);
        assert_eq!(
            dict.next_id(),
            prior_next,
            "global dict must roll back on symbol resolution failure",
        );
    }
}
