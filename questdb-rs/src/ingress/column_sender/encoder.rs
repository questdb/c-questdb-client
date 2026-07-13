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

use std::slice;

use crate::ingress::buffer::SymbolGlobalDict;
use crate::{Result, error};

#[cfg(feature = "arrow-ingress")]
use super::arrow_batch;
use super::chunk::{
    Chunk, ColumnDescriptor, ColumnKind, DesignatedTsDescriptor, SymbolCodesPtr, ValidityDescriptor,
};
use super::numpy_wire;
use super::wire::{
    F32_NULL, F64_NULL, I8_NULL, I16_NULL, I32_NULL, I64_NULL, QWP_FLAG_DEFER_COMMIT,
    QWP_FLAG_DELTA_SYMBOL_DICT, QWP_HEADER_LEN, QWP_MAGIC, QWP_VERSION_1, validate_table_name,
    write_qwp_bytes, write_qwp_varint,
};

/// Per-sender reusable scratch state for one flush. The contained `Vec`s
/// are cleared (not reallocated) between flushes so a long-lived
/// connection pays at most one allocation per growth point per Vec.
#[derive(Default)]
pub(crate) struct EncodeScratch {
    pub(crate) signature: Vec<u8>,
    pub(crate) new_symbols: Vec<Vec<u8>>,
    pub(crate) per_column: Vec<Option<ResolvedColumn>>,
    /// `referenced[slot] = 1` if any non-null row touches that dict slot.
    /// Reused across symbol columns within one flush; bytes (not bools)
    /// so `resize(n, 0)` is a single `memset`.
    pub(crate) referenced: Vec<u8>,
    /// Free list of per-symbol-column `slot -> global id` tables, reclaimed from
    /// `per_column` on [`reset`](Self::reset) so a steady flow of flushes reuses
    /// them instead of allocating one `Vec<u64>` per row-symbol column per flush.
    /// Mirrors the row replay encoder's `per_segment_symbol_globals` pooling.
    symbol_gid_pool: Vec<Vec<u64>>,
}

impl EncodeScratch {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn reset(&mut self) {
        self.signature.clear();
        self.new_symbols.clear();
        // Reclaim each symbol column's `slot -> gid` / per-row gid table into the
        // free list before dropping the resolutions, so it is reused next flush.
        // Row and arrow buffers share one `Vec<u64>` pool.
        for col in self.per_column.drain(..) {
            match col {
                Some(ResolvedColumn::Row(row)) => {
                    let mut gids = row.local_to_global;
                    gids.clear();
                    self.symbol_gid_pool.push(gids);
                }
                #[cfg(feature = "arrow-ingress")]
                Some(ResolvedColumn::Arrow(arrow)) => {
                    let mut gids = arrow.gids;
                    gids.clear();
                    self.symbol_gid_pool.push(gids);
                }
                None => {}
            }
        }
        self.referenced.clear();
    }
}

/// Encode `chunk` into `out` as a complete QWP/WebSocket frame body. The
/// caller has already reserved any prefix bytes it needs in `out` (the
/// connection layer reserves the WS header); the encoder appends QWP
/// bytes only.
pub(crate) fn encode_chunk_into(
    out: &mut Vec<u8>,
    chunk: &Chunk<'_>,
    symbol_dict: &mut SymbolGlobalDict,
    scratch: &mut EncodeScratch,
    defer_commit: bool,
) -> Result<()> {
    encode_chunk_into_mode(
        out,
        chunk,
        symbol_dict,
        scratch,
        defer_commit,
        /* replay_symbols = */ false,
    )
}

pub(crate) fn encode_chunk_replay_into(
    out: &mut Vec<u8>,
    chunk: &Chunk<'_>,
    symbol_dict: &mut SymbolGlobalDict,
    scratch: &mut EncodeScratch,
) -> Result<()> {
    encode_chunk_into_mode(
        out,
        chunk,
        symbol_dict,
        scratch,
        /* defer_commit = */ false,
        /* replay_symbols = */ true,
    )
}

fn encode_chunk_into_mode(
    out: &mut Vec<u8>,
    chunk: &Chunk<'_>,
    symbol_dict: &mut SymbolGlobalDict,
    scratch: &mut EncodeScratch,
    defer_commit: bool,
    replay_symbols: bool,
) -> Result<()> {
    scratch.reset();
    if chunk.is_empty() {
        emit_header_only_frame(out, defer_commit);
        return Ok(());
    }
    let row_count = chunk.row_count();
    if row_count == 0 {
        return Err(error::fmt!(
            InvalidApiCall,
            "Chunk row_count is 0; flush at least one row or hand back an empty chunk."
        ));
    }
    if row_count > super::MAX_CHUNK_ROWS {
        return Err(error::fmt!(
            InvalidApiCall,
            "Chunk row_count {} exceeds MAX_CHUNK_ROWS ({}); split into smaller chunks",
            row_count,
            super::MAX_CHUNK_ROWS
        ));
    }
    // Server-stamping (no per-row designated timestamp) must be an
    // explicit opt-in via `Chunk::at_now`, mirroring the arrow-batch
    // `flush_arrow_batch_at_now` entry point.
    if chunk.designated_ts.is_none() && !chunk.server_now {
        return Err(error::fmt!(
            InvalidApiCall,
            "Chunk has no designated timestamp; \
             call at_micros or at_nanos before flush, or at_now to \
             explicitly let the server stamp each row on arrival."
        ));
    }
    validate_table_name(&chunk.table)?;
    let table_bytes = chunk.table.as_bytes();

    let designated = chunk.designated_ts.as_ref();

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
        &mut scratch.referenced,
        &mut scratch.symbol_gid_pool,
    ) {
        Ok(d) => d,
        Err(e) => {
            symbol_dict.rollback(dict_mark);
            return Err(e);
        }
    };
    let delta_source = if replay_symbols {
        // Dense/replay fallback re-ships the whole dictionary from id 0 so every
        // stored frame is self-sufficient. Emit it straight from `symbol_dict` at
        // encode time (below) rather than copying every entry into `new_symbols`
        // first, which would allocate one `Vec` per dict entry per frame.
        let count = match replay_symbol_dense_count(&scratch.per_column) {
            Ok(count) => count,
            Err(e) => {
                symbol_dict.rollback(dict_mark);
                return Err(e);
            }
        };
        DeltaSource::Dense { count }
    } else {
        DeltaSource::New { delta_start }
    };

    // --- Schema signature ---
    // +1 for the designated timestamp, unless the server stamps rows
    // (`at_now`), in which case the frame carries no ts entry at all —
    // the same shape the arrow-batch `at_now` route emits.
    let column_count = chunk.columns.len() + if designated.is_some() { 1 } else { 0 };
    scratch.signature.reserve(column_count.saturating_mul(8));
    for col in &chunk.columns {
        write_qwp_bytes(&mut scratch.signature, col.name.as_bytes());
        scratch.signature.push(col.wire_type);
    }
    if let Some(designated) = designated {
        write_qwp_bytes(&mut scratch.signature, &[]); // designated_ts has empty name
        scratch.signature.push(designated.unit.wire_type());
    }

    let frame_start = out.len();
    let result = encode_frame_after_signature(
        out,
        chunk,
        designated,
        row_count,
        column_count,
        table_bytes,
        delta_source,
        symbol_dict,
        defer_commit,
        scratch,
    );
    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            out.truncate(frame_start);
            symbol_dict.rollback(dict_mark);
            Err(e)
        }
    }
}

/// How a frame's delta symbol-dictionary section is sourced.
#[derive(Clone, Copy)]
enum DeltaSource {
    /// Delta mode: emit exactly the newly-interned symbols gathered in
    /// `scratch.new_symbols`, based at `delta_start`.
    New { delta_start: u64 },
    /// Dense/replay fallback: re-emit the whole connection dictionary `[0, count)`
    /// straight from `symbol_dict` at encode time (no intermediate per-entry
    /// `Vec`), based at id 0 so the frame is self-sufficient.
    Dense { count: usize },
}

/// Look up dict entry `id` for the dense/replay path, mapping a missing id (an
/// internal invariant break) to a recoverable error rather than a panic.
#[inline]
fn dense_entry(symbol_dict: &SymbolGlobalDict, id: usize) -> Result<&[u8]> {
    symbol_dict.entry(id as u64).ok_or_else(|| {
        error::fmt!(
            InvalidApiCall,
            "internal: missing symbol dictionary entry for global id {}",
            id
        )
    })
}

fn replay_symbol_dense_count(per_column: &[Option<ResolvedColumn>]) -> Result<usize> {
    let mut highest: Option<u64> = None;
    for resolved in per_column.iter().filter_map(Option::as_ref) {
        match resolved {
            ResolvedColumn::Row(row) => {
                for &gid in &row.local_to_global {
                    if gid != u64::MAX {
                        highest = Some(highest.map_or(gid, |h| h.max(gid)));
                    }
                }
            }
            #[cfg(feature = "arrow-ingress")]
            ResolvedColumn::Arrow(arrow) => {
                for &gid in &arrow.gids {
                    highest = Some(highest.map_or(gid, |h| h.max(gid)));
                }
            }
        }
    }
    let Some(highest) = highest else {
        return Ok(0);
    };
    let count = highest.checked_add(1).ok_or_else(|| {
        error::fmt!(
            InvalidApiCall,
            "symbol dictionary too large to encode (highest id {})",
            highest
        )
    })?;
    usize::try_from(count).map_err(|_| {
        error::fmt!(
            InvalidApiCall,
            "symbol dictionary too large to encode ({} entries)",
            count
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_frame_after_signature(
    out: &mut Vec<u8>,
    chunk: &Chunk<'_>,
    designated: Option<&DesignatedTsDescriptor>,
    row_count: usize,
    column_count: usize,
    table_bytes: &[u8],
    delta: DeltaSource,
    symbol_dict: &SymbolGlobalDict,
    defer_commit: bool,
    scratch: &EncodeScratch,
) -> Result<()> {
    // Byte size of the delta symbol-dict entries we will emit, for the up-front
    // reservation. For dense/replay this walks the dict directly rather than an
    // intermediate `new_symbols` copy.
    let delta_entries_bytes = match delta {
        DeltaSource::New { .. } => scratch.new_symbols.iter().fold(0usize, |acc, s| {
            acc.saturating_add(10).saturating_add(s.len())
        }),
        DeltaSource::Dense { count } => {
            let mut sum = 0usize;
            for id in 0..count {
                sum = sum
                    .saturating_add(10)
                    .saturating_add(dense_entry(symbol_dict, id)?.len());
            }
            sum
        }
    };
    let estimated = estimate_frame_size(
        chunk,
        row_count,
        &scratch.signature,
        delta_entries_bytes,
        &scratch.per_column,
    );
    out.try_reserve(estimated).map_err(|_| {
        error::fmt!(
            InvalidApiCall,
            "allocator could not reserve {} bytes for QWP frame",
            estimated
        )
    })?;

    let frame_start = out.len();
    write_header_placeholder(out, /* table_count = */ 1, defer_commit);
    let payload_start = out.len();

    match delta {
        DeltaSource::New { delta_start } => {
            write_qwp_varint(out, delta_start);
            write_qwp_varint(out, scratch.new_symbols.len() as u64);
            for bytes in &scratch.new_symbols {
                write_qwp_bytes(out, bytes);
            }
        }
        DeltaSource::Dense { count } => {
            write_qwp_varint(out, 0); // dense frames base at id 0
            write_qwp_varint(out, count as u64);
            for id in 0..count {
                write_qwp_bytes(out, dense_entry(symbol_dict, id)?);
            }
        }
    }

    write_qwp_bytes(out, table_bytes);
    write_qwp_varint(out, row_count as u64);
    write_qwp_varint(out, column_count as u64);

    out.extend_from_slice(&scratch.signature);

    for (col_idx, col) in chunk.columns.iter().enumerate() {
        unsafe {
            encode_column(out, col, row_count, col_idx, &scratch.per_column)?;
        }
    }

    if let Some(designated) = designated {
        encode_designated_ts(out, designated, row_count)?;
    }

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
    delta_entries_bytes: usize,
    _per_column: &[Option<ResolvedColumn>],
) -> usize {
    // Saturating arithmetic throughout: the encoder's job is to size a
    // reservation, never to compute a wire offset. An overflow that
    // wraps to a small `total` would cause `try_reserve(small)` to
    // succeed and the subsequent per-column writes to abort the process
    // on the infallible `Vec::reserve` call.
    let mut total: usize = QWP_HEADER_LEN;
    total = total.saturating_add(20);
    total = total.saturating_add(delta_entries_bytes);
    total = total
        .saturating_add(10)
        .saturating_add(chunk.table.len())
        .saturating_add(20);
    total = total.saturating_add(11).saturating_add(signature.len());

    let bitmap_bytes = row_count.div_ceil(8);
    for col in &chunk.columns {
        let null_overhead = 1usize.saturating_add(if col.validity.is_some() {
            bitmap_bytes
        } else {
            0
        });
        let payload_size = match col.kind {
            ColumnKind::Byte { .. } => row_count,
            ColumnKind::Short { .. } => row_count.saturating_mul(2),
            ColumnKind::Int { .. } | ColumnKind::Float { .. } | ColumnKind::Ipv4 { .. } => {
                row_count.saturating_mul(4)
            }
            ColumnKind::Long { .. }
            | ColumnKind::Double { .. }
            | ColumnKind::TsNanos { .. }
            | ColumnKind::TsMicros { .. }
            | ColumnKind::DateMillis { .. } => row_count.saturating_mul(8),
            ColumnKind::Bool { .. } => bitmap_bytes,
            ColumnKind::Uuid { .. } => row_count.saturating_mul(16),
            ColumnKind::Long256 { .. } => row_count.saturating_mul(32),
            ColumnKind::Varchar { bytes_len, .. }
            | ColumnKind::VarcharLarge { bytes_len, .. }
            | ColumnKind::Binary { bytes_len, .. } => row_count
                .saturating_add(1)
                .saturating_mul(4)
                .saturating_add(bytes_len),
            ColumnKind::Symbol { .. } => row_count.saturating_mul(5),
            #[cfg(feature = "arrow-ingress")]
            // A deferred Arrow column resolved to symbols emits one varint per
            // non-null row (up to 5 bytes), which `get_buffer_memory_size`
            // undercounts for a dictionary/string key buffer. Add the symbol
            // worst case so the up-front `try_reserve` stays an upper bound and
            // per-column writes never fall back to an infallible realloc.
            ColumnKind::ArrowDeferred { ref arr, .. } => arr
                .get_buffer_memory_size()
                .saturating_add(row_count.saturating_mul(5)),
            ColumnKind::NumpyDeferred { dtype, .. } => {
                dtype.bytes_per_row().saturating_mul(row_count)
            }
        };
        // Per-column metadata slack covering fixed prefix bytes some encoders
        // emit beyond null_flag + payload (e.g. the decimal scale / geohash
        // bits byte on numpy decimal/geohash columns). Keeps the up-front
        // `try_reserve` an upper bound so per-column writes never fall back to
        // an infallible (process-aborting) realloc.
        total = total
            .saturating_add(null_overhead)
            .saturating_add(payload_size)
            .saturating_add(8);
    }
    total = total
        .saturating_add(1)
        .saturating_add(row_count.saturating_mul(8));
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
    #[cfg(feature = "arrow-ingress")]
    Arrow(arrow_batch::ArrowResolvedSymbolColumn),
}

pub(crate) struct RowResolvedSymbol {
    /// Indexed by dict slot. `u64::MAX` for slots the column never
    /// references (we only intern referenced slots).
    pub(crate) local_to_global: Vec<u64>,
    pub(crate) non_null_count: usize,
}

/// Fallibly size `v` to `len` filled with `value`, reusing existing
/// capacity. `len` derives from a caller-supplied dictionary size that
/// has no upper bound, so the allocation must not abort the FFI crate
/// (`panic = "abort"`) on a huge dictionary.
fn try_resize_filled<T: Clone>(v: &mut Vec<T>, len: usize, value: T) -> Result<()> {
    v.clear();
    v.try_reserve(len).map_err(|_| {
        error::fmt!(
            InvalidApiCall,
            "symbol dictionary too large to encode ({} entries)",
            len
        )
    })?;
    v.resize(len, value);
    Ok(())
}

/// Validate a symbol code re-read from the caller's borrowed `codes` buffer at
/// flush into an in-range slot index. `range_check_codes` already proved every
/// code in range at append, but the buffer is borrowed until flush; a caller that
/// mutates it in that window (documented UB, but a plausible footgun for a binding
/// reusing a codes buffer) could push a code out of range. Returning an error
/// keeps that a recoverable `InvalidApiCall` instead of an out-of-bounds index --
/// which, under the FFI `panic = "abort"` profile, would abort the whole process.
#[inline]
fn checked_symbol_slot(code: i64, row: usize, dict_len: usize) -> Result<usize> {
    match usize::try_from(code) {
        Ok(slot) if slot < dict_len => Ok(slot),
        _ => Err(error::fmt!(
            InvalidApiCall,
            "symbol code {} at row {} is out of range for dict_len {}; the borrowed \
             codes/dict buffers must stay unchanged between append and flush",
            code,
            row,
            dict_len
        )),
    }
}

/// Slice dict entry `slot`'s bytes from the borrowed `dict_bytes` at flush,
/// guarding a `dict_offsets` mutated between append and flush (see
/// [`checked_symbol_slot`]) that could yield a reversed or out-of-range range --
/// a slice index that would otherwise abort under `panic = "abort"`.
#[inline]
fn checked_symbol_entry(dict_bytes: &[u8], start: i64, end: i64, slot: usize) -> Result<&[u8]> {
    usize::try_from(start)
        .ok()
        .zip(usize::try_from(end).ok())
        .and_then(|(s, e)| dict_bytes.get(s..e))
        .ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "symbol dict entry {} spans {}..{}, out of range for dict_bytes len {}; \
                 the borrowed codes/dict buffers must stay unchanged between append and flush",
                slot,
                start,
                end,
                dict_bytes.len()
            )
        })
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
    referenced_scratch: &mut Vec<u8>,
    symbol_gid_pool: &mut Vec<Vec<u64>>,
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
                try_resize_filled(referenced_scratch, dict_len, 0)?;
                let mut non_null_count = 0usize;
                for i in 0..row_count {
                    if !is_valid_row(col.validity.as_ref(), i) {
                        continue;
                    }
                    let slot = checked_symbol_slot(unsafe { codes.read_i64(i) }, i, dict_len)?;
                    // slot < dict_len == referenced_scratch.len(), so this cannot panic.
                    referenced_scratch[slot] = 1;
                    non_null_count += 1;
                }
                let mut local_to_global = symbol_gid_pool.pop().unwrap_or_default();
                try_resize_filled(&mut local_to_global, dict_len, u64::MAX)?;
                for (slot, mark) in referenced_scratch.iter().enumerate() {
                    if *mark == 0 {
                        continue;
                    }
                    let start = unsafe { dict_offsets.read_i64(slot) };
                    let end = unsafe { dict_offsets.read_i64(slot + 1) };
                    let entry_bytes = checked_symbol_entry(dict_bytes_slice, start, end, slot)?;
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
            #[cfg(feature = "arrow-ingress")]
            ColumnKind::ArrowDeferred {
                arrow_kind,
                ref arr,
            } => {
                let resolved = arrow_batch::resolve_arrow_symbol_column(
                    arr.as_ref(),
                    arrow_kind,
                    symbol_dict,
                    new_symbols,
                    symbol_gid_pool,
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
            )?;
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
            )?;
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
            )?;
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
                encode_symbol(out, codes, resolved, row_count, validity)?;
            }
        }
        #[cfg(feature = "arrow-ingress")]
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
            src_stride: _,
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
    let data_start = out.len();
    if cfg!(target_endian = "little") {
        let bytes = unsafe { slice::from_raw_parts(data as *const u8, row_count * N) };
        out.extend_from_slice(bytes);
    } else {
        for i in 0..row_count {
            out.extend_from_slice(&to_le(unsafe { *data.add(i) }));
        }
    }
    // memcpy the whole slab above, then overwrite only the null slots with the
    // sentinel — skipping all-valid (0xFF) bitmap bytes 8 rows at a time.
    let Some(v) = validity.filter(|v| v.has_nulls()) else {
        return;
    };
    let null_le = to_le(null_value);
    let mut i = 0usize;
    while i < row_count {
        let byte_idx = i / 8;
        let bit_off = i % 8;
        if bit_off == 0 && i + 8 <= row_count && unsafe { *v.bits.add(byte_idx) } == 0xFF {
            i += 8;
            continue;
        }
        if !unsafe { v.is_valid(i) } {
            let off = data_start + i * N;
            out[off..off + N].copy_from_slice(&null_le);
        }
        i += 1;
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
    match validity.filter(|v| v.has_nulls()) {
        None => {
            out.push(0);
            out.reserve(N * row_count);
            if cfg!(target_endian = "little") {
                let bytes = unsafe { slice::from_raw_parts(data as *const u8, row_count * N) };
                out.extend_from_slice(bytes);
            } else {
                for i in 0..row_count {
                    let value = unsafe { *data.add(i) };
                    out.extend_from_slice(&to_le(value));
                }
            }
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
    match validity.filter(|v| v.has_nulls()) {
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
    out.push(0);
    if row_count == 0 {
        return;
    }
    let full_bytes = row_count / 8;
    let trailing_bits = row_count % 8;
    let bitmap_bytes = full_bytes + usize::from(trailing_bits != 0);
    if validity.is_none() {
        let src = unsafe { slice::from_raw_parts(bits, bitmap_bytes) };
        if trailing_bits == 0 {
            out.extend_from_slice(src);
        } else {
            out.extend_from_slice(&src[..full_bytes]);
            let mask = (1u8 << trailing_bits) - 1;
            out.push(src[full_bytes] & mask);
        }
        return;
    }
    let v = validity.unwrap();
    out.reserve(bitmap_bytes);
    let mut packed = 0u8;
    let mut bit_idx = 0u8;
    for i in 0..row_count {
        let byte_idx = i / 8;
        let bit_off = i % 8;
        let bit = (unsafe { *bits.add(byte_idx) } >> bit_off) & 1;
        if bit == 1 && unsafe { v.is_valid(i) } {
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
) -> Result<()> {
    let offsets_slice = unsafe { slice::from_raw_parts(offsets, offsets_len) };
    let bytes_slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

    match validity.filter(|v| v.has_nulls()) {
        None => {
            out.push(0); // null_flag
            out.reserve(4 * (row_count + 1) + bytes_len);
            let base = offsets_slice[0];
            if base == 0 && cfg!(target_endian = "little") {
                let offset_bytes = unsafe {
                    slice::from_raw_parts(
                        offsets as *const u8,
                        offsets_len * std::mem::size_of::<i32>(),
                    )
                };
                out.extend_from_slice(offset_bytes);
                let used = offsets_slice[row_count] as usize;
                out.extend_from_slice(&bytes_slice[..used]);
            } else if base == 0 {
                for &off in offsets_slice {
                    out.extend_from_slice(&(off as u32).to_le_bytes());
                }
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
                cumulative = cumulative.checked_add(len as u32).ok_or_else(|| {
                    error::fmt!(
                        InvalidApiCall,
                        "VARCHAR/BINARY column: cumulative offset exceeds u32::MAX"
                    )
                })?;
                let off = offsets_start + 4 * next_offset_idx;
                out[off..off + 4].copy_from_slice(&cumulative.to_le_bytes());
                next_offset_idx += 1;
            }
            debug_assert_eq!(next_offset_idx - 1, non_null);
            debug_assert_eq!(out.len() - bytes_anchor, cumulative as usize);
        }
    }
    Ok(())
}

/// Same wire output as [`encode_varchar`], but reads `int64` offsets
/// (Arrow LargeUtf8 layout) and narrows each to `u32` in-place while
/// writing — no intermediate `Vec<i32>` allocation. Per-offset
/// `u32::MAX` overflow has already been rejected at chunk-build time by
/// `validate_varchar_offsets_i64`,
/// so the narrowing here is always lossless.
unsafe fn encode_varchar_large(
    out: &mut Vec<u8>,
    offsets: *const i64,
    offsets_len: usize,
    bytes: *const u8,
    bytes_len: usize,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) -> Result<()> {
    let offsets_slice = unsafe { slice::from_raw_parts(offsets, offsets_len) };
    let bytes_slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

    match validity.filter(|v| v.has_nulls()) {
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
                cumulative = cumulative.checked_add(len as u32).ok_or_else(|| {
                    error::fmt!(
                        InvalidApiCall,
                        "VARCHAR/BINARY column: cumulative offset exceeds u32::MAX"
                    )
                })?;
                let off = offsets_start + 4 * next_offset_idx;
                out[off..off + 4].copy_from_slice(&cumulative.to_le_bytes());
                next_offset_idx += 1;
            }
            debug_assert_eq!(next_offset_idx - 1, non_null);
            debug_assert_eq!(out.len() - bytes_anchor, cumulative as usize);
        }
    }
    Ok(())
}

unsafe fn encode_symbol(
    out: &mut Vec<u8>,
    codes: SymbolCodesPtr,
    resolved: &RowResolvedSymbol,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) -> Result<()> {
    let validity = validity.filter(|v| v.has_nulls());
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
            emit_symbol_rows(out, p, row_count, validity, &resolved.local_to_global)
        },
        SymbolCodesPtr::I16(p) => unsafe {
            emit_symbol_rows(out, p, row_count, validity, &resolved.local_to_global)
        },
        SymbolCodesPtr::I32(p) => unsafe {
            emit_symbol_rows(out, p, row_count, validity, &resolved.local_to_global)
        },
    }
}

unsafe fn emit_symbol_rows<T>(
    out: &mut Vec<u8>,
    codes: *const T,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    local_to_global: &[u64],
) -> Result<()>
where
    T: Copy + Into<i64>,
{
    for i in 0..row_count {
        let valid = validity.is_none_or(|v| unsafe { v.is_valid(i) });
        if !valid {
            continue;
        }
        let code: i64 = unsafe { (*codes.add(i)).into() };
        let slot = checked_symbol_slot(code, i, local_to_global.len())?;
        // slot < local_to_global.len(), so this cannot panic.
        let gid = local_to_global[slot];
        debug_assert_ne!(gid, u64::MAX, "referenced symbol slot has no global id");
        write_qwp_varint(out, gid);
    }
    Ok(())
}

fn encode_designated_ts(
    out: &mut Vec<u8>,
    ts: &DesignatedTsDescriptor,
    row_count: usize,
) -> Result<()> {
    let values = unsafe { slice::from_raw_parts(ts.data, row_count) };
    for (row, &v) in values.iter().enumerate() {
        if v < 0 {
            return Err(error::fmt!(
                InvalidTimestamp,
                "designated timestamp at row {} is negative ({})",
                row,
                v
            ));
        }
    }
    out.push(0); // designated_ts is always non-null
    out.reserve(8 * row_count);
    let scale = ts.unit.scale();
    if scale != 1 {
        for (row, &v) in values.iter().enumerate() {
            let scaled = v.checked_mul(scale).ok_or_else(|| {
                error::fmt!(
                    InvalidTimestamp,
                    "designated timestamp at row {} overflows microseconds ({})",
                    row,
                    v
                )
            })?;
            out.extend_from_slice(&scaled.to_le_bytes());
        }
    } else if cfg!(target_endian = "little") {
        let bytes = unsafe {
            slice::from_raw_parts(ts.data as *const u8, row_count * std::mem::size_of::<i64>())
        };
        out.extend_from_slice(bytes);
    } else {
        for &v in values {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
    Ok(())
}

// ===========================================================================
// Helpers
// ===========================================================================

/// Write `validity` as a QWP-shape (bit = 1 NULL) bitmap appended to
/// `out`. The high bits past `bit_len` in the last byte are masked.
unsafe fn write_qwp_bitmap_from_validity(out: &mut Vec<u8>, v: &ValidityDescriptor) {
    let src = unsafe { slice::from_raw_parts(v.bits, v.byte_len()) };
    super::wire::write_qwp_bitmap_invert(out, src, v.bit_len);
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
    use crate::ingress::TimestampUnit;
    use crate::ingress::column_sender::Validity;

    fn make_chunk_i64(name: &str, data: &[i64]) -> Vec<u8> {
        let mut chunk = Chunk::new("trades");
        chunk.column_i64(name, data, None).unwrap();
        chunk.at_nanos(data).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();
        out
    }

    fn encode_fresh(chunk: &Chunk<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, chunk, &mut dict, &mut scratch, false).unwrap();
        out
    }

    #[test]
    fn checked_symbol_slot_rejects_out_of_range_and_negative_codes() {
        // Defence-in-depth for a codes buffer mutated between append and flush
        // (documented UB, but a footgun): an out-of-range or negative code must
        // yield a recoverable InvalidApiCall, never an out-of-bounds index -- which
        // under the FFI `panic = "abort"` profile would abort the whole process.
        assert_eq!(checked_symbol_slot(0, 0, 3).unwrap(), 0);
        assert_eq!(checked_symbol_slot(2, 5, 3).unwrap(), 2); // last in-range slot
        for bad in [3i64, 99, i64::MAX] {
            let err = checked_symbol_slot(bad, 7, 3).unwrap_err();
            assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
            assert!(err.msg().contains("out of range"), "{}", err.msg());
        }
        for neg in [-1i64, i64::MIN] {
            assert_eq!(
                checked_symbol_slot(neg, 7, 3).unwrap_err().code(),
                crate::ErrorCode::InvalidApiCall
            );
        }
        // An empty dict makes every code out of range.
        assert!(checked_symbol_slot(0, 0, 0).is_err());
    }

    #[test]
    fn checked_symbol_entry_rejects_reversed_or_out_of_range_spans() {
        let dict = b"aabbcc"; // len 6
        assert_eq!(checked_symbol_entry(dict, 2, 4, 1).unwrap(), b"bb");
        assert_eq!(checked_symbol_entry(dict, 0, 6, 0).unwrap(), dict);
        assert_eq!(checked_symbol_entry(dict, 3, 3, 0).unwrap(), b""); // empty span is fine
        // Reversed (start > end), past-the-end, and negative offsets all reject
        // rather than panicking on the slice index.
        for (s, e) in [(4i64, 2i64), (0, 7), (5, 100), (-1, 3), (2, -1)] {
            let err = checked_symbol_entry(dict, s, e, 0).unwrap_err();
            assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        }
    }

    /// `slice_rows(0, n)` must reproduce the whole-chunk bytes for every column
    /// kind, exercising the pointer math, `offsets_len`, and `non_null_count`
    /// recompute for fixed-width, float, bool, and validity-bearing columns.
    #[test]
    fn slice_rows_full_range_matches_whole_chunk() {
        let n = 24usize;
        let i64s: Vec<i64> = (0..n as i64).map(|x| x * 7 - 3).collect();
        let f64s: Vec<f64> = (0..n).map(|x| x as f64 * 1.5).collect();
        let ts: Vec<i64> = (0..n as i64)
            .map(|x| 1_700_000_000_000_000_000 + x)
            .collect();
        let bool_bytes = [0b1010_1010u8, 0b0101_0101, 0b1100_0011];
        // Row 0 and row 22 null.
        let valid_bytes = [0b1111_1110u8, 0b1111_1111, 0b1011_1111];
        let validity = Validity::from_bitmap(&valid_bytes, n).unwrap();

        let mut chunk = Chunk::new("trades");
        chunk.column_i64("a", &i64s, Some(&validity)).unwrap();
        chunk.column_f64("b", &f64s, None).unwrap();
        chunk.column_bool("c", &bool_bytes, n, None).unwrap();
        chunk.at_nanos(&ts).unwrap();

        let whole = encode_fresh(&chunk);
        let view = unsafe { chunk.slice_rows(0, n) };
        let sliced = encode_fresh(&view);
        assert_eq!(whole, sliced);
    }

    /// `slice_rows(off, count)` must encode byte-identically to a chunk built
    /// directly from rows `[off, off + count)`, proving the slice lands on the
    /// right rows rather than row 0.
    #[test]
    fn slice_rows_subrange_matches_freshly_built_subchunk() {
        let n = 24usize;
        let vals: Vec<i64> = (0..n as i64).map(|x| x * 11 + 5).collect();
        let ts: Vec<i64> = (0..n as i64)
            .map(|x| 1_700_000_000_000_000_000 + x)
            .collect();

        let mut src = Chunk::new("trades");
        src.column_i64("v", &vals, None).unwrap();
        src.at_nanos(&ts).unwrap();
        let view = unsafe { src.slice_rows(8, 8) };
        let sliced = encode_fresh(&view);

        let mut fresh = Chunk::new("trades");
        fresh.column_i64("v", &vals[8..16], None).unwrap();
        fresh.at_nanos(&ts[8..16]).unwrap();
        let direct = encode_fresh(&fresh);

        assert_eq!(sliced, direct);
    }

    fn build_varchar(strings: &[&str]) -> (Vec<i32>, Vec<u8>) {
        let mut offsets = Vec::with_capacity(strings.len() + 1);
        let mut bytes = Vec::new();
        offsets.push(0i32);
        for s in strings {
            bytes.extend_from_slice(s.as_bytes());
            offsets.push(bytes.len() as i32);
        }
        (offsets, bytes)
    }

    /// VARCHAR slicing keeps absolute offsets into the full byte buffer; the
    /// encoder must re-base them. A slice at offset 8 (offsets[8] != 0) must
    /// encode identically to a fresh chunk of the same strings (offsets from 0),
    /// proving the re-basing path.
    #[test]
    fn slice_rows_subrange_varchar_matches_freshly_built_subchunk() {
        let owned: Vec<String> = (0..16).map(|i| format!("val-{i}")).collect();
        let strs: Vec<&str> = owned.iter().map(String::as_str).collect();
        let (offsets, bytes) = build_varchar(&strs);
        let ts: Vec<i64> = (0..16).collect();

        let mut src = Chunk::new("trades");
        src.column_str("v", &offsets, &bytes, None).unwrap();
        src.at_nanos(&ts).unwrap();
        let view = unsafe { src.slice_rows(8, 8) };
        let sliced = encode_fresh(&view);

        let (foffsets, fbytes) = build_varchar(&strs[8..16]);
        let mut fresh = Chunk::new("trades");
        fresh.column_str("v", &foffsets, &fbytes, None).unwrap();
        fresh.at_nanos(&ts[8..16]).unwrap();
        let direct = encode_fresh(&fresh);

        assert_eq!(sliced, direct);
    }

    /// SYMBOL slicing advances the per-row codes pointer while sharing the
    /// dictionary verbatim. A slice must encode identically to a fresh chunk of
    /// the same rows (both resolve the shared dict against a fresh global dict).
    #[test]
    fn slice_rows_subrange_symbol_matches_freshly_built_subchunk() {
        let dict_bytes = b"aabbcc";
        let dict_offsets = [0i32, 2, 4, 6];
        let codes: Vec<i32> = (0..16).map(|i| i % 3).collect();
        let ts: Vec<i64> = (0..16).collect();

        let mut src = Chunk::new("trades");
        src.symbol_i32("s", &codes, &dict_offsets, dict_bytes, None)
            .unwrap();
        src.at_nanos(&ts).unwrap();
        let view = unsafe { src.slice_rows(8, 8) };
        let sliced = encode_fresh(&view);

        let mut fresh = Chunk::new("trades");
        fresh
            .symbol_i32("s", &codes[8..16], &dict_offsets, dict_bytes, None)
            .unwrap();
        fresh.at_nanos(&ts[8..16]).unwrap();
        let direct = encode_fresh(&fresh);

        assert_eq!(sliced, direct);
    }

    /// ARROW slicing forwards to `arr.slice(offset, count)`, producing an array
    /// with a non-zero internal offset. The encoder must honour that offset: a
    /// slice must encode identically to a fresh array of the same rows (offset
    /// 0).
    #[cfg(feature = "arrow-ingress")]
    #[test]
    fn slice_rows_subrange_arrow_matches_freshly_built_subchunk() {
        use crate::ingress::column_sender::arrow_batch;
        use arrow::array::{ArrayRef, Int64Array};
        use std::sync::Arc;

        let values: Vec<i64> = (0..16).map(|i| i * 13 - 7).collect();
        let ts: Vec<i64> = (0..16).collect();

        let arr: ArrayRef = Arc::new(Int64Array::from(values.clone()));
        let mut src = Chunk::new("trades");
        src.push_arrow_deferred("v", arrow_batch::ColumnKind::I64, arr)
            .unwrap();
        src.at_nanos(&ts).unwrap();
        let view = unsafe { src.slice_rows(8, 8) };
        let sliced = encode_fresh(&view);

        let fresh_arr: ArrayRef = Arc::new(Int64Array::from(values[8..16].to_vec()));
        let mut fresh = Chunk::new("trades");
        fresh
            .push_arrow_deferred("v", arrow_batch::ColumnKind::I64, fresh_arr)
            .unwrap();
        fresh.at_nanos(&ts[8..16]).unwrap();
        let direct = encode_fresh(&fresh);

        assert_eq!(sliced, direct);
    }

    /// NUMPY slicing advances the raw data pointer by `offset *
    /// source_elem_size` (the source stride, which for `I64Direct` happens to
    /// equal the wire width). A slice must encode identically to a fresh column
    /// built from the rows' bytes at offset 0.
    #[test]
    fn slice_rows_subrange_numpy_matches_freshly_built_subchunk() {
        use crate::ingress::column_sender::NumpyDtype;

        let values: Vec<i64> = (0..16).map(|i| i * 17 + 3).collect();
        let bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        let ts: Vec<i64> = (0..16).collect();

        let mut src = Chunk::new("trades");
        unsafe {
            src.push_numpy_deferred("v", NumpyDtype::I64Direct, bytes.as_ptr(), 16, None)
                .unwrap();
        }
        src.at_nanos(&ts).unwrap();
        let view = unsafe { src.slice_rows(8, 8) };
        let sliced = encode_fresh(&view);

        let fresh_bytes: Vec<u8> = values[8..16].iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut fresh = Chunk::new("trades");
        unsafe {
            fresh
                .push_numpy_deferred("v", NumpyDtype::I64Direct, fresh_bytes.as_ptr(), 8, None)
                .unwrap();
        }
        fresh.at_nanos(&ts[8..16]).unwrap();
        let direct = encode_fresh(&fresh);

        assert_eq!(sliced, direct);
    }

    /// C-1 regression, end-to-end: for a *widening* dtype the source stride (4
    /// bytes for `I32WidenToI64`) differs from the wire width (8), so a split
    /// must advance the source pointer by the source stride. The source buffer
    /// carries `0xEE` sentinel padding past row 16, so an (old, buggy)
    /// wire-width advance stays in bounds but reads the padding — yielding a
    /// clean mismatch instead of an OOB read.
    #[test]
    fn slice_rows_subrange_numpy_widening_matches_freshly_built_subchunk() {
        use crate::ingress::column_sender::NumpyDtype;

        let values: Vec<i32> = (0..16).map(|i| i * 1_000 + 7).collect();
        let mut bytes: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        bytes.resize(16 * 8, 0xEE); // sentinel padding past the 16 real i32 rows
        let ts: Vec<i64> = (0..16).collect();

        let mut src = Chunk::new("trades");
        unsafe {
            src.push_numpy_deferred("v", NumpyDtype::I32WidenToI64, bytes.as_ptr(), 16, None)
                .unwrap();
        }
        src.at_nanos(&ts).unwrap();
        let view = unsafe { src.slice_rows(8, 8) };
        let sliced = encode_fresh(&view);

        let fresh_bytes: Vec<u8> = values[8..16].iter().flat_map(|v| v.to_le_bytes()).collect();
        let mut fresh = Chunk::new("trades");
        unsafe {
            fresh
                .push_numpy_deferred(
                    "v",
                    NumpyDtype::I32WidenToI64,
                    fresh_bytes.as_ptr(),
                    8,
                    None,
                )
                .unwrap();
        }
        fresh.at_nanos(&ts[8..16]).unwrap();
        let direct = encode_fresh(&fresh);

        assert_eq!(sliced, direct);
    }

    /// The chunk (column-major) flush path must reject exactly the table
    /// names that the row/arrow API's [`TableName::new`] rejects — same
    /// grammar, no drift. A divergence here means the same malformed name
    /// is accepted by one entrypoint and rejected by another.
    #[test]
    fn table_name_validation_matches_canonical_validator() {
        use crate::ingress::TableName;
        for name in [
            "ok_table", "a.b", "a-b", "a_b", // accepted by TableName::new
            "bad?name", "a/b", "a,b", ".lead", "trail.", "a..b", "", // rejected
        ] {
            let canonical_rejects = TableName::new(name).is_err();

            // Build a minimal otherwise-valid chunk and encode it — this
            // is exactly what `ColumnSender::flush` does at flush time.
            let mut chunk = Chunk::new(name);
            let ts = [1i64];
            chunk.at_micros(&ts).unwrap();
            let col = [10i64];
            chunk.column_i64("v", &col, None).unwrap();
            let mut out = Vec::new();
            let mut dict = SymbolGlobalDict::new();
            let mut scratch = EncodeScratch::new();
            let chunk_rejects =
                encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).is_err();

            assert_eq!(
                chunk_rejects, canonical_rejects,
                "table name {name:?}: chunk flush and TableName::new disagree \
                 (chunk_rejects={chunk_rejects}, canonical_rejects={canonical_rejects})"
            );
        }
    }

    #[test]
    fn empty_chunk_encodes_to_14_bytes() {
        let chunk = Chunk::new("trades");
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(out.len(), 14);
        assert_eq!(&out[0..4], b"QWP1");
        assert_eq!(out[5], QWP_FLAG_DELTA_SYMBOL_DICT);
        assert_eq!(u16::from_le_bytes([out[6], out[7]]), 0);
    }

    #[test]
    fn defer_commit_flag_is_set_when_requested() {
        let chunk = Chunk::new("trades");
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, true).unwrap();
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
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let err = encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("designated"));
        // The error must advertise the explicit server-stamping opt-in.
        assert!(err.msg().contains("at_now"), "{}", err.msg());
    }

    /// `at_now` (server-assigned timestamps) encodes the same frame shape
    /// the arrow-batch `at_now` route emits: the column count excludes the
    /// designated timestamp and the signature carries no empty-name entry.
    #[test]
    fn at_now_chunk_encodes_without_ts_signature_entry() {
        let data = [1i64, 2, 3];

        let mut server_now = Chunk::new("trades");
        server_now.column_i64("a", &data, None).unwrap();
        server_now.at_now().unwrap();
        let now_frame = encode_fresh(&server_now);

        let mut with_ts = Chunk::new("trades");
        with_ts.column_i64("a", &data, None).unwrap();
        with_ts.at_nanos(&data).unwrap();
        let ts_frame = encode_fresh(&with_ts);

        // [12B header][delta_start][new_symbols][table "trades"][row_count]
        let col_count_offset = 12 + 1 + 1 + 1 + "trades".len() + 1;
        assert_eq!(now_frame[col_count_offset], 1); // just column "a"
        assert_eq!(ts_frame[col_count_offset], 2); // column "a" + ts

        // First (and only) signature entry is column "a", not the ts.
        let schema_offset = col_count_offset + 1;
        assert_eq!(now_frame[schema_offset], 1);
        assert_eq!(now_frame[schema_offset + 1], b'a');

        // The at_now frame drops exactly the ts signature entry (empty
        // name varint + wire type = 2 bytes) and the ts body (null_flag +
        // 8 bytes per row).
        assert_eq!(ts_frame.len() - now_frame.len(), 2 + 1 + 8 * data.len());
    }

    #[test]
    fn at_now_conflicts_with_designated_ts_column() {
        let data = [1i64, 2, 3];

        let mut ts_first = Chunk::new("trades");
        ts_first.at_micros(&data).unwrap();
        let err = ts_first.at_now().unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);

        let mut now_first = Chunk::new("trades");
        now_first.at_now().unwrap();
        let err = now_first.at_micros(&data).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("at_now"), "{}", err.msg());
    }

    #[test]
    fn at_now_only_chunk_is_header_only_and_clear_resets() {
        // No columns appended: still the empty-chunk no-op frame.
        let mut chunk = Chunk::new("trades");
        chunk.at_now().unwrap();
        assert!(chunk.is_empty());
        let out = encode_fresh(&chunk);
        // Header-only frame: 12B header + delta_start(0) + new_symbols(0).
        assert_eq!(out.len(), 14);

        // clear() drops the opt-in: the next flush demands a ts again.
        let data = [1i64, 2];
        chunk.clear();
        chunk.column_i64("a", &data, None).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let err = encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("designated"));
    }

    /// Splitting an oversize `at_now` chunk must preserve the opt-in on
    /// every slice.
    #[test]
    fn slice_rows_preserves_at_now() {
        let n = 16usize;
        let vals: Vec<i64> = (0..n as i64).collect();
        let mut src = Chunk::new("trades");
        src.column_i64("v", &vals, None).unwrap();
        src.at_now().unwrap();

        let view = unsafe { src.slice_rows(8, 8) };
        let sliced = encode_fresh(&view);

        let mut fresh = Chunk::new("trades");
        fresh.column_i64("v", &vals[8..16], None).unwrap();
        fresh.at_now().unwrap();
        let direct = encode_fresh(&fresh);

        assert_eq!(sliced, direct);
    }

    #[test]
    fn second_encode_with_same_schema_still_inlines_schema() {
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();

        let p1 = [1i64, 2];
        let mut c1 = Chunk::new("trades");
        c1.column_i64("price", &p1, None).unwrap();
        c1.at_nanos(&p1).unwrap();
        let mut out1 = Vec::new();
        encode_chunk_into(&mut out1, &c1, &mut dict, &mut scratch, false).unwrap();

        let p2 = [3i64, 4];
        let mut c2 = Chunk::new("trades");
        c2.column_i64("price", &p2, None).unwrap();
        c2.at_nanos(&p2).unwrap();
        let mut out2 = Vec::new();
        encode_chunk_into(&mut out2, &c2, &mut dict, &mut scratch, false).unwrap();

        // Re-flushing the same schema re-inlines it (no REFERENCE form), so
        // the frame is the same size.
        assert_eq!(out2.len(), out1.len());

        // [12B header][delta_start=0][new_symbols=0][table "trades"][row_count][col_count]
        let schema_offset = 12 + 1 + 1 + 1 + "trades".len() + 1 + 1;
        // First inline column def: varint name length (5) then "price".
        assert_eq!(out1[schema_offset], 5);
        assert_eq!(&out1[schema_offset + 1..schema_offset + 6], b"price");
        assert_eq!(out1[schema_offset], out2[schema_offset]);
    }

    #[test]
    fn frame_size_grows_with_column_payloads() {
        let p = [1i64, 2, 3, 4];
        let bits = [0xFFu8];
        let v = Validity::from_bitmap(&bits, 4).unwrap();
        let mut chunk = Chunk::new("trades");
        chunk.column_i64("price", &p, Some(&v)).unwrap();
        chunk.at_nanos(&p).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();
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
            .symbol_i32("sym", &codes, &dict_offsets, dict_bytes, None)
            .unwrap();
        chunk.at_nanos(&ts).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();
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
            .symbol_large_i32("sym", &codes, &dict_offsets, dict_bytes, None)
            .unwrap();
        chunk.at_nanos(&ts).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 2, "alpha + gamma only, beta unsent");
    }

    #[test]
    fn symbol_dict_second_frame_resends_only_new_entries() {
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let dict_offsets = [0i32, 5, 9, 14];
        let dict_bytes = b"alphabetagamma";

        let codes1 = [0i32, 1];
        let ts1 = [1i64, 2];
        let mut c1 = Chunk::new("trades");
        c1.symbol_i32("sym", &codes1, &dict_offsets, dict_bytes, None)
            .unwrap();
        c1.at_nanos(&ts1).unwrap();
        let mut out1 = Vec::new();
        encode_chunk_into(&mut out1, &c1, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 2);

        let codes2 = [0i32, 2];
        let ts2 = [3i64, 4];
        let mut c2 = Chunk::new("trades");
        c2.symbol_i32("sym", &codes2, &dict_offsets, dict_bytes, None)
            .unwrap();
        c2.at_nanos(&ts2).unwrap();
        let mut out2 = Vec::new();
        encode_chunk_into(&mut out2, &c2, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 3, "gamma added on second frame");
    }

    #[test]
    fn replay_encode_uses_dense_symbol_prefix_from_zero() {
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let dict_offsets = [0i32, 5, 9, 14];
        let dict_bytes = b"alphabetagamma";

        let codes1 = [0i32, 1];
        let ts1 = [1i64, 2];
        let mut c1 = Chunk::new("trades");
        c1.symbol_i32("sym", &codes1, &dict_offsets, dict_bytes, None)
            .unwrap();
        c1.at_nanos(&ts1).unwrap();
        let mut out1 = Vec::new();
        encode_chunk_into(&mut out1, &c1, &mut dict, &mut scratch, false).unwrap();
        assert_eq!(dict.next_id(), 2);

        let codes2 = [0i32, 2];
        let ts2 = [3i64, 4];
        let mut c2 = Chunk::new("trades");
        c2.symbol_i32("sym", &codes2, &dict_offsets, dict_bytes, None)
            .unwrap();
        c2.at_nanos(&ts2).unwrap();

        let mut replay = Vec::new();
        encode_chunk_replay_into(&mut replay, &c2, &mut dict, &mut scratch).unwrap();
        assert_eq!(replay[5] & QWP_FLAG_DEFER_COMMIT, 0);

        let mut pos = QWP_HEADER_LEN;
        assert_eq!(read_test_varint(&replay, &mut pos), 0);
        assert_eq!(read_test_varint(&replay, &mut pos), 3);
        assert_eq!(read_test_bytes(&replay, &mut pos), b"alpha");
        assert_eq!(read_test_bytes(&replay, &mut pos), b"beta");
        assert_eq!(read_test_bytes(&replay, &mut pos), b"gamma");
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

    fn read_test_varint(bytes: &[u8], pos: &mut usize) -> u64 {
        let mut shift = 0;
        let mut value = 0u64;
        loop {
            let b = bytes[*pos];
            *pos += 1;
            value |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }

    fn read_test_bytes<'a>(bytes: &'a [u8], pos: &mut usize) -> &'a [u8] {
        let len = read_test_varint(bytes, pos) as usize;
        let start = *pos;
        *pos += len;
        &bytes[start..start + len]
    }

    #[cfg(feature = "arrow-ingress")]
    #[test]
    fn arrow_deferred_i64_column_matches_row_by_row() {
        use crate::ingress::column_sender::arrow_batch;
        use arrow::array::{ArrayRef, Int64Array};
        use std::sync::Arc;

        let values = [10i64, 20, 30];

        let row_by_row = make_chunk_i64("price", &values);

        let arr: ArrayRef = Arc::new(Int64Array::from(values.to_vec()));
        let mut chunk = Chunk::new("trades");
        chunk
            .push_arrow_deferred("price", arrow_batch::ColumnKind::I64, arr)
            .unwrap();
        chunk.at_nanos(&values).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();

        assert_eq!(
            row_by_row, out,
            "ArrowDeferred I64 must produce byte-identical wire to column_i64"
        );
    }

    #[cfg(feature = "arrow-ingress")]
    #[test]
    fn arrow_deferred_symbol_column_interns_into_shared_dict() {
        use crate::ingress::column_sender::arrow_batch;
        use arrow::array::{ArrayRef, StringArray};
        use std::sync::Arc;

        let sym = StringArray::from(vec!["AAPL", "MSFT", "AAPL"]);
        let ts = [1i64, 2, 3];
        let arr: ArrayRef = Arc::new(sym);
        let mut chunk = Chunk::new("trades");
        chunk
            .push_arrow_deferred("sym", arrow_batch::ColumnKind::SymbolUtf8, arr)
            .unwrap();
        chunk.at_nanos(&ts).unwrap();

        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();

        assert_eq!(&out[..4], b"QWP1");
        assert_eq!(dict.next_id(), 2, "two unique symbols interned");
    }

    #[cfg(feature = "arrow-ingress")]
    #[test]
    fn arrow_deferred_symbol_failure_rolls_back_dict() {
        use crate::ingress::column_sender::arrow_batch;
        use arrow::array::types::UInt32Type;
        use arrow::array::{ArrayRef, DictionaryArray, UInt32Array};
        use std::sync::Arc;

        let mut vb = arrow::array::builder::StringBuilder::new();
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
        chunk.at_nanos(&ts).unwrap();

        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        let prior_next = dict.next_id();
        let err = encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::ArrowIngest);
        assert_eq!(
            dict.next_id(),
            prior_next,
            "global dict must roll back on symbol resolution failure",
        );
    }

    fn make_chunk_uuid(rows: &[[u8; 16]], validity: Option<&Validity>, ts: &[i64]) -> Vec<u8> {
        let mut chunk = Chunk::new("trades");
        chunk.column_uuid("id", rows, validity).unwrap();
        chunk.at_nanos(ts).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();
        out
    }

    fn make_chunk_ts_micros(vals: &[i64], validity: Option<&Validity>, ts: &[i64]) -> Vec<u8> {
        let mut chunk = Chunk::new("trades");
        chunk
            .column_ts("t", vals, TimestampUnit::Micros, validity)
            .unwrap();
        chunk.at_nanos(ts).unwrap();
        let mut out = Vec::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, &chunk, &mut dict, &mut scratch, false).unwrap();
        out
    }

    #[test]
    fn all_valid_validity_matches_no_validity_uuid() {
        let rows = [[1u8; 16], [2u8; 16], [3u8; 16]];
        let ts = [1i64, 2, 3];
        let bits = [0b0000_0111u8];
        let v = Validity::from_bitmap(&bits, 3).unwrap();
        assert_eq!(
            make_chunk_uuid(&rows, Some(&v), &ts),
            make_chunk_uuid(&rows, None, &ts),
            "an all-valid validity must encode like no validity: null_flag=0, no bitmap"
        );
    }

    #[test]
    fn all_valid_validity_matches_no_validity_timestamp() {
        let vals = [100i64, 200, 300];
        let ts = [1i64, 2, 3];
        let bits = [0b0000_0111u8];
        let v = Validity::from_bitmap(&bits, 3).unwrap();
        assert_eq!(
            make_chunk_ts_micros(&vals, Some(&v), &ts),
            make_chunk_ts_micros(&vals, None, &ts),
        );
    }

    #[test]
    fn validity_with_null_emits_bitmap_uuid() {
        let rows = [[1u8; 16], [2u8; 16], [3u8; 16]];
        let ts = [1i64, 2, 3];
        let bits = [0b0000_0101u8]; // row 1 null
        let v = Validity::from_bitmap(&bits, 3).unwrap();
        assert_ne!(
            make_chunk_uuid(&rows, Some(&v), &ts),
            make_chunk_uuid(&rows, None, &ts),
            "a real null must emit a bitmap and drop the null row's payload"
        );
    }

    #[test]
    fn uuid_payload_is_byte_verbatim() {
        // QuestDB wire order is the caller's 16 bytes verbatim (low 64 bits
        // little-endian then high 64 bits little-endian). A reordering bug
        // would corrupt every UUID, so pin the passthrough.
        let uuid = [
            0x00u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let out = make_chunk_uuid(&[uuid], None, &[1i64]);
        assert!(
            out.windows(16).any(|w| w == uuid),
            "UUID bytes must appear verbatim in the wire frame"
        );
    }

    #[test]
    fn symbol_gid_table_is_pooled_and_reused_across_flushes() {
        // The per-symbol-column `slot -> global id` table is reclaimed into the
        // scratch free list on reset and reused next flush, rather than allocating
        // a fresh Vec<u64> per row-symbol column per flush. The reused buffer is
        // cleared/refilled, not stale, so the wire is unchanged. (The chunk borrows
        // these arrays zero-copy, so they must outlive it.)
        let codes = [0i32, 1, 0];
        let dict_offsets = [0i32, 4, 8];
        let ts = [1i64, 2, 3];

        let mut scratch = EncodeScratch::new();

        // Flush 1 (fresh dict): interns AAPL, MSFT and builds the slot->gid table.
        let mut chunk1 = Chunk::new("trades");
        chunk1
            .symbol_i32("sym", &codes, &dict_offsets, b"AAPLMSFT", None)
            .unwrap();
        chunk1.at_nanos(&ts).unwrap();
        let mut dict1 = SymbolGlobalDict::new();
        let mut out1 = Vec::new();
        encode_chunk_into(&mut out1, &chunk1, &mut dict1, &mut scratch, false).unwrap();

        // A reset after the flush reclaims the table into the free list.
        scratch.reset();
        assert!(
            !scratch.symbol_gid_pool.is_empty(),
            "the symbol gid table must be reclaimed into the free list on reset"
        );

        // Flush 2 (fresh dict) pops the pooled table; the wire must match flush 1.
        let mut chunk2 = Chunk::new("trades");
        chunk2
            .symbol_i32("sym", &codes, &dict_offsets, b"AAPLMSFT", None)
            .unwrap();
        chunk2.at_nanos(&ts).unwrap();
        let mut dict2 = SymbolGlobalDict::new();
        let mut out2 = Vec::new();
        encode_chunk_into(&mut out2, &chunk2, &mut dict2, &mut scratch, false).unwrap();

        assert_eq!(out1, out2, "pooled reuse must not change the encoded wire");
    }

    #[cfg(feature = "arrow-ingress")]
    #[test]
    fn arrow_symbol_gids_are_pooled_and_reused_across_flushes() {
        // The arrow symbol path's per-column gids buffer is reclaimed into the same
        // scratch free list as the row path on reset, so a steady flow of
        // arrow-symbol flushes reuses it instead of allocating a fresh Vec<u64> per
        // column per flush. The reused buffer is cleared/refilled, so the wire is
        // unchanged.
        use crate::ingress::column_sender::arrow_batch;
        use arrow::array::{ArrayRef, StringArray};
        use std::sync::Arc;

        let build = || {
            let arr: ArrayRef = Arc::new(StringArray::from(vec!["AAPL", "MSFT", "AAPL"]));
            let mut chunk = Chunk::new("trades");
            chunk
                .push_arrow_deferred("sym", arrow_batch::ColumnKind::SymbolUtf8, arr)
                .unwrap();
            chunk.at_nanos(&[1i64, 2, 3]).unwrap();
            chunk
        };

        let mut scratch = EncodeScratch::new();

        let chunk1 = build();
        let mut dict1 = SymbolGlobalDict::new();
        let mut out1 = Vec::new();
        encode_chunk_into(&mut out1, &chunk1, &mut dict1, &mut scratch, false).unwrap();

        // A reset after the flush reclaims the arrow gids buffer into the free list.
        scratch.reset();
        assert!(
            !scratch.symbol_gid_pool.is_empty(),
            "the arrow symbol gids buffer must be reclaimed into the free list on reset"
        );

        // Flush 2 pops the pooled buffer; the wire must match flush 1.
        let chunk2 = build();
        let mut dict2 = SymbolGlobalDict::new();
        let mut out2 = Vec::new();
        encode_chunk_into(&mut out2, &chunk2, &mut dict2, &mut scratch, false).unwrap();

        assert_eq!(
            out1, out2,
            "the reused gids buffer must be refilled, not stale"
        );
    }
}
