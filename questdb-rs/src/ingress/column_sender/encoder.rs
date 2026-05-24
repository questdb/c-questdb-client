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
//! Emits a single-table frame (one chunk = one table = one frame). Most
//! column payloads are already in wire shape inside the chunk (see
//! `chunk.rs`); symbol columns resolve to wire bytes here because their
//! global-id assignment is connection-scoped and chunks are
//! sender-agnostic until flushed.

use std::collections::HashMap;

use crate::ingress::buffer::SymbolGlobalDict;
use crate::{Result, error};

use super::chunk::{Chunk, ChunkColumn};
use super::wire::{
    MAX_NAME_LEN, QWP_FLAG_DELTA_SYMBOL_DICT, QWP_HEADER_LEN, QWP_MAGIC, QWP_SCHEMA_MODE_FULL,
    QWP_SCHEMA_MODE_REFERENCE, QWP_VERSION_1, validate_name, write_qwp_bytes, write_qwp_varint,
};

/// Connection-scoped table-schema interner.
///
/// Each unique signature gets a sequentially-assigned `u64` id. The first
/// emit for a signature uses `QWP_SCHEMA_MODE_FULL`; subsequent emits
/// reuse the id under `QWP_SCHEMA_MODE_REFERENCE`. Both sides of the wire
/// build the same id-by-first-emit mapping; on reconnect both sides reset.
#[derive(Debug, Default)]
pub(crate) struct SchemaRegistry {
    by_signature: HashMap<Vec<u8>, u64>,
    next_id: u64,
}

impl SchemaRegistry {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, signature: &[u8]) -> (u64, bool) {
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

/// Encode `chunk` into a QWP/WebSocket frame.
///
/// Returns the frame bytes ready to hand to
/// [`crate::ingress::Sender::qwp_ws_publish_raw`].
pub(crate) fn encode_chunk(
    chunk: &Chunk,
    schema_registry: &mut SchemaRegistry,
    global_dict: &mut SymbolGlobalDict,
) -> Result<Vec<u8>> {
    if chunk.is_empty() {
        return Ok(encode_header_only_frame());
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

    // Pass 1: resolve symbol columns against the connection-scoped global
    // dict so we know the delta-dict prefix BEFORE writing the table
    // block. We snapshot the dict's pre-encode size for the rollback
    // path below — if anything fails after we touched the dict, the
    // server has not yet seen those entries, so dropping them locally
    // keeps both sides in sync.
    let dict_mark = global_dict.mark();
    let resolution = match resolve_symbols(chunk, global_dict) {
        Ok(r) => r,
        Err(e) => {
            global_dict.rollback(dict_mark);
            return Err(e);
        }
    };

    // Build the schema signature (registry key + FULL-emit payload).
    let column_count = chunk.columns.len() + 1; // +1 for designated timestamp
    let mut signature = Vec::with_capacity(column_count * 8);
    for col in &chunk.columns {
        signature.extend_from_slice(col.signature());
    }
    write_qwp_bytes(&mut signature, &[]);
    signature.push(designated.wire_type);

    let (schema_id, is_new_schema) = schema_registry.intern(&signature);

    // Pre-allocate the full frame.
    let symbol_payload_estimate = resolution
        .per_column_payload
        .iter()
        .filter_map(|p| p.as_ref().map(|v| v.len()))
        .sum::<usize>();
    let resolved_payload_estimate = chunk
        .columns
        .iter()
        .filter_map(|c| match c {
            ChunkColumn::Resolved { payload, .. } => Some(payload.len()),
            ChunkColumn::Symbol { .. } => None,
        })
        .sum::<usize>();
    let payload_estimate = 1 + 10 // dict prefix base (delta_start + count varints)
        + resolution.delta_symbol_bytes_estimate
        + 1 + table_bytes.len()
        + 10
        + 1 + 10 + signature.len()
        + resolved_payload_estimate
        + symbol_payload_estimate
        + designated.payload.len();
    let mut frame = Vec::with_capacity(QWP_HEADER_LEN + payload_estimate);

    write_header_placeholder(&mut frame, /* table_count = */ 1);
    let payload_start = frame.len();

    // Delta-symbol-dict prefix.
    write_qwp_varint(&mut frame, resolution.delta_start);
    write_qwp_varint(&mut frame, resolution.new_symbols.len() as u64);
    for bytes in &resolution.new_symbols {
        write_qwp_bytes(&mut frame, bytes);
    }

    // Table block header.
    write_qwp_bytes(&mut frame, table_bytes);
    write_qwp_varint(&mut frame, row_count as u64);
    write_qwp_varint(&mut frame, column_count as u64);

    // Schema section.
    if is_new_schema {
        frame.push(QWP_SCHEMA_MODE_FULL);
        write_qwp_varint(&mut frame, schema_id);
        frame.extend_from_slice(&signature);
    } else {
        frame.push(QWP_SCHEMA_MODE_REFERENCE);
        write_qwp_varint(&mut frame, schema_id);
    }

    // Column payloads.
    for (col_idx, col) in chunk.columns.iter().enumerate() {
        match col {
            ChunkColumn::Resolved { payload, .. } => {
                frame.extend_from_slice(payload);
            }
            ChunkColumn::Symbol { .. } => {
                let payload = resolution.per_column_payload[col_idx]
                    .as_ref()
                    .expect("symbol payload must have been resolved");
                frame.extend_from_slice(payload);
            }
        }
    }
    frame.extend_from_slice(&designated.payload);

    let payload_len = (frame.len() - payload_start) as u32;
    frame[8..12].copy_from_slice(&payload_len.to_le_bytes());
    Ok(frame)
}

struct SymbolResolution {
    /// Pre-existing global dict size at encode start; the delta-dict
    /// prefix tells the server "ids `delta_start..delta_start +
    /// new_symbols.len()` are these new entries".
    delta_start: u64,
    /// New entries, in the order their ids were assigned.
    new_symbols: Vec<Vec<u8>>,
    /// Conservative byte estimate for the delta-dict prefix.
    delta_symbol_bytes_estimate: usize,
    /// One per column slot; `Some` for symbol columns (wire-shape bytes
    /// for that column), `None` for resolved columns.
    per_column_payload: Vec<Option<Vec<u8>>>,
}

fn resolve_symbols(chunk: &Chunk, global_dict: &mut SymbolGlobalDict) -> Result<SymbolResolution> {
    let delta_start = global_dict_len(global_dict);
    let mut new_symbols: Vec<Vec<u8>> = Vec::new();
    let mut delta_symbol_bytes_estimate: usize = 0;
    let mut per_column_payload: Vec<Option<Vec<u8>>> = Vec::with_capacity(chunk.columns.len());

    for col in &chunk.columns {
        match col {
            ChunkColumn::Resolved { .. } => per_column_payload.push(None),
            ChunkColumn::Symbol {
                row_count,
                codes,
                bitmap,
                non_null_count,
                referenced_symbols,
                ..
            } => {
                // Map each referenced symbol's internal index → global id,
                // remembering new ids so we can append them to the
                // delta-dict prefix.
                let mut internal_to_global = Vec::with_capacity(referenced_symbols.len());
                for bytes in referenced_symbols {
                    let (gid, is_new) = global_dict.intern(bytes);
                    if is_new {
                        delta_symbol_bytes_estimate += 5 + bytes.len();
                        new_symbols.push(bytes.clone());
                    }
                    internal_to_global.push(gid);
                }

                // Build the column's wire payload: null_flag + optional
                // bitmap + dense varint global ids for non-null rows.
                let mut payload = Vec::with_capacity(
                    1 + bitmap.as_ref().map_or(0, |b| b.len()) + non_null_count * 4,
                );
                match bitmap {
                    None => payload.push(0),
                    Some(bm) => {
                        payload.push(1);
                        payload.extend_from_slice(bm);
                    }
                }
                for (i, &internal) in codes.iter().enumerate() {
                    let valid = bitmap.as_ref().is_none_or(|bm| qwp_bit_is_valid(bm, i));
                    if !valid {
                        continue;
                    }
                    debug_assert!(
                        internal != u32::MAX,
                        "valid symbol row at index {i} had sentinel code"
                    );
                    let gid = internal_to_global[internal as usize];
                    write_qwp_varint(&mut payload, gid);
                }
                // Sanity-check: we wrote exactly `non_null_count` ids.
                debug_assert_eq!(
                    *non_null_count,
                    count_non_null(*row_count, bitmap.as_deref())
                );
                per_column_payload.push(Some(payload));
            }
        }
    }

    Ok(SymbolResolution {
        delta_start,
        new_symbols,
        delta_symbol_bytes_estimate,
        per_column_payload,
    })
}

fn write_header_placeholder(frame: &mut Vec<u8>, table_count: u16) {
    frame.extend_from_slice(&QWP_MAGIC);
    frame.push(QWP_VERSION_1);
    frame.push(QWP_FLAG_DELTA_SYMBOL_DICT);
    frame.extend_from_slice(&table_count.to_le_bytes());
    frame.extend_from_slice(&0u32.to_le_bytes()); // payload_len, patched after
}

fn encode_header_only_frame() -> Vec<u8> {
    let mut frame = Vec::with_capacity(QWP_HEADER_LEN + 2);
    write_header_placeholder(&mut frame, 0);
    let payload_start = frame.len();
    write_qwp_varint(&mut frame, 0); // delta_start
    write_qwp_varint(&mut frame, 0); // new_symbols_count
    let payload_len = (frame.len() - payload_start) as u32;
    frame[8..12].copy_from_slice(&payload_len.to_le_bytes());
    frame
}

/// Inspect the QWP-shape bitmap (bit = 1 means NULL): return `true` iff
/// row `i` is valid.
#[inline]
fn qwp_bit_is_valid(bitmap: &[u8], i: usize) -> bool {
    (bitmap[i / 8] >> (i % 8)) & 1 == 0
}

#[inline]
fn count_non_null(row_count: usize, bitmap: Option<&[u8]>) -> usize {
    match bitmap {
        None => row_count,
        Some(bm) => (0..row_count).filter(|&i| qwp_bit_is_valid(bm, i)).count(),
    }
}

/// Pre-encode size of the connection-scoped global dict — the
/// `delta_start` field of the QWP delta-symbol-dict prefix.
fn global_dict_len(global_dict: &SymbolGlobalDict) -> u64 {
    global_dict.next_id()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::column_sender::Validity;

    fn empty_chunk(table: &str) -> Chunk {
        Chunk::new(table)
    }

    #[test]
    fn empty_chunk_encodes_to_14_bytes() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let frame = encode_chunk(&empty_chunk("trades"), &mut reg, &mut dict).unwrap();
        assert_eq!(frame.len(), 14);
        assert_eq!(&frame[0..4], b"QWP1");
        assert_eq!(frame[5], QWP_FLAG_DELTA_SYMBOL_DICT);
        assert_eq!(u16::from_le_bytes([frame[6], frame[7]]), 0);
    }

    #[test]
    fn non_empty_chunk_without_designated_ts_errors() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut chunk = Chunk::new("trades");
        chunk.column_i64("a", &[1, 2, 3], None).unwrap();
        let err = encode_chunk(&chunk, &mut reg, &mut dict).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("designated"));
    }

    #[test]
    fn second_encode_with_same_schema_uses_reference() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut c1 = Chunk::new("trades");
        c1.column_i64("price", &[1, 2], None).unwrap();
        c1.designated_timestamp_nanos(&[10, 20]).unwrap();
        let frame1 = encode_chunk(&c1, &mut reg, &mut dict).unwrap();

        let mut c2 = Chunk::new("trades");
        c2.column_i64("price", &[3, 4], None).unwrap();
        c2.designated_timestamp_nanos(&[30, 40]).unwrap();
        let frame2 = encode_chunk(&c2, &mut reg, &mut dict).unwrap();

        assert!(frame2.len() < frame1.len());
        assert_eq!(reg.len(), 1, "schema signature interned once");

        let schema_mode_offset = 12 + 1 + 1 + 1 + "trades".len() + 1 + 1;
        assert_eq!(frame1[schema_mode_offset], QWP_SCHEMA_MODE_FULL);
        assert_eq!(frame2[schema_mode_offset], QWP_SCHEMA_MODE_REFERENCE);
    }

    #[test]
    fn distinct_schemas_get_distinct_ids() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut a = Chunk::new("a");
        a.column_i64("x", &[1], None).unwrap();
        a.designated_timestamp_nanos(&[1]).unwrap();
        encode_chunk(&a, &mut reg, &mut dict).unwrap();

        let mut b = Chunk::new("b");
        b.column_f64("y", &[1.0], None).unwrap();
        b.designated_timestamp_nanos(&[1]).unwrap();
        encode_chunk(&b, &mut reg, &mut dict).unwrap();

        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn frame_size_grows_with_column_payloads() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut chunk = Chunk::new("trades");
        let bits = [0xFFu8];
        let v = Validity::from_bitmap(&bits, 4).unwrap();
        chunk.column_i64("price", &[1, 2, 3, 4], Some(&v)).unwrap();
        chunk.designated_timestamp_nanos(&[1, 2, 3, 4]).unwrap();
        let frame = encode_chunk(&chunk, &mut reg, &mut dict).unwrap();
        assert!(frame.len() > 32);
    }

    #[test]
    fn symbol_dict_emits_only_referenced_entries() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();

        let mut chunk = Chunk::new("trades");
        // Caller dict has 3 entries; rows only reference "alpha" and "gamma".
        let dict_bytes = b"alphabetagamma";
        let dict_offsets: [i32; 4] = [0, 5, 9, 14];
        chunk
            .symbol_dict_i32(
                "sym",
                &[0, 2, 0, 2], // alpha, gamma, alpha, gamma
                &dict_offsets,
                dict_bytes,
                None,
            )
            .unwrap();
        chunk.designated_timestamp_nanos(&[1, 2, 3, 4]).unwrap();
        let _frame = encode_chunk(&chunk, &mut reg, &mut dict).unwrap();
        // Global dict should have grown by exactly 2 (alpha, gamma) — beta
        // is never sent because no row references it.
        assert_eq!(global_dict_len(&dict), 2);
    }

    #[test]
    fn symbol_dict_second_frame_resends_only_new_entries() {
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let dict_bytes = b"alphabetagamma";
        let dict_offsets: [i32; 4] = [0, 5, 9, 14];

        let mut c1 = Chunk::new("trades");
        c1.symbol_dict_i32("sym", &[0, 1], &dict_offsets, dict_bytes, None)
            .unwrap();
        c1.designated_timestamp_nanos(&[1, 2]).unwrap();
        encode_chunk(&c1, &mut reg, &mut dict).unwrap();
        assert_eq!(global_dict_len(&dict), 2); // alpha, beta

        let mut c2 = Chunk::new("trades");
        // alpha (cached) + gamma (new).
        c2.symbol_dict_i32("sym", &[0, 2], &dict_offsets, dict_bytes, None)
            .unwrap();
        c2.designated_timestamp_nanos(&[3, 4]).unwrap();
        encode_chunk(&c2, &mut reg, &mut dict).unwrap();
        assert_eq!(global_dict_len(&dict), 3, "gamma added on second frame");
    }

    #[test]
    fn symbol_dict_rejects_out_of_range_code() {
        let mut chunk = Chunk::new("trades");
        let dict_bytes = b"alpha";
        let dict_offsets: [i32; 2] = [0, 5];
        let err = chunk
            .symbol_dict_i32("sym", &[0, 99], &dict_offsets, dict_bytes, None)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("out of range"));
    }

    #[test]
    fn symbol_dict_skips_null_codes() {
        let mut chunk = Chunk::new("trades");
        let dict_bytes = b"alpha";
        let dict_offsets: [i32; 2] = [0, 5];
        // Code 99 is out of range, but row 1 is null so its code is not
        // validated.
        let bits = [0b0000_0001];
        let v = Validity::from_bitmap(&bits, 2).unwrap();
        chunk
            .symbol_dict_i32("sym", &[0, 99], &dict_offsets, dict_bytes, Some(&v))
            .expect("null row's bogus code is ignored");
    }
}
