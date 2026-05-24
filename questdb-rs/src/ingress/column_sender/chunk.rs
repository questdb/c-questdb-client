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

//! Column-major chunk: one DataFrame's worth of column buffers destined for
//! a single QuestDB table.
//!
//! The user calls [`Chunk::new`] with a table name, fills it with one
//! `column_*` call per column, optionally pins a designated timestamp, and
//! hands it to [`super::ColumnSender::flush`]. Each `column_*` writes the
//! column straight into wire-shape `Vec<u8>` storage so the flush-time
//! encoder only does a header + per-column `extend_from_slice`.

use std::fmt::{self, Debug, Formatter};

use crate::{Result, error};

use super::validity::{Validity, check_row_count};
use super::wire::{
    F32_NULL, F64_NULL, I8_NULL, I16_NULL, I32_NULL, I64_NULL, QWP_TYPE_BOOLEAN, QWP_TYPE_BYTE,
    QWP_TYPE_DATE, QWP_TYPE_DOUBLE, QWP_TYPE_FLOAT, QWP_TYPE_INT, QWP_TYPE_IPV4, QWP_TYPE_LONG,
    QWP_TYPE_LONG256, QWP_TYPE_SHORT, QWP_TYPE_SYMBOL, QWP_TYPE_TIMESTAMP,
    QWP_TYPE_TIMESTAMP_NANOS, QWP_TYPE_UUID, QWP_TYPE_VARCHAR, validate_name, write_qwp_bytes,
};

/// One column in a chunk.
///
/// Numeric and fixed-width columns are pre-encoded to wire shape at
/// append time and stored as [`ChunkColumn::Resolved`]. Symbol columns
/// stage their codes + referenced dict bytes and resolve to wire shape
/// at flush time ([`ChunkColumn::Symbol`]) because the global symbol id
/// is connection-scoped and chunks are sender-agnostic until flushed.
pub(crate) enum ChunkColumn {
    Resolved {
        #[allow(dead_code)]
        name: String,
        /// `name_len_varint || name_bytes || wire_type_byte`.
        signature_chunk: Vec<u8>,
        /// `payload[0]` is the null-flag byte; `payload[1..]` is the
        /// per-type body (optional bitmap then dense values, or
        /// row-count dense values for the no-bitmap shape).
        payload: Vec<u8>,
    },
    Symbol {
        #[allow(dead_code)]
        name: String,
        signature_chunk: Vec<u8>,
        row_count: usize,
        /// Per-row index into `referenced_symbols`. For null rows the
        /// value is unspecified — the encoder consults the bitmap before
        /// touching the code.
        codes: Vec<u32>,
        /// QWP-shape null bitmap (bit = 1 means NULL). `None` when the
        /// column has no nulls — encoder emits `null_flag = 0`.
        bitmap: Option<Vec<u8>>,
        non_null_count: usize,
        /// Compact list of dict entries this column actually references,
        /// indexed by the values in `codes`. Bounded by the chunk's
        /// per-column cardinality rather than the (potentially huge)
        /// caller dict.
        referenced_symbols: Vec<Vec<u8>>,
    },
}

impl ChunkColumn {
    pub(crate) fn signature(&self) -> &[u8] {
        match self {
            Self::Resolved {
                signature_chunk, ..
            }
            | Self::Symbol {
                signature_chunk, ..
            } => signature_chunk,
        }
    }

    fn name(&self) -> &str {
        match self {
            Self::Resolved { name, .. } | Self::Symbol { name, .. } => name,
        }
    }

    #[cfg(test)]
    pub(crate) fn resolved_payload(&self) -> &[u8] {
        match self {
            Self::Resolved { payload, .. } => payload,
            Self::Symbol { .. } => panic!("not a Resolved column"),
        }
    }
}

/// Designated timestamp slot. Required exactly once per chunk before flush.
pub(crate) struct DesignatedTimestamp {
    /// `QWP_TYPE_TIMESTAMP` (0x0A) for micros, `QWP_TYPE_TIMESTAMP_NANOS`
    /// (0x10) for nanos.
    pub(crate) wire_type: u8,
    /// Already wire-shape: `null_flag=0` then `row_count * 8` bytes of LE
    /// i64. Designated timestamps are non-null per the wire spec, so no
    /// bitmap path.
    pub(crate) payload: Vec<u8>,
}

/// One DataFrame's worth of column buffers destined for one QuestDB table.
///
/// Builders mutate the chunk in-place; on a successful
/// [`super::ColumnSender::flush`] it is cleared (its per-column `Vec<u8>`
/// allocations are retained for the next DataFrame).
pub struct Chunk {
    pub(crate) table: String,
    /// Locked by the first `column_*` call. `None` means the chunk has no
    /// columns yet and the next append will set it.
    pub(crate) row_count: Option<usize>,
    pub(crate) columns: Vec<ChunkColumn>,
    pub(crate) designated_ts: Option<DesignatedTimestamp>,
}

impl Chunk {
    /// Create a chunk for `table`. The table name is validated at flush
    /// time against the QWP/Java client length cap (127 bytes UTF-8).
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            row_count: None,
            columns: Vec::new(),
            designated_ts: None,
        }
    }

    /// Table name the chunk's rows will land in.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Number of rows in the chunk. Locked by the first column append;
    /// returns `0` before any column has been appended.
    pub fn row_count(&self) -> usize {
        self.row_count.unwrap_or(0)
    }

    /// `true` iff the chunk has no columns and no designated timestamp.
    pub fn is_empty(&self) -> bool {
        self.row_count.is_none() && self.designated_ts.is_none()
    }

    /// Reset the chunk for reuse: clears all rows but keeps each column's
    /// allocated capacity. Called automatically after a successful flush.
    pub fn clear(&mut self) {
        self.row_count = None;
        // Drop the column slots; we keep the outer Vec's capacity so the
        // next chunk's `push_column` reuses the slot count without
        // reallocating the Vec itself.
        self.columns.clear();
        self.designated_ts = None;
    }

    // ------------------------------------------------------------------
    // Numeric & fixed-width columns
    // ------------------------------------------------------------------

    /// `BYTE` column. Nullable rows are sentinel-encoded as 0 on the wire.
    pub fn column_i8(
        &mut self,
        name: &str,
        data: &[i8],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        let mut payload = new_payload();
        payload.push(0); // null_flag
        match validity {
            None => {
                // Safety: `i8` and `u8` have identical layout; the cast
                // gives a byte slice without copying.
                let bytes: &[u8] =
                    unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len()) };
                payload.extend_from_slice(bytes);
            }
            Some(v) => {
                for (i, &value) in data.iter().enumerate() {
                    let out = if v.is_valid(i) { value } else { I8_NULL };
                    payload.push(out as u8);
                }
            }
        }
        self.push_column(name, QWP_TYPE_BYTE, payload, row_count)
    }

    /// `SHORT` column. Nullable rows are sentinel-encoded as 0.
    pub fn column_i16(
        &mut self,
        name: &str,
        data: &[i16],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_numeric(
            self,
            name,
            QWP_TYPE_SHORT,
            data,
            validity,
            I16_NULL,
            i16::to_le_bytes,
        )
    }

    /// `INT` column. Nullable rows are sentinel-encoded as `i32::MIN`.
    pub fn column_i32(
        &mut self,
        name: &str,
        data: &[i32],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_numeric(
            self,
            name,
            QWP_TYPE_INT,
            data,
            validity,
            I32_NULL,
            i32::to_le_bytes,
        )
    }

    /// `LONG` column. Nullable rows are sentinel-encoded as `i64::MIN`.
    pub fn column_i64(
        &mut self,
        name: &str,
        data: &[i64],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_numeric(
            self,
            name,
            QWP_TYPE_LONG,
            data,
            validity,
            I64_NULL,
            i64::to_le_bytes,
        )
    }

    /// `FLOAT` column. Nullable rows are sentinel-encoded as `NaN`.
    pub fn column_f32(
        &mut self,
        name: &str,
        data: &[f32],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_numeric(
            self,
            name,
            QWP_TYPE_FLOAT,
            data,
            validity,
            F32_NULL,
            f32::to_le_bytes,
        )
    }

    /// `DOUBLE` column. Nullable rows are sentinel-encoded as `NaN`.
    pub fn column_f64(
        &mut self,
        name: &str,
        data: &[f64],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_numeric(
            self,
            name,
            QWP_TYPE_DOUBLE,
            data,
            validity,
            F64_NULL,
            f64::to_le_bytes,
        )
    }

    /// `BOOLEAN` column. `data` is an Arrow-style LSB-first packed bitmap
    /// (1 = true). Nullable rows are encoded as `false` on the wire — the
    /// row-API + QuestDB convention.
    pub fn column_bool(
        &mut self,
        name: &str,
        data: &[u8],
        row_count: usize,
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        let bytes_required = row_count.div_ceil(8);
        if data.len() < bytes_required {
            return Err(error::fmt!(
                InvalidApiCall,
                "Boolean column data too short: {} bytes for {} rows (need at least {})",
                data.len(),
                row_count,
                bytes_required
            ));
        }
        let row_count = check_row_count(self.row_count, row_count, validity)?;
        let mut payload = new_payload();
        payload.push(0); // null_flag — bool always uses sentinel encoding

        let mut packed = 0u8;
        let mut bit_idx = 0u8;
        for i in 0..row_count {
            let bit = (data[i / 8] >> (i % 8)) & 1;
            let valid = validity.is_none_or(|v| v.is_valid(i));
            if bit == 1 && valid {
                packed |= 1u8 << bit_idx;
            }
            bit_idx += 1;
            if bit_idx == 8 {
                payload.push(packed);
                packed = 0;
                bit_idx = 0;
            }
        }
        if bit_idx != 0 {
            payload.push(packed);
        }
        self.push_column(name, QWP_TYPE_BOOLEAN, payload, row_count)
    }

    // ------------------------------------------------------------------
    // Bitmap-style fixed-width columns (sparse-null types)
    // ------------------------------------------------------------------

    /// `UUID` column. `data[i]` is a 16-byte UUID per row (bytes 0..8 lo
    /// half LE, 8..16 hi half LE — same layout as the row-API path).
    pub fn column_uuid(
        &mut self,
        name: &str,
        data: &[[u8; 16]],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_fixed_width_bitmap(self, name, QWP_TYPE_UUID, data, validity, 16)
    }

    /// `LONG256` column. `data[i]` is a 32-byte LONG256 per row (4 LE
    /// 64-bit limbs, least-significant first).
    pub fn column_long256(
        &mut self,
        name: &str,
        data: &[[u8; 32]],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_fixed_width_bitmap(self, name, QWP_TYPE_LONG256, data, validity, 32)
    }

    /// `IPV4` column. Each `data[i]` is a `u32::from(Ipv4Addr)` (octet 0
    /// in the high byte) encoded little-endian on the wire.
    pub fn column_ipv4(
        &mut self,
        name: &str,
        data: &[u32],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_bitmap(self, name, QWP_TYPE_IPV4, data, validity, u32::to_le_bytes)
    }

    /// `TIMESTAMP_NANOS` column (wire type `0x10`).
    pub fn column_ts_nanos(
        &mut self,
        name: &str,
        data: &[i64],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_bitmap(
            self,
            name,
            QWP_TYPE_TIMESTAMP_NANOS,
            data,
            validity,
            i64::to_le_bytes,
        )
    }

    /// `TIMESTAMP` (microseconds) column (wire type `0x0A`).
    pub fn column_ts_micros(
        &mut self,
        name: &str,
        data: &[i64],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_bitmap(
            self,
            name,
            QWP_TYPE_TIMESTAMP,
            data,
            validity,
            i64::to_le_bytes,
        )
    }

    /// `DATE` column. Milliseconds since the Unix epoch on the wire.
    pub fn column_date_millis(
        &mut self,
        name: &str,
        data: &[i64],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        encode_le_bitmap(self, name, QWP_TYPE_DATE, data, validity, i64::to_le_bytes)
    }

    // ------------------------------------------------------------------
    // Variable-width text (VARCHAR)
    // ------------------------------------------------------------------

    /// `VARCHAR` column (QWP wire type `0x0F`).
    ///
    /// Input is Arrow Utf8 shape: `offsets` has `row_count + 1` entries,
    /// monotonically non-decreasing, where `bytes[offsets[i]..offsets[i+1]]`
    /// is the value for row `i`. `offsets[0]` may be non-zero (the column
    /// encoder rebases to 0 on the wire).
    ///
    /// Wire output: dense (only non-null values), `non_null_count + 1`
    /// little-endian u32 offsets starting at 0, followed by the
    /// concatenated bytes of the non-null rows.
    ///
    /// UTF-8 validity is the caller's responsibility; invalid UTF-8 is
    /// detected by the server and surfaced as a server rejection.
    pub fn column_varchar(
        &mut self,
        name: &str,
        offsets: &[i32],
        bytes: &[u8],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        // Arrow Utf8 layout: offsets length is row_count + 1. We can't
        // call `check_row_count(.. offsets.len() ..)` because the data is
        // really `offsets.len() - 1` rows.
        if offsets.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "VARCHAR offsets must have at least one entry (row_count + 1)"
            ));
        }
        let row_count = offsets.len() - 1;
        let row_count = check_row_count(self.row_count, row_count, validity)?;

        validate_varchar_offsets(offsets, bytes.len())?;

        let mut payload = new_payload();
        match validity {
            None => {
                payload.push(0); // null_flag
                // Rebase offsets to start at 0 and write them as LE u32.
                payload.reserve(4 * (row_count + 1) + bytes.len());
                let base = offsets[0];
                if base == 0 {
                    // Common case: contiguous arrow buffer, base == 0 — the
                    // i32 LE bytes are bit-identical to u32 LE bytes for
                    // non-negative values, so memcpy the offset table.
                    let offset_bytes: &[u8] = unsafe {
                        std::slice::from_raw_parts(
                            offsets.as_ptr().cast::<u8>(),
                            std::mem::size_of_val(offsets),
                        )
                    };
                    payload.extend_from_slice(offset_bytes);
                    // Bytes: copy the in-use slice (caller's buffer may be
                    // longer than the last offset).
                    let used = offsets[row_count] as usize;
                    payload.extend_from_slice(&bytes[..used]);
                } else {
                    for &offset in offsets {
                        let normalized = (offset - base) as u32;
                        payload.extend_from_slice(&normalized.to_le_bytes());
                    }
                    let start = base as usize;
                    let end = offsets[row_count] as usize;
                    payload.extend_from_slice(&bytes[start..end]);
                }
            }
            Some(v) => {
                payload.push(1); // null_flag — bitmap follows
                v.write_qwp_bitmap(&mut payload);

                // Dense offsets: walk non-null rows once, then append the
                // matching bytes. We size the offset table conservatively
                // and patch it as we go to avoid a separate pass.
                let non_null = v.non_null_count();
                let offsets_start = payload.len();
                payload.resize(offsets_start + 4 * (non_null + 1), 0);
                // First dense offset is always 0.
                payload[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());

                let mut cumulative: u32 = 0;
                let mut next_offset_idx = 1usize;
                let bytes_anchor = payload.len();
                for i in 0..row_count {
                    if !v.is_valid(i) {
                        continue;
                    }
                    // Skip slicing for null rows — caller's offsets there
                    // are not trusted (Arrow allows arbitrary values).
                    let start = offsets[i] as usize;
                    let end = offsets[i + 1] as usize;
                    let len = end - start;
                    payload.extend_from_slice(&bytes[start..end]);
                    let new_cumulative = cumulative.checked_add(len as u32).ok_or_else(|| {
                        error::fmt!(InvalidApiCall, "VARCHAR column bytes exceed u32::MAX")
                    })?;
                    cumulative = new_cumulative;
                    let off = offsets_start + 4 * next_offset_idx;
                    payload[off..off + 4].copy_from_slice(&cumulative.to_le_bytes());
                    next_offset_idx += 1;
                }
                debug_assert_eq!(next_offset_idx - 1, non_null);
                debug_assert_eq!(payload.len() - bytes_anchor, cumulative as usize);
            }
        }
        self.push_column(name, QWP_TYPE_VARCHAR, payload, row_count)
    }

    // ------------------------------------------------------------------
    // Symbol columns (dictionary-encoded fast path)
    // ------------------------------------------------------------------

    /// `SYMBOL` column with `i8` dictionary codes (max dict cardinality
    /// 128 — caller should promote to `i16`/`i32` for larger dicts).
    pub fn symbol_dict_i8(
        &mut self,
        name: &str,
        codes: &[i8],
        dict_offsets: &[i32],
        dict_bytes: &[u8],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        push_symbol_column(
            self,
            name,
            codes,
            |c| *c as i32,
            dict_offsets,
            dict_bytes,
            validity,
        )
    }

    /// `SYMBOL` column with `i16` dictionary codes.
    pub fn symbol_dict_i16(
        &mut self,
        name: &str,
        codes: &[i16],
        dict_offsets: &[i32],
        dict_bytes: &[u8],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        push_symbol_column(
            self,
            name,
            codes,
            |c| *c as i32,
            dict_offsets,
            dict_bytes,
            validity,
        )
    }

    /// `SYMBOL` column with `i32` dictionary codes — the Pandas
    /// `Categorical` / Polars `Categorical` shape.
    pub fn symbol_dict_i32(
        &mut self,
        name: &str,
        codes: &[i32],
        dict_offsets: &[i32],
        dict_bytes: &[u8],
        validity: Option<&Validity<'_>>,
    ) -> Result<&mut Self> {
        push_symbol_column(
            self,
            name,
            codes,
            |c| *c,
            dict_offsets,
            dict_bytes,
            validity,
        )
    }

    // ------------------------------------------------------------------
    // Designated timestamp
    // ------------------------------------------------------------------

    /// Designated timestamp in microseconds since the Unix epoch (wire
    /// type `TIMESTAMP` 0x0A). Required exactly once per chunk before
    /// flush. Designated timestamps must be non-null per the wire spec —
    /// there is no validity bitmap.
    pub fn designated_timestamp_micros(&mut self, data: &[i64]) -> Result<&mut Self> {
        self.set_designated_ts(QWP_TYPE_TIMESTAMP, data)
    }

    /// Designated timestamp in nanoseconds since the Unix epoch (wire
    /// type `TIMESTAMP_NANOS` 0x10).
    pub fn designated_timestamp_nanos(&mut self, data: &[i64]) -> Result<&mut Self> {
        self.set_designated_ts(QWP_TYPE_TIMESTAMP_NANOS, data)
    }

    fn set_designated_ts(&mut self, wire_type: u8, data: &[i64]) -> Result<&mut Self> {
        if self.designated_ts.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "designated timestamp already set on this chunk"
            ));
        }
        let row_count = check_row_count(self.row_count, data.len(), None)?;
        let mut payload = new_payload();
        payload.push(0); // null_flag — designated_ts is always non-null
        payload.reserve(8 * data.len());
        for &v in data {
            payload.extend_from_slice(&v.to_le_bytes());
        }
        self.row_count = Some(row_count);
        self.designated_ts = Some(DesignatedTimestamp { wire_type, payload });
        Ok(self)
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn push_column(
        &mut self,
        name: &str,
        wire_type: u8,
        payload: Vec<u8>,
        row_count: usize,
    ) -> Result<&mut Self> {
        validate_name("column", name)?;
        self.guard_unique_name(name)?;
        let signature_chunk = build_signature_chunk(name, wire_type);
        self.columns.push(ChunkColumn::Resolved {
            name: name.to_owned(),
            signature_chunk,
            payload,
        });
        self.row_count = Some(row_count);
        Ok(self)
    }

    fn guard_unique_name(&self, name: &str) -> Result<()> {
        if self.columns.iter().any(|c| c.name() == name) {
            return Err(error::fmt!(
                InvalidApiCall,
                "duplicate column name in chunk: {:?}",
                name
            ));
        }
        Ok(())
    }
}

fn build_signature_chunk(name: &str, wire_type: u8) -> Vec<u8> {
    let mut sig = Vec::with_capacity(1 + name.len() + 1);
    write_qwp_bytes(&mut sig, name.as_bytes());
    sig.push(wire_type);
    sig
}

fn new_payload() -> Vec<u8> {
    // 1 byte null_flag, room for a small bitmap, and most callers extend
    // immediately. 16 bytes is enough to avoid the first realloc for any
    // short column.
    Vec::with_capacity(16)
}

/// Bulk-intern a symbol column at append time.
///
/// Three passes (each O(row_count) or O(dict_len) but never the
/// product):
///   1. Walk `codes` once to mark which dict entries the chunk actually
///      references in a bitset. Validate range; reject out-of-range.
///   2. Walk the bitset to copy referenced dict entries into compact
///      `referenced_symbols` storage and build a `local → internal` map
///      keyed by dict index.
///   3. Walk `codes` again to translate to the compact internal indices
///      and build the QWP-shape bitmap from validity.
///
/// Defers the connection-scoped global-id assignment to flush time
/// because chunks are sender-agnostic — see `doc/COLUMN_SENDER_PLAN.md`.
fn push_symbol_column<'a, T, F>(
    chunk: &'a mut Chunk,
    name: &str,
    codes: &[T],
    to_i32: F,
    dict_offsets: &[i32],
    dict_bytes: &[u8],
    validity: Option<&Validity<'_>>,
) -> Result<&'a mut Chunk>
where
    F: Fn(&T) -> i32,
{
    let row_count = check_row_count(chunk.row_count, codes.len(), validity)?;
    validate_name("column", name)?;
    chunk.guard_unique_name(name)?;

    if dict_offsets.is_empty() {
        return Err(error::fmt!(
            InvalidApiCall,
            "symbol dict offsets must have at least one entry (dict_len + 1)"
        ));
    }
    validate_varchar_offsets(dict_offsets, dict_bytes.len())?;
    let dict_len = dict_offsets.len() - 1;

    // Pass 1: referenced bitset + range check.
    let mut referenced = vec![false; dict_len];
    let mut non_null_count = 0usize;
    for (i, code) in codes.iter().enumerate() {
        if !validity.is_none_or(|v| v.is_valid(i)) {
            continue;
        }
        let idx = to_i32(code);
        if idx < 0 || (idx as usize) >= dict_len {
            return Err(error::fmt!(
                InvalidApiCall,
                "symbol code out of range: row {} -> {} (dict_len = {})",
                i,
                idx,
                dict_len
            ));
        }
        referenced[idx as usize] = true;
        non_null_count += 1;
    }

    // Pass 2: compact referenced dict + build local-to-internal map.
    // `local_to_internal[d] == u32::MAX` for unreferenced entries; we
    // never index it with an unreferenced code (pass 1 marked them so
    // pass 3 only follows referenced entries). `dict_offsets` are
    // absolute byte offsets into `dict_bytes` per the Arrow Utf8 layout
    // (`validate_varchar_offsets` has already proven the slices are in
    // bounds and monotonic).
    let mut local_to_internal = vec![u32::MAX; dict_len];
    let mut referenced_symbols: Vec<Vec<u8>> = Vec::new();
    for (d, mark) in referenced.iter().enumerate() {
        if !*mark {
            continue;
        }
        let start = dict_offsets[d] as usize;
        let end = dict_offsets[d + 1] as usize;
        let internal = referenced_symbols.len() as u32;
        referenced_symbols.push(dict_bytes[start..end].to_vec());
        local_to_internal[d] = internal;
    }

    // Pass 3: translate codes to internal indices; build QWP bitmap.
    let mut compact_codes = Vec::with_capacity(codes.len());
    for (i, code) in codes.iter().enumerate() {
        if !validity.is_none_or(|v| v.is_valid(i)) {
            compact_codes.push(u32::MAX);
            continue;
        }
        let idx = to_i32(code) as usize;
        compact_codes.push(local_to_internal[idx]);
    }
    let bitmap = validity.map(|v| {
        let mut bm = Vec::with_capacity(row_count.div_ceil(8));
        v.write_qwp_bitmap(&mut bm);
        bm
    });

    let signature_chunk = build_signature_chunk(name, QWP_TYPE_SYMBOL);
    chunk.columns.push(ChunkColumn::Symbol {
        name: name.to_owned(),
        signature_chunk,
        row_count,
        codes: compact_codes,
        bitmap,
        non_null_count,
        referenced_symbols,
    });
    chunk.row_count = Some(row_count);
    Ok(chunk)
}

fn validate_varchar_offsets(offsets: &[i32], bytes_len: usize) -> Result<()> {
    // Arrow Utf8 promises monotonic non-decreasing offsets and that every
    // offset is ≤ bytes_len. We trust UTF-8 (server enforces) but cheap
    // bounds checking here saves the server an obvious parse error and
    // gives us a meaningful Rust-side error.
    let mut prev = offsets[0];
    if prev < 0 {
        return Err(error::fmt!(
            InvalidApiCall,
            "VARCHAR offsets must be non-negative (offsets[0] = {})",
            prev
        ));
    }
    for (i, &off) in offsets.iter().enumerate().skip(1) {
        if off < prev {
            return Err(error::fmt!(
                InvalidApiCall,
                "VARCHAR offsets must be non-decreasing (offsets[{}] = {} < offsets[{}] = {})",
                i,
                off,
                i - 1,
                prev
            ));
        }
        prev = off;
    }
    if (prev as usize) > bytes_len {
        return Err(error::fmt!(
            InvalidApiCall,
            "VARCHAR offsets exceed bytes buffer: last offset = {}, bytes_len = {}",
            prev,
            bytes_len
        ));
    }
    Ok(())
}

#[inline]
fn encode_le_numeric<'a, T, const N: usize, F>(
    chunk: &'a mut Chunk,
    name: &str,
    wire_type: u8,
    data: &[T],
    validity: Option<&Validity<'_>>,
    null_value: T,
    to_le: F,
) -> Result<&'a mut Chunk>
where
    T: Copy,
    F: Fn(T) -> [u8; N],
{
    let row_count = check_row_count(chunk.row_count, data.len(), validity)?;
    let mut payload = new_payload();
    payload.push(0); // null_flag — non-sparse-null types always use sentinels
    payload.reserve(N * row_count);
    match validity {
        None => {
            // Safety: `[T]` and the resulting `[u8]` view share the same
            // backing memory; `T` is a plain numeric POD so any byte
            // pattern is sound. This is the column-sender hot path — pure
            // memcpy.
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), std::mem::size_of_val(data))
            };
            payload.extend_from_slice(bytes);
        }
        Some(v) => {
            for (i, &value) in data.iter().enumerate() {
                let out = if v.is_valid(i) { value } else { null_value };
                payload.extend_from_slice(&to_le(out));
            }
        }
    }
    chunk.push_column(name, wire_type, payload, row_count)
}

#[inline]
fn encode_le_bitmap<'a, T, const N: usize, F>(
    chunk: &'a mut Chunk,
    name: &str,
    wire_type: u8,
    data: &[T],
    validity: Option<&Validity<'_>>,
    to_le: F,
) -> Result<&'a mut Chunk>
where
    T: Copy,
    F: Fn(T) -> [u8; N],
{
    let row_count = check_row_count(chunk.row_count, data.len(), validity)?;
    let mut payload = new_payload();
    match validity {
        None => {
            payload.push(0); // null_flag
            payload.reserve(N * row_count);
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), std::mem::size_of_val(data))
            };
            payload.extend_from_slice(bytes);
        }
        Some(v) => {
            payload.push(1); // null_flag — bitmap follows
            v.write_qwp_bitmap(&mut payload);
            payload.reserve(N * v.non_null_count());
            for (i, &value) in data.iter().enumerate() {
                if v.is_valid(i) {
                    payload.extend_from_slice(&to_le(value));
                }
            }
        }
    }
    chunk.push_column(name, wire_type, payload, row_count)
}

#[inline]
fn encode_fixed_width_bitmap<'a, const N: usize>(
    chunk: &'a mut Chunk,
    name: &str,
    wire_type: u8,
    data: &[[u8; N]],
    validity: Option<&Validity<'_>>,
    elem_size: usize,
) -> Result<&'a mut Chunk> {
    debug_assert_eq!(elem_size, N);
    let row_count = check_row_count(chunk.row_count, data.len(), validity)?;
    let mut payload = new_payload();
    match validity {
        None => {
            payload.push(0); // null_flag
            payload.reserve(N * row_count);
            // Bulk memcpy: `[[u8; N]]` is laid out as `N * row_count` bytes
            // contiguously, no per-row work.
            let bytes: &[u8] =
                unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), N * data.len()) };
            payload.extend_from_slice(bytes);
        }
        Some(v) => {
            payload.push(1); // null_flag — bitmap follows
            v.write_qwp_bitmap(&mut payload);
            payload.reserve(N * v.non_null_count());
            for (i, value) in data.iter().enumerate() {
                if v.is_valid(i) {
                    payload.extend_from_slice(&value[..]);
                }
            }
        }
    }
    chunk.push_column(name, wire_type, payload, row_count)
}

impl Debug for Chunk {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Chunk")
            .field("table", &self.table)
            .field("row_count", &self.row_count())
            .field("columns", &self.columns.len())
            .field("has_designated_ts", &self.designated_ts.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_row_count_on_first_column() {
        let mut chunk = Chunk::new("t");
        chunk.column_i64("a", &[1, 2, 3], None).unwrap();
        assert_eq!(chunk.row_count(), 3);
        let err = chunk.column_i64("b", &[1, 2], None).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("row_count"));
    }

    #[test]
    fn rejects_duplicate_column_name() {
        let mut chunk = Chunk::new("t");
        chunk.column_i64("a", &[1], None).unwrap();
        let err = chunk.column_i64("a", &[2], None).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("duplicate"));
    }

    #[test]
    fn rejects_invalid_validity_length() {
        let mut chunk = Chunk::new("t");
        let bits = [0xFFu8];
        let v = Validity::from_bitmap(&bits, 8).unwrap();
        let err = chunk.column_i64("a", &[1, 2, 3], Some(&v)).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("Validity bitmap"));
    }

    #[test]
    fn nullable_i64_sentinel_encodes() {
        let mut chunk = Chunk::new("t");
        let bits = [0b0000_0101]; // bits 0,2 valid; bit 1 null
        let v = Validity::from_bitmap(&bits, 3).unwrap();
        chunk.column_i64("a", &[10, 99, 20], Some(&v)).unwrap();
        let payload = chunk.columns[0].resolved_payload();
        assert_eq!(payload[0], 0, "null_flag must be 0 for I64");
        let raw: Vec<i64> = payload[1..]
            .chunks_exact(8)
            .map(|b| i64::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(raw, vec![10, I64_NULL, 20]);
    }

    #[test]
    fn nullable_uuid_uses_bitmap() {
        let mut chunk = Chunk::new("t");
        let uuids: [[u8; 16]; 3] = [[0x10; 16], [0x99; 16], [0x20; 16]];
        let bits = [0b0000_0101]; // 0 valid, 1 null, 2 valid
        let v = Validity::from_bitmap(&bits, 3).unwrap();
        chunk.column_uuid("u", &uuids, Some(&v)).unwrap();
        let payload = chunk.columns[0].resolved_payload();
        assert_eq!(payload[0], 1, "null_flag must be 1 (bitmap follows)");
        // QWP bitmap: bit=1 means NULL. Arrow bits = 0b101 → invert =
        // 0b010 masked to 3 bits.
        let qwp_bitmap = payload[1];
        assert_eq!(qwp_bitmap & 0b111, 0b010);
        // Dense values: rows 0 and 2 only.
        let dense = &payload[2..];
        assert_eq!(dense.len(), 32);
        assert_eq!(&dense[..16], &[0x10u8; 16]);
        assert_eq!(&dense[16..], &[0x20u8; 16]);
    }

    #[test]
    fn designated_ts_sets_row_count() {
        let mut chunk = Chunk::new("t");
        chunk.designated_timestamp_micros(&[1, 2, 3]).unwrap();
        assert_eq!(chunk.row_count(), 3);
        let err = chunk.designated_timestamp_nanos(&[4, 5, 6]).unwrap_err();
        assert!(err.msg().contains("designated"));
    }

    #[test]
    fn clear_resets_columns_but_keeps_table() {
        let mut chunk = Chunk::new("t");
        chunk.column_i64("a", &[1], None).unwrap();
        chunk.designated_timestamp_nanos(&[10]).unwrap();
        chunk.clear();
        assert_eq!(chunk.row_count(), 0);
        assert!(chunk.is_empty());
        assert_eq!(chunk.table(), "t");
    }

    #[test]
    fn name_validation_rejects_overlong_names() {
        let mut chunk = Chunk::new("t");
        let too_long = "x".repeat(super::super::wire::MAX_NAME_LEN + 1);
        let err = chunk.column_i64(&too_long, &[1], None).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidName);
    }

    #[test]
    fn varchar_no_null_memcpy_path() {
        let mut chunk = Chunk::new("t");
        let offsets: [i32; 4] = [0, 3, 7, 11];
        let bytes = b"abcdefghijk";
        chunk.column_varchar("v", &offsets, bytes, None).unwrap();
        let payload = chunk.columns[0].resolved_payload();
        assert_eq!(payload[0], 0, "null_flag");
        // Offset table: 4 u32 little-endian values matching `offsets`.
        let table = &payload[1..1 + 16];
        let parsed: Vec<u32> = table
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(parsed, vec![0u32, 3, 7, 11]);
        // Byte buffer follows.
        assert_eq!(&payload[1 + 16..], bytes);
    }

    #[test]
    fn varchar_no_null_rebases_non_zero_first_offset() {
        let mut chunk = Chunk::new("t");
        // Caller's Arrow slice starts at offset 5.
        let offsets: [i32; 3] = [5, 8, 12];
        let bytes = b"_____abcdefg____";
        chunk.column_varchar("v", &offsets, bytes, None).unwrap();
        let payload = chunk.columns[0].resolved_payload();
        assert_eq!(payload[0], 0);
        let table = &payload[1..1 + 12];
        let parsed: Vec<u32> = table
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(parsed, vec![0u32, 3, 7]);
        assert_eq!(&payload[1 + 12..], b"abcdefg");
    }

    #[test]
    fn varchar_nullable_gather_skips_null_rows() {
        let mut chunk = Chunk::new("t");
        // 3 rows; row 1 is null. Per the plan we MUST not slice
        // bytes[offsets[1]..offsets[2]] for null rows. We assert the
        // skip implicitly by reusing the same offset on both sides of
        // the null row (so dense bytes still match what's expected) and
        // by checking the output's bytes equal the union of non-null
        // slices only.
        let offsets: [i32; 4] = [0, 3, 3, 6];
        let bytes = b"abcxyz";
        let bits = [0b0000_0101]; // 0 valid, 1 null, 2 valid
        let v = Validity::from_bitmap(&bits, 3).unwrap();
        chunk
            .column_varchar("v", &offsets, bytes, Some(&v))
            .unwrap();
        let payload = chunk.columns[0].resolved_payload();
        assert_eq!(payload[0], 1, "null_flag = 1 (bitmap follows)");
        // QWP bitmap byte: invert Arrow bits 0b101 → 0b010 (mask to 3 bits).
        assert_eq!(payload[1] & 0b111, 0b010);
        // 2 non-null rows → 3 offsets (u32 each) = 12 bytes, then bytes.
        let offsets_section = &payload[2..2 + 12];
        let parsed: Vec<u32> = offsets_section
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        assert_eq!(parsed, vec![0u32, 3, 6]);
        assert_eq!(&payload[2 + 12..], b"abcxyz");
    }

    #[test]
    fn varchar_rejects_negative_offset() {
        let mut chunk = Chunk::new("t");
        let offsets: [i32; 3] = [-1, 1, 2];
        let err = chunk
            .column_varchar("v", &offsets, b"ab", None)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("non-negative"), "msg: {}", err.msg());
    }

    #[test]
    fn varchar_rejects_non_monotonic_offsets() {
        let mut chunk = Chunk::new("t");
        let offsets: [i32; 3] = [0, 5, 3];
        let err = chunk
            .column_varchar("v", &offsets, b"abcde", None)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("non-decreasing"), "msg: {}", err.msg());
    }

    #[test]
    fn varchar_rejects_offsets_past_bytes_end() {
        let mut chunk = Chunk::new("t");
        let offsets: [i32; 3] = [0, 2, 7];
        let err = chunk
            .column_varchar("v", &offsets, b"abcde", None)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("bytes buffer"), "msg: {}", err.msg());
    }

    #[test]
    fn varchar_rejects_empty_offsets() {
        let mut chunk = Chunk::new("t");
        let err = chunk.column_varchar("v", &[], b"", None).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
    }
}
