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

//! `RESULT_BATCH` (msg_kind `0x11`) decoder.
//!
//! Owns per-column byte buffers; downstream code projects to
//! [`ColumnView`](super::column::ColumnView) via [`DecodedBatch::column_view`].
//!
//! Wire layout (post-header, pre-zstd application):
//!
//! ```text
//! msg_kind:   u8        0x11
//! request_id: i64 LE
//! batch_seq:  varint    monotonic per request, starting at 0
//!
//! [if FLAG_DELTA_SYMBOL_DICT]:
//!   delta_start: varint
//!   delta_count: varint
//!   repeat delta_count: varint(entry_len) + entry bytes
//!
//! table block:
//!   name_len:  varint   0 for query results
//!   name:      bytes    (skipped)
//!   row_count: varint
//!   col_count: varint
//!   schema section (see egress::schema)
//!
//! per-column data:
//!   null_flag: u8       0x00 = no bitmap; 0x01 = bitmap of ceil(row/8) bytes
//!   [bitmap]
//!   type-specific values
//! ```
//!
//! Limitations of this decoder (rejected with `UnsupportedServer`):
//! - `FLAG_ZSTD` payload compression
//! - Gorilla-encoded timestamps/dates (per-column discriminator `0x01`)
//! - Column kinds whose wire format isn't yet modelled in
//!   [`ColumnView`](super::column::ColumnView): VARCHAR, BINARY, GEOHASH,
//!   DECIMAL128/256, DOUBLE_ARRAY, LONG_ARRAY

use crate::egress::column::{
    BinaryColumn, ColumnView, Decimal64Column, FixedColumn, Long256Column, SymbolColumn,
    UuidColumn, Validity, VarcharColumn,
};
use crate::egress::column_kind::ColumnKind;
use crate::egress::error::{Error, Result, fmt};
use crate::egress::schema::SchemaRegistry;
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::wire::ByteReader;
use crate::egress::wire::header::flags;
use crate::egress::wire::msg_kind::MsgKind;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Owned column data extracted from a `RESULT_BATCH`.
#[derive(Debug, Clone)]
pub struct ColumnBuffer {
    /// Raw little-endian element bytes. Length = `row_count * elem_size`.
    pub values: Vec<u8>,
    /// `Some` iff the column carried a null bitmap (`null_flag != 0`).
    pub validity: Option<Vec<u8>>,
}

/// Owned per-column data tagged by QWP type.
#[derive(Debug, Clone)]
pub enum DecodedColumn {
    Boolean(ColumnBuffer),
    Byte(ColumnBuffer),
    Short(ColumnBuffer),
    Int(ColumnBuffer),
    Long(ColumnBuffer),
    Float(ColumnBuffer),
    Double(ColumnBuffer),
    Symbol {
        /// Dense per-row connection-scoped codes; `0` in null slots
        /// (validity is the source of truth for null vs id-zero).
        codes: Vec<u32>,
        validity: Option<Vec<u8>>,
    },
    Timestamp(ColumnBuffer),
    Date(ColumnBuffer),
    Uuid(ColumnBuffer),
    Long256(ColumnBuffer),
    TimestampNanos(ColumnBuffer),
    Decimal64 {
        buffer: ColumnBuffer,
        scale: i8,
    },
    Char(ColumnBuffer),
    Ipv4(ColumnBuffer),
    Varchar {
        /// Dense per-row offsets (length `row_count + 1`); null rows are
        /// zero-length entries.
        offsets: Vec<u32>,
        /// Concatenated UTF-8 bytes (validated at decode time).
        data: Vec<u8>,
        validity: Option<Vec<u8>>,
    },
    Binary {
        offsets: Vec<u32>,
        data: Vec<u8>,
        validity: Option<Vec<u8>>,
    },
}

/// One decoded `RESULT_BATCH`.
#[derive(Debug, Clone)]
pub struct DecodedBatch {
    pub request_id: i64,
    pub batch_seq: u64,
    pub schema_id: u64,
    pub row_count: usize,
    pub columns: Vec<DecodedColumn>,
}

impl DecodedBatch {
    /// Project a single column to a borrowing [`ColumnView`].
    ///
    /// `dict` should be the connection's [`SymbolDict`] (only consulted for
    /// `Symbol` columns; ignored otherwise but required so the call site is
    /// borrow-correct in the streaming case).
    pub fn column_view<'a>(&'a self, idx: usize, dict: &'a SymbolDict) -> Result<ColumnView<'a>> {
        let col = self
            .columns
            .get(idx)
            .ok_or_else(|| fmt!(InvalidApiCall, "column index {} out of range", idx))?;
        Ok(match col {
            DecodedColumn::Boolean(b) => ColumnView::Boolean(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Byte(b) => ColumnView::Byte(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Short(b) => ColumnView::Short(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Int(b) => ColumnView::Int(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Long(b) => ColumnView::Long(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Float(b) => ColumnView::Float(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Double(b) => ColumnView::Double(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Timestamp(b) => ColumnView::Timestamp(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Date(b) => ColumnView::Date(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::TimestampNanos(b) => ColumnView::TimestampNanos(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Char(b) => ColumnView::Char(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Ipv4(b) => ColumnView::Ipv4(FixedColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Uuid(b) => ColumnView::Uuid(UuidColumn::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Long256(b) => ColumnView::Long256(Long256Column::new(&b.values, validity_of(b, self.row_count))),
            DecodedColumn::Decimal64 { buffer, scale } => ColumnView::Decimal64(Decimal64Column::new(&buffer.values, validity_of(buffer, self.row_count), *scale)),
            DecodedColumn::Symbol { codes, validity } => ColumnView::Symbol(SymbolColumn::new(
                codes,
                validity_from_opt(validity, self.row_count),
                dict,
            )),
            DecodedColumn::Varchar { offsets, data, validity } => ColumnView::Varchar(
                VarcharColumn::new(offsets, data, validity_from_opt(validity, self.row_count)),
            ),
            DecodedColumn::Binary { offsets, data, validity } => ColumnView::Binary(
                BinaryColumn::new(offsets, data, validity_from_opt(validity, self.row_count)),
            ),
        })
    }
}

fn validity_of<'a>(buf: &'a ColumnBuffer, row_count: usize) -> Validity<'a> {
    validity_from_opt(&buf.validity, row_count)
}

fn validity_from_opt<'a>(validity: &'a Option<Vec<u8>>, row_count: usize) -> Validity<'a> {
    match validity {
        None => Validity::None,
        Some(bytes) => Validity::from_bitmap(bytes, row_count),
    }
}

// ---------------------------------------------------------------------------
// Top-level decode
// ---------------------------------------------------------------------------

/// Decode a `RESULT_BATCH` payload (the bytes following the 12-byte frame
/// header). Mutates `dict` if the batch carries a delta dict section, and
/// `registry` if the batch carries a full schema.
pub fn decode_result_batch(
    payload: &[u8],
    flags_byte: u8,
    dict: &mut SymbolDict,
    registry: &mut SchemaRegistry,
) -> Result<DecodedBatch> {
    if flags_byte & flags::ZSTD != 0 {
        return Err(fmt!(
            UnsupportedServer,
            "FLAG_ZSTD payload compression is not yet supported by this client"
        ));
    }

    let mut r = ByteReader::new(payload);

    let kind = r.read_u8()?;
    if kind != MsgKind::ResultBatch.as_u8() {
        return Err(fmt!(
            ProtocolError,
            "expected RESULT_BATCH (0x11), got 0x{:02X}",
            kind
        ));
    }
    let request_id = r.read_i64_le()?;
    let batch_seq = r.read_varint_u64()?;

    if flags_byte & flags::DELTA_SYMBOL_DICT != 0 {
        let consumed = dict.apply_delta_from_bytes(r.remaining())?;
        r.advance(consumed)?;
    }

    // Table block.
    let name_len = r.read_varint_usize()?;
    r.read_bytes(name_len)?; // table name; ignored for query results
    let row_count = r.read_varint_usize()?;
    let col_count = r.read_varint_usize()?;

    // Schema section.
    let consumed = {
        let schema_section = r.remaining();
        let dec = registry.decode_section(schema_section)?;
        let id = dec.schema_id;
        let consumed = dec.bytes_consumed;
        // Sanity-check the schema's column count.
        let schema = registry
            .get(id)
            .expect("schema must be present after decode_section");
        if schema.len() != col_count {
            return Err(fmt!(
                ProtocolError,
                "schema {} has {} columns but batch announced {}",
                id,
                schema.len(),
                col_count
            ));
        }
        (id, consumed)
    };
    let (schema_id, schema_bytes) = consumed;
    r.advance(schema_bytes)?;

    // Pull out the schema columns by value to avoid borrowing the registry
    // while we mutate it (we don't, in this loop, but borrow-check isn't
    // smart enough about the early consumed-by-decode_section call).
    let kinds: Vec<ColumnKind> = registry
        .get(schema_id)
        .expect("schema present")
        .columns()
        .iter()
        .map(|c| c.kind)
        .collect();

    let mut columns = Vec::with_capacity(col_count);
    for (i, kind) in kinds.iter().enumerate() {
        let col = decode_column(&mut r, *kind, row_count, flags_byte).map_err(|e| {
            Error::new(
                e.code(),
                format!("column {}/{} ({}): {}", i, col_count, kind.name(), e.msg()),
            )
        })?;
        columns.push(col);
    }

    if !r.is_empty() {
        return Err(fmt!(
            ProtocolError,
            "RESULT_BATCH has {} trailing bytes",
            r.remaining().len()
        ));
    }

    Ok(DecodedBatch {
        request_id,
        batch_seq,
        schema_id,
        row_count,
        columns,
    })
}

// ---------------------------------------------------------------------------
// Per-column decode
// ---------------------------------------------------------------------------

fn decode_column(
    r: &mut ByteReader<'_>,
    kind: ColumnKind,
    row_count: usize,
    flags_byte: u8,
) -> Result<DecodedColumn> {
    Ok(match kind {
        ColumnKind::Boolean => DecodedColumn::Boolean(decode_boolean(r, row_count)?),
        ColumnKind::Byte => DecodedColumn::Byte(decode_fixed(r, row_count, 1)?),
        ColumnKind::Short => DecodedColumn::Short(decode_fixed(r, row_count, 2)?),
        ColumnKind::Int => DecodedColumn::Int(decode_fixed(r, row_count, 4)?),
        ColumnKind::Long => DecodedColumn::Long(decode_fixed(r, row_count, 8)?),
        ColumnKind::Float => DecodedColumn::Float(decode_fixed(r, row_count, 4)?),
        ColumnKind::Double => DecodedColumn::Double(decode_fixed(r, row_count, 8)?),
        ColumnKind::Char => DecodedColumn::Char(decode_fixed(r, row_count, 2)?),
        ColumnKind::Ipv4 => DecodedColumn::Ipv4(decode_fixed(r, row_count, 4)?),
        ColumnKind::Uuid => DecodedColumn::Uuid(decode_fixed(r, row_count, 16)?),
        ColumnKind::Long256 => DecodedColumn::Long256(decode_fixed(r, row_count, 32)?),

        ColumnKind::Timestamp => DecodedColumn::Timestamp(decode_temporal(r, row_count, flags_byte)?),
        ColumnKind::Date => DecodedColumn::Date(decode_temporal(r, row_count, flags_byte)?),
        ColumnKind::TimestampNanos => DecodedColumn::TimestampNanos(decode_temporal(r, row_count, flags_byte)?),

        ColumnKind::Symbol => {
            let (codes, validity) = decode_symbol(r, row_count)?;
            DecodedColumn::Symbol { codes, validity }
        }

        ColumnKind::Decimal64 => {
            let (scale, buffer) = decode_decimal64(r, row_count)?;
            DecodedColumn::Decimal64 { buffer, scale }
        }

        ColumnKind::Varchar => {
            let (offsets, data, validity) = decode_varlen(r, row_count, /*utf8=*/ true)?;
            DecodedColumn::Varchar { offsets, data, validity }
        }
        ColumnKind::Binary => {
            let (offsets, data, validity) = decode_varlen(r, row_count, /*utf8=*/ false)?;
            DecodedColumn::Binary { offsets, data, validity }
        }

        ColumnKind::Geohash
        | ColumnKind::Decimal128
        | ColumnKind::Decimal256
        | ColumnKind::DoubleArray
        | ColumnKind::LongArray => {
            return Err(fmt!(
                UnsupportedServer,
                "decoder does not yet support column kind {} (0x{:02X})",
                kind.name(),
                kind.as_u8()
            ));
        }
    })
}

/// VARCHAR / BINARY column body (after the validity section).
///
/// Wire layout: `(non_null + 1) × u32_le` offsets, then `compact_offsets[non_null]`
/// bytes of concatenated values. Returns dense per-row offsets
/// (`row_count + 1` entries; null rows zero-length) plus the original
/// compact data buffer (string boundaries are unchanged by densification).
fn decode_varlen(
    r: &mut ByteReader<'_>,
    row_count: usize,
    utf8: bool,
) -> Result<(Vec<u32>, Vec<u8>, Option<Vec<u8>>)> {
    let validity = decode_validity(r, row_count)?;
    let non_null = match &validity {
        None => row_count,
        Some(bitmap) => row_count - count_nulls(bitmap, row_count),
    };

    // Read the compact offsets array.
    let offsets_byte_len = (non_null + 1)
        .checked_mul(4)
        .ok_or_else(|| fmt!(ProtocolError, "varlen offsets size overflow"))?;
    let offsets_bytes = r.read_bytes(offsets_byte_len)?;
    let mut compact = Vec::with_capacity(non_null + 1);
    for chunk in offsets_bytes.chunks_exact(4) {
        compact.push(u32::from_le_bytes(chunk.try_into().unwrap()));
    }

    // Validate offsets are monotonically non-decreasing and start at 0.
    if compact[0] != 0 {
        return Err(fmt!(
            ProtocolError,
            "varlen offsets must start at 0, got {}",
            compact[0]
        ));
    }
    for i in 1..compact.len() {
        if compact[i] < compact[i - 1] {
            return Err(fmt!(
                ProtocolError,
                "varlen offsets not monotonic at index {}: {} < {}",
                i,
                compact[i],
                compact[i - 1]
            ));
        }
    }

    // Read the concatenated data bytes.
    let data_len = compact[non_null] as usize;
    let data = r.read_bytes(data_len)?.to_vec();

    if utf8 {
        std::str::from_utf8(&data).map_err(|e| {
            fmt!(InvalidUtf8, "varchar data buffer not valid UTF-8: {}", e)
        })?;
    }

    // Densify offsets to row_count + 1 entries.
    let mut dense = vec![0u32; row_count + 1];
    let mut k = 0usize; // walked non-null entries
    for row in 0..row_count {
        if is_null_at_opt(&validity, row) {
            dense[row + 1] = dense[row];
        } else {
            let len = compact[k + 1] - compact[k];
            dense[row + 1] = dense[row] + len;
            k += 1;
        }
    }

    Ok((dense, data, validity))
}

fn decode_validity(r: &mut ByteReader<'_>, row_count: usize) -> Result<Option<Vec<u8>>> {
    let null_flag = r.read_u8()?;
    if null_flag == 0 {
        return Ok(None);
    }
    let bitmap_len = row_count.div_ceil(8);
    let bytes = r.read_bytes(bitmap_len)?;
    Ok(Some(bytes.to_vec()))
}

/// Read `non_null_count × elem_size` compact bytes from the wire and write
/// them into a dense `row_count × elem_size` buffer, with null slots zeroed.
fn decode_fixed(
    r: &mut ByteReader<'_>,
    row_count: usize,
    elem_size: usize,
) -> Result<ColumnBuffer> {
    let validity = decode_validity(r, row_count)?;
    let dense_len = row_count
        .checked_mul(elem_size)
        .ok_or_else(|| fmt!(ProtocolError, "fixed column size overflow"))?;

    match &validity {
        None => {
            let values = r.read_bytes(dense_len)?.to_vec();
            Ok(ColumnBuffer { values, validity })
        }
        Some(bitmap) => {
            let non_null = row_count - count_nulls(bitmap, row_count);
            let compact_len = non_null * elem_size;
            let compact = r.read_bytes(compact_len)?;
            let mut dense = vec![0u8; dense_len];
            let mut src = 0usize;
            for row in 0..row_count {
                if !is_null_at(bitmap, row) {
                    let dst = row * elem_size;
                    dense[dst..dst + elem_size].copy_from_slice(&compact[src..src + elem_size]);
                    src += elem_size;
                }
            }
            Ok(ColumnBuffer {
                values: dense,
                validity,
            })
        }
    }
}

/// QWP `BOOLEAN`: not nullable on the wire (validity always absent), values
/// bit-packed into `ceil(row_count/8)` bytes. We expand to one byte per row
/// so `FixedColumn<u8>` can address rows in O(1).
fn decode_boolean(r: &mut ByteReader<'_>, row_count: usize) -> Result<ColumnBuffer> {
    let validity = decode_validity(r, row_count)?;
    let non_null = match &validity {
        None => row_count,
        Some(bitmap) => row_count - count_nulls(bitmap, row_count),
    };
    let bit_bytes = non_null.div_ceil(8);
    let bits = r.read_bytes(bit_bytes)?.to_vec();

    let mut dense = vec![0u8; row_count];
    let mut src_bit = 0usize;
    for row in 0..row_count {
        if !is_null_at_opt(&validity, row) {
            let b = bits[src_bit >> 3];
            dense[row] = (b >> (src_bit & 7)) & 1;
            src_bit += 1;
        }
    }
    Ok(ColumnBuffer {
        values: dense,
        validity,
    })
}

fn decode_temporal(
    r: &mut ByteReader<'_>,
    row_count: usize,
    flags_byte: u8,
) -> Result<ColumnBuffer> {
    if flags_byte & flags::GORILLA != 0 {
        // The discriminator precedes validity per the spec.
        let disc = r.read_u8()?;
        if disc == 0x01 {
            return Err(fmt!(
                UnsupportedServer,
                "Gorilla-encoded temporals are not yet supported by this client"
            ));
        }
        if disc != 0x00 {
            return Err(fmt!(
                ProtocolError,
                "unknown temporal encoding discriminator 0x{:02X}",
                disc
            ));
        }
    }
    decode_fixed(r, row_count, 8)
}

/// SYMBOL: connection-scoped delta dict path only. Per non-null row, a varint
/// id follows; we expand into a dense `row_count` `u32` buffer with `0` in
/// null slots (validity bitmap is the source of truth for null-vs-id-zero).
//
// TODO(qwp): also support the column-local dict mode (varint dict_size +
// per-entry varint len + bytes preceding the per-row codes). The per-batch
// signal for which mode is in effect needs to be confirmed against the
// reference decoder before implementing.
fn decode_symbol(
    r: &mut ByteReader<'_>,
    row_count: usize,
) -> Result<(Vec<u32>, Option<Vec<u8>>)> {
    let validity = decode_validity(r, row_count)?;
    let mut codes = vec![0u32; row_count];
    for row in 0..row_count {
        if is_null_at_opt(&validity, row) {
            continue;
        }
        let code = r.read_varint_u64().map_err(|e| {
            Error::new(
                e.code(),
                format!("symbol code at row {}: {}", row, e.msg()),
            )
        })?;
        let code32 = u32::try_from(code).map_err(|_| {
            fmt!(
                ProtocolError,
                "symbol code {} at row {} exceeds u32",
                code,
                row
            )
        })?;
        codes[row] = code32;
    }
    Ok((codes, validity))
}

/// DECIMAL64: column-level 1-byte scale follows the validity section, then
/// `non_null_count × 8` LE bytes; densified like the fixed-width path.
fn decode_decimal64(
    r: &mut ByteReader<'_>,
    row_count: usize,
) -> Result<(i8, ColumnBuffer)> {
    let validity = decode_validity(r, row_count)?;
    let scale = r.read_u8()? as i8;
    let dense_len = row_count
        .checked_mul(8)
        .ok_or_else(|| fmt!(ProtocolError, "decimal column size overflow"))?;
    let buffer = match &validity {
        None => {
            let values = r.read_bytes(dense_len)?.to_vec();
            ColumnBuffer { values, validity }
        }
        Some(bitmap) => {
            let non_null = row_count - count_nulls(bitmap, row_count);
            let compact = r.read_bytes(non_null * 8)?;
            let mut dense = vec![0u8; dense_len];
            let mut src = 0usize;
            for row in 0..row_count {
                if !is_null_at(bitmap, row) {
                    let dst = row * 8;
                    dense[dst..dst + 8].copy_from_slice(&compact[src..src + 8]);
                    src += 8;
                }
            }
            ColumnBuffer {
                values: dense,
                validity,
            }
        }
    };
    Ok((scale, buffer))
}

fn count_nulls(bitmap: &[u8], row_count: usize) -> usize {
    let mut nulls = 0usize;
    for r in 0..row_count {
        if is_null_at(bitmap, r) {
            nulls += 1;
        }
    }
    nulls
}

fn is_null_at(bitmap: &[u8], row: usize) -> bool {
    (bitmap[row >> 3] >> (row & 7)) & 1 != 0
}

fn is_null_at_opt(validity: &Option<Vec<u8>>, row: usize) -> bool {
    match validity {
        None => false,
        Some(bitmap) => is_null_at(bitmap, row),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;
    use crate::egress::schema::{Schema, SchemaColumn, SchemaMode};
    use crate::egress::wire::varint::encode_u64;

    /// Helper builder for a `RESULT_BATCH` payload (post-header bytes).
    struct BatchBuilder {
        flags: u8,
        request_id: i64,
        batch_seq: u64,
        delta: Option<Vec<&'static str>>, // delta_start always 0; for tests
        delta_start: u64,
        row_count: usize,
        cols: Vec<(String, ColumnKind)>,
        schema_mode: SchemaMode,
        schema_id: u64,
        column_data: Vec<Vec<u8>>,
    }

    impl BatchBuilder {
        fn new(row_count: usize) -> Self {
            Self {
                flags: 0,
                request_id: 1,
                batch_seq: 0,
                delta: None,
                delta_start: 0,
                row_count,
                cols: Vec::new(),
                schema_mode: SchemaMode::Full,
                schema_id: 1,
                column_data: Vec::new(),
            }
        }

        fn with_flags(mut self, f: u8) -> Self {
            self.flags = f;
            self
        }
        fn with_dict_delta(mut self, start: u64, entries: Vec<&'static str>) -> Self {
            self.flags |= flags::DELTA_SYMBOL_DICT;
            self.delta_start = start;
            self.delta = Some(entries);
            self
        }
        fn with_schema_ref(mut self, id: u64) -> Self {
            self.schema_mode = SchemaMode::Reference;
            self.schema_id = id;
            self
        }
        fn with_schema_id(mut self, id: u64) -> Self {
            self.schema_id = id;
            self
        }
        fn add_column(mut self, name: &str, kind: ColumnKind, data: Vec<u8>) -> Self {
            self.cols.push((name.to_string(), kind));
            self.column_data.push(data);
            self
        }

        fn build(self) -> (u8, Vec<u8>) {
            let mut out = Vec::new();
            out.push(MsgKind::ResultBatch.as_u8());
            out.extend_from_slice(&self.request_id.to_le_bytes());
            encode_u64(self.batch_seq, &mut out);

            if let Some(entries) = self.delta {
                encode_u64(self.delta_start, &mut out);
                encode_u64(entries.len() as u64, &mut out);
                for e in entries {
                    encode_u64(e.len() as u64, &mut out);
                    out.extend_from_slice(e.as_bytes());
                }
            }

            // Table block.
            encode_u64(0, &mut out); // name_len
            encode_u64(self.row_count as u64, &mut out);
            encode_u64(self.cols.len() as u64, &mut out);

            // Schema section.
            out.push(self.schema_mode as u8);
            encode_u64(self.schema_id, &mut out);
            if matches!(self.schema_mode, SchemaMode::Full) {
                encode_u64(self.cols.len() as u64, &mut out);
                for (name, kind) in &self.cols {
                    encode_u64(name.len() as u64, &mut out);
                    out.extend_from_slice(name.as_bytes());
                    out.push(kind.as_u8());
                }
            }

            for data in self.column_data {
                out.extend_from_slice(&data);
            }

            (self.flags, out)
        }
    }

    fn col_no_nulls(values: &[u8]) -> Vec<u8> {
        let mut out = vec![0x00]; // null_flag = 0
        out.extend_from_slice(values);
        out
    }

    fn col_with_bitmap(bitmap: &[u8], values: &[u8]) -> Vec<u8> {
        let mut out = vec![0x01]; // null_flag = 1
        out.extend_from_slice(bitmap);
        out.extend_from_slice(values);
        out
    }

    fn le_i64s(vs: &[i64]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in vs {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o
    }

    #[test]
    fn decode_simple_long_no_nulls() {
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[1, 2, 3])))
            .build();

        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        assert_eq!(batch.row_count, 3);
        assert_eq!(batch.columns.len(), 1);

        let view = batch.column_view(0, &dict).unwrap();
        match view {
            ColumnView::Long(c) => {
                assert_eq!(c.len(), 3);
                assert_eq!(c.value(0), 1);
                assert_eq!(c.value(1), 2);
                assert_eq!(c.value(2), 3);
            }
            other => panic!("unexpected view: {:?}", other.kind()),
        }
    }

    #[test]
    fn decode_long_with_nulls_densifies() {
        // 4 rows; row 1 is null. Wire is COMPACT: only 3 i64 values present.
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column(
                "v",
                ColumnKind::Long,
                col_with_bitmap(&[0x02], &le_i64s(&[10, 30, 40])),
            )
            .build();

        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        assert!(!c.is_null(0));
        assert!(c.is_null(1));
        assert!(!c.is_null(2));
        assert!(!c.is_null(3));
        assert_eq!(c.value(0), 10);
        // Row 1 is null; densified slot is zero per the decoder's contract.
        assert_eq!(c.value(1), 0);
        assert_eq!(c.value(2), 30);
        assert_eq!(c.value(3), 40);
    }

    #[test]
    fn decode_long_densifies_multiple_nulls() {
        // 8 rows; rows 1, 4, 7 null. Bitmap: bits 1,4,7 = 0b1001_0010 = 0x92
        let (flags_byte, payload) = BatchBuilder::new(8)
            .add_column(
                "v",
                ColumnKind::Long,
                col_with_bitmap(&[0x92], &le_i64s(&[100, 102, 103, 105, 106])),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        let expected: Vec<Option<i64>> = vec![
            Some(100), None, Some(102), Some(103), None, Some(105), Some(106), None,
        ];
        let got: Vec<Option<i64>> = (0..8)
            .map(|r| if c.is_null(r) { None } else { Some(c.value(r)) })
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn decode_boolean_bit_packed() {
        // 5 rows, no nulls. Wire bits (LSB-first) for [t, f, t, t, f]:
        // bit0=1, bit1=0, bit2=1, bit3=1, bit4=0 → 0b0000_1101 = 0x0D
        let (flags_byte, payload) = BatchBuilder::new(5)
            .add_column("b", ColumnKind::Boolean, col_no_nulls(&[0x0D]))
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Boolean(c) = view else { panic!() };
        assert_eq!(c.len(), 5);
        assert_eq!(c.value(0), 1);
        assert_eq!(c.value(1), 0);
        assert_eq!(c.value(2), 1);
        assert_eq!(c.value(3), 1);
        assert_eq!(c.value(4), 0);
    }

    #[test]
    fn decode_symbol_with_dict_delta() {
        // 3 rows: AAPL, NULL, MSFT
        // bitmap: 0b00000010 = 0x02
        // codes: varint(0), varint(1)
        let mut col_data = vec![0x01u8, 0x02]; // null_flag, bitmap
        encode_u64(0, &mut col_data);
        encode_u64(1, &mut col_data);

        let (flags_byte, payload) = BatchBuilder::new(3)
            .with_dict_delta(0, vec!["AAPL", "MSFT"])
            .add_column("sym", ColumnKind::Symbol, col_data)
            .build();

        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        assert_eq!(dict.len(), 2);

        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Symbol(s) = view else { panic!() };
        assert_eq!(s.len(), 3);
        assert_eq!(s.resolve(0), Some("AAPL"));
        assert_eq!(s.resolve(1), None);
        assert_eq!(s.resolve(2), Some("MSFT"));
    }

    #[test]
    fn decode_decimal64_with_scale() {
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column(
                "p",
                ColumnKind::Decimal64,
                {
                    let mut d = vec![0x00u8, 0x02]; // null_flag=0, scale=2
                    d.extend_from_slice(&le_i64s(&[12345, 6789]));
                    d
                },
            )
            .build();

        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Decimal64(d) = view else { panic!() };
        assert_eq!(d.scale(), 2);
        assert_eq!(d.value(0), 12345);
        assert_eq!(d.value(1), 6789);
    }

    #[test]
    fn schema_reference_after_full() {
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();

        // First batch: full schema id=7, one Long column, 2 rows.
        let (f1, p1) = BatchBuilder::new(2)
            .with_schema_id(7)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[1, 2])))
            .build();
        decode_result_batch(&p1, f1, &mut dict, &mut reg).unwrap();
        assert!(reg.get(7).is_some());

        // Second batch references id 7. We still need the column metadata
        // to know how to decode, so add the same cols on the builder side
        // (but it emits a Reference frame; the decoder reads kinds from the
        // registry).
        let (f2, p2) = BatchBuilder::new(1)
            .with_schema_ref(7)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[42])))
            .build();
        let b2 = decode_result_batch(&p2, f2, &mut dict, &mut reg).unwrap();
        assert_eq!(b2.schema_id, 7);
        let view = b2.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        assert_eq!(c.value(0), 42);
    }

    #[test]
    fn rejects_zstd_flag() {
        let (_, payload) = BatchBuilder::new(0).build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags::ZSTD, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnsupportedServer);
    }

    #[test]
    fn rejects_gorilla_encoded_timestamp() {
        // 1 timestamp column, gorilla flag, discriminator 0x01.
        let mut col_data = vec![0x01u8]; // gorilla discriminator
        // The decoder rejects before reading further.
        let (_, payload) = BatchBuilder::new(1)
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, {
                col_data.push(0x00);
                col_data.extend_from_slice(&0i64.to_le_bytes());
                col_data
            })
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags::GORILLA, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnsupportedServer);
        assert!(err.msg().to_lowercase().contains("gorilla"));
    }

    #[test]
    fn rejects_unsupported_column_kind() {
        // Geohash isn't in the modelled set yet.
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("g", ColumnKind::Geohash, vec![0x00u8])
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnsupportedServer);
        assert!(err.msg().contains("geohash"));
    }

    fn varchar_col_no_nulls(values: &[&str]) -> Vec<u8> {
        let mut out = vec![0x00u8]; // null_flag
        let mut total = 0u32;
        out.extend_from_slice(&total.to_le_bytes());
        for v in values {
            total += v.len() as u32;
            out.extend_from_slice(&total.to_le_bytes());
        }
        for v in values {
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    fn varchar_col_with_bitmap(bitmap: &[u8], non_null_values: &[&str]) -> Vec<u8> {
        let mut out = vec![0x01u8];
        out.extend_from_slice(bitmap);
        let mut total = 0u32;
        out.extend_from_slice(&total.to_le_bytes());
        for v in non_null_values {
            total += v.len() as u32;
            out.extend_from_slice(&total.to_le_bytes());
        }
        for v in non_null_values {
            out.extend_from_slice(v.as_bytes());
        }
        out
    }

    #[test]
    fn decode_varchar_no_nulls() {
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("s", ColumnKind::Varchar, varchar_col_no_nulls(&["foo", "", "café"]))
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Varchar(c) = view else { panic!() };
        assert_eq!(c.len(), 3);
        assert_eq!(c.value(0), Some("foo"));
        assert_eq!(c.value(1), Some(""));
        assert_eq!(c.value(2), Some("café"));
    }

    #[test]
    fn decode_varchar_with_nulls_densifies_offsets() {
        // 4 rows; rows 0,2 valid; row 1 null; row 3 null.
        // Bitmap bits 1 and 3 set → 0b0000_1010 = 0x0A
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column(
                "s",
                ColumnKind::Varchar,
                varchar_col_with_bitmap(&[0x0A], &["hello", "world"]),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Varchar(c) = view else { panic!() };
        assert_eq!(c.len(), 4);
        assert_eq!(c.value(0), Some("hello"));
        assert_eq!(c.value(1), None);
        assert_eq!(c.value(2), Some("world"));
        assert_eq!(c.value(3), None);
        // Dense offsets: [0, 5, 5, 10, 10]
        assert_eq!(c.offsets(), &[0u32, 5, 5, 10, 10]);
    }

    #[test]
    fn decode_varchar_invalid_utf8_rejected() {
        let mut col = vec![0x00u8]; // null_flag
        // 1 row, len 2
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&2u32.to_le_bytes());
        col.extend_from_slice(&[0xFF, 0xFE]); // invalid UTF-8
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("s", ColumnKind::Varchar, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidUtf8);
    }

    #[test]
    fn decode_binary_no_nulls() {
        let mut col = vec![0x00u8];
        // offsets [0, 3, 5]
        for o in [0u32, 3, 5] {
            col.extend_from_slice(&o.to_le_bytes());
        }
        col.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x42]);
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("b", ColumnKind::Binary, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Binary(c) = view else { panic!() };
        assert_eq!(c.len(), 2);
        assert_eq!(c.value(0), Some([0xDEu8, 0xAD, 0xBE].as_slice()));
        assert_eq!(c.value(1), Some([0xEFu8, 0x42].as_slice()));
    }

    #[test]
    fn decode_binary_invalid_utf8_accepted() {
        // BINARY treats bytes as opaque — 0xFF 0xFE roundtrips fine.
        let mut col = vec![0x00u8];
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&2u32.to_le_bytes());
        col.extend_from_slice(&[0xFF, 0xFE]);
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("b", ColumnKind::Binary, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Binary(c) = view else { panic!() };
        assert_eq!(c.value(0), Some([0xFFu8, 0xFE].as_slice()));
    }

    #[test]
    fn decode_varlen_non_monotonic_rejected() {
        let mut col = vec![0x00u8];
        // offsets [0, 5, 3] — second offset goes backward
        for o in [0u32, 5, 3] {
            col.extend_from_slice(&o.to_le_bytes());
        }
        col.extend_from_slice(&[0u8; 5]);
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("s", ColumnKind::Varchar, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn decode_varchar_all_null_column() {
        // 3 rows, all null. Bitmap: 0b00000111 = 0x07
        // Compact has 0 non-null entries → offsets has 1 entry [0], no data.
        let mut col = vec![0x01u8, 0x07];
        col.extend_from_slice(&0u32.to_le_bytes());
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("s", ColumnKind::Varchar, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Varchar(c) = view else { panic!() };
        assert_eq!(c.len(), 3);
        assert_eq!(c.value(0), None);
        assert_eq!(c.value(1), None);
        assert_eq!(c.value(2), None);
        assert_eq!(c.offsets(), &[0u32, 0, 0, 0]);
    }

    #[test]
    fn trailing_bytes_rejected() {
        let (flags_byte, mut payload) = BatchBuilder::new(1)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[7])))
            .build();
        payload.push(0xAA); // trailing byte
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(err.msg().contains("trailing"));
    }

    #[test]
    fn truncated_column_rejected() {
        let (flags_byte, mut payload) = BatchBuilder::new(1)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[7])))
            .build();
        payload.truncate(payload.len() - 4); // chop value bytes
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn multi_column_batch() {
        // 2 rows, 2 cols: long, double
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("a", ColumnKind::Long, col_no_nulls(&le_i64s(&[10, 20])))
            .add_column("b", ColumnKind::Double, col_no_nulls(&{
                let mut o = Vec::new();
                o.extend_from_slice(&1.5f64.to_le_bytes());
                o.extend_from_slice(&2.5f64.to_le_bytes());
                o
            }))
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        assert_eq!(batch.columns.len(), 2);
        let ColumnView::Long(a) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        let ColumnView::Double(b) = batch.column_view(1, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(a.value(0), 10);
        assert_eq!(a.value(1), 20);
        assert_eq!(b.value(0), 1.5);
        assert_eq!(b.value(1), 2.5);
    }

    // Unused references silenced by binding to `_` in tests where they exist
    // only for symmetry.
    #[allow(dead_code)]
    fn _unused(_: &Schema, _: &SchemaColumn) {}
}
