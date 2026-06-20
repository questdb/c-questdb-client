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
//!   [if batch_seq == 0]:           # schema rides the first batch only
//!     col_count: varint
//!     schema section (see egress::schema)
//!
//! per-column data:
//!   null_flag: u8       0x00 = no bitmap; 0x01 = bitmap of ceil(row/8) bytes
//!   [bitmap]
//!   type-specific values
//! ```
//!
//! `FLAG_ZSTD` payloads are decoded via the optional `compression-zstd`
//! crate feature; an unfeatured build rejects them with
//! `ErrorCode::UnsupportedServer`. Gorilla-encoded timestamps/dates
//! (per-column discriminator `0x01`) are handled by the
//! [`super::gorilla`] module's bitstream decoder. Every column kind in
//! [`super::column_kind::ColumnKind`] has a matching
//! [`super::column::ColumnView`] variant.

use crate::egress::column::{
    BinaryColumn, ColumnView, Decimal64Column, Decimal128Column, Decimal256Column,
    DoubleArrayColumn, FixedColumn, GeohashColumn, Long256Column, LongArrayColumn, SymbolColumn,
    UuidColumn, Validity, VarcharColumn,
};
use crate::egress::column_kind::ColumnKind;
use crate::egress::error::{Error, Result, fmt};
use crate::egress::schema::Schema;
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::wire::ByteReader;
use crate::egress::wire::header::flags;
use crate::egress::wire::msg_kind::MsgKind;
use bytes::Bytes;

/// Per-batch caps mirrored from `java-questdb-client` (`QwpConstants.java`
/// and `QwpResultBatchDecoder.java`). These cap wire-supplied counts and
/// lengths before any `Vec::with_capacity` / `vec![..; n]` allocation so
/// a hostile or corrupted varint can't trigger a multi-GiB up-front
/// allocation and OOM the client before the bytes-too-short check fires.
pub(crate) const MAX_ROWS_PER_BATCH: usize = 1_048_576;
pub(crate) const MAX_COLUMNS_PER_TABLE: usize = 2048;
pub(crate) const MAX_COLUMN_NAME_LENGTH: usize = 127;
pub(crate) const MAX_TABLE_NAME_LENGTH: usize = 127;

/// Take a zero-copy owned slice of `n` bytes from `parent` starting at the
/// reader's current position, and advance the reader.
fn read_owned(r: &mut ByteReader<'_>, parent: &Bytes, n: usize) -> Result<Bytes> {
    let start = r.pos();
    r.advance(n)?;
    Ok(parent.slice(start..start + n))
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Owned column data extracted from a `RESULT_BATCH`.
///
/// `values` and `validity` are typically zero-copy `Bytes` slices into the
/// frame's payload buffer (or, after FLAG_ZSTD, into the decompressed body).
/// Paths that *have* to materialize new bytes (BOOLEAN bit-unpacking, GORILLA
/// temporal expansion, null-bearing fixed-width densification) wrap a fresh
/// `Vec<u8>` via `Bytes::from(vec)`.
#[derive(Debug, Clone)]
pub struct ColumnBuffer {
    /// Raw little-endian element bytes. Length = `row_count * elem_size`.
    pub values: Bytes,
    /// `Some` iff the column carried a null bitmap (`null_flag != 0`).
    pub validity: Option<Bytes>,
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
        /// Dense per-row codes; `0` in null slots (validity is the
        /// source of truth for null vs id-zero).
        codes: Vec<u32>,
        validity: Option<Bytes>,
        /// `Some` when the column carried its own dict inline
        /// (FLAG_DELTA_SYMBOL_DICT clear). `None` means codes index
        /// the connection-scoped dict. Each SYMBOL column in a batch
        /// gets its own local dict — they're not interchangeable.
        local_dict: Option<SymbolDict>,
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
        /// Concatenated UTF-8 bytes (validated at decode time). Borrowed
        /// from the frame payload via `Bytes::slice`.
        data: Bytes,
        validity: Option<Bytes>,
    },
    Binary {
        offsets: Vec<u32>,
        data: Bytes,
        validity: Option<Bytes>,
    },
    Geohash {
        buffer: ColumnBuffer,
        byte_width: u8,
        precision_bits: u8,
    },
    Decimal128 {
        buffer: ColumnBuffer,
        scale: i8,
    },
    Decimal256 {
        buffer: ColumnBuffer,
        scale: i8,
    },
    DoubleArray(ArrayBuffers),
    LongArray(ArrayBuffers),
}

/// Owned per-column buffers for an array column. All four offset/buffer
/// arrays are dense over `row_count`; null rows have empty shape and data
/// slices.
#[derive(Debug, Clone)]
pub struct ArrayBuffers {
    /// Byte offsets into `data` per row; length `row_count + 1`.
    pub data_offsets: Vec<u32>,
    /// Concatenated little-endian element bytes (8 B per element).
    pub data: Bytes,
    /// Concatenated per-row shape entries (one `u32` per dimension).
    pub shapes: Vec<u32>,
    /// Offsets into `shapes` per row; length `row_count + 1`.
    pub shape_offsets: Vec<u32>,
    pub validity: Option<Bytes>,
}

/// One decoded `RESULT_BATCH`.
#[derive(Debug, Clone)]
pub struct DecodedBatch {
    pub request_id: i64,
    pub batch_seq: u64,
    pub row_count: usize,
    pub columns: Vec<DecodedColumn>,
    /// Per-batch wire flags from the frame header (`FLAG_GORILLA`,
    /// `FLAG_DELTA_SYMBOL_DICT`, `FLAG_ZSTD`).
    pub flags: u8,
}

impl DecodedBatch {
    /// Project a single column to a borrowing [`ColumnView`].
    ///
    /// `dict` should be the connection's [`SymbolDict`] (only consulted for
    /// `Symbol` columns; ignored otherwise but required so the call site is
    /// borrow-correct in the streaming case).
    #[inline]
    pub fn column_view<'a>(&'a self, idx: usize, dict: &'a SymbolDict) -> Result<ColumnView<'a>> {
        let col = self
            .columns
            .get(idx)
            .ok_or_else(|| fmt!(InvalidApiCall, "column index {} out of range", idx))?;
        Ok(match col {
            DecodedColumn::Boolean(b) => {
                ColumnView::Boolean(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Byte(b) => {
                ColumnView::Byte(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Short(b) => {
                ColumnView::Short(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Int(b) => {
                ColumnView::Int(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Long(b) => {
                ColumnView::Long(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Float(b) => {
                ColumnView::Float(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Double(b) => {
                ColumnView::Double(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Timestamp(b) => {
                ColumnView::Timestamp(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Date(b) => {
                ColumnView::Date(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::TimestampNanos(b) => ColumnView::TimestampNanos(FixedColumn::new(
                &b.values,
                validity_of(b, self.row_count)?,
            )),
            DecodedColumn::Char(b) => {
                ColumnView::Char(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Ipv4(b) => {
                ColumnView::Ipv4(FixedColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Uuid(b) => {
                ColumnView::Uuid(UuidColumn::new(&b.values, validity_of(b, self.row_count)?))
            }
            DecodedColumn::Long256(b) => ColumnView::Long256(Long256Column::new(
                &b.values,
                validity_of(b, self.row_count)?,
            )),
            DecodedColumn::Decimal64 { buffer, scale } => ColumnView::Decimal64(
                Decimal64Column::new(&buffer.values, validity_of(buffer, self.row_count)?, *scale),
            ),
            DecodedColumn::Symbol {
                codes,
                validity,
                local_dict,
            } => {
                let active_dict = local_dict.as_ref().unwrap_or(dict);
                ColumnView::Symbol(SymbolColumn::new(
                    codes,
                    validity_from_opt(validity, self.row_count)?,
                    active_dict,
                ))
            }
            DecodedColumn::Varchar {
                offsets,
                data,
                validity,
            } => {
                // Safety: `decode_varchar` validates the concatenated
                // `data` buffer as UTF-8 and only emits offsets at
                // codepoint boundaries (see decoder.rs `decode_varchar`,
                // the `std::str::from_utf8(&data)` check around the
                // `utf8` flag). Both invariants required by
                // `VarcharColumn::new` therefore hold.
                let view = unsafe {
                    VarcharColumn::new(offsets, data, validity_from_opt(validity, self.row_count)?)
                };
                ColumnView::Varchar(view)
            }
            DecodedColumn::Binary {
                offsets,
                data,
                validity,
            } => ColumnView::Binary(BinaryColumn::new(
                offsets,
                data,
                validity_from_opt(validity, self.row_count)?,
            )),
            DecodedColumn::Geohash {
                buffer,
                byte_width,
                precision_bits,
            } => ColumnView::Geohash(GeohashColumn::new(
                &buffer.values,
                *byte_width,
                *precision_bits,
                validity_of(buffer, self.row_count)?,
            )),
            DecodedColumn::Decimal128 { buffer, scale } => ColumnView::Decimal128(
                Decimal128Column::new(&buffer.values, validity_of(buffer, self.row_count)?, *scale),
            ),
            DecodedColumn::Decimal256 { buffer, scale } => ColumnView::Decimal256(
                Decimal256Column::new(&buffer.values, validity_of(buffer, self.row_count)?, *scale),
            ),
            DecodedColumn::DoubleArray(b) => ColumnView::DoubleArray(DoubleArrayColumn::new(
                &b.data_offsets,
                &b.data,
                &b.shapes,
                &b.shape_offsets,
                validity_from_opt(&b.validity, self.row_count)?,
            )),
            DecodedColumn::LongArray(b) => ColumnView::LongArray(LongArrayColumn::new(
                &b.data_offsets,
                &b.data,
                &b.shapes,
                &b.shape_offsets,
                validity_from_opt(&b.validity, self.row_count)?,
            )),
        })
    }
}

#[inline]
fn validity_of<'a>(buf: &'a ColumnBuffer, row_count: usize) -> Result<Validity<'a>> {
    validity_from_opt(&buf.validity, row_count)
}

#[inline]
fn validity_from_opt<'a>(validity: &'a Option<Bytes>, row_count: usize) -> Result<Validity<'a>> {
    match validity {
        None => Ok(Validity::None),
        Some(bytes) => Validity::from_bitmap(bytes, row_count),
    }
}

// ---------------------------------------------------------------------------
// Top-level decode
// ---------------------------------------------------------------------------

/// Decode a `RESULT_BATCH` payload (the bytes following the 12-byte frame
/// header). Mutates `dict` if the batch carries a delta dict section. On
/// `batch_seq == 0` it parses the inline schema and stores it in
/// `query_schema`; continuation batches reuse the schema held there.
pub fn decode_result_batch(
    payload: &Bytes,
    flags_byte: u8,
    dict: &mut SymbolDict,
    query_schema: &mut Option<Schema>,
    zstd_scratch: &mut ZstdScratch,
) -> Result<DecodedBatch> {
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

    // The `msg_kind / request_id / batch_seq` prefix is always
    // uncompressed; FLAG_ZSTD covers everything after it (delta-dict
    // section + table block + per-column data) as a single zstd frame.
    // `body` is the parent Bytes used by per-column decoders for zero-copy
    // slicing — either a slice into `payload` (no compression) or a
    // freshly-owned Bytes wrapping the decompressed Vec.
    let _ = &zstd_scratch;
    let body: Bytes = if flags_byte & flags::ZSTD != 0 {
        #[cfg(feature = "compression-zstd")]
        {
            zstd_decompress_body(r.remaining(), zstd_scratch)?
        }
        #[cfg(not(feature = "compression-zstd"))]
        {
            return Err(fmt!(
                UnsupportedServer,
                "server sent FLAG_ZSTD batch but client was built without the \
                 `compression-zstd` feature"
            ));
        }
    } else {
        payload.slice(r.pos()..)
    };
    let mut r = ByteReader::new(&body);

    if flags_byte & flags::DELTA_SYMBOL_DICT != 0 {
        let consumed = dict.apply_delta_from_bytes(r.remaining())?;
        r.advance(consumed)?;
    }

    // Table block.
    //
    // The wire-supplied lengths and counts below are all sanity-capped
    // against constants mirrored from the Java reference client. Without
    // these, a hostile or corrupted varint could request a multi-GiB
    // up-front allocation and OOM the client before any wire-length
    // bounds check fires. The constants match `QwpConstants.java` /
    // `QwpResultBatchDecoder.java` in `java-questdb-client`.
    let name_len = r.read_varint_usize()?;
    if name_len > MAX_TABLE_NAME_LENGTH {
        return Err(fmt!(
            ProtocolError,
            "table name length {} exceeds max {}",
            name_len,
            MAX_TABLE_NAME_LENGTH
        ));
    }
    r.read_bytes(name_len)?; // table name; ignored for query results
    let row_count = r.read_varint_usize()?;
    if row_count > MAX_ROWS_PER_BATCH {
        return Err(fmt!(
            ProtocolError,
            "table block declares {} rows; max supported is {}",
            row_count,
            MAX_ROWS_PER_BATCH
        ));
    }
    // Schema. The full column list rides only the first batch of a query
    // (batch_seq == 0): col_count followed by the inline column descriptors.
    // Continuation batches (batch_seq > 0) carry rows only and reuse the
    // schema parsed from batch 0, which the caller holds in `query_schema`.
    if batch_seq == 0 {
        let col_count = r.read_varint_usize()?;
        if col_count > MAX_COLUMNS_PER_TABLE {
            return Err(fmt!(
                ProtocolError,
                "table block declares {} columns; max supported is {}",
                col_count,
                MAX_COLUMNS_PER_TABLE
            ));
        }
        let (schema, consumed) = Schema::decode_inline(r.remaining(), col_count)?;
        r.advance(consumed)?;
        *query_schema = Some(schema);
    }
    let schema = query_schema.as_ref().ok_or_else(|| {
        fmt!(
            ProtocolError,
            "RESULT_BATCH batch_seq={} arrived before the schema-bearing batch_seq=0",
            batch_seq
        )
    })?;
    let col_count = schema.len();

    // The shared borrow of `query_schema` via `schema` lives until the end
    // of this batch decode; `decode_column` below takes neither
    // `query_schema` nor `dict`, so iterating `schema.columns()` directly
    // is borrow-check clean and avoids a per-batch `Vec<ColumnKind>`
    // allocation that scales with column count.
    let mut columns = Vec::with_capacity(col_count);
    let connection_dict_size = dict.len();
    for (i, col_meta) in schema.columns().iter().enumerate() {
        let kind = col_meta.kind;
        let col = decode_column(
            &mut r,
            &body,
            kind,
            row_count,
            flags_byte,
            connection_dict_size,
        )
        .map_err(|e| {
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
        row_count,
        columns,
        flags: flags_byte,
    })
}

// ---------------------------------------------------------------------------
// Per-column decode
// ---------------------------------------------------------------------------

fn decode_column(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    kind: ColumnKind,
    row_count: usize,
    flags_byte: u8,
    connection_dict_size: usize,
) -> Result<DecodedColumn> {
    Ok(match kind {
        ColumnKind::Boolean => DecodedColumn::Boolean(decode_boolean(r, parent, row_count)?),
        ColumnKind::Byte => {
            DecodedColumn::Byte(decode_fixed_non_nullable(r, parent, row_count, 1, "BYTE")?)
        }
        ColumnKind::Short => {
            DecodedColumn::Short(decode_fixed_non_nullable(r, parent, row_count, 2, "SHORT")?)
        }
        ColumnKind::Int => DecodedColumn::Int(decode_fixed(
            r,
            parent,
            row_count,
            4,
            Some(&null_sentinel::I32_LE),
        )?),
        ColumnKind::Long => DecodedColumn::Long(decode_fixed(
            r,
            parent,
            row_count,
            8,
            Some(&null_sentinel::I64_LE),
        )?),
        ColumnKind::Float => DecodedColumn::Float(decode_fixed(
            r,
            parent,
            row_count,
            4,
            Some(&null_sentinel::F32_NAN_LE),
        )?),
        ColumnKind::Double => DecodedColumn::Double(decode_fixed(
            r,
            parent,
            row_count,
            8,
            Some(&null_sentinel::F64_NAN_LE),
        )?),
        ColumnKind::Char => {
            DecodedColumn::Char(decode_fixed_non_nullable(r, parent, row_count, 2, "CHAR")?)
        }
        // IPv4 NULL sentinel is `0` per spec §11.5; zero-fill is correct,
        // pass `None` to short-circuit the per-row sentinel copy.
        ColumnKind::Ipv4 => DecodedColumn::Ipv4(decode_fixed(r, parent, row_count, 4, None)?),
        ColumnKind::Uuid => DecodedColumn::Uuid(decode_fixed(
            r,
            parent,
            row_count,
            16,
            Some(&null_sentinel::UUID_LE),
        )?),
        ColumnKind::Long256 => DecodedColumn::Long256(decode_fixed(
            r,
            parent,
            row_count,
            32,
            Some(&null_sentinel::LONG256_LE),
        )?),

        ColumnKind::Timestamp => {
            DecodedColumn::Timestamp(decode_temporal(r, parent, row_count, flags_byte)?)
        }
        ColumnKind::Date => DecodedColumn::Date(decode_temporal(r, parent, row_count, flags_byte)?),
        ColumnKind::TimestampNanos => {
            DecodedColumn::TimestampNanos(decode_temporal(r, parent, row_count, flags_byte)?)
        }

        ColumnKind::Symbol => {
            let (codes, validity, local_dict) =
                decode_symbol(r, parent, row_count, flags_byte, connection_dict_size)?;
            DecodedColumn::Symbol {
                codes,
                validity,
                local_dict,
            }
        }

        ColumnKind::Decimal64 => {
            let (scale, buffer) = decode_decimal64(r, parent, row_count)?;
            DecodedColumn::Decimal64 { buffer, scale }
        }

        ColumnKind::Varchar => {
            let (offsets, data, validity) =
                decode_varlen(r, parent, row_count, /*utf8=*/ true)?;
            DecodedColumn::Varchar {
                offsets,
                data,
                validity,
            }
        }
        ColumnKind::Binary => {
            let (offsets, data, validity) =
                decode_varlen(r, parent, row_count, /*utf8=*/ false)?;
            DecodedColumn::Binary {
                offsets,
                data,
                validity,
            }
        }

        ColumnKind::Geohash => {
            let (buffer, byte_width, precision_bits) = decode_geohash(r, parent, row_count)?;
            DecodedColumn::Geohash {
                buffer,
                byte_width,
                precision_bits,
            }
        }
        ColumnKind::Decimal128 => {
            let (scale, buffer) = decode_decimal_wide(r, parent, row_count, 16)?;
            DecodedColumn::Decimal128 { buffer, scale }
        }
        ColumnKind::Decimal256 => {
            let (scale, buffer) = decode_decimal_wide(r, parent, row_count, 32)?;
            DecodedColumn::Decimal256 { buffer, scale }
        }

        ColumnKind::DoubleArray => DecodedColumn::DoubleArray(decode_array(r, parent, row_count)?),
        ColumnKind::LongArray => DecodedColumn::LongArray(decode_array(r, parent, row_count)?),
    })
}

/// Maximum element count we accept for a single array row, as a guard
/// against decode-bombs from a hostile server. 16M elements × 8 B = 128 MiB
/// per row, which already exceeds the per-batch wire cap.
const MAX_ARRAY_ELEMENTS_PER_ROW: u64 = 16 * 1024 * 1024;

/// Maximum rank we accept for a single array row. Matches the QuestDB
/// engine cap; rejects malformed `nDims` early instead of letting a
/// hostile server force the decoder into a long per-row loop.
const MAX_ARRAY_DIMS: usize = 32;

/// DOUBLE_ARRAY / LONG_ARRAY column body (after validity).
///
/// Per non-null row: `1B nDims` + `nDims × u32_le dim_lens` + `prod(dims) × 8 LE element bytes`.
/// Element type only differs by interpretation — wire is identical, so
/// one decoder serves both.
fn decode_array(r: &mut ByteReader<'_>, parent: &Bytes, row_count: usize) -> Result<ArrayBuffers> {
    let validity = decode_validity(r, parent, row_count)?;

    let mut data_offsets = Vec::with_capacity(row_count + 1);
    let mut data: Vec<u8> = Vec::new();
    let mut shapes: Vec<u32> = Vec::new();
    let mut shape_offsets = Vec::with_capacity(row_count + 1);

    data_offsets.push(0u32);
    shape_offsets.push(0u32);

    for row in 0..row_count {
        if is_null_at_opt(&validity, row) {
            data_offsets.push(*data_offsets.last().unwrap());
            shape_offsets.push(*shape_offsets.last().unwrap());
            continue;
        }

        let n_dims = r.read_u8()? as usize;
        if n_dims == 0 {
            return Err(fmt!(
                ProtocolError,
                "array row {} has nDims=0 (must be >= 1)",
                row
            ));
        }
        if n_dims > MAX_ARRAY_DIMS {
            return Err(fmt!(
                ProtocolError,
                "array row {row} has nDims={n_dims}; max {MAX_ARRAY_DIMS}"
            ));
        }

        let mut total: u64 = 1;
        let dims_start = shapes.len();
        for d in 0..n_dims {
            let dim_bytes = r.read_bytes(4)?;
            let dim = u32::from_le_bytes(dim_bytes.try_into().unwrap());
            shapes.push(dim);
            total = total.checked_mul(dim as u64).ok_or_else(|| {
                fmt!(
                    ProtocolError,
                    "array row {} shape product overflow at dim {}",
                    row,
                    d
                )
            })?;
            // Bound every prefix product, not just the final one: `[2^31, 0]`
            // has zero elements but a leading dim that explodes list nesting.
            if total > MAX_ARRAY_ELEMENTS_PER_ROW {
                return Err(fmt!(
                    LimitExceeded,
                    "array row {} has {} elements (max {})",
                    row,
                    total,
                    MAX_ARRAY_ELEMENTS_PER_ROW
                ));
            }
        }
        let byte_count = (total as usize)
            .checked_mul(8)
            .ok_or_else(|| fmt!(ProtocolError, "array row {} byte count overflow", row))?;
        let elements = r.read_bytes(byte_count)?;
        data.extend_from_slice(elements);

        let new_data_off = u32::try_from(data.len())
            .map_err(|_| fmt!(ProtocolError, "array column data exceeds u32 byte offset"))?;
        data_offsets.push(new_data_off);
        let new_shape_off = u32::try_from(dims_start + n_dims)
            .map_err(|_| fmt!(ProtocolError, "array column shape table exceeds u32"))?;
        shape_offsets.push(new_shape_off);
    }

    Ok(ArrayBuffers {
        data_offsets,
        data: Bytes::from(data),
        shapes,
        shape_offsets,
        validity,
    })
}

/// GEOHASH column body (after validity).
///
/// Wire: `varint precision_bits` (1..60), then `non_null × ceil(precision_bits/8)`
/// LE bytes. Densified into `row_count × byte_width` with null slots zeroed.
fn decode_geohash(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
) -> Result<(ColumnBuffer, u8, u8)> {
    let validity = decode_validity(r, parent, row_count)?;
    let precision_bits = r.read_varint_u64()?;
    if precision_bits == 0 || precision_bits > 60 {
        return Err(fmt!(
            ProtocolError,
            "geohash precision_bits {} outside 1..=60",
            precision_bits
        ));
    }
    let byte_width = precision_bits.div_ceil(8) as u8;
    // GEOHASH NULL sentinel per spec §11.5 is `-1` sign-extended across
    // the column's storage width. `0xFF` repeated `byte_width` times.
    let sentinel = &null_sentinel::GEOHASH_FF[..byte_width as usize];
    let buffer = densify_fixed(
        r,
        parent,
        row_count,
        byte_width as usize,
        validity,
        Some(sentinel),
    )?;
    Ok((buffer, byte_width, precision_bits as u8))
}

/// DECIMAL128 / DECIMAL256: column-level 1-byte scale, then non_null × width
/// LE bytes; densified.
fn decode_decimal_wide(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    width: usize,
) -> Result<(i8, ColumnBuffer)> {
    let validity = decode_validity(r, parent, row_count)?;
    let scale = r.read_u8()? as i8;
    if !(0..=crate::egress::binds::MAX_DECIMAL_SCALE).contains(&scale) {
        return Err(fmt!(
            ProtocolError,
            "decimal scale {} outside 0..={}",
            scale,
            crate::egress::binds::MAX_DECIMAL_SCALE
        ));
    }
    let per_width_max: i8 = match width {
        8 => 18,
        16 => 38,
        32 => crate::egress::binds::MAX_DECIMAL_SCALE,
        _ => crate::egress::binds::MAX_DECIMAL_SCALE,
    };
    if scale > per_width_max {
        return Err(fmt!(
            ProtocolError,
            "DECIMAL{} scale {} exceeds per-width maximum {}",
            width * 8,
            scale,
            per_width_max
        ));
    }
    // DECIMAL64 NULL is `Long.MIN_VALUE` (spec §11.5). DECIMAL128 NULL is
    // both halves `Long.MIN_VALUE` (server: `lo == LONG_NULL && hi ==
    // LONG_NULL`); DECIMAL256 NULL is four halves `Long.MIN_VALUE`
    // (server: `decimal128Sink.isNull()` over the full 32-byte sink).
    // The 16/32-byte patterns are identical to UUID / LONG256 — every
    // 8th byte 0x80, the rest 0x00.
    let sentinel: &[u8] = match width {
        8 => &null_sentinel::I64_LE,
        16 => &null_sentinel::UUID_LE,
        32 => &null_sentinel::LONG256_LE,
        other => {
            return Err(fmt!(
                ProtocolError,
                "DECIMAL width must be 8/16/32, got {other}"
            ));
        }
    };
    let buffer = densify_fixed(r, parent, row_count, width, validity, Some(sentinel))?;
    Ok((scale, buffer))
}

/// Per-type NULL sentinel patterns.
///
/// QWP egress §11.5 inherits QuestDB's in-engine NULL sentinels: NULL rows
/// in dense column views carry these bit patterns, simultaneously with
/// the row being marked NULL in the validity bitmap. Our decoder takes
/// compact wire data (only non-null values) and densifies into a
/// `row_count`-sized buffer; spec compliance means filling the null slots
/// with these sentinels, not zero, so a user reading `value(row)` without
/// first calling `is_null(row)` sees the same byte pattern they would have
/// observed had the server pre-densified the column itself.
mod null_sentinel {
    /// `Numbers.INT_NULL = Integer.MIN_VALUE` (4 LE bytes).
    pub const I32_LE: [u8; 4] = i32::MIN.to_le_bytes();
    /// `Numbers.LONG_NULL = Long.MIN_VALUE` (8 LE bytes). Used by LONG,
    /// DATE, TIMESTAMP, TIMESTAMP_NANOS, DECIMAL64.
    pub const I64_LE: [u8; 8] = i64::MIN.to_le_bytes();
    /// `Float.NaN` canonical quiet-NaN bit pattern (Java's `Double.NaN`
    /// matches the IEEE 754 `0x7FC00000`).
    pub const F32_NAN_LE: [u8; 4] = 0x7FC0_0000u32.to_le_bytes();
    /// `Double.NaN` canonical quiet-NaN bit pattern (`0x7FF8_0000_0000_0000`).
    pub const F64_NAN_LE: [u8; 8] = 0x7FF8_0000_0000_0000u64.to_le_bytes();
    /// UUID NULL — both halves `Long.MIN_VALUE`. Layout: every 8th byte
    /// is `0x80`, all others `0x00`.
    pub const UUID_LE: [u8; 16] = [
        0, 0, 0, 0, 0, 0, 0, 0x80, // low half
        0, 0, 0, 0, 0, 0, 0, 0x80, // high half
    ];
    /// LONG256 NULL — four halves `Long.MIN_VALUE`. Same trailing-`0x80`
    /// layout as UUID, repeated four times.
    pub const LONG256_LE: [u8; 32] = [
        0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0,
        0, 0, 0, 0, 0x80,
    ];
    /// GEOHASH NULL — `-1` sign-extended across 1..=8 bytes. Slice to the
    /// column's byte_width.
    pub const GEOHASH_FF: [u8; 8] = [0xFF; 8];
}

/// Common helper: read `non_null × elem_size` compact bytes from `r` and
/// write them into a `row_count × elem_size` dense buffer.
///
/// `null_sentinel`, when `Some`, must have length exactly `elem_size`. It
/// pre-fills null slots so reading `value(row)` on a NULL row returns the
/// QuestDB sentinel (per spec §11.5) instead of zero. `None` keeps the
/// zero-fill path — used for types where the spec doesn't define a
/// sentinel (e.g. SYMBOL, where the validity bit is the sole null
/// indicator) or where the sentinel happens to be all-zero (IPv4).
fn densify_fixed(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    elem_size: usize,
    validity: Option<Bytes>,
    null_sentinel: Option<&[u8]>,
) -> Result<ColumnBuffer> {
    debug_assert!(
        null_sentinel.is_none_or(|s| s.len() == elem_size),
        "null_sentinel length must equal elem_size"
    );
    let dense_len = row_count
        .checked_mul(elem_size)
        .ok_or_else(|| fmt!(ProtocolError, "fixed column size overflow"))?;
    match &validity {
        None => {
            // Zero-copy: borrow the packed values straight out of the
            // payload buffer instead of allocating + memcpy'ing.
            let values = read_owned(r, parent, dense_len)?;
            Ok(ColumnBuffer { values, validity })
        }
        Some(bitmap) => {
            let non_null = row_count - count_nulls(bitmap, row_count);
            let compact = r.read_bytes(non_null * elem_size)?;
            let mut dense = allocate_dense_with_sentinel(dense_len, elem_size, null_sentinel);
            let mut src = 0usize;
            for row in 0..row_count {
                if !is_null_at(bitmap, row) {
                    let dst = row * elem_size;
                    dense[dst..dst + elem_size].copy_from_slice(&compact[src..src + elem_size]);
                    src += elem_size;
                }
            }
            Ok(ColumnBuffer {
                values: Bytes::from(dense),
                validity,
            })
        }
    }
}

/// Allocate a `dense_len`-byte buffer pre-filled with the per-element
/// null sentinel, or zero when `sentinel` is `None` / all-zero.
///
/// All-zero sentinels short-circuit to `vec![0u8; dense_len]` so we don't
/// pay the per-element copy when the type's spec sentinel is `0` (IPv4).
fn allocate_dense_with_sentinel(
    dense_len: usize,
    elem_size: usize,
    sentinel: Option<&[u8]>,
) -> Vec<u8> {
    debug_assert_eq!(
        dense_len % elem_size,
        0,
        "dense_len {dense_len} not a multiple of elem_size {elem_size}"
    );
    match sentinel {
        Some(s) if s.iter().any(|&b| b != 0) => {
            let mut dense = vec![0u8; dense_len];
            for chunk in dense.chunks_exact_mut(elem_size) {
                chunk.copy_from_slice(s);
            }
            dense
        }
        _ => vec![0u8; dense_len],
    }
}

/// VARCHAR / BINARY column body (after the validity section).
///
/// Wire layout: `(non_null + 1) × u32_le` offsets, then `compact_offsets[non_null]`
/// bytes of concatenated values. Returns dense per-row offsets
/// (`row_count + 1` entries; null rows zero-length) plus the original
/// compact data buffer (string boundaries are unchanged by densification).
/// `(offsets, data, validity)` for a decoded VARCHAR / BINARY column body.
type VarlenBuffers = (Vec<u32>, Bytes, Option<Bytes>);

fn decode_varlen(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    utf8: bool,
) -> Result<VarlenBuffers> {
    let validity = decode_validity(r, parent, row_count)?;
    let non_null = match &validity {
        None => row_count,
        Some(bitmap) => row_count - count_nulls(bitmap, row_count),
    };

    // Read the compact offsets array.
    let offsets_byte_len = (non_null + 1)
        .checked_mul(4)
        .ok_or_else(|| fmt!(ProtocolError, "varlen offsets size overflow"))?;
    let offsets_bytes = r.read_bytes(offsets_byte_len)?;
    let count = non_null + 1;
    let mut compact: Vec<u32> = Vec::with_capacity(count);
    // Bulk copy the LE wire bytes into the `Vec<u32>` backing buffer. On
    // little-endian targets this is the entire decode — one `memcpy`, no
    // per-row `from_le_bytes` / `try_into` / `push` shuffle. The source is
    // `&[u8]`, so source alignment is irrelevant; the destination is a
    // `Vec<u32>` of exactly `count` elements (= `offsets_byte_len` bytes).
    //
    // SAFETY: `compact`'s capacity is `count` u32s = `offsets_byte_len`
    // bytes; we copy exactly that many bytes from a non-overlapping slice
    // of the same length, then set the length.
    unsafe {
        std::ptr::copy_nonoverlapping(
            offsets_bytes.as_ptr(),
            compact.as_mut_ptr().cast::<u8>(),
            offsets_byte_len,
        );
        compact.set_len(count);
    }
    #[cfg(target_endian = "big")]
    for v in &mut compact {
        *v = v.swap_bytes();
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

    // Borrow the concatenated data bytes from the payload — zero-copy.
    let data_len = compact[non_null] as usize;
    let data = read_owned(r, parent, data_len)?;

    if utf8 {
        // `VarcharColumn::new` requires every offset to lie on a UTF-8
        // codepoint boundary; validating the buffer as a whole is not
        // sufficient. e.g. `data = [0xC3, 0xB1]` (the codepoint `ñ`) with
        // offsets `[0, 1, 2]` passes the global UTF-8 check, but the row-0
        // slice `[0xC3]` is not valid UTF-8 and would later be handed to
        // `from_utf8_unchecked` — undefined behaviour.
        let s = std::str::from_utf8(&data)
            .map_err(|e| fmt!(InvalidUtf8, "varchar data buffer not valid UTF-8: {}", e))?;
        for &off in &compact {
            if !s.is_char_boundary(off as usize) {
                return Err(fmt!(
                    InvalidUtf8,
                    "varchar offset {} does not lie on a UTF-8 codepoint boundary",
                    off
                ));
            }
        }
    }

    // No-null fast path: compact has `row_count + 1` entries already, in
    // exactly the dense layout the user-facing column expects. Reuse it.
    if validity.is_none() {
        debug_assert_eq!(compact.len(), row_count + 1);
        return Ok((compact, data, validity));
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

fn decode_validity(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
) -> Result<Option<Bytes>> {
    // Per the QWP wire spec the null_flag is 0x00 (no bitmap) or 0x01
    // (bitmap follows). Reject any other byte rather than silently
    // treating it as 0x01 — matches the strict-mask handling in
    // `cache_reset` decoding and surfaces server-side or wire-corruption
    // bugs immediately instead of hiding them.
    let null_flag = r.read_u8()?;
    match null_flag {
        0 => Ok(None),
        1 => {
            let bitmap_len = row_count.div_ceil(8);
            Ok(Some(read_owned(r, parent, bitmap_len)?))
        }
        other => Err(fmt!(
            ProtocolError,
            "unknown null_flag 0x{:02X}; expected 0x00 or 0x01",
            other
        )),
    }
}

/// Read `non_null_count × elem_size` compact bytes from the wire and write
/// them into a dense `row_count × elem_size` buffer. Null slots are filled
/// with `null_sentinel` per spec §11.5 (or zero when `None`).
fn decode_fixed(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    elem_size: usize,
    null_sentinel: Option<&[u8]>,
) -> Result<ColumnBuffer> {
    let validity = decode_validity(r, parent, row_count)?;
    densify_fixed(r, parent, row_count, elem_size, validity, null_sentinel)
}

/// Read and validate the `null_flag` byte for a column type the QWP spec
/// declares non-nullable on the wire (BOOLEAN, BYTE, SHORT, CHAR). Server
/// always emits `0x00` for these (see QuestDB's `QwpResultBatchBuffer.
/// appendCell` — only the `*OrNull` append paths can ever set `nullCount`,
/// and BOOLEAN/BYTE/SHORT/CHAR don't go through them). Anything else means
/// either a buggy server or wire corruption: reject loudly so the bytes
/// don't get reinterpreted as values and shift every later column's
/// interpretation by `bitmap_len`.
fn expect_no_validity_flag(r: &mut ByteReader<'_>, kind: &str) -> Result<()> {
    let null_flag = r.read_u8()?;
    if null_flag != 0 {
        return Err(fmt!(
            ProtocolError,
            "{} column has null_flag 0x{:02X}; spec requires 0x00 \
             ({} is not nullable on the wire)",
            kind,
            null_flag,
            kind
        ));
    }
    Ok(())
}

/// Decode a fixed-width column type that the QWP spec declares non-nullable
/// on the wire (BYTE, SHORT, CHAR). The wire layout is `null_flag=0x00`
/// followed by `row_count × elem_size` raw bytes — no bitmap, no
/// densification needed since every row carries a value.
fn decode_fixed_non_nullable(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    elem_size: usize,
    kind: &str,
) -> Result<ColumnBuffer> {
    expect_no_validity_flag(r, kind)?;
    let byte_count = row_count.checked_mul(elem_size).ok_or_else(|| {
        fmt!(
            ProtocolError,
            "{} column byte count overflow (row_count={}, elem_size={})",
            kind,
            row_count,
            elem_size
        )
    })?;
    let values = read_owned(r, parent, byte_count)?;
    Ok(ColumnBuffer {
        values,
        validity: None,
    })
}

/// QWP `BOOLEAN`: not nullable on the wire (the `null_flag` byte is always
/// `0x00`, no bitmap follows), values bit-packed into `ceil(row_count/8)`
/// bytes. We expand to one byte per row so `FixedColumn<u8>` can address
/// rows in O(1).
fn decode_boolean(
    r: &mut ByteReader<'_>,
    _parent: &Bytes,
    row_count: usize,
) -> Result<ColumnBuffer> {
    expect_no_validity_flag(r, "BOOLEAN")?;
    let bit_bytes = row_count.div_ceil(8);
    let bits = r.read_bytes(bit_bytes)?;

    let mut dense = vec![0u8; row_count];
    for (row, slot) in dense.iter_mut().enumerate() {
        let b = bits[row >> 3];
        *slot = (b >> (row & 7)) & 1;
    }
    Ok(ColumnBuffer {
        values: Bytes::from(dense),
        validity: None,
    })
}

fn decode_temporal(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    flags_byte: u8,
) -> Result<ColumnBuffer> {
    // TIMESTAMP / DATE / TIMESTAMP_NANOS share `Long.MIN_VALUE` as their
    // QuestDB NULL sentinel (spec §11.5).
    let sentinel = Some(&null_sentinel::I64_LE[..]);
    if flags_byte & flags::GORILLA == 0 {
        return decode_fixed(r, parent, row_count, 8, sentinel);
    }

    // Validity comes first under FLAG_GORILLA, same as every other column.
    let validity = decode_validity(r, parent, row_count)?;
    let non_null = match &validity {
        None => row_count,
        Some(bitmap) => row_count - count_nulls(bitmap, row_count),
    };

    let disc = r.read_u8()?;
    match disc {
        0x00 => densify_fixed(r, parent, row_count, 8, validity, sentinel),
        0x01 => decode_gorilla_temporal(r, row_count, non_null, validity),
        other => Err(fmt!(
            ProtocolError,
            "unknown temporal encoding discriminator 0x{:02X}",
            other
        )),
    }
}

fn decode_gorilla_temporal(
    r: &mut ByteReader<'_>,
    row_count: usize,
    non_null: usize,
    validity: Option<Bytes>,
) -> Result<ColumnBuffer> {
    // Spec note: a compliant server-side encoder shortcuts the
    // `non_null < 3` cases to `disc=0x00` (raw) and never reaches the
    // Gorilla branch with fewer than three values. We decode the
    // degenerate cases anyway so a future server variant or rare
    // flush pattern that emits Gorilla framing for very small columns
    // doesn't surface as a hard `ProtocolError`. The natural Gorilla
    // wire layout for `non_null < 3` is `min(non_null, 2)` bare seed
    // timestamps with no bitstream — which is what we read below.
    //
    // Densify into row_count × 8. Null slots get the QuestDB temporal
    // NULL sentinel (`Long.MIN_VALUE`) per spec §11.5 — same as the
    // non-Gorilla path. `checked_mul` mirrors the guard in
    // `densify_fixed`: `row_count` comes from a wire varint that has no
    // per-row size cap, so a 32-bit `usize` (or, more theoretically, a
    // malformed frame on 64-bit) could wrap and produce an undersized
    // buffer that the per-row write below then overruns.
    let dense_len = row_count
        .checked_mul(8)
        .ok_or_else(|| fmt!(ProtocolError, "gorilla temporal column size overflow"))?;
    let mut dense = allocate_dense_with_sentinel(dense_len, 8, Some(&null_sentinel::I64_LE));

    // Read up to two bare seed timestamps. They fill the first one or
    // two non-null rows; the remaining non-null rows (if any) come
    // from the Gorilla bitstream decoder below.
    let mut seeds = [0i64; 2];
    let seed_count = non_null.min(2);
    for seed in seeds.iter_mut().take(seed_count) {
        *seed = i64::from_le_bytes(r.read_bytes(8)?.try_into().unwrap());
    }

    let mut decoder = if non_null >= 3 {
        Some(crate::egress::gorilla::GorillaDecoder::new(
            seeds[0],
            seeds[1],
            r.remaining(),
        ))
    } else {
        None
    };

    // Single pass: walk the validity bitmap and write each decoded
    // value directly into its dense slot. Avoids the intermediate
    // `Vec<i64>` and second densify copy of the older two-pass version.
    let mut filled = 0usize;
    for row in 0..row_count {
        if is_null_at_opt(&validity, row) {
            continue;
        }
        let v = if filled < seed_count {
            seeds[filled]
        } else {
            // `non_null > seed_count` here implies `non_null >= 3`, so
            // `decoder` was built above. Return an error instead of
            // `expect` so a future refactor that violates the invariant
            // surfaces cleanly instead of aborting.
            let dec = decoder.as_mut().ok_or_else(|| {
                fmt!(
                    ProtocolError,
                    "Gorilla decoder state: non_null={non_null}, seed_count={seed_count}, filled={filled}"
                )
            })?;
            dec.decode_next()?
        };
        dense[row * 8..row * 8 + 8].copy_from_slice(&v.to_le_bytes());
        filled += 1;
        if filled == non_null {
            break;
        }
    }
    if let Some(d) = decoder {
        r.advance(d.bytes_consumed())?;
    }

    Ok(ColumnBuffer {
        values: Bytes::from(dense),
        validity,
    })
}

/// SYMBOL column body. Two modes per the spec:
///
/// - **Delta / connection-scoped** (FLAG_DELTA_SYMBOL_DICT set on the
///   batch): no per-column dict; per-row varint ids index into the
///   connection-scoped dict that was just (optionally) extended by the
///   batch's delta-dict section.
/// - **Column-local** (flag clear): the column body opens with
///   `varint dict_size` then `dict_size × (varint len + bytes)`; the
///   per-row ids index into THAT dict only. Each SYMBOL column in the
///   batch carries its own independent local dict.
///
/// Either way we densify the per-row ids into a `row_count`-sized
/// `u32` buffer with `0` in null slots; validity is the source of
/// truth for null-vs-id-zero. Bounds checks reject ids beyond the
/// active dict's size and dict_size beyond row_count.
/// `(codes, validity, local_dict)` for a decoded SYMBOL column body.
type SymbolBuffers = (Vec<u32>, Option<Bytes>, Option<SymbolDict>);

fn decode_symbol(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    flags_byte: u8,
    connection_dict_size: usize,
) -> Result<SymbolBuffers> {
    let validity = decode_validity(r, parent, row_count)?;

    let (active_dict_size, local_dict) = if flags_byte & flags::DELTA_SYMBOL_DICT != 0 {
        // Delta mode: ids index the connection-scoped dict.
        (connection_dict_size, None)
    } else {
        // Column-local: read inline dict.
        let dict_size = r.read_varint_usize()?;
        if dict_size > row_count {
            return Err(fmt!(
                ProtocolError,
                "SYMBOL column-local dict_size {} > row_count {}",
                dict_size,
                row_count
            ));
        }
        let mut entries: Vec<&[u8]> = Vec::with_capacity(dict_size);
        for i in 0..dict_size {
            let entry_len = r.read_varint_usize().map_err(|e| {
                Error::new(
                    e.code(),
                    format!("SYMBOL local dict entry {} length: {}", i, e.msg()),
                )
            })?;
            entries.push(r.read_bytes(entry_len)?);
        }
        let mut local = SymbolDict::new();
        local.apply_delta(0, entries)?;
        (dict_size, Some(local))
    };

    let codes = if validity.is_none() {
        decode_codes_no_nulls(r, row_count, active_dict_size)?
    } else {
        let mut codes = vec![0u32; row_count];
        for (row, slot) in codes.iter_mut().enumerate() {
            if is_null_at_opt(&validity, row) {
                continue;
            }
            let code = r.read_varint_u64().map_err(|e| {
                Error::new(e.code(), format!("symbol code at row {}: {}", row, e.msg()))
            })?;
            let code32 = u32::try_from(code).map_err(|_| {
                fmt!(
                    ProtocolError,
                    "symbol code {} at row {} exceeds u32",
                    code,
                    row
                )
            })?;
            if (code32 as usize) >= active_dict_size {
                return Err(fmt!(
                    ProtocolError,
                    "symbol id {} at row {} out of range (dict size {})",
                    code32,
                    row,
                    active_dict_size
                ));
            }
            *slot = code32;
        }
        codes
    };
    Ok((codes, validity, local_dict))
}

/// No-null fast path for SYMBOL code densification.
///
/// Inlines the 1-, 2-, and 3-byte varint cases (covers every code <= 2^21,
/// which is more than enough for our 100k-cardinality bench data); falls
/// back to the generic decoder for longer values. The bounds check against
/// the active dict size runs as a separate pass after decode so the inner
/// loop is straight-line and auto-vectorizes nicely.
fn decode_codes_no_nulls(
    r: &mut ByteReader<'_>,
    row_count: usize,
    active_dict_size: usize,
) -> Result<Vec<u32>> {
    let mut codes = vec![0u32; row_count];
    let bytes = r.remaining();
    let mut pos = 0usize;
    let limit = bytes.len();

    for slot in codes.iter_mut() {
        // Fast path: try 1-, 2-, 3-byte varints if at least 3 bytes remain.
        if pos + 3 <= limit {
            let b0 = bytes[pos];
            if b0 < 0x80 {
                *slot = b0 as u32;
                pos += 1;
                continue;
            }
            let b1 = bytes[pos + 1];
            if b1 < 0x80 {
                *slot = (b0 & 0x7F) as u32 | ((b1 as u32) << 7);
                pos += 2;
                continue;
            }
            let b2 = bytes[pos + 2];
            if b2 < 0x80 {
                *slot = (b0 & 0x7F) as u32 | (((b1 & 0x7F) as u32) << 7) | ((b2 as u32) << 14);
                pos += 3;
                continue;
            }
        }
        // Slow path: longer varints or near end of buffer. Catches 4- and
        // 5-byte u32-fitting cases plus any over-u32 we have to error on.
        let (v, n) = crate::egress::wire::varint::decode_u64(&bytes[pos..])
            .map_err(|e| Error::new(e.code(), format!("symbol code: {}", e.msg())))?;
        *slot =
            u32::try_from(v).map_err(|_| fmt!(ProtocolError, "symbol code {} exceeds u32", v))?;
        pos += n;
    }
    r.advance(pos)?;

    // Single-pass bounds check after decode. This pass auto-vectorizes
    // (compares u32 lanes to a scalar) and is a few percent of the total.
    let dict_size_u32 = u32::try_from(active_dict_size).map_err(|_| {
        fmt!(
            ProtocolError,
            "active dict size {} exceeds u32",
            active_dict_size
        )
    })?;
    // `any` lowers to a SIMD lane compare; `find` does not (the
    // first-true short-circuit forbids horizontal reduction).
    if codes.iter().any(|&c| c >= dict_size_u32) {
        let (row, &bad) = codes
            .iter()
            .enumerate()
            .find(|&(_, &c)| c >= dict_size_u32)
            .expect("any() reported a match");
        return Err(fmt!(
            ProtocolError,
            "symbol id {} at row {} out of range (dict size {})",
            bad,
            row,
            active_dict_size
        ));
    }
    Ok(codes)
}

/// DECIMAL64: column-level 1-byte scale follows the validity section, then
/// `non_null_count × 8` LE bytes; densified like the fixed-width path.
fn decode_decimal64(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
) -> Result<(i8, ColumnBuffer)> {
    let (scale, buffer) = decode_decimal_wide(r, parent, row_count, 8)?;
    Ok((scale, buffer))
}

/// Maximum zstd-decompressed `RESULT_BATCH` body size we accept. Matches
/// the per-batch wire cap from the spec (16 MiB) with a 4x safety margin
/// so legitimate frames never trip the cap.
#[cfg(feature = "compression-zstd")]
const MAX_ZSTD_DECOMPRESSED: u64 = 64 * 1024 * 1024;

/// Max recyclable buffers held by [`ZstdBufferPool`]. Two is the
/// steady-state for typical streaming: one buffer is in-flight as the
/// caller's current batch, one is being filled for the next batch.
/// Anything beyond that means the consumer is hoarding `Bytes` clones
/// — in which case dropping the extra allocations rather than caching
/// them is the right choice (lets the global allocator reclaim).
#[cfg(feature = "compression-zstd")]
const ZSTD_POOL_CAPACITY: usize = 2;

/// Per-connection recycle pool of decompressed-body `Vec<u8>`s. Each
/// `Bytes` returned by [`zstd_decompress_body`] wraps a `Vec` drawn
/// from the pool via [`PooledZstdBuffer`]; when the last clone of that
/// `Bytes` is dropped, the `Drop` impl returns the `Vec` (capacity
/// preserved) to this pool for the next decompress to claim.
///
/// `Arc<Mutex<...>>`-shared between [`ZstdScratch`] (the draw side)
/// and every live [`PooledZstdBuffer`] (the return side). The `Mutex`
/// is dead-weight in normal use — every draw and return happens on
/// the cursor thread that owns the `Reader` — but `Bytes::from_owner`
/// requires the owner to be `Send + Sync + 'static`, which forces a
/// thread-safe pool handle. Lock-uncontended overhead is ~tens of ns
/// per decompress, negligible against the savings from skipping a
/// multi-MB allocation.
#[cfg(feature = "compression-zstd")]
#[derive(Default)]
struct ZstdBufferPool {
    buffers: std::sync::Mutex<Vec<Vec<u8>>>,
}

/// Owner handed to `Bytes::from_owner` so the decompressed body's
/// backing `Vec` is returned to the pool on drop instead of being
/// freed. `AsRef<[u8]>` exposes the full payload; `Bytes` slicing on
/// top of this is zero-copy by ref-count.
#[cfg(feature = "compression-zstd")]
struct PooledZstdBuffer {
    buf: Vec<u8>,
    pool: std::sync::Arc<ZstdBufferPool>,
}

#[cfg(feature = "compression-zstd")]
impl AsRef<[u8]> for PooledZstdBuffer {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(feature = "compression-zstd")]
impl Drop for PooledZstdBuffer {
    fn drop(&mut self) {
        // Best-effort pool return. A poisoned mutex (would only happen
        // on a panic in another holder) just lets the buffer be freed
        // normally — pool reuse is a perf optimisation, never a
        // correctness invariant.
        let Ok(mut guard) = self.pool.buffers.lock() else {
            return;
        };
        if guard.len() >= ZSTD_POOL_CAPACITY {
            return;
        }
        // Take the buffer so the `mem::take` leaves an empty Vec
        // (capacity 0) in `self.buf` for the impending drop. Skip
        // empty (no-capacity) buffers — they amortise nothing.
        let buf = std::mem::take(&mut self.buf);
        if buf.capacity() > 0 {
            guard.push(buf);
        }
    }
}

/// Per-connection scratch state for zstd batch decompression.
///
/// Holds a persistent `Decompressor` (so the ZSTD_DCtx isn't recreated
/// per batch) and a small recycle pool of output buffers. The pool
/// keeps the multi-MB decompressed-body `Vec` capacity across batches:
/// each `Bytes` we return wraps a pooled `Vec`, returned to the pool
/// when the downstream batch (and any column views borrowing into it)
/// is dropped. Always exists so the decode API doesn't need
/// feature-gated signatures; the fields inside are only populated when
/// `compression-zstd` is on.
#[derive(Default)]
pub struct ZstdScratch {
    #[cfg(feature = "compression-zstd")]
    decompressor: Option<zstd::bulk::Decompressor<'static>>,
    #[cfg(feature = "compression-zstd")]
    pool: std::sync::Arc<ZstdBufferPool>,
}

impl ZstdScratch {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Decompress a single zstd frame containing the body of a
/// `RESULT_BATCH`. The frame header must declare a content size
/// (`ZSTD_c_contentSizeFlag` is on by default in the server encoder);
/// rejecting "unknown" content size keeps decode-bomb amplification
/// closed.
#[cfg(feature = "compression-zstd")]
fn zstd_decompress_body(compressed: &[u8], scratch: &mut ZstdScratch) -> Result<Bytes> {
    let size = match zstd::zstd_safe::get_frame_content_size(compressed) {
        Ok(Some(n)) => n,
        Ok(None) => {
            return Err(fmt!(
                ProtocolError,
                "zstd frame missing content size (protocol violation)"
            ));
        }
        Err(_) => {
            return Err(fmt!(
                ProtocolError,
                "invalid zstd frame header (truncated, bad magic, or content size > u64::MAX)"
            ));
        }
    };
    if size > MAX_ZSTD_DECOMPRESSED {
        return Err(fmt!(
            LimitExceeded,
            "zstd frame content size {} exceeds client cap {}",
            size,
            MAX_ZSTD_DECOMPRESSED
        ));
    }
    let usize_size = usize::try_from(size).map_err(|_| {
        fmt!(
            LimitExceeded,
            "zstd frame content size {} does not fit in usize",
            size
        )
    })?;

    let decompressor = match scratch.decompressor.as_mut() {
        Some(d) => d,
        None => {
            scratch.decompressor = Some(
                zstd::bulk::Decompressor::new()
                    .map_err(|e| fmt!(ProtocolError, "zstd decompressor init failed: {}", e))?,
            );
            scratch.decompressor.as_mut().unwrap()
        }
    };

    // Draw a recycled `Vec<u8>` from the pool if one is available,
    // otherwise allocate fresh. The pool entries retain capacity from
    // their prior decompression — for steady-state batch sizes the
    // `reserve` below is a no-op and there is zero allocation per
    // batch on the hot path.
    let mut buf = scratch
        .pool
        .buffers
        .lock()
        .ok()
        .and_then(|mut g| g.pop())
        .unwrap_or_default();
    buf.clear();
    buf.reserve(usize_size);
    let written = decompressor
        .decompress_to_buffer(compressed, &mut buf)
        .map_err(|e| fmt!(ProtocolError, "zstd decompress failed: {}", e))?;
    if written != usize_size {
        return Err(fmt!(
            ProtocolError,
            "zstd decompressed size {} != frame content size {}",
            written,
            size
        ));
    }
    // Defensive truncate so the AsRef view exposes exactly the bytes
    // the decompressor wrote (it should always equal `usize_size` per
    // the check above, but truncating is cheap insurance against a
    // future zstd quirk that decompresses-less-than-promised without
    // erroring).
    buf.truncate(usize_size);
    let owner = PooledZstdBuffer {
        buf,
        pool: std::sync::Arc::clone(&scratch.pool),
    };
    Ok(Bytes::from_owner(owner))
}

fn count_nulls(bitmap: &[u8], row_count: usize) -> usize {
    let full_bytes = row_count >> 3;
    let tail_bits = row_count & 7;

    // 8-byte-chunked popcount. One `u64::count_ones` lowers to a
    // single hardware popcount instruction on every supported target
    // (POPCNT on x86_64 from SSE4.2, CNT on AArch64), so the chunked
    // loop processes ~8× as many bits per cycle as the byte-by-byte
    // loop the codec used to walk.
    //
    // `from_ne_bytes` on a wire byte stream looks wrong at first
    // glance, but is correct here and intentional: we only call
    // `count_ones` on the resulting `u64`, which counts set bits
    // independent of byte order. The decoded *value* of the `u64` is
    // never used, so the endianness mismatch a `from_le_bytes` would
    // fix doesn't exist — both endiannesses see the same set-bit
    // population. Using `from_ne_bytes` skips the byte-swap
    // `from_le_bytes` would emit on a big-endian target (no-op on
    // little-endian).
    //
    // If this code ever starts reading the `u64` as a number (e.g.
    // bit-scan to find the *position* of a null), switch to
    // `from_le_bytes` — positions are endian-sensitive.
    let body = &bitmap[..full_bytes];
    let mut chunks = body.chunks_exact(8);
    let mut nulls: usize = 0;
    for c in chunks.by_ref() {
        let w = u64::from_ne_bytes(c.try_into().unwrap());
        nulls += w.count_ones() as usize;
    }
    for b in chunks.remainder() {
        nulls += b.count_ones() as usize;
    }
    if tail_bits != 0 {
        let mask = (1u8 << tail_bits) - 1;
        nulls += (bitmap[full_bytes] & mask).count_ones() as usize;
    }
    nulls
}

fn is_null_at(bitmap: &[u8], row: usize) -> bool {
    (bitmap[row >> 3] >> (row & 7)) & 1 != 0
}

fn is_null_at_opt(validity: &Option<Bytes>, row: usize) -> bool {
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
    use crate::egress::schema::{Schema, SchemaColumn};
    use crate::egress::wire::varint::encode_u64;

    /// Reference implementation kept inline in the test: byte-by-byte
    /// popcount with the same tail-bit masking rule. We assert the
    /// chunked production implementation matches this for every
    /// `row_count` in the windows that exercise the cross-chunk
    /// boundary, the chunks-remainder boundary (1-7 bytes after the
    /// last full u64), and the tail-bit boundary (1-7 bits in the
    /// last byte).
    fn count_nulls_naive(bitmap: &[u8], row_count: usize) -> usize {
        let full_bytes = row_count >> 3;
        let tail_bits = row_count & 7;
        let mut nulls = 0usize;
        for b in &bitmap[..full_bytes] {
            nulls += b.count_ones() as usize;
        }
        if tail_bits != 0 {
            let mask = (1u8 << tail_bits) - 1;
            nulls += (bitmap[full_bytes] & mask).count_ones() as usize;
        }
        nulls
    }

    #[test]
    fn count_nulls_chunked_matches_naive_across_boundaries() {
        // Build a deterministic bitmap that exercises a mix of byte
        // values (0x00, 0xFF, alternating, low/high nibbles) over
        // 256 bits — 4 full u64 chunks. Then sample `row_count`
        // across every boundary that matters:
        //   - zero rows (empty)
        //   - 1..=7 tail-only bits
        //   - exactly 8, 16, ..., 64, 128, 192, 256 (whole bytes / chunks)
        //   - off-by-one around each chunk boundary (62, 63, 64, 65)
        //   - exactly one chunk + remainder bytes (72, 80, 88)
        //   - chunk + remainder + tail bits (73..=79, 81..=87, etc)
        let mut bitmap = vec![0u8; 32];
        for (i, b) in bitmap.iter_mut().enumerate() {
            *b = match i % 4 {
                0 => 0x00,
                1 => 0xFF,
                2 => 0xA5,
                _ => 0x5A,
            };
        }
        let row_counts: &[usize] = &[
            0, 1, 2, 3, 4, 5, 6, 7, // tail-only
            8, 9, 15, 16, 23, 24, // small full-byte cases
            56, 57, 62, 63, 64, 65, 66, 67, // chunk boundary
            71, 72, 73, // chunk + 1-byte remainder + tail
            79, 80, 81, // chunk + 2-byte remainder + tail
            87, 88, // chunk + 3-byte remainder
            127, 128, 129, // two-chunk boundary
            191, 192, 193, // three-chunk boundary
            255, 256, // bitmap maximum
        ];
        for &rc in row_counts {
            let got = count_nulls(&bitmap, rc);
            let want = count_nulls_naive(&bitmap, rc);
            assert_eq!(got, want, "count_nulls mismatch at row_count={}", rc);
        }
    }

    /// FLAG_ZSTD rejection path: when the client was built WITHOUT the
    /// `compression-zstd` feature, the decoder must surface
    /// `ErrorCode::UnsupportedServer` rather than silently mis-
    /// interpret the compressed body as raw wire bytes. The arm is
    /// uncovered in default test runs because `almost-all-features`
    /// turns the feature on; this test only compiles when the
    /// feature is off, so a build configuration `cargo test
    /// --features sync-reader-ws --no-default-features` (or any CI
    /// lane that excludes `compression-zstd`) exercises it.
    #[cfg(not(feature = "compression-zstd"))]
    #[test]
    fn zstd_flag_rejected_without_feature() {
        // Minimal RESULT_BATCH prefix the decoder consumes before
        // checking flags: msg_kind=0x11, request_id=0 (8 bytes),
        // batch_seq=0 (1-byte varint). The rejection fires right
        // after this prefix is parsed — no body bytes are needed.
        let mut payload = vec![MsgKind::ResultBatch.as_u8()];
        payload.extend_from_slice(&0i64.to_le_bytes());
        payload.push(0u8); // varint 0
        let payload = Bytes::from(payload);

        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags::ZSTD,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .expect_err("decoder must reject FLAG_ZSTD when built without compression-zstd");
        assert_eq!(err.code(), ErrorCode::UnsupportedServer);
        // Pin the diagnostic so a future error-message refactor can't
        // drop the feature-name hint that an operator needs to act on.
        assert!(
            err.msg().contains("compression-zstd"),
            "rejection message should name the missing feature: {}",
            err.msg()
        );
    }

    /// Sanity: when the bitmap is exactly the size the decoder allocates
    /// (`row_count.div_ceil(8)`), the chunked path still produces the
    /// same answer as the naive walk. Belt-and-braces for the case where
    /// the bitmap has no slack bytes past `full_bytes + (tail_bits != 0)`.
    #[test]
    fn count_nulls_tight_buffer_matches_naive() {
        for row_count in [0usize, 1, 7, 8, 9, 63, 64, 65, 100, 1000] {
            let bytes_needed = row_count.div_ceil(8);
            let mut bitmap = vec![0u8; bytes_needed];
            // Pseudo-random fill: prime-stepped index makes every
            // byte distinct enough to catch chunked-vs-naive drift.
            for (i, b) in bitmap.iter_mut().enumerate() {
                *b = ((i.wrapping_mul(31) ^ 0xA5) & 0xFF) as u8;
            }
            let got = count_nulls(&bitmap, row_count);
            let want = count_nulls_naive(&bitmap, row_count);
            assert_eq!(
                got, want,
                "tight-buffer mismatch at row_count={} ({} bytes)",
                row_count, bytes_needed
            );
        }
    }

    /// Helper builder for a `RESULT_BATCH` payload (post-header bytes).
    struct BatchBuilder {
        flags: u8,
        request_id: i64,
        batch_seq: u64,
        delta: Option<Vec<&'static str>>, // delta_start always 0; for tests
        delta_start: u64,
        row_count: usize,
        cols: Vec<(String, ColumnKind)>,
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
        fn with_batch_seq(mut self, seq: u64) -> Self {
            self.batch_seq = seq;
            self
        }
        fn add_column(mut self, name: &str, kind: ColumnKind, data: Vec<u8>) -> Self {
            self.cols.push((name.to_string(), kind));
            self.column_data.push(data);
            self
        }

        fn build(self) -> (u8, Bytes) {
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

            // Table block. The schema (col_count + inline column descriptors)
            // rides only the first batch (batch_seq == 0); continuation batches
            // carry rows only.
            encode_u64(0, &mut out); // name_len
            encode_u64(self.row_count as u64, &mut out);
            if self.batch_seq == 0 {
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

            (self.flags, Bytes::from(out))
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        assert!(!c.is_null(0));
        assert!(c.is_null(1));
        assert!(!c.is_null(2));
        assert!(!c.is_null(3));
        assert_eq!(c.value(0), 10);
        // Row 1 is null; densified slot carries the QuestDB LONG NULL
        // sentinel (`Long.MIN_VALUE`) per spec §11.5, not zero.
        assert_eq!(c.value(1), i64::MIN);
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        let expected: Vec<Option<i64>> = vec![
            Some(100),
            None,
            Some(102),
            Some(103),
            None,
            Some(105),
            Some(106),
            None,
        ];
        let got: Vec<Option<i64>> = (0..8)
            .map(|r| if c.is_null(r) { None } else { Some(c.value(r)) })
            .collect();
        assert_eq!(got, expected);
    }

    // The wire-to-dense gather is shared across every fixed-width
    // primitive — the regression that landed in commit `a89e0fc`
    // ("decode compact wire and densify per row") was specific to the
    // Long path's inline assertions, but the same compact-vs-dense
    // bug surface applies to Double / Float / Int / Short / Byte.
    // These tests pin the contract for each: non-null wire values land
    // at the right dense indices, and null slots read as zero.

    fn le_f64s(vs: &[f64]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in vs {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o
    }

    fn le_f32s(vs: &[f32]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in vs {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o
    }

    fn le_i32s(vs: &[i32]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in vs {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o
    }

    fn le_i16s(vs: &[i16]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in vs {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o
    }

    #[test]
    fn decode_double_with_nulls_densifies() {
        // 4 rows; row 1 null. Wire: 3 f64 values + bitmap 0x02.
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column(
                "v",
                ColumnKind::Double,
                col_with_bitmap(&[0x02], &le_f64s(&[1.5, 3.5, 4.5])),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Double(c) = view else {
            panic!()
        };
        assert!(!c.is_null(0));
        assert!(c.is_null(1));
        assert!(!c.is_null(2));
        assert!(!c.is_null(3));
        assert_eq!(c.value(0), 1.5);
        // Spec §11.5: DOUBLE NULL is `Double.NaN` (canonical quiet-NaN
        // bit pattern `0x7FF8_0000_0000_0000`). Compare bits — `NaN ==
        // NaN` is always false in IEEE 754, so direct value comparison
        // would silently pass for any NaN.
        assert_eq!(c.value(1).to_bits(), 0x7FF8_0000_0000_0000u64);
        assert_eq!(c.value(2), 3.5);
        assert_eq!(c.value(3), 4.5);
    }

    #[test]
    fn decode_float_with_nulls_densifies() {
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column(
                "v",
                ColumnKind::Float,
                col_with_bitmap(&[0x02], &le_f32s(&[1.5_f32, 3.5_f32, 4.5_f32])),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Float(c) = view else { panic!() };
        assert_eq!(c.value(0), 1.5_f32);
        // Spec §11.5: FLOAT NULL is canonical quiet-NaN `0x7FC0_0000`.
        assert_eq!(c.value(1).to_bits(), 0x7FC0_0000u32);
        assert_eq!(c.value(2), 3.5_f32);
        assert_eq!(c.value(3), 4.5_f32);
    }

    #[test]
    fn decode_int_with_nulls_densifies() {
        // 8 rows; rows 1, 4, 7 null (bitmap 0x92). 5 i32 values on the wire.
        let (flags_byte, payload) = BatchBuilder::new(8)
            .add_column(
                "v",
                ColumnKind::Int,
                col_with_bitmap(&[0x92], &le_i32s(&[10, 12, 13, 15, 16])),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Int(c) = view else { panic!() };
        let expected: Vec<Option<i32>> = vec![
            Some(10),
            None,
            Some(12),
            Some(13),
            None,
            Some(15),
            Some(16),
            None,
        ];
        let got: Vec<Option<i32>> = (0..8)
            .map(|r| if c.is_null(r) { None } else { Some(c.value(r)) })
            .collect();
        assert_eq!(got, expected);
        // Spec §11.5: INT NULL is `Integer.MIN_VALUE`. Spot-check that
        // null slots read as that sentinel (dense buffer contract, not
        // just `is_null` agreeing).
        assert_eq!(c.value(1), i32::MIN);
        assert_eq!(c.value(4), i32::MIN);
        assert_eq!(c.value(7), i32::MIN);
    }

    #[test]
    fn null_sentinels_per_spec_11_5() {
        // Locks the per-type NULL sentinel patterns from spec §11.5
        // against drift. Each row 0 carries a real value; row 1 is NULL
        // and must densify to the sentinel.
        let bitmap = vec![0x02]; // bit 1 set => row 1 is NULL.

        // UUID NULL: both halves Long.MIN_VALUE.
        let mut uuid_vals = vec![0u8; 16];
        uuid_vals[..8].copy_from_slice(&1i64.to_le_bytes());
        uuid_vals[8..16].copy_from_slice(&2i64.to_le_bytes());
        // LONG256 NULL: four halves Long.MIN_VALUE.
        let mut long256_vals = vec![0u8; 32];
        for chunk in 0..4 {
            long256_vals[chunk * 8..chunk * 8 + 8]
                .copy_from_slice(&((chunk + 1) as i64).to_le_bytes());
        }

        let cases: &[(ColumnKind, Vec<u8>, &[u8])] = &[
            (ColumnKind::Int, le_i32s(&[7]), &i32::MIN.to_le_bytes()),
            (ColumnKind::Long, le_i64s(&[7]), &i64::MIN.to_le_bytes()),
            (
                ColumnKind::Float,
                le_f32s(&[1.5]),
                &0x7FC0_0000u32.to_le_bytes(),
            ),
            (
                ColumnKind::Double,
                le_f64s(&[1.5]),
                &0x7FF8_0000_0000_0000u64.to_le_bytes(),
            ),
            (
                ColumnKind::Uuid,
                uuid_vals,
                &[0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x80],
            ),
            (
                ColumnKind::Long256,
                long256_vals,
                &[
                    0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,
                    0x80, 0, 0, 0, 0, 0, 0, 0, 0x80,
                ],
            ),
        ];

        for (kind, value_bytes, expected_null) in cases {
            let (flags_byte, payload) = BatchBuilder::new(2)
                .add_column("v", *kind, col_with_bitmap(&bitmap, value_bytes))
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let batch = decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .unwrap_or_else(|e| panic!("{:?}: {}", kind, e.msg()));
            // Pull row 1's raw bytes via the appropriate ColumnView arm.
            let view = batch.column_view(0, &dict).unwrap();
            let null_bytes: Vec<u8> = match view {
                ColumnView::Int(c) => c.value(1).to_le_bytes().to_vec(),
                ColumnView::Long(c) => c.value(1).to_le_bytes().to_vec(),
                ColumnView::Float(c) => c.value(1).to_bits().to_le_bytes().to_vec(),
                ColumnView::Double(c) => c.value(1).to_bits().to_le_bytes().to_vec(),
                ColumnView::Uuid(c) => c.value(1).to_vec(),
                ColumnView::Long256(c) => c.value(1).to_vec(),
                _ => panic!("unexpected view for {:?}", kind),
            };
            assert_eq!(
                null_bytes, *expected_null,
                "spec §11.5 NULL sentinel mismatch for {:?}: got {:02X?}, expected {:02X?}",
                kind, null_bytes, expected_null
            );
        }

        // Geohash uses byte_width-dependent sentinel = 0xFF * byte_width.
        // GeohashColumn::value returns the row's bytes zero-extended to
        // u64; for byte_width=1 a NULL row reads as 0xFF.
        let mut geo_payload = vec![0x01]; // null_flag = bitmap follows
        geo_payload.extend_from_slice(&[0x02]); // bitmap: row 1 null
        geo_payload.push(8); // varint precision_bits = 8 -> byte_width = 1
        geo_payload.push(0x12); // 1 non-null value
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("g", ColumnKind::Geohash, geo_payload)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let ColumnView::Geohash(c) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(c.value(0), 0x12);
        assert_eq!(
            c.value(1),
            0xFF,
            "spec §11.5: GEOHASH NULL = 0xFF * byte_width"
        );
    }

    #[test]
    fn decode_short_no_nulls() {
        // SHORT is non-nullable on the wire (QwpResultBatchBuffer.appendCell
        // for TYPE_SHORT calls scratch.appendShort with no appendNull path).
        // null_flag is always 0x00; values are straight-through i16 LE.
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column(
                "v",
                ColumnKind::Short,
                col_no_nulls(&le_i16s(&[-1, -2, -3, 32767])),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Short(c) = view else { panic!() };
        assert_eq!(c.value(0), -1);
        assert_eq!(c.value(1), -2);
        assert_eq!(c.value(2), -3);
        assert_eq!(c.value(3), 32767);
        for r in 0..4 {
            assert!(!c.is_null(r));
        }
    }

    #[test]
    fn decode_byte_no_nulls() {
        // BYTE is non-nullable on the wire (TYPE_BYTE -> scratch.appendByte,
        // no appendNull path). null_flag is always 0x00; values are
        // straight-through i8.
        let (flags_byte, payload) = BatchBuilder::new(5)
            .add_column(
                "v",
                ColumnKind::Byte,
                col_no_nulls(&[0x00, 0x7F, 0x80, 0xFF, 0x01]),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Byte(c) = view else { panic!() };
        assert_eq!(c.value(0), 0);
        assert_eq!(c.value(1), 0x7F);
        assert_eq!(c.value(2), -128); // 0x80 as i8
        assert_eq!(c.value(3), -1); // 0xFF as i8
        assert_eq!(c.value(4), 1);
        for r in 0..5 {
            assert!(!c.is_null(r));
        }
    }

    #[test]
    fn decode_boolean_bit_packed() {
        // 5 rows, no nulls. Wire bits (LSB-first) for [t, f, t, t, f]:
        // bit0=1, bit1=0, bit2=1, bit3=1, bit4=0 → 0b0000_1101 = 0x0D
        let (flags_byte, payload) = BatchBuilder::new(5)
            .add_column("b", ColumnKind::Boolean, col_no_nulls(&[0x0D]))
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Boolean(c) = view else {
            panic!()
        };
        assert_eq!(c.len(), 5);
        assert_eq!(c.value(0), 1);
        assert_eq!(c.value(1), 0);
        assert_eq!(c.value(2), 1);
        assert_eq!(c.value(3), 1);
        assert_eq!(c.value(4), 0);
    }

    #[test]
    fn decode_boolean_rejects_validity_bitmap() {
        assert_non_nullable_rejects_bitmap(
            ColumnKind::Boolean,
            "BOOLEAN",
            // 5 rows of bit-packed values; bitmap claims all-non-null.
            col_with_bitmap(&[0b0001_1111], &[0x0D]),
        );
    }

    #[test]
    fn decode_byte_rejects_validity_bitmap() {
        // Server-side proof in QwpResultBatchBuffer.appendCell: TYPE_BYTE
        // path calls scratch.appendByte unconditionally — never appendNull
        // — so nullCount stays 0 and emitColumn always writes null_flag=0x00.
        assert_non_nullable_rejects_bitmap(
            ColumnKind::Byte,
            "BYTE",
            col_with_bitmap(&[0b0001_1111], &[1, 2, 3, 4, 5]),
        );
    }

    #[test]
    fn decode_short_rejects_validity_bitmap() {
        // Same server-side guarantee as BYTE (scratch.appendShort).
        assert_non_nullable_rejects_bitmap(
            ColumnKind::Short,
            "SHORT",
            col_with_bitmap(&[0b0001_1111], &le_i16s(&[1, 2, 3, 4, 5])),
        );
    }

    #[test]
    fn decode_char_rejects_validity_bitmap() {
        // Same server-side guarantee as BYTE (scratch.appendChar).
        assert_non_nullable_rejects_bitmap(
            ColumnKind::Char,
            "CHAR",
            col_with_bitmap(&[0b0001_1111], &le_u16s(&[b'a' as u16; 5])),
        );
    }

    fn assert_non_nullable_rejects_bitmap(kind: ColumnKind, kind_name: &str, body: Vec<u8>) {
        let (flags_byte, payload) = BatchBuilder::new(5).add_column("c", kind, body).build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(
            err.msg().contains(kind_name) && err.msg().contains("null_flag"),
            "unexpected error message for {}: {}",
            kind_name,
            err.msg()
        );
    }

    fn le_u16s(vs: &[u16]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in vs {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o
    }

    /// Build a column-local SYMBOL column body: validity + dict + per-row ids.
    fn symbol_column_local(
        bitmap: Option<&[u8]>,
        dict: &[&str],
        codes_per_non_null: &[u64],
    ) -> Vec<u8> {
        let mut col = Vec::new();
        if let Some(bm) = bitmap {
            col.push(0x01);
            col.extend_from_slice(bm);
        } else {
            col.push(0x00);
        }
        encode_u64(dict.len() as u64, &mut col); // dict_size
        for entry in dict {
            encode_u64(entry.len() as u64, &mut col);
            col.extend_from_slice(entry.as_bytes());
        }
        for code in codes_per_non_null {
            encode_u64(*code, &mut col);
        }
        col
    }

    #[test]
    fn decode_symbol_column_local_no_nulls() {
        // 3 rows, FLAG_DELTA_SYMBOL_DICT clear, dict ["AAPL","MSFT","GOOG"],
        // ids [0, 1, 2].
        let col = symbol_column_local(None, &["AAPL", "MSFT", "GOOG"], &[0, 1, 2]);
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("s", ColumnKind::Symbol, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        // Connection dict stays empty — column-local mode doesn't touch it.
        assert_eq!(dict.len(), 0);

        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Symbol(s) = view else {
            panic!()
        };
        assert_eq!(s.resolve(0), Some("AAPL"));
        assert_eq!(s.resolve(1), Some("MSFT"));
        assert_eq!(s.resolve(2), Some("GOOG"));
    }

    #[test]
    fn decode_symbol_column_local_with_nulls() {
        // 4 rows; row 1 null. bitmap = 0x02, dict ["X", "Y"], codes [1, 0, 0]
        // (3 non-null rows: 0->Y, 2->X, 3->X).
        let col = symbol_column_local(Some(&[0x02]), &["X", "Y"], &[1, 0, 0]);
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column("s", ColumnKind::Symbol, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();

        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Symbol(s) = view else {
            panic!()
        };
        assert_eq!(s.resolve(0), Some("Y"));
        assert!(s.is_null(1));
        assert_eq!(s.resolve(1), None);
        assert_eq!(s.resolve(2), Some("X"));
        assert_eq!(s.resolve(3), Some("X"));
    }

    #[test]
    fn decode_symbol_column_local_independent_per_column() {
        // Two SYMBOL columns in one batch, each with its own dict.
        // The codes happen to overlap (both use id 0) but resolve to
        // different strings — confirming column-local independence.
        let col_a = symbol_column_local(None, &["alpha", "beta"], &[0, 1]);
        let col_b = symbol_column_local(None, &["one", "two"], &[1, 0]);
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("a", ColumnKind::Symbol, col_a)
            .add_column("b", ColumnKind::Symbol, col_b)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();

        let ColumnView::Symbol(a) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        let ColumnView::Symbol(b) = batch.column_view(1, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(a.resolve(0), Some("alpha"));
        assert_eq!(a.resolve(1), Some("beta"));
        assert_eq!(b.resolve(0), Some("two"));
        assert_eq!(b.resolve(1), Some("one"));
    }

    #[test]
    fn decode_symbol_column_local_id_out_of_range_rejected() {
        // dict has 2 entries but a row references id 5.
        let col = symbol_column_local(None, &["a", "b"], &[0, 5]);
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("s", ColumnKind::Symbol, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(err.msg().contains("out of range"));
    }

    #[test]
    fn decode_symbol_column_local_dict_size_exceeds_rows_rejected() {
        // 1 row but dict claims 5 entries — Java reference rejects this.
        let mut col = vec![0x00u8]; // null_flag
        encode_u64(5, &mut col); // dict_size > row_count
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("s", ColumnKind::Symbol, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn decode_symbol_delta_id_out_of_range_rejected() {
        // Connection dict has 2 entries (AAPL, MSFT), batch references id 9.
        let mut col_data = vec![0x00u8]; // null_flag
        encode_u64(9, &mut col_data); // bogus id
        let (flags_byte, payload) = BatchBuilder::new(1)
            .with_dict_delta(0, vec!["AAPL", "MSFT"])
            .add_column("s", ColumnKind::Symbol, col_data)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(err.msg().contains("out of range"));
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        assert_eq!(dict.len(), 2);

        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Symbol(s) = view else {
            panic!()
        };
        assert_eq!(s.len(), 3);
        assert_eq!(s.resolve(0), Some("AAPL"));
        assert_eq!(s.resolve(1), None);
        assert_eq!(s.resolve(2), Some("MSFT"));
    }

    #[test]
    fn decode_decimal64_with_scale() {
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("p", ColumnKind::Decimal64, {
                let mut d = vec![0x00u8, 0x02]; // null_flag=0, scale=2
                d.extend_from_slice(&le_i64s(&[12345, 6789]));
                d
            })
            .build();

        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Decimal64(d) = view else {
            panic!()
        };
        assert_eq!(d.scale(), 2);
        assert_eq!(d.value(0), 12345);
        assert_eq!(d.value(1), 6789);
    }

    #[test]
    fn decode_decimal_rejects_negative_scale() {
        // Server-emitted scale of 0xFF (i8 -1) must surface as a
        // ProtocolError, not silently become a negative scale that
        // misinterprets every value in the column.
        for kind in [
            ColumnKind::Decimal64,
            ColumnKind::Decimal128,
            ColumnKind::Decimal256,
        ] {
            let width = match kind {
                ColumnKind::Decimal64 => 8,
                ColumnKind::Decimal128 => 16,
                ColumnKind::Decimal256 => 32,
                _ => unreachable!(),
            };
            let mut data = vec![0x00u8, 0xFF]; // null_flag=0, scale=-1
            data.extend(std::iter::repeat_n(0u8, width)); // 1 row of zeros
            let (flags_byte, payload) = BatchBuilder::new(1).add_column("p", kind, data).build();

            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let err = decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .unwrap_err();
            assert_eq!(err.code(), crate::egress::ErrorCode::ProtocolError);
            assert!(
                err.msg().contains("decimal scale"),
                "expected scale error msg, got: {}",
                err.msg()
            );
        }
    }

    #[test]
    fn decode_decimal_rejects_scale_above_max() {
        // 39 = MAX_DECIMAL_SCALE + 1.
        let mut data = vec![0x00u8, 39u8];
        data.extend(std::iter::repeat_n(0u8, 8));
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("p", ColumnKind::Decimal64, data)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), crate::egress::ErrorCode::ProtocolError);
    }

    #[test]
    fn schema_reused_across_continuation_batches() {
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;

        // First batch (batch_seq == 0) carries the full inline schema.
        let (f1, p1) = BatchBuilder::new(2)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[1, 2])))
            .build();
        decode_result_batch(&p1, f1, &mut dict, &mut schema, &mut ZstdScratch::new()).unwrap();
        assert!(schema.is_some());

        // Continuation batch (batch_seq == 1) carries rows only and reuses the
        // schema parsed from batch 0.
        let (f2, p2) = BatchBuilder::new(1)
            .with_batch_seq(1)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[42])))
            .build();
        let b2 =
            decode_result_batch(&p2, f2, &mut dict, &mut schema, &mut ZstdScratch::new()).unwrap();
        assert_eq!(b2.batch_seq, 1);
        let view = b2.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        assert_eq!(c.value(0), 42);
    }

    #[test]
    fn continuation_before_schema_rejected() {
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        // A batch_seq > 0 arriving before any batch_seq == 0 has no schema to
        // bind rows to and must be rejected.
        let (f, p) = BatchBuilder::new(1)
            .with_batch_seq(1)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[42])))
            .build();
        let err = decode_result_batch(&p, f, &mut dict, &mut schema, &mut ZstdScratch::new())
            .unwrap_err();
        assert_eq!(err.code(), crate::egress::ErrorCode::ProtocolError);
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_round_trips_simple_long_batch() {
        // Build a raw RESULT_BATCH, then re-pack the body bytes (after
        // msg_kind / request_id / batch_seq) as a zstd frame and verify
        // the decoder restores the original meaning when FLAG_ZSTD is set.
        let (_, raw_payload) = BatchBuilder::new(3)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[10, 20, 30])))
            .build();

        // Split: 1 byte msg_kind + 8 bytes request_id + varint batch_seq
        // is uncompressed; the rest is the body we'll compress.
        let prefix_len = {
            let mut r = ByteReader::new(&raw_payload);
            r.read_u8().unwrap();
            r.read_i64_le().unwrap();
            r.read_varint_u64().unwrap();
            // r.bytes - r.remaining() is awkward; use difference.
            raw_payload.len() - r.remaining().len()
        };
        let prefix = &raw_payload[..prefix_len];
        let body = &raw_payload[prefix_len..];

        let compressed_body = zstd::bulk::compress(body, 0).expect("zstd compress");
        let mut zstd_payload = Vec::new();
        zstd_payload.extend_from_slice(prefix);
        zstd_payload.extend_from_slice(&compressed_body);
        let zstd_payload = Bytes::from(zstd_payload);

        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &zstd_payload,
            flags::ZSTD,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        assert_eq!(batch.row_count, 3);
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        assert_eq!(c.value(0), 10);
        assert_eq!(c.value(1), 20);
        assert_eq!(c.value(2), 30);
    }

    /// Pin the `ZstdScratch` recycle pool: the `Vec<u8>` backing the
    /// first decompressed body is returned to the pool when that
    /// `Bytes` is dropped, and the next decompression pops it back
    /// out instead of allocating fresh. Without `Bytes::from_owner` +
    /// `Drop for PooledZstdBuffer`, the pool would always be empty
    /// and steady-state throughput would pay one full-body
    /// allocation+memcpy per batch.
    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_scratch_pool_recycles_buffer_across_batches() {
        fn build_zstd_payload(seed: i64) -> Bytes {
            let (_, raw_payload) = BatchBuilder::new(3)
                .add_column(
                    "v",
                    ColumnKind::Long,
                    col_no_nulls(&le_i64s(&[seed, seed + 1, seed + 2])),
                )
                .build();
            let prefix_len = {
                let mut r = ByteReader::new(&raw_payload);
                r.read_u8().unwrap();
                r.read_i64_le().unwrap();
                r.read_varint_u64().unwrap();
                raw_payload.len() - r.remaining().len()
            };
            let prefix = &raw_payload[..prefix_len];
            let body = &raw_payload[prefix_len..];
            let compressed = zstd::bulk::compress(body, 0).expect("compress");
            let mut out = Vec::with_capacity(prefix.len() + compressed.len());
            out.extend_from_slice(prefix);
            out.extend_from_slice(&compressed);
            Bytes::from(out)
        }

        let mut scratch = ZstdScratch::new();
        // Pool starts empty.
        assert_eq!(
            scratch.pool.buffers.lock().unwrap().len(),
            0,
            "pool starts empty"
        );

        // First decompression: allocates a fresh buffer, returns
        // `Bytes` wrapping it. Pool still empty (the buffer is alive
        // inside the returned Bytes).
        let body1 = zstd_decompress_body(
            {
                let p = build_zstd_payload(100);
                // Slice off the uncompressed prefix to match what
                // `zstd_decompress_body` is invoked with at the call
                // site (the prefix is consumed by ByteReader first).
                p.slice(10..)
            }
            .as_ref(),
            &mut scratch,
        )
        .expect("decompress 1");
        assert_eq!(
            scratch.pool.buffers.lock().unwrap().len(),
            0,
            "pool empty while body1 holds the buffer"
        );

        // Drop the Bytes: PooledZstdBuffer::drop fires and returns
        // the Vec to the pool.
        let body1_len = body1.len();
        drop(body1);
        let pool_len = scratch.pool.buffers.lock().unwrap().len();
        assert_eq!(
            pool_len, 1,
            "pool should hold the recycled buffer after the first Bytes drops"
        );
        let recycled_capacity = scratch.pool.buffers.lock().unwrap()[0].capacity();
        assert!(
            recycled_capacity >= body1_len,
            "recycled buffer retained capacity >= body length ({} >= {})",
            recycled_capacity,
            body1_len
        );

        // Second decompression: must draw from the pool (the pool
        // pops the recycled buffer and reuses its capacity). After
        // the call, the pool is empty again because the buffer is
        // now owned by `body2`.
        let body2 = zstd_decompress_body(
            {
                let p = build_zstd_payload(200);
                p.slice(10..)
            }
            .as_ref(),
            &mut scratch,
        )
        .expect("decompress 2");
        assert_eq!(
            scratch.pool.buffers.lock().unwrap().len(),
            0,
            "pool emptied by the second decompress drawing from it"
        );
        assert_eq!(body2.len(), body1_len, "second body decoded successfully");

        // Pool is bounded: dropping many concurrent Bytes does NOT
        // grow the pool past `ZSTD_POOL_CAPACITY`. Build a third
        // body to add to the bucket while body2 is still alive.
        let body3 = zstd_decompress_body(
            {
                let p = build_zstd_payload(300);
                p.slice(10..)
            }
            .as_ref(),
            &mut scratch,
        )
        .expect("decompress 3");
        drop(body2);
        drop(body3);
        let final_pool_len = scratch.pool.buffers.lock().unwrap().len();
        assert!(
            final_pool_len <= ZSTD_POOL_CAPACITY,
            "pool stays bounded by ZSTD_POOL_CAPACITY (got {})",
            final_pool_len
        );
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_invalid_frame_is_protocol_error() {
        // Build a payload with a valid prefix + bogus zstd body bytes.
        let (_, raw_payload) = BatchBuilder::new(0).build();
        let prefix_len = {
            let mut r = ByteReader::new(&raw_payload);
            r.read_u8().unwrap();
            r.read_i64_le().unwrap();
            r.read_varint_u64().unwrap();
            raw_payload.len() - r.remaining().len()
        };
        let mut payload = raw_payload[..prefix_len].to_vec();
        payload.extend_from_slice(&[0u8, 0, 0, 0]); // not a zstd frame
        let payload = Bytes::from(payload);
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags::ZSTD,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    /// Splice a custom zstd body onto a 0-row RESULT_BATCH prefix.
    /// Returns the full FLAG_ZSTD payload ready for `decode_result_batch`.
    #[cfg(feature = "compression-zstd")]
    fn zstd_payload_with_body(body: &[u8]) -> Bytes {
        let (_, raw) = BatchBuilder::new(0).build();
        let prefix_len = {
            let mut r = ByteReader::new(&raw);
            r.read_u8().unwrap();
            r.read_i64_le().unwrap();
            r.read_varint_u64().unwrap();
            raw.len() - r.remaining().len()
        };
        let mut out = raw[..prefix_len].to_vec();
        out.extend_from_slice(body);
        Bytes::from(out)
    }

    /// Hand-roll a zstd frame whose Frame_Header_Descriptor declares
    /// an explicit 8-byte Frame_Content_Size set to `forged`. The
    /// frame body is a single empty raw "last" block — enough for
    /// `get_frame_content_size` to parse but cheap enough that we
    /// never actually have to decompress 64+ MiB.
    #[cfg(feature = "compression-zstd")]
    fn forged_fcs_zstd_frame(forged: u64) -> Vec<u8> {
        let mut frame = vec![0x28, 0xB5, 0x2F, 0xFD]; // magic
        // FHD: FCS_flag=3 (8-byte FCS), Single_Segment_flag=1, no
        // Content_Checksum, no Dictionary_ID -> 0xC0 | 0x20 = 0xE0.
        // Single_Segment=1 means the Window_Descriptor byte is omitted.
        frame.push(0xE0);
        frame.extend_from_slice(&forged.to_le_bytes());
        // One last raw block of size 0: header bits 23..3 = 0,
        // bits 2..1 = 0 (raw), bit 0 = 1 (last) -> 0x01 0x00 0x00.
        frame.extend_from_slice(&[0x01, 0x00, 0x00]);
        frame
    }

    /// FLAG_ZSTD body whose zstd frame omits the Frame_Content_Size.
    /// `zstd::stream::write::Encoder` does not write FCS unless the
    /// caller invokes `set_pledged_src_size`, so this exercises the
    /// `Ok(None)` arm of `get_frame_content_size`.
    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_frame_without_content_size_is_protocol_error() {
        use std::io::Write;
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder
            .write_all(b"some bytes that will never be read")
            .unwrap();
        let body = encoder.finish().expect("zstd encode");
        // Sanity-check that the encoder really did omit FCS — if a
        // future zstd-rs default flips, this assertion catches it
        // before the test produces a misleading false-pass.
        assert!(
            matches!(zstd::zstd_safe::get_frame_content_size(&body), Ok(None)),
            "zstd::Encoder default must produce a frame without FCS; \
             header bytes: {:02x?}",
            &body[..body.len().min(16)]
        );

        let payload = zstd_payload_with_body(&body);
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags::ZSTD,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(
            err.msg().contains("missing content size"),
            "expected missing-content-size message, got: {}",
            err.msg()
        );
    }

    /// FLAG_ZSTD body whose frame header advertises a content size
    /// just above the 64 MiB cap. The decoder must reject before
    /// allocating any decompression buffer.
    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_frame_exceeding_cap_is_limit_exceeded() {
        let oversized = MAX_ZSTD_DECOMPRESSED + 1;
        let frame = forged_fcs_zstd_frame(oversized);
        // Sanity-check that get_frame_content_size sees what we forged.
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&frame).ok(),
            Some(Some(oversized)),
            "forged FCS bytes must round-trip through zstd"
        );

        let payload = zstd_payload_with_body(&frame);
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags::ZSTD,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert!(
            err.msg().contains("exceeds client cap"),
            "expected cap-exceeded message, got: {}",
            err.msg()
        );
    }

    /// FLAG_ZSTD body whose frame header advertises a content size
    /// that disagrees with the actual decompressed length. zstd's own
    /// validator catches the mismatch first; the decoder maps it to
    /// `ProtocolError`. Pins coverage of the post-decompress failure
    /// arm so a future refactor that drops zstd's internal check is
    /// still caught by *some* layer.
    #[cfg(feature = "compression-zstd")]
    #[test]
    fn zstd_frame_with_size_mismatch_is_protocol_error() {
        use std::io::Write;
        // Lie to zstd: claim 100 bytes, then write fewer. The encoder
        // writes the pledged size into the FCS but does not enforce
        // the byte count on `finish()`.
        let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 0).unwrap();
        encoder.set_pledged_src_size(Some(100)).ok();
        encoder.write_all(b"only ten!!").unwrap(); // 10 bytes, not 100
        let body = match encoder.finish() {
            Ok(b) => b,
            Err(_) => {
                // Some zstd versions enforce the pledge on finish; if
                // so, this test cannot synthesise the mismatch and we
                // skip rather than false-pass. The defensive
                // post-decompress size check (`written != frame content
                // size`) in `zstd_decompress_body` is then verified only
                // by code review.
                return;
            }
        };
        // Sanity: the FCS must say 100 even though we wrote 10.
        assert_eq!(
            zstd::zstd_safe::get_frame_content_size(&body).ok(),
            Some(Some(100))
        );

        let payload = zstd_payload_with_body(&body);
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags::ZSTD,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn rejects_unknown_temporal_discriminator() {
        // 1 timestamp column, gorilla flag, but an unknown discriminator
        // (0x02 — not raw, not Gorilla).
        let mut col_data = vec![0x00u8]; // null_flag = no bitmap (1 row, no nulls)
        col_data.push(0x02); // unknown discriminator
        let (_, payload) = BatchBuilder::new(1)
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, col_data)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags::GORILLA,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(err.msg().to_lowercase().contains("discriminator"));
    }

    #[test]
    fn decodes_gorilla_with_few_non_null() {
        // Spec-compliant servers shortcut `non_null < 3` to disc=0x00
        // (raw), so the Gorilla branch never runs in the live wire.
        // The decoder is lenient anyway: it accepts the natural
        // degenerate framing — `min(non_null, 2)` bare seed timestamps
        // and no bitstream — so a future server variant doesn't
        // surface as a hard ProtocolError.
        let mut col_data = vec![0x00u8]; // null_flag
        col_data.push(0x01); // gorilla discriminator
        col_data.extend_from_slice(&0i64.to_le_bytes());
        col_data.extend_from_slice(&100i64.to_le_bytes());
        let (_, payload) = BatchBuilder::new(2)
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, col_data)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags::GORILLA,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::TimestampNanos(c) = view else {
            panic!("expected TimestampNanos column")
        };
        assert_eq!(c.value(0), 0);
        assert_eq!(c.value(1), 100);
    }

    #[test]
    fn decodes_gorilla_with_one_non_null() {
        // Single seed timestamp, no bitstream. Bit set in the bitmap
        // means NULL (per `is_null_at`), so 0b0000_0010 marks row 1
        // null and row 0 non-null.
        let mut col_data = vec![0x01u8, 0b0000_0010];
        col_data.push(0x01); // gorilla discriminator
        col_data.extend_from_slice(&42i64.to_le_bytes());
        let (_, payload) = BatchBuilder::new(2)
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, col_data)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags::GORILLA,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::TimestampNanos(c) = view else {
            panic!("expected TimestampNanos column")
        };
        assert!(!c.is_null(0));
        assert_eq!(c.value(0), 42);
        assert!(c.is_null(1));
    }

    #[test]
    fn decodes_gorilla_with_zero_non_null() {
        // Validity bitmap reports both rows null (bits 0 and 1 set);
        // nothing is read from the column body beyond the discriminator.
        let mut col_data = vec![0x01u8, 0b0000_0011];
        col_data.push(0x01); // gorilla discriminator
        let (_, payload) = BatchBuilder::new(2)
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, col_data)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags::GORILLA,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::TimestampNanos(c) = view else {
            panic!("expected TimestampNanos column")
        };
        assert!(c.is_null(0));
        assert!(c.is_null(1));
    }

    #[test]
    fn raw_temporal_under_gorilla_flag_decodes() {
        // Under FLAG_GORILLA the column body is `validity, disc, ...`. With
        // disc=0x00 the values are plain i64 LE (densified for nulls).
        let mut col_data = vec![0x00u8]; // no bitmap
        col_data.push(0x00); // disc = raw
        col_data.extend_from_slice(&le_i64s(&[10, 20, 30]));
        let (_, payload) = BatchBuilder::new(3)
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, col_data)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags::GORILLA,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::TimestampNanos(c) = view else {
            panic!()
        };
        assert_eq!(c.value(0), 10);
        assert_eq!(c.value(1), 20);
        assert_eq!(c.value(2), 30);
    }

    /// Encode `timestamps` (≥ 2 entries) as a Gorilla bitstream matching
    /// the Java encoder: two raw i64 seeds, then per-row delta-of-delta
    /// bits packed LSB-first into bytes. Used by the temporal Gorilla
    /// round-trip tests below.
    fn encode_gorilla_temporal_bitstream(timestamps: &[i64]) -> Vec<u8> {
        assert!(timestamps.len() >= 2, "need at least two seeds");
        let mut prev_delta = timestamps[1] - timestamps[0];
        let mut prev_ts = timestamps[1];
        let mut bytes = Vec::new();
        let mut cur: u8 = 0;
        let mut bits: u32 = 0;
        let write_bit = |b: u8, bytes: &mut Vec<u8>, cur: &mut u8, bits: &mut u32| {
            *cur |= (b & 1) << *bits;
            *bits += 1;
            if *bits == 8 {
                bytes.push(*cur);
                *cur = 0;
                *bits = 0;
            }
        };
        let write_bits = |val: u64, n: u32, bytes: &mut Vec<u8>, cur: &mut u8, bits: &mut u32| {
            for i in 0..n {
                write_bit(((val >> i) & 1) as u8, bytes, cur, bits);
            }
        };
        for &ts in &timestamps[2..] {
            let delta = ts - prev_ts;
            let dod = delta - prev_delta;
            if dod == 0 {
                write_bit(0, &mut bytes, &mut cur, &mut bits);
            } else if (-64..=63).contains(&dod) {
                write_bits(0b01, 2, &mut bytes, &mut cur, &mut bits);
                write_bits((dod as u64) & 0x7F, 7, &mut bytes, &mut cur, &mut bits);
            } else if (-256..=255).contains(&dod) {
                write_bits(0b011, 3, &mut bytes, &mut cur, &mut bits);
                write_bits((dod as u64) & 0x1FF, 9, &mut bytes, &mut cur, &mut bits);
            } else if (-2048..=2047).contains(&dod) {
                write_bits(0b0111, 4, &mut bytes, &mut cur, &mut bits);
                write_bits((dod as u64) & 0xFFF, 12, &mut bytes, &mut cur, &mut bits);
            } else {
                write_bits(0b1111, 4, &mut bytes, &mut cur, &mut bits);
                write_bits(
                    (dod as u64) & 0xFFFF_FFFF,
                    32,
                    &mut bytes,
                    &mut cur,
                    &mut bits,
                );
            }
            prev_delta = delta;
            prev_ts = ts;
        }
        if bits > 0 {
            bytes.push(cur);
        }
        bytes
    }

    /// Wrap a Gorilla bitstream in the per-column body: 1-byte validity
    /// (no nulls), 1-byte disc=0x01 (Gorilla), 16 bytes of seeds,
    /// then the bitstream itself.
    fn build_gorilla_temporal_column_body(timestamps: &[i64]) -> Vec<u8> {
        let bitstream = encode_gorilla_temporal_bitstream(timestamps);
        let mut col = Vec::with_capacity(2 + 16 + bitstream.len());
        col.push(0x00); // null_flag = no nulls
        col.push(0x01); // gorilla disc
        col.extend_from_slice(&timestamps[0].to_le_bytes());
        col.extend_from_slice(&timestamps[1].to_le_bytes());
        col.extend_from_slice(&bitstream);
        col
    }

    /// Round-trip a Gorilla temporal column through `decode_result_batch`
    /// for the given column kind, asserting the decoded values match
    /// the inputs and that the produced `ColumnView` variant is the
    /// expected one. Wrapping each kind's bespoke `ColumnView`
    /// destructure in a closure means the body of the loop in
    /// `decode_gorilla_temporal_round_trip` doesn't have to dispatch
    /// on kind by hand.
    fn assert_gorilla_temporal_round_trip(
        kind: ColumnKind,
        timestamps: &[i64],
        view_to_values: fn(ColumnView<'_>) -> Vec<i64>,
    ) {
        let body = build_gorilla_temporal_column_body(timestamps);
        let (_, payload) = BatchBuilder::new(timestamps.len())
            .with_flags(flags::GORILLA)
            .add_column("ts", kind, body)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags::GORILLA,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_or_else(|e| panic!("decode failed for {:?}: {}", kind, e));
        let view = batch.column_view(0, &dict).unwrap();
        let got = view_to_values(view);
        assert_eq!(
            got.len(),
            timestamps.len(),
            "row count mismatch for {:?}",
            kind
        );
        for (i, (g, e)) in got.iter().zip(timestamps.iter()).enumerate() {
            assert_eq!(
                g, e,
                "{:?} row {} mismatch (got {}, expected {})",
                kind, i, g, e
            );
        }
    }

    /// Gorilla-encoded temporal columns must decode correctly for
    /// every column kind that routes through `decode_temporal`:
    /// `Timestamp` (μs), `TimestampNanos`, and `Date` (ms). The wire
    /// representation is unit-agnostic — i64 bytes packed with DoD —
    /// but the dispatch in `decode_column` selects a different
    /// `DecodedColumn` variant per kind, and consumers downstream
    /// rely on the matching `ColumnView` variant. The earlier version
    /// of this test exercised `TimestampNanos` only; a regression in
    /// the `Timestamp` or `Date` arm would have slipped through.
    #[test]
    fn decode_gorilla_temporal_round_trip() {
        // Values chosen to span every DoD bucket the encoder picks
        // (1 / 9 / 12 / 36 bits) so the decoder's bit-reader
        // bookkeeping is exercised: 1100-1000=100 -> dod 100-100=0
        // (1-bit), then 100-110 -> dod -10 (9-bit), etc.
        let timestamps: [i64; 6] = [1_000, 1_100, 1_200, 1_310, 1_405, 1_488];
        type Extract = fn(ColumnView<'_>) -> Vec<i64>;
        let cases: &[(ColumnKind, Extract)] = &[
            (ColumnKind::Timestamp, |v| {
                let ColumnView::Timestamp(c) = v else {
                    panic!("expected ColumnView::Timestamp")
                };
                (0..c.len()).map(|i| c.value(i)).collect()
            }),
            (ColumnKind::TimestampNanos, |v| {
                let ColumnView::TimestampNanos(c) = v else {
                    panic!("expected ColumnView::TimestampNanos")
                };
                (0..c.len()).map(|i| c.value(i)).collect()
            }),
            (ColumnKind::Date, |v| {
                let ColumnView::Date(c) = v else {
                    panic!("expected ColumnView::Date")
                };
                (0..c.len()).map(|i| c.value(i)).collect()
            }),
        ];
        for &(kind, view_to_values) in cases {
            assert_gorilla_temporal_round_trip(kind, &timestamps, view_to_values);
        }
    }

    fn build_double_array_row(shape: &[u32], elements: &[f64]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(shape.len() as u8);
        for d in shape {
            out.extend_from_slice(&d.to_le_bytes());
        }
        for e in elements {
            out.extend_from_slice(&e.to_le_bytes());
        }
        out
    }

    fn build_long_array_row(shape: &[u32], elements: &[i64]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(shape.len() as u8);
        for d in shape {
            out.extend_from_slice(&d.to_le_bytes());
        }
        for e in elements {
            out.extend_from_slice(&e.to_le_bytes());
        }
        out
    }

    #[test]
    fn decode_double_array_1d_no_nulls() {
        let mut col = vec![0x00u8]; // null_flag
        col.extend_from_slice(&build_double_array_row(&[3], &[1.0, 2.0, 3.0]));
        col.extend_from_slice(&build_double_array_row(&[2], &[10.0, 20.0]));
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("a", ColumnKind::DoubleArray, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::DoubleArray(c) = view else {
            panic!()
        };
        assert_eq!(c.len(), 2);
        assert_eq!(c.shape(0), Some(&[3u32][..]));
        assert_eq!(c.element_count(0), 3);
        assert_eq!(c.element(0, 0), Some(1.0));
        assert_eq!(c.element(0, 2), Some(3.0));
        assert_eq!(c.shape(1), Some(&[2u32][..]));
        assert_eq!(c.element(1, 1), Some(20.0));
    }

    #[test]
    fn decode_long_array_2d_with_nulls() {
        // 3 rows: [[1,2],[3,4]], NULL, [[7,8,9]]
        // Bitmap: row 1 null = 0b00000010 = 0x02
        let mut col = vec![0x01u8, 0x02];
        col.extend_from_slice(&build_long_array_row(&[2, 2], &[1, 2, 3, 4]));
        col.extend_from_slice(&build_long_array_row(&[1, 3], &[7, 8, 9]));
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("a", ColumnKind::LongArray, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::LongArray(c) = view else {
            panic!()
        };
        assert_eq!(c.len(), 3);
        assert_eq!(c.shape(0), Some(&[2u32, 2][..]));
        assert_eq!(c.element_count(0), 4);
        assert_eq!(c.element(0, 3), Some(4));
        assert!(c.is_null(1));
        assert_eq!(c.shape(1), None);
        assert_eq!(c.shape(2), Some(&[1u32, 3][..]));
        assert_eq!(c.element(2, 0), Some(7));
        assert_eq!(c.element(2, 2), Some(9));
    }

    #[test]
    fn decode_array_empty_vs_null_distinct() {
        // 3 rows of DOUBLE_ARRAY: regular [1.0, 2.0], empty (shape [0]), NULL.
        // QuestDB emits a non-null empty array inline with a 0-length
        // dimension; a NULL array is carried in the validity bitmap. The
        // view must keep them distinct: empty is non-null with 0 elements,
        // NULL has no shape.
        let mut col = vec![0x01u8, 0x04]; // null_flag=1, bitmap row 2 null
        col.extend_from_slice(&build_double_array_row(&[2], &[1.0, 2.0]));
        col.extend_from_slice(&build_double_array_row(&[0], &[])); // empty: nDims=1, dim 0
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("a", ColumnKind::DoubleArray, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::DoubleArray(c) = view else {
            panic!()
        };
        assert_eq!(c.len(), 3);

        // Row 0: regular.
        assert!(!c.is_null(0));
        assert_eq!(c.shape(0), Some(&[2u32][..]));
        assert_eq!(c.element_count(0), 2);
        assert_eq!(c.element(0, 0), Some(1.0));
        assert_eq!(c.element(0, 1), Some(2.0));

        // Row 1: empty array — non-null, 1-D shape [0], zero elements. The
        // shape is present (Some) and raw bytes are an empty (not absent)
        // slice — this is what separates it from NULL.
        assert!(!c.is_null(1));
        assert_eq!(c.shape(1), Some(&[0u32][..]));
        assert_eq!(c.element_count(1), 0);
        assert_eq!(c.raw(1), Some(&[][..]));

        // Row 2: NULL — no shape, no raw bytes.
        assert!(c.is_null(2));
        assert_eq!(c.shape(2), None);
        assert_eq!(c.element_count(2), 0);
        assert_eq!(c.raw(2), None);
    }

    #[test]
    fn decode_array_zero_dims_rejected() {
        let mut col = vec![0x00u8];
        col.push(0u8); // nDims = 0
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("a", ColumnKind::DoubleArray, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn decode_array_huge_row_rejected() {
        // Single row with shape claiming MAX+1 elements via a single dim.
        let mut col = vec![0x00u8, 1]; // nDims=1
        let big = (MAX_ARRAY_ELEMENTS_PER_ROW + 1) as u32;
        col.extend_from_slice(&big.to_le_bytes());
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("a", ColumnKind::LongArray, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
    }

    #[test]
    fn decode_array_degenerate_prefix_dim_rejected() {
        // `[2^31, 0]`: zero elements but a leading dim a final-product-only cap
        // would miss.
        let mut col = vec![0x00u8, 2]; // null_flag, nDims=2
        col.extend_from_slice(&(1u32 << 31).to_le_bytes()); // dim0 = 2^31
        col.extend_from_slice(&0u32.to_le_bytes()); // dim1 = 0
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("a", ColumnKind::DoubleArray, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
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
            .add_column(
                "s",
                ColumnKind::Varchar,
                varchar_col_no_nulls(&["foo", "", "café"]),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Varchar(c) = view else {
            panic!()
        };
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Varchar(c) = view else {
            panic!()
        };
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
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidUtf8);
    }

    #[test]
    fn decode_varchar_offset_splitting_codepoint_rejected() {
        // `data = [0xC3, 0xB1]` is the codepoint `ñ` — valid UTF-8 as a
        // whole. Offsets `[0, 1, 2]` would split it: row 0 = `[0xC3]`,
        // row 1 = `[0xB1]`. Both rows are invalid UTF-8 in isolation;
        // handing them to `from_utf8_unchecked` is UB. The decoder must
        // reject this rather than relying on a global `from_utf8` check.
        let mut col = vec![0x00u8]; // null_flag = 0
        for o in [0u32, 1, 2] {
            col.extend_from_slice(&o.to_le_bytes());
        }
        col.extend_from_slice(&[0xC3, 0xB1]);
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("s", ColumnKind::Varchar, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Binary(c) = view else {
            panic!()
        };
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Binary(c) = view else {
            panic!()
        };
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
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    fn le_i128s(vs: &[i128]) -> Vec<u8> {
        let mut o = Vec::new();
        for v in vs {
            o.extend_from_slice(&v.to_le_bytes());
        }
        o
    }

    #[test]
    fn decode_geohash_8bit() {
        // 3 rows, no nulls. precision_bits=8 (varint = 0x08), 1 byte each.
        let mut col = vec![0x00u8]; // null_flag
        encode_u64(8, &mut col); // precision_bits
        col.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("g", ColumnKind::Geohash, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Geohash(c) = view else {
            panic!()
        };
        assert_eq!(c.precision_bits(), 8);
        assert_eq!(c.byte_width(), 1);
        assert_eq!(c.len(), 3);
        assert_eq!(c.value(0), 0xAA);
        assert_eq!(c.value(1), 0xBB);
        assert_eq!(c.value(2), 0xCC);
    }

    #[test]
    fn decode_geohash_60bit_with_nulls() {
        // 4 rows; row 1 null. precision_bits=60, byte_width=8.
        let mut col = vec![0x01u8, 0x02]; // null_flag=1, bitmap row1
        encode_u64(60, &mut col);
        // 3 non-null × 8 bytes
        col.extend_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        col.extend_from_slice(&0xAAAA_BBBB_CCCC_DDDDu64.to_le_bytes());
        col.extend_from_slice(&0x1111_2222_3333_4444u64.to_le_bytes());
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column("g", ColumnKind::Geohash, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Geohash(c) = view else {
            panic!()
        };
        assert_eq!(c.precision_bits(), 60);
        assert_eq!(c.byte_width(), 8);
        assert!(!c.is_null(0));
        assert!(c.is_null(1));
        assert_eq!(c.value(0), 0x0102_0304_0506_0708);
        assert_eq!(c.value(2), 0xAAAA_BBBB_CCCC_DDDD);
        assert_eq!(c.value(3), 0x1111_2222_3333_4444);
    }

    #[test]
    fn decode_geohash_invalid_precision_rejected() {
        let mut col = vec![0x00u8];
        encode_u64(0, &mut col); // precision_bits=0 invalid
        let (flags_byte, payload) = BatchBuilder::new(0)
            .add_column("g", ColumnKind::Geohash, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn decode_decimal128_with_scale() {
        let mut col = vec![0x00u8, 0x04]; // null_flag, scale=4
        col.extend_from_slice(&le_i128s(&[100_000i128, -42i128]));
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("p", ColumnKind::Decimal128, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Decimal128(c) = view else {
            panic!()
        };
        assert_eq!(c.scale(), 4);
        assert_eq!(c.value(0), 100_000i128);
        assert_eq!(c.value(1), -42i128);
    }

    #[test]
    fn decode_decimal256_passes_raw_bytes() {
        let mut col = vec![0x00u8, 0x06]; // null_flag, scale=6
        let row0: [u8; 32] = std::array::from_fn(|i| i as u8);
        let row1: [u8; 32] = std::array::from_fn(|i| (255 - i) as u8);
        col.extend_from_slice(&row0);
        col.extend_from_slice(&row1);
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("p", ColumnKind::Decimal256, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Decimal256(c) = view else {
            panic!()
        };
        assert_eq!(c.scale(), 6);
        assert_eq!(c.value(0), &row0);
        assert_eq!(c.value(1), &row1);
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
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Varchar(c) = view else {
            panic!()
        };
        assert_eq!(c.len(), 3);
        assert_eq!(c.value(0), None);
        assert_eq!(c.value(1), None);
        assert_eq!(c.value(2), None);
        assert_eq!(c.offsets(), &[0u32, 0, 0, 0]);
    }

    #[test]
    fn trailing_bytes_rejected() {
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[7])))
            .build();
        let mut bytes_vec: Vec<u8> = payload.to_vec();
        bytes_vec.push(0xAA); // trailing byte
        let payload = Bytes::from(bytes_vec);
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
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
        let mut schema: Option<Schema> = None;
        let err = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn multi_column_batch() {
        // 2 rows, 2 cols: long, double
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("a", ColumnKind::Long, col_no_nulls(&le_i64s(&[10, 20])))
            .add_column(
                "b",
                ColumnKind::Double,
                col_no_nulls(&{
                    let mut o = Vec::new();
                    o.extend_from_slice(&1.5f64.to_le_bytes());
                    o.extend_from_slice(&2.5f64.to_le_bytes());
                    o
                }),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
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

    // -----------------------------------------------------------------
    // Coverage backfill (PR #140 review items #3, #4, #11).
    //
    // The decoder's existing tests overwhelmingly cover the common
    // row-counts (1..1000) and value-sizes (a few bytes). The edge
    // cases below add coverage that would otherwise only fire under
    // live-server workloads — and only then if the server happens to
    // emit the exact shape.
    // -----------------------------------------------------------------

    /// `row_count == 0` RESULT_BATCH for a fixed-width column. The
    /// decoder still walks its per-column path, so densification, the
    /// validity bitmap allocation (`div_ceil(0, 8) == 0` bytes), and
    /// the column-view constructor all need to handle the empty case
    /// without an off-by-one. Pin the result_end-style "no rows but
    /// schema present" shape that a live query against an empty table
    /// would produce.
    #[test]
    fn decode_zero_row_batch_long() {
        let (flags_byte, payload) = BatchBuilder::new(0)
            .add_column("v", ColumnKind::Long, col_no_nulls(&le_i64s(&[])))
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        assert_eq!(batch.row_count, 0);
        assert_eq!(batch.columns.len(), 1);
        let ColumnView::Long(c) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(c.len(), 0);
    }

    /// Same zero-row case but for VARCHAR, which is the variable-width
    /// path. Wire emits the single trailing offset `[0u32]` (`non_null + 1`
    /// = 1 entries) with no data. The decoder's dense-offset rebuild
    /// must produce a `[0u32]` array of length `row_count + 1 = 1` and
    /// not deref into an empty offsets slice.
    #[test]
    fn decode_zero_row_batch_varchar() {
        let (flags_byte, payload) = BatchBuilder::new(0)
            .add_column("s", ColumnKind::Varchar, varchar_col_no_nulls(&[]))
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        assert_eq!(batch.row_count, 0);
        let ColumnView::Varchar(c) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(c.len(), 0);
        // Dense offsets must include the trailing sentinel; iterating
        // 0..len() yields no slices but the slice indexing math is
        // exercised via `offsets()[0..1]`.
        assert_eq!(c.offsets(), &[0u32]);
    }

    /// Zero rows across a mix of column kinds — every per-kind decode
    /// arm must short-circuit cleanly on `row_count == 0`. A regression
    /// in any one arm (e.g. a stray `unwrap()` on `bitmap.last()`)
    /// would fail this test even though the single-column variants
    /// above might still pass.
    #[test]
    fn decode_zero_row_batch_multi_kind() {
        let (flags_byte, payload) = BatchBuilder::new(0)
            .add_column("i", ColumnKind::Int, col_no_nulls(&le_i32s(&[])))
            .add_column("l", ColumnKind::Long, col_no_nulls(&le_i64s(&[])))
            .add_column("d", ColumnKind::Double, col_no_nulls(&le_f64s(&[])))
            .add_column("s", ColumnKind::Varchar, varchar_col_no_nulls(&[]))
            .add_column("b", ColumnKind::Binary, {
                // Same shape as varchar: one trailing offset, no data.
                let mut out = vec![0x00u8];
                out.extend_from_slice(&0u32.to_le_bytes());
                out
            })
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        assert_eq!(batch.row_count, 0);
        assert_eq!(batch.columns.len(), 5);
        for col_idx in 0..5 {
            let v = batch.column_view(col_idx, &dict).unwrap();
            // The view's row count is what the public API exposes for
            // iteration; every kind must agree it has zero rows.
            let len = match v {
                ColumnView::Int(c) => c.len(),
                ColumnView::Long(c) => c.len(),
                ColumnView::Double(c) => c.len(),
                ColumnView::Varchar(c) => c.len(),
                ColumnView::Binary(c) => c.len(),
                _ => unreachable!(),
            };
            assert_eq!(len, 0, "column {} reported non-zero rows", col_idx);
        }
    }

    /// Multi-MiB VARCHAR value. Verifies the `u32` offset arithmetic
    /// (offsets, data length, cumulative bytes) holds at sizes the
    /// short-string tests above don't exercise. 2 MiB is large enough
    /// to surface any silent `u16` truncation or `i32` overflow in the
    /// decode path while keeping the test under the transport's 64 MiB
    /// cap (which would be applied at the transport layer, not here).
    #[test]
    fn decode_varchar_multi_mb_value() {
        let big = "x".repeat(2 * 1024 * 1024); // 2 MiB of 'x' (ASCII = 1 byte/char)
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column(
                "s",
                ColumnKind::Varchar,
                varchar_col_no_nulls(&[big.as_str()]),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let ColumnView::Varchar(c) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(c.len(), 1);
        let v = c.value(0).expect("non-null");
        // Avoid printing 2 MiB on failure — compare length + sample
        // first/last byte. A regression that truncated would either
        // fail the length or the boundary sample.
        assert_eq!(v.len(), big.len());
        assert_eq!(v.as_bytes()[0], b'x');
        assert_eq!(v.as_bytes()[v.len() - 1], b'x');
    }

    /// Multi-MiB BINARY value across two rows. The second value is
    /// distinct from the first so a regression that reuses the same
    /// offset across rows would fail the byte-level sample check.
    #[test]
    fn decode_binary_multi_mb_value() {
        let big_a = vec![0xABu8; 2 * 1024 * 1024];
        let big_b = vec![0xCDu8; 1024 * 1024 + 7];
        let mut col = vec![0x00u8]; // null_flag = 0
        // offsets: [0, len_a, len_a + len_b]
        let off_a: u32 = big_a.len() as u32;
        let off_b: u32 = (big_a.len() + big_b.len()) as u32;
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&off_a.to_le_bytes());
        col.extend_from_slice(&off_b.to_le_bytes());
        col.extend_from_slice(&big_a);
        col.extend_from_slice(&big_b);
        let (flags_byte, payload) = BatchBuilder::new(2)
            .add_column("b", ColumnKind::Binary, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let ColumnView::Binary(c) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(c.len(), 2);
        let v0 = c.value(0).expect("non-null");
        let v1 = c.value(1).expect("non-null");
        assert_eq!(v0.len(), big_a.len());
        assert_eq!(v0[0], 0xAB);
        assert_eq!(v0[v0.len() - 1], 0xAB);
        assert_eq!(v1.len(), big_b.len());
        assert_eq!(v1[0], 0xCD);
        assert_eq!(v1[v1.len() - 1], 0xCD);
    }

    /// Zero-length BINARY value (`is_null = false`, `len = 0`) MUST
    /// round-trip as a non-null empty slice, distinct from a `NULL` row.
    /// Mirrors the varchar `decode_varchar_no_nulls` empty-string case
    /// (`""` round-trips as `Some("")`); the BINARY variant of the same
    /// shape had no test coverage before.
    #[test]
    fn decode_binary_empty_value_distinct_from_null() {
        // 3 rows: empty, NULL, two-byte value.
        // bitmap: row 1 is NULL → 0b0000_0010 = 0x02
        let mut col = vec![0x01u8]; // null_flag = 1 (bitmap present)
        col.push(0x02); // bitmap byte
        // Offsets for the 2 non-null rows + trailing = [0, 0, 2]
        // (row 0 has zero-length value, row 2 has 2-byte value).
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&0u32.to_le_bytes());
        col.extend_from_slice(&2u32.to_le_bytes());
        col.extend_from_slice(&[0xAA, 0xBB]);
        let (flags_byte, payload) = BatchBuilder::new(3)
            .add_column("b", ColumnKind::Binary, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let ColumnView::Binary(c) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        assert_eq!(c.len(), 3);
        // Empty non-null binary: Some(&[]). Note Some, not None.
        let v0 = c.value(0);
        assert!(
            matches!(v0, Some(s) if s.is_empty()),
            "zero-length non-null binary must be Some(empty slice), not None: got {:?}",
            v0
        );
        // NULL row: None.
        assert_eq!(c.value(1), None);
        assert!(c.is_null(1));
        // Sanity on row 2.
        assert_eq!(c.value(2), Some(&[0xAA, 0xBB][..]));
    }

    /// SYMBOL column with a column-local dict large enough that the
    /// code stream uses multi-byte LEB128. Codes ≥ 128 require 2 bytes
    /// of varint; codes ≥ 16,384 require 3 bytes. The decoder enforces
    /// `dict_size <= row_count` (each code in the stream picks one
    /// dict entry), so we build N = 17,000 rows referencing a 17,000-
    /// entry dict and verify the boundary codes 0 / 127 / 128 /
    /// 16,383 / 16,384 / 16,999 all resolve correctly. This exercises
    /// `decode_codes_no_nulls`'s fast-path branch selection at every
    /// width boundary in one shot.
    ///
    /// 17,000 short entries × ~8 bytes ≈ 140 KB of dict on the wire
    /// plus ≤ 51 KB of codes — well under any cap — but big enough
    /// that a regression to a `u8`-code path or a 1-byte-only varint
    /// reader would fail.
    #[test]
    fn decode_symbol_column_large_dict_multibyte_codes() {
        const N: usize = 17_000;
        // Build the dict and a code stream of length N where the
        // boundary codes appear at known row indices for assertion.
        // Default: row i → code i (forces every dict entry to be
        // referenced at least once and gives a stable mapping).
        let dict_entries: Vec<String> = (0..N).map(|i| format!("s{}", i)).collect();
        let dict_refs: Vec<&str> = dict_entries.iter().map(String::as_str).collect();
        let codes_per_row: Vec<u64> = (0..N as u64).collect();
        let col = symbol_column_local(None, &dict_refs, &codes_per_row);
        let (flags_byte, payload) = BatchBuilder::new(N)
            .add_column("s", ColumnKind::Symbol, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut schema: Option<Schema> = None;
        let batch = decode_result_batch(
            &payload,
            flags_byte,
            &mut dict,
            &mut schema,
            &mut ZstdScratch::new(),
        )
        .unwrap();
        let ColumnView::Symbol(s) = batch.column_view(0, &dict).unwrap() else {
            panic!()
        };
        // Spot-check boundary codes spanning the 1-, 2-, and 3-byte
        // LEB128 widths. Walking all 17k rows would catch the same
        // regressions but inflates test output on failure.
        for &code in &[0u64, 127, 128, 16_383, 16_384, 16_999] {
            let row = code as usize;
            let expected = format!("s{}", code);
            assert_eq!(
                s.resolve(row),
                Some(expected.as_str()),
                "row {} (code {}) misresolved — multi-byte LEB128 boundary regression",
                row,
                code
            );
        }
    }

    // Unused references silenced by binding to `_` in tests where they exist
    // only for symmetry.
    #[allow(dead_code)]
    fn _unused(_: &Schema, _: &SchemaColumn) {}

    // -----------------------------------------------------------------------
    // Hostile-input hardening. Ports the relevant cases from
    // `java-questdb-client/.../QwpResultBatchDecoderHardeningTest.java`. Each
    // test crafts a malformed `RESULT_BATCH` payload directly and asserts
    // that `decode_result_batch` returns an `Err` (no panic, no OOB read,
    // no unbounded allocation) — same intent as the Java reference, just
    // expressed against the Rust decoder's `Result<DecodedBatch>` surface.
    //
    // Only RESULT_BATCH-targeted cases are ported here. Java's
    // `EXEC_DONE`/`RESULT_END`/`QUERY_ERROR` truncation cases belong to
    // the `server_event.rs` decoder and would go in that file's `mod tests`
    // when ported.
    // -----------------------------------------------------------------------
    mod hardening {
        use super::*;

        /// Build a DOUBLE_ARRAY column body with explicit per-row dimension
        /// lists. No nulls. Element bytes are zero-filled — the test only
        /// cares about dimension validation.
        fn array_col_body(row_dims: &[&[u32]]) -> Vec<u8> {
            let mut out = vec![0x00u8]; // null_flag = 0
            for dims in row_dims {
                out.push(dims.len() as u8);
                for &d in *dims {
                    out.extend_from_slice(&d.to_le_bytes());
                }
                let total: usize = dims.iter().map(|&d| d as usize).product();
                out.resize(out.len() + total * 8, 0);
            }
            out
        }

        // -----------------------------------------------------------------
        // ARRAY column dimension validation.
        // -----------------------------------------------------------------

        /// The QWP spec (`docs/qwp/wire-egress.md` §11.5.1) explicitly
        /// states:
        ///
        /// > A non-NULL empty array is a valid value.
        ///
        /// On the wire an empty non-NULL array manifests as a dim list
        /// whose product is zero — most naturally a single dim of zero.
        /// The C++ contract test
        /// `mock: non-null empty-data array row exposes data_offsets symmetry`
        /// in `cpp_test/test_reader_mock.cpp` pins this case against
        /// the Rust reader: shape `[2, 0, 3]` decodes to a non-null row
        /// with a zero-length (empty) per-row data slice and
        /// `element_count == 0`.
        #[test]
        fn array_dim_zero_is_valid_empty_array() {
            // 2D row with a zero in the first dim → 0 elements,
            // 0 data bytes. Spec-compliant empty non-NULL array.
            let body = array_col_body(&[&[0u32, 5u32]]);
            let (flags_byte, payload) = BatchBuilder::new(1)
                .add_column("a", ColumnKind::DoubleArray, body)
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .expect("ARRAY row with dim==0 must decode as a valid empty array");
        }

        /// Ports `testArrayValidDimensionsAreAccepted`. Positive baseline
        /// so the dim-zero test above is exercising the same code path
        /// rather than a generic frame-shape bug.
        #[test]
        fn array_valid_dims_accepted() {
            let body = array_col_body(&[&[2u32, 3u32]]);
            let (flags_byte, payload) = BatchBuilder::new(1)
                .add_column("a", ColumnKind::DoubleArray, body)
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .expect("2D array with all non-zero dims must decode cleanly");
        }

        // -----------------------------------------------------------------
        // GEOHASH precision range.
        // -----------------------------------------------------------------

        /// Ports `testGeohashPrecisionBelowMinIsRejected`. Per spec
        /// precision_bits is in 1..=60; a 0 must be rejected.
        #[test]
        fn geohash_precision_below_min_rejected() {
            // Body: null_flag=0 + varint(precision=0) + no value bytes
            let mut body = vec![0x00u8];
            encode_u64(0, &mut body); // precision_bits = 0
            let (flags_byte, payload) = BatchBuilder::new(0)
                .add_column("g", ColumnKind::Geohash, body)
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let err = decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .expect_err("decoder must reject GEOHASH precision_bits=0");
            assert!(
                err.msg().contains("precision"),
                "error must mention precision, got: {}",
                err.msg()
            );
        }

        /// Ports `testGeohashPrecisionAboveMaxIsRejected`. Precision_bits
        /// > 60 must be rejected.
        #[test]
        fn geohash_precision_above_max_rejected() {
            let mut body = vec![0x00u8];
            encode_u64(61, &mut body); // precision_bits = 61 (above max)
            let (flags_byte, payload) = BatchBuilder::new(0)
                .add_column("g", ColumnKind::Geohash, body)
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let err = decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .expect_err("decoder must reject GEOHASH precision_bits > 60");
            assert!(
                err.msg().contains("precision"),
                "error must mention precision, got: {}",
                err.msg()
            );
        }

        // -----------------------------------------------------------------
        // Table-block name length.
        // -----------------------------------------------------------------

        /// Ports `testTableNameLengthOverflowVarintIsRejected`. The
        /// `MAX_TABLE_NAME_LENGTH = 127` cap (mirrored from the Java
        /// constants) keeps a hostile varint from triggering an oversized
        /// allocation or an arbitrary slice read.
        #[test]
        fn table_name_len_overflow_rejected() {
            // Build the RESULT_BATCH prefix by hand so we can plant a
            // huge name_len varint where BatchBuilder always emits 0.
            let mut out = Vec::new();
            out.push(MsgKind::ResultBatch.as_u8());
            out.extend_from_slice(&1i64.to_le_bytes()); // request_id
            encode_u64(0, &mut out); // batch_seq

            // Table block: name_len = u32::MAX, name bytes follow
            // (won't be read — the cap check fires first).
            encode_u64(u32::MAX as u64, &mut out);

            let payload = Bytes::from(out);
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let err =
                decode_result_batch(&payload, 0, &mut dict, &mut schema, &mut ZstdScratch::new())
                    .expect_err("decoder must reject huge table name length");
            assert!(
                err.msg().contains("table name length"),
                "error must mention table name length, got: {}",
                err.msg()
            );
        }

        // -----------------------------------------------------------------
        // SYMBOL column-local dict size.
        // -----------------------------------------------------------------

        /// Ports `testSymbolColumnNonDeltaHugeDictSizeIsRejected`. A
        /// column-local `dict_size > row_count` must be rejected before
        /// any allocations scale with it.
        #[test]
        fn symbol_non_delta_huge_dict_rejected() {
            // SYMBOL body: null_flag=0 + varint(dict_size=1000) + ...
            // row_count is 3, so dict_size = 1000 trips the cap.
            let mut body = vec![0x00u8];
            encode_u64(1000, &mut body); // dict_size much larger than row_count
            // Don't bother writing dict entries — the cap fires first.
            let (flags_byte, payload) = BatchBuilder::new(3)
                .add_column("s", ColumnKind::Symbol, body)
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let err = decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .expect_err("decoder must reject SYMBOL dict_size > row_count");
            assert!(
                err.msg().contains("dict_size"),
                "error must mention dict_size, got: {}",
                err.msg()
            );
        }

        // -----------------------------------------------------------------
        // Varchar/Binary offset validation.
        // -----------------------------------------------------------------

        /// Ports `testStringColumnNonMonotonicOffsetsAreRejected`. Two
        /// rows with offsets `[0, 10, 5]` — strictly decreasing — must
        /// be rejected before the data slice is exposed.
        #[test]
        fn string_non_monotonic_offsets_rejected() {
            // No-null VARCHAR with 2 rows. Offsets: [0, 10, 5] —
            // monotonicity is violated between index 1 and 2.
            let mut body = vec![0x00u8]; // null_flag = 0
            for &o in &[0u32, 10, 5] {
                body.extend_from_slice(&o.to_le_bytes());
            }
            // 10 bytes of data so the read_bytes for the (claimed)
            // total length doesn't truncate before monotonicity check.
            body.extend_from_slice(&[b'a'; 10]);
            let (flags_byte, payload) = BatchBuilder::new(2)
                .add_column("v", ColumnKind::Varchar, body)
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let err = decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .expect_err("decoder must reject non-monotonic varlen offsets");
            assert!(
                err.msg().contains("not monotonic"),
                "error must say 'not monotonic', got: {}",
                err.msg()
            );
        }

        /// Bonus: the Rust decoder requires the first offset to be 0
        /// (a stronger invariant than just monotonicity). Pin it so a
        /// future encoder/decoder refactor can't silently drop the
        /// check.
        #[test]
        fn string_first_offset_nonzero_rejected() {
            // Single non-null row, offsets [5, 12]. First offset != 0.
            let mut body = vec![0x00u8];
            for &o in &[5u32, 12] {
                body.extend_from_slice(&o.to_le_bytes());
            }
            body.extend_from_slice(&[b'a'; 12]);
            let (flags_byte, payload) = BatchBuilder::new(1)
                .add_column("v", ColumnKind::Varchar, body)
                .build();
            let mut dict = SymbolDict::new();
            let mut schema: Option<Schema> = None;
            let err = decode_result_batch(
                &payload,
                flags_byte,
                &mut dict,
                &mut schema,
                &mut ZstdScratch::new(),
            )
            .expect_err("decoder must reject non-zero first offset");
            assert!(
                err.msg().contains("must start at 0"),
                "error must say first offset must start at 0, got: {}",
                err.msg()
            );
        }
    }
}
