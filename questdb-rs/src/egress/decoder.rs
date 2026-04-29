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
use crate::egress::schema::SchemaRegistry;
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::wire::ByteReader;
use crate::egress::wire::header::flags;
use crate::egress::wire::msg_kind::MsgKind;
use bytes::Bytes;

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
    pub schema_id: u64,
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
    pub fn column_view<'a>(&'a self, idx: usize, dict: &'a SymbolDict) -> Result<ColumnView<'a>> {
        let col = self
            .columns
            .get(idx)
            .ok_or_else(|| fmt!(InvalidApiCall, "column index {} out of range", idx))?;
        Ok(match col {
            DecodedColumn::Boolean(b) => {
                ColumnView::Boolean(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Byte(b) => {
                ColumnView::Byte(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Short(b) => {
                ColumnView::Short(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Int(b) => {
                ColumnView::Int(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Long(b) => {
                ColumnView::Long(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Float(b) => {
                ColumnView::Float(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Double(b) => {
                ColumnView::Double(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Timestamp(b) => {
                ColumnView::Timestamp(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Date(b) => {
                ColumnView::Date(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::TimestampNanos(b) => ColumnView::TimestampNanos(FixedColumn::new(
                &b.values,
                validity_of(b, self.row_count),
            )),
            DecodedColumn::Char(b) => {
                ColumnView::Char(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Ipv4(b) => {
                ColumnView::Ipv4(FixedColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Uuid(b) => {
                ColumnView::Uuid(UuidColumn::new(&b.values, validity_of(b, self.row_count)))
            }
            DecodedColumn::Long256(b) => ColumnView::Long256(Long256Column::new(
                &b.values,
                validity_of(b, self.row_count),
            )),
            DecodedColumn::Decimal64 { buffer, scale } => ColumnView::Decimal64(
                Decimal64Column::new(&buffer.values, validity_of(buffer, self.row_count), *scale),
            ),
            DecodedColumn::Symbol {
                codes,
                validity,
                local_dict,
            } => {
                let active_dict = local_dict.as_ref().unwrap_or(dict);
                ColumnView::Symbol(SymbolColumn::new(
                    codes,
                    validity_from_opt(validity, self.row_count),
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
                    VarcharColumn::new(offsets, data, validity_from_opt(validity, self.row_count))
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
                validity_from_opt(validity, self.row_count),
            )),
            DecodedColumn::Geohash {
                buffer,
                byte_width,
                precision_bits,
            } => ColumnView::Geohash(GeohashColumn::new(
                &buffer.values,
                *byte_width,
                *precision_bits,
                validity_of(buffer, self.row_count),
            )),
            DecodedColumn::Decimal128 { buffer, scale } => ColumnView::Decimal128(
                Decimal128Column::new(&buffer.values, validity_of(buffer, self.row_count), *scale),
            ),
            DecodedColumn::Decimal256 { buffer, scale } => ColumnView::Decimal256(
                Decimal256Column::new(&buffer.values, validity_of(buffer, self.row_count), *scale),
            ),
            DecodedColumn::DoubleArray(b) => ColumnView::DoubleArray(DoubleArrayColumn::new(
                &b.data_offsets,
                &b.data,
                &b.shapes,
                &b.shape_offsets,
                validity_from_opt(&b.validity, self.row_count),
            )),
            DecodedColumn::LongArray(b) => ColumnView::LongArray(LongArrayColumn::new(
                &b.data_offsets,
                &b.data,
                &b.shapes,
                &b.shape_offsets,
                validity_from_opt(&b.validity, self.row_count),
            )),
        })
    }
}

fn validity_of<'a>(buf: &'a ColumnBuffer, row_count: usize) -> Validity<'a> {
    validity_from_opt(&buf.validity, row_count)
}

fn validity_from_opt<'a>(validity: &'a Option<Bytes>, row_count: usize) -> Validity<'a> {
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
    payload: &Bytes,
    flags_byte: u8,
    dict: &mut SymbolDict,
    registry: &mut SchemaRegistry,
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
    let body: Bytes = if flags_byte & flags::ZSTD != 0 {
        #[cfg(feature = "compression-zstd")]
        {
            Bytes::from(zstd_decompress_body(r.remaining())?)
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
    let name_len = r.read_varint_usize()?;
    r.read_bytes(name_len)?; // table name; ignored for query results
    let row_count = r.read_varint_usize()?;
    let col_count = r.read_varint_usize()?;
    // Sanity-cap the wire-supplied column count before any code path
    // turns it into a `Vec::with_capacity(col_count)` — without this
    // a hostile or corrupted varint could request a multi-GiB up-front
    // allocation and OOM the client before the bytes-too-short check
    // ever runs. QuestDB's own table column cap is well under this.
    const MAX_COLS: usize = 4096;
    if col_count > MAX_COLS {
        return Err(fmt!(
            ProtocolError,
            "table block declares {} columns; max supported is {}",
            col_count,
            MAX_COLS
        ));
    }

    // Schema section. col_count comes from the table block above; the
    // schema section itself does not re-emit it.
    let (schema_id, schema_bytes) = {
        let schema_section = r.remaining();
        let dec = registry.decode_section(schema_section, col_count)?;
        (dec.schema_id, dec.bytes_consumed)
    };
    r.advance(schema_bytes)?;
    let schema_cols = registry
        .get(schema_id)
        .expect("schema must be present after decode_section")
        .len();
    if schema_cols != col_count {
        return Err(fmt!(
            ProtocolError,
            "schema {} has {} columns but batch announced {}",
            schema_id,
            schema_cols,
            col_count
        ));
    }

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
    let connection_dict_size = dict.len();
    for (i, kind) in kinds.iter().enumerate() {
        let col = decode_column(
            &mut r,
            &body,
            *kind,
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
        schema_id,
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
        ColumnKind::Byte => DecodedColumn::Byte(decode_fixed(r, parent, row_count, 1)?),
        ColumnKind::Short => DecodedColumn::Short(decode_fixed(r, parent, row_count, 2)?),
        ColumnKind::Int => DecodedColumn::Int(decode_fixed(r, parent, row_count, 4)?),
        ColumnKind::Long => DecodedColumn::Long(decode_fixed(r, parent, row_count, 8)?),
        ColumnKind::Float => DecodedColumn::Float(decode_fixed(r, parent, row_count, 4)?),
        ColumnKind::Double => DecodedColumn::Double(decode_fixed(r, parent, row_count, 8)?),
        ColumnKind::Char => DecodedColumn::Char(decode_fixed(r, parent, row_count, 2)?),
        ColumnKind::Ipv4 => DecodedColumn::Ipv4(decode_fixed(r, parent, row_count, 4)?),
        ColumnKind::Uuid => DecodedColumn::Uuid(decode_fixed(r, parent, row_count, 16)?),
        ColumnKind::Long256 => DecodedColumn::Long256(decode_fixed(r, parent, row_count, 32)?),

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
        }
        if total > MAX_ARRAY_ELEMENTS_PER_ROW {
            return Err(fmt!(
                LimitExceeded,
                "array row {} has {} elements (max {})",
                row,
                total,
                MAX_ARRAY_ELEMENTS_PER_ROW
            ));
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
    let buffer = densify_fixed(r, parent, row_count, byte_width as usize, validity)?;
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
    let buffer = densify_fixed(r, parent, row_count, width, validity)?;
    Ok((scale, buffer))
}

/// Common helper: read `non_null × elem_size` compact bytes from `r` and
/// write them into a `row_count × elem_size` dense buffer.
fn densify_fixed(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    elem_size: usize,
    validity: Option<Bytes>,
) -> Result<ColumnBuffer> {
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
                values: Bytes::from(dense),
                validity,
            })
        }
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

    // Borrow the concatenated data bytes from the payload — zero-copy.
    let data_len = compact[non_null] as usize;
    let data = read_owned(r, parent, data_len)?;

    if utf8 {
        std::str::from_utf8(&data)
            .map_err(|e| fmt!(InvalidUtf8, "varchar data buffer not valid UTF-8: {}", e))?;
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
    let null_flag = r.read_u8()?;
    if null_flag == 0 {
        return Ok(None);
    }
    let bitmap_len = row_count.div_ceil(8);
    Ok(Some(read_owned(r, parent, bitmap_len)?))
}

/// Read `non_null_count × elem_size` compact bytes from the wire and write
/// them into a dense `row_count × elem_size` buffer, with null slots zeroed.
fn decode_fixed(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    elem_size: usize,
) -> Result<ColumnBuffer> {
    let validity = decode_validity(r, parent, row_count)?;
    densify_fixed(r, parent, row_count, elem_size, validity)
}

/// QWP `BOOLEAN`: not nullable on the wire (validity always absent), values
/// bit-packed into `ceil(row_count/8)` bytes. We expand to one byte per row
/// so `FixedColumn<u8>` can address rows in O(1).
fn decode_boolean(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
) -> Result<ColumnBuffer> {
    let validity = decode_validity(r, parent, row_count)?;
    let non_null = match &validity {
        None => row_count,
        Some(bitmap) => row_count - count_nulls(bitmap, row_count),
    };
    let bit_bytes = non_null.div_ceil(8);
    let bits = r.read_bytes(bit_bytes)?.to_vec();

    let mut dense = vec![0u8; row_count];
    let mut src_bit = 0usize;
    for (row, slot) in dense.iter_mut().enumerate() {
        if !is_null_at_opt(&validity, row) {
            let b = bits[src_bit >> 3];
            *slot = (b >> (src_bit & 7)) & 1;
            src_bit += 1;
        }
    }
    Ok(ColumnBuffer {
        values: Bytes::from(dense),
        validity,
    })
}

fn decode_temporal(
    r: &mut ByteReader<'_>,
    parent: &Bytes,
    row_count: usize,
    flags_byte: u8,
) -> Result<ColumnBuffer> {
    if flags_byte & flags::GORILLA == 0 {
        return decode_fixed(r, parent, row_count, 8);
    }

    // Validity comes first under FLAG_GORILLA, same as every other column.
    let validity = decode_validity(r, parent, row_count)?;
    let non_null = match &validity {
        None => row_count,
        Some(bitmap) => row_count - count_nulls(bitmap, row_count),
    };

    let disc = r.read_u8()?;
    match disc {
        0x00 => densify_fixed(r, parent, row_count, 8, validity),
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
    if non_null < 3 {
        return Err(fmt!(
            ProtocolError,
            "Gorilla-encoded column must have non_null >= 3 (got {})",
            non_null
        ));
    }
    // Two i64 LE seed timestamps, then the bitstream.
    let seed = r.read_bytes(16)?;
    let first_ts = i64::from_le_bytes(seed[..8].try_into().unwrap());
    let second_ts = i64::from_le_bytes(seed[8..16].try_into().unwrap());

    let bitstream = r.remaining();
    let mut decoder = crate::egress::gorilla::GorillaDecoder::new(first_ts, second_ts, bitstream);

    let mut decoded = Vec::with_capacity(non_null);
    decoded.push(first_ts);
    decoded.push(second_ts);
    for _ in 2..non_null {
        decoded.push(decoder.decode_next()?);
    }
    let consumed = decoder.bytes_consumed();
    r.advance(consumed)?;

    // Densify into row_count × 8 with null slots zeroed.
    let mut dense = vec![0u8; row_count * 8];
    let mut next = 0usize;
    for row in 0..row_count {
        if !is_null_at_opt(&validity, row) {
            let v = decoded[next];
            dense[row * 8..row * 8 + 8].copy_from_slice(&v.to_le_bytes());
            next += 1;
        }
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
    if let Some((row, &bad)) = codes.iter().enumerate().find(|&(_, &c)| c >= dict_size_u32) {
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

/// Decompress a single zstd frame containing the body of a
/// `RESULT_BATCH`. The frame header must declare a content size
/// (`ZSTD_c_contentSizeFlag` is on by default in the server encoder);
/// rejecting "unknown" content size keeps decode-bomb amplification
/// closed.
#[cfg(feature = "compression-zstd")]
fn zstd_decompress_body(compressed: &[u8]) -> Result<Vec<u8>> {
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

    let decompressed = zstd::bulk::decompress(compressed, usize_size)
        .map_err(|e| fmt!(ProtocolError, "zstd decompress failed: {}", e))?;
    if decompressed.len() != usize_size {
        return Err(fmt!(
            ProtocolError,
            "zstd decompressed size {} != frame content size {}",
            decompressed.len(),
            size
        ));
    }
    Ok(decompressed)
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

            // Table block.
            encode_u64(0, &mut out); // name_len
            encode_u64(self.row_count as u64, &mut out);
            encode_u64(self.cols.len() as u64, &mut out);

            // Schema section. col_count is in the table block above; the
            // schema section itself does not re-emit it.
            out.push(self.schema_mode as u8);
            encode_u64(self.schema_id, &mut out);
            if matches!(self.schema_mode, SchemaMode::Full) {
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Double(c) = view else {
            panic!()
        };
        assert!(!c.is_null(0));
        assert!(c.is_null(1));
        assert!(!c.is_null(2));
        assert!(!c.is_null(3));
        assert_eq!(c.value(0), 1.5);
        // Densified zero in the null slot.
        assert_eq!(c.value(1).to_bits(), 0u64);
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Float(c) = view else { panic!() };
        assert_eq!(c.value(0), 1.5_f32);
        assert_eq!(c.value(1).to_bits(), 0u32);
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        // Spot-check that null slots read as zero (dense buffer
        // contract, not just `is_null` agreeing).
        assert_eq!(c.value(1), 0);
        assert_eq!(c.value(4), 0);
        assert_eq!(c.value(7), 0);
    }

    #[test]
    fn decode_short_with_nulls_densifies() {
        // 4 rows; row 2 null. Wire: 3 i16 values, bitmap 0x04.
        let (flags_byte, payload) = BatchBuilder::new(4)
            .add_column(
                "v",
                ColumnKind::Short,
                col_with_bitmap(&[0x04], &le_i16s(&[-1, -2, -3])),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Short(c) = view else { panic!() };
        assert_eq!(c.value(0), -1);
        assert_eq!(c.value(1), -2);
        assert_eq!(c.value(2), 0); // densified zero
        assert!(c.is_null(2));
        assert_eq!(c.value(3), -3);
    }

    #[test]
    fn decode_byte_with_nulls_densifies() {
        // 5 rows; rows 0, 3 null (bitmap 0b0000_1001 = 0x09). 3 i8 values.
        let (flags_byte, payload) = BatchBuilder::new(5)
            .add_column(
                "v",
                ColumnKind::Byte,
                col_with_bitmap(&[0x09], &[0x7F, 0x80, 0xFF]),
            )
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Byte(c) = view else { panic!() };
        assert!(c.is_null(0));
        assert!(c.is_null(3));
        assert_eq!(c.value(0), 0); // densified zero
        assert_eq!(c.value(1), 0x7F);
        assert_eq!(c.value(2), -128); // 0x80 as i8
        assert_eq!(c.value(3), 0); // densified zero
        assert_eq!(c.value(4), -1); // 0xFF as i8
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();

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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();

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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
            let mut reg = SchemaRegistry::new();
            let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), crate::egress::ErrorCode::ProtocolError);
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&zstd_payload, flags::ZSTD, &mut dict, &mut reg).unwrap();
        assert_eq!(batch.row_count, 3);
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::Long(c) = view else { panic!() };
        assert_eq!(c.value(0), 10);
        assert_eq!(c.value(1), 20);
        assert_eq!(c.value(2), 30);
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags::ZSTD, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags::GORILLA, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
        assert!(err.msg().to_lowercase().contains("discriminator"));
    }

    #[test]
    fn rejects_gorilla_with_too_few_non_null() {
        // Gorilla requires non_null >= 3 (server shortcuts the 1-2 case to
        // raw); fewer than 3 in the Gorilla branch is malformed.
        let mut col_data = vec![0x00u8]; // null_flag
        col_data.push(0x01); // gorilla discriminator
        // 2 seed timestamps would be 16 bytes, but row_count=2 < 3.
        col_data.extend_from_slice(&0i64.to_le_bytes());
        col_data.extend_from_slice(&100i64.to_le_bytes());
        let (_, payload) = BatchBuilder::new(2)
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, col_data)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags::GORILLA, &mut dict, &mut reg).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags::GORILLA, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::TimestampNanos(c) = view else {
            panic!()
        };
        assert_eq!(c.value(0), 10);
        assert_eq!(c.value(1), 20);
        assert_eq!(c.value(2), 30);
    }

    #[test]
    fn decode_gorilla_temporal_round_trip() {
        // Encode a synthetic Gorilla bitstream matching the Java encoder
        // and verify the decoder produces the same timestamps.
        let timestamps: [i64; 6] = [1_000, 1_100, 1_200, 1_310, 1_405, 1_488];
        // First two are seed; remaining are DoD-encoded.
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

        // Build the column body: validity (no nulls), disc=0x01, 16-byte seed, bitstream.
        let mut col = vec![0x00u8]; // null_flag
        col.push(0x01); // gorilla disc
        col.extend_from_slice(&timestamps[0].to_le_bytes());
        col.extend_from_slice(&timestamps[1].to_le_bytes());
        col.extend_from_slice(&bytes);

        let (_, payload) = BatchBuilder::new(timestamps.len())
            .with_flags(flags::GORILLA)
            .add_column("ts", ColumnKind::TimestampNanos, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags::GORILLA, &mut dict, &mut reg).unwrap();
        let view = batch.column_view(0, &dict).unwrap();
        let ColumnView::TimestampNanos(c) = view else {
            panic!()
        };
        for (i, &expected) in timestamps.iter().enumerate() {
            assert_eq!(c.value(i), expected, "row {}", i);
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
    fn decode_array_zero_dims_rejected() {
        let mut col = vec![0x00u8];
        col.push(0u8); // nDims = 0
        let (flags_byte, payload) = BatchBuilder::new(1)
            .add_column("a", ColumnKind::DoubleArray, col)
            .build();
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let err = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap_err();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
        let mut reg = SchemaRegistry::new();
        let batch = decode_result_batch(&payload, flags_byte, &mut dict, &mut reg).unwrap();
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
