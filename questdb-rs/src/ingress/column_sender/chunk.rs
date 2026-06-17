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

//! Column-major chunk: one DataFrame's worth of borrowed column buffers
//! destined for a single QuestDB table.
//!
//! `Chunk<'a>` stores **descriptors** — raw pointers + lengths + an
//! optional validity bitmap — for each column. No data is copied at
//! append time. Caller buffers must remain alive from
//! [`ColumnSender::flush`](super::ColumnSender::flush) call setup until
//! the call returns; the lifetime parameter `'a` enforces this on the
//! safe Rust API.
//!
//! At flush time, the [`encoder`](super::encoder) walks the descriptors
//! and writes wire bytes straight into the connection's reusable write
//! buffer. The no-null hot path is a single `memcpy` per column from the
//! caller's buffer into that buffer.

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::slice;

use crate::{Result, error};

#[cfg(feature = "arrow")]
use super::arrow_batch;
use super::numpy_wire;
use super::validity::{Validity, check_row_count};
use super::wire::{
    MAX_NAME_LEN, QWP_TYPE_BINARY, QWP_TYPE_BOOLEAN, QWP_TYPE_BYTE, QWP_TYPE_DATE, QWP_TYPE_DOUBLE,
    QWP_TYPE_FLOAT, QWP_TYPE_INT, QWP_TYPE_IPV4, QWP_TYPE_LONG, QWP_TYPE_LONG256, QWP_TYPE_SHORT,
    QWP_TYPE_SYMBOL, QWP_TYPE_TIMESTAMP, QWP_TYPE_TIMESTAMP_NANOS, QWP_TYPE_UUID, QWP_TYPE_VARCHAR,
    validate_name,
};

// ===========================================================================
// Descriptors
// ===========================================================================

#[cfg(feature = "arrow")]
pub struct ImportedArrowColumn {
    field: arrow_schema::Field,
    array: arrow_array::ArrayRef,
    kind: arrow_batch::ColumnKind,
}

#[cfg(feature = "arrow")]
impl ImportedArrowColumn {
    /// Import an Arrow column from the Arrow C Data Interface.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `array` and `schema` are valid
    /// `FFI_ArrowArray` / `FFI_ArrowSchema` structures as produced by
    /// the Arrow C Data Interface. The caller's `array.release` is
    /// consumed unconditionally: cleared to `None` on every return,
    /// success or error. The caller MUST NOT invoke the original
    /// release after this call. `schema` is borrowed and remains owned
    /// by the caller.
    pub unsafe fn import_from_ffi(
        array: &mut arrow::ffi::FFI_ArrowArray,
        schema: &arrow::ffi::FFI_ArrowSchema,
        force_not_symbol: bool,
    ) -> Result<Self> {
        use arrow_array::make_array;

        let imported_array = unsafe { std::ptr::read(array) };
        array.release = None;

        let mut field = arrow_schema::Field::try_from(schema)
            .map_err(|err| error::fmt!(ArrowIngest, "schema conversion failed: {}", err))?;
        if force_not_symbol {
            let mut metadata = field.metadata().clone();
            metadata.insert(
                crate::egress::arrow::metadata::SYMBOL.to_string(),
                "false".to_string(),
            );
            field = field.with_metadata(metadata);
        }
        let array_data = unsafe { arrow::ffi::from_ffi(imported_array, schema) }
            .map_err(|err| error::fmt!(ArrowIngest, "from_ffi failed: {}", err))?;
        array_data
            .validate_full()
            .map_err(|err| error::fmt!(ArrowIngest, "Arrow array validation failed: {}", err))?;

        let array = make_array(array_data);
        let kind = arrow_batch::classify(&field, array.as_ref())?;
        Ok(Self { field, array, kind })
    }

    pub fn len(&self) -> usize {
        self.array.len()
    }

    pub fn is_empty(&self) -> bool {
        self.array.is_empty()
    }

    pub fn field(&self) -> &arrow_schema::Field {
        &self.field
    }

    fn slice(&self, row_offset: usize, row_count: usize) -> Result<arrow_array::ArrayRef> {
        let array_len = self.array.len();
        let slice_end = row_offset.checked_add(row_count).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "row_offset {} + row_count {} overflows",
                row_offset,
                row_count
            )
        })?;
        if slice_end > array_len {
            return Err(error::fmt!(
                InvalidApiCall,
                "slice [{}, {}) out of range for array length {}",
                row_offset,
                slice_end,
                array_len
            ));
        }
        Ok(if row_offset == 0 && row_count == array_len {
            self.array.clone()
        } else {
            self.array.slice(row_offset, row_count)
        })
    }
}

/// Validity bitmap descriptor (raw-ptr form, matching `Validity<'a>`).
/// `non_null_count` is pre-computed at column-append time because several
/// encoder paths (e.g. VARCHAR's dense offset table) size their output
/// from it.
#[derive(Clone, Copy)]
pub(crate) struct ValidityDescriptor {
    pub(crate) bits: *const u8,
    pub(crate) bit_len: usize,
    pub(crate) non_null_count: usize,
}

impl ValidityDescriptor {
    fn from_validity(v: &Validity<'_>) -> Self {
        Self {
            bits: v.bits.as_ptr(),
            bit_len: v.bit_len,
            non_null_count: v.non_null_count(),
        }
    }

    /// SAFETY: caller's buffer must still be alive (Chunk's `'a` lifetime
    /// guarantees this on the safe path; the FFI is responsible on the
    /// unsafe path).
    #[inline]
    pub(crate) unsafe fn is_valid(&self, idx: usize) -> bool {
        debug_assert!(idx < self.bit_len);
        let byte = unsafe { *self.bits.add(idx / 8) };
        (byte >> (idx % 8)) & 1 == 1
    }

    /// Length in bytes of the underlying Arrow bitmap.
    #[inline]
    pub(crate) fn byte_len(&self) -> usize {
        self.bit_len.div_ceil(8)
    }

    /// `true` iff at least one row is null. Mirrors the row API's
    /// `uses_null_bitmap`: an all-valid validity is encoded densely with
    /// `null_flag = 0` and no bitmap, matching the Java client and the
    /// Arrow bulk path. `bit_len` equals the column row count (enforced by
    /// `check_row_count`).
    #[inline]
    pub(crate) fn has_nulls(&self) -> bool {
        self.non_null_count < self.bit_len
    }
}

/// Per-column kind dispatch. Each variant carries the raw pointer(s) the
/// encoder dereferences at flush time.
pub(crate) enum ColumnKind {
    // ---- Sentinel-null fixed width (no bitmap; 0x00 null_flag) ----
    Byte {
        data: *const i8,
    },
    Short {
        data: *const i16,
    },
    Int {
        data: *const i32,
    },
    Long {
        data: *const i64,
    },
    Float {
        data: *const f32,
    },
    Double {
        data: *const f64,
    },
    // Bool: Arrow LSB-first bitmap input. row_count is the Chunk's row count.
    Bool {
        bits: *const u8,
    },

    // ---- Bitmap-style fixed width (sparse null encoding) ----
    Ipv4 {
        data: *const u32,
    },
    TsNanos {
        data: *const i64,
    },
    TsMicros {
        data: *const i64,
    },
    DateMillis {
        data: *const i64,
    },
    Uuid {
        data: *const [u8; 16],
    },
    Long256 {
        data: *const [u8; 32],
    },

    // ---- Variable-width text (VARCHAR) ----
    Varchar {
        offsets: *const i32,
        /// row_count + 1
        offsets_len: usize,
        bytes: *const u8,
        bytes_len: usize,
    },

    // ---- Variable-width text from Arrow LargeUtf8 (i64 offsets) ----
    //
    // The wire format is identical to `Varchar`; we narrow each i64
    // offset to u32 on the fly inside the encoder, with an
    // overflow check (QWP's offset table is uint32 LE on the wire).
    VarcharLarge {
        offsets: *const i64,
        /// row_count + 1
        offsets_len: usize,
        bytes: *const u8,
        bytes_len: usize,
    },

    // ---- Variable-width bytes (BINARY) ----
    //
    // Same offsets + bytes layout as `Varchar`; differs only in the
    // wire type byte (`QWP_TYPE_BINARY`) so the server creates a
    // BINARY column. UTF-8 validation is not performed.
    Binary {
        offsets: *const i32,
        /// row_count + 1
        offsets_len: usize,
        bytes: *const u8,
        bytes_len: usize,
    },

    // ---- Symbol (dictionary-encoded) ----
    Symbol {
        codes: SymbolCodesPtr,
        dict_offsets: SymbolOffsetsPtr,
        /// dict cardinality + 1
        dict_offsets_len: usize,
        dict_bytes: *const u8,
        dict_bytes_len: usize,
    },

    /// Arrow array + classified Arrow-side kind. Encoded at flush via
    /// [`arrow_batch::write_arrow_column_body`]. The Arrow `ArrayRef`
    /// holds the buffers via Arc; the enclosing
    /// [`ColumnDescriptor::validity`] is always `None` for this
    /// variant (validity lives inside the array's `NullBuffer`).
    #[cfg(feature = "arrow")]
    ArrowDeferred {
        arrow_kind: arrow_batch::ColumnKind,
        arr: arrow_array::ArrayRef,
    },

    /// Raw numpy buffer + dtype tag, encoded at flush via
    /// [`numpy_wire::emit_into_wire`]. `data` is caller-owned: lifetime
    /// must extend through the next flush / sync call. Validity (if
    /// any) lives in the enclosing [`ColumnDescriptor`].
    NumpyDeferred {
        dtype: numpy_wire::NumpyDtype,
        data: *const u8,
        row_count: usize,
    },
}

#[derive(Clone, Copy)]
pub(crate) enum SymbolCodesPtr {
    I8(*const i8),
    I16(*const i16),
    I32(*const i32),
}

impl SymbolCodesPtr {
    /// Read the dict-index for row `i`, sign-extended to `i64` so the
    /// encoder can range-check uniformly. SAFETY: caller's `codes`
    /// buffer must still be alive.
    #[inline]
    pub(crate) unsafe fn read_i64(&self, i: usize) -> i64 {
        unsafe {
            match self {
                SymbolCodesPtr::I8(p) => *p.add(i) as i64,
                SymbolCodesPtr::I16(p) => *p.add(i) as i64,
                SymbolCodesPtr::I32(p) => *p.add(i) as i64,
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum SymbolOffsetsPtr {
    I32(*const i32),
    I64(*const i64),
}

impl SymbolOffsetsPtr {
    /// Read the dict byte offset for entry `i`, widened to `i64` so the
    /// encoder can consume Arrow UTF-8 and LargeUtf8 dictionaries uniformly.
    /// SAFETY: caller's offsets buffer must still be alive.
    #[inline]
    pub(crate) unsafe fn read_i64(&self, i: usize) -> i64 {
        unsafe {
            match self {
                SymbolOffsetsPtr::I32(p) => *p.add(i) as i64,
                SymbolOffsetsPtr::I64(p) => *p.add(i),
            }
        }
    }
}

/// One column slot in a [`Chunk`]. `name` is owned (the chunk holds it
/// for diagnostics + signature emission); everything else is borrowed.
pub(crate) struct ColumnDescriptor {
    pub(crate) name: String,
    pub(crate) wire_type: u8,
    pub(crate) kind: ColumnKind,
    pub(crate) validity: Option<ValidityDescriptor>,
}

/// Designated timestamp descriptor. Required exactly once per chunk
/// before flush. Designated timestamps are non-null by spec.
pub(crate) struct DesignatedTsDescriptor {
    pub(crate) wire_type: u8,
    pub(crate) data: *const i64,
}

// ===========================================================================
// Chunk
// ===========================================================================

/// One DataFrame's worth of borrowed column buffers destined for one
/// QuestDB table.
///
/// The lifetime parameter `'a` ties the chunk to every column buffer
/// passed in through `column_*` / `symbol_dict_*`. Each call validates
/// inputs and stores a descriptor referencing the caller's buffer; no
/// data is copied. The caller's buffers must outlive the chunk —
/// concretely, they must remain alive from each column append through
/// the next [`ColumnSender::flush`](super::ColumnSender::flush) call.
pub struct Chunk<'a> {
    pub(crate) table: String,
    pub(crate) row_count: Option<usize>,
    pub(crate) columns: Vec<ColumnDescriptor>,
    pub(crate) designated_ts: Option<DesignatedTsDescriptor>,
    _marker: PhantomData<&'a ()>,
}

impl<'a> Chunk<'a> {
    /// Create a chunk for `table`. The table name is validated at flush
    /// time against the QWP/Java client length cap (127 bytes UTF-8).
    pub fn new(table: impl Into<String>) -> Self {
        Self {
            table: table.into(),
            row_count: None,
            columns: Vec::new(),
            designated_ts: None,
            _marker: PhantomData,
        }
    }

    /// Table name this chunk targets. Validated at flush time.
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Row count locked by the first appended column (or designated
    /// timestamp). `0` when neither has been set.
    pub fn row_count(&self) -> usize {
        self.row_count.unwrap_or(0)
    }

    /// `true` when the chunk has no appended columns and no designated
    /// timestamp. Equivalent to "row count has not yet been locked".
    pub fn is_empty(&self) -> bool {
        self.row_count.is_none() && self.designated_ts.is_none()
    }

    /// Reset the chunk for reuse. Drops descriptors but keeps the
    /// `Vec<ColumnDescriptor>` capacity so the next chunk fills the same
    /// slots without reallocating the outer Vec.
    pub fn clear(&mut self) {
        self.row_count = None;
        self.columns.clear();
        self.designated_ts = None;
    }

    // -------------------------------------------------------------------
    // Numeric & fixed-width columns
    // -------------------------------------------------------------------

    /// Append an `i8` column (QWP wire type `BYTE`). `validity` may
    /// carry per-row null bits (Arrow shape: bit = 1 means VALID).
    pub fn column_i8(
        &mut self,
        name: &str,
        data: &'a [i8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_BYTE,
            ColumnKind::Byte {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append an `i16` column (QWP wire type `SHORT`).
    pub fn column_i16(
        &mut self,
        name: &str,
        data: &'a [i16],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_SHORT,
            ColumnKind::Short {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append an `i32` column (QWP wire type `INT`).
    pub fn column_i32(
        &mut self,
        name: &str,
        data: &'a [i32],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_INT,
            ColumnKind::Int {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append an `i64` column (QWP wire type `LONG`).
    pub fn column_i64(
        &mut self,
        name: &str,
        data: &'a [i64],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_LONG,
            ColumnKind::Long {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append an `f32` column (QWP wire type `FLOAT`).
    pub fn column_f32(
        &mut self,
        name: &str,
        data: &'a [f32],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_FLOAT,
            ColumnKind::Float {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append an `f64` column (QWP wire type `DOUBLE`).
    pub fn column_f64(
        &mut self,
        name: &str,
        data: &'a [f64],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_DOUBLE,
            ColumnKind::Double {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append a boolean column (QWP wire type `BOOLEAN`).
    ///
    /// `data` is an LSB-first bit-packed slice: bit `i` is row `i`'s
    /// value (1 = true, 0 = false). At least `ceil(row_count / 8)`
    /// bytes are required; the slice may be longer.
    ///
    /// QWP `BOOLEAN` has no NULL representation on the wire: when
    /// `validity` is supplied, null rows are coerced to `false`. Pass
    /// `None` if your data has no nulls, or use a wider numeric column
    /// if you need to distinguish null from `false` downstream.
    pub fn column_bool(
        &mut self,
        name: &str,
        data: &'a [u8],
        row_count: usize,
        validity: Option<&Validity<'a>>,
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
        self.push_column(
            name,
            QWP_TYPE_BOOLEAN,
            ColumnKind::Bool {
                bits: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    // -------------------------------------------------------------------
    // Bitmap-style fixed-width columns
    // -------------------------------------------------------------------

    /// Append a UUID column (QWP wire type `UUID`). Each row is 16 bytes
    /// in QuestDB wire order — the low 64 bits little-endian followed by
    /// the high 64 bits little-endian. This matches the row API and the
    /// bytes produced by Arrow egress; it is NOT canonical RFC-4122
    /// big-endian, so callers holding big-endian UUIDs must reorder first.
    pub fn column_uuid(
        &mut self,
        name: &str,
        data: &'a [[u8; 16]],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_UUID,
            ColumnKind::Uuid {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append a LONG256 column (QWP wire type `LONG256`). Each row is 32
    /// bytes: the 256-bit value as little-endian limbs, low limb first.
    /// This matches the row API and the bytes produced by Arrow egress.
    pub fn column_long256(
        &mut self,
        name: &str,
        data: &'a [[u8; 32]],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_LONG256,
            ColumnKind::Long256 {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append an IPv4 column (QWP wire type `IPV4`). Each row is the
    /// 32-bit address in host byte order.
    pub fn column_ipv4(
        &mut self,
        name: &str,
        data: &'a [u32],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_IPV4,
            ColumnKind::Ipv4 {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append a timestamp column with nanosecond precision (QWP wire
    /// type `TIMESTAMP_NANOS`). Values are Unix epoch nanoseconds.
    pub fn column_ts_nanos(
        &mut self,
        name: &str,
        data: &'a [i64],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_TIMESTAMP_NANOS,
            ColumnKind::TsNanos {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append a timestamp column with microsecond precision (QWP wire
    /// type `TIMESTAMP`). Values are Unix epoch microseconds.
    pub fn column_ts_micros(
        &mut self,
        name: &str,
        data: &'a [i64],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_TIMESTAMP,
            ColumnKind::TsMicros {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    /// Append a date column with millisecond precision (QWP wire type
    /// `DATE`). Values are Unix epoch milliseconds.
    pub fn column_date_millis(
        &mut self,
        name: &str,
        data: &'a [i64],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, data.len(), validity)?;
        self.push_column(
            name,
            QWP_TYPE_DATE,
            ColumnKind::DateMillis {
                data: data.as_ptr(),
            },
            validity,
            row_count,
        )
    }

    // -------------------------------------------------------------------
    // VARCHAR
    // -------------------------------------------------------------------

    /// Append a VARCHAR column from Arrow Utf8 layout (QWP wire type
    /// `VARCHAR`). `offsets` is `i32` with `row_count + 1` entries
    /// (monotonic, non-negative, last ≤ `bytes.len()`); `bytes` is the
    /// concatenated UTF-8 buffer.
    pub fn column_varchar(
        &mut self,
        name: &str,
        offsets: &'a [i32],
        bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        if offsets.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "VARCHAR offsets must have at least one entry (row_count + 1)"
            ));
        }
        let row_count = offsets.len() - 1;
        let row_count = check_row_count(self.row_count, row_count, validity)?;
        validate_varchar_offsets(offsets, bytes.len())?;
        self.push_column(
            name,
            QWP_TYPE_VARCHAR,
            ColumnKind::Varchar {
                offsets: offsets.as_ptr(),
                offsets_len: offsets.len(),
                bytes: bytes.as_ptr(),
                bytes_len: bytes.len(),
            },
            validity,
            row_count,
        )
    }

    /// Same wire output as [`column_varchar`], but accepts Arrow
    /// LargeUtf8 input where offsets are `int64` instead of `int32`. The
    /// encoder narrows each offset to `u32` at encode time with an
    /// overflow check (QWP's offset table is uint32 LE on the wire), so
    /// no caller-side copy / narrowing is needed.
    ///
    /// Errors if any offset is negative, decreasing, exceeds the bytes
    /// buffer length, or — at encode time — exceeds `u32::MAX`.
    pub fn column_varchar_large(
        &mut self,
        name: &str,
        offsets: &'a [i64],
        bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        if offsets.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "LargeVARCHAR offsets must have at least one entry (row_count + 1)"
            ));
        }
        let row_count = offsets.len() - 1;
        let row_count = check_row_count(self.row_count, row_count, validity)?;
        validate_varchar_offsets_i64(offsets, bytes.len())?;
        self.push_column(
            name,
            QWP_TYPE_VARCHAR,
            ColumnKind::VarcharLarge {
                offsets: offsets.as_ptr(),
                offsets_len: offsets.len(),
                bytes: bytes.as_ptr(),
                bytes_len: bytes.len(),
            },
            validity,
            row_count,
        )
    }

    /// Append a BINARY column. Same offsets + bytes layout as
    /// [`column_varchar`]; the encoder writes the column with wire type
    /// `QWP_TYPE_BINARY` instead of `QWP_TYPE_VARCHAR`. No UTF-8
    /// validation is performed.
    pub fn column_binary(
        &mut self,
        name: &str,
        offsets: &'a [i32],
        bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        if offsets.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "BINARY offsets must have at least one entry (row_count + 1)"
            ));
        }
        let row_count = offsets.len() - 1;
        let row_count = check_row_count(self.row_count, row_count, validity)?;
        validate_varchar_offsets(offsets, bytes.len())?;
        self.push_column(
            name,
            QWP_TYPE_BINARY,
            ColumnKind::Binary {
                offsets: offsets.as_ptr(),
                offsets_len: offsets.len(),
                bytes: bytes.as_ptr(),
                bytes_len: bytes.len(),
            },
            validity,
            row_count,
        )
    }

    // -------------------------------------------------------------------
    // Symbol
    // -------------------------------------------------------------------

    /// Append a SYMBOL column whose per-row codes are `i8` indices into
    /// a dictionary defined by (`dict_offsets`, `dict_bytes`) in Arrow
    /// Utf8 layout. Wire type is `SYMBOL`; the encoder interns each
    /// referenced dictionary entry against the connection-scoped
    /// `SymbolGlobalDict` at flush time.
    pub fn symbol_dict_i8(
        &mut self,
        name: &str,
        codes: &'a [i8],
        dict_offsets: &'a [i32],
        dict_bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        self.push_symbol(
            name,
            SymbolCodesPtr::I8(codes.as_ptr()),
            codes.len(),
            SymbolOffsetsPtr::I32(dict_offsets.as_ptr()),
            dict_offsets.len(),
            dict_bytes,
            validity,
        )
    }

    /// Same as [`symbol_dict_i8`](Self::symbol_dict_i8) but with `i16` codes.
    pub fn symbol_dict_i16(
        &mut self,
        name: &str,
        codes: &'a [i16],
        dict_offsets: &'a [i32],
        dict_bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        self.push_symbol(
            name,
            SymbolCodesPtr::I16(codes.as_ptr()),
            codes.len(),
            SymbolOffsetsPtr::I32(dict_offsets.as_ptr()),
            dict_offsets.len(),
            dict_bytes,
            validity,
        )
    }

    /// Same as [`symbol_dict_i8`](Self::symbol_dict_i8) but with `i32` codes.
    pub fn symbol_dict_i32(
        &mut self,
        name: &str,
        codes: &'a [i32],
        dict_offsets: &'a [i32],
        dict_bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        self.push_symbol(
            name,
            SymbolCodesPtr::I32(codes.as_ptr()),
            codes.len(),
            SymbolOffsetsPtr::I32(dict_offsets.as_ptr()),
            dict_offsets.len(),
            dict_bytes,
            validity,
        )
    }

    /// Same as [`symbol_dict_i8`](Self::symbol_dict_i8) but the dictionary
    /// uses Arrow LargeUtf8 layout (`i64` offsets).
    pub fn symbol_dict_large_i8(
        &mut self,
        name: &str,
        codes: &'a [i8],
        dict_offsets: &'a [i64],
        dict_bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        self.push_symbol(
            name,
            SymbolCodesPtr::I8(codes.as_ptr()),
            codes.len(),
            SymbolOffsetsPtr::I64(dict_offsets.as_ptr()),
            dict_offsets.len(),
            dict_bytes,
            validity,
        )
    }

    /// Same as [`symbol_dict_i16`](Self::symbol_dict_i16) but the dictionary
    /// uses Arrow LargeUtf8 layout (`i64` offsets).
    pub fn symbol_dict_large_i16(
        &mut self,
        name: &str,
        codes: &'a [i16],
        dict_offsets: &'a [i64],
        dict_bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        self.push_symbol(
            name,
            SymbolCodesPtr::I16(codes.as_ptr()),
            codes.len(),
            SymbolOffsetsPtr::I64(dict_offsets.as_ptr()),
            dict_offsets.len(),
            dict_bytes,
            validity,
        )
    }

    /// Same as [`symbol_dict_i32`](Self::symbol_dict_i32) but the dictionary
    /// uses Arrow LargeUtf8 layout (`i64` offsets).
    pub fn symbol_dict_large_i32(
        &mut self,
        name: &str,
        codes: &'a [i32],
        dict_offsets: &'a [i64],
        dict_bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        self.push_symbol(
            name,
            SymbolCodesPtr::I32(codes.as_ptr()),
            codes.len(),
            SymbolOffsetsPtr::I64(dict_offsets.as_ptr()),
            dict_offsets.len(),
            dict_bytes,
            validity,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn push_symbol(
        &mut self,
        name: &str,
        codes: SymbolCodesPtr,
        codes_len: usize,
        dict_offsets: SymbolOffsetsPtr,
        dict_offsets_len: usize,
        dict_bytes: &'a [u8],
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        let row_count = check_row_count(self.row_count, codes_len, validity)?;
        if dict_offsets_len == 0 {
            return Err(error::fmt!(
                InvalidApiCall,
                "symbol dict offsets must have at least one entry (dict_len + 1)"
            ));
        }
        match dict_offsets {
            SymbolOffsetsPtr::I32(p) => {
                let offsets = unsafe { slice::from_raw_parts(p, dict_offsets_len) };
                validate_varchar_offsets(offsets, dict_bytes.len())?;
            }
            SymbolOffsetsPtr::I64(p) => {
                let offsets = unsafe { slice::from_raw_parts(p, dict_offsets_len) };
                validate_varchar_offsets_i64(offsets, dict_bytes.len())?;
            }
        }
        let dict_len = dict_offsets_len - 1;

        // Range-check codes for non-null rows. The encoder relies on
        // every non-null code being a valid dict index, so we surface
        // the failure here at append time.
        let bounds_check = match codes {
            SymbolCodesPtr::I8(p) => unsafe { range_check_codes(p, codes_len, dict_len, validity) },
            SymbolCodesPtr::I16(p) => unsafe {
                range_check_codes(p, codes_len, dict_len, validity)
            },
            SymbolCodesPtr::I32(p) => unsafe {
                range_check_codes(p, codes_len, dict_len, validity)
            },
        };
        bounds_check?;

        self.push_column(
            name,
            QWP_TYPE_SYMBOL,
            ColumnKind::Symbol {
                codes,
                dict_offsets,
                dict_offsets_len,
                dict_bytes: dict_bytes.as_ptr(),
                dict_bytes_len: dict_bytes.len(),
            },
            validity,
            row_count,
        )
    }

    // -------------------------------------------------------------------
    // Numpy deferred (raw caller-owned buffer + dtype tag, encoded
    // single-pass at flush via numpy_wire::emit_into_wire)
    // -------------------------------------------------------------------

    /// Append a column whose source layout is described by a
    /// [`NumpyDtype`]. The data buffer must be contiguous and
    /// native-endian; the caller retains ownership and must keep it
    /// alive until the next flush / sync. Widening, packing, and
    /// per-row conversion happen single-pass during encode — the chunk
    /// allocates nothing per numpy column.
    ///
    /// # Safety
    ///
    /// `data` must be either NULL with `row_count == 0`, or point to
    /// at least `row_count * sizeof(<dtype src element>)` valid,
    /// contiguous, native-endian bytes (one byte per row for
    /// [`NumpyDtype::Bool`]). The caller's buffer must remain alive
    /// until this chunk's next flush / sync returns.
    ///
    /// [`NumpyDtype`]: super::NumpyDtype
    /// [`NumpyDtype::Bool`]: super::NumpyDtype::Bool
    pub unsafe fn push_numpy_deferred(
        &mut self,
        name: &str,
        dtype: numpy_wire::NumpyDtype,
        data: *const u8,
        row_count: usize,
        validity: Option<&Validity<'a>>,
    ) -> Result<&mut Self> {
        if data.is_null() && row_count != 0 {
            return Err(error::fmt!(
                InvalidApiCall,
                "push_numpy_deferred: data pointer is NULL with row_count = {}",
                row_count
            ));
        }
        dtype.validate()?;
        let row_count = check_row_count(self.row_count, row_count, validity)?;
        let wire_type = dtype.wire_type();
        self.push_column(
            name,
            wire_type,
            ColumnKind::NumpyDeferred {
                dtype,
                data,
                row_count,
            },
            validity,
            row_count,
        )
    }

    // -------------------------------------------------------------------
    // Designated timestamp
    // -------------------------------------------------------------------

    /// Pin the chunk's designated timestamp from a microsecond-precision
    /// Unix epoch column (QWP wire type `TIMESTAMP`). Required before
    /// flushing a non-empty chunk; rejects if a designated timestamp has
    /// already been set on this chunk.
    pub fn designated_timestamp_micros(&mut self, data: &'a [i64]) -> Result<&mut Self> {
        self.set_designated_ts(QWP_TYPE_TIMESTAMP, data)
    }

    /// Same as [`designated_timestamp_micros`](Self::designated_timestamp_micros)
    /// but for a nanosecond-precision Unix epoch column (QWP wire type
    /// `TIMESTAMP_NANOS`).
    pub fn designated_timestamp_nanos(&mut self, data: &'a [i64]) -> Result<&mut Self> {
        self.set_designated_ts(QWP_TYPE_TIMESTAMP_NANOS, data)
    }

    fn set_designated_ts(&mut self, wire_type: u8, data: &'a [i64]) -> Result<&mut Self> {
        if self.designated_ts.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "designated timestamp already set on this chunk"
            ));
        }
        let row_count = check_row_count(self.row_count, data.len(), None)?;
        self.designated_ts = Some(DesignatedTsDescriptor {
            wire_type,
            data: data.as_ptr(),
        });
        self.row_count = Some(row_count);
        Ok(self)
    }

    // -------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------

    fn push_column(
        &mut self,
        name: &str,
        wire_type: u8,
        kind: ColumnKind,
        validity: Option<&Validity<'_>>,
        row_count: usize,
    ) -> Result<&mut Self> {
        validate_name("column", name)?;
        if name.len() > MAX_NAME_LEN {
            return Err(error::fmt!(
                InvalidName,
                "column name is too long: {} bytes (max {})",
                name.len(),
                MAX_NAME_LEN
            ));
        }
        self.guard_unique_name(name)?;
        let validity = validity.map(ValidityDescriptor::from_validity);
        self.columns.push(ColumnDescriptor {
            name: name.to_owned(),
            wire_type,
            kind,
            validity,
        });
        self.row_count = Some(row_count);
        Ok(self)
    }

    /// Append an Arrow column to the chunk. The column's QWP wire type
    /// is derived from `field` (Arrow datatype + extension metadata)
    /// via the same classifier used by [`ColumnSender::flush_arrow_batch`].
    /// `arr.len()` participates in the chunk's row-count lock; validity
    /// is read from `arr.nulls()` at flush time.
    ///
    /// `field.name()` is ignored — the caller's `name` argument is the
    /// authoritative column name (it must match the destination table's
    /// schema, regardless of how the upstream Arrow producer named the
    /// column).
    ///
    /// [`ColumnSender::flush_arrow_batch`]: super::ColumnSender::flush_arrow_batch
    #[cfg(feature = "arrow")]
    pub fn push_arrow_column(
        &mut self,
        name: &str,
        field: &arrow_schema::Field,
        arr: arrow_array::ArrayRef,
    ) -> Result<&mut Self> {
        if field.data_type() != arr.data_type() {
            return Err(error::fmt!(
                InvalidApiCall,
                "column {:?}: field data type {:?} does not match array data type {:?}",
                name,
                field.data_type(),
                arr.data_type()
            ));
        }
        let kind = arrow_batch::classify(field, arr.as_ref())?;
        self.push_arrow_deferred(name, kind, arr)
    }

    #[cfg(feature = "arrow")]
    pub fn push_imported_arrow_slice(
        &mut self,
        name: &str,
        imported: &ImportedArrowColumn,
        row_offset: usize,
        row_count: usize,
    ) -> Result<&mut Self> {
        let arr = imported.slice(row_offset, row_count)?;
        self.push_arrow_deferred(name, imported.kind, arr)
    }

    /// Append an Arrow column to the chunk. `arr.len()` participates in
    /// the chunk's row-count lock just like row-by-row column appends.
    /// Validity is read from `arr.nulls()` at flush time; the wire-type
    /// byte is fixed at push time from the classified [`arrow_batch::ColumnKind`].
    ///
    /// Used by `column_sender_chunk_append_arrow_column` (FFI) after
    /// the caller's `ArrowArray` / `ArrowSchema` has been imported into
    /// an `arrow_array::ArrayRef` and classified.
    #[cfg(feature = "arrow")]
    pub(crate) fn push_arrow_deferred(
        &mut self,
        name: &str,
        arrow_kind: arrow_batch::ColumnKind,
        arr: arrow_array::ArrayRef,
    ) -> Result<&mut Self> {
        validate_name("column", name)?;
        if name.len() > MAX_NAME_LEN {
            return Err(error::fmt!(
                InvalidName,
                "column name is too long: {} bytes (max {})",
                name.len(),
                MAX_NAME_LEN
            ));
        }
        self.guard_unique_name(name)?;
        let row_count = check_row_count(self.row_count, arr.len(), None)?;
        let has_nulls = arr.null_count() > 0;
        let wire_type = arrow_batch::wire_type_byte(arrow_kind, has_nulls);
        self.columns.push(ColumnDescriptor {
            name: name.to_owned(),
            wire_type,
            kind: ColumnKind::ArrowDeferred { arrow_kind, arr },
            validity: None,
        });
        self.row_count = Some(row_count);
        Ok(self)
    }

    fn guard_unique_name(&self, name: &str) -> Result<()> {
        if self.columns.iter().any(|c| c.name == name) {
            return Err(error::fmt!(
                InvalidApiCall,
                "duplicate column name in chunk: {:?}",
                name
            ));
        }
        Ok(())
    }
}

fn validate_varchar_offsets(offsets: &[i32], bytes_len: usize) -> Result<()> {
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

fn validate_varchar_offsets_i64(offsets: &[i64], bytes_len: usize) -> Result<()> {
    let first = offsets[0];
    if first < 0 {
        return Err(error::fmt!(
            InvalidApiCall,
            "LargeVARCHAR offsets must be non-negative (offsets[0] = {})",
            first
        ));
    }
    let mut prev = first;
    for (i, &off) in offsets.iter().enumerate().skip(1) {
        if off < prev {
            return Err(error::fmt!(
                InvalidApiCall,
                "LargeVARCHAR offsets must be non-decreasing (offsets[{}] = {} < offsets[{}] = {})",
                i,
                off,
                i - 1,
                prev
            ));
        }
        prev = off;
    }
    let last = prev;
    if (last as u64) > bytes_len as u64 {
        return Err(error::fmt!(
            InvalidApiCall,
            "LargeVARCHAR offsets exceed bytes buffer: last offset = {}, bytes_len = {}",
            last,
            bytes_len
        ));
    }
    // QWP's wire offset table is uint32 LE. The encoder narrows
    // `(off - first)` to u32 per row, so the *span* must fit u32::MAX,
    // not the absolute last offset. A slice taken from the tail of a
    // multi-GiB LargeUtf8 array remains valid as long as the span is
    // bounded.
    let span = last - first;
    if span > u32::MAX as i64 {
        return Err(error::fmt!(
            InvalidApiCall,
            "LargeVARCHAR slice span exceeds QWP uint32 limit: \
             last - first = {} - {} = {} > {} (u32::MAX)",
            last,
            first,
            span,
            u32::MAX
        ));
    }
    Ok(())
}

/// SAFETY: `p` must point to `codes_len` valid `T`s. `validity` (if any)
/// must have `bit_len == codes_len` and a bitmap of at least
/// `ceil(codes_len / 8)` bytes — both enforced by `check_row_count` and
/// `Validity::from_bitmap` before this is called.
unsafe fn range_check_codes<T>(
    p: *const T,
    codes_len: usize,
    dict_len: usize,
    validity: Option<&Validity<'_>>,
) -> Result<()>
where
    T: Copy + Into<i64>,
{
    for i in 0..codes_len {
        if validity.is_some_and(|v| !v.is_valid(i)) {
            continue;
        }
        let code = unsafe { (*p.add(i)).into() };
        if code < 0 || (code as usize) >= dict_len {
            return Err(error::fmt!(
                InvalidApiCall,
                "symbol code out of range: row {} -> {} (dict_len = {})",
                i,
                code,
                dict_len
            ));
        }
    }
    Ok(())
}

impl Debug for Chunk<'_> {
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
        let a = [1i64, 2, 3];
        chunk.column_i64("a", &a, None).unwrap();
        assert_eq!(chunk.row_count(), 3);
        let b = [4i64, 5];
        let err = chunk.column_i64("b", &b, None).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("row_count"));
    }

    #[test]
    fn rejects_duplicate_column_name() {
        let mut chunk = Chunk::new("t");
        let a1 = [1i64];
        chunk.column_i64("a", &a1, None).unwrap();
        let a2 = [2i64];
        let err = chunk.column_i64("a", &a2, None).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("duplicate"));
    }

    #[test]
    fn rejects_invalid_validity_length() {
        let mut chunk = Chunk::new("t");
        let bits = [0xFFu8];
        let v = Validity::from_bitmap(&bits, 8).unwrap();
        let data = [1i64, 2, 3];
        let err = chunk.column_i64("a", &data, Some(&v)).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("Validity bitmap"));
    }

    #[test]
    fn designated_ts_sets_row_count() {
        let mut chunk = Chunk::new("t");
        let ts = [1i64, 2, 3];
        chunk.designated_timestamp_micros(&ts).unwrap();
        assert_eq!(chunk.row_count(), 3);
        let ts2 = [4i64, 5, 6];
        let err = chunk.designated_timestamp_nanos(&ts2).unwrap_err();
        assert!(err.msg().contains("designated"));
    }

    #[test]
    fn clear_resets_columns_but_keeps_table() {
        let mut chunk = Chunk::new("t");
        let a = [1i64];
        let ts = [10i64];
        chunk.column_i64("a", &a, None).unwrap();
        chunk.designated_timestamp_nanos(&ts).unwrap();
        chunk.clear();
        assert_eq!(chunk.row_count(), 0);
        assert!(chunk.is_empty());
        assert_eq!(chunk.table(), "t");
    }

    #[test]
    fn varchar_rejects_negative_offset() {
        let mut chunk = Chunk::new("t");
        let offsets = [-1i32, 1, 2];
        let err = chunk
            .column_varchar("v", &offsets, b"ab", None)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("non-negative"));
    }

    #[test]
    fn varchar_rejects_non_monotonic_offsets() {
        let mut chunk = Chunk::new("t");
        let offsets = [0i32, 5, 3];
        let err = chunk
            .column_varchar("v", &offsets, b"abcde", None)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("non-decreasing"));
    }

    #[test]
    fn symbol_rejects_out_of_range_code() {
        let mut chunk = Chunk::new("t");
        let codes = [0i32, 99];
        let dict_offsets = [0i32, 5];
        let err = chunk
            .symbol_dict_i32("sym", &codes, &dict_offsets, b"alpha", None)
            .unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("out of range"));
    }

    #[test]
    fn symbol_skips_null_codes() {
        let mut chunk = Chunk::new("t");
        let codes = [0i32, 99];
        let dict_offsets = [0i32, 5];
        let bits = [0b0000_0001];
        let v = Validity::from_bitmap(&bits, 2).unwrap();
        chunk
            .symbol_dict_i32("sym", &codes, &dict_offsets, b"alpha", Some(&v))
            .expect("null row's bogus code is ignored");
    }
}
