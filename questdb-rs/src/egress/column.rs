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

//! Layer 0 column views.
//!
//! Typed, borrowing views over the bytes a `RESULT_BATCH` decoder leaves in
//! the batch's owned buffers. These types are deliberately QWP-shaped: they
//! preserve symbol-as-id, decimal-as-(value,scale), and never materialize
//! strings or perform conversions that would force a copy. Adapters
//! (Arrow C ABI, numpy/pandas, polars) consume these on top.
//!
//! ## Validity
//!
//! Per QWP, the null bitmap is LSB-first within each byte and `1` means
//! NULL. A column may carry no bitmap at all when no row is null;
//! [`Validity::None`] expresses that compactly.
//!
//! ## What's modelled here
//!
//! Fixed-width numerics (Bool, Byte, Short, Int, Long, Float, Double, Ipv4),
//! temporals (Timestamp µs / Date ms / TimestampNanos), 16-byte UUID,
//! 32-byte Long256, 2-byte Char, Symbol (dense u32 codes + dict reference),
//! Decimal64/128/256 (mantissa + scale), Geohash (variable byte width),
//! Varchar / Binary (varlen with offset table), and DOUBLE_ARRAY /
//! LONG_ARRAY (multi-dimensional array views).

use std::marker::PhantomData;

use crate::egress::column_kind::ColumnKind;
use crate::egress::error::{Result, fmt};
use crate::egress::symbol_dict::SymbolDict;

// ---------------------------------------------------------------------------
// Validity bitmap
// ---------------------------------------------------------------------------

/// Per-row null information.
///
/// `Validity::None` means "no nulls for this column"; the column carries no
/// bitmap on the wire and `is_null` always returns `false`.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Validity<'a> {
    /// No row in this column is null.
    None,
    /// LSB-first bitmap; bit `1` = null. `row_count` rows total.
    Bitmap { bytes: &'a [u8], row_count: usize },
}

impl<'a> Validity<'a> {
    /// Construct a bitmap-backed validity view.
    ///
    /// Returns `Err(InvalidApiCall)` if `bytes.len() < row_count.div_ceil(8)`
    /// — a too-short bitmap would otherwise cause [`is_null`] to silently
    /// report null rows as non-null (the bytes beyond the buffer end are
    /// indistinguishable from "this row's bit is 0"). The decoder always
    /// sizes the bitmap exactly to `row_count.div_ceil(8)`
    /// (see `decode_validity`), so the error is unreachable from
    /// crate-internal callers; the check exists so external callers can't
    /// build a corrupt view and have it silently mis-report NULL rows.
    pub fn from_bitmap(bytes: &'a [u8], row_count: usize) -> Result<Self> {
        let needed = row_count.div_ceil(8);
        if bytes.len() < needed {
            return Err(fmt!(
                InvalidApiCall,
                "Validity::from_bitmap: bitmap is {} bytes but row_count={} needs at least {}",
                bytes.len(),
                row_count,
                needed
            ));
        }
        Ok(Validity::Bitmap { bytes, row_count })
    }

    pub fn has_nulls(&self) -> bool {
        matches!(self, Validity::Bitmap { .. })
    }

    /// `true` if `row` is null. Out-of-range rows return `false` (matches
    /// the column accessors' "row was never written" treatment).
    ///
    /// Bounds-checked: a [`Validity::Bitmap`](Self::Bitmap) constructed
    /// directly (bypassing [`from_bitmap`](Self::from_bitmap)) with a
    /// too-short bitmap reports `false` for the missing tail rather
    /// than panicking. Constructor-validated values never trip the
    /// fallback.
    pub fn is_null(&self, row: usize) -> bool {
        match self {
            Validity::None => false,
            Validity::Bitmap { bytes, row_count } => {
                if row >= *row_count {
                    return false;
                }
                match bytes.get(row >> 3) {
                    Some(byte) => (byte >> (row & 7)) & 1 != 0,
                    None => false,
                }
            }
        }
    }

    /// Raw bitmap, when present.
    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self {
            Validity::None => None,
            Validity::Bitmap { bytes, .. } => Some(bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixed-width primitives
// ---------------------------------------------------------------------------

/// Decode trait for fixed-width little-endian primitives.
pub trait FixedWidth: Copy {
    const SIZE: usize;
    fn from_le(bytes: &[u8]) -> Self;
}

macro_rules! impl_fixed {
    ($t:ty, $sz:expr) => {
        impl FixedWidth for $t {
            const SIZE: usize = $sz;
            #[inline]
            fn from_le(bytes: &[u8]) -> Self {
                <$t>::from_le_bytes(bytes.try_into().expect("FixedWidth slice length"))
            }
        }
    };
}

impl_fixed!(i16, 2);
impl_fixed!(i32, 4);
impl_fixed!(i64, 8);
impl_fixed!(u16, 2);
impl_fixed!(u32, 4);
impl_fixed!(u64, 8);
impl_fixed!(f32, 4);
impl_fixed!(f64, 8);

impl FixedWidth for i8 {
    const SIZE: usize = 1;
    #[inline]
    fn from_le(bytes: &[u8]) -> Self {
        bytes[0] as i8
    }
}

impl FixedWidth for u8 {
    const SIZE: usize = 1;
    #[inline]
    fn from_le(bytes: &[u8]) -> Self {
        bytes[0]
    }
}

/// Borrowed view over a packed little-endian array of `T`.
#[derive(Debug, Clone, Copy)]
pub struct FixedColumn<'a, T: FixedWidth> {
    raw: &'a [u8],
    validity: Validity<'a>,
    _phantom: PhantomData<T>,
}

impl<'a, T: FixedWidth> FixedColumn<'a, T> {
    /// Construct a borrowed view over decoder-produced bytes.
    ///
    /// `pub(crate)` because the constructor accepts raw wire-format
    /// bytes whose length invariants (multiple of `T::SIZE`, validity
    /// bitmap matching `len()`) are only `debug_assert!`-checked. In
    /// release builds, an out-of-spec input causes silent garbage or
    /// out-of-bounds panics from `value()` — exposing it as a safe
    /// `pub fn` would let external callers trip both. The decoder
    /// upholds the invariants by construction.
    pub(crate) fn new(raw: &'a [u8], validity: Validity<'a>) -> Self {
        debug_assert_eq!(
            raw.len() % T::SIZE,
            0,
            "raw length must be multiple of element size"
        );
        Self {
            raw,
            validity,
            _phantom: PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.raw.len() / T::SIZE
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn validity(&self) -> Validity<'a> {
        self.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.validity.is_null(row)
    }

    /// Raw little-endian bytes for the entire column. `len() * T::SIZE` long.
    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Decode the value at `row`. Caller should consult [`is_null`](Self::is_null)
    /// separately; this returns the underlying bit-pattern regardless.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`. `#[track_caller]` makes the panic
    /// point at the offending call site rather than into this accessor.
    #[inline]
    #[track_caller]
    pub fn value(&self, row: usize) -> T {
        let s = row * T::SIZE;
        T::from_le(&self.raw[s..s + T::SIZE])
    }

    /// Iterator yielding `Option<T>` (None for null rows).
    pub fn iter(&self) -> FixedIter<'_, 'a, T> {
        FixedIter {
            col: self,
            row: 0,
            len: self.len(),
        }
    }
}

pub struct FixedIter<'c, 'a, T: FixedWidth> {
    col: &'c FixedColumn<'a, T>,
    row: usize,
    len: usize,
}

impl<'c, 'a, T: FixedWidth> Iterator for FixedIter<'c, 'a, T> {
    type Item = Option<T>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.row >= self.len {
            return None;
        }
        let r = self.row;
        self.row += 1;
        if self.col.is_null(r) {
            Some(None)
        } else {
            Some(Some(self.col.value(r)))
        }
    }
}

// ---------------------------------------------------------------------------
// Fixed-size byte arrays (UUID, Long256)
// ---------------------------------------------------------------------------

/// Borrowed view over a packed array of fixed-size byte slices.
#[derive(Debug, Clone, Copy)]
pub struct FixedBytesColumn<'a, const N: usize> {
    raw: &'a [u8],
    validity: Validity<'a>,
}

impl<'a, const N: usize> FixedBytesColumn<'a, N> {
    /// `pub(crate)` for the same reason as [`FixedColumn::new`]: the
    /// `raw.len() % N == 0` invariant is `debug_assert!`-only.
    pub(crate) fn new(raw: &'a [u8], validity: Validity<'a>) -> Self {
        debug_assert_eq!(raw.len() % N, 0);
        Self { raw, validity }
    }

    pub fn len(&self) -> usize {
        self.raw.len() / N
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn validity(&self) -> Validity<'a> {
        self.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.validity.is_null(row)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// `&[u8; N]` for the requested row.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`.
    #[inline]
    #[track_caller]
    pub fn value(&self, row: usize) -> &'a [u8; N] {
        let s = row * N;
        (&self.raw[s..s + N])
            .try_into()
            .expect("FixedBytesColumn slice length")
    }
}

pub type UuidColumn<'a> = FixedBytesColumn<'a, 16>;
pub type Long256Column<'a> = FixedBytesColumn<'a, 32>;

// ---------------------------------------------------------------------------
// Symbol column
// ---------------------------------------------------------------------------

/// SYMBOL column: dense per-row `u32` codes plus a borrowed reference to
/// the connection-scoped dictionary.
///
/// The wire encodes codes as a compact varint stream over non-null rows;
/// the decoder densifies that into a `row_count`-sized `u32` slice with
/// `0` in null slots. The validity bitmap is the source of truth for
/// null vs id-zero, so random access is O(1).
#[derive(Debug, Clone, Copy)]
pub struct SymbolColumn<'a> {
    codes: &'a [u32],
    validity: Validity<'a>,
    dict: &'a SymbolDict,
}

impl<'a> SymbolColumn<'a> {
    /// `pub(crate)`: callers must supply `codes` whose entries are all
    /// less than `dict.len()` (decoder-enforced via the post-decode
    /// dict-bounds check). A safe `pub fn` would let external callers
    /// build a column where `resolve()` silently returns `None` for
    /// non-null rows — masking wire corruption as SQL NULL.
    pub(crate) fn new(codes: &'a [u32], validity: Validity<'a>, dict: &'a SymbolDict) -> Self {
        Self {
            codes,
            validity,
            dict,
        }
    }

    pub fn len(&self) -> usize {
        self.codes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.codes.is_empty()
    }

    pub fn validity(&self) -> Validity<'a> {
        self.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.validity.is_null(row)
    }

    /// Dense per-row codes (`0` in null slots — see [`is_null`](Self::is_null)).
    pub fn codes(&self) -> &'a [u32] {
        self.codes
    }

    pub fn dict(&self) -> &'a SymbolDict {
        self.dict
    }

    /// Resolve `row` to its UTF-8 string. `None` for null rows or unknown ids.
    pub fn resolve(&self, row: usize) -> Option<&'a str> {
        if self.is_null(row) {
            return None;
        }
        let code = *self.codes.get(row)?;
        self.dict.get(code)
    }
}

// ---------------------------------------------------------------------------
// Decimal64
// ---------------------------------------------------------------------------

/// DECIMAL64 column: i64 mantissas + a per-batch scale prefix the decoder
/// has already stripped from the data buffer.
#[derive(Debug, Clone, Copy)]
pub struct Decimal64Column<'a> {
    values: FixedColumn<'a, i64>,
    scale: i8,
}

impl<'a> Decimal64Column<'a> {
    /// `pub(crate)`: wraps a `FixedColumn<i64>`; same wire-bytes
    /// invariants apply.
    pub(crate) fn new(raw: &'a [u8], validity: Validity<'a>, scale: i8) -> Self {
        Self {
            values: FixedColumn::new(raw, validity),
            scale,
        }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    pub fn validity(&self) -> Validity<'a> {
        self.values.validity()
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.values.is_null(row)
    }

    pub fn scale(&self) -> i8 {
        self.scale
    }

    pub fn raw(&self) -> &'a [u8] {
        self.values.raw()
    }

    /// Mantissa for `row`. Use `scale()` to interpret the decimal point.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`.
    #[inline]
    #[track_caller]
    pub fn value(&self, row: usize) -> i64 {
        self.values.value(row)
    }
}

// ---------------------------------------------------------------------------
// Variable-length columns (VARCHAR, BINARY)
// ---------------------------------------------------------------------------

/// Per-row offsets into a flat byte buffer.
///
/// `offsets` has `row_count + 1` entries; the bytes for row `i` live at
/// `data[offsets[i]..offsets[i+1]]`. Null rows are represented as
/// zero-length entries (`offsets[i] == offsets[i+1]`); the validity
/// bitmap remains the source of truth for "null vs empty".
///
/// Used internally by [`VarcharColumn`] and [`BinaryColumn`] so they
/// share offset semantics.
#[derive(Debug, Clone, Copy)]
struct VarlenLayout<'a> {
    offsets: &'a [u32],
    data: &'a [u8],
    validity: Validity<'a>,
}

impl<'a> VarlenLayout<'a> {
    fn len(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    fn slice(&self, row: usize) -> Option<&'a [u8]> {
        if self.validity.is_null(row) {
            return None;
        }
        let s = *self.offsets.get(row)? as usize;
        let e = *self.offsets.get(row + 1)? as usize;
        self.data.get(s..e)
    }
}

/// VARCHAR column.
#[derive(Debug, Clone, Copy)]
pub struct VarcharColumn<'a> {
    inner: VarlenLayout<'a>,
}

impl<'a> VarcharColumn<'a> {
    /// Construct from caller-validated buffers.
    ///
    /// # Safety
    ///
    /// The entire `data` byte range, from offset `0` up to the largest
    /// value referenced by `offsets`, must be valid UTF-8 *and* every
    /// `(offsets[i], offsets[i+1])` pair must lie on a UTF-8 character
    /// boundary. [`value`](Self::value) reads each row through
    /// `from_utf8_unchecked` for performance; violating this contract
    /// produces an invalid `&str` and is undefined behavior.
    ///
    /// The decoder upholds this invariant by validating the concatenated
    /// `data` buffer once at decode time and only emitting offsets at
    /// codepoint boundaries.
    pub(crate) unsafe fn new(offsets: &'a [u32], data: &'a [u8], validity: Validity<'a>) -> Self {
        Self {
            inner: VarlenLayout {
                offsets,
                data,
                validity,
            },
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    pub fn validity(&self) -> Validity<'a> {
        self.inner.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.inner.validity.is_null(row)
    }

    pub fn offsets(&self) -> &'a [u32] {
        self.inner.offsets
    }

    pub fn data(&self) -> &'a [u8] {
        self.inner.data
    }

    /// UTF-8 string for `row`. `None` for null rows.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`.
    #[inline]
    #[track_caller]
    pub fn value(&self, row: usize) -> Option<&'a str> {
        let bytes = self.inner.slice(row)?;
        // Safety: `VarcharColumn::new` is an `unsafe fn` whose contract
        // requires `data` to be valid UTF-8 across every offset boundary,
        // so any sub-slice produced by `inner.slice` is also valid UTF-8.
        Some(unsafe { std::str::from_utf8_unchecked(bytes) })
    }
}

/// BINARY column. Same offset/data shape as [`VarcharColumn`] but bytes
/// are opaque.
#[derive(Debug, Clone, Copy)]
pub struct BinaryColumn<'a> {
    inner: VarlenLayout<'a>,
}

impl<'a> BinaryColumn<'a> {
    /// `pub(crate)`: callers must supply monotonically-non-decreasing
    /// `offsets` ending at `data.len()`, with `offsets.len() == row_count + 1`
    /// (or matching the no-null fast path the decoder uses). Out-of-spec
    /// inputs cause `value()` to read garbage or panic.
    pub(crate) fn new(offsets: &'a [u32], data: &'a [u8], validity: Validity<'a>) -> Self {
        Self {
            inner: VarlenLayout {
                offsets,
                data,
                validity,
            },
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    pub fn validity(&self) -> Validity<'a> {
        self.inner.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.inner.validity.is_null(row)
    }

    pub fn offsets(&self) -> &'a [u32] {
        self.inner.offsets
    }

    pub fn data(&self) -> &'a [u8] {
        self.inner.data
    }

    /// Raw bytes for `row`. `None` for null rows.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`.
    #[inline]
    #[track_caller]
    pub fn value(&self, row: usize) -> Option<&'a [u8]> {
        self.inner.slice(row)
    }
}

// ---------------------------------------------------------------------------
// GEOHASH
// ---------------------------------------------------------------------------

/// GEOHASH column.
///
/// Wire carries a column-level `precision_bits` (1..60) and packs each row
/// into `ceil(precision_bits / 8)` little-endian bytes. The decoder
/// densifies into `row_count × byte_width`. Values can be inspected raw or
/// zero-extended to `u64` via [`value`](Self::value).
#[derive(Debug, Clone, Copy)]
pub struct GeohashColumn<'a> {
    raw: &'a [u8],
    byte_width: u8,
    precision_bits: u8,
    validity: Validity<'a>,
}

impl<'a> GeohashColumn<'a> {
    /// `pub(crate)`: the `byte_width` ∈ 1..=8 and `raw.len() % byte_width
    /// == 0` invariants are `debug_assert!`-only.
    pub(crate) fn new(
        raw: &'a [u8],
        byte_width: u8,
        precision_bits: u8,
        validity: Validity<'a>,
    ) -> Self {
        debug_assert!((1..=8).contains(&byte_width));
        debug_assert_eq!(raw.len() % byte_width as usize, 0);
        Self {
            raw,
            byte_width,
            precision_bits,
            validity,
        }
    }

    pub fn precision_bits(&self) -> u8 {
        self.precision_bits
    }

    pub fn byte_width(&self) -> u8 {
        self.byte_width
    }

    pub fn len(&self) -> usize {
        if self.byte_width == 0 {
            0
        } else {
            self.raw.len() / self.byte_width as usize
        }
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn validity(&self) -> Validity<'a> {
        self.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.validity.is_null(row)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Zero-extend the row's `byte_width` LE bytes to a `u64`.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`.
    #[track_caller]
    pub fn value(&self, row: usize) -> u64 {
        let bw = self.byte_width as usize;
        let s = row * bw;
        let mut buf = [0u8; 8];
        buf[..bw].copy_from_slice(&self.raw[s..s + bw]);
        u64::from_le_bytes(buf)
    }
}

// ---------------------------------------------------------------------------
// DECIMAL128 / DECIMAL256
// ---------------------------------------------------------------------------

/// DECIMAL128 column: 16-byte little-endian mantissa per row, single column-
/// level scale.
#[derive(Debug, Clone, Copy)]
pub struct Decimal128Column<'a> {
    raw: &'a [u8],
    scale: i8,
    validity: Validity<'a>,
}

impl<'a> Decimal128Column<'a> {
    /// `pub(crate)`: `raw.len() % 16 == 0` invariant is
    /// `debug_assert!`-only.
    pub(crate) fn new(raw: &'a [u8], validity: Validity<'a>, scale: i8) -> Self {
        debug_assert_eq!(raw.len() % 16, 0);
        Self {
            raw,
            scale,
            validity,
        }
    }

    pub fn len(&self) -> usize {
        self.raw.len() / 16
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn scale(&self) -> i8 {
        self.scale
    }

    pub fn validity(&self) -> Validity<'a> {
        self.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.validity.is_null(row)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Mantissa for `row` as `i128`. Use [`scale`](Self::scale) to
    /// interpret the decimal point.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`.
    #[inline]
    #[track_caller]
    pub fn value(&self, row: usize) -> i128 {
        let s = row * 16;
        i128::from_le_bytes(self.raw[s..s + 16].try_into().expect("16-byte row"))
    }
}

/// DECIMAL256 column: 32-byte mantissa per row, single column-level scale.
///
/// Rust has no native 256-bit integer; the accessor returns the raw 32
/// little-endian bytes and leaves higher-level decoding (e.g. via
/// `bigdecimal`) to the consumer.
#[derive(Debug, Clone, Copy)]
pub struct Decimal256Column<'a> {
    raw: &'a [u8],
    scale: i8,
    validity: Validity<'a>,
}

impl<'a> Decimal256Column<'a> {
    /// `pub(crate)`: `raw.len() % 32 == 0` invariant is
    /// `debug_assert!`-only.
    pub(crate) fn new(raw: &'a [u8], validity: Validity<'a>, scale: i8) -> Self {
        debug_assert_eq!(raw.len() % 32, 0);
        Self {
            raw,
            scale,
            validity,
        }
    }

    pub fn len(&self) -> usize {
        self.raw.len() / 32
    }

    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub fn scale(&self) -> i8 {
        self.scale
    }

    pub fn validity(&self) -> Validity<'a> {
        self.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.validity.is_null(row)
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// Raw 32 LE bytes for `row`. Apply scale via a wider decimal type.
    ///
    /// # Panics
    /// Panics if `row >= self.len()`.
    #[inline]
    #[track_caller]
    pub fn value(&self, row: usize) -> &'a [u8; 32] {
        let s = row * 32;
        (&self.raw[s..s + 32]).try_into().expect("32-byte row")
    }
}

// ---------------------------------------------------------------------------
// DOUBLE_ARRAY / LONG_ARRAY
// ---------------------------------------------------------------------------

/// Borrowed view over per-row shape + flat element bytes for an array
/// column. Each row is independently shaped (n-D); null rows have
/// zero-length shape and zero-length data slices.
///
/// Used internally by [`DoubleArrayColumn`] and [`LongArrayColumn`].
#[derive(Debug, Clone, Copy)]
struct ArrayLayout<'a> {
    /// Byte offsets into `data` per row; length `row_count + 1`.
    data_offsets: &'a [u32],
    /// Concatenated little-endian element bytes for all non-null rows.
    data: &'a [u8],
    /// Concatenated per-row shape entries.
    shapes: &'a [u32],
    /// Offsets into `shapes` per row; length `row_count + 1`.
    shape_offsets: &'a [u32],
    validity: Validity<'a>,
}

impl<'a> ArrayLayout<'a> {
    fn len(&self) -> usize {
        self.data_offsets.len().saturating_sub(1)
    }

    fn shape(&self, row: usize) -> Option<&'a [u32]> {
        if self.validity.is_null(row) {
            return None;
        }
        let s = *self.shape_offsets.get(row)? as usize;
        let e = *self.shape_offsets.get(row + 1)? as usize;
        self.shapes.get(s..e)
    }

    fn raw(&self, row: usize) -> Option<&'a [u8]> {
        if self.validity.is_null(row) {
            return None;
        }
        let s = *self.data_offsets.get(row)? as usize;
        let e = *self.data_offsets.get(row + 1)? as usize;
        self.data.get(s..e)
    }
}

/// `DOUBLE_ARRAY` column: per-row n-D shape and flat little-endian `f64`
/// elements.
#[derive(Debug, Clone, Copy)]
pub struct DoubleArrayColumn<'a> {
    inner: ArrayLayout<'a>,
}

impl<'a> DoubleArrayColumn<'a> {
    /// `pub(crate)`: the four-buffer layout (data_offsets,
    /// shape_offsets, shapes, data) must be internally consistent —
    /// `data_offsets`/`shape_offsets` non-decreasing, terminating at
    /// `data.len()`/`shapes.len()`, and matching the validity bitmap's
    /// row count. Out-of-spec inputs cause `element()` / `shape()` to
    /// return garbage or panic.
    pub(crate) fn new(
        data_offsets: &'a [u32],
        data: &'a [u8],
        shapes: &'a [u32],
        shape_offsets: &'a [u32],
        validity: Validity<'a>,
    ) -> Self {
        Self {
            inner: ArrayLayout {
                data_offsets,
                data,
                shapes,
                shape_offsets,
                validity,
            },
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    pub fn validity(&self) -> Validity<'a> {
        self.inner.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.inner.validity.is_null(row)
    }

    /// Per-row shape (`None` for null rows).
    pub fn shape(&self, row: usize) -> Option<&'a [u32]> {
        self.inner.shape(row)
    }

    /// Flat little-endian element bytes for `row` (`None` for null rows).
    /// Decode each 8-byte chunk as `f64::from_le_bytes`.
    pub fn raw(&self, row: usize) -> Option<&'a [u8]> {
        self.inner.raw(row)
    }

    /// Element count for `row` (product of shape; 0 for null rows).
    pub fn element_count(&self, row: usize) -> usize {
        self.raw(row).map(|b| b.len() / 8).unwrap_or(0)
    }

    /// Decode element at flat index `idx` of `row`. Caller must respect
    /// shape ordering; this is row-major flat indexing.
    pub fn element(&self, row: usize, idx: usize) -> Option<f64> {
        let bytes = self.raw(row)?;
        let s = idx.checked_mul(8)?;
        let chunk = bytes.get(s..s + 8)?;
        Some(f64::from_le_bytes(chunk.try_into().expect("8 bytes")))
    }
}

/// `LONG_ARRAY` column: per-row n-D shape and flat little-endian `i64`
/// elements.
#[derive(Debug, Clone, Copy)]
pub struct LongArrayColumn<'a> {
    inner: ArrayLayout<'a>,
}

impl<'a> LongArrayColumn<'a> {
    /// `pub(crate)`: see [`DoubleArrayColumn::new`] — same four-buffer
    /// invariants apply.
    pub(crate) fn new(
        data_offsets: &'a [u32],
        data: &'a [u8],
        shapes: &'a [u32],
        shape_offsets: &'a [u32],
        validity: Validity<'a>,
    ) -> Self {
        Self {
            inner: ArrayLayout {
                data_offsets,
                data,
                shapes,
                shape_offsets,
                validity,
            },
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }

    pub fn validity(&self) -> Validity<'a> {
        self.inner.validity
    }

    pub fn is_null(&self, row: usize) -> bool {
        self.inner.validity.is_null(row)
    }

    pub fn shape(&self, row: usize) -> Option<&'a [u32]> {
        self.inner.shape(row)
    }

    pub fn raw(&self, row: usize) -> Option<&'a [u8]> {
        self.inner.raw(row)
    }

    pub fn element_count(&self, row: usize) -> usize {
        self.raw(row).map(|b| b.len() / 8).unwrap_or(0)
    }

    pub fn element(&self, row: usize, idx: usize) -> Option<i64> {
        let bytes = self.raw(row)?;
        let s = idx.checked_mul(8)?;
        let chunk = bytes.get(s..s + 8)?;
        Some(i64::from_le_bytes(chunk.try_into().expect("8 bytes")))
    }
}

// ---------------------------------------------------------------------------
// ColumnView discriminated union
// ---------------------------------------------------------------------------

/// Typed view over a single column in a `RESULT_BATCH`.
///
/// Covers every column kind the QWP egress decoder produces today:
/// fixed-width numerics and temporals, UUID, Long256, Char, Symbol,
/// Decimal64/128/256, Geohash, Varchar, Binary, and DOUBLE_ARRAY /
/// LONG_ARRAY.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum ColumnView<'a> {
    Boolean(FixedColumn<'a, u8>),
    Byte(FixedColumn<'a, i8>),
    Short(FixedColumn<'a, i16>),
    Int(FixedColumn<'a, i32>),
    Long(FixedColumn<'a, i64>),
    Float(FixedColumn<'a, f32>),
    Double(FixedColumn<'a, f64>),
    Symbol(SymbolColumn<'a>),
    /// Microsecond-precision timestamp (i64 LE).
    Timestamp(FixedColumn<'a, i64>),
    /// Millisecond-precision date (i64 LE).
    Date(FixedColumn<'a, i64>),
    Uuid(UuidColumn<'a>),
    Long256(Long256Column<'a>),
    /// Nanosecond-precision timestamp (i64 LE).
    TimestampNanos(FixedColumn<'a, i64>),
    Decimal64(Decimal64Column<'a>),
    /// QuestDB CHAR is a 2-byte UTF-16 code unit.
    Char(FixedColumn<'a, u16>),
    /// IPv4 address as a host-order u32 (server emits LE).
    Ipv4(FixedColumn<'a, u32>),
    Varchar(VarcharColumn<'a>),
    Binary(BinaryColumn<'a>),
    Geohash(GeohashColumn<'a>),
    Decimal128(Decimal128Column<'a>),
    Decimal256(Decimal256Column<'a>),
    DoubleArray(DoubleArrayColumn<'a>),
    LongArray(LongArrayColumn<'a>),
}

impl ColumnView<'_> {
    pub fn kind(&self) -> ColumnKind {
        match self {
            ColumnView::Boolean(_) => ColumnKind::Boolean,
            ColumnView::Byte(_) => ColumnKind::Byte,
            ColumnView::Short(_) => ColumnKind::Short,
            ColumnView::Int(_) => ColumnKind::Int,
            ColumnView::Long(_) => ColumnKind::Long,
            ColumnView::Float(_) => ColumnKind::Float,
            ColumnView::Double(_) => ColumnKind::Double,
            ColumnView::Symbol(_) => ColumnKind::Symbol,
            ColumnView::Timestamp(_) => ColumnKind::Timestamp,
            ColumnView::Date(_) => ColumnKind::Date,
            ColumnView::Uuid(_) => ColumnKind::Uuid,
            ColumnView::Long256(_) => ColumnKind::Long256,
            ColumnView::TimestampNanos(_) => ColumnKind::TimestampNanos,
            ColumnView::Decimal64(_) => ColumnKind::Decimal64,
            ColumnView::Char(_) => ColumnKind::Char,
            ColumnView::Ipv4(_) => ColumnKind::Ipv4,
            ColumnView::Varchar(_) => ColumnKind::Varchar,
            ColumnView::Binary(_) => ColumnKind::Binary,
            ColumnView::Geohash(_) => ColumnKind::Geohash,
            ColumnView::Decimal128(_) => ColumnKind::Decimal128,
            ColumnView::Decimal256(_) => ColumnKind::Decimal256,
            ColumnView::DoubleArray(_) => ColumnKind::DoubleArray,
            ColumnView::LongArray(_) => ColumnKind::LongArray,
        }
    }

    pub fn len(&self) -> usize {
        match self {
            ColumnView::Boolean(c) => c.len(),
            ColumnView::Byte(c) => c.len(),
            ColumnView::Short(c) => c.len(),
            ColumnView::Int(c) => c.len(),
            ColumnView::Long(c) => c.len(),
            ColumnView::Float(c) => c.len(),
            ColumnView::Double(c) => c.len(),
            ColumnView::Symbol(c) => c.len(),
            ColumnView::Timestamp(c) => c.len(),
            ColumnView::Date(c) => c.len(),
            ColumnView::Uuid(c) => c.len(),
            ColumnView::Long256(c) => c.len(),
            ColumnView::TimestampNanos(c) => c.len(),
            ColumnView::Decimal64(c) => c.len(),
            ColumnView::Char(c) => c.len(),
            ColumnView::Ipv4(c) => c.len(),
            ColumnView::Varchar(c) => c.len(),
            ColumnView::Binary(c) => c.len(),
            ColumnView::Geohash(c) => c.len(),
            ColumnView::Decimal128(c) => c.len(),
            ColumnView::Decimal256(c) => c.len(),
            ColumnView::DoubleArray(c) => c.len(),
            ColumnView::LongArray(c) => c.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_null(&self, row: usize) -> bool {
        match self {
            ColumnView::Boolean(c) => c.is_null(row),
            ColumnView::Byte(c) => c.is_null(row),
            ColumnView::Short(c) => c.is_null(row),
            ColumnView::Int(c) => c.is_null(row),
            ColumnView::Long(c) => c.is_null(row),
            ColumnView::Float(c) => c.is_null(row),
            ColumnView::Double(c) => c.is_null(row),
            ColumnView::Symbol(c) => c.is_null(row),
            ColumnView::Timestamp(c) => c.is_null(row),
            ColumnView::Date(c) => c.is_null(row),
            ColumnView::Uuid(c) => c.is_null(row),
            ColumnView::Long256(c) => c.is_null(row),
            ColumnView::TimestampNanos(c) => c.is_null(row),
            ColumnView::Decimal64(c) => c.is_null(row),
            ColumnView::Char(c) => c.is_null(row),
            ColumnView::Ipv4(c) => c.is_null(row),
            ColumnView::Varchar(c) => c.is_null(row),
            ColumnView::Binary(c) => c.is_null(row),
            ColumnView::Geohash(c) => c.is_null(row),
            ColumnView::Decimal128(c) => c.is_null(row),
            ColumnView::Decimal256(c) => c.is_null(row),
            ColumnView::DoubleArray(c) => c.is_null(row),
            ColumnView::LongArray(c) => c.is_null(row),
        }
    }

    pub fn validity<'b>(&'b self) -> Validity<'b> {
        match self {
            ColumnView::Boolean(c) => c.validity(),
            ColumnView::Byte(c) => c.validity(),
            ColumnView::Short(c) => c.validity(),
            ColumnView::Int(c) => c.validity(),
            ColumnView::Long(c) => c.validity(),
            ColumnView::Float(c) => c.validity(),
            ColumnView::Double(c) => c.validity(),
            ColumnView::Symbol(c) => c.validity(),
            ColumnView::Timestamp(c) => c.validity(),
            ColumnView::Date(c) => c.validity(),
            ColumnView::Uuid(c) => c.validity(),
            ColumnView::Long256(c) => c.validity(),
            ColumnView::TimestampNanos(c) => c.validity(),
            ColumnView::Decimal64(c) => c.validity(),
            ColumnView::Char(c) => c.validity(),
            ColumnView::Ipv4(c) => c.validity(),
            ColumnView::Varchar(c) => c.validity(),
            ColumnView::Binary(c) => c.validity(),
            ColumnView::Geohash(c) => c.validity(),
            ColumnView::Decimal128(c) => c.validity(),
            ColumnView::Decimal256(c) => c.validity(),
            ColumnView::DoubleArray(c) => c.validity(),
            ColumnView::LongArray(c) => c.validity(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn le_i64s(values: &[i64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(values.len() * 8);
        for v in values {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    fn le_f64s(values: &[f64]) -> Vec<u8> {
        let mut out = Vec::with_capacity(values.len() * 8);
        for v in values {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out
    }

    #[test]
    fn validity_no_bitmap() {
        let v = Validity::None;
        assert!(!v.has_nulls());
        for r in 0..10 {
            assert!(!v.is_null(r));
        }
    }

    #[test]
    fn validity_bitmap_lsb_first_one_is_null() {
        // 8 rows: row0=null, row1=valid, row2=null, row3..7=valid
        // bitmap byte: 0b0000_0101 = 0x05
        let bytes = [0x05];
        let v = Validity::from_bitmap(&bytes, 8).unwrap();
        assert!(v.is_null(0));
        assert!(!v.is_null(1));
        assert!(v.is_null(2));
        for r in 3..8 {
            assert!(!v.is_null(r));
        }
    }

    #[test]
    fn validity_bitmap_spans_bytes() {
        // 10 rows, only row 9 is null → byte 0 = 0, byte 1 = 0b0000_0010 = 0x02
        let bytes = [0x00, 0x02];
        let v = Validity::from_bitmap(&bytes, 10).unwrap();
        for r in 0..9 {
            assert!(!v.is_null(r));
        }
        assert!(v.is_null(9));
    }

    #[test]
    fn validity_bitmap_exact_length_accepted() {
        // The decoder always sizes the bitmap to ceil(row_count / 8).
        // `from_bitmap` must accept exact-length buffers.
        let bytes = [0x00u8; 13]; // ceil(100 / 8) = 13
        let v = Validity::from_bitmap(&bytes, 100).unwrap();
        for r in 0..100 {
            assert!(!v.is_null(r));
        }
    }

    #[test]
    fn validity_bitmap_short_rejected_in_constructor() {
        // 100 rows need ceil(100 / 8) = 13 bytes; supplying 0 must
        // surface InvalidApiCall up front rather than silently treat
        // null rows as non-null.
        let bytes: [u8; 0] = [];
        let err = Validity::from_bitmap(&bytes, 100).unwrap_err();
        assert_eq!(err.code(), crate::egress::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("Validity::from_bitmap: bitmap is"));
    }

    #[test]
    fn validity_bitmap_off_by_one_rejected() {
        // 9 rows need 2 bytes; supplying 1 must surface InvalidApiCall.
        let bytes = [0xFFu8];
        let err = Validity::from_bitmap(&bytes, 9).unwrap_err();
        assert_eq!(err.code(), crate::egress::ErrorCode::InvalidApiCall);
    }

    #[test]
    fn validity_bitmap_direct_construction_short_does_not_panic() {
        // External code that bypasses `from_bitmap` and builds the
        // variant literally with a too-short bitmap is technically
        // outside the type's contract. `is_null` MUST NOT panic for
        // this case; the missing tail is reported as "not null"
        // (matching the pre-validation behavior of `bytes.get(...)`).
        // Properly-constructed `Validity` values can never trip this
        // path because `from_bitmap` rejects short bitmaps up front.
        let bytes: [u8; 0] = [];
        let v = Validity::Bitmap {
            bytes: &bytes,
            row_count: 100,
        };
        assert!(!v.is_null(50));
    }

    #[test]
    fn fixed_i64_value_and_iter() {
        let raw = le_i64s(&[1, -2, 0x0102_0304_0506_0708]);
        let col = FixedColumn::<i64>::new(&raw, Validity::None);
        assert_eq!(col.len(), 3);
        assert_eq!(col.value(0), 1);
        assert_eq!(col.value(1), -2);
        assert_eq!(col.value(2), 0x0102_0304_0506_0708);
        let collected: Vec<_> = col.iter().collect();
        assert_eq!(
            collected,
            vec![Some(1i64), Some(-2), Some(0x0102_0304_0506_0708)]
        );
    }

    #[test]
    fn fixed_f64_with_nulls() {
        let raw = le_f64s(&[1.0, 2.0, 3.0, 4.0]);
        // row 1 null → bitmap 0b0000_0010 = 0x02
        let bm = [0x02];
        let col = FixedColumn::<f64>::new(&raw, Validity::from_bitmap(&bm, 4).unwrap());
        let collected: Vec<_> = col.iter().collect();
        assert_eq!(collected, vec![Some(1.0), None, Some(3.0), Some(4.0)]);
    }

    #[test]
    fn fixed_i32_le() {
        let raw = vec![0x04u8, 0x03, 0x02, 0x01]; // 0x01020304 LE
        let col = FixedColumn::<i32>::new(&raw, Validity::None);
        assert_eq!(col.len(), 1);
        assert_eq!(col.value(0), 0x01020304);
    }

    #[test]
    fn fixed_bool_via_u8() {
        let raw = vec![0x00u8, 0x01, 0x00];
        let col = FixedColumn::<u8>::new(&raw, Validity::None);
        assert_eq!(col.value(0), 0);
        assert_eq!(col.value(1), 1);
    }

    #[test]
    fn uuid_value_returns_array() {
        let raw: Vec<u8> = (0..32u8).collect();
        let col = UuidColumn::new(&raw, Validity::None);
        assert_eq!(col.len(), 2);
        assert_eq!(col.value(0)[0], 0);
        assert_eq!(col.value(0)[15], 15);
        assert_eq!(col.value(1)[0], 16);
        assert_eq!(col.value(1)[15], 31);
    }

    #[test]
    fn long256_value_returns_32_bytes() {
        let raw: Vec<u8> = (0..32u8).collect();
        let col = Long256Column::new(&raw, Validity::None);
        assert_eq!(col.len(), 1);
        assert_eq!(col.value(0).len(), 32);
        assert_eq!(col.value(0)[31], 31);
    }

    #[test]
    fn symbol_resolves_codes_through_dict() {
        let mut dict = SymbolDict::new();
        dict.apply_delta(
            0,
            [b"AAPL".as_slice(), b"MSFT".as_slice(), b"GOOG".as_slice()],
        )
        .unwrap();

        // 4 rows: AAPL, NULL, MSFT, GOOG. Bitmap row1 null → 0b0000_0010 = 0x02
        // Codes are dense per row, with `0` (garbage) in the null slot.
        let codes = [0u32, 0, 1, 2];
        let bm = [0x02u8];
        let col = SymbolColumn::new(&codes, Validity::from_bitmap(&bm, 4).unwrap(), &dict);

        assert_eq!(col.len(), 4);
        assert_eq!(col.resolve(0), Some("AAPL"));
        assert_eq!(col.resolve(1), None);
        assert_eq!(col.resolve(2), Some("MSFT"));
        assert_eq!(col.resolve(3), Some("GOOG"));
    }

    #[test]
    fn symbol_no_nulls_path() {
        let mut dict = SymbolDict::new();
        dict.apply_delta(0, [b"x".as_slice(), b"y".as_slice()])
            .unwrap();
        let codes = [1u32, 0, 1];
        let col = SymbolColumn::new(&codes, Validity::None, &dict);
        assert_eq!(col.resolve(0), Some("y"));
        assert_eq!(col.resolve(1), Some("x"));
        assert_eq!(col.resolve(2), Some("y"));
    }

    #[test]
    fn decimal64_carries_scale() {
        let raw = le_i64s(&[12345, 6789]);
        let col = Decimal64Column::new(&raw, Validity::None, 2);
        assert_eq!(col.scale(), 2);
        assert_eq!(col.value(0), 12345);
        assert_eq!(col.value(1), 6789);
    }

    #[test]
    fn column_view_kind_matches_inner() {
        let raw = le_i64s(&[1, 2]);
        let v = ColumnView::Long(FixedColumn::<i64>::new(&raw, Validity::None));
        assert_eq!(v.kind(), ColumnKind::Long);
        assert_eq!(v.len(), 2);

        let v = ColumnView::TimestampNanos(FixedColumn::<i64>::new(&raw, Validity::None));
        assert_eq!(v.kind(), ColumnKind::TimestampNanos);

        let v = ColumnView::Decimal64(Decimal64Column::new(&raw, Validity::None, 4));
        assert_eq!(v.kind(), ColumnKind::Decimal64);
    }

    #[test]
    fn column_view_is_null_dispatches() {
        let raw = le_i64s(&[1, 2, 3]);
        let bm = [0x02u8]; // row 1 null
        let v = ColumnView::Long(FixedColumn::<i64>::new(
            &raw,
            Validity::from_bitmap(&bm, 3).unwrap(),
        ));
        assert!(!v.is_null(0));
        assert!(v.is_null(1));
        assert!(!v.is_null(2));
    }
}
