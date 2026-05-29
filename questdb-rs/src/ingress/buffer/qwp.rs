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

// Shared QWP encoding primitives — used by qwp-udp's flat
// row-encoding path and by qwp-ws's columnar buffer. When only
// qwp-ws is enabled, the udp-only helpers naturally go dead.
// Suppress only in that exact configuration so future drift on a
// build that DOES enable qwp-udp still surfaces.
#![cfg_attr(not(feature = "_sender-qwp-udp"), allow(dead_code))]

use crate::Error;
#[cfg(test)]
use crate::ErrorCode;
use crate::error;
use crate::ingress::decimal::DecimalView;
use crate::ingress::ndarr::{self, ArrayElementSealed};
use crate::ingress::{ArrayElement, MAX_ARRAY_DIMS, NdArrayView, Timestamp};
use std::collections::hash_map::RandomState;
use std::fmt::Debug;
#[cfg(feature = "_sender-qwp-ws")]
use std::hash::BuildHasherDefault;
use std::hash::{BuildHasher, Hash, Hasher};

use super::op_state::{Op, OpState};
use super::{Bookmark, BufferBookmarkMeta, ColumnName, StoredBookmark, TableName};
#[cfg(feature = "arrow")]
use arrow_buffer::NullBuffer;

/// Wire layout of a QWP datagram header.
///
/// ```text
/// [0..4]   magic        "QWP1"
/// [4]      version      protocol version (currently 1)
/// [5]      flags        reserved
/// [6..8]   table_count  little-endian u16
/// [8..12]  payload_len  little-endian u32
/// ```
#[repr(C, packed)]
pub(crate) struct QwpMessageHeader {
    pub(crate) magic: [u8; 4],
    pub(crate) version: u8,
    pub(crate) flags: u8,
    pub(crate) table_count: u16,
    pub(crate) payload_len: u32,
}

impl QwpMessageHeader {
    /// Serialize the header into the first [`QWP_MESSAGE_HEADER_SIZE`] bytes of `out`.
    fn write_to(&self, out: &mut [u8]) {
        out[..4].copy_from_slice(&self.magic);
        out[4] = self.version;
        out[5] = self.flags;
        out[6..8].copy_from_slice(&self.table_count.to_le_bytes());
        out[8..12].copy_from_slice(&self.payload_len.to_le_bytes());
    }
}

pub(crate) const QWP_MESSAGE_HEADER_SIZE: usize = std::mem::size_of::<QwpMessageHeader>();

// Compile-time guarantee that the header is exactly 12 bytes.
const _: () = assert!(QWP_MESSAGE_HEADER_SIZE == 12);
const _: () = assert!(MAX_ARRAY_DIMS <= u8::MAX as usize);

pub(crate) const QWP_SCHEMA_MODE_FULL: u8 = 0x00;
#[cfg(all(test, feature = "_sender-qwp-ws"))]
pub(crate) const QWP_SCHEMA_MODE_REFERENCE: u8 = 0x01;
pub(crate) const QWP_TYPE_BOOLEAN: u8 = 0x01;
pub(crate) const QWP_TYPE_BYTE: u8 = 0x02;
pub(crate) const QWP_TYPE_SHORT: u8 = 0x03;
pub(crate) const QWP_TYPE_INT: u8 = 0x04;
pub(crate) const QWP_TYPE_LONG: u8 = 0x05;
pub(crate) const QWP_TYPE_FLOAT: u8 = 0x06;
pub(crate) const QWP_TYPE_DOUBLE: u8 = 0x07;
pub(crate) const QWP_TYPE_SYMBOL: u8 = 0x09;
pub(crate) const QWP_TYPE_TIMESTAMP: u8 = 0x0A;
pub(crate) const QWP_TYPE_DATE: u8 = 0x0B;
pub(crate) const QWP_TYPE_UUID: u8 = 0x0C;
pub(crate) const QWP_TYPE_LONG256: u8 = 0x0D;
pub(crate) const QWP_TYPE_GEOHASH: u8 = 0x0E;
pub(crate) const QWP_TYPE_VARCHAR: u8 = 0x0F;
pub(crate) const QWP_TYPE_TIMESTAMP_NANOS: u8 = 0x10;
pub(crate) const QWP_TYPE_DOUBLE_ARRAY: u8 = 0x11;
pub(crate) const QWP_TYPE_LONG_ARRAY: u8 = 0x12;
pub(crate) const QWP_TYPE_DECIMAL64: u8 = 0x13;
pub(crate) const QWP_TYPE_DECIMAL128: u8 = 0x14;
pub(crate) const QWP_TYPE_DECIMAL256: u8 = 0x15;
pub(crate) const QWP_TYPE_CHAR: u8 = 0x16;
pub(crate) const QWP_TYPE_BINARY: u8 = 0x17;
pub(crate) const QWP_TYPE_IPV4: u8 = 0x18;
const QWP_LONG256_BYTES: usize = 32;
pub(crate) const QWP_VERSION_1: u8 = 1;
const QWP_INLINE_SCHEMA_ID: u64 = 0;
const QWP_DECIMAL_MAX_SCALE: u8 = 76;
const QWP_DECIMAL_SCALE_UNSET: u8 = u8::MAX;
const QWP_DECIMAL_MAG_LIMBS: usize = 4;
const QWP_DECIMAL_MAG_BYTES: usize = QWP_DECIMAL_MAG_LIMBS * 8;
const QWP_DECIMAL_SIGN_BIT: u64 = 1u64 << 63;

fn checked_qwp_u32(value: usize, what: &'static str) -> crate::Result<u32> {
    if value > u32::MAX as usize {
        return Err(error::fmt!(
            InvalidApiCall,
            "QWP/UDP {} exceeds maximum of {}",
            what,
            u32::MAX
        ));
    }
    Ok(value as u32)
}

fn checked_qwp_push_index(len: usize, what: &'static str) -> crate::Result<u32> {
    if len >= u32::MAX as usize {
        return Err(error::fmt!(
            InvalidApiCall,
            "QWP/UDP {} exceeds maximum of {}",
            what,
            u32::MAX
        ));
    }
    Ok(len as u32)
}

fn checked_qwp_usize_add(
    current: usize,
    additional: usize,
    what: &'static str,
) -> crate::Result<usize> {
    current.checked_add(additional).ok_or_else(|| {
        error::fmt!(
            InvalidApiCall,
            "QWP/UDP {} exceeds maximum of {}",
            what,
            usize::MAX
        )
    })
}

fn checked_qwp_usize_mul(a: usize, b: usize, what: &'static str) -> crate::Result<usize> {
    a.checked_mul(b).ok_or_else(|| {
        error::fmt!(
            InvalidApiCall,
            "QWP/UDP {} exceeds maximum of {}",
            what,
            usize::MAX
        )
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StoredQwpDecimal {
    scale: u8,
    negative: bool,
    magnitude: [u64; QWP_DECIMAL_MAG_LIMBS],
}

impl StoredQwpDecimal {
    fn from_decimal_view(value: DecimalView<'_>) -> crate::Result<Option<Self>> {
        match value {
            DecimalView::String { value } => parse_decimal_text(value),
            DecimalView::Scaled { scale, value } => {
                if scale > QWP_DECIMAL_MAX_SCALE {
                    return Err(invalid_decimal_error(format!(
                        "QuestDB decimal scale cannot exceed {}, got {}",
                        QWP_DECIMAL_MAX_SCALE, scale
                    )));
                }
                let (magnitude, negative) = sign_mag_from_signed_be(value.as_ref())?;
                Ok(Some(Self {
                    scale,
                    negative,
                    magnitude,
                }))
            }
        }
    }

    fn wire_bytes_with_scale(
        &self,
        target_scale: u8,
    ) -> crate::Result<[u8; QWP_DECIMAL_MAG_BYTES]> {
        if target_scale < self.scale {
            return Err(error::fmt!(
                InvalidApiCall,
                "cannot rescale decimal from scale {} to {} without precision loss",
                self.scale,
                target_scale
            ));
        }

        let mut magnitude = self.magnitude;
        for _ in 0..u32::from(target_scale - self.scale) {
            mul_mag_small(
                &mut magnitude,
                10,
                "QWP decimal rescale exceeds DECIMAL256 range",
            )?;
        }
        let signed_range_err = if target_scale == self.scale {
            "QWP decimal value exceeds signed DECIMAL256 range"
        } else {
            "QWP decimal rescale exceeds signed DECIMAL256 range"
        };
        sign_mag_to_twos_le_bytes(
            self.negative && !mag_is_zero(&magnitude),
            &magnitude,
            signed_range_err,
        )
    }

    fn write_magnitude_to(&self, out: &mut Vec<u8>) {
        for limb in self.magnitude {
            out.extend_from_slice(&limb.to_le_bytes());
        }
    }
}

fn invalid_decimal_error(msg: impl Into<String>) -> crate::Error {
    error::fmt!(InvalidDecimal, "{}", msg.into())
}

fn mag_is_zero(magnitude: &[u64; QWP_DECIMAL_MAG_LIMBS]) -> bool {
    magnitude.iter().all(|&limb| limb == 0)
}

fn add_mag_small(
    magnitude: &mut [u64; QWP_DECIMAL_MAG_LIMBS],
    addend: u32,
    err_msg: &'static str,
) -> crate::Result<()> {
    let mut carry = u128::from(addend);
    for limb in magnitude.iter_mut() {
        let sum = u128::from(*limb) + carry;
        *limb = sum as u64;
        carry = sum >> 64;
        if carry == 0 {
            return Ok(());
        }
    }
    Err(invalid_decimal_error(err_msg))
}

fn mul_mag_small(
    magnitude: &mut [u64; QWP_DECIMAL_MAG_LIMBS],
    factor: u32,
    err_msg: &'static str,
) -> crate::Result<()> {
    let mut carry = 0u128;
    for limb in magnitude.iter_mut() {
        let product = u128::from(*limb) * u128::from(factor) + carry;
        *limb = product as u64;
        carry = product >> 64;
    }
    if carry != 0 {
        return Err(invalid_decimal_error(err_msg));
    }
    Ok(())
}

fn negate_twos_complement_be(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        *byte = !*byte;
    }
    let mut carry = 1u16;
    for byte in bytes.iter_mut().rev() {
        let sum = u16::from(*byte) + carry;
        *byte = sum as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
}

fn sign_mag_from_signed_be(bytes: &[u8]) -> crate::Result<([u64; QWP_DECIMAL_MAG_LIMBS], bool)> {
    if bytes.len() > QWP_DECIMAL_MAG_BYTES {
        return Err(invalid_decimal_error(format!(
            "QWP/UDP decimal mantissa exceeds {} bytes",
            QWP_DECIMAL_MAG_BYTES
        )));
    }
    if bytes.is_empty() {
        return Ok(([0; QWP_DECIMAL_MAG_LIMBS], false));
    }

    let negative = bytes[0] & 0x80 != 0;
    let mut extended = [if negative { 0xFF } else { 0x00 }; QWP_DECIMAL_MAG_BYTES];
    extended[QWP_DECIMAL_MAG_BYTES - bytes.len()..].copy_from_slice(bytes);
    if negative {
        negate_twos_complement_be(&mut extended);
    }

    let mut magnitude = [0u64; QWP_DECIMAL_MAG_LIMBS];
    for (idx, limb) in magnitude.iter_mut().enumerate() {
        let start = QWP_DECIMAL_MAG_BYTES - (idx + 1) * 8;
        let end = start + 8;
        let raw: [u8; 8] = extended[start..end]
            .try_into()
            .expect("fixed-width decimal slice");
        *limb = u64::from_be_bytes(raw);
    }
    let negative = negative && !mag_is_zero(&magnitude);
    Ok((magnitude, negative))
}

fn sign_mag_to_twos_le_bytes(
    negative: bool,
    magnitude: &[u64; QWP_DECIMAL_MAG_LIMBS],
    err_msg: &'static str,
) -> crate::Result<[u8; QWP_DECIMAL_MAG_BYTES]> {
    ensure_signed_decimal256_fits(negative, magnitude, err_msg)?;
    let mut out = [0u8; QWP_DECIMAL_MAG_BYTES];
    for (idx, limb) in magnitude.iter().enumerate() {
        let start = idx * 8;
        out[start..start + 8].copy_from_slice(&limb.to_le_bytes());
    }
    if negative && !mag_is_zero(magnitude) {
        for byte in &mut out {
            *byte = !*byte;
        }
        let mut carry = 1u16;
        for byte in &mut out {
            let sum = u16::from(*byte) + carry;
            *byte = sum as u8;
            carry = sum >> 8;
            if carry == 0 {
                break;
            }
        }
    }
    Ok(out)
}

fn ensure_signed_decimal256_fits(
    negative: bool,
    magnitude: &[u64; QWP_DECIMAL_MAG_LIMBS],
    err_msg: &'static str,
) -> crate::Result<()> {
    let high = magnitude[QWP_DECIMAL_MAG_LIMBS - 1];
    let lower_non_zero = magnitude[..QWP_DECIMAL_MAG_LIMBS - 1]
        .iter()
        .any(|&limb| limb != 0);

    let fits = if negative {
        high < QWP_DECIMAL_SIGN_BIT || (high == QWP_DECIMAL_SIGN_BIT && !lower_non_zero)
    } else {
        high < QWP_DECIMAL_SIGN_BIT
    };

    if fits {
        Ok(())
    } else {
        Err(invalid_decimal_error(err_msg))
    }
}

fn parse_decimal_text(value: &str) -> crate::Result<Option<StoredQwpDecimal>> {
    if value.is_empty() {
        return Err(invalid_decimal_error("empty decimal value"));
    }

    let (negative, body) = match value.as_bytes()[0] {
        b'+' => (false, &value[1..]),
        b'-' => (true, &value[1..]),
        _ => (false, value),
    };
    if body.eq_ignore_ascii_case("nan") || body.eq_ignore_ascii_case("infinity") {
        return Ok(None);
    }
    if body.is_empty() {
        return Err(invalid_decimal_error("missing decimal digits"));
    }

    let mut magnitude = [0u64; QWP_DECIMAL_MAG_LIMBS];
    let mut seen_digit = false;
    let mut seen_point = false;
    let mut seen_exp = false;
    let mut seen_exp_sign = false;
    let mut seen_exp_digit = false;
    let mut exp_negative = false;
    let mut frac_digits = 0u32;
    let mut exponent = 0u32;

    for byte in body.bytes() {
        match byte {
            b'0'..=b'9' if !seen_exp => {
                seen_digit = true;
                mul_mag_small(
                    &mut magnitude,
                    10,
                    "QWP/UDP decimal value exceeds DECIMAL256 range",
                )?;
                add_mag_small(
                    &mut magnitude,
                    u32::from(byte - b'0'),
                    "QWP/UDP decimal value exceeds DECIMAL256 range",
                )?;
                if seen_point {
                    frac_digits = frac_digits.checked_add(1).ok_or_else(|| {
                        invalid_decimal_error("decimal scale exceeds supported range")
                    })?;
                }
            }
            b'0'..=b'9' => {
                seen_exp_digit = true;
                exponent = exponent
                    .checked_mul(10)
                    .and_then(|value| value.checked_add(u32::from(byte - b'0')))
                    .ok_or_else(|| invalid_decimal_error("decimal exponent is too large"))?;
            }
            b'.' if !seen_point && !seen_exp => seen_point = true,
            b'e' | b'E' if !seen_exp && seen_digit => seen_exp = true,
            b'+' | b'-' if seen_exp && !seen_exp_sign && !seen_exp_digit => {
                seen_exp_sign = true;
                exp_negative = byte == b'-';
            }
            _ => {
                return Err(invalid_decimal_error(format!(
                    "invalid decimal value {:?}",
                    value
                )));
            }
        }
    }

    if !seen_digit {
        return Err(invalid_decimal_error(format!(
            "invalid decimal value {:?}",
            value
        )));
    }
    if seen_exp && !seen_exp_digit {
        return Err(invalid_decimal_error(format!(
            "invalid decimal exponent in {:?}",
            value
        )));
    }

    let exponent = if exp_negative {
        -(i64::from(exponent))
    } else {
        i64::from(exponent)
    };
    let mut scale = i64::from(frac_digits) - exponent;
    if scale < 0 {
        let delta = (-scale) as u32;
        if mag_is_zero(&magnitude) {
            scale = 0;
        } else {
            // `10^77` still fits in 256 unsigned bits, so allow that much
            // multiplication here and rely on the final signed DECIMAL256
            // range check during wire encoding.
            if delta > 77 {
                return Err(invalid_decimal_error(
                    "QWP/UDP decimal rescale exceeds DECIMAL256 range",
                ));
            }
            for _ in 0..delta {
                mul_mag_small(
                    &mut magnitude,
                    10,
                    "QWP/UDP decimal rescale exceeds DECIMAL256 range",
                )?;
            }
            scale = 0;
        }
    }
    if scale > i64::from(QWP_DECIMAL_MAX_SCALE) {
        return Err(invalid_decimal_error(format!(
            "QuestDB decimal scale cannot exceed {}, got {}",
            QWP_DECIMAL_MAX_SCALE, scale
        )));
    }

    Ok(Some(StoredQwpDecimal {
        scale: scale as u8,
        negative: negative && !mag_is_zero(&magnitude),
        magnitude,
    }))
}

// --- Arena slice types ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ByteSlice {
    offset: u32,
    len: u32,
}

impl ByteSlice {
    fn as_range(&self) -> std::ops::Range<usize> {
        self.offset as usize..(self.offset as usize + self.len as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NameSlice(ByteSlice);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ValueSlice(ByteSlice);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DecimalValue {
    magnitude: ValueSlice,
    scale: u8,
    negative: bool,
}

impl DecimalValue {
    fn load_magnitude(self, value_bytes: &[u8]) -> crate::Result<[u64; QWP_DECIMAL_MAG_LIMBS]> {
        let bytes = &value_bytes[self.magnitude.0.as_range()];
        if bytes.len() != QWP_DECIMAL_MAG_BYTES {
            return Err(error::fmt!(
                InvalidApiCall,
                "internal QWP decimal magnitude length mismatch: expected {}, got {}",
                QWP_DECIMAL_MAG_BYTES,
                bytes.len()
            ));
        }

        let mut magnitude = [0u64; QWP_DECIMAL_MAG_LIMBS];
        for (idx, limb) in magnitude.iter_mut().enumerate() {
            let start = idx * 8;
            let end = start + 8;
            let raw: [u8; 8] = bytes[start..end]
                .try_into()
                .expect("slice length is validated above");
            *limb = u64::from_le_bytes(raw);
        }
        Ok(magnitude)
    }

    fn wire_bytes_with_scale(
        self,
        value_bytes: &[u8],
        target_scale: u8,
    ) -> crate::Result<[u8; QWP_DECIMAL_MAG_BYTES]> {
        StoredQwpDecimal {
            scale: self.scale,
            negative: self.negative,
            magnitude: self.load_magnitude(value_bytes)?,
        }
        .wire_bytes_with_scale(target_scale)
    }
}

// --- Column kind ---

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ColumnKind {
    Bool,
    Symbol,
    I8,
    I16,
    I32,
    I64,
    F32,
    F64,
    String,
    Decimal64,
    Decimal128,
    Decimal,
    DoubleArray,
    TimestampMicros,
    TimestampNanos,
    Uuid,
    Long256,
    Ipv4,
    Date,
    Char,
    Binary,
    Geohash,
    LongArray,
}

// --- Designated timestamp ---

#[derive(Clone, Copy, Debug)]
enum DesignatedTs {
    Micros(i64),
    Nanos(i64),
}

// --- Value reference into arenas ---

#[derive(Clone, Copy, Debug)]
enum ValueRef {
    Bool(bool),
    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    F32(f32),
    F64(f64),
    TimestampMicros(i64),
    TimestampNanos(i64),
    Symbol(ValueSlice),
    String(ValueSlice),
    DecimalNull,
    Decimal(DecimalValue),
    Decimal64Null,
    Decimal64(DecimalValue),
    Decimal128Null,
    Decimal128(DecimalValue),
    DoubleArray(ValueSlice),
    Uuid(ValueSlice),
    Long256(ValueSlice),
    Ipv4(u32),
    DateMillis(i64),
    Char(u16),
    Binary(ValueSlice),
    Geohash { bits: u64, precision_bits: u8 },
    LongArray(ValueSlice),
}

impl ValueRef {
    fn kind(&self) -> ColumnKind {
        match self {
            ValueRef::Bool(_) => ColumnKind::Bool,
            ValueRef::I8(_) => ColumnKind::I8,
            ValueRef::I16(_) => ColumnKind::I16,
            ValueRef::I32(_) => ColumnKind::I32,
            ValueRef::I64(_) => ColumnKind::I64,
            ValueRef::F32(_) => ColumnKind::F32,
            ValueRef::F64(_) => ColumnKind::F64,
            ValueRef::TimestampMicros(_) => ColumnKind::TimestampMicros,
            ValueRef::TimestampNanos(_) => ColumnKind::TimestampNanos,
            ValueRef::Symbol(_) => ColumnKind::Symbol,
            ValueRef::String(_) => ColumnKind::String,
            ValueRef::DecimalNull | ValueRef::Decimal(_) => ColumnKind::Decimal,
            ValueRef::Decimal64Null | ValueRef::Decimal64(_) => ColumnKind::Decimal64,
            ValueRef::Decimal128Null | ValueRef::Decimal128(_) => ColumnKind::Decimal128,
            ValueRef::DoubleArray(_) => ColumnKind::DoubleArray,
            ValueRef::Uuid(_) => ColumnKind::Uuid,
            ValueRef::Long256(_) => ColumnKind::Long256,
            ValueRef::Ipv4(_) => ColumnKind::Ipv4,
            ValueRef::DateMillis(_) => ColumnKind::Date,
            ValueRef::Char(_) => ColumnKind::Char,
            ValueRef::Binary(_) => ColumnKind::Binary,
            ValueRef::Geohash { .. } => ColumnKind::Geohash,
            ValueRef::LongArray(_) => ColumnKind::LongArray,
        }
    }
}

// --- Cell reference (planner scratch) ---

const CELL_END: u32 = u32::MAX;

#[derive(Clone, Copy, Debug)]
struct CellRef {
    row_idx: u32,
    /// Pre-computed symbol dictionary index; unused for non-symbol columns.
    symbol_dict_idx: u32,
    next: u32,
    value: ValueRef,
}

// --- Row and entry metadata ---

#[derive(Clone, Copy, Debug)]
struct RowMeta {
    table: NameSlice,
    entry_start: u32,
    entry_count: u32,
    designated_ts: Option<DesignatedTs>,
}

#[derive(Clone, Copy, Debug)]
struct EntryMeta {
    name: NameSlice,
    value: ValueRef,
}

// --- Segment metadata ---

#[derive(Clone, Copy, Debug)]
struct SegmentMeta {
    table: NameSlice,
    row_start: u32,
    row_count: u32,
}

// --- Pending row state ---

#[derive(Clone, Copy, Debug)]
struct PendingRowState {
    table: Option<NameSlice>,
    entry_start: u32,
    name_bytes_start: u32,
    value_bytes_start: u32,
    saved_state: BufferState,
}

impl PendingRowState {
    fn empty() -> Self {
        Self {
            table: None,
            entry_start: 0,
            name_bytes_start: 0,
            value_bytes_start: 0,
            saved_state: BufferState::new(),
        }
    }
}

// --- Buffer state ---

#[derive(Clone, Copy, Debug)]
struct BufferState {
    op_state: OpState,
    row_count: usize,
}

impl BufferState {
    fn new() -> Self {
        Self {
            op_state: OpState::new(),
            row_count: 0,
        }
    }
}

// --- Size hint ---

#[derive(Clone, Debug)]
struct QwpSizeHint {
    committed_len: usize,
    planner: RowGroupPlanner,
    scratch: RowGroupPlanner,
    group_table: Option<NameSlice>,
    completed: Vec<RowGroupPlanner>,
    completed_count: usize,
}

impl QwpSizeHint {
    fn new() -> Self {
        Self {
            committed_len: 0,
            planner: RowGroupPlanner::new(),
            scratch: RowGroupPlanner::new(),
            group_table: None,
            completed: Vec::new(),
            completed_count: 0,
        }
    }

    fn clear(&mut self) {
        self.committed_len = 0;
        self.planner.clear();
        for p in &mut self.completed[..self.completed_count] {
            p.clear();
        }
        // Ensure scratch retains capacity for the next cycle by swapping
        // with a planner that was used (and thus has capacity). Without
        // this, scratch can be left zero-capacity after a pool-growth
        // cycle and would allocate on first use in the next cycle.
        if self.completed_count > 0 {
            std::mem::swap(
                &mut self.scratch,
                &mut self.completed[self.completed_count - 1],
            );
        } else {
            std::mem::swap(&mut self.scratch, &mut self.planner);
        }
        self.scratch.clear();
        self.completed_count = 0;
        self.group_table = None;
    }

    fn reserve(&mut self, additional: usize, max_segments: usize) {
        self.planner.reserve_for_encoded_bytes(additional);
        self.scratch.reserve_for_encoded_bytes(additional);
        self.completed.reserve(max_segments);
    }

    fn len(&self) -> usize {
        self.committed_len
    }

    fn segment_planner(&self, seg_idx: usize) -> crate::Result<&RowGroupPlanner> {
        if seg_idx < self.completed_count {
            Ok(&self.completed[seg_idx])
        } else if seg_idx == self.completed_count {
            Ok(&self.planner)
        } else {
            Err(error::fmt!(
                InvalidApiCall,
                "internal error: missing cached planner for segment {}",
                seg_idx
            ))
        }
    }

    fn add_committed_row(
        &mut self,
        row: &RowMeta,
        entries: &[EntryMeta],
        name_bytes: &[u8],
        value_bytes: &[u8],
        last_segment_table: Option<NameSlice>,
    ) -> crate::Result<()> {
        let table_name = &name_bytes[row.table.0.as_range()];
        let same_group = if let Some(group_table) = self.group_table {
            if let Some(seg_table) = last_segment_table {
                &name_bytes[group_table.0.as_range()] == table_name
                    && &name_bytes[seg_table.0.as_range()] == table_name
            } else {
                false
            }
        } else {
            false
        };

        let row_entries =
            &entries[row.entry_start as usize..(row.entry_start + row.entry_count) as usize];

        if same_group {
            let previous_len = self.planner.current_len;
            let cp = self.planner.checkpoint();
            if let Err(err) =
                self.planner
                    .add_row(row, row_entries, name_bytes, value_bytes, table_name.len())
            {
                self.planner.rollback(cp);
                return Err(err);
            }
            let new_len = self.planner.current_len;
            self.committed_len = self.committed_len - previous_len + new_len;
            return Ok(());
        }

        self.scratch.clear();
        self.scratch
            .add_row(row, row_entries, name_bytes, value_bytes, table_name.len())?;
        self.committed_len += self.scratch.current_len;

        if self.group_table.is_some() {
            if self.completed_count < self.completed.len() {
                std::mem::swap(&mut self.planner, &mut self.completed[self.completed_count]);
            } else {
                let saved = std::mem::replace(&mut self.planner, RowGroupPlanner::new());
                self.completed.push(saved);
            }
            self.completed_count += 1;
            std::mem::swap(&mut self.planner, &mut self.scratch);
        } else {
            std::mem::swap(&mut self.planner, &mut self.scratch);
        }
        self.group_table = Some(row.table);
        Ok(())
    }
}

// --- Stored rewind state ---
// We intentionally avoid snapshotting QwpSizeHint here because that would clone
// planner Vecs on every capture. Instead we store only scalar arena lengths and
// recompute the size hint from committed rows on rewind. The O(rows) replay
// cost is acceptable because rewind is not a steady-state hot path.

#[derive(Clone, Copy, Debug)]
struct QwpMarker {
    rows_len: u32,
    entries_len: u32,
    segments_len: u32,
    tail_segment_row_count: Option<u32>,
    name_bytes_len: u32,
    value_bytes_len: u32,
    state: BufferState,
}

// --- QwpBuffer ---

#[derive(Debug)]
pub(crate) struct QwpBuffer {
    name_bytes: Vec<u8>,
    value_bytes: Vec<u8>,
    rows: Vec<RowMeta>,
    entries: Vec<EntryMeta>,
    segments: Vec<SegmentMeta>,
    pending: PendingRowState,
    state: BufferState,
    size_hint: QwpSizeHint,
    bookmark_meta: BufferBookmarkMeta,
    bookmark: StoredBookmark<QwpMarker>,
    max_name_len: usize,
}

impl Clone for QwpBuffer {
    fn clone(&self) -> Self {
        // Copy only live data, not spare capacity
        let name_bytes = self.name_bytes[..].to_vec();
        let value_bytes = self.value_bytes[..].to_vec();
        let rows = self.rows[..].to_vec();
        let entries = self.entries[..].to_vec();
        let segments = self.segments[..].to_vec();
        Self {
            name_bytes,
            value_bytes,
            rows,
            entries,
            segments,
            pending: self.pending,
            state: self.state,
            size_hint: self.size_hint.clone(),
            // Preserve the stored rewind payload so marker-based rewind on the
            // clone matches historical behavior, but assign a fresh origin so
            // explicit bookmarks from the source buffer still fail on the
            // clone.
            bookmark_meta: BufferBookmarkMeta::new(),
            bookmark: self.bookmark,
            max_name_len: self.max_name_len,
        }
    }
}

impl QwpBuffer {
    pub(crate) fn new(max_name_len: usize) -> Self {
        Self {
            name_bytes: Vec::new(),
            value_bytes: Vec::new(),
            rows: Vec::new(),
            entries: Vec::new(),
            segments: Vec::new(),
            pending: PendingRowState::empty(),
            state: BufferState::new(),
            size_hint: QwpSizeHint::new(),
            bookmark_meta: BufferBookmarkMeta::new(),
            bookmark: StoredBookmark::new(),
            max_name_len,
        }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        // Heuristic prewarm: use the minimum encoded schema contribution per
        // entry (~3 bytes) to size the primary arenas and active planners.
        // Dense shapes such as packed booleans can still outgrow this initial
        // estimate and rely on first-use warmup to settle at steady-state
        // capacity.
        let max_entries = additional / 3;
        let max_rows = max_entries;
        let max_segments = (max_rows / 4).max(1);
        self.name_bytes.reserve(additional);
        self.value_bytes.reserve(additional);
        self.rows.reserve(max_rows.max(1));
        self.entries.reserve(max_entries.max(1));
        self.segments.reserve(max_segments);
        self.size_hint.reserve(additional, max_segments);
    }

    pub(crate) fn len(&self) -> usize {
        self.size_hint.len() + self.pending_size_hint()
    }

    pub(crate) fn row_count(&self) -> usize {
        self.state.row_count
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pending.table.is_none() && self.rows.is_empty()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.name_bytes.capacity()
            + self.value_bytes.capacity()
            + self.rows.capacity() * std::mem::size_of::<RowMeta>()
            + self.entries.capacity() * std::mem::size_of::<EntryMeta>()
            + self.segments.capacity() * std::mem::size_of::<SegmentMeta>()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &[]
    }

    fn snapshot_bookmark_state(&self) -> crate::Result<QwpMarker> {
        Ok(QwpMarker {
            rows_len: checked_qwp_u32(self.rows.len(), "row metadata length")?,
            entries_len: checked_qwp_u32(self.entries.len(), "entry metadata length")?,
            segments_len: checked_qwp_u32(self.segments.len(), "segment metadata length")?,
            tail_segment_row_count: self.segments.last().map(|s| s.row_count),
            name_bytes_len: checked_qwp_u32(self.name_bytes.len(), "name_bytes length")?,
            value_bytes_len: checked_qwp_u32(self.value_bytes.len(), "value_bytes length")?,
            state: self.state,
        })
    }

    fn rewind_to_state(&mut self, marker: QwpMarker) -> crate::Result<()> {
        let size_hint = self.build_size_hint_for_target(
            marker.segments_len as usize,
            marker.tail_segment_row_count,
        )?;

        self.rows.truncate(marker.rows_len as usize);
        self.entries.truncate(marker.entries_len as usize);
        self.name_bytes.truncate(marker.name_bytes_len as usize);
        self.value_bytes.truncate(marker.value_bytes_len as usize);
        self.segments.truncate(marker.segments_len as usize);
        if let Some(tail_row_count) = marker.tail_segment_row_count
            && let Some(last_seg) = self.segments.last_mut()
        {
            last_seg.row_count = tail_row_count;
        }
        self.pending = PendingRowState::empty();
        self.state = marker.state;
        self.size_hint = size_hint;
        self.bookmark.clear();
        Ok(())
    }

    pub(crate) fn set_marker(&mut self) -> crate::Result<()> {
        self.state.op_state.ensure_marker_can_be_set()?;
        let marker = self.snapshot_bookmark_state()?;
        self.bookmark.capture(self.bookmark_meta.origin(), marker);
        Ok(())
    }

    pub(crate) fn bookmark(&mut self) -> crate::Result<Bookmark> {
        self.state.op_state.ensure_bookmark_can_be_set()?;
        let marker = self.snapshot_bookmark_state()?;
        Ok(self.bookmark.capture(self.bookmark_meta.origin(), marker))
    }

    pub(crate) fn rewind_to_bookmark(&mut self, bookmark: Bookmark) -> crate::Result<()> {
        let marker = self
            .bookmark
            .restore(self.bookmark_meta.origin(), bookmark)?;
        self.rewind_to_state(marker)
    }

    pub(crate) fn clear_bookmark(&mut self, bookmark: Bookmark) {
        self.bookmark
            .clear_if_matches(self.bookmark_meta.origin(), bookmark);
    }

    pub(crate) fn rewind_to_marker(&mut self) -> crate::Result<()> {
        let marker = self
            .bookmark
            .current()
            .ok_or_else(OpState::missing_marker_error)?;
        self.rewind_to_state(marker)
    }

    pub(crate) fn clear_marker(&mut self) {
        self.bookmark.clear();
    }

    pub(crate) fn clear(&mut self) {
        self.name_bytes.clear();
        self.value_bytes.clear();
        self.rows.clear();
        self.entries.clear();
        self.segments.clear();
        self.pending = PendingRowState::empty();
        self.state = BufferState::new();
        self.size_hint.clear();
        self.bookmark.clear();
    }

    fn build_size_hint_for_target(
        &self,
        segments_len: usize,
        tail_segment_row_count: Option<u32>,
    ) -> crate::Result<QwpSizeHint> {
        let mut size_hint = QwpSizeHint::new();
        let mut prev_seg_table: Option<NameSlice> = None;
        for seg_idx in 0..segments_len {
            let segment = self.segments[seg_idx];
            let row_count = if seg_idx + 1 == segments_len {
                tail_segment_row_count.unwrap_or(segment.row_count)
            } else {
                segment.row_count
            };
            let start = segment.row_start as usize;
            for i in 0..row_count as usize {
                let row = &self.rows[start + i];
                let last_seg_table = if i == 0 {
                    prev_seg_table
                } else {
                    Some(segment.table)
                };
                size_hint.add_committed_row(
                    row,
                    &self.entries,
                    &self.name_bytes,
                    &self.value_bytes,
                    last_seg_table,
                )?;
            }
            if row_count > 0 {
                prev_seg_table = Some(segment.table);
            }
        }
        Ok(size_hint)
    }

    pub(crate) fn check_can_flush(&self) -> crate::Result<()> {
        self.check_op(Op::Flush)
    }

    fn check_op(&self, op: Op) -> crate::Result<()> {
        self.state.op_state.check(op)
    }

    fn validate_max_name_len(&self, name: &str) -> crate::Result<()> {
        if name.len() > self.max_name_len {
            return Err(error::fmt!(
                InvalidName,
                "Bad name: {:?}: Too long (max {} characters)",
                name,
                self.max_name_len
            ));
        }
        Ok(())
    }

    fn checked_arena_offset(
        arena_len: usize,
        append_len: usize,
        arena_name: &'static str,
    ) -> crate::Result<u32> {
        let end = arena_len.checked_add(append_len).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/UDP {} arena exceeds maximum of {} bytes",
                arena_name,
                u32::MAX
            )
        })?;
        if end > u32::MAX as usize {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/UDP {} arena exceeds maximum of {} bytes",
                arena_name,
                u32::MAX
            ));
        }
        Ok(arena_len as u32)
    }

    fn append_name(&mut self, name: &str) -> crate::Result<NameSlice> {
        let offset = Self::checked_arena_offset(self.name_bytes.len(), name.len(), "name_bytes")?;
        let len = checked_qwp_u32(name.len(), "name length")?;
        self.name_bytes.extend_from_slice(name.as_bytes());
        Ok(NameSlice(ByteSlice { offset, len }))
    }

    fn append_value_str(&mut self, value: &str) -> crate::Result<ValueSlice> {
        let offset =
            Self::checked_arena_offset(self.value_bytes.len(), value.len(), "value_bytes")?;
        let len = checked_qwp_u32(value.len(), "value length")?;
        self.value_bytes.extend_from_slice(value.as_bytes());
        Ok(ValueSlice(ByteSlice { offset, len }))
    }

    fn append_value_long256(
        &mut self,
        value: &[u8; QWP_LONG256_BYTES],
    ) -> crate::Result<ValueSlice> {
        let offset =
            Self::checked_arena_offset(self.value_bytes.len(), QWP_LONG256_BYTES, "value_bytes")?;
        self.value_bytes.extend_from_slice(value);
        Ok(ValueSlice(ByteSlice {
            offset,
            len: checked_qwp_u32(QWP_LONG256_BYTES, "long256 length")?,
        }))
    }

    fn append_value_uuid(&mut self, lo: u64, hi: u64) -> crate::Result<ValueSlice> {
        let offset = Self::checked_arena_offset(self.value_bytes.len(), 16, "value_bytes")?;
        self.value_bytes.extend_from_slice(&lo.to_le_bytes());
        self.value_bytes.extend_from_slice(&hi.to_le_bytes());
        Ok(ValueSlice(ByteSlice {
            offset,
            len: checked_qwp_u32(16, "uuid length")?,
        }))
    }

    fn append_value_decimal(
        &mut self,
        value: DecimalView<'_>,
    ) -> crate::Result<Option<DecimalValue>> {
        let Some(decimal) = StoredQwpDecimal::from_decimal_view(value)? else {
            return Ok(None);
        };
        let offset = Self::checked_arena_offset(
            self.value_bytes.len(),
            QWP_DECIMAL_MAG_BYTES,
            "value_bytes",
        )?;
        decimal.write_magnitude_to(&mut self.value_bytes);
        Ok(Some(DecimalValue {
            magnitude: ValueSlice(ByteSlice {
                offset,
                len: checked_qwp_u32(QWP_DECIMAL_MAG_BYTES, "decimal magnitude length")?,
            }),
            scale: decimal.scale,
            negative: decimal.negative,
        }))
    }

    fn append_value_array<T, D>(&mut self, view: &T) -> crate::Result<ValueSlice>
    where
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
    {
        let ndim = view.ndim();
        if ndim == 0 {
            return Err(error::fmt!(
                ArrayError,
                "Zero-dimensional arrays are not supported",
            ));
        }
        if ndim > MAX_ARRAY_DIMS {
            return Err(error::fmt!(
                ArrayError,
                "Array dimension mismatch: expected at most {} dimensions, but got {}",
                MAX_ARRAY_DIMS,
                ndim
            ));
        }

        let array_buf_size = ndarr::check_and_get_array_bytes_size(view)?;
        let shape_header_size = checked_qwp_usize_mul(ndim, 4, "array shape header size")?;
        let payload_len = checked_qwp_usize_add(1, shape_header_size, "array payload size")?;
        let payload_len = checked_qwp_usize_add(payload_len, array_buf_size, "array payload size")?;

        let offset =
            Self::checked_arena_offset(self.value_bytes.len(), payload_len, "value_bytes")?;
        let len = checked_qwp_u32(payload_len, "array value length")?;

        let ndim_u8 = u8::try_from(ndim).map_err(|_| {
            error::fmt!(
                ArrayError,
                "Array dimension rank exceeds maximum encodable size of {}",
                u8::MAX
            )
        })?;

        let start = self.value_bytes.len();
        self.value_bytes.push(ndim_u8);
        for i in 0..ndim {
            let dim = view.dim(i)?;
            // This should already hold because `check_and_get_array_bytes_size()`
            // enforces `MAX_ARRAY_DIM_LEN`, but keep the narrowing explicit so
            // any future limit changes still fail with a precise error here.
            let dim = u32::try_from(dim).map_err(|_| {
                error::fmt!(
                    ArrayError,
                    "Array dimension {} exceeds maximum encodable size of {}",
                    i,
                    u32::MAX
                )
            })?;
            self.value_bytes.extend_from_slice(&dim.to_le_bytes());
        }
        let data_start = self.value_bytes.len();
        self.value_bytes.resize(data_start + array_buf_size, 0);
        if let Err(err) = ndarr::write_array_data(
            view,
            &mut self.value_bytes[data_start..data_start + array_buf_size],
            array_buf_size,
        ) {
            self.value_bytes.truncate(start);
            return Err(err);
        }

        Ok(ValueSlice(ByteSlice { offset, len }))
    }

    #[cfg(test)]
    fn name_str(&self, ns: NameSlice) -> &str {
        std::str::from_utf8(&self.name_bytes[ns.0.as_range()]).expect("name must be valid UTF-8")
    }

    fn rollback_pending(&mut self) {
        let saved_state = self.pending.saved_state;
        self.entries.truncate(self.pending.entry_start as usize);
        self.name_bytes
            .truncate(self.pending.name_bytes_start as usize);
        self.value_bytes
            .truncate(self.pending.value_bytes_start as usize);
        self.state = saved_state;
        self.pending = PendingRowState::empty();
    }

    fn push_entry(&mut self, entry: EntryMeta) -> crate::Result<()> {
        checked_qwp_push_index(self.entries.len(), "entry metadata length")?;
        self.entries.push(entry);
        Ok(())
    }

    fn mark_pending_entry_name(&self, name: &str) -> crate::Result<()> {
        // Linear scan over current row's entries for duplicate detection
        let start = self.pending.entry_start as usize;
        let name_bytes = name.as_bytes();
        for entry in &self.entries[start..] {
            let entry_name = &self.name_bytes[entry.name.0.as_range()];
            if entry_name == name_bytes {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "column '{}' already set for current row",
                    name
                ));
            }
        }
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn table<'a, N>(&mut self, name: N) -> crate::Result<&mut Self>
    where
        N: TryInto<TableName<'a>>,
        Error: From<N::Error>,
    {
        let name: TableName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Table)?;

        // Record rollback points
        self.pending = PendingRowState {
            table: None, // set below
            entry_start: checked_qwp_u32(self.entries.len(), "entry metadata length")?,
            name_bytes_start: checked_qwp_u32(self.name_bytes.len(), "name_bytes length")?,
            value_bytes_start: checked_qwp_u32(self.value_bytes.len(), "value_bytes length")?,
            saved_state: self.state,
        };

        let table_ns = self.append_name(name.as_ref())?;
        self.pending.table = Some(table_ns);
        self.state.op_state.record_table();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn symbol<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Symbol)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_vs = self.append_value_str(value.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Symbol(value_vs),
        })?;
        self.state.op_state.record_symbol();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_bool<'a, N>(&mut self, name: N, value: bool) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Bool(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i8<'a, N>(&mut self, name: N, value: i8) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::I8(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i16<'a, N>(&mut self, name: N, value: i16) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::I16(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i32<'a, N>(&mut self, name: N, value: i32) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::I32(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i64<'a, N>(&mut self, name: N, value: i64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::I64(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_f32<'a, N>(&mut self, name: N, value: f32) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::F32(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_f64<'a, N>(&mut self, name: N, value: f64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::F64(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_str<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_vs = self.append_value_str(value.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::String(value_vs),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_dec<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        let value: DecimalView<'a> = value.try_into()?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_ref = match self.append_value_decimal(value)? {
            Some(value_ref) => ValueRef::Decimal(value_ref),
            None => ValueRef::DecimalNull,
        };
        self.push_entry(EntryMeta {
            name: name_ns,
            value: value_ref,
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_dec64<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        let value: DecimalView<'a> = value.try_into()?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_ref = match self.append_value_decimal(value)? {
            Some(decimal_value) => {
                let bytes =
                    decimal_value.wire_bytes_with_scale(&self.value_bytes, decimal_value.scale)?;
                narrow_decimal_le_fits(&bytes, 8).ok_or_else(|| decimal_fit_error(64))?;
                ValueRef::Decimal64(decimal_value)
            }
            None => ValueRef::Decimal64Null,
        };
        self.push_entry(EntryMeta {
            name: name_ns,
            value: value_ref,
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_dec128<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        let value: DecimalView<'a> = value.try_into()?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_ref = match self.append_value_decimal(value)? {
            Some(decimal_value) => {
                let bytes =
                    decimal_value.wire_bytes_with_scale(&self.value_bytes, decimal_value.scale)?;
                narrow_decimal_le_fits(&bytes, 16).ok_or_else(|| decimal_fit_error(128))?;
                ValueRef::Decimal128(decimal_value)
            }
            None => ValueRef::Decimal128Null,
        };
        self.push_entry(EntryMeta {
            name: name_ns,
            value: value_ref,
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_uuid<'a, N>(
        &mut self,
        name: N,
        lo: u64,
        hi: u64,
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_vs = self.append_value_uuid(lo, hi)?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Uuid(value_vs),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_long256<'a, N>(
        &mut self,
        name: N,
        value: &[u8; QWP_LONG256_BYTES],
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_vs = self.append_value_long256(value)?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Long256(value_vs),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_ipv4<'a, N>(&mut self, name: N, value: u32) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Ipv4(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_date<'a, N>(&mut self, name: N, millis: i64) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::DateMillis(millis),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_char<'a, N>(&mut self, name: N, value: u16) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Char(value),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_binary<'a, N>(&mut self, name: N, value: &[u8]) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let offset =
            Self::checked_arena_offset(self.value_bytes.len(), value.len(), "value_bytes")?;
        let len = checked_qwp_u32(value.len(), "binary length")?;
        self.value_bytes.extend_from_slice(value);
        let value_vs = ValueSlice(ByteSlice { offset, len });
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Binary(value_vs),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_geohash<'a, N>(
        &mut self,
        name: N,
        bits: u64,
        precision_bits: u8,
    ) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        if !(1..=60).contains(&precision_bits) {
            return Err(error::fmt!(
                InvalidApiCall,
                "GEOHASH precision must be in 1..=60, got {}",
                precision_bits
            ));
        }
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::Geohash {
                bits,
                precision_bits,
            },
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[allow(private_bounds)]
    pub(crate) fn column_arr<'a, N, T, D>(&mut self, name: N, view: &T) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
        Error: From<N::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_vs = self.append_value_array(view)?;
        let value = match D::type_tag() {
            tag if tag == <f64 as ArrayElementSealed>::type_tag() => {
                ValueRef::DoubleArray(value_vs)
            }
            tag if tag == <i64 as ArrayElementSealed>::type_tag() => ValueRef::LongArray(value_vs),
            other => {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "Unsupported array element type tag {}",
                    other
                ));
            }
        };
        self.push_entry(EntryMeta {
            name: name_ns,
            value,
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> crate::Result<&mut Self>
    where
        N: TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        let name: ColumnName<'a> = name.try_into()?;
        self.validate_max_name_len(name.as_ref())?;
        self.check_op(Op::Column)?;
        self.mark_pending_entry_name(name.as_ref())?;
        let ts: Timestamp = value.try_into()?;
        let name_ns = self.append_name(name.as_ref())?;
        let value_ref = match ts {
            Timestamp::Micros(v) => ValueRef::TimestampMicros(v.as_i64()),
            Timestamp::Nanos(v) => ValueRef::TimestampNanos(v.as_i64()),
        };
        self.push_entry(EntryMeta {
            name: name_ns,
            value: value_ref,
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn at<T>(&mut self, timestamp: T) -> crate::Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        self.check_op(Op::At)?;
        let timestamp: Timestamp = timestamp.try_into()?;
        let number = match timestamp {
            Timestamp::Micros(ts) => ts.as_i64(),
            Timestamp::Nanos(ts) => ts.as_i64(),
        };
        if number < 0 {
            return Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {} is negative. It must be >= 0.",
                number
            ));
        }
        self.commit_current_row(Some(to_designated_ts(timestamp)))
    }

    #[inline(always)]
    pub(crate) fn at_now(&mut self) -> crate::Result<()> {
        self.check_op(Op::At)?;
        self.commit_current_row(None)
    }

    fn commit_current_row(&mut self, designated_ts: Option<DesignatedTs>) -> crate::Result<()> {
        let table_ns = match self.pending.table {
            Some(ns) => ns,
            None => {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "table() must be called before adding columns"
                ));
            }
        };

        let entry_start = self.pending.entry_start;
        let last_seg_table = self.segments.last().map(|s| s.table);

        // If the new row belongs to the same table as the last segment,
        // we extend that segment instead of pushing a new one.
        // Carry the segment index and precomputed new row count together
        // so the later commit has no unwrap() calls.
        let seg_extend: Option<usize> = if let (Some(last_table), Some(last_idx)) =
            (last_seg_table, self.segments.len().checked_sub(1))
        {
            if self.name_bytes[last_table.0.as_range()] == self.name_bytes[table_ns.0.as_range()] {
                Some(last_idx)
            } else {
                None
            }
        } else {
            None
        };

        // seg_update: either extend an existing segment (with its index and
        // precomputed new row count) or push a new one. Preflighting here
        // avoids unwrap() calls in the infallible commit section below.
        enum SegUpdate {
            Extend { idx: usize, new_row_count: u32 },
            PushNew,
        }

        let (entry_count, row_start, seg_update) = match (|| -> crate::Result<_> {
            let entries_len = checked_qwp_u32(self.entries.len(), "entry metadata length")?;
            let entry_count = entries_len.checked_sub(entry_start).ok_or_else(|| {
                error::fmt!(
                    InvalidApiCall,
                    "internal error: pending entry_start exceeds entry metadata length"
                )
            })?;

            if entry_count == 0 {
                return Err(error::fmt!(InvalidApiCall, "no columns were provided"));
            }

            let row_start = checked_qwp_push_index(self.rows.len(), "row metadata length")?;
            let seg_update = if let Some(seg_idx) = seg_extend {
                let new_row_count =
                    self.segments[seg_idx]
                        .row_count
                        .checked_add(1)
                        .ok_or_else(|| {
                            error::fmt!(
                                InvalidApiCall,
                                "QWP/UDP segment row count exceeds maximum of {}",
                                u32::MAX
                            )
                        })?;
                SegUpdate::Extend {
                    idx: seg_idx,
                    new_row_count,
                }
            } else {
                checked_qwp_push_index(self.segments.len(), "segment metadata length")?;
                SegUpdate::PushNew
            };
            Ok((entry_count, row_start, seg_update))
        })() {
            Ok(values) => values,
            Err(err) => {
                self.rollback_pending();
                return Err(err);
            }
        };

        let row = RowMeta {
            table: table_ns,
            entry_start,
            entry_count,
            designated_ts,
        };

        // Update size hint before segments (fallible, must not leave partial state)
        if let Err(err) = self.size_hint.add_committed_row(
            &row,
            &self.entries,
            &self.name_bytes,
            &self.value_bytes,
            last_seg_table,
        ) {
            self.rollback_pending();
            return Err(err);
        }

        // Remaining updates are infallible because the last fallible checks
        // were preflighted above.
        match seg_update {
            SegUpdate::Extend { idx, new_row_count } => {
                self.segments[idx].row_count = new_row_count;
            }
            SegUpdate::PushNew => {
                self.segments.push(SegmentMeta {
                    table: table_ns,
                    row_start,
                    row_count: 1,
                });
            }
        }

        self.rows.push(row);
        self.state.row_count += 1;
        self.state.op_state.finish_row();
        self.pending = PendingRowState::empty();
        Ok(())
    }

    /// Rough estimate for the uncommitted row; replaced by the accurate
    /// `RowGroupPlanner` value once the row is committed via `at()`/`at_now()`.
    fn pending_size_hint(&self) -> usize {
        let Some(table_ns) = self.pending.table else {
            return 0;
        };
        let mut size = table_ns.0.len as usize;
        for entry in &self.entries[self.pending.entry_start as usize..] {
            size += entry.name.0.len as usize;
            size += match &entry.value {
                ValueRef::Bool(_) | ValueRef::I8(_) => 1,
                ValueRef::I16(_) | ValueRef::Char(_) => 2,
                ValueRef::I32(_) | ValueRef::Ipv4(_) | ValueRef::F32(_) => 4,
                ValueRef::Symbol(vs) => vs.0.len as usize + 3,
                ValueRef::I64(_) | ValueRef::F64(_) | ValueRef::DateMillis(_) => 8,
                ValueRef::Uuid(_) => 16,
                ValueRef::Long256(_) => QWP_LONG256_BYTES,
                ValueRef::String(vs) => vs.0.len as usize + 9,
                ValueRef::Binary(vs) => vs.0.len as usize + 9,
                ValueRef::DecimalNull | ValueRef::Decimal64Null | ValueRef::Decimal128Null => 1,
                ValueRef::Decimal(_) => QWP_DECIMAL_MAG_BYTES + 4,
                ValueRef::Decimal64(_) => 8 + 4,
                ValueRef::Decimal128(_) => 16 + 4,
                ValueRef::DoubleArray(vs) | ValueRef::LongArray(vs) => vs.0.len as usize + 5,
                ValueRef::TimestampMicros(_) | ValueRef::TimestampNanos(_) => 9,
                ValueRef::Geohash { .. } => 9,
            };
        }
        size + 1
    }

    fn rows_for_segment(&self, segment: &SegmentMeta) -> &[RowMeta] {
        let start = segment.row_start as usize;
        let end = start + segment.row_count as usize;
        &self.rows[start..end]
    }

    fn entries_for_row(&self, row: &RowMeta) -> &[EntryMeta] {
        let start = row.entry_start as usize;
        let end = start + row.entry_count as usize;
        &self.entries[start..end]
    }

    fn encode_planner_to_scratch_and_send(
        &self,
        planner: &RowGroupPlanner,
        table_name: &[u8],
        datagram: &mut Vec<u8>,
        send: &mut dyn FnMut(&[u8]) -> crate::Result<()>,
    ) -> crate::Result<()> {
        datagram.clear();
        encode_row_group_from_scratch(
            planner,
            &self.name_bytes,
            &self.value_bytes,
            table_name,
            datagram,
        )?;
        send(datagram)
    }

    /// Encode datagrams for the current buffer contents.
    /// Test-only helper that collects datagrams into a Vec.
    #[cfg(test)]
    fn encode_datagrams(&self, max_datagram_size: usize) -> crate::Result<Vec<Vec<u8>>> {
        if self.pending.table.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot flush with an incomplete row. \
                 Call `at` or `at_now` to complete the pending row."
            ));
        }
        let mut datagrams = Vec::new();
        let mut planner = RowGroupPlanner::new();
        let mut datagram_buf = Vec::new();

        for segment in &self.segments {
            let rows = self.rows_for_segment(segment);
            let table_name = &self.name_bytes[segment.table.0.as_range()];

            planner.clear();

            for row in rows {
                let row_entries = self.entries_for_row(row);

                let cp = planner.checkpoint();
                planner.add_row(
                    row,
                    row_entries,
                    &self.name_bytes,
                    &self.value_bytes,
                    table_name.len(),
                )?;

                if cp.row_count > 0 && planner.current_len > max_datagram_size {
                    planner.rollback(cp);

                    encode_row_group_from_scratch(
                        &planner,
                        &self.name_bytes,
                        &self.value_bytes,
                        table_name,
                        &mut datagram_buf,
                    )?;
                    datagrams.push(datagram_buf.clone());
                    datagram_buf.clear();

                    planner.clear();

                    planner.add_row(
                        row,
                        row_entries,
                        &self.name_bytes,
                        &self.value_bytes,
                        table_name.len(),
                    )?;
                    if planner.current_len > max_datagram_size {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                            max_datagram_size,
                            planner.current_len
                        ));
                    }
                } else if planner.current_len > max_datagram_size {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                        max_datagram_size,
                        planner.current_len
                    ));
                }
            }

            if planner.row_count() > 0 {
                encode_row_group_from_scratch(
                    &planner,
                    &self.name_bytes,
                    &self.value_bytes,
                    table_name,
                    &mut datagram_buf,
                )?;
                datagrams.push(datagram_buf.clone());
                datagram_buf.clear();
            }
        }

        Ok(datagrams)
    }

    /// Streaming flush: encode and send datagrams directly to the socket.
    /// Uses sender-owned scratch to avoid allocations.
    pub(crate) fn flush_to_socket(
        &self,
        scratch: &mut QwpSendScratch,
        max_datagram_size: usize,
        send: &mut dyn FnMut(&[u8]) -> crate::Result<()>,
    ) -> crate::Result<()> {
        if self.pending.table.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot flush with an incomplete row. \
                 Call `at` or `at_now` to complete the pending row."
            ));
        }
        for (seg_idx, segment) in self.segments.iter().enumerate() {
            let table_name = &self.name_bytes[segment.table.0.as_range()];
            let cached = self.size_hint.segment_planner(seg_idx)?;

            // Fast path: segment fits in one datagram, encode from cached planner.
            if cached.current_len <= max_datagram_size {
                self.encode_planner_to_scratch_and_send(
                    cached,
                    table_name,
                    &mut scratch.datagram,
                    send,
                )?;
                continue;
            }

            // Slow path: row-by-row replay for datagram splitting.
            let rows = self.rows_for_segment(segment);

            scratch.planner.clear();

            for row in rows {
                let row_entries = self.entries_for_row(row);

                let cp = scratch.planner.checkpoint();
                scratch.planner.add_row(
                    row,
                    row_entries,
                    &self.name_bytes,
                    &self.value_bytes,
                    table_name.len(),
                )?;

                if cp.row_count > 0 && scratch.planner.current_len > max_datagram_size {
                    scratch.planner.rollback(cp);

                    let planner = &scratch.planner;
                    let datagram = &mut scratch.datagram;
                    self.encode_planner_to_scratch_and_send(planner, table_name, datagram, send)?;

                    scratch.planner.clear();

                    scratch.planner.add_row(
                        row,
                        row_entries,
                        &self.name_bytes,
                        &self.value_bytes,
                        table_name.len(),
                    )?;
                    if scratch.planner.current_len > max_datagram_size {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                            max_datagram_size,
                            scratch.planner.current_len
                        ));
                    }
                } else if scratch.planner.current_len > max_datagram_size {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "single row exceeds maximum datagram size ({} bytes), estimated {} bytes",
                        max_datagram_size,
                        scratch.planner.current_len
                    ));
                }
            }

            if scratch.planner.row_count() > 0 {
                let planner = &scratch.planner;
                let datagram = &mut scratch.datagram;
                self.encode_planner_to_scratch_and_send(planner, table_name, datagram, send)?;
            }
        }
        Ok(())
    }
}

// --- Sender scratch ---

pub(crate) struct QwpSendScratch {
    pub(crate) planner: RowGroupPlanner,
    pub(crate) datagram: Vec<u8>,
}

impl QwpSendScratch {
    pub(crate) fn new(max_datagram_size: usize) -> Self {
        let mut planner = RowGroupPlanner::new();
        planner.reserve_for_encoded_bytes(max_datagram_size);
        Self {
            planner,
            datagram: Vec::with_capacity(max_datagram_size),
        }
    }
}

// --- WebSocket columnar buffer ---

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Copy, Debug)]
struct QwpWsMarker {
    snapshot_idx: u32,
}

#[cfg(feature = "_sender-qwp-ws")]
type QwpWsSymbolHashMap<V> =
    std::collections::HashMap<Vec<u8>, V, BuildHasherDefault<QwpWsSymbolHasher>>;

#[cfg(feature = "_sender-qwp-ws")]
const QWP_WS_SYMBOL_HASH_OFFSET: u64 = 0xcbf29ce484222325;

#[cfg(feature = "_sender-qwp-ws")]
const QWP_WS_SYMBOL_HASH_PRIME: u64 = 0x100000001b3;

#[cfg(feature = "_sender-qwp-ws")]
fn qwp_ws_symbol_hash(bytes: &[u8]) -> u64 {
    qwp_ws_symbol_hash_with_seed(QWP_WS_SYMBOL_HASH_OFFSET, bytes)
}

#[cfg(feature = "_sender-qwp-ws")]
fn qwp_ws_symbol_hash_with_seed(mut hash: u64, bytes: &[u8]) -> u64 {
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(QWP_WS_SYMBOL_HASH_PRIME);
    }
    hash
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
struct QwpWsSymbolHasher(u64);

#[cfg(feature = "_sender-qwp-ws")]
impl Default for QwpWsSymbolHasher {
    fn default() -> Self {
        Self(QWP_WS_SYMBOL_HASH_OFFSET)
    }
}

#[cfg(feature = "_sender-qwp-ws")]
impl Hasher for QwpWsSymbolHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0 = qwp_ws_symbol_hash_with_seed(self.0, bytes);
    }
}

#[cfg(feature = "_sender-qwp-ws")]
type QwpWsLocalSymbolHashMap =
    std::collections::HashMap<u64, QwpWsLocalSymbolBucket, BuildHasherDefault<QwpWsU64Hasher>>;

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug, Default)]
struct QwpWsU64Hasher(u64);

#[cfg(feature = "_sender-qwp-ws")]
impl Hasher for QwpWsU64Hasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut value = 0u64;
        for (shift, &byte) in bytes.iter().take(8).enumerate() {
            value |= u64::from(byte) << (shift * 8);
        }
        self.0 = value;
    }

    fn write_u64(&mut self, value: u64) {
        self.0 = value;
    }
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
enum QwpWsLocalSymbolBucket {
    One(u32),
    Many(Vec<u32>),
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug, Default)]
struct QwpWsLocalSymbolLookup {
    buckets: QwpWsLocalSymbolHashMap,
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpWsLocalSymbolLookup {
    fn reserve(&mut self, additional: usize) {
        self.buckets.reserve(additional);
    }

    fn clear(&mut self) {
        self.buckets.clear();
    }

    fn get(&self, hash: u64, bytes: &[u8], dict: &[QwpWsSymbolEntry], data: &[u8]) -> Option<u32> {
        match self.buckets.get(&hash)? {
            QwpWsLocalSymbolBucket::One(local_id) => symbol_entry_bytes(dict, data, *local_id)
                .filter(|stored| *stored == bytes)
                .map(|_| *local_id),
            QwpWsLocalSymbolBucket::Many(local_ids) => {
                local_ids.iter().copied().find(|&local_id| {
                    symbol_entry_bytes(dict, data, local_id).is_some_and(|stored| stored == bytes)
                })
            }
        }
    }

    fn insert(&mut self, hash: u64, local_id: u32) {
        use std::collections::hash_map::Entry;

        match self.buckets.entry(hash) {
            Entry::Vacant(entry) => {
                entry.insert(QwpWsLocalSymbolBucket::One(local_id));
            }
            Entry::Occupied(mut entry) => match entry.get_mut() {
                QwpWsLocalSymbolBucket::One(existing) => {
                    let existing = *existing;
                    *entry.get_mut() = QwpWsLocalSymbolBucket::Many(vec![existing, local_id]);
                }
                QwpWsLocalSymbolBucket::Many(local_ids) => local_ids.push(local_id),
            },
        }
    }

    fn retain_local_ids_below(&mut self, dict_len: usize) {
        self.buckets.retain(|_, bucket| match bucket {
            QwpWsLocalSymbolBucket::One(local_id) => (*local_id as usize) < dict_len,
            QwpWsLocalSymbolBucket::Many(local_ids) => {
                local_ids.retain(|local_id| (*local_id as usize) < dict_len);
                !local_ids.is_empty()
            }
        });
    }
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
struct QwpWsSnapshot {
    tables: Vec<QwpWsTableBuffer>,
    table_lookup: std::collections::HashMap<Vec<u8>, usize>,
    current_table_idx: Option<usize>,
    state: BufferState,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
struct QwpWsRowRollbackMark {
    tables_len: usize,
    current_table_idx: Option<usize>,
    state: BufferState,
    table_mark: QwpWsTableRollbackMark,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
struct QwpWsTableRollbackMark {
    row_count: u32,
    in_progress: bool,
    in_progress_column_count: usize,
    column_access_cursor: usize,
    columns_len: usize,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
struct QwpWsTableBuffer {
    table_name: Vec<u8>,
    packed_table_name: u64,
    row_count: u32,
    in_progress: bool,
    in_progress_column_count: usize,
    column_access_cursor: usize,
    columns: Vec<QwpWsColumnBuffer>,
    column_lookup: std::collections::HashMap<String, usize>,
    row_mark: Option<QwpWsRowRollbackMark>,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
struct QwpWsColumnBuffer {
    name: Vec<u8>,
    lower_ascii_name: Vec<u8>,
    packed_lower_ascii_name: u64,
    kind: ColumnKind,
    last_written_row: Option<u32>,
    non_null_count: u32,
    values: QwpWsColumnValues,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
enum QwpWsColumnValues {
    Bool {
        cells: Vec<QwpWsCell<bool>>,
    },
    I8 {
        cells: Vec<QwpWsCell<i8>>,
    },
    I16 {
        cells: Vec<QwpWsCell<i16>>,
    },
    I32 {
        cells: Vec<QwpWsCell<i32>>,
    },
    I64 {
        cells: Vec<QwpWsCell<i64>>,
    },
    F32 {
        cells: Vec<QwpWsCell<f32>>,
    },
    F64 {
        cells: Vec<QwpWsCell<f64>>,
    },
    TimestampMicros {
        cells: Vec<QwpWsCell<i64>>,
    },
    TimestampNanos {
        cells: Vec<QwpWsCell<i64>>,
    },
    String {
        cells: Vec<QwpWsSliceCell>,
        data: Vec<u8>,
    },
    Symbol {
        cells: Vec<QwpWsSymbolCell>,
        dict: Vec<QwpWsSymbolEntry>,
        lookup: QwpWsLocalSymbolLookup,
        data: Vec<u8>,
    },
    Decimal {
        cells: Vec<QwpWsDecimalCell>,
        decimal_scale: u8,
    },
    Decimal64 {
        cells: Vec<QwpWsDecimalCell>,
        decimal_scale: u8,
    },
    Decimal128 {
        cells: Vec<QwpWsDecimalCell>,
        decimal_scale: u8,
    },
    DoubleArray {
        cells: Vec<QwpWsSliceCell>,
        data: Vec<u8>,
    },
    Uuid {
        cells: Vec<QwpWsCell<(u64, u64)>>,
    },
    Long256 {
        cells: Vec<QwpWsSliceCell>,
        data: Vec<u8>,
    },
    Ipv4 {
        cells: Vec<QwpWsCell<u32>>,
    },
    Date {
        cells: Vec<QwpWsCell<i64>>,
    },
    Char {
        cells: Vec<QwpWsCell<u16>>,
    },
    Binary {
        cells: Vec<QwpWsSliceCell>,
        data: Vec<u8>,
    },
    Geohash {
        cells: Vec<QwpWsCell<u64>>,
        precision_bits: u8,
    },
    LongArray {
        cells: Vec<QwpWsSliceCell>,
        data: Vec<u8>,
    },
    #[cfg(feature = "arrow")]
    ArrowFixed {
        bitmap: Option<Vec<u8>>,
        values: Vec<u8>,
        row_count: u32,
    },
    #[cfg(feature = "arrow")]
    ArrowVarLen {
        bitmap: Option<Vec<u8>>,
        offsets: Vec<u32>,
        data: Vec<u8>,
        row_count: u32,
    },
    #[cfg(feature = "arrow")]
    ArrowBool {
        bitmap: Option<Vec<u8>>,
        packed_bits: Vec<u8>,
        row_count: u32,
    },
    #[cfg(feature = "arrow")]
    ArrowSymbol {
        bitmap: Option<Vec<u8>>,
        dict: Vec<QwpWsSymbolEntry>,
        dict_lookup: QwpWsLocalSymbolLookup,
        dict_data: Vec<u8>,
        keys: Vec<u32>,
        row_count: u32,
    },
    #[cfg(feature = "arrow")]
    ArrowDecimal {
        bitmap: Option<Vec<u8>>,
        values: Vec<u8>,
        decimal_scale: u8,
        element_width: u8,
        row_count: u32,
    },
    #[cfg(feature = "arrow")]
    ArrowGeohash {
        bitmap: Option<Vec<u8>>,
        values: Vec<u8>,
        precision_bits: u8,
        row_count: u32,
    },
    #[cfg(feature = "arrow")]
    ArrowArray {
        bitmap: Option<Vec<u8>>,
        data: Vec<u8>,
        row_count: u32,
    },
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Copy, Debug)]
struct QwpWsCell<T: Copy> {
    row_idx: u32,
    value: T,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Copy, Debug)]
struct QwpWsSliceCell {
    row_idx: u32,
    offset: u32,
    len: u32,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Copy, Debug)]
struct QwpWsSymbolCell {
    row_idx: u32,
    local_id: u32,
    is_new: bool,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Debug)]
struct QwpWsSymbolEntry {
    offset: u32,
    len: u32,
}

#[cfg(feature = "_sender-qwp-ws")]
fn symbol_entry_bytes<'a>(
    dict: &[QwpWsSymbolEntry],
    data: &'a [u8],
    local_id: u32,
) -> Option<&'a [u8]> {
    let entry = dict.get(local_id as usize)?;
    let start = entry.offset as usize;
    let end = entry.offset.checked_add(entry.len)? as usize;
    data.get(start..end)
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Copy, Debug)]
struct QwpWsDecimalCell {
    row_idx: u32,
    value: Option<StoredQwpDecimal>,
}

#[cfg(feature = "_sender-qwp-ws")]
fn pop_value_cell_for_row<T: Copy>(cells: &mut Vec<QwpWsCell<T>>, row_idx: u32) -> bool {
    if cells.last().is_some_and(|cell| cell.row_idx == row_idx) {
        cells.pop();
        true
    } else {
        false
    }
}

#[cfg(feature = "_sender-qwp-ws")]
fn pop_slice_cell_for_row(cells: &mut Vec<QwpWsSliceCell>, row_idx: u32) -> Option<QwpWsSliceCell> {
    if cells.last().is_some_and(|cell| cell.row_idx == row_idx) {
        cells.pop()
    } else {
        None
    }
}

#[cfg(feature = "_sender-qwp-ws")]
fn pop_symbol_cell_for_row(
    cells: &mut Vec<QwpWsSymbolCell>,
    row_idx: u32,
) -> Option<QwpWsSymbolCell> {
    if cells.last().is_some_and(|cell| cell.row_idx == row_idx) {
        cells.pop()
    } else {
        None
    }
}

#[cfg(feature = "_sender-qwp-ws")]
fn pop_decimal_cell_for_row(
    cells: &mut Vec<QwpWsDecimalCell>,
    row_idx: u32,
) -> Option<QwpWsDecimalCell> {
    if cells.last().is_some_and(|cell| cell.row_idx == row_idx) {
        cells.pop()
    } else {
        None
    }
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Debug)]
pub(crate) struct QwpWsColumnarBuffer {
    tables: Vec<QwpWsTableBuffer>,
    table_lookup: std::collections::HashMap<Vec<u8>, usize>,
    current_table_idx: Option<usize>,
    state: BufferState,
    bookmark_meta: BufferBookmarkMeta,
    bookmark: StoredBookmark<QwpWsMarker>,
    snapshots: Vec<QwpWsSnapshot>,
    max_name_len: usize,
}

#[cfg(feature = "_sender-qwp-ws")]
impl Clone for QwpWsColumnarBuffer {
    fn clone(&self) -> Self {
        Self {
            tables: self.tables.clone(),
            table_lookup: self.table_lookup.clone(),
            current_table_idx: self.current_table_idx,
            state: self.state,
            // Preserve the stored rewind payload so marker-based rewind on the
            // clone matches the source, but assign a fresh origin so explicit
            // bookmarks from the source buffer fail on the clone.
            bookmark_meta: BufferBookmarkMeta::new(),
            bookmark: self.bookmark,
            snapshots: self.snapshots.clone(),
            max_name_len: self.max_name_len,
        }
    }
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpWsColumnarBuffer {
    pub(crate) fn new(max_name_len: usize) -> Self {
        Self {
            tables: Vec::new(),
            table_lookup: std::collections::HashMap::new(),
            current_table_idx: None,
            state: BufferState::new(),
            bookmark_meta: BufferBookmarkMeta::new(),
            bookmark: StoredBookmark::new(),
            snapshots: Vec::new(),
            max_name_len,
        }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        let estimated_columns = (additional / 16).max(1);
        self.tables.reserve(1);
        self.table_lookup.reserve(1);
        for table in &mut self.tables {
            table.columns.reserve(estimated_columns);
            table.column_lookup.reserve(estimated_columns);
            for column in &mut table.columns {
                column.reserve_for_rows(estimated_columns);
            }
        }
    }

    pub(crate) fn len(&self) -> usize {
        let mut total = QWP_MESSAGE_HEADER_SIZE + 2;
        let mut symbol_dict_count = 0usize;
        let mut symbol_dict_bytes = 0usize;
        for table in self.non_empty_tables() {
            total += qwp_string_byte_len(table.table_name.len());
            total += qwp_varint_size(table.row_count as u64);
            total += qwp_varint_size(table.columns.len() as u64);
            total += 1 + qwp_varint_size(QWP_INLINE_SCHEMA_ID);
            for column in &table.columns {
                total += qwp_string_byte_len(column.name.len()) + 1;
                total += column.estimated_payload_len(table.row_count as usize);
                match &column.values {
                    QwpWsColumnValues::Symbol { dict, data, .. } => {
                        symbol_dict_count += dict.len();
                        for entry in dict {
                            let bytes =
                                &data[entry.offset as usize..(entry.offset + entry.len) as usize];
                            symbol_dict_bytes += qwp_string_byte_len(bytes.len());
                        }
                    }
                    #[cfg(feature = "arrow")]
                    QwpWsColumnValues::ArrowSymbol {
                        dict, dict_data, ..
                    } => {
                        symbol_dict_count += dict.len();
                        for entry in dict {
                            let bytes = &dict_data
                                [entry.offset as usize..(entry.offset + entry.len) as usize];
                            symbol_dict_bytes += qwp_string_byte_len(bytes.len());
                        }
                    }
                    _ => {}
                }
            }
        }
        total += qwp_varint_size(0);
        total += qwp_varint_size(symbol_dict_count as u64);
        total += symbol_dict_bytes;
        total
    }

    pub(crate) fn row_count(&self) -> usize {
        self.state.row_count
    }

    pub(crate) fn is_empty(&self) -> bool {
        !self.tables.iter().any(|table| {
            table.in_progress || table.row_count > 0 || table.in_progress_column_count > 0
        })
    }

    pub(crate) fn capacity(&self) -> usize {
        let mut cap = self.tables.capacity() * std::mem::size_of::<QwpWsTableBuffer>();
        for table in &self.tables {
            cap += table.table_name.capacity();
            cap += table.columns.capacity() * std::mem::size_of::<QwpWsColumnBuffer>();
            for column in &table.columns {
                cap +=
                    column.name.capacity() + column.lower_ascii_name.capacity() + column.capacity();
            }
        }
        cap
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &[]
    }

    pub(crate) fn check_can_flush(&self) -> crate::Result<()> {
        self.check_op(Op::Flush)
    }

    pub(crate) fn set_marker(&mut self) -> crate::Result<()> {
        self.state.op_state.ensure_marker_can_be_set()?;
        let marker = self.capture_snapshot()?;
        self.bookmark.capture(self.bookmark_meta.origin(), marker);
        Ok(())
    }

    pub(crate) fn bookmark(&mut self) -> crate::Result<Bookmark> {
        self.state.op_state.ensure_bookmark_can_be_set()?;
        let marker = self.capture_snapshot()?;
        Ok(self.bookmark.capture(self.bookmark_meta.origin(), marker))
    }

    pub(crate) fn rewind_to_bookmark(&mut self, bookmark: Bookmark) -> crate::Result<()> {
        let marker = self
            .bookmark
            .restore(self.bookmark_meta.origin(), bookmark)?;
        self.restore_snapshot(marker)
    }

    pub(crate) fn clear_bookmark(&mut self, bookmark: Bookmark) {
        self.bookmark
            .clear_if_matches(self.bookmark_meta.origin(), bookmark);
    }

    pub(crate) fn rewind_to_marker(&mut self) -> crate::Result<()> {
        let marker = self
            .bookmark
            .current()
            .ok_or_else(OpState::missing_marker_error)?;
        self.restore_snapshot(marker)
    }

    pub(crate) fn clear_marker(&mut self) {
        self.bookmark.clear();
    }

    pub(crate) fn clear(&mut self) {
        for table in &mut self.tables {
            table.clear_rows();
        }
        self.current_table_idx = None;
        self.state = BufferState::new();
        self.bookmark.clear();
    }

    fn capture_snapshot(&mut self) -> crate::Result<QwpWsMarker> {
        let snapshot_idx = checked_qwp_push_index(self.snapshots.len(), "QWP/WS snapshot count")?;
        self.snapshots.push(QwpWsSnapshot {
            tables: self.tables.clone(),
            table_lookup: self.table_lookup.clone(),
            current_table_idx: self.current_table_idx,
            state: self.state,
        });
        Ok(QwpWsMarker { snapshot_idx })
    }

    fn restore_snapshot(&mut self, marker: QwpWsMarker) -> crate::Result<()> {
        let snapshot = self
            .snapshots
            .get(marker.snapshot_idx as usize)
            .cloned()
            .ok_or_else(|| error::fmt!(InvalidApiCall, "Can't rewind to stale QWP/WS marker."))?;
        self.tables = snapshot.tables;
        self.table_lookup = snapshot.table_lookup;
        self.current_table_idx = snapshot.current_table_idx;
        self.state = snapshot.state;
        self.bookmark.clear();
        Ok(())
    }

    fn check_op(&self, op: Op) -> crate::Result<()> {
        self.state.op_state.check(op)
    }

    fn validate_max_name_len(&self, name: &str) -> crate::Result<()> {
        if name.len() > self.max_name_len {
            return Err(error::fmt!(
                InvalidName,
                "Bad name: {:?}: Too long (max {} characters)",
                name,
                self.max_name_len
            ));
        }
        Ok(())
    }

    #[inline(always)]
    pub(crate) fn table<'a, N>(&mut self, name: N) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<TableName<'a>>,
        Error: From<N::Error>,
    {
        self.check_op(Op::Table)?;

        let table_bytes = name.as_ref().as_bytes();
        let tables_len_before = self.tables.len();
        let current_table_idx_before = self.current_table_idx;
        let state_before = self.state;
        let idx = match self.current_table_idx {
            Some(current_idx)
                if names_equal_packed(
                    &self.tables[current_idx].table_name,
                    self.tables[current_idx].packed_table_name,
                    table_bytes,
                ) =>
            {
                current_idx
            }
            _ => {
                let name = match name.try_into() {
                    Ok(name) => name,
                    Err(err) => {
                        self.rollback_current_row();
                        return Err(err.into());
                    }
                };
                if let Err(err) = self.validate_max_name_len(name.as_ref()) {
                    self.rollback_current_row();
                    return Err(err);
                }
                self.lookup_or_create_table(name.as_ref().as_bytes())?
            }
        };
        self.current_table_idx = Some(idx);

        let table_mark = self.tables[idx].rollback_mark();
        self.tables[idx].in_progress = true;
        self.tables[idx].in_progress_column_count = 0;
        self.tables[idx].column_access_cursor = 0;
        self.tables[idx].row_mark = Some(QwpWsRowRollbackMark {
            tables_len: tables_len_before,
            current_table_idx: current_table_idx_before,
            state: state_before,
            table_mark,
        });
        self.state.op_state.record_table();
        Ok(self)
    }

    fn lookup_or_create_table(&mut self, table_name: &[u8]) -> crate::Result<usize> {
        if let Some(&idx) = self.table_lookup.get(table_name) {
            return Ok(idx);
        }
        checked_qwp_push_index(self.tables.len(), "QWP/WS table count")?;
        let idx = self.tables.len();
        self.tables.push(QwpWsTableBuffer::new(table_name));
        self.table_lookup.insert(table_name.to_vec(), idx);
        Ok(idx)
    }

    #[inline(always)]
    pub(crate) fn symbol<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let value = value.as_ref();
        self.append_named_value(name, ColumnKind::Symbol, |column, row_idx| {
            column.append_symbol(row_idx, value)
        })?;
        self.state.op_state.record_symbol();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_bool<'a, N>(&mut self, name: N, value: bool) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Bool, |column, row_idx| {
            column.append_bool(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i8<'a, N>(&mut self, name: N, value: i8) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::I8, |column, row_idx| {
            column.append_i8(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i16<'a, N>(&mut self, name: N, value: i16) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::I16, |column, row_idx| {
            column.append_i16(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i32<'a, N>(&mut self, name: N, value: i32) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::I32, |column, row_idx| {
            column.append_i32(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_i64<'a, N>(&mut self, name: N, value: i64) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::I64, |column, row_idx| {
            column.append_i64(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_f32<'a, N>(&mut self, name: N, value: f32) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::F32, |column, row_idx| {
            column.append_f32(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_f64<'a, N>(&mut self, name: N, value: f64) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::F64, |column, row_idx| {
            column.append_f64(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_str<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: AsRef<str>,
        Error: From<N::Error>,
    {
        let value = value.as_ref();
        self.append_named_value(name, ColumnKind::String, |column, row_idx| {
            column.append_string(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_dec<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        self.check_op(Op::Column)?;
        let value: DecimalView<'a> = match value.try_into() {
            Ok(value) => value,
            Err(err) => {
                self.rollback_current_row();
                return Err(err.into());
            }
        };
        let decimal = match StoredQwpDecimal::from_decimal_view(value) {
            Ok(decimal) => decimal,
            Err(err) => {
                self.rollback_current_row();
                return Err(err);
            }
        };
        self.append_named_value(name, ColumnKind::Decimal, |column, row_idx| {
            column.append_decimal(row_idx, decimal)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_dec64<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        self.check_op(Op::Column)?;
        let value: DecimalView<'a> = match value.try_into() {
            Ok(value) => value,
            Err(err) => {
                self.rollback_current_row();
                return Err(err.into());
            }
        };
        let decimal = match StoredQwpDecimal::from_decimal_view(value) {
            Ok(decimal) => decimal,
            Err(err) => {
                self.rollback_current_row();
                return Err(err);
            }
        };
        self.append_named_value(name, ColumnKind::Decimal64, |column, row_idx| {
            column.append_decimal64(row_idx, decimal)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_dec128<'a, N, S>(&mut self, name: N, value: S) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        S: TryInto<DecimalView<'a>>,
        Error: From<N::Error>,
        Error: From<S::Error>,
    {
        self.check_op(Op::Column)?;
        let value: DecimalView<'a> = match value.try_into() {
            Ok(value) => value,
            Err(err) => {
                self.rollback_current_row();
                return Err(err.into());
            }
        };
        let decimal = match StoredQwpDecimal::from_decimal_view(value) {
            Ok(decimal) => decimal,
            Err(err) => {
                self.rollback_current_row();
                return Err(err);
            }
        };
        self.append_named_value(name, ColumnKind::Decimal128, |column, row_idx| {
            column.append_decimal128(row_idx, decimal)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_uuid<'a, N>(
        &mut self,
        name: N,
        lo: u64,
        hi: u64,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Uuid, |column, row_idx| {
            column.append_uuid(row_idx, lo, hi)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_long256<'a, N>(
        &mut self,
        name: N,
        value: &[u8; QWP_LONG256_BYTES],
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Long256, |column, row_idx| {
            column.append_long256(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_ipv4<'a, N>(&mut self, name: N, value: u32) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Ipv4, |column, row_idx| {
            column.append_ipv4(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_date<'a, N>(&mut self, name: N, millis: i64) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Date, |column, row_idx| {
            column.append_date(row_idx, millis)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_char<'a, N>(&mut self, name: N, value: u16) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Char, |column, row_idx| {
            column.append_char(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    pub(crate) fn column_binary<'a, N>(&mut self, name: N, value: &[u8]) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Binary, |column, row_idx| {
            column.append_binary(row_idx, value)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_geohash<'a, N>(
        &mut self,
        name: N,
        bits: u64,
        precision_bits: u8,
    ) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
    {
        self.append_named_value(name, ColumnKind::Geohash, |column, row_idx| {
            column.append_geohash(row_idx, bits, precision_bits)
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

    #[allow(private_bounds)]
    pub(crate) fn column_arr<'a, N, T, D>(&mut self, name: N, view: &T) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
        Error: From<N::Error>,
    {
        self.check_op(Op::Column)?;
        let payload = match Self::encode_array_value(view) {
            Ok(payload) => payload,
            Err(err) => {
                self.rollback_current_row();
                return Err(err);
            }
        };
        let tag = D::type_tag();
        let f64_tag = <f64 as ArrayElementSealed>::type_tag();
        let i64_tag = <i64 as ArrayElementSealed>::type_tag();
        if tag == f64_tag {
            self.append_named_value(name, ColumnKind::DoubleArray, |column, row_idx| {
                column.append_double_array(row_idx, &payload)
            })?;
        } else if tag == i64_tag {
            self.append_named_value(name, ColumnKind::LongArray, |column, row_idx| {
                column.append_long_array(row_idx, &payload)
            })?;
        } else {
            self.rollback_current_row();
            return Err(error::fmt!(
                InvalidApiCall,
                "Unsupported array element type tag {}",
                tag
            ));
        }
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn column_ts<'a, N, T>(&mut self, name: N, value: T) -> crate::Result<&mut Self>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        T: TryInto<Timestamp>,
        Error: From<N::Error>,
        Error: From<T::Error>,
    {
        self.check_op(Op::Column)?;
        let ts: Timestamp = match value.try_into() {
            Ok(ts) => ts,
            Err(err) => {
                self.rollback_current_row();
                return Err(err.into());
            }
        };
        match ts {
            Timestamp::Micros(v) => {
                let value = v.as_i64();
                self.append_named_value(name, ColumnKind::TimestampMicros, |column, row_idx| {
                    column.append_timestamp_micros(row_idx, value)
                })?;
            }
            Timestamp::Nanos(v) => {
                let value = v.as_i64();
                self.append_named_value(name, ColumnKind::TimestampNanos, |column, row_idx| {
                    column.append_timestamp_nanos(row_idx, value)
                })?;
            }
        }
        self.state.op_state.record_column();
        Ok(self)
    }

    #[inline(always)]
    pub(crate) fn at<T>(&mut self, timestamp: T) -> crate::Result<()>
    where
        T: TryInto<Timestamp>,
        Error: From<T::Error>,
    {
        self.check_op(Op::At)?;
        let timestamp: Timestamp = timestamp.try_into()?;
        let number = match timestamp {
            Timestamp::Micros(ts) => ts.as_i64(),
            Timestamp::Nanos(ts) => ts.as_i64(),
        };
        if number < 0 {
            return Err(error::fmt!(
                InvalidTimestamp,
                "Timestamp {} is negative. It must be >= 0.",
                number
            ));
        }
        if let Err(err) = self.append_designated_ts(to_designated_ts(timestamp)) {
            self.rollback_current_row();
            return Err(err);
        }
        self.commit_current_row()
    }

    #[inline(always)]
    pub(crate) fn at_now(&mut self) -> crate::Result<()> {
        self.check_op(Op::At)?;
        self.commit_current_row()
    }

    #[inline(always)]
    fn append_named_value<'a, N, F>(
        &mut self,
        name: N,
        kind: ColumnKind,
        append: F,
    ) -> crate::Result<()>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
        F: FnOnce(&mut QwpWsColumnBuffer, u32) -> crate::Result<()>,
    {
        let op = if kind == ColumnKind::Symbol {
            Op::Symbol
        } else {
            Op::Column
        };
        self.check_op(op)?;
        self.append_column_value(name, kind, append)
    }

    #[inline(always)]
    fn append_designated_ts(&mut self, ts: DesignatedTs) -> crate::Result<()> {
        match ts {
            DesignatedTs::Micros(value) => self.append_column_value(
                ColumnName::new_unchecked(""),
                ColumnKind::TimestampMicros,
                |column, row_idx| column.append_timestamp_micros(row_idx, value),
            ),
            DesignatedTs::Nanos(value) => self.append_column_value(
                ColumnName::new_unchecked(""),
                ColumnKind::TimestampNanos,
                |column, row_idx| column.append_timestamp_nanos(row_idx, value),
            ),
        }
    }

    #[inline(always)]
    fn append_column_value<'a, N, F>(
        &mut self,
        name: N,
        kind: ColumnKind,
        append: F,
    ) -> crate::Result<()>
    where
        N: AsRef<str> + TryInto<ColumnName<'a>>,
        Error: From<N::Error>,
        F: FnOnce(&mut QwpWsColumnBuffer, u32) -> crate::Result<()>,
    {
        let Some(table_idx) = self.current_table_idx else {
            return Err(error::fmt!(
                InvalidApiCall,
                "table() must be called before adding columns"
            ));
        };
        match self.tables[table_idx].lookup_column(name.as_ref().as_bytes()) {
            Ok(Some(idx)) => {
                self.append_resolved_column_value(
                    table_idx,
                    idx,
                    name.as_ref().as_bytes(),
                    kind,
                    append,
                )?;
            }
            Ok(None) => {
                let name: ColumnName<'a> = match name.try_into() {
                    Ok(name) => name,
                    Err(err) => {
                        self.rollback_current_row();
                        return Err(err.into());
                    }
                };
                if let Err(err) = self.validate_max_name_len(name.as_ref()) {
                    self.rollback_current_row();
                    return Err(err);
                }
                match self.tables[table_idx].create_column(name.as_ref().as_bytes(), kind) {
                    Ok(idx) => {
                        self.append_resolved_column_value(
                            table_idx,
                            idx,
                            name.as_ref().as_bytes(),
                            kind,
                            append,
                        )?;
                    }
                    Err(err) => {
                        self.rollback_current_row();
                        return Err(err);
                    }
                }
            }
            Err(err) => {
                self.rollback_current_row();
                return Err(err);
            }
        }
        Ok(())
    }

    #[inline(always)]
    fn append_resolved_column_value<F>(
        &mut self,
        table_idx: usize,
        col_idx: usize,
        type_mismatch_name: &[u8],
        kind: ColumnKind,
        append: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut QwpWsColumnBuffer, u32) -> crate::Result<()>,
    {
        let table = &mut self.tables[table_idx];
        let row_idx = table.row_count;
        if table.columns[col_idx].kind != kind {
            let err = batched_type_change_error_ws(type_mismatch_name);
            self.rollback_current_row();
            return Err(err);
        }
        let duplicate = table.columns[col_idx].last_written_row == Some(row_idx);
        if duplicate {
            return Ok(());
        }
        if let Err(err) = append(&mut table.columns[col_idx], row_idx) {
            self.rollback_current_row();
            return Err(err);
        }
        table.columns[col_idx].last_written_row = Some(row_idx);
        table.in_progress_column_count += 1;
        table.column_access_cursor = col_idx + 1;
        Ok(())
    }

    #[inline(always)]
    fn commit_current_row(&mut self) -> crate::Result<()> {
        let Some(table_idx) = self.current_table_idx else {
            return Err(error::fmt!(
                InvalidApiCall,
                "table() must be called before adding columns"
            ));
        };
        if self.tables[table_idx].in_progress_column_count == 0 {
            self.rollback_current_row();
            return Err(error::fmt!(InvalidApiCall, "no columns were provided"));
        }
        let row_count = match self.tables[table_idx].row_count.checked_add(1) {
            Some(row_count) => row_count,
            None => {
                self.rollback_current_row();
                return Err(error::fmt!(
                    InvalidApiCall,
                    "QWP/WebSocket table row count exceeds maximum of {}",
                    u32::MAX
                ));
            }
        };
        self.tables[table_idx].row_count = row_count;
        self.tables[table_idx].in_progress = false;
        self.tables[table_idx].in_progress_column_count = 0;
        self.tables[table_idx].column_access_cursor = 0;
        self.tables[table_idx].row_mark = None;
        self.state.row_count += 1;
        self.state.op_state.finish_row();
        Ok(())
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_begin(
        &mut self,
        table_name: TableName<'_>,
    ) -> crate::Result<ArrowBulkCtx> {
        self.check_op(Op::Table)?;
        let table_bytes = table_name.as_ref().as_bytes();
        self.validate_max_name_len(table_name.as_ref())?;
        let idx = self.lookup_or_create_table(table_bytes)?;
        if self.tables[idx].in_progress {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS bulk arrow append cannot start while a row is in progress on table '{}'",
                table_name.as_ref()
            ));
        }
        self.current_table_idx = Some(idx);
        let table = &self.tables[idx];
        let starting_rows = table.row_count;
        let table_mark = QwpWsTableRollbackMark {
            row_count: table.row_count,
            in_progress: table.in_progress,
            in_progress_column_count: table.in_progress_column_count,
            column_access_cursor: table.column_access_cursor,
            columns_len: table.columns.len(),
        };
        let pre_column_marks = table.columns.iter().map(|c| c.arrow_snapshot()).collect();
        Ok(ArrowBulkCtx {
            table_idx: idx,
            starting_rows,
            table_mark,
            pre_column_marks,
        })
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_rollback(&mut self, ctx: ArrowBulkCtx) {
        let table = &mut self.tables[ctx.table_idx];
        let pre_count = ctx.table_mark.columns_len;
        if table.columns.len() > pre_count {
            table.columns.truncate(pre_count);
        }
        for (col, mark) in table
            .columns
            .iter_mut()
            .zip(ctx.pre_column_marks.into_iter())
        {
            col.arrow_restore(mark);
        }
        table.row_count = ctx.table_mark.row_count;
        table.in_progress = ctx.table_mark.in_progress;
        table.in_progress_column_count = ctx.table_mark.in_progress_column_count;
        table.column_access_cursor = ctx.table_mark.column_access_cursor;
        table.row_mark = None;
        table.rebuild_column_lookup();
        if ctx.table_mark.row_count == 0 && !ctx.table_mark.in_progress {
            self.current_table_idx = None;
        }
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_fixed<F>(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name: ColumnName<'_>,
        kind: ColumnKind,
        info: ArrowBatchInfo<'_>,
        write_values: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        let col_bytes = column_name.as_ref().as_bytes();
        self.validate_max_name_len(column_name.as_ref())?;
        let col_idx = self.lookup_or_create_arrow_column(ctx, col_bytes, kind)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_fixed_batch(
            kind,
            info,
            write_values,
        )
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_varlen<F>(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name: ColumnName<'_>,
        kind: ColumnKind,
        info: ArrowBatchInfo<'_>,
        write: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u32>, &mut Vec<u8>) -> crate::Result<()>,
    {
        let col_bytes = column_name.as_ref().as_bytes();
        self.validate_max_name_len(column_name.as_ref())?;
        let col_idx = self.lookup_or_create_arrow_column(ctx, col_bytes, kind)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_varlen_batch(kind, info, write)
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_bool(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name: ColumnName<'_>,
        batch_packed_bits: &[u8],
        info: ArrowBatchInfo<'_>,
    ) -> crate::Result<()> {
        let col_bytes = column_name.as_ref().as_bytes();
        self.validate_max_name_len(column_name.as_ref())?;
        let col_idx = self.lookup_or_create_arrow_column(ctx, col_bytes, ColumnKind::Bool)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_bool_batch(batch_packed_bits, info)
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_symbol(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name: ColumnName<'_>,
        batch_keys: &[u32],
        batch_dict_entries: &[(u32, u32)],
        batch_dict_data: &[u8],
        info: ArrowBatchInfo<'_>,
    ) -> crate::Result<()> {
        let col_bytes = column_name.as_ref().as_bytes();
        self.validate_max_name_len(column_name.as_ref())?;
        let col_idx = self.lookup_or_create_arrow_column(ctx, col_bytes, ColumnKind::Symbol)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_symbol_batch(
            batch_keys,
            batch_dict_entries,
            batch_dict_data,
            info,
        )
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_decimal<F>(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name: ColumnName<'_>,
        kind: ColumnKind,
        spec: ArrowDecimalSpec,
        info: ArrowBatchInfo<'_>,
        write_values: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        let col_bytes = column_name.as_ref().as_bytes();
        self.validate_max_name_len(column_name.as_ref())?;
        let col_idx = self.lookup_or_create_arrow_column(ctx, col_bytes, kind)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_decimal_batch(
            kind,
            spec,
            info,
            write_values,
        )
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_geohash<F>(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name: ColumnName<'_>,
        precision_bits: u8,
        info: ArrowBatchInfo<'_>,
        write_values: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        let col_bytes = column_name.as_ref().as_bytes();
        self.validate_max_name_len(column_name.as_ref())?;
        let col_idx = self.lookup_or_create_arrow_column(ctx, col_bytes, ColumnKind::Geohash)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_geohash_batch(
            precision_bits,
            info,
            write_values,
        )
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_array<F>(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name: ColumnName<'_>,
        kind: ColumnKind,
        info: ArrowBatchInfo<'_>,
        write_data: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        let col_bytes = column_name.as_ref().as_bytes();
        self.validate_max_name_len(column_name.as_ref())?;
        let col_idx = self.lookup_or_create_arrow_column(ctx, col_bytes, kind)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_array_batch(kind, info, write_data)
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_set_designated_ts<F>(
        &mut self,
        ctx: &ArrowBulkCtx,
        kind: ColumnKind,
        info: ArrowBatchInfo<'_>,
        write_values: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        if !matches!(
            kind,
            ColumnKind::TimestampMicros | ColumnKind::TimestampNanos
        ) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS designated timestamp must be TimestampMicros or TimestampNanos, got {:?}",
                kind
            ));
        }
        let col_idx = self.lookup_or_create_arrow_column(ctx, b"", kind)?;
        self.tables[ctx.table_idx].columns[col_idx].append_arrow_fixed_batch(
            kind,
            info,
            write_values,
        )
    }

    #[cfg(feature = "arrow")]
    pub(crate) fn arrow_bulk_commit(
        &mut self,
        ctx: &ArrowBulkCtx,
        batch_rows: u32,
    ) -> crate::Result<()> {
        let table = &mut self.tables[ctx.table_idx];
        let expected_rows = ctx.starting_rows.checked_add(batch_rows).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WS table row count overflow on '{}'",
                String::from_utf8_lossy(&table.table_name)
            )
        })?;
        for column in &table.columns {
            let arrow_rows = column.arrow_row_count();
            match arrow_rows {
                Some(rows) if rows == expected_rows => {}
                Some(rows) => {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "QWP/WS arrow column '{}' has {} rows after bulk batch but table expects {}",
                        String::from_utf8_lossy(&column.name),
                        rows,
                        expected_rows
                    ));
                }
                None => {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "QWP/WS column '{}' is not in arrow-fed mode; mixed bulk + row-by-row batches are not supported",
                        String::from_utf8_lossy(&column.name)
                    ));
                }
            }
        }
        table.row_count = expected_rows;
        table.in_progress = false;
        table.in_progress_column_count = 0;
        table.column_access_cursor = 0;
        table.row_mark = None;
        let added = batch_rows as usize;
        self.state.row_count = self
            .state
            .row_count
            .checked_add(added)
            .ok_or_else(|| error::fmt!(InvalidApiCall, "QWP/WS buffer row count overflow"))?;
        self.state.op_state.finish_row();
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn lookup_or_create_arrow_column(
        &mut self,
        ctx: &ArrowBulkCtx,
        column_name_bytes: &[u8],
        kind: ColumnKind,
    ) -> crate::Result<usize> {
        let table = &mut self.tables[ctx.table_idx];
        let idx = match table.lookup_column(column_name_bytes)? {
            Some(idx) => {
                if table.columns[idx].kind != kind {
                    return Err(batched_type_change_error_ws(column_name_bytes));
                }
                idx
            }
            None => table.create_column(column_name_bytes, kind)?,
        };
        table.column_access_cursor = idx + 1;
        Ok(idx)
    }

    fn rollback_current_row(&mut self) {
        let Some(table_idx) = self.current_table_idx else {
            return;
        };
        let Some(row_mark) = self.tables[table_idx].row_mark.take() else {
            return;
        };
        self.tables[table_idx].restore(row_mark.table_mark);
        self.tables.truncate(row_mark.tables_len);
        self.rebuild_table_lookup();
        self.current_table_idx = row_mark.current_table_idx;
        self.state = row_mark.state;
    }

    fn rebuild_table_lookup(&mut self) {
        self.table_lookup.clear();
        for (idx, table) in self.tables.iter().enumerate() {
            self.table_lookup.insert(table.table_name.clone(), idx);
        }
    }

    fn non_empty_tables(&self) -> impl Iterator<Item = &QwpWsTableBuffer> {
        self.tables.iter().filter(|table| table.row_count > 0)
    }

    #[allow(private_bounds)]
    fn encode_array_value<T, D>(view: &T) -> crate::Result<Vec<u8>>
    where
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
    {
        let ndim = view.ndim();
        if ndim == 0 {
            return Err(error::fmt!(
                ArrayError,
                "Zero-dimensional arrays are not supported",
            ));
        }
        if ndim > MAX_ARRAY_DIMS {
            return Err(error::fmt!(
                ArrayError,
                "Array dimension mismatch: expected at most {} dimensions, but got {}",
                MAX_ARRAY_DIMS,
                ndim
            ));
        }

        let array_buf_size = ndarr::check_and_get_array_bytes_size(view)?;
        let shape_header_size = checked_qwp_usize_mul(ndim, 4, "array shape header size")?;
        let payload_len = checked_qwp_usize_add(1, shape_header_size, "array payload size")?;
        let payload_len = checked_qwp_usize_add(payload_len, array_buf_size, "array payload size")?;
        let mut out = Vec::with_capacity(payload_len);

        let ndim_u8 = u8::try_from(ndim).map_err(|_| {
            error::fmt!(
                ArrayError,
                "Array dimension rank exceeds maximum encodable size of {}",
                u8::MAX
            )
        })?;
        out.push(ndim_u8);
        for i in 0..ndim {
            let dim = view.dim(i)?;
            let dim = u32::try_from(dim).map_err(|_| {
                error::fmt!(
                    ArrayError,
                    "Array dimension {} exceeds maximum encodable size of {}",
                    i,
                    u32::MAX
                )
            })?;
            out.extend_from_slice(&dim.to_le_bytes());
        }
        let data_start = out.len();
        out.resize(data_start + array_buf_size, 0);
        ndarr::write_array_data(
            view,
            &mut out[data_start..data_start + array_buf_size],
            array_buf_size,
        )?;
        Ok(out)
    }

    pub(crate) fn encode_ws_replay_message(
        &self,
        scratch: &mut QwpWsEncodeScratch,
        global_dict: &mut SymbolGlobalDict,
        version: u8,
    ) -> crate::Result<()> {
        self.check_can_flush()?;
        let out = &mut scratch.message;
        out.clear();

        let header_start = out.len();
        out.extend_from_slice(&[0u8; QWP_MESSAGE_HEADER_SIZE]);
        let payload_start = out.len();

        while scratch.per_segment_symbol_globals.len() < self.tables.len() {
            scratch.per_segment_symbol_globals.push(Vec::new());
        }
        let mut highest_referenced_symbol_id: Option<u64> = None;
        for (table_idx, table) in self.tables.iter().enumerate() {
            let per_col = &mut scratch.per_segment_symbol_globals[table_idx];
            while per_col.len() < table.columns.len() {
                per_col.push(Vec::new());
            }
            for (col_idx, column) in table.columns.iter().enumerate() {
                let globals = &mut per_col[col_idx];
                globals.clear();
                match &column.values {
                    QwpWsColumnValues::Symbol { dict, data, .. } => {
                        globals.reserve(dict.len());
                        for entry in dict {
                            let bytes =
                                &data[entry.offset as usize..(entry.offset + entry.len) as usize];
                            let (gid, _) = global_dict.intern(bytes);
                            highest_referenced_symbol_id = Some(
                                highest_referenced_symbol_id
                                    .map_or(gid, |highest| highest.max(gid)),
                            );
                            globals.push(gid);
                        }
                    }
                    #[cfg(feature = "arrow")]
                    QwpWsColumnValues::ArrowSymbol {
                        dict, dict_data, ..
                    } => {
                        globals.reserve(dict.len());
                        for entry in dict {
                            let bytes = &dict_data
                                [entry.offset as usize..(entry.offset + entry.len) as usize];
                            let (gid, _) = global_dict.intern(bytes);
                            highest_referenced_symbol_id = Some(
                                highest_referenced_symbol_id
                                    .map_or(gid, |highest| highest.max(gid)),
                            );
                            globals.push(gid);
                        }
                    }
                    _ => {}
                }
            }
        }

        write_qwp_varint(out, 0);
        let dense_count = highest_referenced_symbol_id.map_or(0, |highest| highest + 1);
        write_qwp_varint(out, dense_count);
        for id in 0..dense_count {
            let bytes = global_dict.entry(id).ok_or_else(|| {
                error::fmt!(
                    InvalidApiCall,
                    "internal QWP/WS replay encoder error: missing global symbol id {}",
                    id
                )
            })?;
            write_qwp_bytes(out, bytes);
        }

        scratch.replay_schema_count = 0;
        let table_count = checked_qwp_u16(
            self.tables
                .iter()
                .filter(|table| table.row_count > 0)
                .count(),
            "WS message table count",
        )?;
        for (table_idx, table) in self.tables.iter().enumerate() {
            if table.row_count == 0 {
                continue;
            }
            write_qwp_bytes(out, &table.table_name);
            write_qwp_varint(out, table.row_count as u64);
            write_qwp_varint(out, table.columns.len() as u64);

            scratch.schema_signature.clear();
            for column in &table.columns {
                write_qwp_bytes(&mut scratch.schema_signature, &column.name);
                scratch.schema_signature.push(wire_type_byte(
                    column.kind,
                    column.uses_null_bitmap(table.row_count as usize),
                ));
            }
            let schema_id = intern_replay_schema_signature(
                &mut scratch.replay_schema_signatures,
                &mut scratch.replay_schema_count,
                &scratch.schema_signature,
            );
            out.push(QWP_SCHEMA_MODE_FULL);
            write_qwp_varint(out, schema_id);
            out.extend_from_slice(&scratch.schema_signature);

            for (col_idx, column) in table.columns.iter().enumerate() {
                let globals = &scratch.per_segment_symbol_globals[table_idx][col_idx];
                column.encode(table.row_count as usize, globals, out)?;
            }
        }

        let header = QwpMessageHeader {
            magic: *b"QWP1",
            version,
            flags: QWP_FLAG_DELTA_SYMBOL_DICT,
            table_count,
            payload_len: checked_qwp_u32(
                out.len() - payload_start,
                "WS replay message payload length",
            )?,
        };
        header.write_to(&mut out[header_start..header_start + QWP_MESSAGE_HEADER_SIZE]);
        Ok(())
    }
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpWsTableBuffer {
    fn new(table_name: &[u8]) -> Self {
        Self {
            table_name: table_name.to_vec(),
            packed_table_name: packed_name(table_name),
            row_count: 0,
            in_progress: false,
            in_progress_column_count: 0,
            column_access_cursor: 0,
            columns: Vec::new(),
            column_lookup: std::collections::HashMap::new(),
            row_mark: None,
        }
    }

    fn clear_rows(&mut self) {
        self.row_count = 0;
        self.in_progress = false;
        self.in_progress_column_count = 0;
        self.column_access_cursor = 0;
        self.row_mark = None;
        for column in &mut self.columns {
            column.clear_rows();
        }
    }

    fn rollback_mark(&self) -> QwpWsTableRollbackMark {
        QwpWsTableRollbackMark {
            row_count: self.row_count,
            in_progress: self.in_progress,
            in_progress_column_count: self.in_progress_column_count,
            column_access_cursor: self.column_access_cursor,
            columns_len: self.columns.len(),
        }
    }

    fn restore(&mut self, mark: QwpWsTableRollbackMark) {
        for column in &mut self.columns[..mark.columns_len] {
            column.rollback_row(mark.row_count);
        }
        self.columns.truncate(mark.columns_len);
        self.row_count = mark.row_count;
        self.in_progress = mark.in_progress;
        self.in_progress_column_count = mark.in_progress_column_count;
        self.column_access_cursor = mark.column_access_cursor;
        self.row_mark = None;
        self.rebuild_column_lookup();
    }

    #[inline(always)]
    fn lookup_column(&mut self, name: &[u8]) -> crate::Result<Option<usize>> {
        if self.column_access_cursor < self.columns.len()
            && names_equal_lower_ascii(
                &self.columns[self.column_access_cursor].lower_ascii_name,
                self.columns[self.column_access_cursor].packed_lower_ascii_name,
                name,
            )
        {
            return Ok(Some(self.column_access_cursor));
        }

        let lookup_key = column_lookup_key(name)?;
        if let Some(&idx) = self.column_lookup.get(&lookup_key) {
            return Ok(Some(idx));
        }

        Ok(None)
    }

    fn create_column(&mut self, name: &[u8], kind: ColumnKind) -> crate::Result<usize> {
        checked_qwp_push_index(self.columns.len(), "QWP/WS column count")?;
        let lookup_key = column_lookup_key(name)?;
        let idx = self.columns.len();
        self.columns.push(QwpWsColumnBuffer::new(name, kind));
        self.column_lookup.insert(lookup_key, idx);
        Ok(idx)
    }

    fn rebuild_column_lookup(&mut self) {
        self.column_lookup.clear();
        for (idx, column) in self.columns.iter().enumerate() {
            if let Ok(key) = column_lookup_key(&column.name) {
                self.column_lookup.insert(key, idx);
            }
        }
    }
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpWsColumnBuffer {
    fn new(name: &[u8], kind: ColumnKind) -> Self {
        Self {
            name: name.to_vec(),
            lower_ascii_name: lowercase_ascii_bytes(name),
            packed_lower_ascii_name: packed_lower_ascii_name(name),
            kind,
            last_written_row: None,
            non_null_count: 0,
            values: QwpWsColumnValues::new(kind),
        }
    }

    fn reserve_for_rows(&mut self, rows: usize) {
        match &mut self.values {
            QwpWsColumnValues::Bool { cells } => cells.reserve(rows),
            QwpWsColumnValues::I8 { cells } => cells.reserve(rows),
            QwpWsColumnValues::I16 { cells } => cells.reserve(rows),
            QwpWsColumnValues::I32 { cells } => cells.reserve(rows),
            QwpWsColumnValues::I64 { cells } => cells.reserve(rows),
            QwpWsColumnValues::F32 { cells } => cells.reserve(rows),
            QwpWsColumnValues::F64 { cells } => cells.reserve(rows),
            QwpWsColumnValues::TimestampMicros { cells } => cells.reserve(rows),
            QwpWsColumnValues::TimestampNanos { cells } => cells.reserve(rows),
            QwpWsColumnValues::String { cells, data } => {
                cells.reserve(rows);
                data.reserve(rows * 8);
            }
            QwpWsColumnValues::Symbol {
                cells,
                dict,
                lookup,
                data,
                ..
            } => {
                cells.reserve(rows);
                dict.reserve(rows);
                lookup.reserve(rows);
                data.reserve(rows * 8);
            }
            QwpWsColumnValues::Decimal { cells, .. } => cells.reserve(rows),
            QwpWsColumnValues::Decimal64 { cells, .. } => cells.reserve(rows),
            QwpWsColumnValues::Decimal128 { cells, .. } => cells.reserve(rows),
            QwpWsColumnValues::DoubleArray { cells, data } => {
                cells.reserve(rows);
                data.reserve(rows * 16);
            }
            QwpWsColumnValues::Uuid { cells } => cells.reserve(rows),
            QwpWsColumnValues::Long256 { cells, data } => {
                cells.reserve(rows);
                data.reserve(rows * QWP_LONG256_BYTES);
            }
            QwpWsColumnValues::Ipv4 { cells } => cells.reserve(rows),
            QwpWsColumnValues::Date { cells } => cells.reserve(rows),
            QwpWsColumnValues::Char { cells } => cells.reserve(rows),
            QwpWsColumnValues::Binary { cells, data } => {
                cells.reserve(rows);
                data.reserve(rows * 8);
            }
            QwpWsColumnValues::Geohash { cells, .. } => cells.reserve(rows),
            QwpWsColumnValues::LongArray { cells, data } => {
                cells.reserve(rows);
                data.reserve(rows * 16);
            }
            #[cfg(feature = "arrow")]
            QwpWsColumnValues::ArrowFixed { values, .. }
            | QwpWsColumnValues::ArrowGeohash { values, .. }
            | QwpWsColumnValues::ArrowDecimal { values, .. } => values.reserve(rows),
            #[cfg(feature = "arrow")]
            QwpWsColumnValues::ArrowVarLen { offsets, data, .. } => {
                offsets.reserve(rows.saturating_add(1));
                data.reserve(rows.saturating_mul(8));
            }
            #[cfg(feature = "arrow")]
            QwpWsColumnValues::ArrowBool { packed_bits, .. } => {
                packed_bits.reserve(rows.div_ceil(8));
            }
            #[cfg(feature = "arrow")]
            QwpWsColumnValues::ArrowSymbol {
                dict,
                dict_lookup,
                dict_data,
                keys,
                ..
            } => {
                dict.reserve(rows);
                dict_lookup.reserve(rows);
                dict_data.reserve(rows.saturating_mul(8));
                keys.reserve(rows);
            }
            #[cfg(feature = "arrow")]
            QwpWsColumnValues::ArrowArray { data, .. } => {
                data.reserve(rows.saturating_mul(16));
            }
        }
    }

    fn clear_rows(&mut self) {
        self.last_written_row = None;
        self.non_null_count = 0;
        // After Arrow bulk usage, reset the variant tag so the row-by-row
        // setters don't reject the cleared column with type_mismatch_error_ws.
        #[cfg(feature = "arrow")]
        if self.arrow_row_count().is_some() {
            self.values = QwpWsColumnValues::new(self.kind);
            return;
        }
        self.values.clear_rows();
    }

    fn capacity(&self) -> usize {
        self.values.capacity()
    }

    fn rollback_row(&mut self, row_idx: u32) {
        if self.last_written_row != Some(row_idx) {
            return;
        }
        if self.values.rollback_row(row_idx) {
            self.non_null_count -= 1;
        }
        self.last_written_row = None;
    }

    fn uses_null_bitmap(&self, row_count: usize) -> bool {
        uses_null_bitmap(
            kind_supports_sparse_nulls(self.kind),
            row_count,
            self.non_null_count,
        )
    }

    fn estimated_payload_len(&self, row_count: usize) -> usize {
        let bitmap = if self.uses_null_bitmap(row_count) {
            bitmap_bytes(row_count)
        } else {
            0
        };
        1 + bitmap + self.values.estimated_data_len(row_count)
    }

    fn append_bool(&mut self, row_idx: u32, value: bool) -> crate::Result<()> {
        let QwpWsColumnValues::Bool { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_i8(&mut self, row_idx: u32, value: i8) -> crate::Result<()> {
        let QwpWsColumnValues::I8 { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_i16(&mut self, row_idx: u32, value: i16) -> crate::Result<()> {
        let QwpWsColumnValues::I16 { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_i32(&mut self, row_idx: u32, value: i32) -> crate::Result<()> {
        let QwpWsColumnValues::I32 { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_i64(&mut self, row_idx: u32, value: i64) -> crate::Result<()> {
        let QwpWsColumnValues::I64 { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_f32(&mut self, row_idx: u32, value: f32) -> crate::Result<()> {
        let QwpWsColumnValues::F32 { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_f64(&mut self, row_idx: u32, value: f64) -> crate::Result<()> {
        let QwpWsColumnValues::F64 { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_timestamp_micros(&mut self, row_idx: u32, value: i64) -> crate::Result<()> {
        let QwpWsColumnValues::TimestampMicros { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_timestamp_nanos(&mut self, row_idx: u32, value: i64) -> crate::Result<()> {
        let QwpWsColumnValues::TimestampNanos { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_string(&mut self, row_idx: u32, value: &str) -> crate::Result<()> {
        let QwpWsColumnValues::String { cells, data } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        let offset = QwpBuffer::checked_arena_offset(data.len(), value.len(), "QWP/WS string")?;
        let len = checked_qwp_u32(value.len(), "QWP/WS string length")?;
        data.extend_from_slice(value.as_bytes());
        cells.push(QwpWsSliceCell {
            row_idx,
            offset,
            len,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_symbol(&mut self, row_idx: u32, value: &str) -> crate::Result<()> {
        let QwpWsColumnValues::Symbol {
            cells,
            dict,
            lookup,
            data,
        } = &mut self.values
        else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        let bytes = value.as_bytes();
        let hash = qwp_ws_symbol_hash(bytes);
        let (local_id, is_new) = if let Some(local_id) = lookup.get(hash, bytes, dict, data) {
            (local_id, false)
        } else {
            let local_id = checked_qwp_push_index(dict.len(), "QWP/WS symbol dictionary length")?;
            let offset = QwpBuffer::checked_arena_offset(data.len(), bytes.len(), "QWP/WS symbol")?;
            let len = checked_qwp_u32(bytes.len(), "QWP/WS symbol length")?;
            data.extend_from_slice(bytes);
            dict.push(QwpWsSymbolEntry { offset, len });
            lookup.insert(hash, local_id);
            (local_id, true)
        };
        cells.push(QwpWsSymbolCell {
            row_idx,
            local_id,
            is_new,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_decimal(
        &mut self,
        row_idx: u32,
        value: Option<StoredQwpDecimal>,
    ) -> crate::Result<()> {
        let QwpWsColumnValues::Decimal {
            cells,
            decimal_scale,
        } = &mut self.values
        else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        if let Some(value) = value {
            if *decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                *decimal_scale = value.scale;
            }
            cells.push(QwpWsDecimalCell {
                row_idx,
                value: Some(value),
            });
            self.increment_non_null()?;
        } else {
            cells.push(QwpWsDecimalCell {
                row_idx,
                value: None,
            });
        }
        Ok(())
    }

    fn append_decimal64(
        &mut self,
        row_idx: u32,
        value: Option<StoredQwpDecimal>,
    ) -> crate::Result<()> {
        let QwpWsColumnValues::Decimal64 {
            cells,
            decimal_scale,
        } = &mut self.values
        else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        if let Some(value) = value {
            let bytes = value.wire_bytes_with_scale(value.scale)?;
            narrow_decimal_le_fits(&bytes, 8).ok_or_else(|| decimal_fit_error(64))?;
            if *decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                *decimal_scale = value.scale;
            }
            cells.push(QwpWsDecimalCell {
                row_idx,
                value: Some(value),
            });
            self.increment_non_null()?;
        } else {
            cells.push(QwpWsDecimalCell {
                row_idx,
                value: None,
            });
        }
        Ok(())
    }

    fn append_decimal128(
        &mut self,
        row_idx: u32,
        value: Option<StoredQwpDecimal>,
    ) -> crate::Result<()> {
        let QwpWsColumnValues::Decimal128 {
            cells,
            decimal_scale,
        } = &mut self.values
        else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        if let Some(value) = value {
            let bytes = value.wire_bytes_with_scale(value.scale)?;
            narrow_decimal_le_fits(&bytes, 16).ok_or_else(|| decimal_fit_error(128))?;
            if *decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                *decimal_scale = value.scale;
            }
            cells.push(QwpWsDecimalCell {
                row_idx,
                value: Some(value),
            });
            self.increment_non_null()?;
        } else {
            cells.push(QwpWsDecimalCell {
                row_idx,
                value: None,
            });
        }
        Ok(())
    }

    fn append_double_array(&mut self, row_idx: u32, payload: &[u8]) -> crate::Result<()> {
        let QwpWsColumnValues::DoubleArray { cells, data } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        let offset = QwpBuffer::checked_arena_offset(data.len(), payload.len(), "QWP/WS array")?;
        let len = checked_qwp_u32(payload.len(), "QWP/WS array length")?;
        data.extend_from_slice(payload);
        cells.push(QwpWsSliceCell {
            row_idx,
            offset,
            len,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_uuid(&mut self, row_idx: u32, lo: u64, hi: u64) -> crate::Result<()> {
        let QwpWsColumnValues::Uuid { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell {
            row_idx,
            value: (lo, hi),
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_long256(
        &mut self,
        row_idx: u32,
        value: &[u8; QWP_LONG256_BYTES],
    ) -> crate::Result<()> {
        let QwpWsColumnValues::Long256 { cells, data } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        let offset =
            QwpBuffer::checked_arena_offset(data.len(), QWP_LONG256_BYTES, "QWP/WS long256")?;
        let len = checked_qwp_u32(QWP_LONG256_BYTES, "QWP/WS long256 length")?;
        data.extend_from_slice(value);
        cells.push(QwpWsSliceCell {
            row_idx,
            offset,
            len,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_ipv4(&mut self, row_idx: u32, value: u32) -> crate::Result<()> {
        let QwpWsColumnValues::Ipv4 { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_date(&mut self, row_idx: u32, millis: i64) -> crate::Result<()> {
        let QwpWsColumnValues::Date { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell {
            row_idx,
            value: millis,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_char(&mut self, row_idx: u32, value: u16) -> crate::Result<()> {
        let QwpWsColumnValues::Char { cells } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        cells.push(QwpWsCell { row_idx, value });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_binary(&mut self, row_idx: u32, value: &[u8]) -> crate::Result<()> {
        let QwpWsColumnValues::Binary { cells, data } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        let offset = QwpBuffer::checked_arena_offset(data.len(), value.len(), "QWP/WS binary")?;
        let len = checked_qwp_u32(value.len(), "QWP/WS binary length")?;
        data.extend_from_slice(value);
        cells.push(QwpWsSliceCell {
            row_idx,
            offset,
            len,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_long_array(&mut self, row_idx: u32, payload: &[u8]) -> crate::Result<()> {
        let QwpWsColumnValues::LongArray { cells, data } = &mut self.values else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        let offset =
            QwpBuffer::checked_arena_offset(data.len(), payload.len(), "QWP/WS long array")?;
        let len = checked_qwp_u32(payload.len(), "QWP/WS long array length")?;
        data.extend_from_slice(payload);
        cells.push(QwpWsSliceCell {
            row_idx,
            offset,
            len,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn append_geohash(&mut self, row_idx: u32, bits: u64, precision_bits: u8) -> crate::Result<()> {
        let QwpWsColumnValues::Geohash {
            cells,
            precision_bits: col_precision,
        } = &mut self.values
        else {
            return Err(type_mismatch_error_ws(&self.name));
        };
        if !(1..=60).contains(&precision_bits) {
            return Err(error::fmt!(
                InvalidApiCall,
                "GEOHASH precision must be in 1..=60, got {}",
                precision_bits
            ));
        }
        if *col_precision == 0 {
            *col_precision = precision_bits;
        } else if *col_precision != precision_bits {
            return Err(error::fmt!(
                InvalidApiCall,
                "GEOHASH precision mismatch within column: pinned at {} bits, got {}",
                *col_precision,
                precision_bits
            ));
        }
        cells.push(QwpWsCell {
            row_idx,
            value: bits,
        });
        self.increment_non_null()?;
        Ok(())
    }

    fn increment_non_null(&mut self) -> crate::Result<()> {
        self.non_null_count = self.non_null_count.checked_add(1).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket non-null value count exceeds maximum of {}",
                u32::MAX
            )
        })?;
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn precheck_arrow_batch_overflows(
        &self,
        prior_row_count: u32,
        info: &ArrowBatchInfo<'_>,
    ) -> crate::Result<(u32, u32)> {
        let new_row_count = prior_row_count.checked_add(info.rows).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow row count overflow on column '{}'",
                String::from_utf8_lossy(&self.name)
            )
        })?;
        let new_non_null = self
            .non_null_count
            .checked_add(info.non_null)
            .ok_or_else(|| {
                error::fmt!(
                    InvalidApiCall,
                    "QWP/WebSocket non-null value count exceeds maximum of {}",
                    u32::MAX
                )
            })?;
        Ok((new_row_count, new_non_null))
    }

    #[cfg(feature = "arrow")]
    fn is_fresh(&self) -> bool {
        self.last_written_row.is_none() && self.non_null_count == 0
    }

    #[cfg(feature = "arrow")]
    fn arrow_row_count(&self) -> Option<u32> {
        match &self.values {
            QwpWsColumnValues::ArrowFixed { row_count, .. }
            | QwpWsColumnValues::ArrowVarLen { row_count, .. }
            | QwpWsColumnValues::ArrowBool { row_count, .. }
            | QwpWsColumnValues::ArrowSymbol { row_count, .. }
            | QwpWsColumnValues::ArrowDecimal { row_count, .. }
            | QwpWsColumnValues::ArrowGeohash { row_count, .. }
            | QwpWsColumnValues::ArrowArray { row_count, .. } => Some(*row_count),
            _ => None,
        }
    }

    #[cfg(feature = "arrow")]
    fn append_arrow_fixed_batch<F>(
        &mut self,
        kind: ColumnKind,
        info: ArrowBatchInfo<'_>,
        write_values: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        if self.kind != kind {
            return Err(type_mismatch_error_ws(&self.name));
        }
        let element_width = fixed_element_width(kind).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-fixed not valid for {:?} on column '{}'",
                kind,
                String::from_utf8_lossy(&self.name)
            )
        })?;
        let expected_rows = if kind_supports_sparse_nulls(kind) {
            info.non_null as usize
        } else {
            info.rows as usize
        };
        let expected_bytes = expected_rows.saturating_mul(element_width);
        if !matches!(self.values, QwpWsColumnValues::ArrowFixed { .. }) {
            if !self.is_fresh() {
                return Err(arrow_bulk_mixing_error(&self.name));
            }
            self.values = QwpWsColumnValues::ArrowFixed {
                bitmap: None,
                values: Vec::new(),
                row_count: 0,
            };
        }
        let prior_rows = match &self.values {
            QwpWsColumnValues::ArrowFixed { row_count, .. } => *row_count,
            _ => unreachable!(),
        };
        let (new_row_count, new_non_null) =
            self.precheck_arrow_batch_overflows(prior_rows, &info)?;
        let QwpWsColumnValues::ArrowFixed {
            bitmap,
            values,
            row_count,
        } = &mut self.values
        else {
            unreachable!()
        };
        let prior_len = values.len();
        if let Err(e) = write_values(values) {
            values.truncate(prior_len);
            return Err(e);
        }
        let written = values.len() - prior_len;
        if written != expected_bytes {
            values.truncate(prior_len);
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-fixed expects {} bytes ({} rows × {}), got {}",
                expected_bytes,
                expected_rows,
                element_width,
                written
            ));
        }
        extend_qwp_bitmap(bitmap, prior_rows as usize, info.bitmap, info.rows as usize);
        *row_count = new_row_count;
        self.non_null_count = new_non_null;
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn append_arrow_varlen_batch<F>(
        &mut self,
        kind: ColumnKind,
        info: ArrowBatchInfo<'_>,
        write: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u32>, &mut Vec<u8>) -> crate::Result<()>,
    {
        if self.kind != kind {
            return Err(type_mismatch_error_ws(&self.name));
        }
        if !matches!(self.values, QwpWsColumnValues::ArrowVarLen { .. }) {
            if !self.is_fresh() {
                return Err(arrow_bulk_mixing_error(&self.name));
            }
            self.values = QwpWsColumnValues::ArrowVarLen {
                bitmap: None,
                offsets: vec![0u32],
                data: Vec::new(),
                row_count: 0,
            };
        }
        let prior_rows = match &self.values {
            QwpWsColumnValues::ArrowVarLen { row_count, .. } => *row_count,
            _ => unreachable!(),
        };
        let (new_row_count, new_non_null) =
            self.precheck_arrow_batch_overflows(prior_rows, &info)?;
        let QwpWsColumnValues::ArrowVarLen {
            bitmap,
            offsets,
            data,
            row_count,
        } = &mut self.values
        else {
            unreachable!()
        };
        let prior_offsets_len = offsets.len();
        let prior_data_len = data.len();
        if let Err(e) = write(offsets, data) {
            offsets.truncate(prior_offsets_len);
            data.truncate(prior_data_len);
            return Err(e);
        }
        let pushed = offsets.len() - prior_offsets_len;
        if pushed != info.non_null as usize {
            offsets.truncate(prior_offsets_len);
            data.truncate(prior_data_len);
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-varlen expects {} offsets pushed for {} non-null rows, got {}",
                info.non_null,
                info.non_null,
                pushed
            ));
        }
        extend_qwp_bitmap(bitmap, prior_rows as usize, info.bitmap, info.rows as usize);
        *row_count = new_row_count;
        self.non_null_count = new_non_null;
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn append_arrow_bool_batch(
        &mut self,
        batch_packed_bits: &[u8],
        info: ArrowBatchInfo<'_>,
    ) -> crate::Result<()> {
        if self.kind != ColumnKind::Bool {
            return Err(type_mismatch_error_ws(&self.name));
        }
        if batch_packed_bits.len() != (info.rows as usize).div_ceil(8) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-bool expects {} packed bytes for {} rows, got {}",
                (info.rows as usize).div_ceil(8),
                info.rows,
                batch_packed_bits.len()
            ));
        }
        if !matches!(self.values, QwpWsColumnValues::ArrowBool { .. }) {
            if !self.is_fresh() {
                return Err(arrow_bulk_mixing_error(&self.name));
            }
            self.values = QwpWsColumnValues::ArrowBool {
                bitmap: None,
                packed_bits: Vec::new(),
                row_count: 0,
            };
        }
        let prior_rows = match &self.values {
            QwpWsColumnValues::ArrowBool { row_count, .. } => *row_count,
            _ => unreachable!(),
        };
        let (new_row_count, new_non_null) =
            self.precheck_arrow_batch_overflows(prior_rows, &info)?;
        let QwpWsColumnValues::ArrowBool {
            bitmap,
            packed_bits,
            row_count,
        } = &mut self.values
        else {
            unreachable!()
        };
        append_packed_bits(
            packed_bits,
            prior_rows as usize,
            batch_packed_bits,
            info.rows as usize,
        );
        extend_qwp_bitmap(bitmap, prior_rows as usize, info.bitmap, info.rows as usize);
        *row_count = new_row_count;
        self.non_null_count = new_non_null;
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn append_arrow_symbol_batch(
        &mut self,
        batch_keys: &[u32],
        batch_dict_entries: &[(u32, u32)],
        batch_dict_data: &[u8],
        info: ArrowBatchInfo<'_>,
    ) -> crate::Result<()> {
        if self.kind != ColumnKind::Symbol {
            return Err(type_mismatch_error_ws(&self.name));
        }
        if batch_keys.len() != info.rows as usize {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-symbol expects {} keys, got {}",
                info.rows,
                batch_keys.len()
            ));
        }
        if !matches!(self.values, QwpWsColumnValues::ArrowSymbol { .. }) {
            if !self.is_fresh() {
                return Err(arrow_bulk_mixing_error(&self.name));
            }
            self.values = QwpWsColumnValues::ArrowSymbol {
                bitmap: None,
                dict: Vec::new(),
                dict_lookup: QwpWsLocalSymbolLookup::default(),
                dict_data: Vec::new(),
                keys: Vec::new(),
                row_count: 0,
            };
        }
        let prior_rows = match &self.values {
            QwpWsColumnValues::ArrowSymbol { row_count, .. } => *row_count,
            _ => unreachable!(),
        };
        let (new_row_count, new_non_null) =
            self.precheck_arrow_batch_overflows(prior_rows, &info)?;
        let QwpWsColumnValues::ArrowSymbol {
            bitmap,
            dict,
            dict_lookup,
            dict_data,
            keys,
            row_count,
        } = &mut self.values
        else {
            unreachable!()
        };
        let mut batch_to_local: Vec<u32> = Vec::with_capacity(batch_dict_entries.len());
        for &(off, len) in batch_dict_entries {
            let bytes = &batch_dict_data[off as usize..(off + len) as usize];
            let hash = qwp_ws_symbol_hash(bytes);
            let local_id = if let Some(existing) = dict_lookup.get(hash, bytes, dict, dict_data) {
                existing
            } else {
                let id = checked_qwp_push_index(dict.len(), "QWP/WS symbol dictionary length")?;
                let data_offset =
                    QwpBuffer::checked_arena_offset(dict_data.len(), bytes.len(), "QWP/WS symbol")?;
                let qwp_len = checked_qwp_u32(bytes.len(), "QWP/WS symbol length")?;
                dict_data.extend_from_slice(bytes);
                dict.push(QwpWsSymbolEntry {
                    offset: data_offset,
                    len: qwp_len,
                });
                dict_lookup.insert(hash, id);
                id
            };
            batch_to_local.push(local_id);
        }
        keys.reserve(info.rows as usize);
        for (row_idx, &batch_key) in batch_keys.iter().enumerate() {
            let is_null = info.bitmap.is_some_and(|nb| nb.is_null(row_idx));
            if is_null {
                keys.push(0);
                continue;
            }
            let mapped = batch_to_local
                .get(batch_key as usize)
                .copied()
                .ok_or_else(|| {
                    error::fmt!(
                        InvalidApiCall,
                        "QWP/WS arrow-symbol key {} out of range (dict size {})",
                        batch_key,
                        batch_to_local.len()
                    )
                })?;
            keys.push(mapped);
        }
        extend_qwp_bitmap(bitmap, prior_rows as usize, info.bitmap, info.rows as usize);
        *row_count = new_row_count;
        self.non_null_count = new_non_null;
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn append_arrow_decimal_batch<F>(
        &mut self,
        kind: ColumnKind,
        spec: ArrowDecimalSpec,
        info: ArrowBatchInfo<'_>,
        write_values: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        if self.kind != kind {
            return Err(type_mismatch_error_ws(&self.name));
        }
        if !matches!(
            kind,
            ColumnKind::Decimal | ColumnKind::Decimal64 | ColumnKind::Decimal128
        ) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-decimal only valid for Decimal / Decimal64 / Decimal128, got {:?}",
                kind
            ));
        }
        let expected_bytes = (info.non_null as usize).saturating_mul(spec.element_width as usize);
        if !matches!(self.values, QwpWsColumnValues::ArrowDecimal { .. }) {
            if !self.is_fresh() {
                return Err(arrow_bulk_mixing_error(&self.name));
            }
            self.values = QwpWsColumnValues::ArrowDecimal {
                bitmap: None,
                values: Vec::new(),
                decimal_scale: spec.scale,
                element_width: spec.element_width,
                row_count: 0,
            };
        }
        let prior_rows = match &self.values {
            QwpWsColumnValues::ArrowDecimal { row_count, .. } => *row_count,
            _ => unreachable!(),
        };
        let (new_row_count, new_non_null) =
            self.precheck_arrow_batch_overflows(prior_rows, &info)?;
        let QwpWsColumnValues::ArrowDecimal {
            bitmap,
            values,
            decimal_scale,
            element_width: stored_width,
            row_count,
        } = &mut self.values
        else {
            unreachable!()
        };
        if *stored_width != spec.element_width {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-decimal element width mismatch on '{}': existing={}, batch={}",
                String::from_utf8_lossy(&self.name),
                stored_width,
                spec.element_width
            ));
        }
        if info.non_null > 0
            && *decimal_scale != QWP_DECIMAL_SCALE_UNSET
            && *decimal_scale != spec.scale
        {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-decimal scale changed on '{}': existing={}, batch={}",
                String::from_utf8_lossy(&self.name),
                decimal_scale,
                spec.scale
            ));
        }
        let prior_len = values.len();
        if let Err(e) = write_values(values) {
            values.truncate(prior_len);
            return Err(e);
        }
        let written = values.len() - prior_len;
        if written != expected_bytes {
            values.truncate(prior_len);
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-decimal expects {} value bytes for {} non-null rows of width {}, got {}",
                expected_bytes,
                info.non_null,
                spec.element_width,
                written
            ));
        }
        if info.non_null > 0 {
            *decimal_scale = spec.scale;
        }
        extend_qwp_bitmap(bitmap, prior_rows as usize, info.bitmap, info.rows as usize);
        *row_count = new_row_count;
        self.non_null_count = new_non_null;
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn append_arrow_geohash_batch<F>(
        &mut self,
        precision_bits: u8,
        info: ArrowBatchInfo<'_>,
        write_values: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        if self.kind != ColumnKind::Geohash {
            return Err(type_mismatch_error_ws(&self.name));
        }
        let element_width = geohash_bytes_per_value(precision_bits);
        let expected_bytes = (info.non_null as usize).saturating_mul(element_width);
        if !matches!(self.values, QwpWsColumnValues::ArrowGeohash { .. }) {
            if !self.is_fresh() {
                return Err(arrow_bulk_mixing_error(&self.name));
            }
            self.values = QwpWsColumnValues::ArrowGeohash {
                bitmap: None,
                values: Vec::new(),
                precision_bits,
                row_count: 0,
            };
        }
        let prior_rows = match &self.values {
            QwpWsColumnValues::ArrowGeohash { row_count, .. } => *row_count,
            _ => unreachable!(),
        };
        let (new_row_count, new_non_null) =
            self.precheck_arrow_batch_overflows(prior_rows, &info)?;
        let QwpWsColumnValues::ArrowGeohash {
            bitmap,
            values,
            precision_bits: stored_precision,
            row_count,
        } = &mut self.values
        else {
            unreachable!()
        };
        if *stored_precision != precision_bits {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-geohash precision mismatch on '{}': existing={}, batch={}",
                String::from_utf8_lossy(&self.name),
                stored_precision,
                precision_bits
            ));
        }
        let prior_len = values.len();
        if let Err(e) = write_values(values) {
            values.truncate(prior_len);
            return Err(e);
        }
        let written = values.len() - prior_len;
        if written != expected_bytes {
            values.truncate(prior_len);
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-geohash expects {} value bytes for {} non-null rows of width {}, got {}",
                expected_bytes,
                info.non_null,
                element_width,
                written
            ));
        }
        extend_qwp_bitmap(bitmap, prior_rows as usize, info.bitmap, info.rows as usize);
        *row_count = new_row_count;
        self.non_null_count = new_non_null;
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn append_arrow_array_batch<F>(
        &mut self,
        kind: ColumnKind,
        info: ArrowBatchInfo<'_>,
        write_data: F,
    ) -> crate::Result<()>
    where
        F: FnOnce(&mut Vec<u8>) -> crate::Result<()>,
    {
        if self.kind != kind {
            return Err(type_mismatch_error_ws(&self.name));
        }
        if !matches!(kind, ColumnKind::DoubleArray | ColumnKind::LongArray) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow-array only valid for DoubleArray / LongArray, got {:?}",
                kind
            ));
        }
        if !matches!(self.values, QwpWsColumnValues::ArrowArray { .. }) {
            if !self.is_fresh() {
                return Err(arrow_bulk_mixing_error(&self.name));
            }
            self.values = QwpWsColumnValues::ArrowArray {
                bitmap: None,
                data: Vec::new(),
                row_count: 0,
            };
        }
        let prior_rows = match &self.values {
            QwpWsColumnValues::ArrowArray { row_count, .. } => *row_count,
            _ => unreachable!(),
        };
        let (new_row_count, new_non_null) =
            self.precheck_arrow_batch_overflows(prior_rows, &info)?;
        let QwpWsColumnValues::ArrowArray {
            bitmap,
            data,
            row_count,
        } = &mut self.values
        else {
            unreachable!()
        };
        let prior_len = data.len();
        if let Err(e) = write_data(data) {
            data.truncate(prior_len);
            return Err(e);
        }
        extend_qwp_bitmap(bitmap, prior_rows as usize, info.bitmap, info.rows as usize);
        *row_count = new_row_count;
        self.non_null_count = new_non_null;
        Ok(())
    }

    fn encode(&self, row_count: usize, globals: &[u64], out: &mut Vec<u8>) -> crate::Result<()> {
        out.push(u8::from(self.uses_null_bitmap(row_count)));
        if self.uses_null_bitmap(row_count) {
            self.values.encode_null_bitmap(row_count, out)?;
        }
        self.values.encode(row_count, globals, out)
    }
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpWsColumnValues {
    fn new(kind: ColumnKind) -> Self {
        match kind {
            ColumnKind::Bool => Self::Bool { cells: Vec::new() },
            ColumnKind::I8 => Self::I8 { cells: Vec::new() },
            ColumnKind::I16 => Self::I16 { cells: Vec::new() },
            ColumnKind::I32 => Self::I32 { cells: Vec::new() },
            ColumnKind::I64 => Self::I64 { cells: Vec::new() },
            ColumnKind::F32 => Self::F32 { cells: Vec::new() },
            ColumnKind::F64 => Self::F64 { cells: Vec::new() },
            ColumnKind::TimestampMicros => Self::TimestampMicros { cells: Vec::new() },
            ColumnKind::TimestampNanos => Self::TimestampNanos { cells: Vec::new() },
            ColumnKind::String => Self::String {
                cells: Vec::new(),
                data: Vec::new(),
            },
            ColumnKind::Symbol => Self::Symbol {
                cells: Vec::new(),
                dict: Vec::new(),
                lookup: QwpWsLocalSymbolLookup::default(),
                data: Vec::new(),
            },
            ColumnKind::Decimal => Self::Decimal {
                cells: Vec::new(),
                decimal_scale: QWP_DECIMAL_SCALE_UNSET,
            },
            ColumnKind::Decimal64 => Self::Decimal64 {
                cells: Vec::new(),
                decimal_scale: QWP_DECIMAL_SCALE_UNSET,
            },
            ColumnKind::Decimal128 => Self::Decimal128 {
                cells: Vec::new(),
                decimal_scale: QWP_DECIMAL_SCALE_UNSET,
            },
            ColumnKind::DoubleArray => Self::DoubleArray {
                cells: Vec::new(),
                data: Vec::new(),
            },
            ColumnKind::Uuid => Self::Uuid { cells: Vec::new() },
            ColumnKind::Long256 => Self::Long256 {
                cells: Vec::new(),
                data: Vec::new(),
            },
            ColumnKind::Ipv4 => Self::Ipv4 { cells: Vec::new() },
            ColumnKind::Date => Self::Date { cells: Vec::new() },
            ColumnKind::Char => Self::Char { cells: Vec::new() },
            ColumnKind::Binary => Self::Binary {
                cells: Vec::new(),
                data: Vec::new(),
            },
            ColumnKind::Geohash => Self::Geohash {
                cells: Vec::new(),
                precision_bits: 0,
            },
            ColumnKind::LongArray => Self::LongArray {
                cells: Vec::new(),
                data: Vec::new(),
            },
        }
    }

    fn clear_rows(&mut self) {
        match self {
            Self::Bool { cells } => cells.clear(),
            Self::I8 { cells } => cells.clear(),
            Self::I16 { cells } => cells.clear(),
            Self::I32 { cells } => cells.clear(),
            Self::I64 { cells } => cells.clear(),
            Self::F32 { cells } => cells.clear(),
            Self::F64 { cells } => cells.clear(),
            Self::TimestampMicros { cells } => cells.clear(),
            Self::TimestampNanos { cells } => cells.clear(),
            Self::String { cells, data }
            | Self::DoubleArray { cells, data }
            | Self::Long256 { cells, data }
            | Self::Binary { cells, data }
            | Self::LongArray { cells, data } => {
                cells.clear();
                data.clear();
            }
            Self::Uuid { cells } => cells.clear(),
            Self::Ipv4 { cells } => cells.clear(),
            Self::Date { cells } => cells.clear(),
            Self::Char { cells } => cells.clear(),
            Self::Geohash { cells, .. } => cells.clear(),
            Self::Symbol {
                cells,
                dict,
                lookup,
                data,
            } => {
                cells.clear();
                dict.clear();
                lookup.clear();
                data.clear();
            }
            Self::Decimal { cells, .. }
            | Self::Decimal64 { cells, .. }
            | Self::Decimal128 { cells, .. } => {
                cells.clear();
            }
            #[cfg(feature = "arrow")]
            Self::ArrowFixed {
                bitmap,
                values,
                row_count,
            }
            | Self::ArrowGeohash {
                bitmap,
                values,
                row_count,
                ..
            }
            | Self::ArrowDecimal {
                bitmap,
                values,
                row_count,
                ..
            } => {
                bitmap.take();
                values.clear();
                *row_count = 0;
            }
            #[cfg(feature = "arrow")]
            Self::ArrowVarLen {
                bitmap,
                offsets,
                data,
                row_count,
            } => {
                bitmap.take();
                offsets.clear();
                data.clear();
                *row_count = 0;
            }
            #[cfg(feature = "arrow")]
            Self::ArrowBool {
                bitmap,
                packed_bits,
                row_count,
            } => {
                bitmap.take();
                packed_bits.clear();
                *row_count = 0;
            }
            #[cfg(feature = "arrow")]
            Self::ArrowSymbol {
                bitmap,
                dict,
                dict_lookup,
                dict_data,
                keys,
                row_count,
            } => {
                bitmap.take();
                dict.clear();
                dict_lookup.clear();
                dict_data.clear();
                keys.clear();
                *row_count = 0;
            }
            #[cfg(feature = "arrow")]
            Self::ArrowArray {
                bitmap,
                data,
                row_count,
            } => {
                bitmap.take();
                data.clear();
                *row_count = 0;
            }
        }
    }

    fn capacity(&self) -> usize {
        match self {
            Self::Bool { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<bool>>(),
            Self::I8 { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<i8>>(),
            Self::I16 { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<i16>>(),
            Self::I32 { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<i32>>(),
            Self::I64 { cells }
            | Self::TimestampMicros { cells }
            | Self::TimestampNanos { cells } => {
                cells.capacity() * std::mem::size_of::<QwpWsCell<i64>>()
            }
            Self::F32 { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<f32>>(),
            Self::F64 { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<f64>>(),
            Self::String { cells, data }
            | Self::DoubleArray { cells, data }
            | Self::Long256 { cells, data } => {
                cells.capacity() * std::mem::size_of::<QwpWsSliceCell>() + data.capacity()
            }
            Self::Uuid { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<(u64, u64)>>(),
            Self::Ipv4 { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<u32>>(),
            Self::Date { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<i64>>(),
            Self::Char { cells } => cells.capacity() * std::mem::size_of::<QwpWsCell<u16>>(),
            Self::Binary { cells, data } => {
                cells.capacity() * std::mem::size_of::<QwpWsSliceCell>() + data.capacity()
            }
            Self::Geohash { cells, .. } => cells.capacity() * std::mem::size_of::<QwpWsCell<u64>>(),
            Self::LongArray { cells, data } => {
                cells.capacity() * std::mem::size_of::<QwpWsSliceCell>() + data.capacity()
            }
            Self::Symbol {
                cells, dict, data, ..
            } => {
                cells.capacity() * std::mem::size_of::<QwpWsSymbolCell>()
                    + dict.capacity() * std::mem::size_of::<QwpWsSymbolEntry>()
                    + data.capacity()
            }
            Self::Decimal { cells, .. }
            | Self::Decimal64 { cells, .. }
            | Self::Decimal128 { cells, .. } => {
                cells.capacity() * std::mem::size_of::<QwpWsDecimalCell>()
            }
            #[cfg(feature = "arrow")]
            Self::ArrowFixed { bitmap, values, .. }
            | Self::ArrowGeohash { bitmap, values, .. }
            | Self::ArrowDecimal { bitmap, values, .. } => {
                bitmap.as_ref().map(|b| b.capacity()).unwrap_or(0) + values.capacity()
            }
            #[cfg(feature = "arrow")]
            Self::ArrowVarLen {
                bitmap,
                offsets,
                data,
                ..
            } => {
                bitmap.as_ref().map(|b| b.capacity()).unwrap_or(0)
                    + offsets.capacity() * std::mem::size_of::<u32>()
                    + data.capacity()
            }
            #[cfg(feature = "arrow")]
            Self::ArrowBool {
                bitmap,
                packed_bits,
                ..
            } => bitmap.as_ref().map(|b| b.capacity()).unwrap_or(0) + packed_bits.capacity(),
            #[cfg(feature = "arrow")]
            Self::ArrowSymbol {
                bitmap,
                dict,
                dict_data,
                keys,
                ..
            } => {
                bitmap.as_ref().map(|b| b.capacity()).unwrap_or(0)
                    + dict.capacity() * std::mem::size_of::<QwpWsSymbolEntry>()
                    + dict_data.capacity()
                    + keys.capacity() * std::mem::size_of::<u32>()
            }
            #[cfg(feature = "arrow")]
            Self::ArrowArray { bitmap, data, .. } => {
                bitmap.as_ref().map(|b| b.capacity()).unwrap_or(0) + data.capacity()
            }
        }
    }

    fn rollback_row(&mut self, row_idx: u32) -> bool {
        match self {
            Self::Bool { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::I8 { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::I16 { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::I32 { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::I64 { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::F32 { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::F64 { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::TimestampMicros { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::TimestampNanos { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::String { cells, data }
            | Self::DoubleArray { cells, data }
            | Self::Long256 { cells, data } => {
                if let Some(cell) = pop_slice_cell_for_row(cells, row_idx) {
                    data.truncate(cell.offset as usize);
                    true
                } else {
                    false
                }
            }
            Self::Uuid { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::Ipv4 { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::Date { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::Char { cells } => pop_value_cell_for_row(cells, row_idx),
            Self::Binary { cells, data } => {
                if let Some(cell) = pop_slice_cell_for_row(cells, row_idx) {
                    data.truncate(cell.offset as usize);
                    true
                } else {
                    false
                }
            }
            Self::Geohash { cells, .. } => pop_value_cell_for_row(cells, row_idx),
            Self::LongArray { cells, data } => {
                if let Some(cell) = pop_slice_cell_for_row(cells, row_idx) {
                    data.truncate(cell.offset as usize);
                    true
                } else {
                    false
                }
            }
            Self::Symbol {
                cells,
                dict,
                lookup,
                data,
            } => {
                let Some(cell) = pop_symbol_cell_for_row(cells, row_idx) else {
                    return false;
                };
                if cell.is_new
                    && let Some(entry) = dict.pop()
                {
                    debug_assert_eq!(cell.local_id as usize, dict.len());
                    data.truncate(entry.offset as usize);
                    lookup.retain_local_ids_below(dict.len());
                }
                true
            }
            Self::Decimal {
                cells,
                decimal_scale,
            }
            | Self::Decimal64 {
                cells,
                decimal_scale,
            }
            | Self::Decimal128 {
                cells,
                decimal_scale,
            } => {
                let Some(cell) = pop_decimal_cell_for_row(cells, row_idx) else {
                    return false;
                };
                if cell.value.is_some() {
                    if cells.is_empty() {
                        *decimal_scale = 0;
                    } else {
                        *decimal_scale = cells
                            .iter()
                            .filter_map(|cell| cell.value.map(|value| value.scale))
                            .max()
                            .unwrap_or(0);
                    }
                    true
                } else {
                    false
                }
            }
            #[cfg(feature = "arrow")]
            Self::ArrowFixed { .. }
            | Self::ArrowVarLen { .. }
            | Self::ArrowBool { .. }
            | Self::ArrowSymbol { .. }
            | Self::ArrowDecimal { .. }
            | Self::ArrowGeohash { .. }
            | Self::ArrowArray { .. } => false,
        }
    }

    fn estimated_data_len(&self, row_count: usize) -> usize {
        match self {
            Self::Bool { .. } => packed_bytes(row_count),
            Self::I8 { .. } => row_count,
            Self::I16 { .. } => row_count.saturating_mul(2),
            Self::I32 { .. } => row_count.saturating_mul(4),
            Self::I64 { .. } | Self::F64 { .. } => row_count.saturating_mul(8),
            Self::F32 { .. } => row_count.saturating_mul(4),
            Self::TimestampMicros { cells } | Self::TimestampNanos { cells } => {
                cells.len().saturating_mul(8)
            }
            Self::String { cells, data } => (cells.len() + 1).saturating_mul(4) + data.len(),
            Self::Symbol { cells, .. } => cells
                .iter()
                .map(|cell| qwp_varint_size(cell.local_id as u64))
                .sum(),
            Self::Decimal { cells, .. } => {
                1 + cells
                    .iter()
                    .filter(|cell| cell.value.is_some())
                    .count()
                    .saturating_mul(QWP_DECIMAL_MAG_BYTES)
            }
            Self::Decimal64 { cells, .. } => {
                1 + cells
                    .iter()
                    .filter(|cell| cell.value.is_some())
                    .count()
                    .saturating_mul(8)
            }
            Self::Decimal128 { cells, .. } => {
                1 + cells
                    .iter()
                    .filter(|cell| cell.value.is_some())
                    .count()
                    .saturating_mul(16)
            }
            Self::DoubleArray { data, .. } => data.len(),
            Self::Uuid { cells } => cells.len().saturating_mul(16),
            Self::Long256 { data, .. } => data.len(),
            Self::Ipv4 { cells } => cells.len().saturating_mul(4),
            Self::Date { cells } => cells.len().saturating_mul(8),
            Self::Char { .. } => row_count.saturating_mul(2),
            Self::Binary { cells, data } => (cells.len() + 1).saturating_mul(4) + data.len(),
            Self::Geohash {
                cells,
                precision_bits,
            } => {
                1 + cells
                    .len()
                    .saturating_mul(geohash_bytes_per_value(*precision_bits))
            }
            Self::LongArray { data, .. } => data.len(),
            #[cfg(feature = "arrow")]
            Self::ArrowFixed { values, .. }
            | Self::ArrowGeohash { values, .. }
            | Self::ArrowDecimal { values, .. } => values.len(),
            #[cfg(feature = "arrow")]
            Self::ArrowVarLen { offsets, data, .. } => offsets.len().saturating_mul(4) + data.len(),
            #[cfg(feature = "arrow")]
            Self::ArrowBool { packed_bits, .. } => packed_bits.len(),
            #[cfg(feature = "arrow")]
            Self::ArrowSymbol { keys, .. } => keys.iter().map(|&k| qwp_varint_size(k as u64)).sum(),
            #[cfg(feature = "arrow")]
            Self::ArrowArray { data, .. } => data.len(),
        }
    }

    fn encode_null_bitmap(&self, row_count: usize, out: &mut Vec<u8>) -> crate::Result<()> {
        #[cfg(feature = "arrow")]
        if let Some(prebuilt) = self.prebuilt_qwp_bitmap(row_count)? {
            out.extend_from_slice(prebuilt);
            return Ok(());
        }
        let mut packed = 0u8;
        let mut bit_idx = 0u8;
        let mut cursor = self.first_row_cursor();
        for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
            let present = if let Some(cell_row) = self.row_at_cursor(cursor) {
                if cell_row == row_idx {
                    let is_non_null = !self.value_at_cursor_is_null(cursor);
                    cursor += 1;
                    is_non_null
                } else {
                    false
                }
            } else {
                false
            };
            if !present {
                packed |= 1 << bit_idx;
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
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn prebuilt_qwp_bitmap(&self, row_count: usize) -> crate::Result<Option<&[u8]>> {
        let (bitmap, arrow_rows) = match self {
            Self::ArrowFixed {
                bitmap, row_count, ..
            }
            | Self::ArrowVarLen {
                bitmap, row_count, ..
            }
            | Self::ArrowBool {
                bitmap, row_count, ..
            }
            | Self::ArrowSymbol {
                bitmap, row_count, ..
            }
            | Self::ArrowDecimal {
                bitmap, row_count, ..
            }
            | Self::ArrowGeohash {
                bitmap, row_count, ..
            }
            | Self::ArrowArray {
                bitmap, row_count, ..
            } => (bitmap.as_deref(), *row_count as usize),
            _ => return Ok(None),
        };
        if arrow_rows != row_count {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WS arrow column row mismatch: arrow holds {} rows, table has {}",
                arrow_rows,
                row_count
            ));
        }
        Ok(bitmap)
    }

    fn encode(&self, row_count: usize, globals: &[u64], out: &mut Vec<u8>) -> crate::Result<()> {
        match self {
            Self::Bool { cells } => {
                let mut cursor = 0usize;
                let mut packed = 0u8;
                let mut bit_idx = 0u8;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).is_some_and(|cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            false
                        }
                    });
                    if value {
                        packed |= 1 << bit_idx;
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
                Ok(())
            }
            Self::I8 { cells } => {
                let mut cursor = 0usize;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).map_or(0i8, |cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            0
                        }
                    });
                    out.push(value as u8);
                }
                Ok(())
            }
            Self::I16 { cells } => {
                let mut cursor = 0usize;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).map_or(0i16, |cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            0
                        }
                    });
                    out.extend_from_slice(&value.to_le_bytes());
                }
                Ok(())
            }
            Self::I32 { cells } => {
                let mut cursor = 0usize;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).map_or(i32::MIN, |cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            i32::MIN
                        }
                    });
                    out.extend_from_slice(&value.to_le_bytes());
                }
                Ok(())
            }
            Self::I64 { cells } => {
                let mut cursor = 0usize;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).map_or(i64::MIN, |cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            i64::MIN
                        }
                    });
                    out.extend_from_slice(&value.to_le_bytes());
                }
                Ok(())
            }
            Self::F32 { cells } => {
                let mut cursor = 0usize;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).map_or(f32::NAN, |cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            f32::NAN
                        }
                    });
                    out.extend_from_slice(&value.to_le_bytes());
                }
                Ok(())
            }
            Self::F64 { cells } => {
                let mut cursor = 0usize;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).map_or(f64::NAN, |cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            f64::NAN
                        }
                    });
                    out.extend_from_slice(&value.to_le_bytes());
                }
                Ok(())
            }
            Self::TimestampMicros { cells } | Self::TimestampNanos { cells } => {
                for cell in cells {
                    out.extend_from_slice(&cell.value.to_le_bytes());
                }
                Ok(())
            }
            Self::String { cells, data } => {
                let offsets_start = out.len();
                let offset_count = checked_qwp_usize_add(cells.len(), 1, "string offset count")?;
                let offset_table_len =
                    checked_qwp_usize_mul(offset_count, 4, "string offset table")?;
                let offsets_end =
                    checked_qwp_usize_add(offsets_start, offset_table_len, "string offset table")?;
                out.resize(offsets_end, 0);
                out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());
                let mut cumulative: usize = 0;
                for (idx, cell) in cells.iter().enumerate() {
                    let range = cell.offset as usize..(cell.offset + cell.len) as usize;
                    out.extend_from_slice(&data[range]);
                    cumulative = checked_qwp_usize_add(
                        cumulative,
                        cell.len as usize,
                        "string column bytes",
                    )?;
                    let offset_u32 = checked_qwp_u32(cumulative, "string column offset")?;
                    let pos = offsets_start + (idx + 1) * 4;
                    out[pos..pos + 4].copy_from_slice(&offset_u32.to_le_bytes());
                }
                Ok(())
            }
            Self::Symbol { cells, .. } => {
                for cell in cells {
                    let gid = globals.get(cell.local_id as usize).copied().ok_or_else(|| {
                        error::fmt!(
                            InvalidApiCall,
                            "internal QWP/WS encoder error: missing global symbol id for column-local index {}",
                            cell.local_id
                        )
                    })?;
                    write_qwp_varint(out, gid);
                }
                Ok(())
            }
            Self::Decimal {
                cells,
                decimal_scale,
            } => {
                let scale_byte = if *decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                    0
                } else {
                    *decimal_scale
                };
                out.push(scale_byte);
                for cell in cells {
                    if let Some(value) = cell.value {
                        out.extend_from_slice(&value.wire_bytes_with_scale(*decimal_scale)?);
                    }
                }
                Ok(())
            }
            Self::Decimal64 {
                cells,
                decimal_scale,
            } => {
                let scale_byte = if *decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                    0
                } else {
                    *decimal_scale
                };
                out.push(scale_byte);
                for cell in cells {
                    if let Some(value) = cell.value {
                        let bytes = value.wire_bytes_with_scale(*decimal_scale)?;
                        let low = narrow_decimal_le_fits(&bytes, 8)
                            .ok_or_else(|| decimal_fit_error(64))?;
                        out.extend_from_slice(low);
                    }
                }
                Ok(())
            }
            Self::Decimal128 {
                cells,
                decimal_scale,
            } => {
                let scale_byte = if *decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                    0
                } else {
                    *decimal_scale
                };
                out.push(scale_byte);
                for cell in cells {
                    if let Some(value) = cell.value {
                        let bytes = value.wire_bytes_with_scale(*decimal_scale)?;
                        let low = narrow_decimal_le_fits(&bytes, 16)
                            .ok_or_else(|| decimal_fit_error(128))?;
                        out.extend_from_slice(low);
                    }
                }
                Ok(())
            }
            Self::DoubleArray { cells, data } => {
                for cell in cells {
                    let range = cell.offset as usize..(cell.offset + cell.len) as usize;
                    out.extend_from_slice(&data[range]);
                }
                Ok(())
            }
            Self::Uuid { cells } => {
                for cell in cells {
                    out.extend_from_slice(&cell.value.0.to_le_bytes());
                    out.extend_from_slice(&cell.value.1.to_le_bytes());
                }
                Ok(())
            }
            Self::Long256 { cells, data } => {
                for cell in cells {
                    let range = cell.offset as usize..(cell.offset + cell.len) as usize;
                    out.extend_from_slice(&data[range]);
                }
                Ok(())
            }
            Self::Ipv4 { cells } => {
                for cell in cells {
                    out.extend_from_slice(&cell.value.to_le_bytes());
                }
                Ok(())
            }
            Self::Date { cells } => {
                for cell in cells {
                    out.extend_from_slice(&cell.value.to_le_bytes());
                }
                Ok(())
            }
            Self::Char { cells } => {
                let mut cursor = 0usize;
                for row_idx in 0..checked_qwp_u32(row_count, "QWP/WS row count")? {
                    let value = cells.get(cursor).map_or(0u16, |cell| {
                        if cell.row_idx == row_idx {
                            cursor += 1;
                            cell.value
                        } else {
                            0
                        }
                    });
                    out.extend_from_slice(&value.to_le_bytes());
                }
                Ok(())
            }
            Self::Binary { cells, data } => {
                let offsets_start = out.len();
                let offset_count = checked_qwp_usize_add(cells.len(), 1, "binary offset count")?;
                let offset_table_len =
                    checked_qwp_usize_mul(offset_count, 4, "binary offset table")?;
                let offsets_end =
                    checked_qwp_usize_add(offsets_start, offset_table_len, "binary offset table")?;
                out.resize(offsets_end, 0);
                out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());
                let mut cumulative: usize = 0;
                for (idx, cell) in cells.iter().enumerate() {
                    let range = cell.offset as usize..(cell.offset + cell.len) as usize;
                    out.extend_from_slice(&data[range]);
                    cumulative = checked_qwp_usize_add(
                        cumulative,
                        cell.len as usize,
                        "binary column bytes",
                    )?;
                    let offset_u32 = checked_qwp_u32(cumulative, "binary column offset")?;
                    let pos = offsets_start + (idx + 1) * 4;
                    out[pos..pos + 4].copy_from_slice(&offset_u32.to_le_bytes());
                }
                Ok(())
            }
            Self::Geohash {
                cells,
                precision_bits,
            } => {
                write_qwp_varint(out, *precision_bits as u64);
                let bytes_per_value = geohash_bytes_per_value(*precision_bits);
                for cell in cells {
                    let le = cell.value.to_le_bytes();
                    out.extend_from_slice(&le[..bytes_per_value]);
                }
                Ok(())
            }
            Self::LongArray { cells, data } => {
                for cell in cells {
                    let range = cell.offset as usize..(cell.offset + cell.len) as usize;
                    out.extend_from_slice(&data[range]);
                }
                Ok(())
            }
            #[cfg(feature = "arrow")]
            Self::ArrowFixed {
                values,
                row_count: arrow_rows,
                ..
            } => {
                ensure_arrow_row_count(*arrow_rows, row_count)?;
                out.extend_from_slice(values);
                Ok(())
            }
            #[cfg(feature = "arrow")]
            Self::ArrowVarLen {
                offsets,
                data,
                row_count: arrow_rows,
                ..
            } => {
                ensure_arrow_row_count(*arrow_rows, row_count)?;
                for offset in offsets {
                    out.extend_from_slice(&offset.to_le_bytes());
                }
                out.extend_from_slice(data);
                Ok(())
            }
            #[cfg(feature = "arrow")]
            Self::ArrowBool {
                packed_bits,
                row_count: arrow_rows,
                ..
            } => {
                ensure_arrow_row_count(*arrow_rows, row_count)?;
                out.extend_from_slice(packed_bits);
                Ok(())
            }
            #[cfg(feature = "arrow")]
            Self::ArrowSymbol {
                bitmap,
                keys,
                row_count: arrow_rows,
                ..
            } => {
                ensure_arrow_row_count(*arrow_rows, row_count)?;
                for (row_idx, &local_id) in keys.iter().enumerate() {
                    if let Some(bm) = bitmap.as_deref()
                        && (bm[row_idx / 8] >> (row_idx % 8)) & 1 == 1
                    {
                        continue;
                    }
                    let gid = globals
                        .get(local_id as usize)
                        .copied()
                        .ok_or_else(|| {
                            error::fmt!(
                                InvalidApiCall,
                                "internal QWP/WS encoder error: missing global symbol id for column-local index {}",
                                local_id
                            )
                        })?;
                    write_qwp_varint(out, gid);
                }
                Ok(())
            }
            #[cfg(feature = "arrow")]
            Self::ArrowDecimal {
                values,
                decimal_scale,
                row_count: arrow_rows,
                ..
            } => {
                ensure_arrow_row_count(*arrow_rows, row_count)?;
                out.push(*decimal_scale);
                out.extend_from_slice(values);
                Ok(())
            }
            #[cfg(feature = "arrow")]
            Self::ArrowGeohash {
                values,
                precision_bits,
                row_count: arrow_rows,
                ..
            } => {
                ensure_arrow_row_count(*arrow_rows, row_count)?;
                write_qwp_varint(out, *precision_bits as u64);
                out.extend_from_slice(values);
                Ok(())
            }
            #[cfg(feature = "arrow")]
            Self::ArrowArray {
                data,
                row_count: arrow_rows,
                ..
            } => {
                ensure_arrow_row_count(*arrow_rows, row_count)?;
                out.extend_from_slice(data);
                Ok(())
            }
        }
    }

    fn first_row_cursor(&self) -> usize {
        0
    }

    fn row_at_cursor(&self, cursor: usize) -> Option<u32> {
        match self {
            Self::Bool { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::I8 { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::I16 { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::I32 { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::I64 { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::F32 { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::F64 { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::TimestampMicros { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::TimestampNanos { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::String { cells, .. } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::Symbol { cells, .. } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::Decimal { cells, .. }
            | Self::Decimal64 { cells, .. }
            | Self::Decimal128 { cells, .. } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::DoubleArray { cells, .. } | Self::Long256 { cells, .. } => {
                cells.get(cursor).map(|cell| cell.row_idx)
            }
            Self::Uuid { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::Ipv4 { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::Date { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::Char { cells } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::Binary { cells, .. } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::Geohash { cells, .. } => cells.get(cursor).map(|cell| cell.row_idx),
            Self::LongArray { cells, .. } => cells.get(cursor).map(|cell| cell.row_idx),
            #[cfg(feature = "arrow")]
            Self::ArrowFixed { .. }
            | Self::ArrowVarLen { .. }
            | Self::ArrowBool { .. }
            | Self::ArrowSymbol { .. }
            | Self::ArrowDecimal { .. }
            | Self::ArrowGeohash { .. }
            | Self::ArrowArray { .. } => None,
        }
    }

    fn value_at_cursor_is_null(&self, cursor: usize) -> bool {
        match self {
            Self::Decimal { cells, .. }
            | Self::Decimal64 { cells, .. }
            | Self::Decimal128 { cells, .. } => {
                cells.get(cursor).is_some_and(|cell| cell.value.is_none())
            }
            _ => false,
        }
    }
}

#[cfg(feature = "_sender-qwp-ws")]
fn lowercase_ascii_bytes(name: &[u8]) -> Vec<u8> {
    name.iter().map(|byte| byte.to_ascii_lowercase()).collect()
}

#[cfg(feature = "_sender-qwp-ws")]
#[inline(always)]
fn packed_name(name: &[u8]) -> u64 {
    if name.len() > 8 {
        return 0;
    }
    let mut packed = 0u64;
    for (index, byte) in name.iter().enumerate() {
        packed |= u64::from(*byte) << (index * 8);
    }
    packed
}

#[cfg(feature = "_sender-qwp-ws")]
#[inline(always)]
fn packed_lower_ascii_name(name: &[u8]) -> u64 {
    if name.len() > 8 {
        return 0;
    }
    let mut packed = 0u64;
    for (index, byte) in name.iter().enumerate() {
        packed |= u64::from(byte.to_ascii_lowercase()) << (index * 8);
    }
    packed
}

#[cfg(feature = "_sender-qwp-ws")]
#[inline(always)]
fn names_equal_packed(left: &[u8], packed_left: u64, right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    if right.len() <= 8 {
        return packed_left == packed_name(right);
    }
    left == right
}

#[cfg(feature = "_sender-qwp-ws")]
#[inline(always)]
fn names_equal_lower_ascii(left_lower: &[u8], packed_left_lower: u64, right: &[u8]) -> bool {
    if left_lower.len() != right.len() {
        return false;
    }
    if right.len() <= 8 {
        return packed_left_lower == packed_lower_ascii_name(right);
    }
    left_lower
        .iter()
        .zip(right)
        .all(|(&left, &right)| left == right.to_ascii_lowercase())
}

#[cfg(feature = "_sender-qwp-ws")]
fn column_lookup_key(name: &[u8]) -> crate::Result<String> {
    let name = std::str::from_utf8(name).map_err(|err| {
        error::fmt!(
            InvalidApiCall,
            "internal QWP/WS column name is not UTF-8: {}",
            err
        )
    })?;
    Ok(name.to_lowercase())
}

#[cfg(feature = "_sender-qwp-ws")]
fn batched_type_change_error_ws(entry_name: &[u8]) -> crate::Error {
    if entry_name.is_empty() {
        error::fmt!(
            InvalidApiCall,
            "QWP/WebSocket designated timestamp changes type within a batched table"
        )
    } else {
        error::fmt!(
            InvalidApiCall,
            "QWP/WebSocket column {:?} changes type within a batched table",
            std::str::from_utf8(entry_name).unwrap_or("<invalid>")
        )
    }
}

#[cfg(feature = "_sender-qwp-ws")]
#[cfg(feature = "arrow")]
#[derive(Debug)]
pub(crate) struct ArrowBulkCtx {
    table_idx: usize,
    starting_rows: u32,
    table_mark: QwpWsTableRollbackMark,
    pre_column_marks: Vec<ArrowColRollbackMark>,
}

#[cfg(feature = "_sender-qwp-ws")]
#[cfg(feature = "arrow")]
#[derive(Clone, Debug)]
enum ArrowColRollbackMark {
    NonArrow {
        last_written_row: Option<u32>,
        non_null_count: u32,
    },
    ArrowFixed {
        bitmap_len: Option<usize>,
        values_len: usize,
        row_count: u32,
    },
    ArrowVarLen {
        bitmap_len: Option<usize>,
        offsets_len: usize,
        data_len: usize,
        row_count: u32,
    },
    ArrowBool {
        bitmap_len: Option<usize>,
        packed_bits_len: usize,
        row_count: u32,
    },
    ArrowSymbol {
        bitmap_len: Option<usize>,
        dict_len: usize,
        dict_data_len: usize,
        keys_len: usize,
        row_count: u32,
    },
    ArrowDecimal {
        bitmap_len: Option<usize>,
        values_len: usize,
        row_count: u32,
    },
    ArrowGeohash {
        bitmap_len: Option<usize>,
        values_len: usize,
        row_count: u32,
    },
    ArrowArray {
        bitmap_len: Option<usize>,
        data_len: usize,
        row_count: u32,
    },
}

#[cfg(feature = "arrow")]
impl QwpWsColumnBuffer {
    fn arrow_snapshot(&self) -> ArrowColRollbackMark {
        let bitmap_to_len = |b: &Option<Vec<u8>>| b.as_ref().map(|v| v.len());
        match &self.values {
            QwpWsColumnValues::ArrowFixed {
                bitmap,
                values,
                row_count,
            } => ArrowColRollbackMark::ArrowFixed {
                bitmap_len: bitmap_to_len(bitmap),
                values_len: values.len(),
                row_count: *row_count,
            },
            QwpWsColumnValues::ArrowVarLen {
                bitmap,
                offsets,
                data,
                row_count,
            } => ArrowColRollbackMark::ArrowVarLen {
                bitmap_len: bitmap_to_len(bitmap),
                offsets_len: offsets.len(),
                data_len: data.len(),
                row_count: *row_count,
            },
            QwpWsColumnValues::ArrowBool {
                bitmap,
                packed_bits,
                row_count,
            } => ArrowColRollbackMark::ArrowBool {
                bitmap_len: bitmap_to_len(bitmap),
                packed_bits_len: packed_bits.len(),
                row_count: *row_count,
            },
            QwpWsColumnValues::ArrowSymbol {
                bitmap,
                dict,
                dict_data,
                keys,
                row_count,
                ..
            } => ArrowColRollbackMark::ArrowSymbol {
                bitmap_len: bitmap_to_len(bitmap),
                dict_len: dict.len(),
                dict_data_len: dict_data.len(),
                keys_len: keys.len(),
                row_count: *row_count,
            },
            QwpWsColumnValues::ArrowDecimal {
                bitmap,
                values,
                row_count,
                ..
            } => ArrowColRollbackMark::ArrowDecimal {
                bitmap_len: bitmap_to_len(bitmap),
                values_len: values.len(),
                row_count: *row_count,
            },
            QwpWsColumnValues::ArrowGeohash {
                bitmap,
                values,
                row_count,
                ..
            } => ArrowColRollbackMark::ArrowGeohash {
                bitmap_len: bitmap_to_len(bitmap),
                values_len: values.len(),
                row_count: *row_count,
            },
            QwpWsColumnValues::ArrowArray {
                bitmap,
                data,
                row_count,
            } => ArrowColRollbackMark::ArrowArray {
                bitmap_len: bitmap_to_len(bitmap),
                data_len: data.len(),
                row_count: *row_count,
            },
            _ => ArrowColRollbackMark::NonArrow {
                last_written_row: self.last_written_row,
                non_null_count: self.non_null_count,
            },
        }
    }

    fn arrow_restore(&mut self, mark: ArrowColRollbackMark) {
        let restore_bitmap = |bitmap: &mut Option<Vec<u8>>, target: Option<usize>| match target {
            None => {
                *bitmap = None;
            }
            Some(len) => {
                if let Some(b) = bitmap.as_mut() {
                    b.truncate(len);
                }
            }
        };
        match (&mut self.values, mark) {
            (
                QwpWsColumnValues::ArrowFixed {
                    bitmap,
                    values,
                    row_count,
                },
                ArrowColRollbackMark::ArrowFixed {
                    bitmap_len,
                    values_len,
                    row_count: rc,
                },
            ) => {
                restore_bitmap(bitmap, bitmap_len);
                values.truncate(values_len);
                *row_count = rc;
            }
            (
                QwpWsColumnValues::ArrowVarLen {
                    bitmap,
                    offsets,
                    data,
                    row_count,
                },
                ArrowColRollbackMark::ArrowVarLen {
                    bitmap_len,
                    offsets_len,
                    data_len,
                    row_count: rc,
                },
            ) => {
                restore_bitmap(bitmap, bitmap_len);
                offsets.truncate(offsets_len);
                data.truncate(data_len);
                *row_count = rc;
            }
            (
                QwpWsColumnValues::ArrowBool {
                    bitmap,
                    packed_bits,
                    row_count,
                },
                ArrowColRollbackMark::ArrowBool {
                    bitmap_len,
                    packed_bits_len,
                    row_count: rc,
                },
            ) => {
                restore_bitmap(bitmap, bitmap_len);
                packed_bits.truncate(packed_bits_len);
                *row_count = rc;
            }
            (
                QwpWsColumnValues::ArrowSymbol {
                    bitmap,
                    dict,
                    dict_lookup,
                    dict_data,
                    keys,
                    row_count,
                },
                ArrowColRollbackMark::ArrowSymbol {
                    bitmap_len,
                    dict_len,
                    dict_data_len,
                    keys_len,
                    row_count: rc,
                },
            ) => {
                restore_bitmap(bitmap, bitmap_len);
                dict.truncate(dict_len);
                dict_data.truncate(dict_data_len);
                keys.truncate(keys_len);
                dict_lookup.retain_local_ids_below(dict_len);
                *row_count = rc;
            }
            (
                QwpWsColumnValues::ArrowDecimal {
                    bitmap,
                    values,
                    row_count,
                    ..
                },
                ArrowColRollbackMark::ArrowDecimal {
                    bitmap_len,
                    values_len,
                    row_count: rc,
                },
            ) => {
                restore_bitmap(bitmap, bitmap_len);
                values.truncate(values_len);
                *row_count = rc;
            }
            (
                QwpWsColumnValues::ArrowGeohash {
                    bitmap,
                    values,
                    row_count,
                    ..
                },
                ArrowColRollbackMark::ArrowGeohash {
                    bitmap_len,
                    values_len,
                    row_count: rc,
                },
            ) => {
                restore_bitmap(bitmap, bitmap_len);
                values.truncate(values_len);
                *row_count = rc;
            }
            (
                QwpWsColumnValues::ArrowArray {
                    bitmap,
                    data,
                    row_count,
                },
                ArrowColRollbackMark::ArrowArray {
                    bitmap_len,
                    data_len,
                    row_count: rc,
                },
            ) => {
                restore_bitmap(bitmap, bitmap_len);
                data.truncate(data_len);
                *row_count = rc;
            }
            (
                _,
                ArrowColRollbackMark::NonArrow {
                    last_written_row,
                    non_null_count,
                },
            ) => {
                self.last_written_row = last_written_row;
                self.non_null_count = non_null_count;
                if self.arrow_row_count().is_some() {
                    self.values = QwpWsColumnValues::new(self.kind);
                }
            }
            _ => {
                self.values.clear_rows();
            }
        }
    }
}

#[cfg(feature = "arrow")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ArrowBatchInfo<'a> {
    pub bitmap: Option<&'a NullBuffer>,
    pub rows: u32,
    pub non_null: u32,
}

#[cfg(feature = "arrow")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct ArrowDecimalSpec {
    pub scale: u8,
    pub element_width: u8,
}

#[cfg(feature = "arrow")]
fn fixed_element_width(kind: ColumnKind) -> Option<usize> {
    Some(match kind {
        ColumnKind::I8 => 1,
        ColumnKind::I16 | ColumnKind::Char => 2,
        ColumnKind::I32 | ColumnKind::F32 | ColumnKind::Ipv4 => 4,
        ColumnKind::I64
        | ColumnKind::F64
        | ColumnKind::TimestampMicros
        | ColumnKind::TimestampNanos
        | ColumnKind::Date => 8,
        ColumnKind::Uuid => 16,
        ColumnKind::Long256 => 32,
        _ => return None,
    })
}

#[cfg(feature = "arrow")]
fn ensure_arrow_row_count(arrow_rows: u32, expected: usize) -> crate::Result<()> {
    if arrow_rows as usize != expected {
        return Err(error::fmt!(
            InvalidApiCall,
            "QWP/WS arrow column row mismatch: arrow={} table={}",
            arrow_rows,
            expected
        ));
    }
    Ok(())
}

#[cfg(feature = "arrow")]
fn arrow_bulk_mixing_error(column_name: &[u8]) -> crate::Error {
    error::fmt!(
        InvalidApiCall,
        "column '{}' has row-by-row writes; cannot switch to bulk arrow write within the same batch",
        String::from_utf8_lossy(column_name)
    )
}

#[cfg(feature = "arrow")]
fn append_packed_bits(
    existing: &mut Vec<u8>,
    existing_rows: usize,
    incoming: &[u8],
    incoming_rows: usize,
) {
    let total_rows = existing_rows + incoming_rows;
    let total_bytes = total_rows.div_ceil(8);
    if existing.len() < total_bytes {
        existing.resize(total_bytes, 0);
    }
    for i in 0..incoming_rows {
        if (incoming[i / 8] >> (i % 8)) & 1 == 1 {
            let target = existing_rows + i;
            existing[target / 8] |= 1 << (target % 8);
        }
    }
}

#[cfg(feature = "arrow")]
fn extend_qwp_bitmap(
    existing: &mut Option<Vec<u8>>,
    existing_rows: usize,
    incoming: Option<&NullBuffer>,
    incoming_rows: usize,
) {
    let total_rows = existing_rows + incoming_rows;
    if existing.is_none() && incoming.is_none() {
        return;
    }
    let total_bytes = total_rows.div_ceil(8);
    let mut bm = existing
        .take()
        .unwrap_or_else(|| vec![0u8; existing_rows.div_ceil(8)]);
    if bm.len() < total_bytes {
        bm.resize(total_bytes, 0);
    }
    if let Some(nulls) = incoming {
        for i in 0..incoming_rows {
            if nulls.is_null(i) {
                let target = existing_rows + i;
                bm[target / 8] |= 1 << (target % 8);
            }
        }
    }
    *existing = Some(bm);
}

fn type_mismatch_error_ws(entry_name: &[u8]) -> crate::Error {
    batched_type_change_error_ws(entry_name)
}

// --- WebSocket (delta-symbol-dict) encoder ---

#[cfg(feature = "_sender-qwp-ws")]
const QWP_FLAG_DELTA_SYMBOL_DICT: u8 = 0x08;

/// Connection-scoped global symbol dictionary used by the QWP/WebSocket
/// transport's delta-symbol-dict mode.
///
/// The dictionary is owned by the sender and lives for the duration of the
/// WebSocket connection. New symbols added during a flush are recorded in the
/// per-message delta section so the server can rebuild the same global
/// dictionary; on reconnect both sides reset.
#[cfg(feature = "_sender-qwp-ws")]
#[derive(Debug, Default)]
pub(crate) struct SymbolGlobalDict {
    map: QwpWsSymbolHashMap<u64>,
    entries: Vec<Vec<u8>>,
    next_id: u64,
}

#[cfg(feature = "_sender-qwp-ws")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct SymbolGlobalDictMark {
    entries_len: usize,
    next_id: u64,
}

#[cfg(feature = "_sender-qwp-ws")]
impl SymbolGlobalDict {
    pub(crate) fn new() -> Self {
        Self {
            map: QwpWsSymbolHashMap::default(),
            entries: Vec::new(),
            next_id: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> u64 {
        self.next_id
    }

    pub(crate) fn mark(&self) -> SymbolGlobalDictMark {
        SymbolGlobalDictMark {
            entries_len: self.entries.len(),
            next_id: self.next_id,
        }
    }

    pub(crate) fn rollback(&mut self, mark: SymbolGlobalDictMark) {
        while self.entries.len() > mark.entries_len {
            if let Some(entry) = self.entries.pop() {
                self.map.remove(entry.as_slice());
            }
        }
        self.next_id = mark.next_id;
    }

    fn entry(&self, id: u64) -> Option<&[u8]> {
        let index = usize::try_from(id).ok()?;
        self.entries.get(index).map(Vec::as_slice)
    }

    /// Returns `(global_id, is_new)`.
    fn intern(&mut self, bytes: &[u8]) -> (u64, bool) {
        if let Some(&id) = self.map.get(bytes) {
            return (id, false);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let owned = bytes.to_vec();
        self.entries.push(owned.clone());
        self.map.insert(owned, id);
        (id, true)
    }
}

/// Reusable scratch buffers for encoding a single QWP/WebSocket message.
#[cfg(feature = "_sender-qwp-ws")]
#[derive(Default)]
pub(crate) struct QwpWsEncodeScratch {
    pub(crate) message: Vec<u8>,
    /// Per-segment, per-column-local-index mapping to global symbol IDs.
    /// Populated during the pre-pass of `encode_ws_message` and consumed by
    /// the symbol-column writer.
    per_segment_symbol_globals: Vec<Vec<Vec<u64>>>,
    /// Reusable buffer holding the on-the-wire bytes of one schema's column
    /// definitions: `(varint name_len, name, type_code)*`. Doubles as the
    /// signature key for the schema registry and as the payload to splice into
    /// the message in full mode, avoiding a second pass over the columns.
    schema_signature: Vec<u8>,
    /// Reusable per-message schema signatures for the self-sufficient replay
    /// encoder.
    replay_schema_signatures: Vec<Vec<u8>>,
    replay_schema_count: usize,
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpWsEncodeScratch {
    pub(crate) fn new() -> Self {
        Self {
            message: Vec::with_capacity(16 * 1024),
            per_segment_symbol_globals: Vec::new(),
            schema_signature: Vec::new(),
            replay_schema_signatures: Vec::new(),
            replay_schema_count: 0,
        }
    }
}

/// Connection-scoped schema registry used by the QWP/WebSocket transport's
/// reference-mode schemas (§9). The first time a particular column-set
/// signature is seen on a connection, the encoder assigns a fresh id and emits
/// it in full mode; subsequent batches with the same signature emit reference
/// mode (just the id), saving the per-message column-definition bytes.
///
/// Two tables that happen to have the same column shape may share an id — the
/// server's registry stores the column set only, and the table name lives in
/// the table header.
#[cfg(all(test, feature = "_sender-qwp-ws"))]
#[derive(Debug, Default)]
pub(crate) struct SchemaRegistry {
    map: std::collections::HashMap<Vec<u8>, u64>,
    next_id: u64,
}

#[cfg(all(test, feature = "_sender-qwp-ws"))]
impl SchemaRegistry {
    pub(crate) fn new() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            next_id: 0,
        }
    }

    /// Returns `(schema_id, is_new)`. When `is_new` is true the caller must
    /// emit full-mode (column definitions inline) so the server registers the
    /// id; otherwise it should emit reference-mode (just the id).
    fn intern(&mut self, signature: &[u8]) -> (u64, bool) {
        if let Some(&id) = self.map.get(signature) {
            return (id, false);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.map.insert(signature.to_vec(), id);
        (id, true)
    }
}

#[cfg(feature = "_sender-qwp-ws")]
fn intern_replay_schema_signature(
    signatures: &mut Vec<Vec<u8>>,
    active_count: &mut usize,
    signature: &[u8],
) -> u64 {
    for (index, stored) in signatures.iter().take(*active_count).enumerate() {
        if stored.as_slice() == signature {
            return index as u64;
        }
    }

    if *active_count == signatures.len() {
        signatures.push(Vec::new());
    }
    let stored = &mut signatures[*active_count];
    stored.clear();
    stored.extend_from_slice(signature);
    let id = *active_count as u64;
    *active_count += 1;
    id
}

#[cfg(feature = "_sender-qwp-ws")]
impl QwpBuffer {
    /// Encode all currently-buffered table blocks into a single QWP/WebSocket
    /// message using delta-symbol-dict mode (FLAG_DELTA_SYMBOL_DICT).
    ///
    /// New symbols discovered while encoding are added to `global_dict` and
    /// recorded in the message's delta section so the server can mirror the
    /// dictionary state. The encoded payload lands in `scratch.message`.
    #[cfg(test)]
    pub(crate) fn encode_ws_message(
        &self,
        scratch: &mut QwpWsEncodeScratch,
        global_dict: &mut SymbolGlobalDict,
        schema_registry: &mut SchemaRegistry,
        version: u8,
    ) -> crate::Result<()> {
        if self.pending.table.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot flush with an incomplete row. \
                 Call `at` or `at_now` to complete the pending row."
            ));
        }

        let out = &mut scratch.message;
        out.clear();

        // Header placeholder (filled at the end).
        let header_start = out.len();
        out.extend_from_slice(&[0u8; QWP_MESSAGE_HEADER_SIZE]);
        let payload_start = out.len();

        // ---- Pass 1: build per-segment symbol-id mapping & collect new entries ----
        scratch.per_segment_symbol_globals.clear();
        scratch
            .per_segment_symbol_globals
            .reserve(self.segments.len());
        let delta_start = global_dict.len();
        // Collect new symbol byte ranges (referencing self.value_bytes) in the
        // order they receive global IDs.
        let mut new_symbol_ranges: Vec<std::ops::Range<usize>> = Vec::new();

        for (seg_idx, _) in self.segments.iter().enumerate() {
            let planner = self.size_hint.segment_planner(seg_idx)?;
            let mut per_col: Vec<Vec<u64>> = Vec::with_capacity(planner.columns.len());
            for col in &planner.columns {
                let mut globals_for_col: Vec<u64> = Vec::new();
                if matches!(col.kind, ColumnKind::Symbol) {
                    globals_for_col.reserve(col.dict_count as usize);
                    let mut cursor = col.dict_head;
                    while cursor != CELL_END {
                        let entry = &planner.symbol_dict[cursor as usize];
                        let range = entry.value.0.as_range();
                        let bytes = &self.value_bytes[range.clone()];
                        let (gid, is_new) = global_dict.intern(bytes);
                        globals_for_col.push(gid);
                        if is_new {
                            new_symbol_ranges.push(range);
                        }
                        cursor = entry.next;
                    }
                }
                per_col.push(globals_for_col);
            }
            scratch.per_segment_symbol_globals.push(per_col);
        }

        // ---- Delta dictionary section ----
        write_qwp_varint(out, delta_start);
        write_qwp_varint(out, new_symbol_ranges.len() as u64);
        for range in &new_symbol_ranges {
            let bytes = &self.value_bytes[range.clone()];
            write_qwp_bytes(out, bytes);
        }

        // ---- Table blocks ----
        let table_count: u16 = checked_qwp_u16(self.segments.len(), "WS message table count")?;
        for (seg_idx, segment) in self.segments.iter().enumerate() {
            let planner = self.size_hint.segment_planner(seg_idx)?;
            let table_name = &self.name_bytes[segment.table.0.as_range()];
            let row_count = planner.row_count;

            // Table header
            write_qwp_bytes(out, table_name);
            write_qwp_varint(out, row_count as u64);
            write_qwp_varint(out, planner.columns.len() as u64);

            // Schema: build the column-definition byte sequence once. It is
            // both the registry key (column-set signature) and the payload we
            // splice inline when emitting full mode.
            scratch.schema_signature.clear();
            for col in &planner.columns {
                write_qwp_bytes(
                    &mut scratch.schema_signature,
                    &self.name_bytes[col.name.0.as_range()],
                );
                scratch
                    .schema_signature
                    .push(wire_type_byte(col.kind, col.uses_null_bitmap(row_count)));
            }
            let (schema_id, is_new) = schema_registry.intern(&scratch.schema_signature);
            if is_new {
                out.push(QWP_SCHEMA_MODE_FULL);
                write_qwp_varint(out, schema_id);
                out.extend_from_slice(&scratch.schema_signature);
            } else {
                out.push(QWP_SCHEMA_MODE_REFERENCE);
                write_qwp_varint(out, schema_id);
            }

            // Column payloads
            for (col_idx, col) in planner.columns.iter().enumerate() {
                if matches!(col.kind, ColumnKind::Symbol) {
                    let globals = &scratch.per_segment_symbol_globals[seg_idx][col_idx];
                    encode_symbol_column_delta_dict(col, row_count, &planner.cells, globals, out)?;
                } else {
                    encode_column_from_cells(
                        col,
                        row_count,
                        &planner.cells,
                        &planner.symbol_dict,
                        &self.value_bytes,
                        out,
                    )?;
                }
            }
        }

        // Fill header
        let header = QwpMessageHeader {
            magic: *b"QWP1",
            version,
            flags: QWP_FLAG_DELTA_SYMBOL_DICT,
            table_count,
            payload_len: checked_qwp_u32(out.len() - payload_start, "WS message payload length")?,
        };
        header.write_to(&mut out[header_start..header_start + QWP_MESSAGE_HEADER_SIZE]);

        Ok(())
    }

    /// Encode all currently-buffered table blocks into one self-sufficient
    /// QWP/WebSocket message for replayable Store-and-Forward storage.
    ///
    /// This is the Java-style v1 replay shape: every frame carries the dense
    /// global symbol dictionary prefix from id 0 through the highest symbol id
    /// referenced by this frame, and every table block carries its full schema.
    #[cfg(test)]
    pub(crate) fn encode_ws_replay_message(
        &self,
        scratch: &mut QwpWsEncodeScratch,
        global_dict: &mut SymbolGlobalDict,
        version: u8,
    ) -> crate::Result<()> {
        if self.pending.table.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot flush with an incomplete row. \
                 Call `at` or `at_now` to complete the pending row."
            ));
        }

        let out = &mut scratch.message;
        out.clear();

        // Header placeholder (filled at the end).
        let header_start = out.len();
        out.extend_from_slice(&[0u8; QWP_MESSAGE_HEADER_SIZE]);
        let payload_start = out.len();

        // ---- Pass 1: map frame-local symbol ids to connection-global ids ----
        while scratch.per_segment_symbol_globals.len() < self.segments.len() {
            scratch.per_segment_symbol_globals.push(Vec::new());
        }
        let mut highest_referenced_symbol_id: Option<u64> = None;

        for (seg_idx, _) in self.segments.iter().enumerate() {
            let planner = self.size_hint.segment_planner(seg_idx)?;
            let per_col = &mut scratch.per_segment_symbol_globals[seg_idx];
            while per_col.len() < planner.columns.len() {
                per_col.push(Vec::new());
            }
            for (col_idx, col) in planner.columns.iter().enumerate() {
                let globals_for_col = &mut per_col[col_idx];
                globals_for_col.clear();
                if matches!(col.kind, ColumnKind::Symbol) {
                    globals_for_col.reserve(col.dict_count as usize);
                    let mut cursor = col.dict_head;
                    while cursor != CELL_END {
                        let entry = &planner.symbol_dict[cursor as usize];
                        let range = entry.value.0.as_range();
                        let bytes = &self.value_bytes[range];
                        let (gid, _) = global_dict.intern(bytes);
                        highest_referenced_symbol_id = Some(
                            highest_referenced_symbol_id.map_or(gid, |highest| highest.max(gid)),
                        );
                        globals_for_col.push(gid);
                        cursor = entry.next;
                    }
                }
            }
        }

        // ---- Dense dictionary prefix section ----
        write_qwp_varint(out, 0);
        let dense_count = highest_referenced_symbol_id.map_or(0, |highest| highest + 1);
        write_qwp_varint(out, dense_count);
        for id in 0..dense_count {
            let bytes = global_dict.entry(id).ok_or_else(|| {
                error::fmt!(
                    InvalidApiCall,
                    "internal QWP/WS replay encoder error: missing global symbol id {}",
                    id
                )
            })?;
            write_qwp_bytes(out, bytes);
        }

        // ---- Table blocks ----
        scratch.replay_schema_count = 0;
        let table_count: u16 = checked_qwp_u16(self.segments.len(), "WS message table count")?;
        for (seg_idx, segment) in self.segments.iter().enumerate() {
            let planner = self.size_hint.segment_planner(seg_idx)?;
            let table_name = &self.name_bytes[segment.table.0.as_range()];
            let row_count = planner.row_count;

            // Table header
            write_qwp_bytes(out, table_name);
            write_qwp_varint(out, row_count as u64);
            write_qwp_varint(out, planner.columns.len() as u64);

            // Always emit full schema. The schema id is still included because
            // it is part of QWP full-schema mode, but this replay path never
            // emits reference-only table blocks.
            scratch.schema_signature.clear();
            for col in &planner.columns {
                write_qwp_bytes(
                    &mut scratch.schema_signature,
                    &self.name_bytes[col.name.0.as_range()],
                );
                scratch
                    .schema_signature
                    .push(wire_type_byte(col.kind, col.uses_null_bitmap(row_count)));
            }
            let schema_id = intern_replay_schema_signature(
                &mut scratch.replay_schema_signatures,
                &mut scratch.replay_schema_count,
                &scratch.schema_signature,
            );
            out.push(QWP_SCHEMA_MODE_FULL);
            write_qwp_varint(out, schema_id);
            out.extend_from_slice(&scratch.schema_signature);

            // Column payloads
            for (col_idx, col) in planner.columns.iter().enumerate() {
                if matches!(col.kind, ColumnKind::Symbol) {
                    let globals = &scratch.per_segment_symbol_globals[seg_idx][col_idx];
                    encode_symbol_column_delta_dict(col, row_count, &planner.cells, globals, out)?;
                } else {
                    encode_column_from_cells(
                        col,
                        row_count,
                        &planner.cells,
                        &planner.symbol_dict,
                        &self.value_bytes,
                        out,
                    )?;
                }
            }
        }

        // Fill header
        let header = QwpMessageHeader {
            magic: *b"QWP1",
            version,
            flags: QWP_FLAG_DELTA_SYMBOL_DICT,
            table_count,
            payload_len: checked_qwp_u32(
                out.len() - payload_start,
                "WS replay message payload length",
            )?,
        };
        header.write_to(&mut out[header_start..header_start + QWP_MESSAGE_HEADER_SIZE]);

        Ok(())
    }
}

#[cfg(feature = "_sender-qwp-ws")]
fn checked_qwp_u16(value: usize, what: &'static str) -> crate::Result<u16> {
    if value > u16::MAX as usize {
        return Err(error::fmt!(
            InvalidApiCall,
            "QWP {} exceeds maximum of {}",
            what,
            u16::MAX
        ));
    }
    Ok(value as u16)
}

#[cfg(all(test, feature = "_sender-qwp-ws"))]
fn encode_symbol_column_delta_dict(
    col: &ColumnStats,
    row_count: usize,
    cells: &[CellRef],
    globals: &[u64],
    out: &mut Vec<u8>,
) -> crate::Result<()> {
    let uses_null_bitmap = col.uses_null_bitmap(row_count);
    out.push(u8::from(uses_null_bitmap));

    if uses_null_bitmap {
        let mut packed = 0u8;
        let mut bit_idx = 0u8;
        for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
            if maybe_cell.is_none_or(|cell| cell_value_is_null(cell.value)) {
                packed |= 1 << bit_idx;
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

    // Varint global IDs for each non-null row, in row order.
    for cell in CellIter::new(cells, col.cell_head) {
        let local_idx = cell.symbol_dict_idx as usize;
        let gid = globals.get(local_idx).copied().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "internal QWP/WS encoder error: missing global symbol id for column-local index {}",
                local_idx
            )
        })?;
        write_qwp_varint(out, gid);
    }
    Ok(())
}

/// Synthetic designated-timestamp entry used when iterating row specs.
/// The empty column name is represented as a zero-length NameSlice.
const DESIGNATED_TS_NAME: NameSlice = NameSlice(ByteSlice { offset: 0, len: 0 });

fn designated_ts_entry(ts: DesignatedTs) -> EntryMeta {
    EntryMeta {
        name: DESIGNATED_TS_NAME,
        value: match ts {
            DesignatedTs::Micros(v) => ValueRef::TimestampMicros(v),
            DesignatedTs::Nanos(v) => ValueRef::TimestampNanos(v),
        },
    }
}

fn batched_type_change_error(entry_name: &[u8]) -> crate::Error {
    if entry_name.is_empty() {
        error::fmt!(
            InvalidApiCall,
            "QWP/UDP designated timestamp changes type within a batched table"
        )
    } else {
        error::fmt!(
            InvalidApiCall,
            "QWP/UDP column {:?} changes type within a batched table",
            std::str::from_utf8(entry_name).unwrap_or("<invalid>")
        )
    }
}

// --- Symbol dictionary entry (flat arena, linked per column) ---

#[derive(Clone, Copy, Debug)]
struct SymbolEntry {
    value: ValueSlice,
    next: u32,
    bucket_next: u32,
    hash: u64,
    col_idx: u16,
    dict_idx: u32,
}

// --- Column stats (all scalar, no nested Vecs) ---

#[derive(Clone, Copy, Debug)]
struct ColumnStats {
    name: NameSlice,
    non_null_count: u32,
    variable_data_len: usize,
    symbol_dict_bytes: usize,
    symbol_row_index_bytes: usize,
    decimal_scale: u8,
    geohash_precision_bits: u8,
    dict_head: u32,
    dict_tail: u32,
    cell_head: u32,
    cell_tail: u32,
    dict_count: u32,
    cached_schema_len: usize,
    kind: ColumnKind,
    supports_sparse_nulls: bool,
}

impl ColumnStats {
    #[allow(clippy::too_many_arguments)]
    fn payload_len_parts(
        kind: ColumnKind,
        supports_sparse_nulls: bool,
        row_count: usize,
        non_null_count: u32,
        variable_data_len: usize,
        symbol_dict_bytes: usize,
        symbol_row_index_bytes: usize,
        dict_count: u32,
    ) -> crate::Result<usize> {
        let uses_null_bitmap = uses_null_bitmap(supports_sparse_nulls, row_count, non_null_count);
        let bitmap = if uses_null_bitmap {
            bitmap_bytes(row_count)
        } else {
            0
        };

        let data_len = match kind {
            ColumnKind::Bool => packed_bytes(row_count),
            ColumnKind::I8 => row_count,
            ColumnKind::I16 => checked_qwp_usize_mul(row_count, 2, "column data size")?,
            ColumnKind::I32 => checked_qwp_usize_mul(row_count, 4, "column data size")?,
            ColumnKind::I64 | ColumnKind::F64 => {
                checked_qwp_usize_mul(row_count, 8, "column data size")?
            }
            ColumnKind::F32 => checked_qwp_usize_mul(row_count, 4, "column data size")?,
            ColumnKind::Decimal64 => checked_qwp_usize_add(
                1,
                checked_qwp_usize_mul(non_null_count as usize, 8, "decimal64 column size")?,
                "decimal64 column size",
            )?,
            ColumnKind::Decimal128 => checked_qwp_usize_add(
                1,
                checked_qwp_usize_mul(non_null_count as usize, 16, "decimal128 column size")?,
                "decimal128 column size",
            )?,
            ColumnKind::Decimal => checked_qwp_usize_add(
                1,
                checked_qwp_usize_mul(
                    non_null_count as usize,
                    QWP_DECIMAL_MAG_BYTES,
                    "decimal column size",
                )?,
                "decimal column size",
            )?,
            ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => {
                checked_qwp_usize_mul(non_null_count as usize, 8, "column data size")?
            }
            ColumnKind::Uuid => {
                checked_qwp_usize_mul(non_null_count as usize, 16, "uuid column size")?
            }
            ColumnKind::Long256 => checked_qwp_usize_mul(
                non_null_count as usize,
                QWP_LONG256_BYTES,
                "long256 column size",
            )?,
            ColumnKind::Ipv4 => {
                checked_qwp_usize_mul(non_null_count as usize, 4, "ipv4 column size")?
            }
            ColumnKind::Date => {
                checked_qwp_usize_mul(non_null_count as usize, 8, "date column size")?
            }
            ColumnKind::Char => checked_qwp_usize_mul(row_count, 2, "char column size")?,
            ColumnKind::Binary => {
                let offset_count =
                    checked_qwp_usize_add(non_null_count as usize, 1, "binary offset count")?;
                let offsets = checked_qwp_usize_mul(offset_count, 4, "binary offset table")?;
                checked_qwp_usize_add(offsets, variable_data_len, "binary column size")?
            }
            ColumnKind::Geohash => {
                checked_qwp_usize_add(1, variable_data_len, "geohash column size")?
            }
            ColumnKind::String => {
                let offset_count =
                    checked_qwp_usize_add(non_null_count as usize, 1, "string offset count")?;
                let offsets = checked_qwp_usize_mul(offset_count, 4, "string offset table")?;
                checked_qwp_usize_add(offsets, variable_data_len, "string column size")?
            }
            ColumnKind::DoubleArray | ColumnKind::LongArray => variable_data_len,
            ColumnKind::Symbol => {
                let base = checked_qwp_usize_add(
                    qwp_varint_size(dict_count as u64),
                    symbol_dict_bytes,
                    "symbol column size",
                )?;
                checked_qwp_usize_add(base, symbol_row_index_bytes, "symbol column size")?
            }
        };
        let with_bitmap = checked_qwp_usize_add(1, bitmap, "column header size")?;
        checked_qwp_usize_add(with_bitmap, data_len, "column payload size")
    }

    fn new(entry: &EntryMeta) -> Self {
        let kind = entry.value.kind();
        let name_len = entry.name.0.len as usize;
        let cached_schema_len = qwp_varint_size(name_len as u64) + name_len + 1;
        Self {
            name: entry.name,
            non_null_count: 0,
            variable_data_len: 0,
            symbol_dict_bytes: 0,
            symbol_row_index_bytes: 0,
            decimal_scale: QWP_DECIMAL_SCALE_UNSET,
            geohash_precision_bits: 0,
            dict_head: CELL_END,
            dict_tail: CELL_END,
            cell_head: CELL_END,
            cell_tail: CELL_END,
            dict_count: 0,
            cached_schema_len,
            kind,
            supports_sparse_nulls: kind_supports_sparse_nulls(kind),
        }
    }

    fn payload_len(&self, row_count: usize) -> crate::Result<usize> {
        Self::payload_len_parts(
            self.kind,
            self.supports_sparse_nulls,
            row_count,
            self.non_null_count,
            self.variable_data_len,
            self.symbol_dict_bytes,
            self.symbol_row_index_bytes,
            self.dict_count,
        )
    }

    fn add_non_symbol_value(&mut self, value: &ValueRef) -> crate::Result<()> {
        let new_non_null_count = self.non_null_count.checked_add(1).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/UDP non-null value count exceeds maximum of {}",
                u32::MAX
            )
        })?;
        match self.kind {
            ColumnKind::Bool => match value {
                ValueRef::Bool(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for boolean column"
                )),
            },
            ColumnKind::I8 => match value {
                ValueRef::I8(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for byte column"
                )),
            },
            ColumnKind::I16 => match value {
                ValueRef::I16(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for short column"
                )),
            },
            ColumnKind::I32 => match value {
                ValueRef::I32(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for int column"
                )),
            },
            ColumnKind::I64 => match value {
                ValueRef::I64(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for long column"
                )),
            },
            ColumnKind::F64 => match value {
                ValueRef::F64(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for double column"
                )),
            },
            ColumnKind::F32 => match value {
                ValueRef::F32(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for float column"
                )),
            },
            ColumnKind::Decimal => match value {
                ValueRef::DecimalNull => Ok(()),
                ValueRef::Decimal(decimal_value) => {
                    if self.non_null_count == 0 {
                        self.decimal_scale = decimal_value.scale;
                    }
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for decimal column"
                )),
            },
            ColumnKind::Decimal64 => match value {
                ValueRef::Decimal64Null => Ok(()),
                ValueRef::Decimal64(decimal_value) => {
                    if self.non_null_count == 0 {
                        self.decimal_scale = decimal_value.scale;
                    }
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for decimal64 column"
                )),
            },
            ColumnKind::Decimal128 => match value {
                ValueRef::Decimal128Null => Ok(()),
                ValueRef::Decimal128(decimal_value) => {
                    if self.non_null_count == 0 {
                        self.decimal_scale = decimal_value.scale;
                    }
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for decimal128 column"
                )),
            },
            ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => match value {
                ValueRef::TimestampMicros(_) | ValueRef::TimestampNanos(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for timestamp column"
                )),
            },
            ColumnKind::Uuid => match value {
                ValueRef::Uuid(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for uuid column"
                )),
            },
            ColumnKind::Long256 => match value {
                ValueRef::Long256(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for long256 column"
                )),
            },
            ColumnKind::Ipv4 => match value {
                ValueRef::Ipv4(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for ipv4 column"
                )),
            },
            ColumnKind::Date => match value {
                ValueRef::DateMillis(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for date column"
                )),
            },
            ColumnKind::Char => match value {
                ValueRef::Char(_) => {
                    self.non_null_count = new_non_null_count;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for char column"
                )),
            },
            ColumnKind::Binary => match value {
                ValueRef::Binary(vs) => {
                    let new_variable_data_len = checked_qwp_usize_add(
                        self.variable_data_len,
                        vs.0.len as usize,
                        "binary payload bytes",
                    )?;
                    self.non_null_count = new_non_null_count;
                    self.variable_data_len = new_variable_data_len;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for binary column"
                )),
            },
            ColumnKind::Geohash => match value {
                ValueRef::Geohash { precision_bits, .. } => {
                    if !(1..=60).contains(precision_bits) {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "GEOHASH precision must be in 1..=60, got {}",
                            precision_bits
                        ));
                    }
                    if self.non_null_count == 0 {
                        self.geohash_precision_bits = *precision_bits;
                    } else if self.geohash_precision_bits != *precision_bits {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "GEOHASH precision mismatch within column: pinned at {} bits, got {}",
                            self.geohash_precision_bits,
                            precision_bits
                        ));
                    }
                    let bytes = geohash_bytes_per_value(*precision_bits);
                    let new_variable_data_len = checked_qwp_usize_add(
                        self.variable_data_len,
                        bytes,
                        "geohash payload bytes",
                    )?;
                    self.non_null_count = new_non_null_count;
                    self.variable_data_len = new_variable_data_len;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for geohash column"
                )),
            },
            ColumnKind::String => match value {
                ValueRef::String(vs) => {
                    let new_variable_data_len = checked_qwp_usize_add(
                        self.variable_data_len,
                        vs.0.len as usize,
                        "string payload bytes",
                    )?;
                    self.non_null_count = new_non_null_count;
                    self.variable_data_len = new_variable_data_len;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for string column"
                )),
            },
            ColumnKind::DoubleArray => match value {
                ValueRef::DoubleArray(vs) => {
                    let new_variable_data_len = checked_qwp_usize_add(
                        self.variable_data_len,
                        vs.0.len as usize,
                        "array payload bytes",
                    )?;
                    self.non_null_count = new_non_null_count;
                    self.variable_data_len = new_variable_data_len;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for double array column"
                )),
            },
            ColumnKind::LongArray => match value {
                ValueRef::LongArray(vs) => {
                    let new_variable_data_len = checked_qwp_usize_add(
                        self.variable_data_len,
                        vs.0.len as usize,
                        "array payload bytes",
                    )?;
                    self.non_null_count = new_non_null_count;
                    self.variable_data_len = new_variable_data_len;
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for long array column"
                )),
            },
            ColumnKind::Symbol => {
                // Symbol accounting handled by RowGroupPlanner
                Ok(())
            }
        }
    }

    fn uses_null_bitmap(&self, row_count: usize) -> bool {
        uses_null_bitmap(self.supports_sparse_nulls, row_count, self.non_null_count)
    }
}

// --- Checkpoint types ---

#[derive(Clone, Debug)]
struct ColumnUndo {
    non_null_count: u32,
    variable_data_len: usize,
    symbol_dict_bytes: usize,
    symbol_row_index_bytes: usize,
    decimal_scale: u8,
    geohash_precision_bits: u8,
    dict_tail: u32,
    cell_tail: u32,
    col_idx: u16,
    dict_count: u32,
}

#[derive(Clone, Copy, Debug)]
struct SymbolLookupUndo {
    bucket_idx: usize,
    previous_head: u32,
}

#[derive(Clone, Copy, Debug)]
struct Checkpoint {
    columns_len: usize,
    cells_len: usize,
    symbol_dict_len: usize,
    symbol_lookup_undo_len: usize,
    row_count: usize,
    current_len: usize,
    total_schema_len: usize,
    bool_column_count: usize,
    fixed1_column_count: usize,
    fixed2_column_count: usize,
    fixed4_column_count: usize,
    fixed8_column_count: usize,
    sparse_column_count: usize,
    active_bitmap_column_count: usize,
    symbol_hash_resize_epoch: u64,
}

// --- Row group planner (unified estimator + flush scratch) ---

pub(crate) struct RowGroupPlanner {
    columns: Vec<ColumnStats>,
    cells: Vec<CellRef>,
    symbol_dict: Vec<SymbolEntry>,
    symbol_hash_buckets: Vec<u32>,
    undo_stack: Vec<ColumnUndo>,
    symbol_lookup_undo: Vec<SymbolLookupUndo>,
    row_count: usize,
    current_len: usize,
    total_schema_len: usize,
    bool_column_count: usize,
    fixed1_column_count: usize,
    fixed2_column_count: usize,
    fixed4_column_count: usize,
    fixed8_column_count: usize,
    sparse_column_count: usize,
    active_bitmap_column_count: usize,
    symbol_hash_resize_epoch: u64,
    symbol_hasher: RandomState,
}

impl Clone for RowGroupPlanner {
    fn clone(&self) -> Self {
        Self {
            columns: self.columns.clone(),
            cells: self.cells.clone(),
            symbol_dict: self.symbol_dict.clone(),
            symbol_hash_buckets: self.symbol_hash_buckets.clone(),
            undo_stack: Vec::new(),
            symbol_lookup_undo: Vec::new(),
            row_count: self.row_count,
            current_len: self.current_len,
            total_schema_len: self.total_schema_len,
            bool_column_count: self.bool_column_count,
            fixed1_column_count: self.fixed1_column_count,
            fixed2_column_count: self.fixed2_column_count,
            fixed4_column_count: self.fixed4_column_count,
            fixed8_column_count: self.fixed8_column_count,
            sparse_column_count: self.sparse_column_count,
            active_bitmap_column_count: self.active_bitmap_column_count,
            symbol_hash_resize_epoch: self.symbol_hash_resize_epoch,
            symbol_hasher: self.symbol_hasher.clone(),
        }
    }
}

impl std::fmt::Debug for RowGroupPlanner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RowGroupPlanner")
            .field("columns", &self.columns)
            .field("cells_len", &self.cells.len())
            .field("row_count", &self.row_count)
            .field("current_len", &self.current_len)
            .finish()
    }
}

impl RowGroupPlanner {
    fn checked_u16(value: usize, what: &'static str) -> crate::Result<u16> {
        if value > u16::MAX as usize {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/UDP {} exceeds maximum of {}",
                what,
                u16::MAX
            ));
        }
        Ok(value as u16)
    }

    fn checked_u32(value: usize, what: &'static str) -> crate::Result<u32> {
        checked_qwp_u32(value, what)
    }

    fn new() -> Self {
        Self {
            columns: Vec::new(),
            cells: Vec::new(),
            symbol_dict: Vec::new(),
            symbol_hash_buckets: Vec::new(),
            undo_stack: Vec::new(),
            symbol_lookup_undo: Vec::new(),
            row_count: 0,
            current_len: 0,
            total_schema_len: 0,
            bool_column_count: 0,
            fixed1_column_count: 0,
            fixed2_column_count: 0,
            fixed4_column_count: 0,
            fixed8_column_count: 0,
            sparse_column_count: 0,
            active_bitmap_column_count: 0,
            symbol_hash_resize_epoch: 0,
            symbol_hasher: RandomState::new(),
        }
    }

    fn clear(&mut self) {
        self.columns.clear();
        self.cells.clear();
        self.symbol_dict.clear();
        self.symbol_hash_buckets.fill(CELL_END);
        self.undo_stack.clear();
        self.symbol_lookup_undo.clear();
        self.row_count = 0;
        self.current_len = 0;
        self.total_schema_len = 0;
        self.bool_column_count = 0;
        self.fixed1_column_count = 0;
        self.fixed2_column_count = 0;
        self.fixed4_column_count = 0;
        self.fixed8_column_count = 0;
        self.sparse_column_count = 0;
        self.active_bitmap_column_count = 0;
        self.symbol_hash_resize_epoch = 0;
    }

    fn reserve_for_encoded_bytes(&mut self, encoded_bytes: usize) {
        let max_entries = (encoded_bytes / 3).max(1);
        self.columns.reserve(max_entries);
        self.cells.reserve(max_entries);
        self.symbol_dict.reserve(max_entries);
        self.undo_stack.reserve(max_entries);
        self.symbol_lookup_undo.reserve(max_entries);
        self.ensure_symbol_hash_capacity(max_entries);
    }

    fn row_count(&self) -> usize {
        self.row_count
    }

    fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            columns_len: self.columns.len(),
            cells_len: self.cells.len(),
            symbol_dict_len: self.symbol_dict.len(),
            symbol_lookup_undo_len: self.symbol_lookup_undo.len(),
            row_count: self.row_count,
            current_len: self.current_len,
            total_schema_len: self.total_schema_len,
            bool_column_count: self.bool_column_count,
            fixed1_column_count: self.fixed1_column_count,
            fixed2_column_count: self.fixed2_column_count,
            fixed4_column_count: self.fixed4_column_count,
            fixed8_column_count: self.fixed8_column_count,
            sparse_column_count: self.sparse_column_count,
            active_bitmap_column_count: self.active_bitmap_column_count,
            symbol_hash_resize_epoch: self.symbol_hash_resize_epoch,
        }
    }

    fn rollback(&mut self, cp: Checkpoint) {
        for undo in self.undo_stack.drain(..).rev() {
            let col = &mut self.columns[undo.col_idx as usize];
            col.non_null_count = undo.non_null_count;
            col.variable_data_len = undo.variable_data_len;
            col.symbol_dict_bytes = undo.symbol_dict_bytes;
            col.symbol_row_index_bytes = undo.symbol_row_index_bytes;
            col.decimal_scale = undo.decimal_scale;
            col.geohash_precision_bits = undo.geohash_precision_bits;
            col.dict_tail = undo.dict_tail;
            col.dict_count = undo.dict_count;
            if col.dict_tail != CELL_END {
                self.symbol_dict[col.dict_tail as usize].next = CELL_END;
            } else {
                col.dict_head = CELL_END;
            }
            col.cell_tail = undo.cell_tail;
            if col.cell_tail != CELL_END {
                self.cells[col.cell_tail as usize].next = CELL_END;
            } else {
                col.cell_head = CELL_END;
            }
        }
        if self.symbol_hash_resize_epoch == cp.symbol_hash_resize_epoch {
            for undo in self
                .symbol_lookup_undo
                .drain(cp.symbol_lookup_undo_len..)
                .rev()
            {
                self.symbol_hash_buckets[undo.bucket_idx] = undo.previous_head;
            }
        } else {
            self.symbol_lookup_undo.truncate(cp.symbol_lookup_undo_len);
        }
        self.columns.truncate(cp.columns_len);
        self.cells.truncate(cp.cells_len);
        self.symbol_dict.truncate(cp.symbol_dict_len);
        if self.symbol_hash_resize_epoch != cp.symbol_hash_resize_epoch {
            self.rebuild_symbol_hash();
        }
        self.row_count = cp.row_count;
        self.current_len = cp.current_len;
        self.total_schema_len = cp.total_schema_len;
        self.bool_column_count = cp.bool_column_count;
        self.fixed1_column_count = cp.fixed1_column_count;
        self.fixed2_column_count = cp.fixed2_column_count;
        self.fixed4_column_count = cp.fixed4_column_count;
        self.fixed8_column_count = cp.fixed8_column_count;
        self.sparse_column_count = cp.sparse_column_count;
        self.active_bitmap_column_count = cp.active_bitmap_column_count;
    }

    fn add_row(
        &mut self,
        row: &RowMeta,
        row_entries: &[EntryMeta],
        name_bytes: &[u8],
        value_bytes: &[u8],
        table_name_len: usize,
    ) -> crate::Result<()> {
        let old_row_count = self.row_count;
        let old_column_count = self.columns.len();
        let old_total_schema_len = self.total_schema_len;
        let old_bool_column_count = self.bool_column_count;
        let old_fixed1_column_count = self.fixed1_column_count;
        let old_fixed2_column_count = self.fixed2_column_count;
        let old_fixed4_column_count = self.fixed4_column_count;
        let old_fixed8_column_count = self.fixed8_column_count;
        let old_sparse_column_count = self.sparse_column_count;
        let old_active_bitmap_column_count = self.active_bitmap_column_count;
        self.undo_stack.clear();
        let ts_entry = row.designated_ts.map(designated_ts_entry);
        let extra = ts_entry.as_slice();
        let row_idx = Self::checked_u32(self.row_count, "row group row count")?;

        for entry in row_entries.iter().chain(extra.iter()) {
            let entry_name = &name_bytes[entry.name.0.as_range()];
            if let Some(idx) = self.find_column(entry_name, name_bytes) {
                let undo_col_idx = Self::checked_u16(idx, "column count")?;
                let col = &mut self.columns[idx];
                if col.kind != entry.value.kind() {
                    return Err(batched_type_change_error(entry_name));
                }
                self.undo_stack.push(ColumnUndo {
                    non_null_count: col.non_null_count,
                    variable_data_len: col.variable_data_len,
                    symbol_dict_bytes: col.symbol_dict_bytes,
                    symbol_row_index_bytes: col.symbol_row_index_bytes,
                    decimal_scale: col.decimal_scale,
                    geohash_precision_bits: col.geohash_precision_bits,
                    dict_tail: col.dict_tail,
                    cell_tail: col.cell_tail,
                    col_idx: undo_col_idx,
                    dict_count: col.dict_count,
                });
                let cell_idx = checked_qwp_push_index(self.cells.len(), "planner cell count")?;
                self.cells.push(CellRef {
                    row_idx,
                    symbol_dict_idx: 0,
                    next: CELL_END,
                    value: entry.value,
                });
                if col.cell_tail != CELL_END {
                    self.cells[col.cell_tail as usize].next = cell_idx;
                } else {
                    col.cell_head = cell_idx;
                }
                col.cell_tail = cell_idx;
                if col.kind == ColumnKind::Symbol {
                    self.add_symbol_value(idx, cell_idx, &entry.value, value_bytes)?;
                } else {
                    col.add_non_symbol_value(&entry.value)?;
                }
            } else {
                self.push_new_column(entry, value_bytes, row_idx)?;
            }
        }

        let new_row_count = old_row_count.checked_add(1).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/UDP row group row count exceeds maximum"
            )
        })?;
        if old_row_count == 0 {
            let mut total = base_datagram_len(table_name_len, new_row_count, self.columns.len());
            total += self.total_schema_len;
            let mut active_bitmap_column_count = 0usize;
            for col in &self.columns {
                total += col.payload_len(new_row_count)?;
                if col.uses_null_bitmap(new_row_count) {
                    active_bitmap_column_count += 1;
                }
            }
            self.row_count = new_row_count;
            self.current_len = total;
            self.active_bitmap_column_count = active_bitmap_column_count;
            return Ok(());
        }

        let packed_delta = packed_bytes(new_row_count) - packed_bytes(old_row_count);
        let bitmap_delta = bitmap_bytes(new_row_count) - bitmap_bytes(old_row_count);

        let mut touched_bool_column_count = 0usize;
        let mut touched_fixed1_column_count = 0usize;
        let mut touched_fixed2_column_count = 0usize;
        let mut touched_fixed4_column_count = 0usize;
        let mut touched_fixed8_column_count = 0usize;
        let mut touched_sparse_column_count = 0usize;
        let mut touched_old_active_bitmap_column_count = 0usize;
        let mut touched_new_active_bitmap_column_count = 0usize;
        let mut delta =
            qwp_varint_size(new_row_count as u64) - qwp_varint_size(old_row_count as u64);

        for undo in &self.undo_stack {
            let col = &self.columns[undo.col_idx as usize];
            match col.kind {
                ColumnKind::Bool => touched_bool_column_count += 1,
                ColumnKind::I8 => touched_fixed1_column_count += 1,
                ColumnKind::I16 | ColumnKind::Char => touched_fixed2_column_count += 1,
                ColumnKind::I32 | ColumnKind::F32 => touched_fixed4_column_count += 1,
                ColumnKind::I64 | ColumnKind::F64 => touched_fixed8_column_count += 1,
                ColumnKind::Symbol
                | ColumnKind::String
                | ColumnKind::Decimal64
                | ColumnKind::Decimal128
                | ColumnKind::Decimal
                | ColumnKind::DoubleArray
                | ColumnKind::TimestampMicros
                | ColumnKind::TimestampNanos
                | ColumnKind::Uuid
                | ColumnKind::Long256
                | ColumnKind::Ipv4
                | ColumnKind::Date
                | ColumnKind::Binary
                | ColumnKind::Geohash
                | ColumnKind::LongArray => {
                    touched_sparse_column_count += 1;
                    if uses_null_bitmap(
                        col.supports_sparse_nulls,
                        old_row_count,
                        undo.non_null_count,
                    ) {
                        touched_old_active_bitmap_column_count += 1;
                    }
                    if col.uses_null_bitmap(new_row_count) {
                        touched_new_active_bitmap_column_count += 1;
                    }
                }
            }
            delta += col.payload_len(new_row_count)?
                - ColumnStats::payload_len_parts(
                    col.kind,
                    col.supports_sparse_nulls,
                    old_row_count,
                    undo.non_null_count,
                    undo.variable_data_len,
                    undo.symbol_dict_bytes,
                    undo.symbol_row_index_bytes,
                    undo.dict_count,
                )?;
        }

        debug_assert!(touched_bool_column_count <= old_bool_column_count);
        debug_assert!(touched_fixed1_column_count <= old_fixed1_column_count);
        debug_assert!(touched_fixed2_column_count <= old_fixed2_column_count);
        debug_assert!(touched_fixed4_column_count <= old_fixed4_column_count);
        debug_assert!(touched_fixed8_column_count <= old_fixed8_column_count);
        debug_assert!(touched_sparse_column_count <= old_sparse_column_count);
        debug_assert!(touched_old_active_bitmap_column_count <= old_active_bitmap_column_count);

        delta += (old_bool_column_count - touched_bool_column_count) * packed_delta;
        delta += old_fixed1_column_count - touched_fixed1_column_count;
        delta += (old_fixed2_column_count - touched_fixed2_column_count) * 2;
        delta += (old_fixed4_column_count - touched_fixed4_column_count) * 4;
        delta += (old_fixed8_column_count - touched_fixed8_column_count) * 8;
        let old_dense_sparse_column_count =
            old_sparse_column_count - old_active_bitmap_column_count;
        let touched_old_dense_sparse_column_count =
            touched_sparse_column_count - touched_old_active_bitmap_column_count;
        debug_assert!(touched_old_dense_sparse_column_count <= old_dense_sparse_column_count);
        delta += (old_active_bitmap_column_count - touched_old_active_bitmap_column_count)
            * bitmap_delta;
        delta += (old_dense_sparse_column_count - touched_old_dense_sparse_column_count)
            * bitmap_bytes(new_row_count);

        let mut new_bitmap_column_count = 0usize;
        if self.columns.len() > old_column_count {
            delta += qwp_varint_size(self.columns.len() as u64)
                - qwp_varint_size(old_column_count as u64);
            delta += self.total_schema_len - old_total_schema_len;
            for col in &self.columns[old_column_count..] {
                delta += col.payload_len(new_row_count)?;
                if col.uses_null_bitmap(new_row_count) {
                    new_bitmap_column_count += 1;
                }
            }
        }

        self.row_count = new_row_count;
        self.current_len += delta;
        self.active_bitmap_column_count = (old_sparse_column_count - touched_sparse_column_count)
            + touched_new_active_bitmap_column_count
            + new_bitmap_column_count;
        debug_assert!(self.active_bitmap_column_count <= self.sparse_column_count);
        Ok(())
    }

    fn add_symbol_value(
        &mut self,
        col_idx: usize,
        cell_idx: u32,
        value: &ValueRef,
        value_bytes: &[u8],
    ) -> crate::Result<()> {
        let ValueRef::Symbol(vs) = value else {
            return Ok(());
        };
        let symbol_bytes = &value_bytes[vs.0.as_range()];
        let col_idx_u16 = Self::checked_u16(col_idx, "column count")?;
        let hash = self.hash_symbol_key(col_idx_u16, symbol_bytes);
        self.ensure_symbol_hash_capacity(self.symbol_dict.len() + 1);
        let bucket_idx = self.symbol_hash_bucket_idx(hash);
        let mut cursor = self.symbol_hash_buckets[bucket_idx];
        let mut found_idx = None;
        while cursor != CELL_END {
            let de = &self.symbol_dict[cursor as usize];
            if de.hash == hash
                && de.col_idx == col_idx_u16
                && &value_bytes[de.value.0.as_range()] == symbol_bytes
            {
                found_idx = Some(de.dict_idx as usize);
                break;
            }
            cursor = de.bucket_next;
        }
        let sym_idx = if let Some(idx) = found_idx {
            idx
        } else {
            self.columns[col_idx].dict_count as usize
        };
        let symbol_dict_idx = Self::checked_u32(sym_idx, "symbol dictionary index")?;

        let col = &self.columns[col_idx];
        let new_non_null_count = col.non_null_count.checked_add(1).ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/UDP non-null value count exceeds maximum of {}",
                u32::MAX
            )
        })?;
        let new_symbol_row_index_bytes = checked_qwp_usize_add(
            col.symbol_row_index_bytes,
            qwp_varint_size(sym_idx as u64),
            "symbol row-index bytes",
        )?;
        let new_symbol_dict_bytes = if found_idx.is_none() {
            checked_qwp_usize_add(
                col.symbol_dict_bytes,
                qwp_string_byte_len(symbol_bytes.len()),
                "symbol dictionary bytes",
            )?
        } else {
            col.symbol_dict_bytes
        };
        let new_dict_count = if found_idx.is_none() {
            col.dict_count.checked_add(1).ok_or_else(|| {
                error::fmt!(
                    InvalidApiCall,
                    "QWP/UDP symbol dictionary count exceeds maximum of {}",
                    u32::MAX
                )
            })?
        } else {
            col.dict_count
        };

        let col = &mut self.columns[col_idx];
        col.non_null_count = new_non_null_count;
        col.symbol_row_index_bytes = new_symbol_row_index_bytes;
        if found_idx.is_none() {
            col.symbol_dict_bytes = new_symbol_dict_bytes;
            // Use push-index semantics: reject len >= u32::MAX so that
            // valid indices are always < CELL_END (u32::MAX sentinel).
            let dict_idx =
                checked_qwp_push_index(self.symbol_dict.len(), "symbol dictionary length")?;
            let previous_head = self.symbol_hash_buckets[bucket_idx];
            self.symbol_lookup_undo.push(SymbolLookupUndo {
                bucket_idx,
                previous_head,
            });
            self.symbol_dict.push(SymbolEntry {
                value: *vs,
                next: CELL_END,
                bucket_next: previous_head,
                hash,
                col_idx: col_idx_u16,
                dict_idx: col.dict_count,
            });
            self.symbol_hash_buckets[bucket_idx] = dict_idx;
            if col.dict_tail != CELL_END {
                self.symbol_dict[col.dict_tail as usize].next = dict_idx;
            } else {
                col.dict_head = dict_idx;
            }
            col.dict_tail = dict_idx;
            col.dict_count = new_dict_count;
        }
        // Store pre-computed index so encoding is O(1) per cell.
        // The caller passes the index of the cell it pushed immediately
        // before invoking this helper.
        self.cells[cell_idx as usize].symbol_dict_idx = symbol_dict_idx;
        Ok(())
    }

    fn hash_symbol_key(&self, col_idx: u16, symbol_bytes: &[u8]) -> u64 {
        let mut hasher = self.symbol_hasher.build_hasher();
        col_idx.hash(&mut hasher);
        symbol_bytes.hash(&mut hasher);
        hasher.finish()
    }

    fn symbol_hash_bucket_idx(&self, hash: u64) -> usize {
        debug_assert!(!self.symbol_hash_buckets.is_empty());
        hash as usize & (self.symbol_hash_buckets.len() - 1)
    }

    fn ensure_symbol_hash_capacity(&mut self, required_entries: usize) {
        let min_buckets = (required_entries.saturating_mul(2))
            .next_power_of_two()
            .max(16);
        if self.symbol_hash_buckets.len() >= min_buckets {
            return;
        }
        self.symbol_hash_buckets.resize(min_buckets, CELL_END);
        self.symbol_hash_resize_epoch += 1;
        self.rebuild_symbol_hash();
    }

    fn rebuild_symbol_hash(&mut self) {
        if self.symbol_hash_buckets.is_empty() {
            return;
        }
        // All dict indices are < CELL_END because add_symbol_value uses
        // checked_qwp_push_index, which rejects len >= u32::MAX.
        debug_assert!(self.symbol_dict.len() <= u32::MAX as usize);
        self.symbol_hash_buckets.fill(CELL_END);
        for (dict_idx, entry) in self.symbol_dict.iter_mut().enumerate() {
            let bucket_idx = entry.hash as usize & (self.symbol_hash_buckets.len() - 1);
            entry.bucket_next = self.symbol_hash_buckets[bucket_idx];
            self.symbol_hash_buckets[bucket_idx] = dict_idx as u32;
        }
    }

    fn push_new_column(
        &mut self,
        entry: &EntryMeta,
        value_bytes: &[u8],
        row_idx: u32,
    ) -> crate::Result<()> {
        let col = ColumnStats::new(entry);
        match col.kind {
            ColumnKind::Bool => self.bool_column_count += 1,
            ColumnKind::I8 => self.fixed1_column_count += 1,
            ColumnKind::I16 | ColumnKind::Char => self.fixed2_column_count += 1,
            ColumnKind::I32 | ColumnKind::F32 => self.fixed4_column_count += 1,
            ColumnKind::I64 | ColumnKind::F64 => self.fixed8_column_count += 1,
            ColumnKind::Symbol
            | ColumnKind::String
            | ColumnKind::Decimal64
            | ColumnKind::Decimal128
            | ColumnKind::Decimal
            | ColumnKind::DoubleArray
            | ColumnKind::TimestampMicros
            | ColumnKind::TimestampNanos
            | ColumnKind::Uuid
            | ColumnKind::Long256
            | ColumnKind::Ipv4
            | ColumnKind::Date
            | ColumnKind::Binary
            | ColumnKind::Geohash
            | ColumnKind::LongArray => self.sparse_column_count += 1,
        }
        self.total_schema_len += col.cached_schema_len;
        self.columns.push(col);
        let col_idx = self.columns.len() - 1;

        let cell_idx = checked_qwp_push_index(self.cells.len(), "planner cell count")?;
        self.cells.push(CellRef {
            row_idx,
            symbol_dict_idx: 0,
            next: CELL_END,
            value: entry.value,
        });
        let col = &mut self.columns[col_idx];
        col.cell_head = cell_idx;
        col.cell_tail = cell_idx;

        if entry.value.kind() == ColumnKind::Symbol {
            self.add_symbol_value(col_idx, cell_idx, &entry.value, value_bytes)?;
        } else {
            self.columns[col_idx].add_non_symbol_value(&entry.value)?;
        }
        Ok(())
    }

    fn find_column(&self, name: &[u8], name_bytes: &[u8]) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| &name_bytes[c.name.0.as_range()] == name)
    }
}

// --- Encoding functions ---

fn base_datagram_len(table_name_len: usize, row_count: usize, column_count: usize) -> usize {
    QWP_MESSAGE_HEADER_SIZE
        + qwp_string_byte_len(table_name_len)
        + qwp_varint_size(row_count as u64)
        + qwp_varint_size(column_count as u64)
        + 1
        + qwp_varint_size(QWP_INLINE_SCHEMA_ID)
}

fn qwp_string_byte_len(byte_len: usize) -> usize {
    qwp_varint_size(byte_len as u64) + byte_len
}

fn qwp_varint_size(mut value: u64) -> usize {
    let mut size = 1usize;
    while value > 0x7F {
        value >>= 7;
        size += 1;
    }
    size
}

fn packed_bytes(value_count: usize) -> usize {
    value_count.div_ceil(8)
}

fn bitmap_bytes(value_count: usize) -> usize {
    value_count.div_ceil(8)
}

fn uses_null_bitmap(supports_sparse_nulls: bool, row_count: usize, non_null_count: u32) -> bool {
    supports_sparse_nulls && (non_null_count as usize) < row_count
}

fn kind_supports_sparse_nulls(kind: ColumnKind) -> bool {
    // QuestDB BOOLEAN is non-nullable, so sparse/missing bool values are
    // encoded via the packed payload as `false` rather than through a null
    // bitmap. Only the types below preserve sparse nulls explicitly.
    matches!(
        kind,
        ColumnKind::Symbol
            | ColumnKind::String
            | ColumnKind::Decimal64
            | ColumnKind::Decimal128
            | ColumnKind::Decimal
            | ColumnKind::DoubleArray
            | ColumnKind::TimestampMicros
            | ColumnKind::TimestampNanos
            | ColumnKind::Uuid
            | ColumnKind::Long256
            | ColumnKind::Ipv4
            | ColumnKind::Date
            | ColumnKind::Binary
            | ColumnKind::Geohash
            | ColumnKind::LongArray
    )
}

fn narrow_decimal_le_fits(bytes: &[u8; QWP_DECIMAL_MAG_BYTES], width: usize) -> Option<&[u8]> {
    debug_assert!(width == 8 || width == 16);
    let (low, high) = bytes.split_at(width);
    let sign_byte = if (low[width - 1] & 0x80) != 0 {
        0xFF
    } else {
        0x00
    };
    if high.iter().all(|&b| b == sign_byte) {
        Some(low)
    } else {
        None
    }
}

fn decimal_fit_error(width: u32) -> crate::Error {
    error::fmt!(
        InvalidApiCall,
        "decimal value does not fit DECIMAL{width} wire width"
    )
}

fn write_qwp_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7F {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_qwp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_qwp_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn cell_value_is_null(value: ValueRef) -> bool {
    matches!(value, ValueRef::DecimalNull)
}

fn wire_type_byte(kind: ColumnKind, nullable: bool) -> u8 {
    let _ = nullable;
    match kind {
        ColumnKind::Bool => QWP_TYPE_BOOLEAN,
        ColumnKind::I8 => QWP_TYPE_BYTE,
        ColumnKind::I16 => QWP_TYPE_SHORT,
        ColumnKind::I32 => QWP_TYPE_INT,
        ColumnKind::I64 => QWP_TYPE_LONG,
        ColumnKind::F32 => QWP_TYPE_FLOAT,
        ColumnKind::F64 => QWP_TYPE_DOUBLE,
        ColumnKind::Symbol => QWP_TYPE_SYMBOL,
        ColumnKind::String => QWP_TYPE_VARCHAR,
        ColumnKind::Decimal64 => QWP_TYPE_DECIMAL64,
        ColumnKind::Decimal128 => QWP_TYPE_DECIMAL128,
        ColumnKind::Decimal => QWP_TYPE_DECIMAL256,
        ColumnKind::DoubleArray => QWP_TYPE_DOUBLE_ARRAY,
        ColumnKind::TimestampMicros => QWP_TYPE_TIMESTAMP,
        ColumnKind::TimestampNanos => QWP_TYPE_TIMESTAMP_NANOS,
        ColumnKind::Uuid => QWP_TYPE_UUID,
        ColumnKind::Long256 => QWP_TYPE_LONG256,
        ColumnKind::Ipv4 => QWP_TYPE_IPV4,
        ColumnKind::Date => QWP_TYPE_DATE,
        ColumnKind::Char => QWP_TYPE_CHAR,
        ColumnKind::Binary => QWP_TYPE_BINARY,
        ColumnKind::Geohash => QWP_TYPE_GEOHASH,
        ColumnKind::LongArray => QWP_TYPE_LONG_ARRAY,
    }
}

fn geohash_bytes_per_value(precision_bits: u8) -> usize {
    (precision_bits as usize).div_ceil(8)
}

/// Encode a row group directly from the planner's pre-indexed cells.
/// No intermediate dense matrices or entry scanning - writes directly to `out`.
fn encode_row_group_from_scratch(
    planner: &RowGroupPlanner,
    name_bytes: &[u8],
    value_bytes: &[u8],
    table_name: &[u8],
    out: &mut Vec<u8>,
) -> crate::Result<()> {
    let row_count = planner.row_count;

    // Write header placeholder
    let header_start = out.len();
    out.extend_from_slice(&[0u8; QWP_MESSAGE_HEADER_SIZE]);
    let payload_start = out.len();

    // Payload: table name, row count, column count, schema mode, schema id
    write_qwp_bytes(out, table_name);
    write_qwp_varint(out, row_count as u64);
    write_qwp_varint(out, planner.columns.len() as u64);
    out.push(QWP_SCHEMA_MODE_FULL);
    write_qwp_varint(out, QWP_INLINE_SCHEMA_ID);

    // Schema
    for col in &planner.columns {
        write_qwp_bytes(out, &name_bytes[col.name.0.as_range()]);
        out.push(wire_type_byte(col.kind, col.uses_null_bitmap(row_count)));
    }

    // Column payloads
    for col in &planner.columns {
        encode_column_from_cells(
            col,
            row_count,
            &planner.cells,
            &planner.symbol_dict,
            value_bytes,
            out,
        )?;
    }

    // Fill header
    let header = QwpMessageHeader {
        magic: *b"QWP1",
        version: QWP_VERSION_1,
        flags: 0,
        table_count: 1,
        payload_len: checked_qwp_u32(out.len() - payload_start, "datagram payload length")?,
    };
    header.write_to(&mut out[header_start..header_start + QWP_MESSAGE_HEADER_SIZE]);

    Ok(())
}

// --- Cell iteration helpers ---

/// Iterates non-null cells for a column via linked list.
struct CellIter<'a> {
    cells: &'a [CellRef],
    cursor: u32,
}

impl<'a> CellIter<'a> {
    fn new(cells: &'a [CellRef], head: u32) -> Self {
        Self {
            cells,
            cursor: head,
        }
    }
}

impl<'a> Iterator for CellIter<'a> {
    type Item = &'a CellRef;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == CELL_END {
            return None;
        }
        let cell = &self.cells[self.cursor as usize];
        self.cursor = cell.next;
        Some(cell)
    }
}

/// Iterates all rows 0..row_count, yielding `Some(&CellRef)` for non-null
/// rows and `None` for gaps. Used for null bitmaps and non-nullable gap-filling.
struct GapFillIter<'a> {
    cells: &'a [CellRef],
    cursor: u32,
    next_non_null: u32,
    row: u32,
    row_count: u32,
}

impl<'a> GapFillIter<'a> {
    fn new(cells: &'a [CellRef], head: u32, row_count: usize) -> crate::Result<Self> {
        let next_non_null = if head != CELL_END {
            cells[head as usize].row_idx
        } else {
            u32::MAX
        };
        Ok(Self {
            cells,
            cursor: head,
            next_non_null,
            row: 0,
            row_count: checked_qwp_u32(row_count, "row group row count")?,
        })
    }
}

impl<'a> Iterator for GapFillIter<'a> {
    type Item = Option<&'a CellRef>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.row >= self.row_count {
            return None;
        }
        let result = if self.row == self.next_non_null {
            let cell = &self.cells[self.cursor as usize];
            self.cursor = cell.next;
            self.next_non_null = if self.cursor != CELL_END {
                self.cells[self.cursor as usize].row_idx
            } else {
                u32::MAX
            };
            Some(cell)
        } else {
            None
        };
        self.row += 1;
        Some(result)
    }
}

/// Encode a single column's payload by following the pre-indexed cell linked list.
/// O(cells_for_column) instead of O(rows * entries_per_row) name comparisons.
fn encode_column_from_cells(
    col: &ColumnStats,
    row_count: usize,
    cells: &[CellRef],
    symbol_dict: &[SymbolEntry],
    value_bytes: &[u8],
    out: &mut Vec<u8>,
) -> crate::Result<()> {
    let uses_null_bitmap = col.uses_null_bitmap(row_count);

    out.push(u8::from(uses_null_bitmap));

    // Null bitmap
    if uses_null_bitmap {
        let mut packed = 0u8;
        let mut bit_idx = 0u8;
        for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
            if maybe_cell.is_none_or(|cell| cell_value_is_null(cell.value)) {
                packed |= 1 << bit_idx;
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

    match col.kind {
        // Bool, I64 and F64 never use null bitmaps in QWP. Gaps are filled
        // with sentinels (false / i64::MIN / NaN) matching QuestDB's internal
        // storage, so no null bitmap is needed.
        ColumnKind::Bool => {
            debug_assert!(
                !uses_null_bitmap,
                "Bool columns must not use null bitmaps in QWP"
            );
            let mut packed = 0u8;
            let mut bit_idx = 0u8;
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                if maybe_cell.is_some_and(|c| matches!(c.value, ValueRef::Bool(true))) {
                    packed |= 1 << bit_idx;
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

        ColumnKind::I8 => {
            debug_assert!(
                !uses_null_bitmap,
                "I8 columns must not use null bitmaps in QWP"
            );
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                let v = match maybe_cell.map(|c| c.value) {
                    Some(ValueRef::I8(v)) => v,
                    _ => 0,
                };
                out.push(v as u8);
            }
        }

        ColumnKind::I16 => {
            debug_assert!(
                !uses_null_bitmap,
                "I16 columns must not use null bitmaps in QWP"
            );
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                let v = match maybe_cell.map(|c| c.value) {
                    Some(ValueRef::I16(v)) => v,
                    _ => 0,
                };
                out.extend_from_slice(&v.to_le_bytes());
            }
        }

        ColumnKind::I32 => {
            debug_assert!(
                !uses_null_bitmap,
                "I32 columns must not use null bitmaps in QWP"
            );
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                let v = match maybe_cell.map(|c| c.value) {
                    Some(ValueRef::I32(v)) => v,
                    _ => i32::MIN,
                };
                out.extend_from_slice(&v.to_le_bytes());
            }
        }

        ColumnKind::I64 => {
            debug_assert!(
                !uses_null_bitmap,
                "I64 columns must not use null bitmaps in QWP"
            );
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                let v = match maybe_cell.map(|c| c.value) {
                    Some(ValueRef::I64(v)) => v,
                    _ => i64::MIN,
                };
                out.extend_from_slice(&v.to_le_bytes());
            }
        }

        ColumnKind::F64 => {
            debug_assert!(
                !uses_null_bitmap,
                "F64 columns must not use null bitmaps in QWP"
            );
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                let v = match maybe_cell.map(|c| c.value) {
                    Some(ValueRef::F64(v)) => v,
                    _ => f64::NAN,
                };
                out.extend_from_slice(&v.to_le_bytes());
            }
        }

        ColumnKind::F32 => {
            debug_assert!(
                !uses_null_bitmap,
                "F32 columns must not use null bitmaps in QWP"
            );
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                let v = match maybe_cell.map(|c| c.value) {
                    Some(ValueRef::F32(v)) => v,
                    _ => f32::NAN,
                };
                out.extend_from_slice(&v.to_le_bytes());
            }
        }

        ColumnKind::TimestampMicros | ColumnKind::TimestampNanos => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::TimestampMicros(v) | ValueRef::TimestampNanos(v) = cell.value {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }

        ColumnKind::String => {
            let non_null_count = col.non_null_count as usize;
            let offsets_start = out.len();
            debug_assert!(
                non_null_count
                    .checked_add(1)
                    .and_then(|n| n.checked_mul(4))
                    .is_some()
            );
            let offset_count = checked_qwp_usize_add(non_null_count, 1, "string offset count")?;
            let offset_table_len = checked_qwp_usize_mul(offset_count, 4, "string offset table")?;
            let offsets_end =
                checked_qwp_usize_add(offsets_start, offset_table_len, "string offset table")?;
            out.resize(offsets_end, 0);
            out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());

            let mut cumulative: usize = 0;
            let mut offset_idx = 1usize;
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::String(vs) = cell.value {
                    let text = &value_bytes[vs.0.as_range()];
                    out.extend_from_slice(text);
                    cumulative =
                        checked_qwp_usize_add(cumulative, text.len(), "string column bytes")?;
                    let offset_u32 = checked_qwp_u32(cumulative, "string column offset")?;
                    let pos = offsets_start + offset_idx * 4;
                    out[pos..pos + 4].copy_from_slice(&offset_u32.to_le_bytes());
                    offset_idx += 1;
                }
            }
        }

        ColumnKind::Decimal => {
            out.push(if col.decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                0
            } else {
                col.decimal_scale
            });
            for cell in CellIter::new(cells, col.cell_head) {
                match cell.value {
                    ValueRef::DecimalNull => {}
                    ValueRef::Decimal(decimal_value) => {
                        out.extend_from_slice(
                            &decimal_value.wire_bytes_with_scale(value_bytes, col.decimal_scale)?,
                        );
                    }
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP type mismatch for decimal column"
                        ));
                    }
                }
            }
        }

        ColumnKind::Decimal64 => {
            out.push(if col.decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                0
            } else {
                col.decimal_scale
            });
            for cell in CellIter::new(cells, col.cell_head) {
                match cell.value {
                    ValueRef::Decimal64Null => {}
                    ValueRef::Decimal64(decimal_value) => {
                        let bytes =
                            decimal_value.wire_bytes_with_scale(value_bytes, col.decimal_scale)?;
                        let low = narrow_decimal_le_fits(&bytes, 8)
                            .ok_or_else(|| decimal_fit_error(64))?;
                        out.extend_from_slice(low);
                    }
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP type mismatch for decimal64 column"
                        ));
                    }
                }
            }
        }

        ColumnKind::Decimal128 => {
            out.push(if col.decimal_scale == QWP_DECIMAL_SCALE_UNSET {
                0
            } else {
                col.decimal_scale
            });
            for cell in CellIter::new(cells, col.cell_head) {
                match cell.value {
                    ValueRef::Decimal128Null => {}
                    ValueRef::Decimal128(decimal_value) => {
                        let bytes =
                            decimal_value.wire_bytes_with_scale(value_bytes, col.decimal_scale)?;
                        let low = narrow_decimal_le_fits(&bytes, 16)
                            .ok_or_else(|| decimal_fit_error(128))?;
                        out.extend_from_slice(low);
                    }
                    _ => {
                        return Err(error::fmt!(
                            InvalidApiCall,
                            "internal QWP type mismatch for decimal128 column"
                        ));
                    }
                }
            }
        }

        ColumnKind::DoubleArray => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::DoubleArray(vs) = cell.value {
                    out.extend_from_slice(&value_bytes[vs.0.as_range()]);
                }
            }
        }

        ColumnKind::LongArray => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::LongArray(vs) = cell.value {
                    out.extend_from_slice(&value_bytes[vs.0.as_range()]);
                }
            }
        }

        ColumnKind::Uuid => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::Uuid(vs) = cell.value {
                    out.extend_from_slice(&value_bytes[vs.0.as_range()]);
                }
            }
        }

        ColumnKind::Long256 => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::Long256(vs) = cell.value {
                    out.extend_from_slice(&value_bytes[vs.0.as_range()]);
                }
            }
        }

        ColumnKind::Ipv4 => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::Ipv4(v) = cell.value {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }

        ColumnKind::Date => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::DateMillis(v) = cell.value {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }

        ColumnKind::Char => {
            debug_assert!(
                !uses_null_bitmap,
                "Char columns must not use null bitmaps in QWP"
            );
            for maybe_cell in GapFillIter::new(cells, col.cell_head, row_count)? {
                let v = match maybe_cell.map(|c| c.value) {
                    Some(ValueRef::Char(v)) => v,
                    _ => 0u16,
                };
                out.extend_from_slice(&v.to_le_bytes());
            }
        }

        ColumnKind::Binary => {
            let non_null_count = col.non_null_count as usize;
            let offsets_start = out.len();
            let offset_count = checked_qwp_usize_add(non_null_count, 1, "binary offset count")?;
            let offset_table_len = checked_qwp_usize_mul(offset_count, 4, "binary offset table")?;
            let offsets_end =
                checked_qwp_usize_add(offsets_start, offset_table_len, "binary offset table")?;
            out.resize(offsets_end, 0);
            out[offsets_start..offsets_start + 4].copy_from_slice(&0u32.to_le_bytes());

            let mut cumulative: usize = 0;
            let mut offset_idx = 1usize;
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::Binary(vs) = cell.value {
                    let payload = &value_bytes[vs.0.as_range()];
                    out.extend_from_slice(payload);
                    cumulative =
                        checked_qwp_usize_add(cumulative, payload.len(), "binary column bytes")?;
                    let offset_u32 = checked_qwp_u32(cumulative, "binary column offset")?;
                    let pos = offsets_start + offset_idx * 4;
                    out[pos..pos + 4].copy_from_slice(&offset_u32.to_le_bytes());
                    offset_idx += 1;
                }
            }
        }

        ColumnKind::Geohash => {
            write_qwp_varint(out, col.geohash_precision_bits as u64);
            let bytes_per_value = geohash_bytes_per_value(col.geohash_precision_bits);
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::Geohash { bits, .. } = cell.value {
                    let le = bits.to_le_bytes();
                    out.extend_from_slice(&le[..bytes_per_value]);
                }
            }
        }

        ColumnKind::Symbol => {
            // Dictionary via linked list
            write_qwp_varint(out, col.dict_count as u64);
            let mut dict_cursor = col.dict_head;
            while dict_cursor != CELL_END {
                let de = &symbol_dict[dict_cursor as usize];
                write_qwp_bytes(out, &value_bytes[de.value.0.as_range()]);
                dict_cursor = de.next;
            }
            // Row indexes from pre-computed cell indexes (O(1) per cell)
            for cell in CellIter::new(cells, col.cell_head) {
                write_qwp_varint(out, cell.symbol_dict_idx as u64);
            }
        }
    }

    Ok(())
}

fn to_designated_ts(timestamp: Timestamp) -> DesignatedTs {
    match timestamp {
        Timestamp::Micros(ts) => DesignatedTs::Micros(ts.as_i64()),
        Timestamp::Nanos(ts) => DesignatedTs::Nanos(ts.as_i64()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::{TimestampMicros, TimestampNanos};
    use crate::tests::qwp_decode::{DecodedDatagram, DecodedValue, decode_datagram};
    use proptest::prelude::*;
    use std::collections::BTreeMap;

    fn exact_planner_len(planner: &RowGroupPlanner, table_name_len: usize) -> usize {
        if planner.row_count == 0 {
            return 0;
        }
        let mut total = base_datagram_len(table_name_len, planner.row_count, planner.columns.len());
        total += planner.total_schema_len;
        for col in &planner.columns {
            total += col.payload_len(planner.row_count).unwrap();
        }
        total
    }

    fn encoded_planner_len(
        planner: &RowGroupPlanner,
        name_bytes: &[u8],
        value_bytes: &[u8],
        table_name: &str,
    ) -> usize {
        let mut datagram = Vec::new();
        encode_row_group_from_scratch(
            planner,
            name_bytes,
            value_bytes,
            table_name.as_bytes(),
            &mut datagram,
        )
        .unwrap();
        datagram.len()
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn read_test_varint(bytes: &[u8], pos: &mut usize) -> u64 {
        let mut shift = 0;
        let mut value = 0u64;
        loop {
            let b = bytes[*pos];
            *pos += 1;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn read_test_bytes(bytes: &[u8], pos: &mut usize) -> Vec<u8> {
        let len = read_test_varint(bytes, pos) as usize;
        let out = bytes[*pos..*pos + len].to_vec();
        *pos += len;
        out
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn ws_delta_entries(message: &[u8]) -> (u64, Vec<Vec<u8>>, usize) {
        assert_eq!(&message[0..4], b"QWP1");
        assert_eq!(message[4], QWP_VERSION_1);
        assert_eq!(
            message[5] & QWP_FLAG_DELTA_SYMBOL_DICT,
            QWP_FLAG_DELTA_SYMBOL_DICT
        );
        assert_eq!(
            u32::from_le_bytes([message[8], message[9], message[10], message[11]]) as usize,
            message.len() - QWP_MESSAGE_HEADER_SIZE
        );

        let mut pos = QWP_MESSAGE_HEADER_SIZE;
        let delta_start = read_test_varint(message, &mut pos);
        let delta_count = read_test_varint(message, &mut pos);
        let mut entries = Vec::new();
        for _ in 0..delta_count {
            entries.push(read_test_bytes(message, &mut pos));
        }
        (delta_start, entries, pos)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn first_ws_schema_mode(message: &[u8]) -> u8 {
        let (_, _, mut pos) = ws_delta_entries(message);
        let _table_name = read_test_bytes(message, &mut pos);
        let _row_count = read_test_varint(message, &mut pos);
        let _column_count = read_test_varint(message, &mut pos);
        message[pos]
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_local_symbol_lookup_handles_hash_collisions() {
        let mut lookup = QwpWsLocalSymbolLookup::default();
        let mut dict = Vec::new();
        let mut data = Vec::new();
        let forced_hash = 7;

        let alpha_offset = data.len() as u32;
        data.extend_from_slice(b"alpha");
        dict.push(QwpWsSymbolEntry {
            offset: alpha_offset,
            len: 5,
        });
        lookup.insert(forced_hash, 0);

        let beta_offset = data.len() as u32;
        data.extend_from_slice(b"beta");
        dict.push(QwpWsSymbolEntry {
            offset: beta_offset,
            len: 4,
        });
        lookup.insert(forced_hash, 1);

        assert_eq!(lookup.get(forced_hash, b"alpha", &dict, &data), Some(0));
        assert_eq!(lookup.get(forced_hash, b"beta", &dict, &data), Some(1));
        assert_eq!(lookup.get(forced_hash, b"gamma", &dict, &data), None);

        lookup.retain_local_ids_below(1);

        assert_eq!(lookup.get(forced_hash, b"alpha", &dict, &data), Some(0));
        assert_eq!(lookup.get(forced_hash, b"beta", &dict, &data), None);
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn decode_single_i64_column_ws_replay(message: &[u8]) -> Vec<(String, String, Vec<i64>)> {
        let (_, _, mut pos) = ws_delta_entries(message);
        let table_count = u16::from_le_bytes([message[6], message[7]]) as usize;
        let mut tables = Vec::with_capacity(table_count);
        for _ in 0..table_count {
            let table_name = String::from_utf8(read_test_bytes(message, &mut pos)).unwrap();
            let row_count = read_test_varint(message, &mut pos) as usize;
            let column_count = read_test_varint(message, &mut pos);
            assert_eq!(column_count, 1);
            assert_eq!(message[pos], QWP_SCHEMA_MODE_FULL);
            pos += 1;
            let _schema_id = read_test_varint(message, &mut pos);
            let column_name = String::from_utf8(read_test_bytes(message, &mut pos)).unwrap();
            assert_eq!(message[pos], QWP_TYPE_LONG);
            pos += 1;
            assert_eq!(message[pos], 0, "test helper expects dense long column");
            pos += 1;

            let mut values = Vec::with_capacity(row_count);
            for _ in 0..row_count {
                let raw: [u8; 8] = message[pos..pos + 8].try_into().unwrap();
                pos += 8;
                values.push(i64::from_le_bytes(raw));
            }
            tables.push((table_name, column_name, values));
        }
        assert_eq!(pos, message.len());
        tables
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[derive(Clone, Copy)]
    struct PanicTableName(&'static str);

    #[cfg(feature = "_sender-qwp-ws")]
    impl AsRef<str> for PanicTableName {
        fn as_ref(&self) -> &str {
            self.0
        }
    }

    #[cfg(feature = "_sender-qwp-ws")]
    impl<'a> TryFrom<PanicTableName> for TableName<'a> {
        type Error = crate::Error;

        fn try_from(_: PanicTableName) -> crate::Result<Self> {
            panic!("existing QWP/WS table names must not be revalidated")
        }
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[derive(Clone, Copy)]
    struct PanicColumnName(&'static str);

    #[cfg(feature = "_sender-qwp-ws")]
    impl AsRef<str> for PanicColumnName {
        fn as_ref(&self) -> &str {
            self.0
        }
    }

    #[cfg(feature = "_sender-qwp-ws")]
    impl<'a> TryFrom<PanicColumnName> for ColumnName<'a> {
        type Error = crate::Error;

        fn try_from(_: PanicColumnName) -> crate::Result<Self> {
            panic!("existing QWP/WS column names must not be revalidated")
        }
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn add_trade_row(buf: &mut QwpBuffer, sym: &str, qty: i64) {
        buf.table("trades")
            .unwrap()
            .symbol("sym", sym)
            .unwrap()
            .column_i64("qty", qty)
            .unwrap()
            .at_now()
            .unwrap();
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PropTable {
        Trades,
        Quotes,
        Metrics,
        Audit,
    }

    impl PropTable {
        fn as_str(self) -> &'static str {
            match self {
                Self::Trades => "trades",
                Self::Quotes => "quotes",
                Self::Metrics => "metrics",
                Self::Audit => "audit",
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum PropTsKind {
        Micros,
        Nanos,
    }

    #[derive(Clone, Debug)]
    struct PropSegmentConfig {
        table: PropTable,
        has_symbol: bool,
        has_bool: bool,
        has_i64: bool,
        has_f64: bool,
        has_string: bool,
        has_decimal: bool,
        decimal_scale: Option<u8>,
        has_array: bool,
        ts_kind: Option<PropTsKind>,
        designated_ts_kind: Option<PropTsKind>,
    }

    #[derive(Clone, Debug)]
    struct PropRow {
        symbol: Option<String>,
        bool_value: Option<bool>,
        i64_value: Option<i64>,
        f64_value: Option<f64>,
        string_value: Option<String>,
        decimal_value: Option<String>,
        array_values: Option<Vec<f64>>,
        ts_value: Option<i64>,
        designated_ts: Option<i64>,
    }

    #[derive(Clone, Debug)]
    struct PropSegment {
        config: PropSegmentConfig,
        rows: Vec<PropRow>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SemanticRow {
        table: String,
        fields: BTreeMap<String, SemanticValue>,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum SemanticValue {
        Bool(bool),
        I64(i64),
        F64(u64),
        String(String),
        Decimal { scale: u8, unscaled_be: Vec<u8> },
        F64Array { shape: Vec<usize>, values: Vec<u64> },
        TimestampMicros(i64),
        TimestampNanos(i64),
        Null,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum SemanticKind {
        Bool,
        I64,
        F64,
        String,
        Decimal,
        F64Array,
        TimestampMicros,
        TimestampNanos,
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct ActiveSegmentSchema {
        symbol: bool,
        bool_col: bool,
        i64_col: bool,
        f64_col: bool,
        string_col: bool,
        decimal_col: bool,
        decimal_scale: u8,
        array_col: bool,
        ts_col: Option<PropTsKind>,
        designated_ts: Option<PropTsKind>,
    }

    fn prop_table_strategy() -> BoxedStrategy<PropTable> {
        prop_oneof![
            Just(PropTable::Trades),
            Just(PropTable::Quotes),
            Just(PropTable::Metrics),
            Just(PropTable::Audit),
        ]
        .boxed()
    }

    fn prop_ts_kind_strategy() -> BoxedStrategy<PropTsKind> {
        prop_oneof![Just(PropTsKind::Micros), Just(PropTsKind::Nanos)].boxed()
    }

    fn prop_small_text(max_len: usize) -> BoxedStrategy<String> {
        proptest::string::string_regex(&format!("[a-z0-9_-]{{0,{max_len}}}"))
            .unwrap()
            .boxed()
    }

    fn prop_f64_strategy() -> BoxedStrategy<f64> {
        ((-500i32..=500), (0u8..=3))
            .prop_map(|(whole, frac)| f64::from(whole) + f64::from(frac) / 4.0)
            .boxed()
    }

    fn prop_decimal_scale_strategy() -> BoxedStrategy<u8> {
        (0u8..=3u8).boxed()
    }

    fn format_decimal_string(unscaled: i64, scale: u8) -> String {
        if scale == 0 {
            return unscaled.to_string();
        }

        let negative = unscaled < 0;
        let digits = unscaled.abs().to_string();
        let scale_usize = scale as usize;
        let mut out = String::new();
        if negative {
            out.push('-');
        }
        if digits.len() <= scale_usize {
            out.push_str("0.");
            for _ in 0..(scale_usize - digits.len()) {
                out.push('0');
            }
            out.push_str(&digits);
        } else {
            let split = digits.len() - scale_usize;
            out.push_str(&digits[..split]);
            out.push('.');
            out.push_str(&digits[split..]);
        }
        out
    }

    fn prop_decimal_string_with_scale(scale: u8) -> BoxedStrategy<String> {
        (-50_000i64..=50_000i64)
            .prop_map(move |unscaled| format_decimal_string(unscaled, scale))
            .boxed()
    }

    fn prop_row_count_strategy() -> BoxedStrategy<usize> {
        prop_oneof![
            8 => 1usize..=4usize,
            2 => 5usize..=8usize,
            1 => Just(15usize),
            1 => Just(16usize),
            1 => Just(17usize),
        ]
        .boxed()
    }

    fn prop_segment_config_strategy() -> BoxedStrategy<PropSegmentConfig> {
        (
            prop_table_strategy(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            prop_oneof![2 => Just(None), 1 => prop_ts_kind_strategy().prop_map(Some)],
            prop_oneof![2 => Just(None), 1 => prop_ts_kind_strategy().prop_map(Some)],
            prop_decimal_scale_strategy(),
        )
            .prop_map(
                |(
                    table,
                    has_symbol,
                    has_bool,
                    has_i64,
                    has_f64,
                    has_string,
                    has_decimal,
                    has_array,
                    ts_kind,
                    designated_ts_kind,
                    decimal_scale,
                )| PropSegmentConfig {
                    table,
                    has_symbol,
                    has_bool,
                    has_i64,
                    has_f64,
                    has_string,
                    has_decimal,
                    decimal_scale: has_decimal.then_some(decimal_scale),
                    has_array,
                    ts_kind,
                    designated_ts_kind,
                },
            )
            .prop_filter("segment must expose at least one actual field", |cfg| {
                cfg.has_symbol
                    || cfg.has_bool
                    || cfg.has_i64
                    || cfg.has_f64
                    || cfg.has_string
                    || cfg.has_decimal
                    || cfg.has_array
                    || cfg.ts_kind.is_some()
            })
            .boxed()
    }

    fn prop_row_strategy(cfg: PropSegmentConfig) -> BoxedStrategy<PropRow> {
        let symbol = if cfg.has_symbol {
            prop_oneof![
                1 => Just(None::<String>),
                3 => prop_small_text(8).prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<String>).boxed()
        };
        let bool_value = if cfg.has_bool {
            prop_oneof![
                1 => Just(None::<bool>),
                3 => any::<bool>().prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<bool>).boxed()
        };
        let i64_value = if cfg.has_i64 {
            prop_oneof![
                1 => Just(None::<i64>),
                3 => (-2_000i64..=2_000).prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<i64>).boxed()
        };
        let f64_value = if cfg.has_f64 {
            prop_oneof![
                1 => Just(None::<f64>),
                3 => prop_f64_strategy().prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<f64>).boxed()
        };
        let string_value = if cfg.has_string {
            prop_oneof![
                1 => Just(None::<String>),
                3 => prop_small_text(12).prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<String>).boxed()
        };
        let decimal_value = if let Some(scale) = cfg.decimal_scale {
            prop_oneof![
                1 => Just(None::<String>),
                3 => prop_decimal_string_with_scale(scale).prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<String>).boxed()
        };
        let array_values = if cfg.has_array {
            prop_oneof![
                1 => Just(None::<Vec<f64>>),
                3 => prop::collection::vec(prop_f64_strategy(), 0..=4).prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<Vec<f64>>).boxed()
        };
        let ts_value = if cfg.ts_kind.is_some() {
            prop_oneof![
                1 => Just(None::<i64>),
                3 => (-2_000i64..=2_000).prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<i64>).boxed()
        };
        let designated_ts = if cfg.designated_ts_kind.is_some() {
            prop_oneof![
                1 => Just(None::<i64>),
                3 => (0i64..=2_000).prop_map(Some),
            ]
            .boxed()
        } else {
            Just(None::<i64>).boxed()
        };

        (
            symbol,
            bool_value,
            i64_value,
            f64_value,
            string_value,
            decimal_value,
            array_values,
            ts_value,
            designated_ts,
        )
            .prop_map(
                |(
                    symbol,
                    bool_value,
                    i64_value,
                    f64_value,
                    string_value,
                    decimal_value,
                    array_values,
                    ts_value,
                    designated_ts,
                )| PropRow {
                    symbol,
                    bool_value,
                    i64_value,
                    f64_value,
                    string_value,
                    decimal_value,
                    array_values,
                    ts_value,
                    designated_ts,
                },
            )
            .prop_filter("row must commit at least one field", |row| {
                row.symbol.is_some()
                    || row.bool_value.is_some()
                    || row.i64_value.is_some()
                    || row.f64_value.is_some()
                    || row.string_value.is_some()
                    || row.decimal_value.is_some()
                    || row.array_values.is_some()
                    || row.ts_value.is_some()
            })
            .boxed()
    }

    fn prop_segment_strategy() -> BoxedStrategy<PropSegment> {
        prop_segment_config_strategy()
            .prop_flat_map(|cfg| {
                let row_strategy = prop_row_strategy(cfg.clone());
                let cfg_for_rows = cfg.clone();
                prop_row_count_strategy().prop_flat_map(move |row_count| {
                    let cfg_for_segment = cfg_for_rows.clone();
                    prop::collection::vec(row_strategy.clone(), row_count..=row_count).prop_map(
                        move |rows| PropSegment {
                            config: cfg_for_segment.clone(),
                            rows,
                        },
                    )
                })
            })
            .boxed()
    }

    fn prop_scenario_strategy(
        min_segments: usize,
        max_segments: usize,
    ) -> BoxedStrategy<Vec<PropSegment>> {
        prop::collection::vec(prop_segment_strategy(), min_segments..=max_segments)
            .prop_filter(
                "adjacent segments must not target the same table",
                |segments| {
                    !segments
                        .windows(2)
                        .any(|pair| pair[0].config.table == pair[1].config.table)
                },
            )
            .boxed()
    }

    fn prop_dense_nullable_row_strategy(cfg: PropSegmentConfig) -> BoxedStrategy<PropRow> {
        let symbol = if cfg.has_symbol {
            prop_small_text(8).prop_map(Some).boxed()
        } else {
            Just(None::<String>).boxed()
        };
        let string_value = if cfg.has_string {
            prop_small_text(12).prop_map(Some).boxed()
        } else {
            Just(None::<String>).boxed()
        };
        let decimal_value = if let Some(scale) = cfg.decimal_scale {
            prop_decimal_string_with_scale(scale).prop_map(Some).boxed()
        } else {
            Just(None::<String>).boxed()
        };
        let array_values = if cfg.has_array {
            prop::collection::vec(prop_f64_strategy(), 0..=4)
                .prop_map(Some)
                .boxed()
        } else {
            Just(None::<Vec<f64>>).boxed()
        };
        let ts_value = if cfg.ts_kind.is_some() {
            (0i64..=2_000).prop_map(Some).boxed()
        } else {
            Just(None::<i64>).boxed()
        };
        let designated_ts = if cfg.designated_ts_kind.is_some() {
            (0i64..=2_000).prop_map(Some).boxed()
        } else {
            Just(None::<i64>).boxed()
        };

        (
            symbol,
            string_value,
            decimal_value,
            array_values,
            ts_value,
            designated_ts,
        )
            .prop_map(
                |(symbol, string_value, decimal_value, array_values, ts_value, designated_ts)| {
                    PropRow {
                        symbol,
                        bool_value: None,
                        i64_value: None,
                        f64_value: None,
                        string_value,
                        decimal_value,
                        array_values,
                        ts_value,
                        designated_ts,
                    }
                },
            )
            .boxed()
    }

    fn prop_dense_nullable_segment_strategy() -> BoxedStrategy<PropSegment> {
        (
            prop_table_strategy(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            prop_oneof![Just(None), prop_ts_kind_strategy().prop_map(Some)],
            prop_oneof![Just(None), prop_ts_kind_strategy().prop_map(Some)],
            prop_decimal_scale_strategy(),
        )
            .prop_map(
                |(
                    table,
                    has_symbol,
                    has_string,
                    has_decimal,
                    has_array,
                    ts_kind,
                    designated_ts_kind,
                    decimal_scale,
                )| PropSegmentConfig {
                    table,
                    has_symbol,
                    has_bool: false,
                    has_i64: false,
                    has_f64: false,
                    has_string,
                    has_decimal,
                    decimal_scale: has_decimal.then_some(decimal_scale),
                    has_array,
                    ts_kind,
                    designated_ts_kind,
                },
            )
            .prop_filter(
                "segment must include at least one Java-nullable column value",
                |cfg| {
                    cfg.has_symbol
                        || cfg.has_string
                        || cfg.has_decimal
                        || cfg.has_array
                        || cfg.ts_kind.is_some()
                },
            )
            .prop_flat_map(|cfg| {
                let row_strategy = prop_dense_nullable_row_strategy(cfg.clone());
                let cfg_for_rows = cfg.clone();
                prop_row_count_strategy().prop_flat_map(move |row_count| {
                    let cfg_for_segment = cfg_for_rows.clone();
                    prop::collection::vec(row_strategy.clone(), row_count..=row_count).prop_map(
                        move |rows| PropSegment {
                            config: cfg_for_segment.clone(),
                            rows,
                        },
                    )
                })
            })
            .boxed()
    }

    fn prop_decimal_scale_widening_pair_strategy() -> BoxedStrategy<(String, String)> {
        (
            0u8..=2u8,
            -5_000i64..=5_000i64,
            any::<bool>(),
            0i64..=5_000i64,
            1u8..=2u8,
            1u8..=9u8,
        )
            .prop_map(
                |(first_scale, first_unscaled, negative, base, extra_scale, tail_digit)| {
                    let first = format_decimal_string(first_unscaled, first_scale);
                    let later_scale = first_scale + extra_scale;
                    let mut later_unscaled =
                        base * 10i64.pow(u32::from(extra_scale)) + i64::from(tail_digit);
                    if negative {
                        later_unscaled = -later_unscaled;
                    }
                    let later = format_decimal_string(later_unscaled, later_scale);
                    (first, later)
                },
            )
            .boxed()
    }

    fn active_schema(segment: &PropSegment) -> ActiveSegmentSchema {
        let mut schema = ActiveSegmentSchema::default();
        for row in &segment.rows {
            schema.symbol |= row.symbol.is_some();
            schema.bool_col |= row.bool_value.is_some();
            schema.i64_col |= row.i64_value.is_some();
            schema.f64_col |= row.f64_value.is_some();
            schema.string_col |= row.string_value.is_some();
            if row.decimal_value.is_some() {
                schema.decimal_col = true;
                schema.decimal_scale = segment.config.decimal_scale.unwrap_or(0);
            }
            schema.array_col |= row.array_values.is_some();
            if row.ts_value.is_some() {
                schema.ts_col = segment.config.ts_kind;
            }
            if row.designated_ts.is_some() {
                schema.designated_ts = segment.config.designated_ts_kind;
            }
        }
        schema
    }

    fn apply_segments(buf: &mut QwpBuffer, segments: &[PropSegment]) {
        for segment in segments {
            for row in &segment.rows {
                apply_row(buf, segment, row);
            }
        }
    }

    fn apply_row(buf: &mut QwpBuffer, segment: &PropSegment, row: &PropRow) {
        buf.table(segment.config.table.as_str()).unwrap();

        if let Some(value) = row.symbol.as_deref() {
            buf.symbol("sym", value).unwrap();
        }
        if let Some(value) = row.bool_value {
            buf.column_bool("flag", value).unwrap();
        }
        if let Some(value) = row.i64_value {
            buf.column_i64("qty", value).unwrap();
        }
        if let Some(value) = row.f64_value {
            buf.column_f64("px", value).unwrap();
        }
        if let Some(value) = row.string_value.as_deref() {
            buf.column_str("note", value).unwrap();
        }
        if let Some(value) = row.decimal_value.as_deref() {
            buf.column_dec("price", value).unwrap();
        }
        if let Some(values) = row.array_values.as_ref() {
            buf.column_arr("samples", values).unwrap();
        }
        if let Some(value) = row.ts_value {
            match segment.config.ts_kind.expect("ts value requires ts kind") {
                PropTsKind::Micros => {
                    buf.column_ts("event_ts", TimestampMicros::new(value))
                        .unwrap();
                }
                PropTsKind::Nanos => {
                    buf.column_ts("event_ts", TimestampNanos::new(value))
                        .unwrap();
                }
            }
        }

        if let Some(value) = row.designated_ts {
            match segment
                .config
                .designated_ts_kind
                .expect("designated ts value requires ts kind")
            {
                PropTsKind::Micros => buf.at(TimestampMicros::new(value)).unwrap(),
                PropTsKind::Nanos => buf.at(TimestampNanos::new(value)).unwrap(),
            }
        } else {
            buf.at_now().unwrap();
        }
    }

    fn semantic_rows_from_segments(segments: &[PropSegment]) -> Vec<SemanticRow> {
        let mut rows = Vec::new();
        for segment in segments {
            let schema = active_schema(segment);
            for row in &segment.rows {
                let mut fields = BTreeMap::new();
                if schema.symbol {
                    fields.insert(
                        "sym".to_owned(),
                        match &row.symbol {
                            Some(value) => SemanticValue::String(value.clone()),
                            None => SemanticValue::Null,
                        },
                    );
                }
                if schema.bool_col {
                    fields.insert(
                        "flag".to_owned(),
                        SemanticValue::Bool(row.bool_value.unwrap_or(false)),
                    );
                }
                if schema.i64_col {
                    fields.insert(
                        "qty".to_owned(),
                        SemanticValue::I64(row.i64_value.unwrap_or(i64::MIN)),
                    );
                }
                if schema.f64_col {
                    fields.insert(
                        "px".to_owned(),
                        SemanticValue::F64(row.f64_value.unwrap_or(f64::NAN).to_bits()),
                    );
                }
                if schema.string_col {
                    fields.insert(
                        "note".to_owned(),
                        match &row.string_value {
                            Some(value) => SemanticValue::String(value.clone()),
                            None => SemanticValue::Null,
                        },
                    );
                }
                if schema.decimal_col {
                    fields.insert(
                        "price".to_owned(),
                        match row.decimal_value.as_deref() {
                            Some(value) => semantic_decimal_from_text(value),
                            None => SemanticValue::Null,
                        },
                    );
                }
                if schema.array_col {
                    fields.insert(
                        "samples".to_owned(),
                        match row.array_values.as_ref() {
                            Some(values) => semantic_f64_array(values),
                            None => SemanticValue::Null,
                        },
                    );
                }
                if let Some(kind) = schema.ts_col {
                    fields.insert(
                        "event_ts".to_owned(),
                        match row.ts_value {
                            Some(value) => semantic_ts(kind, value),
                            None => SemanticValue::Null,
                        },
                    );
                }
                if let Some(kind) = schema.designated_ts {
                    fields.insert(
                        String::new(),
                        match row.designated_ts {
                            Some(value) => semantic_ts(kind, value),
                            None => SemanticValue::Null,
                        },
                    );
                }
                rows.push(SemanticRow {
                    table: segment.config.table.as_str().to_owned(),
                    fields,
                });
            }
        }
        rows
    }

    fn semantic_ts(kind: PropTsKind, value: i64) -> SemanticValue {
        match kind {
            PropTsKind::Micros => SemanticValue::TimestampMicros(value),
            PropTsKind::Nanos => SemanticValue::TimestampNanos(value),
        }
    }

    fn trim_signed_be(bytes: &[u8]) -> Vec<u8> {
        if bytes.is_empty() {
            return vec![0];
        }
        let negative = bytes[0] & 0x80 != 0;
        let mut keep_from = 0usize;
        while keep_from < bytes.len() - 1 {
            let current = bytes[keep_from];
            let next = bytes[keep_from + 1];
            let should_trim = if negative {
                current == 0xFF && (next & 0x80) == 0x80
            } else {
                current == 0x00 && (next & 0x80) == 0x00
            };
            if should_trim {
                keep_from += 1;
            } else {
                break;
            }
        }
        bytes[keep_from..].to_vec()
    }

    fn semantic_decimal_from_text(value: &str) -> SemanticValue {
        let decimal = parse_decimal_text(value)
            .unwrap()
            .expect("finite generated decimal must parse");
        let mut be = decimal
            .wire_bytes_with_scale(decimal.scale)
            .unwrap()
            .to_vec();
        be.reverse();
        SemanticValue::Decimal {
            scale: decimal.scale,
            unscaled_be: trim_signed_be(&be),
        }
    }

    fn decoded_decimal_from_text_with_scale(value: &str, target_scale: u8) -> DecodedValue {
        let decimal = parse_decimal_text(value)
            .unwrap()
            .expect("finite generated decimal must parse");
        let mut be = decimal
            .wire_bytes_with_scale(target_scale)
            .unwrap()
            .to_vec();
        be.reverse();
        DecodedValue::Decimal {
            scale: target_scale,
            unscaled_be: trim_signed_be(&be),
        }
    }

    fn semantic_f64_array(values: &[f64]) -> SemanticValue {
        SemanticValue::F64Array {
            shape: vec![values.len()],
            values: values.iter().map(|value| value.to_bits()).collect(),
        }
    }

    fn semantic_rows_from_datagrams(datagrams: &[Vec<u8>]) -> Vec<SemanticRow> {
        let decoded = datagrams
            .iter()
            .map(|datagram| decode_datagram(datagram).unwrap())
            .collect::<Vec<_>>();
        let mut rows = Vec::new();
        let mut group_start = 0usize;
        while group_start < decoded.len() {
            let table_name = decoded[group_start].table.name.clone();
            let mut group_end = group_start + 1;
            while group_end < decoded.len() && decoded[group_end].table.name == table_name {
                group_end += 1;
            }
            let schema = semantic_group_schema(&decoded[group_start..group_end]);
            for datagram in &decoded[group_start..group_end] {
                let columns = &datagram.table.columns;
                for decoded_row in &datagram.table.rows {
                    let mut fields = BTreeMap::new();
                    for (column, value) in columns.iter().zip(decoded_row.iter().cloned()) {
                        fields.insert(column.name.clone(), semantic_value_from_decoded(value));
                    }
                    for (name, kind) in &schema {
                        fields
                            .entry(name.clone())
                            .or_insert_with(|| default_semantic_value(*kind));
                    }
                    rows.push(SemanticRow {
                        table: table_name.clone(),
                        fields,
                    });
                }
            }
            group_start = group_end;
        }
        rows
    }

    fn semantic_group_schema(
        decoded: &[crate::tests::qwp_decode::DecodedDatagram],
    ) -> BTreeMap<String, SemanticKind> {
        let mut schema = BTreeMap::new();
        for datagram in decoded {
            for (col_idx, column) in datagram.table.columns.iter().enumerate() {
                schema
                    .entry(column.name.clone())
                    .or_insert_with(|| infer_semantic_kind(datagram, col_idx));
            }
        }
        schema
    }

    fn infer_semantic_kind(
        datagram: &crate::tests::qwp_decode::DecodedDatagram,
        col_idx: usize,
    ) -> SemanticKind {
        for row in &datagram.table.rows {
            match &row[col_idx] {
                DecodedValue::Bool(_) => return SemanticKind::Bool,
                DecodedValue::I64(_) => return SemanticKind::I64,
                DecodedValue::F64(_) => return SemanticKind::F64,
                DecodedValue::Symbol(_) | DecodedValue::String(_) => return SemanticKind::String,
                DecodedValue::Decimal { .. } => return SemanticKind::Decimal,
                DecodedValue::F64Array { .. } => return SemanticKind::F64Array,
                DecodedValue::TimestampMicros(_) => return SemanticKind::TimestampMicros,
                DecodedValue::TimestampNanos(_) => return SemanticKind::TimestampNanos,
                DecodedValue::I8(_) | DecodedValue::I16(_) | DecodedValue::I32(_) => panic!(
                    "narrow integer columns are not exercised by qwp_prop tests; \
                     extend PropSegmentConfig if a narrow int column should be inferred"
                ),
                DecodedValue::Uuid { .. } | DecodedValue::Long256(_) | DecodedValue::Ipv4(_) => {
                    panic!("UUID/LONG256/IPv4 columns are not exercised by qwp_prop tests")
                }
                DecodedValue::DateMillis(_) | DecodedValue::Char(_) | DecodedValue::Binary(_) => {
                    panic!("DATE/CHAR/BINARY columns are not exercised by qwp_prop tests")
                }
                DecodedValue::Geohash { .. } => {
                    panic!("GEOHASH columns are not exercised by qwp_prop tests")
                }
                DecodedValue::I64Array { .. } => {
                    panic!("LONG_ARRAY columns are not exercised by qwp_prop tests")
                }
                DecodedValue::F32(_) => {
                    panic!("FLOAT columns are not exercised by qwp_prop tests")
                }
                DecodedValue::Null => {}
            }
        }
        panic!(
            "property schema inference saw all-null column {:?} in decoded datagram",
            datagram.table.columns[col_idx].name
        );
    }

    fn default_semantic_value(kind: SemanticKind) -> SemanticValue {
        match kind {
            SemanticKind::Bool => SemanticValue::Bool(false),
            SemanticKind::I64 => SemanticValue::I64(i64::MIN),
            SemanticKind::F64 => SemanticValue::F64(f64::NAN.to_bits()),
            SemanticKind::String => SemanticValue::Null,
            SemanticKind::Decimal => SemanticValue::Null,
            SemanticKind::F64Array => SemanticValue::Null,
            SemanticKind::TimestampMicros => SemanticValue::Null,
            SemanticKind::TimestampNanos => SemanticValue::Null,
        }
    }

    fn semantic_value_from_decoded(value: DecodedValue) -> SemanticValue {
        match value {
            DecodedValue::Bool(value) => SemanticValue::Bool(value),
            DecodedValue::Symbol(value) | DecodedValue::String(value) => {
                SemanticValue::String(value)
            }
            DecodedValue::I64(value) => SemanticValue::I64(value),
            DecodedValue::F64(value) => SemanticValue::F64(value.to_bits()),
            DecodedValue::Decimal { scale, unscaled_be } => {
                SemanticValue::Decimal { scale, unscaled_be }
            }
            DecodedValue::F64Array { shape, values } => SemanticValue::F64Array {
                shape,
                values: values.into_iter().map(f64::to_bits).collect(),
            },
            DecodedValue::TimestampMicros(value) => SemanticValue::TimestampMicros(value),
            DecodedValue::TimestampNanos(value) => SemanticValue::TimestampNanos(value),
            DecodedValue::I8(_) | DecodedValue::I16(_) | DecodedValue::I32(_) => {
                panic!("narrow integer columns are not exercised by qwp_prop tests")
            }
            DecodedValue::Uuid { .. } | DecodedValue::Long256(_) | DecodedValue::Ipv4(_) => {
                panic!("UUID/LONG256/IPv4 columns are not exercised by qwp_prop tests")
            }
            DecodedValue::DateMillis(_) | DecodedValue::Char(_) | DecodedValue::Binary(_) => {
                panic!("DATE/CHAR/BINARY columns are not exercised by qwp_prop tests")
            }
            DecodedValue::Geohash { .. } => {
                panic!("GEOHASH columns are not exercised by qwp_prop tests")
            }
            DecodedValue::I64Array { .. } => {
                panic!("LONG_ARRAY columns are not exercised by qwp_prop tests")
            }
            DecodedValue::F32(_) => {
                panic!("FLOAT columns are not exercised by qwp_prop tests")
            }
            DecodedValue::Null => SemanticValue::Null,
        }
    }

    fn java_dense_nullable_column_names(cfg: &PropSegmentConfig) -> Vec<&'static str> {
        let mut names = Vec::new();
        if cfg.has_symbol {
            names.push("sym");
        }
        if cfg.has_string {
            names.push("note");
        }
        if cfg.has_decimal {
            names.push("price");
        }
        if cfg.has_array {
            names.push("samples");
        }
        if cfg.ts_kind.is_some() {
            names.push("event_ts");
        }
        if cfg.designated_ts_kind.is_some() {
            names.push("");
        }
        names
    }

    fn encode_unsplit_single_segment(segment: &PropSegment) -> DecodedDatagram {
        let mut buf = QwpBuffer::new(512);
        apply_segments(&mut buf, std::slice::from_ref(segment));
        let datagrams = buf.encode_datagrams(usize::MAX).unwrap();
        assert_eq!(datagrams.len(), 1, "single segment should stay unsplit");
        decode_datagram(&datagrams[0]).unwrap()
    }

    fn total_rows(segments: &[PropSegment]) -> usize {
        segments.iter().map(|segment| segment.rows.len()).sum()
    }

    fn max_single_row_datagram_len(segments: &[PropSegment]) -> usize {
        let mut max_len = 0;
        for segment in segments {
            for row in &segment.rows {
                let one_row = PropSegment {
                    config: segment.config.clone(),
                    rows: vec![row.clone()],
                };
                let mut buf = QwpBuffer::new(127);
                apply_segments(&mut buf, &[one_row]);
                let datagram = buf.encode_datagrams(usize::MAX).unwrap();
                max_len = max_len.max(datagram[0].len());
            }
        }
        max_len
    }

    #[test]
    fn qwp_struct_sizes() {
        use std::mem::size_of;
        assert_eq!(size_of::<ValueRef>(), 16);
        assert_eq!(size_of::<CellRef>(), 32);
        assert_eq!(size_of::<EntryMeta>(), 24);
        assert_eq!(size_of::<RowMeta>(), 32);
        assert_eq!(size_of::<SymbolEntry>(), 32);
        assert_eq!(size_of::<ColumnStats>(), 72);
        assert_eq!(size_of::<ColumnUndo>(), 48);
        assert_eq!(size_of::<SymbolLookupUndo>(), 16);
        assert_eq!(size_of::<Option<DesignatedTs>>(), size_of::<DesignatedTs>());
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            .. ProptestConfig::default()
        })]

        #[test]
        fn qwp_prop_encode_decode_roundtrip(
            segments in prop_scenario_strategy(1, 4),
        ) {
            let expected = semantic_rows_from_segments(&segments);
            let mut buf = QwpBuffer::new(127);
            apply_segments(&mut buf, &segments);

            prop_assert_eq!(buf.row_count(), total_rows(&segments));

            let datagrams = buf.encode_datagrams(usize::MAX).unwrap();
            let actual = semantic_rows_from_datagrams(&datagrams);
            prop_assert_eq!(actual, expected);

            let encoded_len: usize = datagrams.iter().map(Vec::len).sum();
            prop_assert_eq!(buf.len(), encoded_len);
        }

        #[test]
        fn qwp_prop_split_preserves_semantics(
            segments in prop_scenario_strategy(1, 4),
            extra in 0usize..64usize,
        ) {
            let mut buf = QwpBuffer::new(127);
            apply_segments(&mut buf, &segments);

            let unsplit = buf.encode_datagrams(usize::MAX).unwrap();
            let max_datagram_size = max_single_row_datagram_len(&segments) + extra;
            let split = buf.encode_datagrams(max_datagram_size).unwrap();

            prop_assert_eq!(
                semantic_rows_from_datagrams(&split),
                semantic_rows_from_datagrams(&unsplit),
            );

            let unsplit_len: usize = unsplit.iter().map(Vec::len).sum();
            prop_assert_eq!(buf.len(), unsplit_len);
        }

        #[test]
        fn qwp_prop_marker_rewind_restores_exact_datagrams(
            prefix in prop_scenario_strategy(0, 3),
            suffix in prop_scenario_strategy(1, 3),
        ) {
            prop_assume!(
                prefix.is_empty()
                    || suffix.is_empty()
                    || prefix.last().unwrap().config.table != suffix.first().unwrap().config.table
            );

            let prefix_expected = semantic_rows_from_segments(&prefix);
            let mut buf = QwpBuffer::new(127);
            apply_segments(&mut buf, &prefix);
            let before = buf.encode_datagrams(usize::MAX).unwrap();

            buf.set_marker().unwrap();
            apply_segments(&mut buf, &suffix);
            buf.rewind_to_marker().unwrap();

            let after = buf.encode_datagrams(usize::MAX).unwrap();
            prop_assert_eq!(&after, &before);
            prop_assert_eq!(semantic_rows_from_datagrams(&after), prefix_expected);

            let rewound_len: usize = after.iter().map(Vec::len).sum();
            prop_assert_eq!(buf.len(), rewound_len);
        }

        #[test]
        fn qwp_prop_java_dense_nullable_columns_skip_null_bitmaps(
            segment in prop_dense_nullable_segment_strategy(),
        ) {
            let decoded = encode_unsplit_single_segment(&segment);
            for name in java_dense_nullable_column_names(&segment.config) {
                let column = decoded
                    .table
                    .columns
                    .iter()
                    .find(|column| column.name == name)
                    .unwrap_or_else(|| panic!("missing expected column {name:?} in decoded datagram"));
                prop_assert!(
                    !column.nullable,
                    "Java QWP writer uses null_flag=0 when nullCount==0, but Rust emitted a bitmap for column {:?}",
                    name
                );
            }
        }

        #[test]
        fn qwp_prop_decimal_upscale_preserves_values(
            (small_scale, large_scale) in prop_decimal_scale_widening_pair_strategy(),
        ) {
            // The strategy yields (smaller-scale, larger-scale). Java parity
            // pins the column to the FIRST value's scale and rescales
            // subsequent values UP losslessly. So feed the LARGER-scale
            // value first (pins the column to that scale), then the smaller-
            // scale value which upscales without precision loss.
            let pinned_decimal = parse_decimal_text(large_scale.as_str())
                .unwrap()
                .expect("finite generated decimal must parse");

            let mut buf = QwpBuffer::new(512);
            buf.table("trades")
                .unwrap()
                .column_dec("price", large_scale.as_str())
                .unwrap()
                .at_now()
                .unwrap();

            buf.table("trades")
                .unwrap()
                .column_dec("price", small_scale.as_str())
                .unwrap()
                .at_now()
                .unwrap();

            let datagrams = buf.encode_datagrams(usize::MAX).unwrap();
            prop_assert_eq!(datagrams.len(), 1);

            let decoded = decode_datagram(&datagrams[0]).expect("datagram should decode");
            prop_assert_eq!(
                decoded.table.rows,
                vec![
                    vec![decoded_decimal_from_text_with_scale(large_scale.as_str(), pinned_decimal.scale)],
                    vec![decoded_decimal_from_text_with_scale(small_scale.as_str(), pinned_decimal.scale)],
                ],
            );
        }
    }

    #[test]
    fn qwp_checked_arena_offset_rejects_overflow() {
        let err = QwpBuffer::checked_arena_offset(u32::MAX as usize, 1, "name_bytes").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP name_bytes arena exceeds maximum")
        );

        let err =
            QwpBuffer::checked_arena_offset(u32::MAX as usize - 1, 2, "value_bytes").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP value_bytes arena exceeds maximum")
        );
    }

    #[test]
    fn qwp_decimal_failed_commit_restores_decimal_value_bytes_len() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .column_dec("price", "1.2")
            .unwrap();
        assert_eq!(buf.value_bytes.len(), QWP_DECIMAL_MAG_BYTES);
        let value_bytes_cap_before = buf.value_bytes.capacity();
        let price_name = buf.entries.last().unwrap().name;
        buf.entries.push(EntryMeta {
            name: price_name,
            value: ValueRef::Bool(true),
        });

        let err = buf.at_now().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/UDP column "price" changes type within a batched table"#
        );
        assert!(buf.pending.table.is_none());
        assert!(buf.is_empty());
        assert_eq!(buf.value_bytes.len(), 0);
        assert_eq!(buf.value_bytes.capacity(), value_bytes_cap_before);
    }

    #[test]
    fn qwp_decimal_marker_rewind_truncates_decimal_value_bytes() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .column_dec("price", "1.20")
            .unwrap();
        buf.at_now().unwrap();
        assert_eq!(buf.value_bytes.len(), QWP_DECIMAL_MAG_BYTES);

        buf.set_marker().unwrap();
        buf.table("trades")
            .unwrap()
            .column_dec("price", "1.50")
            .unwrap();
        buf.at_now().unwrap();
        assert_eq!(buf.value_bytes.len(), QWP_DECIMAL_MAG_BYTES * 2);

        buf.rewind_to_marker().unwrap();
        assert_eq!(buf.row_count(), 1);
        assert_eq!(buf.value_bytes.len(), QWP_DECIMAL_MAG_BYTES);
    }

    #[test]
    fn qwp_decimal_clear_resets_value_bytes_but_retains_capacity() {
        let mut buf = QwpBuffer::new(127);

        for _ in 0..10 {
            buf.table("trades")
                .unwrap()
                .column_dec("price", "1.25")
                .unwrap()
                .at_now()
                .unwrap();
        }

        let value_bytes_cap_before = buf.value_bytes.capacity();
        assert!(value_bytes_cap_before > 0);
        assert_eq!(buf.value_bytes.len(), QWP_DECIMAL_MAG_BYTES * 10);

        buf.clear();
        assert_eq!(buf.value_bytes.len(), 0);
        assert_eq!(buf.value_bytes.capacity(), value_bytes_cap_before);
    }

    #[test]
    fn qwp_planner_checked_u16_rejects_overflow() {
        let err = RowGroupPlanner::checked_u16(u16::MAX as usize + 1, "column count").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("QWP/UDP column count exceeds maximum"));
    }

    #[test]
    fn qwp_checked_u32_helpers_reject_overflow() {
        let err = checked_qwp_u32(u32::MAX as usize + 1, "row metadata length").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP row metadata length exceeds maximum")
        );

        let err = checked_qwp_push_index(u32::MAX as usize, "planner cell count").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP planner cell count exceeds maximum")
        );
    }

    #[test]
    fn qwp_push_index_rejects_cell_end_collision() {
        let err =
            checked_qwp_push_index(CELL_END as usize, "symbol dictionary length").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP symbol dictionary length exceeds maximum")
        );
    }

    #[test]
    fn qwp_gap_fill_iter_rejects_row_count_overflow() {
        let err = match GapFillIter::new(&[], CELL_END, u32::MAX as usize + 1) {
            Ok(_) => panic!("expected row_count overflow to fail"),
            Err(err) => err,
        };
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP row group row count exceeds maximum")
        );
    }

    #[test]
    fn qwp_string_payload_counter_rejects_overflow() {
        let string_value = ValueRef::String(ValueSlice(ByteSlice { offset: 0, len: 1 }));
        let mut col = ColumnStats::new(&EntryMeta {
            name: NameSlice(ByteSlice { offset: 0, len: 1 }),
            value: string_value,
        });
        col.variable_data_len = usize::MAX;

        let err = col.add_non_symbol_value(&string_value).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP string payload bytes exceeds maximum")
        );
    }

    #[test]
    fn qwp_symbol_payload_counters_reject_overflow() {
        let symbol_value = ValueRef::Symbol(ValueSlice(ByteSlice { offset: 0, len: 1 }));
        let mut planner = RowGroupPlanner::new();
        planner.columns.push(ColumnStats::new(&EntryMeta {
            name: NameSlice(ByteSlice { offset: 0, len: 1 }),
            value: symbol_value,
        }));
        planner.cells.push(CellRef {
            row_idx: 0,
            symbol_dict_idx: 0,
            next: CELL_END,
            value: symbol_value,
        });
        planner.columns[0].symbol_row_index_bytes = usize::MAX;

        let err = planner
            .add_symbol_value(0, 0, &symbol_value, b"a")
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP symbol row-index bytes exceeds maximum")
        );
    }

    #[test]
    fn qwp_symbol_dictionary_supports_more_than_u16_max_entries_per_segment() {
        let symbol_value = ValueRef::Symbol(ValueSlice(ByteSlice { offset: 0, len: 1 }));
        let mut planner = RowGroupPlanner::new();
        planner.columns.push(ColumnStats::new(&EntryMeta {
            name: NameSlice(ByteSlice { offset: 0, len: 1 }),
            value: symbol_value,
        }));
        planner.columns[0].dict_count = u16::MAX as u32;
        planner.cells.push(CellRef {
            row_idx: 0,
            symbol_dict_idx: 0,
            next: CELL_END,
            value: symbol_value,
        });

        planner.add_symbol_value(0, 0, &symbol_value, b"a").unwrap();

        assert_eq!(planner.columns[0].dict_count, u16::MAX as u32 + 1);
        assert_eq!(planner.columns[0].non_null_count, 1);
        assert_eq!(planner.symbol_dict.len(), 1);
        assert_eq!(
            planner.cells.last().unwrap().symbol_dict_idx,
            u16::MAX as u32
        );
    }

    #[test]
    fn qwp_long_column_names_do_not_undercount_datagram_size() {
        let long_name = "c".repeat(u16::MAX as usize + 1);
        let mut buf = QwpBuffer::new(long_name.len());
        buf.table("t")
            .unwrap()
            .column_i64(long_name.as_str(), 1)
            .unwrap();
        buf.at_now().unwrap();

        assert!(buf.len() > 1400);

        let err = buf.encode_datagrams(1400).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("single row exceeds maximum datagram size")
        );
    }

    #[test]
    fn qwp_flushes_segment_with_more_than_u16_max_distinct_symbols() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        for i in 0..=u16::MAX {
            buf.table("trades")
                .unwrap()
                .symbol("sym", i.to_string())
                .unwrap();
            buf.at_now().unwrap();
        }

        let mut datagram_count = 0usize;
        buf.flush_to_socket(&mut scratch, 1400, &mut |datagram| {
            datagram_count += 1;
            assert!(datagram.len() <= 1400);
            Ok(())
        })
        .unwrap();

        assert_eq!(buf.row_count(), u16::MAX as usize + 1);
        assert!(datagram_count > 1);
    }

    #[test]
    fn qwp_flushes_segment_with_exactly_u16_max_distinct_symbols() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        for i in 0..u16::MAX {
            buf.table("trades")
                .unwrap()
                .symbol("sym", i.to_string())
                .unwrap();
            buf.at_now().unwrap();
        }

        let mut datagram_count = 0usize;
        buf.flush_to_socket(&mut scratch, 1400, &mut |datagram| {
            datagram_count += 1;
            assert!(datagram.len() <= 1400);
            Ok(())
        })
        .unwrap();

        assert_eq!(buf.row_count(), u16::MAX as usize);
        assert!(datagram_count > 0);
    }

    #[test]
    fn qwp_size_hint_segment_planner_rejects_out_of_range_index() {
        let size_hint = QwpSizeHint::new();

        let err = size_hint.segment_planner(1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            "internal error: missing cached planner for segment 1"
        );
    }

    #[test]
    fn qwp_planner_rollback_restores_symbol_hash_after_resize() {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        for i in 0..7 {
            buf.table("t")
                .unwrap()
                .symbol("s1", format!("v{i}"))
                .unwrap()
                .column_i64("x", i)
                .unwrap();
            buf.at_now().unwrap();
        }

        buf.table("t")
            .unwrap()
            .symbol("s1", "v7")
            .unwrap()
            .symbol("s2", "w0")
            .unwrap()
            .column_i64("x", 7)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("t")
            .unwrap()
            .symbol("s1", "v3")
            .unwrap()
            .symbol("s2", "w0")
            .unwrap()
            .column_i64("x", 8)
            .unwrap();
        buf.at_now().unwrap();

        for row in &buf.rows[..7] {
            planner
                .add_row(
                    row,
                    buf.entries_for_row(row),
                    &buf.name_bytes,
                    &buf.value_bytes,
                    "t".len(),
                )
                .unwrap();
        }

        let cp = planner.checkpoint();
        let resize_row = &buf.rows[7];
        planner
            .add_row(
                resize_row,
                buf.entries_for_row(resize_row),
                &buf.name_bytes,
                &buf.value_bytes,
                "t".len(),
            )
            .unwrap();
        assert_eq!(
            planner.current_len,
            encoded_planner_len(&planner, &buf.name_bytes, &buf.value_bytes, "t",)
        );

        planner.rollback(cp);
        assert_eq!(
            planner.current_len,
            encoded_planner_len(&planner, &buf.name_bytes, &buf.value_bytes, "t",)
        );

        let post_rollback_row = &buf.rows[8];
        planner
            .add_row(
                post_rollback_row,
                buf.entries_for_row(post_rollback_row),
                &buf.name_bytes,
                &buf.value_bytes,
                "t".len(),
            )
            .unwrap();
        assert_eq!(
            planner.current_len,
            encoded_planner_len(&planner, &buf.name_bytes, &buf.value_bytes, "t",)
        );
    }

    #[test]
    fn qwp_single_row_with_designated_timestamp_encodes_header() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap();
        buf.at(TimestampNanos::new(42)).unwrap();

        let datagrams = buf.encode_datagrams(1400).unwrap();
        assert_eq!(datagrams.len(), 1);
        let datagram = &datagrams[0];
        assert_eq!(&datagram[0..4], b"QWP1");
        assert_eq!(datagram[4], QWP_VERSION_1);
        assert_eq!(u16::from_le_bytes([datagram[6], datagram[7]]), 1);
        assert_eq!(
            u32::from_le_bytes([datagram[8], datagram[9], datagram[10], datagram[11]]) as usize,
            datagram.len() - QWP_MESSAGE_HEADER_SIZE
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_replay_reemits_dense_symbol_prefix_on_later_frame() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        add_trade_row(&mut buf, "BTC-USD", 1);
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();
        let first = scratch.message.clone();
        let (delta_start, entries, _) = ws_delta_entries(&first);
        assert_eq!(delta_start, 0);
        assert_eq!(entries, vec![b"BTC-USD".to_vec()]);
        assert_eq!(first_ws_schema_mode(&first), QWP_SCHEMA_MODE_FULL);

        buf.clear();
        add_trade_row(&mut buf, "BTC-USD", 2);
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();
        let second = scratch.message.clone();
        let (delta_start, entries, _) = ws_delta_entries(&second);
        assert_eq!(delta_start, 0);
        assert_eq!(
            entries,
            vec![b"BTC-USD".to_vec()],
            "replay frames must re-emit already-known symbols"
        );
        assert_eq!(first_ws_schema_mode(&second), QWP_SCHEMA_MODE_FULL);
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_replay_dense_prefix_includes_lower_symbol_ids() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        add_trade_row(&mut buf, "A", 1);
        add_trade_row(&mut buf, "B", 2);
        add_trade_row(&mut buf, "C", 3);
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        buf.clear();
        add_trade_row(&mut buf, "C", 4);
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        let replay = scratch.message.clone();
        let (delta_start, entries, _) = ws_delta_entries(&replay);
        assert_eq!(delta_start, 0);
        assert_eq!(
            entries,
            vec![b"A".to_vec(), b"B".to_vec(), b"C".to_vec()],
            "a frame referencing id 2 must carry the dense 0..=2 prefix"
        );
        assert_eq!(first_ws_schema_mode(&replay), QWP_SCHEMA_MODE_FULL);
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_replay_does_not_mutate_delta_encoder_schema_refs() {
        let mut buf = QwpBuffer::new(127);
        let mut replay_scratch = QwpWsEncodeScratch::new();
        let mut replay_dict = SymbolGlobalDict::new();
        let mut delta_scratch = QwpWsEncodeScratch::new();
        let mut delta_dict = SymbolGlobalDict::new();
        let mut schema_registry = SchemaRegistry::new();

        add_trade_row(&mut buf, "ETH-USD", 1);
        buf.encode_ws_message(
            &mut delta_scratch,
            &mut delta_dict,
            &mut schema_registry,
            QWP_VERSION_1,
        )
        .unwrap();
        buf.encode_ws_replay_message(&mut replay_scratch, &mut replay_dict, QWP_VERSION_1)
            .unwrap();
        assert_eq!(
            first_ws_schema_mode(&replay_scratch.message),
            QWP_SCHEMA_MODE_FULL
        );

        buf.clear();
        add_trade_row(&mut buf, "ETH-USD", 2);
        buf.encode_ws_message(
            &mut delta_scratch,
            &mut delta_dict,
            &mut schema_registry,
            QWP_VERSION_1,
        )
        .unwrap();
        assert_eq!(
            first_ws_schema_mode(&delta_scratch.message),
            QWP_SCHEMA_MODE_REFERENCE,
            "existing delta encoder should keep reference-schema behavior"
        );

        buf.encode_ws_replay_message(&mut replay_scratch, &mut replay_dict, QWP_VERSION_1)
            .unwrap();
        assert_eq!(
            first_ws_schema_mode(&replay_scratch.message),
            QWP_SCHEMA_MODE_FULL,
            "replay encoder must always emit full schema"
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_bookmark_rejects_cross_buffer_use_after_clone() {
        let mut original = QwpWsColumnarBuffer::new(127);

        original
            .table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        let original_bookmark = original.bookmark().unwrap();

        let mut cloned = original.clone();
        cloned
            .table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();

        let err = cloned.rewind_to_bookmark(original_bookmark).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            "Can't rewind to the bookmark: Bookmark does not belong to this buffer."
        );

        cloned.rewind_to_marker().unwrap();
        assert_eq!(cloned.row_count(), 1);

        original
            .table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();
        original.rewind_to_bookmark(original_bookmark).unwrap();
        assert_eq!(original.row_count(), 1);

        let clone_bookmark = cloned.bookmark().unwrap();
        cloned
            .table("trades")
            .unwrap()
            .symbol("sym", "ADA-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap()
            .at_now()
            .unwrap();
        cloned.rewind_to_bookmark(clone_bookmark).unwrap();
        assert_eq!(cloned.row_count(), 1);
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_existing_names_skip_validation() {
        let mut buf = QwpWsColumnarBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .column_i64("a", 1)
            .unwrap()
            .column_i64("b", 2)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table(PanicTableName("trades"))
            .unwrap()
            .column_i64(PanicColumnName("b"), 3)
            .unwrap()
            .column_i64(PanicColumnName("a"), 4)
            .unwrap()
            .at_now()
            .unwrap();

        assert_eq!(buf.row_count(), 2);
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_new_names_still_validate_and_rollback() {
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        let err = buf.table("bad?").unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidName);

        buf.table("trades").unwrap();
        let err = buf.column_i64("bad?", 1).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidName);

        buf.table("trades")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        assert_eq!(
            decode_single_i64_column_ws_replay(&scratch.message),
            vec![("trades".to_owned(), "qty".to_owned(), vec![3])]
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_duplicate_column_with_different_type_errors() {
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        buf.table("trades").unwrap().column_i64("qty", 1).unwrap();
        let err = buf.column_bool("QTY", true).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/WebSocket column "QTY" changes type within a batched table"#
        );

        buf.table("trades")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        assert_eq!(
            decode_single_i64_column_ws_replay(&scratch.message),
            vec![("trades".to_owned(), "qty".to_owned(), vec![3])]
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_rollback_removes_new_symbol_from_current_row() {
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ROLLBACK")
            .unwrap();
        let err = buf.column_bool("qty", true).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        let (_, entries, _) = ws_delta_entries(&scratch.message);
        assert_eq!(entries, vec![b"ETH-USD".to_vec(), b"BTC-USD".to_vec()]);
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_duplicate_column_is_first_value_wins() {
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        buf.table("trades")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .column_i64("QTY", 2)
            .unwrap()
            .at_now()
            .unwrap();
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        assert_eq!(
            decode_single_i64_column_ws_replay(&scratch.message),
            vec![("trades".to_owned(), "qty".to_owned(), vec![1])]
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_column_identity_is_case_insensitive() {
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        buf.table("trades")
            .unwrap()
            .column_i64("Qty", 7)
            .unwrap()
            .at_now()
            .unwrap();
        buf.table("trades")
            .unwrap()
            .column_i64("qty", 8)
            .unwrap()
            .at_now()
            .unwrap();
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        assert_eq!(
            decode_single_i64_column_ws_replay(&scratch.message),
            vec![("trades".to_owned(), "Qty".to_owned(), vec![7, 8])]
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_type_mismatch_rolls_back_partial_row() {
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        buf.table("trades")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades").unwrap().column_i64("other", 2).unwrap();
        let err = buf.column_bool("QTY", true).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/WebSocket column "QTY" changes type within a batched table"#
        );

        buf.table("trades")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        assert_eq!(
            decode_single_i64_column_ws_replay(&scratch.message),
            vec![("trades".to_owned(), "qty".to_owned(), vec![1, 3])]
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_interleaved_tables_are_grouped_by_table() {
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        buf.table("trades")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        buf.table("quotes")
            .unwrap()
            .column_i64("qty", 10)
            .unwrap()
            .at_now()
            .unwrap();
        buf.table("trades")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        assert_eq!(
            decode_single_i64_column_ws_replay(&scratch.message),
            vec![
                ("trades".to_owned(), "qty".to_owned(), vec![1, 2]),
                ("quotes".to_owned(), "qty".to_owned(), vec![10]),
            ]
        );
    }

    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    fn qwp_ws_columnar_replay_matches_row_log_for_all_value_kinds_and_schema_growth() {
        let mut row_log = QwpBuffer::new(127);
        let mut columnar = QwpWsColumnarBuffer::new(127);
        let samples = vec![1.0_f64, 2.0];

        row_log
            .table("audit")
            .unwrap()
            .symbol("sym", "A")
            .unwrap()
            .column_bool("active", true)
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .column_f64("px", 1.5)
            .unwrap()
            .column_str("note", "first")
            .unwrap()
            .column_dec("price", "12.3400")
            .unwrap()
            .column_arr("samples", &samples)
            .unwrap()
            .column_ts("event_ts", TimestampMicros::new(7))
            .unwrap()
            .at(TimestampNanos::new(9))
            .unwrap();
        columnar
            .table("audit")
            .unwrap()
            .symbol("sym", "A")
            .unwrap()
            .column_bool("active", true)
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .column_f64("px", 1.5)
            .unwrap()
            .column_str("note", "first")
            .unwrap()
            .column_dec("price", "12.3400")
            .unwrap()
            .column_arr("samples", &samples)
            .unwrap()
            .column_ts("event_ts", TimestampMicros::new(7))
            .unwrap()
            .at(TimestampNanos::new(9))
            .unwrap();

        row_log
            .table("audit")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();
        columnar
            .table("audit")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        row_log
            .table("audit")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .column_i64("late", 99)
            .unwrap()
            .at_now()
            .unwrap();
        columnar
            .table("audit")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .column_i64("late", 99)
            .unwrap()
            .at_now()
            .unwrap();

        let mut row_log_scratch = QwpWsEncodeScratch::new();
        let mut row_log_dict = SymbolGlobalDict::new();
        row_log
            .encode_ws_replay_message(&mut row_log_scratch, &mut row_log_dict, QWP_VERSION_1)
            .unwrap();

        let mut columnar_scratch = QwpWsEncodeScratch::new();
        let mut columnar_dict = SymbolGlobalDict::new();
        columnar
            .encode_ws_replay_message(&mut columnar_scratch, &mut columnar_dict, QWP_VERSION_1)
            .unwrap();

        assert_eq!(columnar_scratch.message, row_log_scratch.message);
    }

    #[cfg(feature = "_sender-qwp-ws")]
    const QWP_WS_COLUMNAR_BENCH_BATCH_SIZE: usize = 1000;

    #[cfg(feature = "_sender-qwp-ws")]
    fn qwp_ws_columnar_bench_rows() -> usize {
        std::env::var("QWP_WS_COLUMNAR_BENCH_ROWS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|rows| *rows > 0)
            .unwrap_or(20_000_000)
    }

    #[cfg(feature = "_sender-qwp-ws")]
    fn fill_qwp_ws_columnar_benchmark_batch(
        buf: &mut QwpWsColumnarBuffer,
        batch_idx: usize,
        rows: usize,
    ) {
        let symbols = [
            "SYM000", "SYM001", "SYM002", "SYM003", "SYM004", "SYM005", "SYM006", "SYM007",
        ];
        let venues = ["ldn", "nyc", "ams", "fra", "sin", "hkg", "tyo", "sfo"];
        for row_idx in 0..rows {
            let seq = (batch_idx * QWP_WS_COLUMNAR_BENCH_BATCH_SIZE + row_idx) as i64;
            buf.table("trades")
                .unwrap()
                .symbol("sym", symbols[row_idx & 7])
                .unwrap()
                .column_i64("qty", seq)
                .unwrap()
                .column_f64("px", 100.0 + (seq & 1023) as f64)
                .unwrap()
                .column_str("venue", venues[row_idx & 7])
                .unwrap()
                .column_ts("event_ts", TimestampMicros::new(seq))
                .unwrap()
                .at(TimestampNanos::new(seq))
                .unwrap();
        }
    }

    /// Run with:
    /// `cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_columnar_row_build_benchmark --lib -- --ignored --nocapture --test-threads=1`
    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    #[ignore = "performance benchmark"]
    fn qwp_ws_columnar_row_build_benchmark() {
        let rows = qwp_ws_columnar_bench_rows();
        let batches = rows.div_ceil(QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
        let mut buf = QwpWsColumnarBuffer::new(127);

        fill_qwp_ws_columnar_benchmark_batch(&mut buf, 0, QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
        buf.clear();

        let started = std::time::Instant::now();
        let mut built_rows = 0usize;
        for batch_idx in 0..batches {
            let rows_in_batch = (rows - built_rows).min(QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
            fill_qwp_ws_columnar_benchmark_batch(&mut buf, batch_idx, rows_in_batch);
            std::hint::black_box(buf.len());
            buf.clear();
            built_rows += rows_in_batch;
        }
        let elapsed = started.elapsed();
        eprintln!(
            "qwp_ws_columnar_row_build_benchmark rows={} batch_size={} build_ms={} rows_per_sec={:.2}",
            rows,
            QWP_WS_COLUMNAR_BENCH_BATCH_SIZE,
            elapsed.as_millis(),
            rows as f64 / elapsed.as_secs_f64()
        );
    }

    /// Run with:
    /// `cargo test --release --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_columnar_encode_benchmark --lib -- --ignored --nocapture --test-threads=1`
    #[cfg(feature = "_sender-qwp-ws")]
    #[test]
    #[ignore = "performance benchmark"]
    fn qwp_ws_columnar_encode_benchmark() {
        let requested_rows = qwp_ws_columnar_bench_rows();
        let iterations = requested_rows.div_ceil(QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
        let measured_rows = iterations * QWP_WS_COLUMNAR_BENCH_BATCH_SIZE;
        let mut buf = QwpWsColumnarBuffer::new(127);
        let mut scratch = QwpWsEncodeScratch::new();
        let mut global_dict = SymbolGlobalDict::new();

        fill_qwp_ws_columnar_benchmark_batch(&mut buf, 0, QWP_WS_COLUMNAR_BENCH_BATCH_SIZE);
        buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
            .unwrap();

        let started = std::time::Instant::now();
        for _ in 0..iterations {
            buf.encode_ws_replay_message(&mut scratch, &mut global_dict, QWP_VERSION_1)
                .unwrap();
            std::hint::black_box(scratch.message.len());
        }
        let elapsed = started.elapsed();
        eprintln!(
            "qwp_ws_columnar_encode_benchmark rows={} batch_size={} encode_ms={} rows_per_sec={:.2}",
            measured_rows,
            QWP_WS_COLUMNAR_BENCH_BATCH_SIZE,
            elapsed.as_millis(),
            measured_rows as f64 / elapsed.as_secs_f64()
        );
    }

    #[test]
    fn qwp_single_row_without_designated_timestamp_omits_empty_column() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap();
        buf.at_now().unwrap();

        let datagram = buf.encode_datagrams(1400).unwrap().pop().unwrap();
        assert!(!datagram.windows(2).any(|w| w == [0, QWP_TYPE_TIMESTAMP]));
        assert!(
            !datagram
                .windows(2)
                .any(|w| w == [0, QWP_TYPE_TIMESTAMP_NANOS])
        );
    }

    #[test]
    fn qwp_state_machine_matches_ilp_shape() {
        let mut buf = QwpBuffer::new(127);
        let err = buf.at_now().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("Bad call to `at`"));

        buf.table("trades").unwrap();
        let err = buf.at(TimestampMicros::new(1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("should have called `symbol` or `column` instead")
        );
    }

    #[test]
    fn qwp_at_rejects_negative_designated_timestamps_without_losing_pending_row() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades").unwrap().column_i64("qty", 1).unwrap();

        let err = buf.at(TimestampMicros::new(-1)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidTimestamp);
        assert_eq!(err.msg(), "Timestamp -1 is negative. It must be >= 0.");
        assert_eq!(buf.row_count(), 0);

        buf.at(TimestampMicros::new(1)).unwrap();
        assert_eq!(buf.row_count(), 1);

        let mut nanos_buf = QwpBuffer::new(127);
        nanos_buf
            .table("trades")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap();

        let err = nanos_buf.at(TimestampNanos::new(-2)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidTimestamp);
        assert_eq!(err.msg(), "Timestamp -2 is negative. It must be >= 0.");
        assert_eq!(nanos_buf.row_count(), 0);

        nanos_buf.at(TimestampNanos::new(2)).unwrap();
        assert_eq!(nanos_buf.row_count(), 1);
    }

    #[test]
    fn qwp_size_hint_preserves_current_group_after_new_group_error() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades").unwrap().column_i64("qty", 1).unwrap();
        buf.at_now().unwrap();

        let len_before = buf.len();
        let planner_len_before = buf.size_hint.planner.current_len;
        let planner_rows_before = buf.size_hint.planner.row_count();
        let group_table_before = buf.size_hint.group_table;
        let last_seg_table = buf.segments.last().map(|segment| segment.table);

        let bad_table = buf.append_name("quotes").unwrap();
        let bad_name = buf.append_name("dup").unwrap();
        let entry_start = buf.entries.len() as u32;
        buf.entries.push(EntryMeta {
            name: bad_name,
            value: ValueRef::I64(1),
        });
        buf.entries.push(EntryMeta {
            name: bad_name,
            value: ValueRef::Bool(true),
        });
        let bad_row = RowMeta {
            table: bad_table,
            entry_start,
            entry_count: 2,
            designated_ts: None,
        };

        let err = buf
            .size_hint
            .add_committed_row(
                &bad_row,
                &buf.entries,
                &buf.name_bytes,
                &buf.value_bytes,
                last_seg_table,
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/UDP column "dup" changes type within a batched table"#
        );
        assert_eq!(buf.size_hint.committed_len, len_before);
        assert_eq!(buf.size_hint.planner.current_len, planner_len_before);
        assert_eq!(buf.size_hint.planner.row_count(), planner_rows_before);
        assert_eq!(buf.size_hint.group_table, group_table_before);

        buf.table("trades").unwrap().column_i64("qty", 2).unwrap();
        buf.at_now().unwrap();

        let actual: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(buf.len(), actual);
    }

    #[test]
    fn qwp_first_row_size_hint_error_resets_flush_state_to_init() {
        let mut buf = QwpBuffer::new(127);

        buf.table("longname").unwrap().column_i64("qty", 1).unwrap();
        let qty_name = buf.entries.last().unwrap().name;
        buf.entries.push(EntryMeta {
            name: qty_name,
            value: ValueRef::Bool(true),
        });

        let err = buf.at_now().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/UDP column "qty" changes type within a batched table"#
        );
        assert_eq!(buf.row_count(), 0);
        assert!(buf.is_empty());

        // After error rollback, buffer is empty — flush is a no-op.
        buf.check_can_flush().unwrap();

        buf.table("hi").unwrap().column_i64("qty", 2).unwrap();
        buf.at_now().unwrap();
        assert_eq!(buf.row_count(), 1);
    }

    #[test]
    fn qwp_later_size_hint_error_keeps_flushable_state() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades").unwrap().column_i64("qty", 1).unwrap();
        buf.at_now().unwrap();

        buf.table("trades")
            .unwrap()
            .column_bool("qty", true)
            .unwrap();

        let err = buf.at_now().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/UDP column "qty" changes type within a batched table"#
        );
        assert_eq!(buf.row_count(), 1);
        buf.check_can_flush().unwrap();
    }

    #[test]
    fn qwp_failed_commit_restores_saved_buffer_state() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades").unwrap().column_i64("qty", 1).unwrap();
        buf.at_now().unwrap();

        let len_before = buf.len();
        let state_before = buf.state;
        let entries_len_before = buf.entries.len();
        let name_bytes_len_before = buf.name_bytes.len();
        let value_bytes_len_before = buf.value_bytes.len();

        buf.table("quotes").unwrap().column_i64("qty", 2).unwrap();
        let qty_name = buf.entries.last().unwrap().name;
        buf.entries.push(EntryMeta {
            name: qty_name,
            value: ValueRef::Bool(true),
        });

        let err = buf.at_now().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/UDP column "qty" changes type within a batched table"#
        );
        assert_eq!(buf.len(), len_before);
        assert_eq!(buf.row_count(), 1);
        assert_eq!(buf.state.op_state, state_before.op_state);
        assert_eq!(buf.state.row_count, state_before.row_count);
        assert_eq!(buf.entries.len(), entries_len_before);
        assert_eq!(buf.name_bytes.len(), name_bytes_len_before);
        assert_eq!(buf.value_bytes.len(), value_bytes_len_before);
        assert!(buf.pending.table.is_none());
        buf.check_can_flush().unwrap();
    }

    #[test]
    fn qwp_late_commit_overflow_restores_pending_and_size_hint_state() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades").unwrap().column_i64("qty", 1).unwrap();
        buf.at_now().unwrap();

        let len_before = buf.len();
        let state_before = buf.state;
        let planner_len_before = buf.size_hint.planner.current_len;
        let planner_rows_before = buf.size_hint.planner.row_count();
        let entries_len_before = buf.entries.len();
        let name_bytes_len_before = buf.name_bytes.len();
        let value_bytes_len_before = buf.value_bytes.len();

        buf.table("trades").unwrap().column_i64("qty", 2).unwrap();
        buf.segments.last_mut().unwrap().row_count = u32::MAX;

        let err = buf.at_now().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg()
                .contains("QWP/UDP segment row count exceeds maximum")
        );
        assert_eq!(buf.len(), len_before);
        assert_eq!(buf.row_count(), 1);
        assert_eq!(buf.state.op_state, state_before.op_state);
        assert_eq!(buf.state.row_count, state_before.row_count);
        assert_eq!(buf.size_hint.planner.current_len, planner_len_before);
        assert_eq!(buf.size_hint.planner.row_count(), planner_rows_before);
        assert_eq!(buf.entries.len(), entries_len_before);
        assert_eq!(buf.name_bytes.len(), name_bytes_len_before);
        assert_eq!(buf.value_bytes.len(), value_bytes_len_before);
        assert!(buf.pending.table.is_none());
        buf.check_can_flush().unwrap();
    }

    #[test]
    fn qwp_rewind_to_marker_propagates_size_hint_replay_errors() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades").unwrap().column_i64("qty", 1).unwrap();
        buf.at_now().unwrap();
        buf.table("trades").unwrap().column_i64("qty", 2).unwrap();
        buf.at_now().unwrap();
        buf.set_marker().unwrap();
        let marker_before = buf.bookmark.current().expect("marker should be set");
        let len_before = buf.len();
        let row_count_before = buf.row_count();
        let rows_len_before = buf.rows.len();
        let segments_len_before = buf.segments.len();

        let second_row_entry_idx = buf.rows[1].entry_start as usize;
        buf.entries[second_row_entry_idx].value = ValueRef::Bool(true);

        let err = buf.rewind_to_marker().unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert_eq!(
            err.msg(),
            r#"QWP/UDP column "qty" changes type within a batched table"#
        );
        assert_eq!(buf.len(), len_before);
        assert_eq!(buf.row_count(), row_count_before);
        assert_eq!(buf.rows.len(), rows_len_before);
        assert_eq!(buf.segments.len(), segments_len_before);
        let marker_after = buf
            .bookmark
            .current()
            .expect("marker should be preserved on failure");
        assert_eq!(marker_after.rows_len, marker_before.rows_len);
        assert_eq!(marker_after.entries_len, marker_before.entries_len);
        assert_eq!(marker_after.segments_len, marker_before.segments_len);
        assert_eq!(
            marker_after.tail_segment_row_count,
            marker_before.tail_segment_row_count
        );
    }

    #[test]
    fn qwp_estimator_matches_actual_for_supported_prefixes() {
        let mut buf = QwpBuffer::new(127);

        buf.table("audit")
            .unwrap()
            .symbol("sym", "stable")
            .unwrap()
            .column_bool("active", true)
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .column_f64("px", 11.5)
            .unwrap()
            .column_str("venue", "tokyo-1")
            .unwrap()
            .column_ts("event_ts", TimestampMicros::new(100))
            .unwrap()
            .at(TimestampMicros::new(1000))
            .unwrap();

        buf.table("audit")
            .unwrap()
            .symbol("sym", "stable")
            .unwrap()
            .column_bool("active", false)
            .unwrap()
            .column_f64("px", 12.5)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("audit")
            .unwrap()
            .symbol("sym", "tokyo-3")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .column_str("venue", "tokyo-3-xxxxxxxx")
            .unwrap()
            .at(TimestampMicros::new(3000))
            .unwrap();

        buf.table("audit")
            .unwrap()
            .symbol("sym", "tokyo-4")
            .unwrap()
            .column_bool("active", true)
            .unwrap()
            .column_ts("event_ts", TimestampMicros::new(444))
            .unwrap()
            .at_now()
            .unwrap();

        for prefix_len in 1..=buf.rows.len() {
            let rows = &buf.rows[..prefix_len];
            let table_name = buf.name_str(rows[0].table);
            let mut planner = RowGroupPlanner::new();
            for row in rows {
                let row_entries = buf.entries_for_row(row);
                planner
                    .add_row(
                        row,
                        row_entries,
                        &buf.name_bytes,
                        &buf.value_bytes,
                        table_name.len(),
                    )
                    .unwrap();
            }
            let estimated = planner.current_len;

            let mut datagram_buf = Vec::new();
            encode_row_group_from_scratch(
                &planner,
                &buf.name_bytes,
                &buf.value_bytes,
                table_name.as_bytes(),
                &mut datagram_buf,
            )
            .unwrap();
            let actual = datagram_buf.len();
            assert_eq!(estimated, actual, "prefix {prefix_len}");
        }
    }

    #[test]
    fn qwp_estimator_matches_actual_across_symbol_varint_boundary() {
        let mut buf = QwpBuffer::new(127);
        for i in 0..160 {
            buf.table("sym_audit")
                .unwrap()
                .symbol("sym", format!("sym-{i}"))
                .unwrap()
                .column_i64("x", i)
                .unwrap()
                .at_now()
                .unwrap();
        }

        for prefix_len in 1..=buf.rows.len() {
            let rows = &buf.rows[..prefix_len];
            let table_name = buf.name_str(rows[0].table);
            let mut planner = RowGroupPlanner::new();
            for row in rows {
                let row_entries = buf.entries_for_row(row);
                planner
                    .add_row(
                        row,
                        row_entries,
                        &buf.name_bytes,
                        &buf.value_bytes,
                        table_name.len(),
                    )
                    .unwrap();
            }
            let estimated = planner.current_len;

            let mut datagram_buf = Vec::new();
            encode_row_group_from_scratch(
                &planner,
                &buf.name_bytes,
                &buf.value_bytes,
                table_name.as_bytes(),
                &mut datagram_buf,
            )
            .unwrap();
            let actual = datagram_buf.len();
            assert_eq!(estimated, actual, "prefix {}", prefix_len);
        }
    }

    #[test]
    fn qwp_len_matches_unsplit_datagram_encoding_for_committed_groups() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_str("venue", "binance")
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 9)
            .unwrap()
            .at_now()
            .unwrap();

        let actual: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(buf.len(), actual);
    }

    #[test]
    fn qwp_len_rewinds_with_marker_state() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        let before = buf.len();
        buf.set_marker().unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();

        assert!(buf.len() > before);
        buf.rewind_to_marker().unwrap();
        assert_eq!(buf.len(), before);

        let actual: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(buf.len(), actual);
    }

    #[test]
    fn qwp_len_resets_after_clear() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        assert!(!buf.is_empty());
        assert_eq!(buf.row_count(), 1);

        buf.clear();

        assert_eq!(buf.len(), 0);
        assert_eq!(buf.row_count(), 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn qwp_len_clone_tracks_cached_state_independently() {
        let mut original = QwpBuffer::new(127);

        original
            .table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        original
            .table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        let mut cloned = original.clone();
        assert_eq!(original.len(), cloned.len());

        let original_actual: usize = original
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        let cloned_actual: usize = cloned
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(original.len(), original_actual);
        assert_eq!(cloned.len(), cloned_actual);

        cloned
            .table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();

        assert_ne!(original.len(), cloned.len());

        let original_after: usize = original
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        let cloned_after: usize = cloned
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(original.len(), original_after);
        assert_eq!(cloned.len(), cloned_after);
    }

    #[test]
    fn qwp_len_treats_non_contiguous_same_table_rows_as_distinct_groups() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        buf.table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap()
            .at_now()
            .unwrap();
        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        let before = buf.len();
        let actual_before: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(before, actual_before);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();

        assert!(buf.len() > before);
        let actual_after: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(buf.len(), actual_after);
    }

    #[test]
    fn qwp_retained_capacity_after_clear() {
        let mut buf = QwpBuffer::new(127);

        for i in 0..10 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", format!("SYM-{i}"))
                .unwrap()
                .column_i64("qty", i)
                .unwrap()
                .at_now()
                .unwrap();
        }

        let cap_before = buf.capacity();
        assert!(cap_before > 0);

        buf.clear();
        let cap_after = buf.capacity();
        assert_eq!(
            cap_before, cap_after,
            "capacity must not drop after clear()"
        );

        // Refill
        for i in 0..10 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", format!("SYM-{i}"))
                .unwrap()
                .column_i64("qty", i)
                .unwrap()
                .at_now()
                .unwrap();
        }

        let cap_refilled = buf.capacity();
        assert_eq!(
            cap_before, cap_refilled,
            "capacity must not change after refill with same workload"
        );
    }

    #[test]
    fn qwp_reserve_prewarms_active_size_hint_planners() {
        let mut buf = QwpBuffer::new(127);

        buf.reserve(300);

        assert!(buf.size_hint.planner.columns.capacity() > 0);
        assert!(buf.size_hint.planner.cells.capacity() > 0);
        assert!(buf.size_hint.planner.symbol_dict.capacity() > 0);
        assert!(buf.size_hint.planner.undo_stack.capacity() > 0);
        assert!(buf.size_hint.planner.symbol_lookup_undo.capacity() > 0);
        assert!(buf.size_hint.planner.symbol_hash_buckets.len() >= 16);

        assert!(buf.size_hint.scratch.columns.capacity() > 0);
        assert!(buf.size_hint.scratch.cells.capacity() > 0);
        assert!(buf.size_hint.scratch.symbol_dict.capacity() > 0);
        assert!(buf.size_hint.scratch.undo_stack.capacity() > 0);
        assert!(buf.size_hint.scratch.symbol_lookup_undo.capacity() > 0);
        assert!(buf.size_hint.scratch.symbol_hash_buckets.len() >= 16);

        assert!(buf.size_hint.completed.capacity() > 0);
    }

    #[test]
    fn qwp_send_scratch_new_prewarms_planner_vectors() {
        let scratch = QwpSendScratch::new(1400);

        assert!(scratch.datagram.capacity() >= 1400);
        assert!(scratch.planner.columns.capacity() > 0);
        assert!(scratch.planner.cells.capacity() > 0);
        assert!(scratch.planner.symbol_dict.capacity() > 0);
        assert!(scratch.planner.undo_stack.capacity() > 0);
        assert!(scratch.planner.symbol_lookup_undo.capacity() > 0);
        assert!(scratch.planner.symbol_hash_buckets.len() >= 16);
    }

    #[test]
    fn qwp_marker_rewind_tail_segment() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        buf.set_marker().unwrap();

        // Add more rows to same table (same segment)
        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 2)
            .unwrap()
            .at_now()
            .unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "SOL-USD")
            .unwrap()
            .column_i64("qty", 3)
            .unwrap()
            .at_now()
            .unwrap();

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].row_count, 3);

        buf.rewind_to_marker().unwrap();

        assert_eq!(buf.segments.len(), 1);
        assert_eq!(buf.segments[0].row_count, 1);
        assert_eq!(buf.rows.len(), 1);

        // Can continue adding rows
        buf.table("trades")
            .unwrap()
            .symbol("sym", "DOGE-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap()
            .at_now()
            .unwrap();

        assert_eq!(buf.segments[0].row_count, 2);

        let datagrams = buf.encode_datagrams(1400).unwrap();
        assert_eq!(datagrams.len(), 1);
    }

    #[test]
    fn qwp_clone_while_pending() {
        let mut buf = QwpBuffer::new(127);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();

        // Start a new row but don't finish it
        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap();

        let mut cloned = buf.clone();

        // Finish in original
        buf.column_i64("qty", 2).unwrap();
        buf.at_now().unwrap();

        // Finish in clone with different data
        cloned.column_f64("px", 42.5).unwrap();
        cloned.at_now().unwrap();

        assert_eq!(buf.row_count(), 2);
        assert_eq!(cloned.row_count(), 2);

        // They should produce different datagrams
        let orig_dgrams = buf.encode_datagrams(1400).unwrap();
        let cloned_dgrams = cloned.encode_datagrams(1400).unwrap();
        assert_ne!(orig_dgrams, cloned_dgrams);
    }

    #[test]
    fn qwp_line_sender_protocol_behavior_after_close() {
        let mut buf = QwpBuffer::new(127);
        buf.table("test")
            .unwrap()
            .symbol("s", "v")
            .unwrap()
            .column_i64("x", 1)
            .unwrap();
        buf.at_now().unwrap();

        buf.clear();
        assert!(buf.is_empty());
        assert_eq!(buf.row_count(), 0);
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn qwp_single_row_oversize_returns_error() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_str("venue", "a]]very-long-string-that-makes-the-row-big")
            .unwrap()
            .column_i64("qty", 42)
            .unwrap();
        buf.at_now().unwrap();

        // Use a very small max datagram size so one row can't fit
        let result = buf.encode_datagrams(30);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("single row exceeds"));
    }

    #[test]
    fn qwp_planner_checkpoint_rollback_restores_state() {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        buf.table("t")
            .unwrap()
            .symbol("s", "a")
            .unwrap()
            .column_i64("x", 1)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("t")
            .unwrap()
            .symbol("s", "b")
            .unwrap()
            .column_i64("x", 2)
            .unwrap();
        buf.at_now().unwrap();

        let row0 = &buf.rows[0];
        let row1 = &buf.rows[1];
        let entries0 = buf.entries_for_row(row0);
        let entries1 = buf.entries_for_row(row1);

        // Add first row
        planner
            .add_row(row0, entries0, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        let len_after_1 = planner.current_len;
        assert_eq!(planner.row_count(), 1);

        // Checkpoint, add second row, then rollback
        let cp = planner.checkpoint();
        planner
            .add_row(row1, entries1, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.row_count(), 2);
        assert!(planner.current_len > len_after_1);

        planner.rollback(cp);
        assert_eq!(planner.row_count(), 1);
        assert_eq!(planner.current_len, len_after_1);
        assert_eq!(planner.columns.len(), cp.columns_len);
    }

    #[test]
    fn qwp_planner_rollback_returns_new_columns_to_pool() {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        // Row 1: only "x"
        buf.table("t").unwrap().column_i64("x", 1).unwrap();
        buf.at_now().unwrap();

        // Row 2: "x" and "y" (introduces new column)
        buf.table("t")
            .unwrap()
            .column_i64("x", 2)
            .unwrap()
            .column_i64("y", 3)
            .unwrap();
        buf.at_now().unwrap();

        let row0 = &buf.rows[0];
        let row1 = &buf.rows[1];
        let entries0 = buf.entries_for_row(row0);
        let entries1 = buf.entries_for_row(row1);

        planner
            .add_row(row0, entries0, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.columns.len(), 1); // just "x"

        let cp = planner.checkpoint();
        planner
            .add_row(row1, entries1, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.columns.len(), 2); // "x" + "y"

        planner.rollback(cp);
        assert_eq!(planner.columns.len(), 1); // "y" removed by truncate
    }

    #[test]
    fn qwp_planner_incremental_len_stays_exact_across_rollback_and_reuse() {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        buf.table("t").unwrap().column_i64("x", 1).unwrap();
        buf.at_now().unwrap();

        buf.table("t")
            .unwrap()
            .column_i64("x", 2)
            .unwrap()
            .column_bool("flag", true)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("t")
            .unwrap()
            .column_i64("x", 3)
            .unwrap()
            .column_str("note", "hello")
            .unwrap();
        buf.at_now().unwrap();

        let row0 = &buf.rows[0];
        let row1 = &buf.rows[1];
        let row2 = &buf.rows[2];
        let entries0 = buf.entries_for_row(row0);
        let entries1 = buf.entries_for_row(row1);
        let entries2 = buf.entries_for_row(row2);

        planner
            .add_row(row0, entries0, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.current_len, exact_planner_len(&planner, "t".len()));

        let cp = planner.checkpoint();
        planner
            .add_row(row1, entries1, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.current_len, exact_planner_len(&planner, "t".len()));

        planner.rollback(cp);
        assert_eq!(planner.current_len, exact_planner_len(&planner, "t".len()));

        planner
            .add_row(row2, entries2, &buf.name_bytes, &buf.value_bytes, "t".len())
            .unwrap();
        assert_eq!(planner.current_len, exact_planner_len(&planner, "t".len()));
    }

    #[test]
    fn qwp_planner_incremental_len_matches_actual_across_untouched_column_boundaries() {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        buf.table("audit")
            .unwrap()
            .column_bool("active", true)
            .unwrap()
            .column_str("venue", "tokyo")
            .unwrap()
            .column_ts("event_ts", TimestampMicros::new(1))
            .unwrap()
            .column_i64("qty", 1)
            .unwrap();
        buf.at_now().unwrap();

        for i in 2..=17 {
            buf.table("audit").unwrap().column_i64("qty", i).unwrap();
            buf.at_now().unwrap();
        }

        for prefix_len in 1..=buf.rows.len() {
            let row = &buf.rows[prefix_len - 1];
            let row_entries = buf.entries_for_row(row);
            planner
                .add_row(
                    row,
                    row_entries,
                    &buf.name_bytes,
                    &buf.value_bytes,
                    "audit".len(),
                )
                .unwrap();
            let actual = encoded_planner_len(&planner, &buf.name_bytes, &buf.value_bytes, "audit");
            assert_eq!(planner.current_len, actual, "prefix {}", prefix_len);
        }
    }

    #[test]
    fn qwp_planner_incremental_len_matches_actual_across_untouched_column_boundaries_dense_sparse_transition_emits_bitmap()
     {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        buf.table("audit")
            .unwrap()
            .column_str("venue", "tokyo")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap();
        buf.at_now().unwrap();

        let row0 = &buf.rows[0];
        let entries0 = buf.entries_for_row(row0);
        planner
            .add_row(
                row0,
                entries0,
                &buf.name_bytes,
                &buf.value_bytes,
                "audit".len(),
            )
            .unwrap();
        assert_eq!(
            planner.current_len,
            exact_planner_len(&planner, "audit".len())
        );
        assert_eq!(
            planner.current_len,
            encoded_planner_len(&planner, &buf.name_bytes, &buf.value_bytes, "audit")
        );
        assert_eq!(planner.active_bitmap_column_count, 0);

        let mut datagram = Vec::new();
        encode_row_group_from_scratch(
            &planner,
            &buf.name_bytes,
            &buf.value_bytes,
            b"audit",
            &mut datagram,
        )
        .unwrap();
        let decoded = decode_datagram(&datagram).unwrap();
        let venue = decoded
            .table
            .columns
            .iter()
            .find(|column| column.name == "venue")
            .unwrap();
        assert!(!venue.nullable, "dense first row must skip null bitmap");
        assert_eq!(
            decoded.table.rows[0][0],
            DecodedValue::String("tokyo".to_owned())
        );

        buf.table("audit").unwrap().column_i64("qty", 2).unwrap();
        buf.at_now().unwrap();

        let row1 = &buf.rows[1];
        let entries1 = buf.entries_for_row(row1);
        planner
            .add_row(
                row1,
                entries1,
                &buf.name_bytes,
                &buf.value_bytes,
                "audit".len(),
            )
            .unwrap();
        assert_eq!(
            planner.current_len,
            exact_planner_len(&planner, "audit".len())
        );
        assert_eq!(
            planner.current_len,
            encoded_planner_len(&planner, &buf.name_bytes, &buf.value_bytes, "audit")
        );
        assert_eq!(planner.active_bitmap_column_count, 1);

        datagram.clear();
        encode_row_group_from_scratch(
            &planner,
            &buf.name_bytes,
            &buf.value_bytes,
            b"audit",
            &mut datagram,
        )
        .unwrap();
        let decoded = decode_datagram(&datagram).unwrap();
        let venue = decoded
            .table
            .columns
            .iter()
            .find(|column| column.name == "venue")
            .unwrap();
        assert!(venue.nullable, "later omission must enable null bitmap");
        assert_eq!(
            decoded.table.rows[0][0],
            DecodedValue::String("tokyo".to_owned())
        );
        assert_eq!(decoded.table.rows[1][0], DecodedValue::Null);
    }

    #[test]
    fn qwp_planner_incremental_len_matches_actual_when_late_schema_growth_crosses_varint_boundary()
    {
        let mut planner = RowGroupPlanner::new();
        let mut buf = QwpBuffer::new(127);

        buf.table("wide").unwrap().column_i64("base", 1).unwrap();
        buf.at_now().unwrap();

        buf.table("wide").unwrap().column_i64("base", 2).unwrap();
        for idx in 0..127 {
            let name = format!("c{idx:03}");
            buf.column_i64(name.as_str(), idx as i64).unwrap();
        }
        buf.at_now().unwrap();

        let row0 = &buf.rows[0];
        let row1 = &buf.rows[1];
        let entries0 = buf.entries_for_row(row0);
        let entries1 = buf.entries_for_row(row1);

        planner
            .add_row(
                row0,
                entries0,
                &buf.name_bytes,
                &buf.value_bytes,
                "wide".len(),
            )
            .unwrap();
        planner
            .add_row(
                row1,
                entries1,
                &buf.name_bytes,
                &buf.value_bytes,
                "wide".len(),
            )
            .unwrap();

        assert_eq!(planner.columns.len(), 128);
        let actual = encoded_planner_len(&planner, &buf.name_bytes, &buf.value_bytes, "wide");
        assert_eq!(planner.current_len, actual);
    }

    #[test]
    fn qwp_size_hint_matches_unsplit_len_across_same_group_bitmap_boundaries() {
        let mut buf = QwpBuffer::new(127);

        for i in 1..=17 {
            buf.table("audit").unwrap();
            if i == 1 {
                buf.column_bool("active", true)
                    .unwrap()
                    .column_str("venue", "tokyo")
                    .unwrap()
                    .column_ts("event_ts", TimestampMicros::new(1))
                    .unwrap();
            }
            buf.column_i64("qty", i).unwrap();
            buf.at_now().unwrap();

            let actual: usize = buf
                .encode_datagrams(usize::MAX)
                .unwrap()
                .iter()
                .map(Vec::len)
                .sum();
            assert_eq!(buf.len(), actual, "after row {}", i);
        }
    }

    #[test]
    fn qwp_long_lived_churn_retains_capacity_without_unbounded_growth() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        // Simulate many fill/flush/clear cycles with varying table names
        for cycle in 0..20 {
            for i in 0..5 {
                let tname = format!("table_{}", cycle % 3);
                buf.table(tname.as_str())
                    .unwrap()
                    .symbol("sym", format!("sym-{i}"))
                    .unwrap()
                    .column_i64("x", i)
                    .unwrap();
                buf.at_now().unwrap();
            }

            // Flush to a no-op sink
            buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
                .unwrap();
            buf.clear();
        }

        // After many cycles, capacity should be bounded, not growing unboundedly.
        // The pool should have reusable columns.
        let cap = buf.capacity();
        assert!(cap > 0);

        // Do one more cycle and verify capacity doesn't grow
        for i in 0..5 {
            buf.table("table_0")
                .unwrap()
                .symbol("sym", format!("sym-{i}"))
                .unwrap()
                .column_i64("x", i)
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        // Capacity should be stable
        assert!(
            buf.capacity() <= cap * 2,
            "capacity should not grow unboundedly"
        );
    }

    #[test]
    fn qwp_sparse_wide_rows_planner_stays_bounded() {
        // Test with rows that have very different column sets
        let mut buf = QwpBuffer::new(127);

        // Row 1: columns a, b, c
        buf.table("wide")
            .unwrap()
            .column_i64("a", 1)
            .unwrap()
            .column_i64("b", 2)
            .unwrap()
            .column_i64("c", 3)
            .unwrap();
        buf.at_now().unwrap();

        // Row 2: columns d, e, f (completely different)
        buf.table("wide")
            .unwrap()
            .column_i64("d", 4)
            .unwrap()
            .column_i64("e", 5)
            .unwrap()
            .column_i64("f", 6)
            .unwrap();
        buf.at_now().unwrap();

        // Row 3: columns a, d (mix)
        buf.table("wide")
            .unwrap()
            .column_i64("a", 7)
            .unwrap()
            .column_i64("d", 8)
            .unwrap();
        buf.at_now().unwrap();

        // Should produce valid datagrams
        let datagrams = buf.encode_datagrams(1400).unwrap();
        assert_eq!(datagrams.len(), 1);

        // Verify estimated len matches actual
        let estimated = buf.len();
        let actual: usize = datagrams.iter().map(Vec::len).sum();
        assert_eq!(estimated, actual);
    }

    #[test]
    fn qwp_split_near_varint_boundary() {
        // Create rows that push symbol dictionary size across varint boundary (128 symbols)
        let mut buf = QwpBuffer::new(127);
        for i in 0..140 {
            buf.table("syms")
                .unwrap()
                .symbol("s", format!("v{i}"))
                .unwrap()
                .column_i64("x", i)
                .unwrap();
            buf.at_now().unwrap();
        }

        // Use a size that forces splits around the varint boundary
        let datagrams = buf.encode_datagrams(400).unwrap();
        assert!(datagrams.len() > 1);

        // Verify each datagram is valid (starts with QWP1 header)
        for d in &datagrams {
            assert_eq!(&d[0..4], b"QWP1");
            let payload_len = u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as usize;
            assert_eq!(payload_len, d.len() - QWP_MESSAGE_HEADER_SIZE);
        }

        // Verify total estimated len matches actual
        let estimated = buf.len();
        // The estimated len is for unsplit encoding, so it should match
        // a single-datagram encoding
        let unsplit: usize = buf
            .encode_datagrams(usize::MAX)
            .unwrap()
            .iter()
            .map(Vec::len)
            .sum();
        assert_eq!(estimated, unsplit);
    }

    /// Run with: `cargo test --features sync-sender-qwp-udp -- qwp_zero_alloc --ignored --test-threads=1`
    #[test]
    #[ignore = "requires single-threaded execution: --test-threads=1"]
    fn qwp_zero_alloc_steady_state_after_prewarm() {
        use crate::alloc_counter;

        // Prewarm: fill buffer and scratch, flush, clear
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        // Use fixed-length strings to avoid format! allocations in the hot loop
        let symbols = ["AAA", "BBB", "CCC", "DDD", "EEE"];
        let venues = ["tokyo", "london", "newyork", "paris", "berlin"];

        // Warmup cycle: ensure all vecs have grown to needed capacity
        for i in 0..5 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", symbols[i])
                .unwrap()
                .column_i64("qty", i as i64)
                .unwrap()
                .column_str("venue", venues[i])
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        // Second warmup to ensure planner pool is populated
        for i in 0..5 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", symbols[i])
                .unwrap()
                .column_i64("qty", i as i64)
                .unwrap()
                .column_str("venue", venues[i])
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        // Now measure steady-state allocations
        alloc_counter::start_counting();

        for _cycle in 0..5 {
            for i in 0..5 {
                buf.table("trades")
                    .unwrap()
                    .symbol("sym", symbols[i])
                    .unwrap()
                    .column_i64("qty", i as i64)
                    .unwrap()
                    .column_str("venue", venues[i])
                    .unwrap();
                buf.at_now().unwrap();
            }
            buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
                .unwrap();
            buf.clear();
        }

        let alloc_count = alloc_counter::stop_counting();
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations in steady state after prewarm, got {alloc_count}"
        );
    }

    /// Run with: `cargo test --features sync-sender-qwp-udp -- qwp_zero_alloc_multi_table --ignored --test-threads=1`
    #[test]
    #[ignore = "requires single-threaded execution: --test-threads=1"]
    fn qwp_zero_alloc_multi_table_steady_state_after_prewarm() {
        use crate::alloc_counter;

        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        let tables = ["trades", "quotes", "orders"];
        let symbols = ["AAA", "BBB", "CCC"];

        // Warmup cycle 1
        for (i, table) in tables.iter().enumerate() {
            buf.table(*table)
                .unwrap()
                .symbol("sym", symbols[i])
                .unwrap()
                .column_i64("x", i as i64)
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        // Warmup cycle 2 (ensures planner pool is populated)
        for (i, table) in tables.iter().enumerate() {
            buf.table(*table)
                .unwrap()
                .symbol("sym", symbols[i])
                .unwrap()
                .column_i64("x", i as i64)
                .unwrap();
            buf.at_now().unwrap();
        }
        buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
            .unwrap();
        buf.clear();

        alloc_counter::start_counting();

        for _cycle in 0..5 {
            for (i, table) in tables.iter().enumerate() {
                buf.table(*table)
                    .unwrap()
                    .symbol("sym", symbols[i])
                    .unwrap()
                    .column_i64("x", i as i64)
                    .unwrap();
                buf.at_now().unwrap();
            }
            buf.flush_to_socket(&mut scratch, 1400, &mut |_| Ok(()))
                .unwrap();
            buf.clear();
        }

        let alloc_count = alloc_counter::stop_counting();
        assert_eq!(
            alloc_count, 0,
            "Expected zero allocations in multi-table steady state, got {alloc_count}"
        );
    }

    #[test]
    fn qwp_flush_to_socket_matches_encode_datagrams_single_table() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        for i in 0..10 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", format!("SYM-{i}"))
                .unwrap()
                .column_i64("qty", i)
                .unwrap()
                .column_str("venue", format!("venue-{i}"))
                .unwrap();
            buf.at_now().unwrap();
        }

        let reference = buf.encode_datagrams(1400).unwrap();

        let mut socket_datagrams: Vec<Vec<u8>> = Vec::new();
        buf.flush_to_socket(&mut scratch, 1400, &mut |datagram| {
            socket_datagrams.push(datagram.to_vec());
            Ok(())
        })
        .unwrap();

        assert_eq!(reference, socket_datagrams);
    }

    #[test]
    fn qwp_flush_to_socket_matches_encode_datagrams_multi_table() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(1400);

        buf.table("trades")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_i64("qty", 4)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("quotes")
            .unwrap()
            .symbol("sym", "ETH-USD")
            .unwrap()
            .column_f64("px", 42.5)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("trades")
            .unwrap()
            .symbol("sym", "BTC-USD")
            .unwrap()
            .column_i64("qty", 9)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("orders")
            .unwrap()
            .column_str("id", "ord-123")
            .unwrap()
            .column_bool("filled", true)
            .unwrap();
        buf.at_now().unwrap();

        let reference = buf.encode_datagrams(1400).unwrap();

        let mut socket_datagrams: Vec<Vec<u8>> = Vec::new();
        buf.flush_to_socket(&mut scratch, 1400, &mut |datagram| {
            socket_datagrams.push(datagram.to_vec());
            Ok(())
        })
        .unwrap();

        assert_eq!(reference, socket_datagrams);
    }

    #[test]
    fn qwp_flush_to_socket_large_segment_falls_back_to_replay() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(200);

        // Add enough rows to a single table so the segment exceeds a small
        // max_datagram_size, forcing the slow path (datagram splitting).
        for i in 0..50 {
            buf.table("trades")
                .unwrap()
                .symbol("sym", format!("SYM-{i}"))
                .unwrap()
                .column_i64("qty", i)
                .unwrap();
            buf.at_now().unwrap();
        }

        let mut socket_datagrams: Vec<Vec<u8>> = Vec::new();
        buf.flush_to_socket(&mut scratch, 200, &mut |datagram| {
            socket_datagrams.push(datagram.to_vec());
            Ok(())
        })
        .unwrap();

        // Should have been split into multiple datagrams
        assert!(
            socket_datagrams.len() > 1,
            "expected multiple datagrams, got {}",
            socket_datagrams.len()
        );

        // Each datagram should be valid
        for d in &socket_datagrams {
            assert_eq!(&d[0..4], b"QWP1");
            let payload_len = u32::from_le_bytes([d[8], d[9], d[10], d[11]]) as usize;
            assert_eq!(payload_len, d.len() - QWP_MESSAGE_HEADER_SIZE);
            assert!(d.len() <= 200, "datagram {} > 200", d.len());
        }

        // Compare against encode_datagrams (the replay oracle)
        let reference = buf.encode_datagrams(200).unwrap();
        assert_eq!(reference, socket_datagrams);
    }

    #[test]
    fn qwp_flush_to_socket_mixed_fast_and_slow_paths() {
        let mut buf = QwpBuffer::new(127);
        let mut scratch = QwpSendScratch::new(300);

        // First segment: small (fast path)
        buf.table("meta").unwrap().column_i64("ver", 1).unwrap();
        buf.at_now().unwrap();

        // Second segment: large enough to need splitting (slow path)
        for i in 0..40 {
            buf.table("data")
                .unwrap()
                .symbol("key", format!("k-{i}"))
                .unwrap()
                .column_i64("val", i)
                .unwrap();
            buf.at_now().unwrap();
        }

        // Third segment: small again (fast path)
        buf.table("footer")
            .unwrap()
            .column_bool("done", true)
            .unwrap();
        buf.at_now().unwrap();

        let reference = buf.encode_datagrams(300).unwrap();

        let mut socket_datagrams: Vec<Vec<u8>> = Vec::new();
        buf.flush_to_socket(&mut scratch, 300, &mut |datagram| {
            socket_datagrams.push(datagram.to_vec());
            Ok(())
        })
        .unwrap();

        assert_eq!(reference, socket_datagrams);
    }

    fn first_table(decoded: &DecodedDatagram) -> &crate::tests::qwp_decode::DecodedTable {
        &decoded.table
    }

    #[test]
    fn qwp_column_i8_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        for v in [i8::MIN, -1, 0, 1, i8::MAX] {
            buf.table("metrics").unwrap().column_i8("v", v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        assert_eq!(datagrams.len(), 1);
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = first_table(&decoded);
        assert_eq!(table.columns[0].type_code, QWP_TYPE_BYTE);
        assert!(!table.columns[0].nullable);
        let got: Vec<_> = table.rows.iter().map(|row| row[0].clone()).collect();
        assert_eq!(
            got,
            vec![
                DecodedValue::I8(i8::MIN),
                DecodedValue::I8(-1),
                DecodedValue::I8(0),
                DecodedValue::I8(1),
                DecodedValue::I8(i8::MAX),
            ]
        );
    }

    #[test]
    fn qwp_column_i16_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        for v in [i16::MIN, -1, 0, 1, i16::MAX] {
            buf.table("metrics").unwrap().column_i16("v", v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        assert_eq!(datagrams.len(), 1);
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = first_table(&decoded);
        assert_eq!(table.columns[0].type_code, QWP_TYPE_SHORT);
        assert!(!table.columns[0].nullable);
        let got: Vec<_> = table.rows.iter().map(|row| row[0].clone()).collect();
        assert_eq!(
            got,
            vec![
                DecodedValue::I16(i16::MIN),
                DecodedValue::I16(-1),
                DecodedValue::I16(0),
                DecodedValue::I16(1),
                DecodedValue::I16(i16::MAX),
            ]
        );
    }

    #[test]
    fn qwp_column_i32_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        for v in [i32::MIN, -1, 0, 1, i32::MAX] {
            buf.table("metrics").unwrap().column_i32("v", v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        assert_eq!(datagrams.len(), 1);
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = first_table(&decoded);
        assert_eq!(table.columns[0].type_code, QWP_TYPE_INT);
        assert!(!table.columns[0].nullable);
        let got: Vec<_> = table.rows.iter().map(|row| row[0].clone()).collect();
        assert_eq!(
            got,
            vec![
                DecodedValue::I32(i32::MIN),
                DecodedValue::I32(-1),
                DecodedValue::I32(0),
                DecodedValue::I32(1),
                DecodedValue::I32(i32::MAX),
            ]
        );
    }

    #[test]
    fn qwp_narrow_int_sentinel_fills_missing_rows() {
        let mut buf = QwpBuffer::new(127);

        buf.table("metrics")
            .unwrap()
            .column_i8("b", 7)
            .unwrap()
            .column_i16("s", 1234)
            .unwrap()
            .column_i32("i", 99_999)
            .unwrap()
            .column_bool("flag", true)
            .unwrap();
        buf.at_now().unwrap();

        buf.table("metrics")
            .unwrap()
            .column_bool("flag", false)
            .unwrap();
        buf.at_now().unwrap();

        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = first_table(&decoded);
        let by_name: std::collections::HashMap<_, _> = table
            .columns
            .iter()
            .enumerate()
            .map(|(idx, col)| (col.name.as_str(), idx))
            .collect();
        for col in &table.columns {
            assert!(
                !col.nullable,
                "narrow int / bool columns must use sentinel mode, not bitmap (column {})",
                col.name
            );
        }
        let b_idx = by_name["b"];
        let s_idx = by_name["s"];
        let i_idx = by_name["i"];
        // BYTE/SHORT sentinel = 0 per spec §11.1; INT sentinel = i32::MIN
        // so the server's Integer.MIN_VALUE null convention round-trips a
        // missing row as null rather than as the value 0.
        assert_eq!(table.rows[1][b_idx], DecodedValue::I8(0));
        assert_eq!(table.rows[1][s_idx], DecodedValue::I16(0));
        assert_eq!(table.rows[1][i_idx], DecodedValue::I32(i32::MIN));
    }

    #[test]
    fn qwp_narrow_int_method_pins_wire_type_regardless_of_value() {
        let mut buf = QwpBuffer::new(127);
        buf.table("metrics")
            .unwrap()
            .column_i8("b", 0)
            .unwrap()
            .column_i16("s", 0)
            .unwrap()
            .column_i32("i", 0)
            .unwrap()
            .column_i64("l", 0)
            .unwrap();
        buf.at_now().unwrap();

        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = first_table(&decoded);
        let codes: Vec<u8> = table.columns.iter().map(|c| c.type_code).collect();
        assert_eq!(
            codes,
            vec![QWP_TYPE_BYTE, QWP_TYPE_SHORT, QWP_TYPE_INT, QWP_TYPE_LONG]
        );
    }

    #[test]
    fn qwp_column_dec64_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        for v in ["0.00", "1.25", "-1.25", "92233720368547.75"] {
            buf.table("trades")
                .unwrap()
                .column_dec64("price", v)
                .unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        assert_eq!(datagrams.len(), 1);
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = first_table(&decoded);
        assert_eq!(table.columns[0].type_code, QWP_TYPE_DECIMAL64);
        let strs: Vec<String> = table
            .rows
            .iter()
            .map(|row| match &row[0] {
                DecodedValue::Decimal { scale, unscaled_be } => {
                    decimal_to_string(*scale, unscaled_be)
                }
                other => panic!("unexpected value {:?}", other),
            })
            .collect();
        assert_eq!(strs, vec!["0.00", "1.25", "-1.25", "92233720368547.75"]);
    }

    #[test]
    fn qwp_column_dec128_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        for v in [
            "0",
            "170141183460469231731687303715884105727",
            "-170141183460469231731687303715884105728",
        ] {
            buf.table("trades")
                .unwrap()
                .column_dec128("amt", v)
                .unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = first_table(&decoded);
        assert_eq!(table.columns[0].type_code, QWP_TYPE_DECIMAL128);
        let strs: Vec<String> = table
            .rows
            .iter()
            .map(|row| match &row[0] {
                DecodedValue::Decimal { scale, unscaled_be } => {
                    decimal_to_string(*scale, unscaled_be)
                }
                other => panic!("unexpected value {:?}", other),
            })
            .collect();
        assert_eq!(
            strs,
            vec![
                "0".to_string(),
                "170141183460469231731687303715884105727".to_string(),
                "-170141183460469231731687303715884105728".to_string(),
            ]
        );
    }

    #[test]
    fn qwp_column_dec64_rejects_overflow_at_call_site() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades").unwrap();
        let err = buf
            .column_dec64("v", "9223372036854775808")
            .expect_err("call should fail for value > i64::MAX");
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(
            err.msg().contains("DECIMAL64"),
            "error should name DECIMAL64: {}",
            err.msg()
        );
    }

    #[test]
    fn qwp_column_dec128_rejects_overflow_at_call_site() {
        let mut buf = QwpBuffer::new(127);
        buf.table("trades").unwrap();
        let err = buf
            .column_dec128("v", "170141183460469231731687303715884105728")
            .expect_err("call should fail for value > i128::MAX");
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("DECIMAL128"), "{}", err.msg());
    }

    #[test]
    fn qwp_column_dec64_upscales_subsequent_lossless() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t").unwrap().column_dec64("v", "1.25").unwrap();
        buf.at_now().unwrap();
        buf.table("t").unwrap().column_dec64("v", "1.1").unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_DECIMAL64);
        let strs: Vec<String> = table
            .rows
            .iter()
            .map(|row| match &row[0] {
                DecodedValue::Decimal { scale, unscaled_be } => {
                    decimal_to_string(*scale, unscaled_be)
                }
                other => panic!("unexpected value {:?}", other),
            })
            .collect();
        assert_eq!(strs, vec!["1.25".to_string(), "1.10".to_string()]);
    }

    #[test]
    fn qwp_column_dec64_downscale_precision_loss_rejects() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t").unwrap().column_dec64("v", "1.25").unwrap();
        buf.at_now().unwrap();
        buf.table("t").unwrap().column_dec64("v", "1.234").unwrap();
        buf.at_now().unwrap();
        let err = buf
            .encode_datagrams(64 * 1024)
            .expect_err("downscale must error on precision loss");
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("precision loss"), "{}", err.msg());
    }

    #[test]
    fn qwp_column_dec128_upscales_subsequent_lossless() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t").unwrap().column_dec128("v", "1.25").unwrap();
        buf.at_now().unwrap();
        buf.table("t").unwrap().column_dec128("v", "1.1").unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let strs: Vec<String> = decoded
            .table
            .rows
            .iter()
            .map(|row| match &row[0] {
                DecodedValue::Decimal { scale, unscaled_be } => {
                    decimal_to_string(*scale, unscaled_be)
                }
                other => panic!("unexpected value {:?}", other),
            })
            .collect();
        assert_eq!(strs, vec!["1.25".to_string(), "1.10".to_string()]);
    }

    #[test]
    fn qwp_column_dec_upscales_subsequent_lossless() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t").unwrap().column_dec("v", "1.25").unwrap();
        buf.at_now().unwrap();
        buf.table("t").unwrap().column_dec("v", "1.1").unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let strs: Vec<String> = decoded
            .table
            .rows
            .iter()
            .map(|row| match &row[0] {
                DecodedValue::Decimal { scale, unscaled_be } => {
                    decimal_to_string(*scale, unscaled_be)
                }
                other => panic!("unexpected value {:?}", other),
            })
            .collect();
        assert_eq!(strs, vec!["1.25".to_string(), "1.10".to_string()]);
    }

    #[test]
    fn qwp_column_uuid_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let cases: &[(u64, u64)] = &[
            (0, 0),
            (1, 0),
            (0, 1),
            (0xDEAD_BEEF_DEAD_BEEFu64, 0xCAFE_BABE_CAFE_BABEu64),
            (u64::MAX, u64::MAX),
        ];
        for (lo, hi) in cases {
            buf.table("trades")
                .unwrap()
                .column_uuid("id", *lo, *hi)
                .unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_UUID);
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        let expected: Vec<_> = cases
            .iter()
            .map(|&(lo, hi)| DecodedValue::Uuid { lo, hi })
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn qwp_column_long256_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let v0 = [0u8; 32];
        let mut v1 = [0u8; 32];
        for (i, b) in v1.iter_mut().enumerate() {
            *b = i as u8;
        }
        let v2 = [0xFFu8; 32];
        for v in [&v0, &v1, &v2] {
            buf.table("hashes").unwrap().column_long256("h", v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_LONG256);
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        assert_eq!(
            got,
            vec![
                DecodedValue::Long256(v0),
                DecodedValue::Long256(v1),
                DecodedValue::Long256(v2),
            ]
        );
    }

    #[test]
    fn qwp_column_ipv4_roundtrip() {
        use std::net::Ipv4Addr;
        let mut buf = QwpBuffer::new(127);
        let cases: &[Ipv4Addr] = &[
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 2),
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(255, 255, 255, 255),
        ];
        for v in cases {
            buf.table("conns")
                .unwrap()
                .column_ipv4("src", u32::from(*v))
                .unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_IPV4);
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        let expected: Vec<_> = cases
            .iter()
            .map(|&v| DecodedValue::Ipv4(u32::from(v)))
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn qwp_uuid_long256_ipv4_use_bitmap_for_missing_rows() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t")
            .unwrap()
            .column_uuid("u", 1, 2)
            .unwrap()
            .column_long256("l", &[7u8; 32])
            .unwrap()
            .column_ipv4("ip", 0x0100007Fu32)
            .unwrap();
        buf.at_now().unwrap();
        buf.table("t")
            .unwrap()
            .column_ipv4("ip", 0x0200007Fu32)
            .unwrap();
        buf.at_now().unwrap();

        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        let by_name: std::collections::HashMap<_, _> = table
            .columns
            .iter()
            .enumerate()
            .map(|(i, c)| (c.name.as_str(), i))
            .collect();
        assert!(table.columns[by_name["u"]].nullable);
        assert!(table.columns[by_name["l"]].nullable);
        assert_eq!(table.rows[1][by_name["u"]], DecodedValue::Null);
        assert_eq!(table.rows[1][by_name["l"]], DecodedValue::Null);
        assert_eq!(
            table.rows[1][by_name["ip"]],
            DecodedValue::Ipv4(0x0200007Fu32)
        );
    }

    #[test]
    fn qwp_column_date_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let cases: &[i64] = &[0, 1, -1, i64::MIN, i64::MAX, 1_700_000_000_000];
        for v in cases {
            buf.table("t").unwrap().column_date("d", *v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_DATE);
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        let expected: Vec<_> = cases.iter().map(|&v| DecodedValue::DateMillis(v)).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn qwp_column_char_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let cases: &[u16] = &[0x0041, 0x4E2D, 0xFFFF, 0x0001];
        for v in cases {
            buf.table("t").unwrap().column_char("c", *v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_CHAR);
        assert!(!table.columns[0].nullable);
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        let expected: Vec<_> = cases.iter().map(|&v| DecodedValue::Char(v)).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn qwp_column_binary_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let v0: &[u8] = b"";
        let v1: &[u8] = &[0xFF, 0xFE, 0xFD, 0x00, 0x01];
        let v2: &[u8] = &[0xAB; 64];
        for v in [v0, v1, v2] {
            buf.table("t").unwrap().column_binary("b", v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_BINARY);
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        assert_eq!(
            got,
            vec![
                DecodedValue::Binary(v0.to_vec()),
                DecodedValue::Binary(v1.to_vec()),
                DecodedValue::Binary(v2.to_vec()),
            ]
        );
    }

    #[test]
    fn qwp_column_geohash_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let precision_bits: u8 = 25;
        let mask = (1u64 << precision_bits) - 1;
        let cases: &[u64] = &[0, 0x1F, 0xABCDE, mask];
        for bits in cases {
            buf.table("t")
                .unwrap()
                .column_geohash("g", *bits, precision_bits)
                .unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_GEOHASH);
        let bytes_per_value = (precision_bits as usize).div_ceil(8);
        let byte_mask = if bytes_per_value == 8 {
            u64::MAX
        } else {
            (1u64 << (bytes_per_value * 8)) - 1
        };
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        let expected: Vec<_> = cases
            .iter()
            .map(|&bits| DecodedValue::Geohash {
                bits: bits & byte_mask,
                precision_bits,
            })
            .collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn qwp_column_geohash_precision_mismatch_rejects() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t").unwrap().column_geohash("g", 7, 5).unwrap();
        buf.at_now().unwrap();
        buf.table("t").unwrap().column_geohash("g", 7, 6).unwrap();
        let err = buf
            .at_now()
            .expect_err("row commit must reject precision mismatch");
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("GEOHASH"), "{}", err.msg());
    }

    #[test]
    fn qwp_column_geohash_precision_out_of_range_rejects() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t").unwrap();
        let err = buf
            .column_geohash("g", 0, 0)
            .expect_err("precision 0 must fail");
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        let err = buf
            .column_geohash("g", 0, 61)
            .expect_err("precision 61 must fail");
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
    }

    #[test]
    fn qwp_column_long_array_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let a1: Vec<i64> = vec![1, 2, 3, -1, -2];
        let a2: Vec<i64> = vec![i64::MAX, i64::MIN, 0];
        for v in [&a1, &a2] {
            buf.table("t").unwrap().column_arr("arr", v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_LONG_ARRAY);
        let got: Vec<_> = table.rows.iter().map(|r| r[0].clone()).collect();
        assert_eq!(
            got,
            vec![
                DecodedValue::I64Array {
                    shape: vec![a1.len()],
                    values: a1,
                },
                DecodedValue::I64Array {
                    shape: vec![a2.len()],
                    values: a2,
                },
            ]
        );
    }

    #[test]
    fn qwp_column_long_array_ilp_buffer_rejects() {
        use crate::ingress::ProtocolVersion;
        use crate::ingress::buffer::Buffer;
        let mut buf = Buffer::new(ProtocolVersion::V2);
        let arr: Vec<i64> = vec![1, 2, 3];
        let err = buf
            .table("t")
            .unwrap()
            .column_arr("arr", &arr)
            .expect_err("LONG_ARRAY on ILP must be rejected");
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
    }

    #[test]
    fn qwp_column_uuid_lo_first_then_hi_byte_order() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t")
            .unwrap()
            .column_uuid("id", 0x0102030405060708u64, 0x090A0B0C0D0E0F10u64)
            .unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_UUID);
        match table.rows[0][0] {
            DecodedValue::Uuid { lo, hi } => {
                assert_eq!(lo, 0x0102030405060708u64);
                assert_eq!(hi, 0x090A0B0C0D0E0F10u64);
            }
            ref other => panic!("expected UUID, got {:?}", other),
        }
    }

    #[test]
    fn qwp_column_long256_little_endian_byte_order() {
        let mut buf = QwpBuffer::new(127);
        let raw: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
            0x1D, 0x1E, 0x1F, 0x20,
        ];
        buf.table("t").unwrap().column_long256("v", &raw).unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_LONG256);
        match &table.rows[0][0] {
            DecodedValue::Long256(bytes) => assert_eq!(bytes.as_slice(), &raw),
            other => panic!("expected Long256, got {:?}", other),
        }
    }

    #[test]
    fn qwp_column_ipv4_big_endian_octet_order() {
        let mut buf = QwpBuffer::new(127);
        let addr: u32 = (192u32 << 24) | (168u32 << 16) | (1u32 << 8) | 42u32;
        buf.table("t").unwrap().column_ipv4("ip", addr).unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_IPV4);
        match table.rows[0][0] {
            DecodedValue::Ipv4(v) => assert_eq!(v, addr),
            ref other => panic!("expected Ipv4, got {:?}", other),
        }
    }

    #[test]
    fn qwp_column_date_millis_roundtrip_negative() {
        let mut buf = QwpBuffer::new(127);
        buf.table("t").unwrap().column_date("d", -1).unwrap();
        buf.at_now().unwrap();
        buf.table("t")
            .unwrap()
            .column_date("d", 1_700_000_000_000)
            .unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_DATE);
        match table.rows[0][0] {
            DecodedValue::DateMillis(v) => assert_eq!(v, -1),
            ref other => panic!("expected DateMillis, got {:?}", other),
        }
        match table.rows[1][0] {
            DecodedValue::DateMillis(v) => assert_eq!(v, 1_700_000_000_000),
            ref other => panic!("expected DateMillis, got {:?}", other),
        }
    }

    #[test]
    fn qwp_column_char_bmp_codepoint_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        for &v in &[b'A' as u16, 0xD7FFu16, 0xE000u16, 0xFFFDu16] {
            buf.table("t").unwrap().column_char("c", v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_CHAR);
        let got: Vec<u16> = table
            .rows
            .iter()
            .map(|r| match r[0] {
                DecodedValue::Char(v) => v,
                _ => panic!(),
            })
            .collect();
        assert_eq!(got, vec![b'A' as u16, 0xD7FFu16, 0xE000u16, 0xFFFDu16]);
    }

    #[test]
    fn qwp_column_binary_does_not_validate_utf8() {
        let mut buf = QwpBuffer::new(127);
        let non_utf8: &[u8] = &[0xFF, 0xFE, 0x00, 0x80, 0xC0];
        buf.table("t")
            .unwrap()
            .column_binary("b", non_utf8)
            .unwrap();
        buf.at_now().unwrap();
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        match &decoded.table.rows[0][0] {
            DecodedValue::Binary(bytes) => assert_eq!(bytes.as_slice(), non_utf8),
            other => panic!("expected Binary, got {:?}", other),
        }
    }

    #[test]
    fn qwp_column_f32_roundtrip() {
        let mut buf = QwpBuffer::new(127);
        let cases: &[f32] = &[0.0, 1.5, -1.5, f32::MIN, f32::MAX];
        for v in cases {
            buf.table("t").unwrap().column_f32("v", *v).unwrap();
            buf.at_now().unwrap();
        }
        let datagrams = buf.encode_datagrams(64 * 1024).unwrap();
        let decoded = decode_datagram(&datagrams[0]).unwrap();
        let table = &decoded.table;
        assert_eq!(table.columns[0].type_code, QWP_TYPE_FLOAT);
        assert!(!table.columns[0].nullable);
        let got: Vec<_> = table
            .rows
            .iter()
            .map(|r| match r[0] {
                DecodedValue::F32(v) => v,
                _ => panic!(),
            })
            .collect();
        for (g, e) in got.iter().zip(cases.iter()) {
            assert_eq!(g.to_bits(), e.to_bits());
        }
    }

    fn decimal_to_string(scale: u8, unscaled_be: &[u8]) -> String {
        let signed_value: i128 = {
            if unscaled_be.is_empty() {
                0
            } else {
                let mut buf = [0u8; 16];
                let sign_byte = if unscaled_be[0] & 0x80 != 0 {
                    0xFF
                } else {
                    0x00
                };
                assert!(
                    unscaled_be.len() <= 16,
                    "test helper supports magnitudes up to 16 bytes only"
                );
                buf.fill(sign_byte);
                buf[16 - unscaled_be.len()..].copy_from_slice(unscaled_be);
                i128::from_be_bytes(buf)
            }
        };
        if scale == 0 {
            return signed_value.to_string();
        }
        let negative = signed_value < 0;
        let abs = if negative {
            (0i128.wrapping_sub(signed_value)) as u128
        } else {
            signed_value as u128
        };
        let abs_str = abs.to_string();
        let scale = scale as usize;
        let (whole, frac) = if abs_str.len() > scale {
            let split = abs_str.len() - scale;
            (abs_str[..split].to_string(), abs_str[split..].to_string())
        } else {
            (
                "0".to_string(),
                format!("{:0>width$}", abs_str, width = scale),
            )
        };
        let sign = if negative { "-" } else { "" };
        format!("{sign}{whole}.{frac}")
    }
}
