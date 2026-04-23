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

use crate::Error;
#[cfg(test)]
use crate::ErrorCode;
use crate::error;
use crate::ingress::decimal::DecimalView;
use crate::ingress::ndarr::{self, ArrayElementSealed};
use crate::ingress::{ArrayElement, MAX_ARRAY_DIMS, NdArrayView, Timestamp};
use std::collections::hash_map::RandomState;
use std::fmt::Debug;
use std::hash::{BuildHasher, Hash, Hasher};

use super::ilp::{ColumnName, TableName};
use super::op_state::{Op, OpState};
use super::{Bookmark, BufferBookmarkMeta, StoredBookmark};

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
pub(crate) const QWP_TYPE_BOOLEAN: u8 = 0x01;
pub(crate) const QWP_TYPE_DOUBLE: u8 = 0x07;
pub(crate) const QWP_TYPE_LONG: u8 = 0x05;
// Match the newer Java QWP client/spec text column type.
pub(crate) const QWP_TYPE_VARCHAR: u8 = 0x0F;
pub(crate) const QWP_TYPE_SYMBOL: u8 = 0x09;
pub(crate) const QWP_TYPE_TIMESTAMP: u8 = 0x0A;
pub(crate) const QWP_TYPE_TIMESTAMP_NANOS: u8 = 0x10;
pub(crate) const QWP_TYPE_DOUBLE_ARRAY: u8 = 0x11;
pub(crate) const QWP_TYPE_DECIMAL256: u8 = 0x15;
pub(crate) const QWP_VERSION_1: u8 = 1;
const QWP_INLINE_SCHEMA_ID: u64 = 0;
const QWP_DECIMAL_MAX_SCALE: u8 = 76;
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
                "internal QWP decimal scale regression: target {} < value {}",
                target_scale,
                self.scale
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
enum ColumnKind {
    Bool,
    Symbol,
    I64,
    F64,
    String,
    Decimal,
    DoubleArray,
    TimestampMicros,
    TimestampNanos,
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
    I64(i64),
    F64(f64),
    TimestampMicros(i64),
    TimestampNanos(i64),
    Symbol(ValueSlice),
    String(ValueSlice),
    DecimalNull,
    Decimal(DecimalValue),
    DoubleArray(ValueSlice),
}

impl ValueRef {
    fn kind(&self) -> ColumnKind {
        match self {
            ValueRef::Bool(_) => ColumnKind::Bool,
            ValueRef::I64(_) => ColumnKind::I64,
            ValueRef::F64(_) => ColumnKind::F64,
            ValueRef::TimestampMicros(_) => ColumnKind::TimestampMicros,
            ValueRef::TimestampNanos(_) => ColumnKind::TimestampNanos,
            ValueRef::Symbol(_) => ColumnKind::Symbol,
            ValueRef::String(_) => ColumnKind::String,
            ValueRef::DecimalNull => ColumnKind::Decimal,
            ValueRef::Decimal(_) => ColumnKind::Decimal,
            ValueRef::DoubleArray(_) => ColumnKind::DoubleArray,
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

    fn append_value_f64_array<T, D>(&mut self, view: &T) -> crate::Result<ValueSlice>
    where
        T: NdArrayView<D>,
        D: ArrayElement + ArrayElementSealed,
    {
        if D::type_tag() != <f64 as ArrayElementSealed>::type_tag() {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/UDP currently supports only f64 arrays"
            ));
        }

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
        let value_vs = self.append_value_f64_array(view)?;
        self.push_entry(EntryMeta {
            name: name_ns,
            value: ValueRef::DoubleArray(value_vs),
        })?;
        self.state.op_state.record_column();
        Ok(self)
    }

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
                ValueRef::Bool(_) => 1,
                ValueRef::Symbol(vs) => vs.0.len as usize + 3,
                ValueRef::I64(_) | ValueRef::F64(_) => 8,
                ValueRef::String(vs) => vs.0.len as usize + 9,
                ValueRef::DecimalNull => 1,
                ValueRef::Decimal(_) => QWP_DECIMAL_MAG_BYTES + 4,
                ValueRef::DoubleArray(vs) => vs.0.len as usize + 5,
                ValueRef::TimestampMicros(_) | ValueRef::TimestampNanos(_) => 9,
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
            ColumnKind::I64 | ColumnKind::F64 => {
                checked_qwp_usize_mul(row_count, 8, "column data size")?
            }
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
            ColumnKind::String => {
                let offset_count =
                    checked_qwp_usize_add(non_null_count as usize, 1, "string offset count")?;
                let offsets = checked_qwp_usize_mul(offset_count, 4, "string offset table")?;
                checked_qwp_usize_add(offsets, variable_data_len, "string column size")?
            }
            ColumnKind::DoubleArray => variable_data_len,
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
            decimal_scale: 0,
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
            ColumnKind::Decimal => match value {
                ValueRef::DecimalNull => Ok(()),
                ValueRef::Decimal(decimal_value) => {
                    self.non_null_count = new_non_null_count;
                    self.decimal_scale = self.decimal_scale.max(decimal_value.scale);
                    Ok(())
                }
                _ => Err(error::fmt!(
                    InvalidApiCall,
                    "internal QWP type mismatch for decimal column"
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
                ColumnKind::I64 | ColumnKind::F64 => touched_fixed8_column_count += 1,
                ColumnKind::Symbol
                | ColumnKind::String
                | ColumnKind::Decimal
                | ColumnKind::DoubleArray
                | ColumnKind::TimestampMicros
                | ColumnKind::TimestampNanos => {
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
        debug_assert!(touched_fixed8_column_count <= old_fixed8_column_count);
        debug_assert!(touched_sparse_column_count <= old_sparse_column_count);
        debug_assert!(touched_old_active_bitmap_column_count <= old_active_bitmap_column_count);

        delta += (old_bool_column_count - touched_bool_column_count) * packed_delta;
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
            ColumnKind::I64 | ColumnKind::F64 => self.fixed8_column_count += 1,
            ColumnKind::Symbol
            | ColumnKind::String
            | ColumnKind::Decimal
            | ColumnKind::DoubleArray
            | ColumnKind::TimestampMicros
            | ColumnKind::TimestampNanos => self.sparse_column_count += 1,
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
            | ColumnKind::Decimal
            | ColumnKind::DoubleArray
            | ColumnKind::TimestampMicros
            | ColumnKind::TimestampNanos
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
        ColumnKind::Symbol => QWP_TYPE_SYMBOL,
        ColumnKind::I64 => QWP_TYPE_LONG,
        ColumnKind::F64 => QWP_TYPE_DOUBLE,
        ColumnKind::String => QWP_TYPE_VARCHAR,
        ColumnKind::Decimal => QWP_TYPE_DECIMAL256,
        ColumnKind::DoubleArray => QWP_TYPE_DOUBLE_ARRAY,
        ColumnKind::TimestampMicros => QWP_TYPE_TIMESTAMP,
        ColumnKind::TimestampNanos => QWP_TYPE_TIMESTAMP_NANOS,
    }
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
            out[offsets_start..offsets_start + 4].copy_from_slice(&0i32.to_le_bytes());

            let mut cumulative: i32 = 0;
            let mut offset_idx = 1usize;
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::String(vs) = cell.value {
                    let text = &value_bytes[vs.0.as_range()];
                    out.extend_from_slice(text);
                    cumulative += text.len() as i32;
                    let pos = offsets_start + offset_idx * 4;
                    out[pos..pos + 4].copy_from_slice(&cumulative.to_le_bytes());
                    offset_idx += 1;
                }
            }
        }

        ColumnKind::Decimal => {
            out.push(col.decimal_scale);
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

        ColumnKind::DoubleArray => {
            for cell in CellIter::new(cells, col.cell_head) {
                if let ValueRef::DoubleArray(vs) = cell.value {
                    out.extend_from_slice(&value_bytes[vs.0.as_range()]);
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

    fn prop_java_decimal_rejection_pair_strategy() -> BoxedStrategy<(String, String)> {
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
        fn qwp_prop_java_decimal_first_scale_contract(
            (first, later) in prop_java_decimal_rejection_pair_strategy(),
        ) {
            let mut buf = QwpBuffer::new(512);
            buf.table("trades")
                .unwrap()
                .column_dec("price", first.as_str())
                .unwrap()
                .at(TimestampMicros::new(1))
                .unwrap();

            let rust_result = (|| -> crate::Result<()> {
                buf.table("trades")?
                    .column_dec("price", later.as_str())?
                    .at(TimestampMicros::new(2))?;
                let _ = buf.encode_datagrams(usize::MAX)?;
                Ok(())
            })();

            prop_assert!(
                rust_result.is_err(),
                "Java QWP sender would reject decimal scale change from {:?} to {:?}, but Rust accepted it",
                first,
                later
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
            .column_dec("price", "1.2")
            .unwrap();
        buf.at_now().unwrap();
        assert_eq!(buf.value_bytes.len(), QWP_DECIMAL_MAG_BYTES);

        buf.set_marker().unwrap();
        buf.table("trades")
            .unwrap()
            .column_dec("price", "1.5e-3")
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
}
