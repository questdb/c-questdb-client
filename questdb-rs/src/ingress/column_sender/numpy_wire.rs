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

//! Numpy-side wire encoder. Walks a raw, contiguous, native-endian numpy
//! buffer described by [`NumpyDtype`] and writes the QWP column body
//! straight into the connection's outbound buffer.
//!
//! This module is intentionally **independent of arrow-rs**: it shares
//! the QWP wire-format constants with [`super::wire`] and the
//! [`ValidityDescriptor`] shape with [`super::chunk`], and nothing
//! else. The numpy entry point can build (and run at full coverage)
//! without the `arrow` Cargo feature.

use std::slice;

use crate::ingress::{MAX_ARRAY_DIMS, MAX_NDARRAY_LEAF_ELEMS};
use crate::{Result, error};

use super::chunk::ValidityDescriptor;
use super::wire::{
    F32_NULL, F64_NULL, I8_NULL, I16_NULL, I32_NULL, I64_NULL, QWP_TYPE_BOOLEAN, QWP_TYPE_BYTE,
    QWP_TYPE_CHAR, QWP_TYPE_DATE, QWP_TYPE_DECIMAL64, QWP_TYPE_DECIMAL128, QWP_TYPE_DECIMAL256,
    QWP_TYPE_DOUBLE, QWP_TYPE_DOUBLE_ARRAY, QWP_TYPE_FLOAT, QWP_TYPE_GEOHASH, QWP_TYPE_INT,
    QWP_TYPE_IPV4, QWP_TYPE_LONG, QWP_TYPE_LONG256, QWP_TYPE_SHORT, QWP_TYPE_TIMESTAMP,
    QWP_TYPE_TIMESTAMP_NANOS, QWP_TYPE_UUID,
};

/// Numpy source-dtype tag. The chunk's `NumpyDeferred` variant stores
/// one; the encoder walks it at flush.
///
/// Scale (decimal) and bit-width (geohash) values must be validated by
/// the caller (push_numpy_deferred / the FFI dispatcher) before being
/// embedded — emit code trusts them and does not re-check ranges.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NumpyDtype {
    // ---- Direct (zero-copy bulk emit) ----
    I64Direct,
    F64Direct,
    DateI64Direct,
    TimestampMicrosDirect,
    TimestampNanosDirect,
    LongDirect,
    UuidDirect,
    Long256Direct,
    Ipv4Direct,
    CharDirect,

    // ---- Direct narrow signed integers (sentinel-encoded; BYTE/SHORT
    // ----- use value 0 as the null sentinel) ----
    I8Direct,
    I16Direct,
    I32Direct,

    // ---- Signed widen to next-up signed wire to avoid sentinel
    // ----- collision with source value range ----
    I8WidenToI32,
    I16WidenToI32,
    I32WidenToI64,

    // ---- Unsigned widen to smallest signed wire that holds the source
    // ----- range WITHOUT colliding with the null sentinel ----
    U8WidenToI32,
    U16WidenToI32,
    U32WidenToI64,
    U64WidenToI64,

    // ---- f16 widen (no f16 wire type); f32 direct ----
    F32Direct,
    F16Widen,

    // ---- Other per-row conversions ----
    Bool,
    DatetimeSecToMicros,
    DatetimeMinuteToMicros,
    DatetimeHourToMicros,
    DatetimeDayToMicros,
    DatetimeWeekToMicros,
    DatetimeMonthToMicros,
    DatetimeYearToMicros,

    // ---- Decimal (scale carried) ----
    Decimal64 {
        scale: u8,
    },
    Decimal128 {
        scale: u8,
    },
    Decimal256 {
        scale: u8,
    },

    // ---- Geohash (bits carried) ----
    GeohashI8 {
        bits: u8,
    },
    GeohashI16 {
        bits: u8,
    },
    GeohashI32 {
        bits: u8,
    },
    GeohashI64 {
        bits: u8,
    },

    /// f64 ndarray: rectangular tensor of shape (row_count, dim[0], dim[1], …).
    /// `ndim` is `1..=MAX_ARRAY_DIMS`; only the first `ndim` entries of
    /// `shape` are meaningful — trailing entries are zero. All rows share
    /// this shape (numpy ndarrays are rectangular).
    F64Ndarray {
        ndim: u8,
        shape: [u32; MAX_ARRAY_DIMS],
    },
}

impl NumpyDtype {
    /// QWP wire-type byte for the column slot this dtype produces.
    pub fn wire_type(&self) -> u8 {
        use NumpyDtype as D;
        match self {
            D::I8Direct => QWP_TYPE_BYTE,
            D::I16Direct => QWP_TYPE_SHORT,
            D::I32Direct
            | D::I8WidenToI32
            | D::I16WidenToI32
            | D::U8WidenToI32
            | D::U16WidenToI32 => QWP_TYPE_INT,
            D::I64Direct
            | D::LongDirect
            | D::I32WidenToI64
            | D::U32WidenToI64
            | D::U64WidenToI64 => QWP_TYPE_LONG,
            D::F64Direct => QWP_TYPE_DOUBLE,
            D::F32Direct | D::F16Widen => QWP_TYPE_FLOAT,
            D::Bool => QWP_TYPE_BOOLEAN,
            D::DateI64Direct => QWP_TYPE_DATE,
            D::TimestampMicrosDirect
            | D::DatetimeSecToMicros
            | D::DatetimeMinuteToMicros
            | D::DatetimeHourToMicros
            | D::DatetimeDayToMicros
            | D::DatetimeWeekToMicros
            | D::DatetimeMonthToMicros
            | D::DatetimeYearToMicros => QWP_TYPE_TIMESTAMP,
            D::TimestampNanosDirect => QWP_TYPE_TIMESTAMP_NANOS,
            D::UuidDirect => QWP_TYPE_UUID,
            D::Long256Direct => QWP_TYPE_LONG256,
            D::Ipv4Direct => QWP_TYPE_IPV4,
            D::CharDirect => QWP_TYPE_CHAR,
            D::Decimal64 { .. } => QWP_TYPE_DECIMAL64,
            D::Decimal128 { .. } => QWP_TYPE_DECIMAL128,
            D::Decimal256 { .. } => QWP_TYPE_DECIMAL256,
            D::GeohashI8 { .. }
            | D::GeohashI16 { .. }
            | D::GeohashI32 { .. }
            | D::GeohashI64 { .. } => QWP_TYPE_GEOHASH,
            D::F64Ndarray { .. } => QWP_TYPE_DOUBLE_ARRAY,
        }
    }

    /// Per-row wire payload size for the upfront frame-size estimate.
    /// Bool is bit-packed so the true cost is `row_count.div_ceil(8)`;
    /// reporting 1 here keeps the estimate as a (correct) over-bound.
    /// The leading scale / bits byte for decimal / geohash is a fixed
    /// +1 per column and is rolled into the column's null-overhead
    /// allowance by the caller.
    pub fn bytes_per_row(&self) -> usize {
        use NumpyDtype as D;
        match self {
            D::Bool | D::I8Direct => 1,
            D::I16Direct | D::CharDirect => 2,
            D::I32Direct
            | D::I8WidenToI32
            | D::I16WidenToI32
            | D::U8WidenToI32
            | D::U16WidenToI32
            | D::F32Direct
            | D::F16Widen
            | D::Ipv4Direct => 4,
            D::I64Direct
            | D::F64Direct
            | D::LongDirect
            | D::DateI64Direct
            | D::TimestampMicrosDirect
            | D::TimestampNanosDirect
            | D::DatetimeSecToMicros
            | D::DatetimeMinuteToMicros
            | D::DatetimeHourToMicros
            | D::DatetimeDayToMicros
            | D::DatetimeWeekToMicros
            | D::DatetimeMonthToMicros
            | D::DatetimeYearToMicros
            | D::I32WidenToI64
            | D::U32WidenToI64
            | D::U64WidenToI64
            | D::Decimal64 { .. } => 8,
            D::UuidDirect | D::Decimal128 { .. } => 16,
            D::Long256Direct | D::Decimal256 { .. } => 32,
            D::GeohashI8 { .. } => 1,
            D::GeohashI16 { .. } => 2,
            D::GeohashI32 { .. } => 4,
            D::GeohashI64 { .. } => 8,
            D::F64Ndarray { ndim, shape } => {
                // Per-row: ndim u8 + (dim u32) × ndim + (value f64) × prod(dims).
                let nd = *ndim as usize;
                let mut leaf: usize = 1;
                for &d in &shape[..nd] {
                    leaf = leaf.saturating_mul(d as usize);
                }
                (1usize)
                    .saturating_add(4usize.saturating_mul(nd))
                    .saturating_add(8usize.saturating_mul(leaf))
            }
        }
    }

    /// Reject dtype configurations that the encoder cannot safely
    /// allocate for. Currently bounds `F64Ndarray`'s shape to
    /// `1..=MAX_ARRAY_DIMS` dimensions, non-zero per-dimension extents,
    /// and `prod(shape) <= MAX_NDARRAY_LEAF_ELEMS` to keep the per-row
    /// reservation well under `isize::MAX`. All other variants are
    /// inherently bounded by their wire-type encoding.
    pub fn validate(&self) -> Result<()> {
        if let NumpyDtype::F64Ndarray { ndim, shape } = self {
            let nd = *ndim as usize;
            if nd == 0 {
                return Err(error::fmt!(InvalidApiCall, "F64Ndarray ndim must be >= 1"));
            }
            if nd > MAX_ARRAY_DIMS {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "F64Ndarray ndim must be <= {} (MAX_ARRAY_DIMS), got {}",
                    MAX_ARRAY_DIMS,
                    nd
                ));
            }
            let mut leaf_count: usize = 1;
            for (i, &dim) in shape[..nd].iter().enumerate() {
                if dim == 0 {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "F64Ndarray shape[{}] must be >= 1, got 0",
                        i
                    ));
                }
                leaf_count = leaf_count.checked_mul(dim as usize).ok_or_else(|| {
                    error::fmt!(InvalidApiCall, "F64Ndarray shape product overflows usize")
                })?;
                if leaf_count > MAX_NDARRAY_LEAF_ELEMS {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "F64Ndarray shape product exceeds MAX_NDARRAY_LEAF_ELEMS ({}) at dim {}",
                        MAX_NDARRAY_LEAF_ELEMS,
                        i
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Encode one numpy column body straight into `out`.
///
/// # Safety
///
/// `data` must be either NULL with `row_count == 0`, or point to at
/// least `row_count * size_of(<source dtype>)` valid contiguous bytes
/// (one byte per row for `Bool`). `validity`, if present, must reference
/// a bitmap of at least `ceil(row_count / 8)` bytes; the caller is
/// responsible for keeping all referenced memory alive for the duration
/// of the call.
pub(crate) unsafe fn emit_into_wire(
    out: &mut Vec<u8>,
    dtype: NumpyDtype,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) -> Result<()> {
    use NumpyDtype as D;
    match dtype {
        // ---- Direct sentinel-encoded LE ----
        D::I64Direct | D::LongDirect => unsafe {
            emit_sentinel_le::<i64, 8>(
                out,
                data,
                row_count,
                validity,
                I64_NULL.to_le_bytes(),
                i64::to_le_bytes,
            )
        },
        D::F64Direct => unsafe {
            emit_sentinel_le::<f64, 8>(
                out,
                data,
                row_count,
                validity,
                F64_NULL.to_le_bytes(),
                f64::to_le_bytes,
            )
        },
        D::CharDirect => unsafe {
            emit_sentinel_le::<u16, 2>(out, data, row_count, validity, [0u8; 2], u16::to_le_bytes)
        },

        // ---- Direct bitmap-encoded LE ----
        D::DateI64Direct => unsafe {
            emit_bitmap_le::<i64, 8>(out, data, row_count, validity, i64::to_le_bytes)
        },
        D::TimestampMicrosDirect | D::TimestampNanosDirect => unsafe {
            emit_bitmap_le::<i64, 8>(out, data, row_count, validity, i64::to_le_bytes)
        },
        D::Ipv4Direct => unsafe {
            emit_bitmap_le::<u32, 4>(out, data, row_count, validity, u32::to_le_bytes)
        },
        D::UuidDirect => unsafe { emit_bitmap_fsb::<16>(out, data, row_count, validity) },
        D::Long256Direct => unsafe { emit_bitmap_fsb::<32>(out, data, row_count, validity) },

        // ---- Direct narrow signed integers (sentinel LE) ----
        D::I8Direct => unsafe {
            emit_sentinel_le::<i8, 1>(out, data, row_count, validity, [I8_NULL as u8], |v| {
                [v as u8]
            })
        },
        D::I16Direct => unsafe {
            emit_sentinel_le::<i16, 2>(
                out,
                data,
                row_count,
                validity,
                I16_NULL.to_le_bytes(),
                i16::to_le_bytes,
            )
        },
        D::I32Direct => unsafe {
            emit_sentinel_le::<i32, 4>(
                out,
                data,
                row_count,
                validity,
                I32_NULL.to_le_bytes(),
                i32::to_le_bytes,
            )
        },

        // ---- Signed widen (sentinel-safe; mirrors unsigned widen) ----
        D::I8WidenToI32 => unsafe {
            emit_widen_i32_sentinel::<i8>(out, data, row_count, validity, I32_NULL, |v| v as i32)
        },
        D::I16WidenToI32 => unsafe {
            emit_widen_i32_sentinel::<i16>(out, data, row_count, validity, I32_NULL, |v| v as i32)
        },
        D::I32WidenToI64 => unsafe {
            emit_widen_i64_sentinel::<i32>(out, data, row_count, validity, I64_NULL, |v| v as i64)
        },

        // ---- Unsigned widen to smallest signed wire that avoids the
        // ----- null-sentinel collision (BYTE/SHORT use value 0 as null).
        D::U8WidenToI32 => unsafe {
            emit_widen_i32_sentinel::<u8>(out, data, row_count, validity, I32_NULL, |v| v as i32)
        },
        D::U16WidenToI32 => unsafe {
            emit_widen_i32_sentinel::<u16>(out, data, row_count, validity, I32_NULL, |v| v as i32)
        },
        D::U32WidenToI64 => unsafe {
            emit_widen_i64_sentinel::<u32>(out, data, row_count, validity, I64_NULL, |v| v as i64)
        },
        D::U64WidenToI64 => unsafe { emit_u64_widen_i64_checked(out, data, row_count, validity)? },

        // ---- f32 sentinel FLOAT ----
        D::F32Direct => unsafe {
            emit_sentinel_le::<f32, 4>(
                out,
                data,
                row_count,
                validity,
                F32_NULL.to_le_bytes(),
                f32::to_le_bytes,
            )
        },

        // ---- f16 → f32 sentinel FLOAT ----
        D::F16Widen => unsafe { emit_f16_to_f32(out, data, row_count, validity) },

        // ---- Bool (byte-per-row → packed LSB-first bitmap) ----
        D::Bool => unsafe { emit_bool(out, data, row_count, validity) },

        // ---- datetime64[s/m/h/D] → ×K → TIMESTAMP (bitmap) ----
        D::DatetimeSecToMicros => unsafe {
            emit_i64_to_micros(out, data, row_count, validity, "s", |v| {
                v.checked_mul(1_000_000)
            })?
        },
        D::DatetimeMinuteToMicros => unsafe {
            emit_i64_to_micros(out, data, row_count, validity, "m", |v| {
                v.checked_mul(60_000_000)
            })?
        },
        D::DatetimeHourToMicros => unsafe {
            emit_i64_to_micros(out, data, row_count, validity, "h", |v| {
                v.checked_mul(3_600_000_000)
            })?
        },
        D::DatetimeDayToMicros => unsafe {
            emit_i64_to_micros(out, data, row_count, validity, "D", |v| {
                v.checked_mul(86_400_000_000)
            })?
        },
        D::DatetimeWeekToMicros => unsafe {
            emit_i64_to_micros(out, data, row_count, validity, "W", |v| {
                v.checked_mul(604_800_000_000)
            })?
        },
        // ---- datetime64[M/Y] → calendar → TIMESTAMP (bitmap) ----
        // `days_from_civil` is comparatively expensive (a few divisions);
        // most numpy datetime arrays are sorted or near-sorted, so a
        // single-slot last-value cache absorbs the bulk of repeated
        // (year, month) inputs without affecting random-data correctness.
        D::DatetimeMonthToMicros => unsafe {
            let mut last: Option<(i64, i64)> = None;
            emit_i64_to_micros(out, data, row_count, validity, "M", |v| {
                if let Some((k, r)) = last
                    && k == v
                {
                    return Some(r);
                }
                let r = month_offset_to_micros(v)?;
                last = Some((v, r));
                Some(r)
            })?
        },
        D::DatetimeYearToMicros => unsafe {
            let mut last: Option<(i64, i64)> = None;
            emit_i64_to_micros(out, data, row_count, validity, "Y", |v| {
                if let Some((k, r)) = last
                    && k == v
                {
                    return Some(r);
                }
                let r = year_offset_to_micros(v)?;
                last = Some((v, r));
                Some(r)
            })?
        },

        // ---- Decimal (scale byte + bitmap-encoded fixed-width) ----
        D::Decimal64 { scale } => unsafe {
            emit_decimal::<8>(out, scale, data, row_count, validity)
        },
        D::Decimal128 { scale } => unsafe {
            emit_decimal::<16>(out, scale, data, row_count, validity)
        },
        D::Decimal256 { scale } => unsafe {
            emit_decimal::<32>(out, scale, data, row_count, validity)
        },

        // ---- Geohash (bits byte + bitmap-encoded width-N rows) ----
        D::GeohashI8 { bits } => unsafe {
            emit_geohash::<1>(out, bits, data, row_count, validity)?
        },
        D::GeohashI16 { bits } => unsafe {
            emit_geohash::<2>(out, bits, data, row_count, validity)?
        },
        D::GeohashI32 { bits } => unsafe {
            emit_geohash::<4>(out, bits, data, row_count, validity)?
        },
        D::GeohashI64 { bits } => unsafe {
            emit_geohash::<8>(out, bits, data, row_count, validity)?
        },

        // ---- f64 ndarray (DOUBLE_ARRAY, bitmap-encoded nulls) ----
        D::F64Ndarray { ndim, shape } => unsafe {
            emit_f64_ndarray(out, ndim, shape, data, row_count, validity)?
        },
    }
    Ok(())
}

// ===========================================================================
// Shared primitives
// ===========================================================================

/// Sentinel-encoded wire format: `null_flag = 0` + dense `N`-byte rows
/// (null rows write `sentinel`).
#[inline]
unsafe fn emit_sentinel_le<T, const N: usize>(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    sentinel: [u8; N],
    to_le: impl Fn(T) -> [u8; N],
) where
    T: Copy,
{
    out.push(0);
    out.reserve(N * row_count);
    let typed = data as *const T;
    match validity {
        None => {
            if row_count > 0 {
                let bytes = unsafe { slice::from_raw_parts(data, row_count * N) };
                out.extend_from_slice(bytes);
            }
        }
        Some(v) => {
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let value = unsafe { *typed.add(i) };
                    out.extend_from_slice(&to_le(value));
                } else {
                    out.extend_from_slice(&sentinel);
                }
            }
        }
    }
}

/// Bitmap-encoded wire format: `null_flag` (0 or 1) + optional bitmap +
/// dense `N`-byte rows (non-null only when bitmap present, all rows
/// otherwise).
#[inline]
unsafe fn emit_bitmap_le<T, const N: usize>(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    to_le: impl Fn(T) -> [u8; N],
) where
    T: Copy,
{
    let typed = data as *const T;
    match validity {
        None => {
            out.push(0);
            out.reserve(N * row_count);
            if row_count > 0 {
                let bytes = unsafe { slice::from_raw_parts(data, row_count * N) };
                out.extend_from_slice(bytes);
            }
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            out.reserve(N * v.non_null_count);
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let value = unsafe { *typed.add(i) };
                    out.extend_from_slice(&to_le(value));
                }
            }
        }
    }
}

/// Bitmap-encoded fixed-size-binary rows (no per-element conversion).
#[inline]
unsafe fn emit_bitmap_fsb<const N: usize>(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    match validity {
        None => {
            out.push(0);
            out.reserve(N * row_count);
            if row_count > 0 {
                let bytes = unsafe { slice::from_raw_parts(data, N * row_count) };
                out.extend_from_slice(bytes);
            }
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

/// Widen each source value through `widen` (monomorphised per source
/// dtype), then emit as a sentinel-encoded LE i32 column.
#[inline]
unsafe fn emit_widen_i32_sentinel<T>(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    sentinel: i32,
    widen: impl Fn(T) -> i32,
) where
    T: Copy,
{
    out.push(0);
    out.reserve(4 * row_count);
    let typed = data as *const T;
    let sentinel_bytes = sentinel.to_le_bytes();
    match validity {
        None => {
            for i in 0..row_count {
                let v = unsafe { *typed.add(i) };
                out.extend_from_slice(&widen(v).to_le_bytes());
            }
        }
        Some(v) => {
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let raw = unsafe { *typed.add(i) };
                    out.extend_from_slice(&widen(raw).to_le_bytes());
                } else {
                    out.extend_from_slice(&sentinel_bytes);
                }
            }
        }
    }
}

/// Widen each source value through `widen` (monomorphised per source
/// dtype), then emit as a sentinel-encoded LE i64 column.
#[inline]
unsafe fn emit_widen_i64_sentinel<T>(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    sentinel: i64,
    widen: impl Fn(T) -> i64,
) where
    T: Copy,
{
    out.push(0);
    out.reserve(8 * row_count);
    let typed = data as *const T;
    let sentinel_bytes = sentinel.to_le_bytes();
    match validity {
        None => {
            for i in 0..row_count {
                let v = unsafe { *typed.add(i) };
                out.extend_from_slice(&widen(v).to_le_bytes());
            }
        }
        Some(v) => {
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let raw = unsafe { *typed.add(i) };
                    out.extend_from_slice(&widen(raw).to_le_bytes());
                } else {
                    out.extend_from_slice(&sentinel_bytes);
                }
            }
        }
    }
}

#[inline]
fn u64_to_i64_checked(v: u64, row: usize) -> Result<i64> {
    if v > i64::MAX as u64 {
        return Err(error::fmt!(
            InvalidApiCall,
            "u64 value {} at row {} does not fit QuestDB LONG (max i64::MAX)",
            v,
            row
        ));
    }
    Ok(v as i64)
}

unsafe fn emit_u64_widen_i64_checked(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) -> Result<()> {
    let typed = data as *const u64;
    if validity.is_none() && row_count > 0 {
        let slice = unsafe { slice::from_raw_parts(typed, row_count) };
        let mut acc: u64 = 0;
        for &v in slice {
            acc |= v;
        }
        if acc < (1u64 << 63) {
            unsafe {
                emit_widen_i64_sentinel::<u64>(out, data, row_count, validity, I64_NULL, |v| {
                    v as i64
                })
            };
            return Ok(());
        }
    }
    out.push(0);
    out.reserve(8 * row_count);
    let sentinel_bytes = I64_NULL.to_le_bytes();
    match validity {
        None => {
            for i in 0..row_count {
                let v = unsafe { *typed.add(i) };
                out.extend_from_slice(&u64_to_i64_checked(v, i)?.to_le_bytes());
            }
        }
        Some(v) => {
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let raw = unsafe { *typed.add(i) };
                    out.extend_from_slice(&u64_to_i64_checked(raw, i)?.to_le_bytes());
                } else {
                    out.extend_from_slice(&sentinel_bytes);
                }
            }
        }
    }
    Ok(())
}

/// f16 → f32 (sentinel FLOAT). Implements the IEEE-754 half-precision
/// → single-precision expansion inline so the module has no `half` /
/// `arrow_buffer` dependency. Preserves bit-patterns (signaling NaN
/// bits may differ between platforms; this matches what `half::f16::to_f32`
/// would emit on x86/aarch64).
unsafe fn emit_f16_to_f32(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    out.push(0);
    out.reserve(4 * row_count);
    let typed = data as *const u16;
    let sentinel = F32_NULL.to_le_bytes();
    match validity {
        None => {
            for i in 0..row_count {
                let bits = unsafe { *typed.add(i) };
                out.extend_from_slice(&f16_bits_to_f32(bits).to_le_bytes());
            }
        }
        Some(v) => {
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let bits = unsafe { *typed.add(i) };
                    out.extend_from_slice(&f16_bits_to_f32(bits).to_le_bytes());
                } else {
                    out.extend_from_slice(&sentinel);
                }
            }
        }
    }
}

/// IEEE-754 binary16 → binary32. Branchless on the common non-special
/// path; subnormals and NaN/Inf get a per-case fixup. Reproduces the
/// algorithm `half::f16::to_f32_const` uses.
#[inline]
fn f16_bits_to_f32(bits: u16) -> f32 {
    let sign = ((bits >> 15) as u32) << 31;
    let exp = ((bits >> 10) & 0x1F) as u32;
    let mant = (bits & 0x3FF) as u32;
    let f32_bits = match exp {
        0 => {
            if mant == 0 {
                // +/- zero
                sign
            } else {
                // Subnormal: normalise by shifting until the leading
                // bit is in position 10, then bias-adjust.
                let mut m = mant;
                let mut e: i32 = -14;
                while (m & 0x400) == 0 {
                    m <<= 1;
                    e -= 1;
                }
                m &= 0x3FF;
                let exp_f32 = ((e + 127) as u32) << 23;
                sign | exp_f32 | (m << 13)
            }
        }
        31 => {
            // Inf / NaN: f32 exponent all-ones; preserve mantissa.
            sign | (0xFFu32 << 23) | (mant << 13)
        }
        _ => {
            let exp_f32 = (exp + (127 - 15)) << 23;
            sign | exp_f32 | (mant << 13)
        }
    };
    f32::from_bits(f32_bits)
}

/// Bool: numpy byte-per-row (0 == false, non-zero == true) → packed
/// LSB-first bitmap → BOOLEAN.
unsafe fn emit_bool(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    out.push(0);
    let bitmap_bytes = row_count.div_ceil(8);
    out.reserve(bitmap_bytes);
    if validity.is_none() {
        let full_chunks = row_count / 8;
        let tail = row_count % 8;
        for chunk_idx in 0..full_chunks {
            let base = chunk_idx * 8;
            let src = unsafe { data.add(base) };
            let b0 = unsafe { *src };
            let b1 = unsafe { *src.add(1) };
            let b2 = unsafe { *src.add(2) };
            let b3 = unsafe { *src.add(3) };
            let b4 = unsafe { *src.add(4) };
            let b5 = unsafe { *src.add(5) };
            let b6 = unsafe { *src.add(6) };
            let b7 = unsafe { *src.add(7) };
            let packed = u8::from(b0 != 0)
                | (u8::from(b1 != 0) << 1)
                | (u8::from(b2 != 0) << 2)
                | (u8::from(b3 != 0) << 3)
                | (u8::from(b4 != 0) << 4)
                | (u8::from(b5 != 0) << 5)
                | (u8::from(b6 != 0) << 6)
                | (u8::from(b7 != 0) << 7);
            out.push(packed);
        }
        if tail != 0 {
            let base = full_chunks * 8;
            let mut packed = 0u8;
            for i in 0..tail {
                let b = unsafe { *data.add(base + i) };
                if b != 0 {
                    packed |= 1u8 << i;
                }
            }
            out.push(packed);
        }
        return;
    }
    let v = validity.unwrap();
    let mut packed = 0u8;
    let mut bit_idx = 0u8;
    for i in 0..row_count {
        let raw = unsafe { *data.add(i) };
        if unsafe { v.is_valid(i) } && raw != 0 {
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

/// datetime64[unit] → TIMESTAMP (microseconds, bitmap-encoded). The
/// `convert` closure maps one source `i64` to a microsecond `i64`,
/// returning `None` on overflow / out-of-range so the caller surfaces a
/// `InvalidApiCall` error pointing at the offending row.
#[inline]
unsafe fn emit_i64_to_micros<F>(
    out: &mut Vec<u8>,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
    unit_label: &str,
    mut convert: F,
) -> Result<()>
where
    F: FnMut(i64) -> Option<i64>,
{
    let typed = data as *const i64;
    let make_err = |i: usize, value: i64| {
        error::fmt!(
            InvalidApiCall,
            "datetime64[{}] value at row {} ({}) overflows i64 when converted to microseconds",
            unit_label,
            i,
            value
        )
    };
    // numpy NaT is `i64::MIN`, which is also QuestDB's i64 null sentinel
    // (`I64_NULL`). Map it straight through to null so an in-band NaT is
    // treated consistently with the direct (already-µs) paths instead of
    // failing the whole batch on conversion overflow.
    match validity {
        None => {
            out.push(0);
            out.reserve(8 * row_count);
            for i in 0..row_count {
                let value = unsafe { *typed.add(i) };
                let micros = if value == I64_NULL {
                    I64_NULL
                } else {
                    convert(value).ok_or_else(|| make_err(i, value))?
                };
                out.extend_from_slice(&micros.to_le_bytes());
            }
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            out.reserve(8 * v.non_null_count);
            for i in 0..row_count {
                if !unsafe { v.is_valid(i) } {
                    continue;
                }
                let value = unsafe { *typed.add(i) };
                let micros = if value == I64_NULL {
                    I64_NULL
                } else {
                    convert(value).ok_or_else(|| make_err(i, value))?
                };
                out.extend_from_slice(&micros.to_le_bytes());
            }
        }
    }
    Ok(())
}

/// Microseconds at the start of `1970 + year_offset` (proleptic
/// Gregorian). Returns `None` on overflow.
fn year_offset_to_micros(year_offset: i64) -> Option<i64> {
    // Cap so the final `days * 86_400_000_000` always fits in i64.
    // i64::MAX / 86_400_000_000 ≈ 1.067e8 days ≈ 292_277 years.
    if !(-292_277..=292_277).contains(&year_offset) {
        return None;
    }
    let year = 1970 + year_offset;
    let days = days_from_civil(year, 1, 1);
    days.checked_mul(86_400_000_000)
}

/// Microseconds at the start of `(1970-01) + month_offset` (proleptic
/// Gregorian). Negative offsets are calendar-correct via euclidean mod.
fn month_offset_to_micros(month_offset: i64) -> Option<i64> {
    let year_offset = month_offset.div_euclid(12);
    let month_in_year = month_offset.rem_euclid(12) as u32 + 1; // 1..=12
    if !(-292_277..=292_277).contains(&year_offset) {
        return None;
    }
    let year = 1970 + year_offset;
    let days = days_from_civil(year, month_in_year, 1);
    days.checked_mul(86_400_000_000)
}

/// Days from the Unix epoch (1970-01-01) to the given proleptic
/// Gregorian (year, month, day). Howard Hinnant's `days_from_civil`
/// (public-domain algorithm, http://howardhinnant.github.io/date_algorithms.html).
/// Safe for `|year| < ~2.5e16`; callers above cap year first.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let m_adj = if m > 2 { m - 3 } else { m + 9 } as u64;
    let doy = (153 * m_adj + 2) / 5 + d as u64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146_096]
    era * 146_097 + doe as i64 - 719_468
}

/// Decimal wire: `null_flag` + optional bitmap + `scale` byte + dense
/// `N`-byte mantissas (only non-nulls when bitmap present, full row
/// count otherwise). Reproduces the arrow-side `write_decimal*_payload`
/// shape exactly: the scale byte is written **after** the bitmap.
#[inline]
unsafe fn emit_decimal<const N: usize>(
    out: &mut Vec<u8>,
    scale: u8,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) {
    match validity {
        None => {
            out.push(0);
            out.reserve(1 + N * row_count);
            out.push(scale);
            if row_count > 0 {
                let bytes = unsafe { slice::from_raw_parts(data, N * row_count) };
                out.extend_from_slice(bytes);
            }
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            out.reserve(1 + N * v.non_null_count);
            out.push(scale);
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

/// Geohash wire: `null_flag` + optional bitmap + `bits` byte + dense
/// `elem`-byte rows (only non-nulls when bitmap present, full row count
/// otherwise). `SRC` is the source-int width (1/2/4/8 bytes); `elem` is
/// the wire-element width derived from `bits` (`bits.div_ceil(8)`),
/// which is always `<= SRC`.
///
/// The encoder writes the low `elem` bytes of each source int, matching
/// `arrow_batch::write_geohash_payload`. Caller has validated `bits` is
/// within the source dtype's representable range.
#[inline]
unsafe fn emit_geohash<const SRC: usize>(
    out: &mut Vec<u8>,
    bits: u8,
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) -> Result<()> {
    let elem = (bits as usize).div_ceil(8);
    if elem > SRC {
        return Err(error::fmt!(
            InvalidApiCall,
            "numpy geohash bits ({bits}) exceeds source dtype width ({SRC} bytes)"
        ));
    }
    match validity {
        None => {
            out.push(0);
            out.reserve(1 + elem * row_count);
            out.push(bits);
            if elem == SRC && row_count > 0 {
                let bytes = unsafe { slice::from_raw_parts(data, SRC * row_count) };
                out.extend_from_slice(bytes);
            } else {
                for i in 0..row_count {
                    let row_start = unsafe { data.add(i * SRC) };
                    let row = unsafe { slice::from_raw_parts(row_start, elem) };
                    out.extend_from_slice(row);
                }
            }
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            out.reserve(1 + elem * v.non_null_count);
            out.push(bits);
            for i in 0..row_count {
                if unsafe { v.is_valid(i) } {
                    let row_start = unsafe { data.add(i * SRC) };
                    let row = unsafe { slice::from_raw_parts(row_start, elem) };
                    out.extend_from_slice(row);
                }
            }
        }
    }
    Ok(())
}

/// f64 ndarray (DOUBLE_ARRAY): `null_flag` + optional bitmap, then for
/// each non-null row `ndim u8 + (dim u32) × ndim + (value f64) × prod(dims)`.
/// Source layout is `row_count` contiguous tensors of `prod(shape[..ndim])`
/// f64s in C-order; null rows still occupy that many source bytes and are
/// skipped on emit, not on read.
#[inline]
unsafe fn emit_f64_ndarray(
    out: &mut Vec<u8>,
    ndim: u8,
    shape: [u32; MAX_ARRAY_DIMS],
    data: *const u8,
    row_count: usize,
    validity: Option<&ValidityDescriptor>,
) -> Result<()> {
    let nd = ndim as usize;
    let leaf_count: usize = shape[..nd]
        .iter()
        .copied()
        .map(|d| d as usize)
        .try_fold(1usize, usize::checked_mul)
        .ok_or_else(|| error::fmt!(InvalidApiCall, "F64Ndarray shape overflows usize"))?;
    if leaf_count > MAX_NDARRAY_LEAF_ELEMS {
        return Err(error::fmt!(
            InvalidApiCall,
            "F64Ndarray shape product {} exceeds MAX_NDARRAY_LEAF_ELEMS ({})",
            leaf_count,
            MAX_NDARRAY_LEAF_ELEMS
        ));
    }
    let row_payload = 1usize
        .checked_add(4usize.saturating_mul(nd))
        .and_then(|v| v.checked_add(8usize.saturating_mul(leaf_count)))
        .ok_or_else(|| error::fmt!(InvalidApiCall, "F64Ndarray row payload overflows usize"))?;
    let row_bytes = leaf_count
        .checked_mul(8)
        .ok_or_else(|| error::fmt!(InvalidApiCall, "F64Ndarray row size overflows usize"))?;

    let non_null_rows = match validity {
        None => {
            out.push(0);
            row_count
        }
        Some(v) => {
            out.push(1);
            unsafe { write_qwp_bitmap_from_validity(out, v) };
            v.non_null_count
        }
    };
    let reserve_bytes = non_null_rows.checked_mul(row_payload).ok_or_else(|| {
        error::fmt!(
            InvalidApiCall,
            "F64Ndarray reservation overflows usize ({} rows * {} bytes/row)",
            non_null_rows,
            row_payload
        )
    })?;
    out.try_reserve(reserve_bytes).map_err(|_| {
        error::fmt!(
            InvalidApiCall,
            "F64Ndarray reservation of {} bytes failed",
            reserve_bytes
        )
    })?;

    let header_len = 1 + 4 * nd;
    let mut header: [u8; 1 + 4 * MAX_ARRAY_DIMS] = [0u8; 1 + 4 * MAX_ARRAY_DIMS];
    header[0] = ndim;
    for (i, &d) in shape[..nd].iter().enumerate() {
        let off = 1 + 4 * i;
        header[off..off + 4].copy_from_slice(&d.to_le_bytes());
    }
    let header = &header[..header_len];

    for row in 0..row_count {
        if let Some(v) = validity
            && !unsafe { v.is_valid(row) }
        {
            continue;
        }
        out.extend_from_slice(header);
        let src = unsafe { data.add(row * row_bytes) };
        if cfg!(target_endian = "little") {
            if row_bytes > 0 {
                out.extend_from_slice(unsafe { slice::from_raw_parts(src, row_bytes) });
            }
        } else {
            for i in 0..leaf_count {
                let bits = unsafe { (src.add(i * 8) as *const u64).read_unaligned() };
                out.extend_from_slice(&bits.to_le_bytes());
            }
        }
    }
    Ok(())
}

/// Append `validity` as a QWP-shape bitmap (bit = 1 → NULL).
unsafe fn write_qwp_bitmap_from_validity(out: &mut Vec<u8>, v: &ValidityDescriptor) {
    let src = unsafe { slice::from_raw_parts(v.bits, v.byte_len()) };
    super::wire::write_qwp_bitmap_invert(out, src, v.bit_len);
}

#[cfg(test)]
mod tests {
    use super::super::Validity;
    use super::super::chunk::Chunk;
    use super::super::encoder::{EncodeScratch, SchemaRegistry, encode_chunk_into};
    use super::*;
    use crate::ingress::buffer::SymbolGlobalDict;

    fn encode(chunk: &Chunk<'_>) -> Vec<u8> {
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, chunk, &mut reg, &mut dict, &mut scratch, false).unwrap();
        out
    }

    fn encode_err(chunk: &Chunk<'_>) -> crate::Error {
        let mut out = Vec::new();
        let mut reg = SchemaRegistry::new();
        let mut dict = SymbolGlobalDict::new();
        let mut scratch = EncodeScratch::new();
        encode_chunk_into(&mut out, chunk, &mut reg, &mut dict, &mut scratch, false).unwrap_err()
    }

    #[test]
    fn i8_direct_matches_column_i8() {
        let src = [1i8, -2, 3];
        let ts = [10i64, 20, 30];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::I8Direct,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i8("v", &src, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "I8Direct must produce byte-identical wire to column_i8"
        );
    }

    #[test]
    fn i16_direct_matches_column_i16() {
        let src = [1i16, -2, 3];
        let ts = [10i64, 20, 30];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::I16Direct,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i16("v", &src, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "I16Direct must produce byte-identical wire to column_i16"
        );
    }

    #[test]
    fn i32_direct_matches_column_i32() {
        let src = [1i32, -2, 3];
        let ts = [10i64, 20, 30];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::I32Direct,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i32("v", &src, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "I32Direct must produce byte-identical wire to column_i32"
        );
    }

    #[test]
    fn u8_widen_matches_column_i32() {
        // u8 widens to INT (not SHORT) to avoid SHORT's null sentinel
        // value 0 silently swallowing source values of 0.
        let src = [0u8, 1, 200, 255];
        let widened: [i32; 4] = [0, 1, 200, 255];
        let ts = [10i64, 20, 30, 40];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred("v", NumpyDtype::U8WidenToI32, src.as_ptr(), src.len(), None)
                .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i32("v", &widened, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "U8WidenToI32 must produce byte-identical wire to column_i32 over the widened data"
        );
    }

    #[test]
    fn u16_widen_matches_column_i32() {
        let src = [0u16, 1, 30000, 65535];
        let widened: [i32; 4] = [0, 1, 30000, 65535];
        let ts = [10i64, 20, 30, 40];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::U16WidenToI32,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i32("v", &widened, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "U16WidenToI32 must produce byte-identical wire to column_i32 over the widened data"
        );
    }

    #[test]
    fn i8_widen_matches_column_i32() {
        // i8 widens to INT (not BYTE) so source value 0 does not collide
        // with BYTE's null sentinel (which is 0).
        let src = [-128i8, -1, 0, 1, 127];
        let widened: [i32; 5] = [-128, -1, 0, 1, 127];
        let ts = [10i64, 20, 30, 40, 50];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::I8WidenToI32,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i32("v", &widened, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "I8WidenToI32 must produce byte-identical wire to column_i32 over the widened data"
        );
    }

    #[test]
    fn i16_widen_matches_column_i32() {
        let src = [i16::MIN, -1, 0, 1, i16::MAX];
        let widened: [i32; 5] = [i16::MIN as i32, -1, 0, 1, i16::MAX as i32];
        let ts = [10i64, 20, 30, 40, 50];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::I16WidenToI32,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i32("v", &widened, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "I16WidenToI32 must produce byte-identical wire to column_i32 over the widened data"
        );
    }

    #[test]
    fn i32_widen_matches_column_i64() {
        // i32 widens to LONG so source value i32::MIN does not collide with
        // INT's null sentinel (which is i32::MIN).
        let src = [i32::MIN, -1, 0, 1, i32::MAX];
        let widened: [i64; 5] = [i32::MIN as i64, -1, 0, 1, i32::MAX as i64];
        let ts = [10i64, 20, 30, 40, 50];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::I32WidenToI64,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i64("v", &widened, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "I32WidenToI64 must produce byte-identical wire to column_i64 over the widened data"
        );
    }

    #[test]
    fn u64_widen_within_i64_range_matches_column_i64() {
        let src = [0u64, 42, i64::MAX as u64];
        let widened: [i64; 3] = [0, 42, i64::MAX];
        let ts = [10i64, 20, 30];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::U64WidenToI64,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_i64("v", &widened, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "U64WidenToI64 must produce signed LONG wire for values within i64::MAX"
        );
    }

    #[test]
    fn u64_widen_above_i64_max_rejects() {
        let src = [i64::MAX as u64 + 1];
        let ts = [10i64];

        let mut chunk = Chunk::new("t");
        unsafe {
            chunk
                .push_numpy_deferred(
                    "v",
                    NumpyDtype::U64WidenToI64,
                    src.as_ptr() as *const u8,
                    src.len(),
                    None,
                )
                .unwrap();
        }
        chunk.designated_timestamp_nanos(&ts).unwrap();
        let err = encode_err(&chunk);
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(
            err.msg().contains("does not fit QuestDB LONG"),
            "{}",
            err.msg()
        );
    }

    #[test]
    fn nullable_u64_widen_above_i64_max_rejects() {
        let src = [0u64, i64::MAX as u64 + 1];
        let ts = [10i64, 20];
        let validity_bits = [0b0000_0010u8];
        let validity = Validity::from_bitmap(&validity_bits, src.len()).unwrap();

        let mut chunk = Chunk::new("t");
        unsafe {
            chunk
                .push_numpy_deferred(
                    "v",
                    NumpyDtype::U64WidenToI64,
                    src.as_ptr() as *const u8,
                    src.len(),
                    Some(&validity),
                )
                .unwrap();
        }
        chunk.designated_timestamp_nanos(&ts).unwrap();
        let err = encode_err(&chunk);
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(
            err.msg().contains("does not fit QuestDB LONG"),
            "{}",
            err.msg()
        );
    }

    #[test]
    fn f32_direct_matches_column_f32() {
        let src = [1.5f32, -2.25, 3.125, f32::NAN];
        let ts = [10i64, 20, 30, 40];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "v",
                NumpyDtype::F32Direct,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_f32("v", &src, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "F32Direct must produce byte-identical wire to column_f32"
        );
    }

    #[test]
    fn bool_with_null_matches_column_bool() {
        let raw = [1u8, 0, 1, 1];
        let ts = [1i64, 2, 3, 4];
        // Arrow-shape validity: bit = 1 means valid. Mark row 2 null.
        let v_bits = [0b0000_1011u8];
        let v = Validity::from_bitmap(&v_bits, 4).unwrap();

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred("b", NumpyDtype::Bool, raw.as_ptr(), raw.len(), Some(&v))
                .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut packed = vec![0u8; raw.len().div_ceil(8)];
        for (i, &b) in raw.iter().enumerate() {
            if b != 0 {
                packed[i / 8] |= 1u8 << (i % 8);
            }
        }
        let mut b = Chunk::new("t");
        b.column_bool("b", &packed, raw.len(), Some(&v)).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "Bool numpy emit must match column_bool over the equivalent packed bitmap"
        );
    }

    #[test]
    fn timestamp_nanos_direct_matches_column_ts_nanos() {
        let src = [1_000i64, 2_000, 3_000];
        let ts = [1i64, 2, 3];

        let mut a = Chunk::new("t");
        unsafe {
            a.push_numpy_deferred(
                "ts",
                NumpyDtype::TimestampNanosDirect,
                src.as_ptr() as *const u8,
                src.len(),
                None,
            )
            .unwrap();
        }
        a.designated_timestamp_nanos(&ts).unwrap();
        let bytes_a = encode(&a);

        let mut b = Chunk::new("t");
        b.column_ts_nanos("ts", &src, None).unwrap();
        b.designated_timestamp_nanos(&ts).unwrap();
        let bytes_b = encode(&b);

        assert_eq!(
            bytes_a, bytes_b,
            "TimestampNanosDirect must produce byte-identical wire to column_ts_nanos"
        );
    }

    /// Helper: encode one numpy datetime column + a fixed ts, return wire bytes.
    fn encode_datetime_col(dtype: NumpyDtype, src_le_bytes: &[u8], row_count: usize) -> Vec<u8> {
        let ts: Vec<i64> = (0..row_count as i64).collect();
        let mut chunk = Chunk::new("t");
        unsafe {
            chunk
                .push_numpy_deferred("v", dtype, src_le_bytes.as_ptr(), row_count, None)
                .unwrap();
        }
        chunk.designated_timestamp_nanos(&ts).unwrap();
        encode(&chunk)
    }

    /// Helper: encode `column_ts_micros(values)` + fixed ts, return wire bytes.
    fn encode_micros_col(values: &[i64]) -> Vec<u8> {
        let ts: Vec<i64> = (0..values.len() as i64).collect();
        let mut chunk = Chunk::new("t");
        chunk.column_ts_micros("v", values, None).unwrap();
        chunk.designated_timestamp_nanos(&ts).unwrap();
        encode(&chunk)
    }

    #[test]
    fn datetime_day_matches_column_ts_micros() {
        let src = [0i64, 1, 18262]; // epoch, +1d, 2020-01-01
        let expected = [0i64, 86_400_000_000, 18262 * 86_400_000_000];
        let raw: Vec<u8> = src.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            encode_datetime_col(NumpyDtype::DatetimeDayToMicros, &raw, src.len()),
            encode_micros_col(&expected),
        );
    }

    #[test]
    fn datetime_nat_maps_to_null_not_error() {
        // numpy NaT is `i64::MIN`, which is also QuestDB's i64 null
        // sentinel (`I64_NULL`). The converting path must pass it through
        // as null rather than failing the whole batch on overflow.
        let src = [0i64, i64::MIN, 1];
        let expected = [0i64, i64::MIN, 86_400_000_000];
        let raw: Vec<u8> = src.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            encode_datetime_col(NumpyDtype::DatetimeDayToMicros, &raw, src.len()),
            encode_micros_col(&expected),
        );
    }

    #[test]
    fn datetime_hour_matches_column_ts_micros() {
        let src = [0i64, 1, 24];
        let expected = [0i64, 3_600_000_000, 24 * 3_600_000_000];
        let raw: Vec<u8> = src.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            encode_datetime_col(NumpyDtype::DatetimeHourToMicros, &raw, src.len()),
            encode_micros_col(&expected),
        );
    }

    #[test]
    fn datetime_minute_matches_column_ts_micros() {
        let src = [0i64, 1, 60];
        let expected = [0i64, 60_000_000, 60 * 60_000_000];
        let raw: Vec<u8> = src.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            encode_datetime_col(NumpyDtype::DatetimeMinuteToMicros, &raw, src.len()),
            encode_micros_col(&expected),
        );
    }

    #[test]
    fn datetime_year_matches_calendar() {
        // y=0 → 1970-01-01, y=50 → 2020-01-01 (18262 days), y=-1 → 1969-01-01 (-365 days)
        let src = [0i64, 50, -1];
        let expected = [0i64, 18262 * 86_400_000_000, -365 * 86_400_000_000];
        let raw: Vec<u8> = src.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            encode_datetime_col(NumpyDtype::DatetimeYearToMicros, &raw, src.len()),
            encode_micros_col(&expected),
        );
    }

    #[test]
    fn datetime_month_matches_calendar() {
        // m=0 → 1970-01-01, m=1 → 1970-02-01 (31 days), m=13 → 1971-02-01 (365+31 days),
        // m=-1 → 1969-12-01 (-31 days)
        let src = [0i64, 1, 13, -1];
        let expected = [
            0i64,
            31 * 86_400_000_000,
            (365 + 31) * 86_400_000_000,
            -31 * 86_400_000_000,
        ];
        let raw: Vec<u8> = src.iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(
            encode_datetime_col(NumpyDtype::DatetimeMonthToMicros, &raw, src.len()),
            encode_micros_col(&expected),
        );
    }

    #[test]
    fn datetime_year_out_of_range_rejected() {
        let bad = [10_000_000i64]; // far beyond the ±292_277 cap
        let ts = [1i64];
        let mut chunk = Chunk::new("t");
        unsafe {
            chunk
                .push_numpy_deferred(
                    "ts",
                    NumpyDtype::DatetimeYearToMicros,
                    bad.as_ptr() as *const u8,
                    bad.len(),
                    None,
                )
                .unwrap();
        }
        chunk.designated_timestamp_nanos(&ts).unwrap();
        let err = {
            let mut out = Vec::new();
            let mut reg = SchemaRegistry::new();
            let mut dict = SymbolGlobalDict::new();
            let mut scratch = EncodeScratch::new();
            encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false)
                .unwrap_err()
        };
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("overflows"));
    }

    #[test]
    fn datetime_sec_overflow_rejected() {
        let bad = [i64::MAX];
        let ts = [1i64];

        let mut chunk = Chunk::new("t");
        unsafe {
            chunk
                .push_numpy_deferred(
                    "ts",
                    NumpyDtype::DatetimeSecToMicros,
                    bad.as_ptr() as *const u8,
                    bad.len(),
                    None,
                )
                .unwrap();
        }
        chunk.designated_timestamp_nanos(&ts).unwrap();
        let err = {
            let mut out = Vec::new();
            let mut reg = SchemaRegistry::new();
            let mut dict = SymbolGlobalDict::new();
            let mut scratch = EncodeScratch::new();
            encode_chunk_into(&mut out, &chunk, &mut reg, &mut dict, &mut scratch, false)
                .unwrap_err()
        };
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
        assert!(err.msg().contains("overflows"));
    }

    #[test]
    fn f64_ndarray_1d_no_validity_layout() {
        // 2 rows, ndim=1, shape=[3] — wire body per row is
        // [ndim:u8=1, dim:u32 LE=3, 3×f64 LE values]. Two non-null
        // rows + leading null_flag=0 gives a deterministic byte image
        // we can construct and compare against.
        let rows: [f64; 6] = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let ts = [10i64, 20];
        let mut shape = [0u32; MAX_ARRAY_DIMS];
        shape[0] = 3;

        let mut chunk = Chunk::new("t");
        unsafe {
            chunk
                .push_numpy_deferred(
                    "v",
                    NumpyDtype::F64Ndarray { ndim: 1, shape },
                    rows.as_ptr() as *const u8,
                    2,
                    None,
                )
                .unwrap();
        }
        chunk.designated_timestamp_nanos(&ts).unwrap();
        let bytes = encode(&chunk);

        // The full frame contains schema / header bytes too; assert the
        // column body subsequence appears exactly once.
        let mut body: Vec<u8> = Vec::new();
        body.push(0u8); // null_flag = 0 (no validity)
        for row_chunk in rows.chunks_exact(3) {
            body.push(1u8); // ndim
            body.extend_from_slice(&3u32.to_le_bytes()); // dim
            for &v in row_chunk {
                body.extend_from_slice(&v.to_le_bytes());
            }
        }
        assert!(
            bytes.windows(body.len()).any(|w| w == body.as_slice()),
            "expected ndarray column body subsequence in encoded frame"
        );
    }

    #[test]
    fn f16_bits_to_f32_known_values() {
        // 0.0
        assert_eq!(f16_bits_to_f32(0x0000), 0.0f32);
        // -0.0
        assert_eq!(f16_bits_to_f32(0x8000).to_bits(), (-0.0f32).to_bits());
        // 1.0
        assert_eq!(f16_bits_to_f32(0x3C00), 1.0f32);
        // -2.0
        assert_eq!(f16_bits_to_f32(0xC000), -2.0f32);
        // +inf
        assert!(f16_bits_to_f32(0x7C00).is_infinite() && f16_bits_to_f32(0x7C00) > 0.0);
        // smallest positive subnormal: 2^-24
        let v = f16_bits_to_f32(0x0001);
        assert_eq!(v, 2.0f32.powi(-24));
    }
}
