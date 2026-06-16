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

//! Wire-format helpers for the column-major sender encoder.
//!
//! These are intentionally duplicated from the row-API encoder
//! (`buffer/qwp.rs`): the row helpers are private to that module and the
//! plan calls out the wire surface as a place where we accept the ~100
//! lines of duplication to keep the column-sender hot path free of
//! cross-module hops. See `doc/COLUMN_SENDER_PLAN.md` §2.1.

/// QWP message header magic.
pub(crate) const QWP_MAGIC: [u8; 4] = *b"QWP1";
pub(crate) const QWP_VERSION_1: u8 = 1;
/// Wire-spec flag set on every column-sender frame (matches the row-API
/// `QwpBuffer::encode_ws_message`).
pub(crate) const QWP_FLAG_DEFER_COMMIT: u8 = 0x01;
pub(crate) const QWP_FLAG_DELTA_SYMBOL_DICT: u8 = 0x08;
pub(crate) const QWP_HEADER_LEN: usize = 12;

// Wire type codes — duplicated from `buffer/qwp.rs`. See the QWP v1 spec
// (`questdb/documentation/connect/wire-protocols/qwp-ingress-websocket.md`)
// §Type byte table for the canonical list.
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
pub(crate) const QWP_TYPE_DECIMAL64: u8 = 0x13;
pub(crate) const QWP_TYPE_DECIMAL128: u8 = 0x14;
pub(crate) const QWP_TYPE_DECIMAL256: u8 = 0x15;
pub(crate) const QWP_TYPE_CHAR: u8 = 0x16;
pub(crate) const QWP_TYPE_BINARY: u8 = 0x17;
pub(crate) const QWP_TYPE_IPV4: u8 = 0x18;

/// Maximum bytes a UTF-8 column or table name is allowed to occupy on the
/// wire. Matches the row-API + Java client cap.
pub(crate) const MAX_NAME_LEN: usize = 127;

/// Wire-shape sentinels QuestDB treats as NULL for each fixed-width
/// non-bitmap-capable type. The row-API encoder writes these for missing
/// values; the column-sender mirrors them on the nullable path so the
/// wire bytes are byte-compatible with the row encoder.
pub(crate) const I8_NULL: i8 = 0;
pub(crate) const I16_NULL: i16 = 0;
pub(crate) const I32_NULL: i32 = i32::MIN;
pub(crate) const I64_NULL: i64 = i64::MIN;
pub(crate) const F32_NULL: f32 = f32::NAN;
pub(crate) const F64_NULL: f64 = f64::NAN;

/// Append `value` to `out` as an unsigned QWP varint (LEB128).
#[inline]
pub(crate) fn write_qwp_varint(out: &mut Vec<u8>, mut value: u64) {
    while value > 0x7F {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Append a length-prefixed byte string: `varint(len) + bytes`.
#[inline]
pub(crate) fn write_qwp_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_qwp_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// Append `src[..bit_len bits]` to `out`, inverted (Arrow `1=valid` →
/// QWP `1=null`), masking the high bits past `bit_len` in the trailing
/// byte. Word-stride on the bulk; byte-stride only on the tail. Caller
/// owns the source slice's lifetime.
#[inline]
pub(crate) fn write_qwp_bitmap_invert(out: &mut Vec<u8>, src: &[u8], bit_len: usize) {
    let full_bytes = bit_len / 8;
    let trailing_bits = bit_len % 8;
    let bitmap_bytes = full_bytes + usize::from(trailing_bits != 0);
    let dst_start = out.len();
    out.resize(dst_start + bitmap_bytes, 0);
    let dst = &mut out[dst_start..dst_start + bitmap_bytes];
    let mut i = 0;
    while i + 8 <= full_bytes {
        let w = u64::from_ne_bytes(src[i..i + 8].try_into().unwrap());
        dst[i..i + 8].copy_from_slice(&(!w).to_ne_bytes());
        i += 8;
    }
    for j in i..full_bytes {
        dst[j] = !src[j];
    }
    if trailing_bits != 0 {
        let mask = (1u8 << trailing_bits) - 1;
        dst[full_bytes] = (!src[full_bytes]) & mask;
    }
}

/// Validate a UTF-8 name against the QWP/Java client length cap.
pub(crate) fn validate_name(kind: &'static str, name: &str) -> crate::Result<()> {
    if name.is_empty() {
        return Err(crate::error::fmt!(
            InvalidName,
            "{} name must not be empty",
            kind
        ));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(crate::error::fmt!(
            InvalidName,
            "{} name is too long: {} bytes (max {})",
            kind,
            name.len(),
            MAX_NAME_LEN
        ));
    }
    Ok(())
}
