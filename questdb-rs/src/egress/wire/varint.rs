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

//! Unsigned LEB128 varint codec used by QWP wire format.
//!
//! 7-bit groups, LSB first, high bit (`0x80`) is a continuation flag.

use crate::egress::error::{Error, ErrorCode, Result, fmt};

/// Maximum bytes a u64 LEB128 value can occupy: ceil(64 / 7) = 10.
pub const MAX_VARINT_LEN_U64: usize = 10;

/// Encode `value` into `out`, returning the number of bytes written.
///
/// `out` must have at least [`MAX_VARINT_LEN_U64`] bytes of capacity remaining
/// for any caller-provided value.
pub fn encode_u64(mut value: u64, out: &mut Vec<u8>) -> usize {
    let start = out.len();
    while value & !0x7F != 0 {
        out.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out.len() - start
}

/// Encode `value` into the head of `out`, returning the number of bytes
/// written. Slice-form counterpart of [`encode_u64`] for callers that
/// build small fixed-shape frames on the stack and want to avoid the
/// per-call `Vec` allocation. `out` must be at least
/// [`MAX_VARINT_LEN_U64`] bytes long for any caller-provided value;
/// shorter inputs panic with a slice-index-out-of-range — the contract
/// is "size your buffer to the worst case", same as the `Vec` variant's
/// implicit capacity requirement.
pub fn encode_u64_into_slice(mut value: u64, out: &mut [u8]) -> usize {
    let mut i = 0;
    while value & !0x7F != 0 {
        out[i] = ((value & 0x7F) as u8) | 0x80;
        value >>= 7;
        i += 1;
    }
    out[i] = value as u8;
    i + 1
}

/// Decode a varint from `bytes`, returning `(value, bytes_consumed)`.
///
/// Errors when:
/// - input ends mid-varint
/// - the encoded value would not fit in `u64`
pub fn decode_u64(bytes: &[u8]) -> Result<(u64, usize)> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        if shift >= 64 {
            return Err(fmt!(
                ProtocolError,
                "varint exceeds 64-bit range at byte {}",
                i
            ));
        }
        let chunk = (b & 0x7F) as u64;
        // Guard against the 10th byte carrying bits beyond bit 63.
        if shift == 63 && (chunk & !0x01) != 0 {
            return Err(fmt!(
                ProtocolError,
                "varint exceeds 64-bit range at byte {}",
                i
            ));
        }
        result |= chunk << shift;
        if b & 0x80 == 0 {
            return Ok((result, i + 1));
        }
        shift += 7;
    }
    Err(fmt!(
        ProtocolError,
        "truncated varint: {} bytes without terminator",
        bytes.len()
    ))
}

/// Decode a varint that must fit in `usize`. Convenience for length fields.
pub fn decode_usize(bytes: &[u8]) -> Result<(usize, usize)> {
    let (v, n) = decode_u64(bytes)?;
    let v_us = usize::try_from(v).map_err(|_| {
        Error::new(
            ErrorCode::ProtocolError,
            format!("varint value {} does not fit in usize", v),
        )
    })?;
    Ok((v_us, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(value: u64, expected_len: usize) {
        let mut buf = Vec::new();
        let n = encode_u64(value, &mut buf);
        assert_eq!(n, expected_len, "encoded length for {}", value);
        assert_eq!(buf.len(), expected_len);
        let (decoded, consumed) = decode_u64(&buf).expect("decode");
        assert_eq!(decoded, value);
        assert_eq!(consumed, expected_len);
    }

    #[test]
    fn boundaries() {
        roundtrip(0, 1);
        roundtrip(1, 1);
        roundtrip(0x7F, 1);
        roundtrip(0x80, 2);
        roundtrip(0x3FFF, 2);
        roundtrip(0x4000, 3);
        roundtrip(u32::MAX as u64, 5);
        roundtrip(u64::MAX, 10);
    }

    #[test]
    fn reference_vector_300() {
        // 300 = 0xAC 0x02 (per the canonical LEB128 example)
        let mut buf = Vec::new();
        encode_u64(300, &mut buf);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn truncated_is_error() {
        // A value with continuation bit set but no follow-up byte.
        let bytes = [0x80u8];
        let err = decode_u64(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn overlong_is_error() {
        // 11-byte sequence: all continuation. Invalid (max is 10 bytes for u64).
        let bytes = [0x80u8; 11];
        let err = decode_u64(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn tenth_byte_with_high_bits_is_error() {
        // 10 bytes is allowed, but only bit 0 of the final byte may be set
        // (bit 63 of the value). This sets bit 1 of byte 9 -> bit 64.
        let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        let err = decode_u64(&bytes).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn decode_consumes_only_one_value() {
        let mut buf = Vec::new();
        encode_u64(300, &mut buf);
        encode_u64(7, &mut buf);
        let (v1, n1) = decode_u64(&buf).unwrap();
        assert_eq!(v1, 300);
        let (v2, n2) = decode_u64(&buf[n1..]).unwrap();
        assert_eq!(v2, 7);
        assert_eq!(n1 + n2, buf.len());
    }

    #[test]
    fn decode_usize_succeeds_for_small_values() {
        let mut buf = Vec::new();
        encode_u64(42, &mut buf);
        let (v, _) = decode_usize(&buf).unwrap();
        assert_eq!(v, 42);
    }

    /// Regression: the slice-form
    /// `encode_u64_into_slice` and the Vec-form `encode_u64` MUST
    /// produce byte-for-byte identical output for every input. The
    /// slice form has a distinct failure mode (slice-OOB if the
    /// caller under-sizes the buffer) and was previously
    /// untested; pin the byte-equivalence at every documented
    /// boundary so a future divergence (e.g. an "optimisation" that
    /// drops the high bit on the last byte) fails this test.
    #[test]
    fn slice_form_matches_vec_form_at_boundaries() {
        for value in [
            0u64,
            1,
            0x7F,
            0x80,
            0x3FFF,
            0x4000,
            u32::MAX as u64,
            u64::MAX,
            300, // canonical LEB128 reference value
        ] {
            let mut vec_buf = Vec::new();
            let vec_n = encode_u64(value, &mut vec_buf);

            let mut slice_buf = [0u8; MAX_VARINT_LEN_U64];
            let slice_n = encode_u64_into_slice(value, &mut slice_buf);

            assert_eq!(
                slice_n, vec_n,
                "slice_form vs vec_form byte-count for value {}",
                value,
            );
            assert_eq!(
                &slice_buf[..slice_n],
                vec_buf.as_slice(),
                "slice_form vs vec_form bytes for value {}",
                value,
            );

            // Round-trip via `decode_u64` against the slice-form
            // output independently — guarantees the bytes the
            // slice form emitted are themselves a valid varint and
            // not just structurally identical to the Vec form's
            // (which could equally be wrong if both shared a bug).
            let (decoded, consumed) = decode_u64(&slice_buf[..slice_n]).expect("slice-form decode");
            assert_eq!(decoded, value);
            assert_eq!(consumed, slice_n);
        }
    }

    /// Regression for N3 (companion to `slice_form_matches_vec_form_at_boundaries`):
    /// the docstring on `encode_u64_into_slice` promises "shorter
    /// inputs panic with slice-index-out-of-range". Pin that
    /// contract via `#[should_panic]` so a future refactor that
    /// e.g. swaps the slice indexer for a `get_mut(i)?.write(b)`
    /// shape fails this test (and surfaces the contract change).
    #[test]
    #[should_panic]
    fn slice_form_panics_on_undersized_buffer() {
        // `u64::MAX` requires 10 bytes; a 1-byte buffer must panic.
        let mut buf = [0u8; 1];
        let _ = encode_u64_into_slice(u64::MAX, &mut buf);
    }
}
