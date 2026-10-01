/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2026 QuestDB
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

//! Gorilla delta-of-delta *encoder* for QWP ingress `TIMESTAMP` /
//! `TIMESTAMP_NANOS` columns, written when `FLAG_GORILLA` is set on the
//! message header. Exact mirror of the egress decoder in
//! [`crate::egress::gorilla`]; see that module for the bit format
//! (LSB-first within each byte):
//!
//! ```text
//! '0'                     -> DoD = 0                   (1 bit)
//! '10' + 7-bit signed     -> DoD in [-64, 63]          (9 bits)
//! '110' + 9-bit signed    -> DoD in [-256, 255]        (12 bits)
//! '1110' + 12-bit signed  -> DoD in [-2048, 2047]      (16 bits)
//! '1111' + 32-bit signed  -> any other DoD             (36 bits)
//! ```
//!
//! Column payload layout (after the column's null-header):
//! one discriminator byte, then either dense raw LE i64 values
//! (`ENCODING_UNCOMPRESSED`) or two raw LE i64 seed values followed by the
//! DoD bitstream (`ENCODING_GORILLA`).
//!
//! All delta arithmetic is wrapping, matching both the Java client's
//! (silently overflowing) long arithmetic and the egress decoder's
//! `wrapping_add` reconstruction, so encode/decode round-trips even at
//! the i64 extremes.

/// Per-column encoding discriminator: dense raw LE i64 values.
pub(crate) const ENCODING_UNCOMPRESSED: u8 = 0x00;
/// Per-column encoding discriminator: Gorilla seeds + DoD bitstream.
pub(crate) const ENCODING_GORILLA: u8 = 0x01;

/// LSB-first bit writer appending to a byte vector. Bits collect in a 64-bit
/// accumulator that reaches `out` one whole word at a time.
struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    acc: u64,
    /// Pending bits in `acc`, always < 64.
    nbits: u32,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            acc: 0,
            nbits: 0,
        }
    }

    /// Append the low `n` bits of `value`; the bits above `n` must be zero.
    ///
    /// Forced inline: the encode loop is instantiated once per value source,
    /// and with the plain hint it measured about 1 ns per value slower.
    #[inline(always)]
    fn write_bits(&mut self, value: u64, n: u32) {
        debug_assert!(n > 0 && n < 64 && value >> n == 0);
        self.acc |= value << self.nbits;
        let total = self.nbits + n;
        if total >= 64 {
            self.out.extend_from_slice(&self.acc.to_le_bytes());
            // `n < 64` means a flush only happens with bits already pending,
            // so the shift below is always < 64.
            self.acc = value >> (64 - self.nbits);
            self.nbits = total - 64;
        } else {
            self.nbits = total;
        }
    }

    /// Flush the pending bits, zero-padding the last byte's high bits.
    fn finish(self) {
        let bytes = self.nbits.div_ceil(8) as usize;
        self.out.extend_from_slice(&self.acc.to_le_bytes()[..bytes]);
    }
}

/// The low `n` bits of `v`'s two's-complement representation.
#[inline(always)]
fn low_bits(v: i64, n: u32) -> u64 {
    (v as u64) & ((1u64 << n) - 1)
}

/// One delta-of-delta as `(code, bit length)`: the bucket prefix in the low
/// bits, the payload above it, so each value is a single write. `None` when
/// the value falls outside the 32-bit bucket, which ends Gorilla encoding for
/// the column.
#[inline(always)]
fn dod_code(dod: i64) -> Option<(u64, u32)> {
    if dod == 0 {
        Some((0, 1))
    } else if (-64..=63).contains(&dod) {
        Some((0b01 | (low_bits(dod, 7) << 2), 9))
    } else if (-256..=255).contains(&dod) {
        Some((0b011 | (low_bits(dod, 9) << 3), 12))
    } else if (-2048..=2047).contains(&dod) {
        Some((0b0111 | (low_bits(dod, 12) << 4), 16))
    } else if (i32::MIN as i64..=i32::MAX as i64).contains(&dod) {
        Some((0b1111 | (low_bits(dod, 32) << 4), 36))
    } else {
        None
    }
}

/// Encode ≥ 3 values as two raw LE seeds + DoD bitstream. Returns `false`,
/// leaving a partial stream in `out`, as soon as a delta-of-delta falls
/// outside the 32-bit bucket; the caller truncates `out` back to where it
/// started and ships the column raw instead.
fn try_encode_gorilla(out: &mut Vec<u8>, mut values: impl Iterator<Item = i64>) -> bool {
    let first = values.next().expect("gorilla encode needs >= 3 values");
    let second = values.next().expect("gorilla encode needs >= 3 values");
    out.extend_from_slice(&first.to_le_bytes());
    out.extend_from_slice(&second.to_le_bytes());
    let mut w = BitWriter::new(out);
    let mut prev = second;
    let mut prev_delta = second.wrapping_sub(first);
    for v in values {
        let delta = v.wrapping_sub(prev);
        let dod = delta.wrapping_sub(prev_delta);
        let Some((code, n)) = dod_code(dod) else {
            return false;
        };
        w.write_bits(code, n);
        prev_delta = delta;
        prev = v;
    }
    w.finish();
    true
}

/// Dense raw LE values through one pre-sized slab, so the loop carries no
/// per-value capacity check and a contiguous source compiles to a plain copy.
fn write_raw(out: &mut Vec<u8>, count: usize, values: impl Iterator<Item = i64>) {
    let start = out.len();
    out.resize(start + count * 8, 0);
    for (dst, v) in out[start..].chunks_exact_mut(8).zip(values) {
        dst.copy_from_slice(&v.to_le_bytes());
    }
}

/// Write one temporal column's payload: discriminator byte + dense non-null
/// values. Gorilla when `count > 2` and every DoD fits i32; raw otherwise.
///
/// One optimistic pass: the column is Gorilla-encoded while it is checked, and
/// the first out-of-range delta-of-delta discards that output and writes the
/// raw layout instead. So `make_values` is called once when the column
/// compresses and twice when it falls back, and must yield exactly `count`
/// identical values each time.
///
/// Output never exceeds `1 + count * 8` bytes, so callers whose frame-size
/// estimates already cover the raw layout only need one extra byte per
/// temporal column to keep their up-front `try_reserve` an upper bound.
pub(crate) fn write_temporal_column<I>(out: &mut Vec<u8>, count: usize, make_values: impl Fn() -> I)
where
    I: Iterator<Item = i64>,
{
    let start = out.len();
    if count > 2 {
        out.push(ENCODING_GORILLA);
        if try_encode_gorilla(out, make_values()) {
            return;
        }
        out.truncate(start);
    }
    out.push(ENCODING_UNCOMPRESSED);
    write_raw(out, count, make_values());
}

/// The payload [`write_temporal_column`] emits for `dense` values. Tests of
/// the encode paths build their expected bytes from it; `golden_tests` pins
/// the bytes themselves.
#[cfg(test)]
pub(crate) fn temporal_payload(dense: &[i64]) -> Vec<u8> {
    let mut out = Vec::new();
    write_temporal_column(&mut out, dense.len(), || dense.iter().copied());
    out
}

/// Fixed-byte tests: they pin the exact wire bytes, so a bucket or padding
/// change that stays self-consistent with the client's own decoder (and so
/// survives the round-trip tests below) still fails here.
#[cfg(test)]
mod golden_tests {
    use super::*;

    /// Rebuild the value sequence whose consecutive delta-of-deltas are `dods`.
    fn values_from_dods(first: i64, second: i64, dods: &[i64]) -> Vec<i64> {
        let mut values = vec![first, second];
        let mut delta = second.wrapping_sub(first);
        let mut prev = second;
        for &dod in dods {
            delta = delta.wrapping_add(dod);
            prev = prev.wrapping_add(delta);
            values.push(prev);
        }
        values
    }

    #[test]
    fn bucket_edges_match_reference_bytes() {
        // Both sides of every bucket edge, negative and positive, then the
        // i32 extremes. 293 stream bits, so the last byte carries 3 bits of
        // zero padding.
        #[rustfmt::skip]
        let dods = [
            0, 1, -1, 63, -64, 64, -65, 255, -256, 256, -257, 2047, -2048, 2048, -2049,
            i32::MAX as i64, i32::MIN as i64,
        ];
        let values = values_from_dods(1_700_000_000_000_000, 1_700_000_000_001_000, &dods);
        // Produced by an independent bit-at-a-time implementation of the
        // format in the module docs, not by this encoder.
        #[rustfmt::skip]
        let expected: [u8; 54] = [
            // discriminator
            0x01,
            // seeds
            0x00, 0x40, 0x1E, 0x18, 0x24, 0x0A, 0x06, 0x00,
            0xE8, 0x43, 0x1E, 0x18, 0x24, 0x0A, 0x06, 0x00,
            // DoD bitstream
            0x0A, 0xF4, 0xEF, 0x17, 0x70, 0x40, 0xF6, 0x7B, 0xFF, 0x06,
            0xF0, 0x00, 0xE2, 0xFE, 0xFD, 0xFE, 0xEF, 0x00, 0xF0, 0x01,
            0x10, 0x00, 0x00, 0xFE, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x1E, 0x00, 0x00, 0x00, 0x10,
        ];
        assert_eq!(temporal_payload(&values), expected);
    }

    #[test]
    fn dod_one_past_i32_encodes_raw() {
        // The last case overflows only at the end of a long zero-DoD run: the
        // optimistic Gorilla pass has already flushed whole 64-bit words by
        // then, and every one of them must be discarded.
        let mut late_overflow = vec![0i64; 200];
        late_overflow.push(i32::MAX as i64 + 1);
        for values in [
            vec![0, 0, i32::MAX as i64 + 1],
            vec![0, 0, i32::MIN as i64 - 1],
            late_overflow,
        ] {
            let mut raw = vec![ENCODING_UNCOMPRESSED];
            raw.extend(values.iter().flat_map(|v| v.to_le_bytes()));
            assert_eq!(temporal_payload(&values), raw);
        }
    }
}

// The round-trip tests depend on the egress decoder, which is behind the
// `_egress` feature (not implied by the sender-only CI feature combos) —
// gate them accordingly, following the `ingress/polars.rs` precedent.
#[cfg(all(test, feature = "_egress"))]
mod tests {
    use super::*;
    use crate::egress::gorilla::GorillaDecoder;

    /// Decode a `write_temporal_column` payload back into values using the
    /// production egress decoder as the reference implementation.
    fn decode_temporal(payload: &[u8], count: usize) -> Vec<i64> {
        let (disc, rest) = payload.split_first().expect("non-empty payload");
        match *disc {
            ENCODING_UNCOMPRESSED => {
                assert_eq!(rest.len(), count * 8);
                rest.as_chunks::<8>()
                    .0
                    .iter()
                    .map(|c| i64::from_le_bytes(*c))
                    .collect()
            }
            ENCODING_GORILLA => {
                assert!(count > 2, "gorilla discriminator implies > 2 values");
                let s0 = i64::from_le_bytes(rest[0..8].try_into().unwrap());
                let s1 = i64::from_le_bytes(rest[8..16].try_into().unwrap());
                let mut vals = vec![s0, s1];
                let mut dec = GorillaDecoder::new(s0, s1, &rest[16..]);
                for _ in 2..count {
                    vals.push(dec.decode_next().unwrap());
                }
                assert_eq!(16 + dec.bytes_consumed(), rest.len());
                vals
            }
            other => panic!("unknown discriminator 0x{other:02X}"),
        }
    }

    fn roundtrip(values: &[i64]) -> Vec<u8> {
        let mut out = Vec::new();
        write_temporal_column(&mut out, values.len(), || values.iter().copied());
        assert_eq!(decode_temporal(&out, values.len()), values);
        out
    }

    #[test]
    fn regular_interval_compresses_and_roundtrips() {
        let values: Vec<i64> = (0..100)
            .map(|i| 1_700_000_000_000_000 + i * 1_000)
            .collect();
        let out = roundtrip(&values);
        assert_eq!(out[0], ENCODING_GORILLA);
        // 1 disc + 16 seeds + 98 zero-DoD bits (~13 bytes) — far below raw 800.
        assert!(
            out.len() < 40,
            "expected heavy compression, got {} bytes",
            out.len()
        );
    }

    #[test]
    fn bucket_edges_roundtrip() {
        // Consecutive DoDs engineered to hit every bucket boundary.
        let dods: [i64; 12] = [0, 1, -1, 63, -64, 64, 255, -256, 256, 2047, -2048, 2048];
        let mut values = vec![0i64, 10];
        let mut delta = 10i64;
        let mut prev = 10i64;
        for dod in dods {
            delta += dod;
            prev += delta;
            values.push(prev);
        }
        let out = roundtrip(&values);
        assert_eq!(out[0], ENCODING_GORILLA);
    }

    #[test]
    fn extreme_i32_dod_still_gorilla() {
        let out = roundtrip(&[0, 0, i32::MAX as i64]);
        assert_eq!(out[0], ENCODING_GORILLA);
        let out = roundtrip(&[0, 0, i32::MIN as i64]);
        assert_eq!(out[0], ENCODING_GORILLA);
    }

    #[test]
    fn dod_overflow_falls_back_to_raw() {
        let values = [0i64, 0, i64::MAX];
        let out = roundtrip(&values);
        assert_eq!(out[0], ENCODING_UNCOMPRESSED);
        assert_eq!(out.len(), 1 + values.len() * 8);
    }

    #[test]
    fn short_columns_stay_raw() {
        for values in [&[][..], &[7i64][..], &[7i64, 8][..]] {
            let out = roundtrip(values);
            assert_eq!(out[0], ENCODING_UNCOMPRESSED);
            assert_eq!(out.len(), 1 + values.len() * 8);
        }
    }

    #[test]
    fn negative_values_roundtrip() {
        roundtrip(&[-5_000_000i64, -3_000_000, -1_500_000, -100, 42]);
    }

    #[test]
    fn i64_extremes_roundtrip_via_wrapping() {
        // Deltas overflow i64, but wrapping encode matches wrapping decode.
        roundtrip(&[i64::MIN, i64::MAX, i64::MIN, i64::MIN + 5, i64::MIN + 10]);
    }
}
