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

/// LSB-first bit writer appending to a byte vector.
struct BitWriter<'a> {
    out: &'a mut Vec<u8>,
    cur: u8,
    nbits: u8,
}

impl<'a> BitWriter<'a> {
    fn new(out: &'a mut Vec<u8>) -> Self {
        Self {
            out,
            cur: 0,
            nbits: 0,
        }
    }

    #[inline]
    fn write_bit(&mut self, bit: u8) {
        self.cur |= (bit & 1) << self.nbits;
        self.nbits += 1;
        if self.nbits == 8 {
            self.out.push(self.cur);
            self.cur = 0;
            self.nbits = 0;
        }
    }

    #[inline]
    fn write_bits(&mut self, value: u64, n: u32) {
        for i in 0..n {
            self.write_bit(((value >> i) & 1) as u8);
        }
    }

    /// Write the low `n` bits of `v`'s two's-complement representation.
    #[inline]
    fn write_signed(&mut self, v: i64, n: u32) {
        self.write_bits((v as u64) & ((1u64 << n) - 1), n);
    }

    /// Flush the trailing partial byte (zero-padded high bits).
    fn finish(self) {
        if self.nbits > 0 {
            self.out.push(self.cur);
        }
    }
}

fn encode_dod(w: &mut BitWriter<'_>, dod: i64) {
    if dod == 0 {
        w.write_bit(0);
    } else if (-64..=63).contains(&dod) {
        w.write_bits(0b01, 2);
        w.write_signed(dod, 7);
    } else if (-256..=255).contains(&dod) {
        w.write_bits(0b011, 3);
        w.write_signed(dod, 9);
    } else if (-2048..=2047).contains(&dod) {
        w.write_bits(0b0111, 4);
        w.write_signed(dod, 12);
    } else {
        w.write_bits(0b1111, 4);
        w.write_signed(dod, 32);
    }
}

/// True when every delta-of-delta of `values` fits the i32 bucket, i.e. the
/// sequence is Gorilla-encodable. Caller ensures the iterator yields ≥ 3
/// values (shorter sequences ship raw regardless).
fn gorilla_feasible(mut values: impl Iterator<Item = i64>) -> bool {
    let Some(first) = values.next() else {
        return false;
    };
    let Some(second) = values.next() else {
        return false;
    };
    let mut prev = second;
    let mut prev_delta = second.wrapping_sub(first);
    for v in values {
        let delta = v.wrapping_sub(prev);
        let dod = delta.wrapping_sub(prev_delta);
        if dod < i32::MIN as i64 || dod > i32::MAX as i64 {
            return false;
        }
        prev_delta = delta;
        prev = v;
    }
    true
}

/// Encode ≥ 3 values as two raw LE seeds + DoD bitstream. Caller must have
/// verified feasibility via [`gorilla_feasible`].
fn encode_gorilla(out: &mut Vec<u8>, mut values: impl Iterator<Item = i64>) {
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
        encode_dod(&mut w, dod);
        prev_delta = delta;
        prev = v;
    }
    w.finish();
}

/// Write one temporal column's payload: discriminator byte + dense non-null
/// values. Gorilla when `count > 2` and every DoD fits i32; raw otherwise.
///
/// `make_values` is called up to twice (feasibility pass + encode pass) and
/// must yield exactly `count` identical values each time.
///
/// Output never exceeds `1 + count * 8` bytes, so callers whose frame-size
/// estimates already cover the raw layout only need one extra byte per
/// temporal column to keep their up-front `try_reserve` an upper bound.
pub(crate) fn write_temporal_column<I>(out: &mut Vec<u8>, count: usize, make_values: impl Fn() -> I)
where
    I: Iterator<Item = i64>,
{
    if count > 2 && gorilla_feasible(make_values()) {
        out.push(ENCODING_GORILLA);
        encode_gorilla(out, make_values());
    } else {
        out.push(ENCODING_UNCOMPRESSED);
        out.reserve(count * 8);
        for v in make_values() {
            out.extend_from_slice(&v.to_le_bytes());
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
                rest.chunks_exact(8)
                    .map(|c| i64::from_le_bytes(c.try_into().unwrap()))
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
