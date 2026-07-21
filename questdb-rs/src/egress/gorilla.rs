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

//! Gorilla delta-of-delta decoder for `TIMESTAMP` / `TIMESTAMP_NANOS` /
//! `DATE` columns when `FLAG_GORILLA` is set on the message.
//!
//! Bit format (LSB-first inside each byte):
//!
//! ```text
//! '0'                     -> DoD = 0                   (1 bit)
//! '10' + 7-bit signed     -> DoD in [-64, 63]          (9 bits)
//! '110' + 9-bit signed    -> DoD in [-256, 255]        (12 bits)
//! '1110' + 12-bit signed  -> DoD in [-2048, 2047]      (16 bits)
//! '1111' + 32-bit signed  -> any other DoD             (36 bits)
//! ```
//!
//! Where `DoD = delta_i - delta_{i-1}`. The first two timestamps are shipped
//! uncompressed at the head of the column body (16 bytes); they seed the
//! state and all subsequent values are reconstructed via the bitstream.

use crate::egress::wire::bit_reader::BitReader;
use crate::error::Result;

/// Stateful decoder that consumes a Gorilla bitstream.
pub struct GorillaDecoder<'a> {
    reader: BitReader<'a>,
    prev_delta: i64,
    prev_ts: i64,
}

impl<'a> GorillaDecoder<'a> {
    /// Initialise from the two uncompressed seed timestamps and the
    /// remaining bitstream bytes.
    pub fn new(first_ts: i64, second_ts: i64, bitstream: &'a [u8]) -> Self {
        Self {
            reader: BitReader::new(bitstream),
            prev_delta: second_ts.wrapping_sub(first_ts),
            prev_ts: second_ts,
        }
    }

    /// Decode the next timestamp.
    #[inline]
    pub fn decode_next(&mut self) -> Result<i64> {
        let dod = self.decode_dod()?;
        let delta = self.prev_delta.wrapping_add(dod);
        let ts = self.prev_ts.wrapping_add(delta);
        self.prev_delta = delta;
        self.prev_ts = ts;
        Ok(ts)
    }

    /// Bytes consumed from the bitstream so far (rounded up).
    pub fn bytes_consumed(&self) -> usize {
        self.reader.bytes_consumed()
    }

    #[inline]
    fn decode_dod(&mut self) -> Result<i64> {
        if self.reader.read_bit()? == 0 {
            return Ok(0);
        }
        if self.reader.read_bit()? == 0 {
            return self.reader.read_signed(7);
        }
        if self.reader.read_bit()? == 0 {
            return self.reader.read_signed(9);
        }
        if self.reader.read_bit()? == 0 {
            return self.reader.read_signed(12);
        }
        self.reader.read_signed(32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny encoder mirror for tests — writes the same bit format as
    /// `QwpGorillaEncoder.java` but only what the unit tests below need.
    /// Helpers keep the bytes purely for round-trip verification.
    struct GorillaEncoder {
        bytes: Vec<u8>,
        cur_byte: u8,
        bits: u32,
    }

    impl GorillaEncoder {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                cur_byte: 0,
                bits: 0,
            }
        }

        fn write_bit(&mut self, b: u8) {
            self.cur_byte |= (b & 1) << self.bits;
            self.bits += 1;
            if self.bits == 8 {
                self.bytes.push(self.cur_byte);
                self.cur_byte = 0;
                self.bits = 0;
            }
        }

        fn write_bits(&mut self, value: u64, n: u32) {
            for i in 0..n {
                self.write_bit(((value >> i) & 1) as u8);
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.bits > 0 {
                self.bytes.push(self.cur_byte);
            }
            self.bytes
        }

        fn write_dod(&mut self, dod: i64) {
            if dod == 0 {
                self.write_bit(0);
            } else if (-64..=63).contains(&dod) {
                self.write_bits(0b01, 2);
                self.write_bits((dod & 0x7F) as u64, 7);
            } else if (-256..=255).contains(&dod) {
                self.write_bits(0b011, 3);
                self.write_bits((dod & 0x1FF) as u64, 9);
            } else if (-2048..=2047).contains(&dod) {
                self.write_bits(0b0111, 4);
                self.write_bits((dod & 0xFFF) as u64, 12);
            } else {
                self.write_bits(0b1111, 4);
                self.write_bits((dod & 0xFFFF_FFFF) as u64, 32);
            }
        }
    }

    fn roundtrip(timestamps: &[i64]) {
        assert!(timestamps.len() >= 3);
        let first = timestamps[0];
        let second = timestamps[1];

        // Encode DoDs.
        let mut prev_delta = second.wrapping_sub(first);
        let mut prev_ts = second;
        let mut enc = GorillaEncoder::new();
        for &ts in &timestamps[2..] {
            let delta = ts.wrapping_sub(prev_ts);
            let dod = delta.wrapping_sub(prev_delta);
            enc.write_dod(dod);
            prev_delta = delta;
            prev_ts = ts;
        }
        let bitstream = enc.finish();

        // Decode and compare.
        let mut dec = GorillaDecoder::new(first, second, &bitstream);
        for (i, &expected) in timestamps[2..].iter().enumerate() {
            let got = dec.decode_next().unwrap();
            assert_eq!(got, expected, "row {}", i + 2);
        }
    }

    #[test]
    fn dod_zero_path() {
        // Constant delta → all DoDs = 0 → '0' bit each.
        roundtrip(&[1_000, 1_100, 1_200, 1_300, 1_400, 1_500]);
    }

    #[test]
    fn small_jitter_uses_7_bit_bucket() {
        // Deltas ~100 with small wobble → DoD in [-64, 63].
        roundtrip(&[1_000, 1_100, 1_205, 1_298, 1_402, 1_499]);
    }

    #[test]
    fn larger_jumps_use_higher_buckets() {
        roundtrip(&[
            1_000, 1_100, 1_500, 2_000, 2_700, 3_300, 4_500, 8_000, 100_000, 1_000_000,
        ]);
    }

    #[test]
    fn extreme_dod_uses_32_bit_bucket() {
        // Large but i32-fitting jump forces the 32-bit bucket.
        // DoD here is on the order of 10^9, well above the 12-bit bucket
        // range, but stays within i32::MAX.
        roundtrip(&[0i64, 100, 200, 1_000_000_000, 1_000_000_100]);
    }

    #[test]
    fn negative_dod_signed_correctly() {
        roundtrip(&[1_000, 1_100, 1_150, 1_180, 1_190, 1_195]);
    }

    #[test]
    fn dense_timestamps_nanos() {
        // Realistic ns timestamps: ~1µs spacing with occasional jitter.
        let base = 1_700_000_000_000_000_000i64;
        let mut ts = Vec::new();
        for i in 0..32i64 {
            ts.push(base + i * 1_000 + (i % 5));
        }
        roundtrip(&ts);
    }

    #[test]
    fn read_past_end_errors() {
        let mut dec = GorillaDecoder::new(0, 100, &[]);
        assert!(dec.decode_next().is_err());
    }

    // ------------------------------------------------------------------
    // Fixed-vector tests
    //
    // The roundtrip tests above use an in-test encoder that mirrors the
    // decoder. A symmetric encoder/decoder shift bug (e.g. both reading
    // and writing 8 bits where the spec says 7) would round-trip
    // cleanly but disagree with the server. The tests below pin the
    // expected bitstream BYTES for each bucket — independent of the
    // in-test encoder — so the wire contract is anchored against
    // hand-coded layouts.
    // ------------------------------------------------------------------

    /// Pack a sequence of `0`/`1` bits into bytes LSB-first inside each
    /// byte (matches the Gorilla wire layout described at the top of
    /// this file). Independent of `GorillaEncoder`, so the resulting
    /// bytes are a true fixed vector.
    fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; bits.len().div_ceil(8).max(1)];
        for (i, &b) in bits.iter().enumerate() {
            bytes[i / 8] |= (b & 1) << (i % 8);
        }
        bytes
    }

    /// Seed the decoder so that `prev_delta = 0`, `prev_ts = 0`. Then a
    /// single decoded timestamp equals the DoD itself: ts = 0 + (0 + dod).
    fn decode_one_dod(bitstream: &[u8]) -> i64 {
        let mut dec = GorillaDecoder::new(0, 0, bitstream);
        dec.decode_next().unwrap()
    }

    /// Append the LSB-first bits of `value` (`n` bits, sign-truncated)
    /// to `bits`.
    fn push_bits_le(bits: &mut Vec<u8>, value: i64, n: u32) {
        let mask: u64 = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
        let v = (value as u64) & mask;
        for i in 0..n {
            bits.push(((v >> i) & 1) as u8);
        }
    }

    #[test]
    fn fixed_vector_dod_zero() {
        // Wire layout: just the single '0' bit. After flushing, byte 0
        // has bit 0 unset; the decoder reads bit 0 and returns DoD=0.
        let bs = bits_to_bytes(&[0]);
        assert_eq!(bs, vec![0x00]);
        assert_eq!(decode_one_dod(&bs), 0);
    }

    #[test]
    fn fixed_vector_seven_bit_bucket_min_max() {
        // 7-bit bucket: prefix '10' (bit0=1, bit1=0), then 7 bits of
        // `dod & 0x7F` LSB-first.
        for &dod in &[1i64, -1, 63, -64, 32, -32, 16, -16] {
            let mut bits = vec![1u8, 0u8];
            push_bits_le(&mut bits, dod, 7);
            let bs = bits_to_bytes(&bits);
            assert_eq!(decode_one_dod(&bs), dod, "dod={}", dod);
        }
    }

    #[test]
    fn fixed_vector_seven_bit_bucket_byte_layout() {
        // DoD = 1 (positive, smallest non-zero): bits = [1,0,1,0,0,0,0,0,0]
        // Byte 0: bits 0..=7 = [1,0,1,0,0,0,0,0] = 0x05
        // Byte 1: bit 0 = 0 → 0x00
        let bs = bits_to_bytes(&[1, 0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(bs, vec![0x05, 0x00]);
        assert_eq!(decode_one_dod(&bs), 1);

        // DoD = -64 (smallest negative, 7-bit two's complement = 0x40)
        // bits = [1,0, 0,0,0,0,0,0,1] → byte 0 = 0x01, byte 1 = 0x01
        let bs = bits_to_bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(bs, vec![0x01, 0x01]);
        assert_eq!(decode_one_dod(&bs), -64);
    }

    #[test]
    fn fixed_vector_nine_bit_bucket_boundary_64_minus_65() {
        // DoD = 64 must use the 9-bit bucket: prefix '110' (bit0=1,
        // bit1=1, bit2=0), then 9 bits of `64 & 0x1FF` LSB-first.
        let mut bits = vec![1u8, 1, 0];
        push_bits_le(&mut bits, 64, 9);
        let bs = bits_to_bytes(&bits);
        assert_eq!(decode_one_dod(&bs), 64);

        // DoD = -65 must also fall into the 9-bit bucket.
        let mut bits = vec![1u8, 1, 0];
        push_bits_le(&mut bits, -65, 9);
        let bs = bits_to_bytes(&bits);
        assert_eq!(decode_one_dod(&bs), -65);
    }

    #[test]
    fn fixed_vector_nine_bit_bucket_min_max() {
        // 9-bit bucket signed range: [-256, 255].
        for &dod in &[64i64, -65, 100, -100, 255, -256, 200, -200] {
            let mut bits = vec![1u8, 1, 0];
            push_bits_le(&mut bits, dod, 9);
            let bs = bits_to_bytes(&bits);
            assert_eq!(decode_one_dod(&bs), dod, "dod={}", dod);
        }
    }

    #[test]
    fn fixed_vector_twelve_bit_bucket_boundary_256_minus_257() {
        // DoD = 256 → 12-bit bucket: prefix '1110' (bit0..3 = 1,1,1,0),
        // then 12 bits LSB-first.
        let mut bits = vec![1u8, 1, 1, 0];
        push_bits_le(&mut bits, 256, 12);
        let bs = bits_to_bytes(&bits);
        assert_eq!(decode_one_dod(&bs), 256);

        let mut bits = vec![1u8, 1, 1, 0];
        push_bits_le(&mut bits, -257, 12);
        let bs = bits_to_bytes(&bits);
        assert_eq!(decode_one_dod(&bs), -257);
    }

    #[test]
    fn fixed_vector_twelve_bit_bucket_min_max() {
        // 12-bit bucket signed range: [-2048, 2047].
        for &dod in &[256i64, -257, 1000, -1000, 2047, -2048, 1500, -1500] {
            let mut bits = vec![1u8, 1, 1, 0];
            push_bits_le(&mut bits, dod, 12);
            let bs = bits_to_bytes(&bits);
            assert_eq!(decode_one_dod(&bs), dod, "dod={}", dod);
        }
    }

    #[test]
    fn fixed_vector_thirty_two_bit_bucket_boundary_2048_minus_2049() {
        // DoD = 2048 → 32-bit bucket: prefix '1111' (bit0..3 = all 1),
        // then 32 bits LSB-first of `dod as i32`.
        let mut bits = vec![1u8, 1, 1, 1];
        push_bits_le(&mut bits, 2048, 32);
        let bs = bits_to_bytes(&bits);
        assert_eq!(decode_one_dod(&bs), 2048);

        let mut bits = vec![1u8, 1, 1, 1];
        push_bits_le(&mut bits, -2049, 32);
        let bs = bits_to_bytes(&bits);
        assert_eq!(decode_one_dod(&bs), -2049);
    }

    #[test]
    fn fixed_vector_thirty_two_bit_extremes() {
        // The 32-bit bucket payload is sign-extended to i64 by
        // `BitReader::read_signed`. Pin behaviour at i32::MIN /
        // i32::MAX and a value near i32::MIN that would silently
        // lose its sign if `read_signed` zero-extended instead.
        for &dod in &[
            i32::MIN as i64,
            i32::MIN as i64 + 1,
            i32::MAX as i64,
            i32::MAX as i64 - 1,
            -1_000_000_000,
            1_000_000_000,
        ] {
            let mut bits = vec![1u8, 1, 1, 1];
            push_bits_le(&mut bits, dod, 32);
            let bs = bits_to_bytes(&bits);
            assert_eq!(decode_one_dod(&bs), dod, "dod={}", dod);
        }
    }
}
