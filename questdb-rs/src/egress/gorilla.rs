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

use crate::egress::error::Result;
use crate::egress::wire::bit_reader::BitReader;

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
}
