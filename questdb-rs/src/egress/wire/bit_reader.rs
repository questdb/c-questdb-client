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

//! LSB-first bit reader for Gorilla-compressed columns.
//!
//! Mirrors `QwpBitReader.java`: bytes are pulled from the underlying slice
//! lazily into a 64-bit window; bits consume from the low end. Reads past
//! the end surface as `ProtocolError`.

use crate::error::{Result, fmt};

/// Borrowed bit reader over `&[u8]`. LSB-first within each byte.
pub struct BitReader<'a> {
    bytes: &'a [u8],
    /// Next byte to pull into the window.
    byte_pos: usize,
    /// Sliding bit window. Low `bits_in_window` bits are valid.
    window: u64,
    bits_in_window: u32,
    /// Total bits consumed via `read_bit` / `read_bits`.
    bits_read: u64,
    /// Total bits available (byte length × 8).
    bits_total: u64,
}

impl<'a> BitReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_pos: 0,
            window: 0,
            bits_in_window: 0,
            bits_read: 0,
            bits_total: (bytes.len() as u64) * 8,
        }
    }

    /// Total bits consumed so far.
    pub fn bit_position(&self) -> u64 {
        self.bits_read
    }

    /// Bytes consumed so far, rounded up — useful for advancing an outer
    /// byte cursor past the bitstream.
    pub fn bytes_consumed(&self) -> usize {
        self.bits_read.div_ceil(8) as usize
    }

    /// Read one bit (0 or 1).
    #[inline]
    pub fn read_bit(&mut self) -> Result<u8> {
        if self.bits_read >= self.bits_total {
            return Err(fmt!(ProtocolError, "BitReader: read past end"));
        }
        if !self.ensure_bits(1) {
            return Err(fmt!(ProtocolError, "BitReader: read past end"));
        }
        let bit = (self.window & 1) as u8;
        self.window >>= 1;
        self.bits_in_window -= 1;
        self.bits_read += 1;
        Ok(bit)
    }

    /// Read `n` bits LSB-first as an unsigned integer in the low bits.
    #[inline]
    pub fn read_bits(&mut self, n: u32) -> Result<u64> {
        if n == 0 {
            return Ok(0);
        }
        if n > 64 {
            return Err(fmt!(
                ProtocolError,
                "BitReader: cannot read {} bits into u64",
                n
            ));
        }
        if self.bits_read + n as u64 > self.bits_total {
            return Err(fmt!(ProtocolError, "BitReader: read past end"));
        }

        let mut result: u64 = 0;
        let mut remaining = n;
        let mut shift: u32 = 0;
        while remaining > 0 {
            if self.bits_in_window == 0 {
                let want = remaining.min(64);
                if !self.ensure_bits(want) {
                    return Err(fmt!(ProtocolError, "BitReader: read past end"));
                }
            }
            let take = remaining.min(self.bits_in_window);
            let mask = if take == 64 {
                u64::MAX
            } else {
                (1u64 << take) - 1
            };
            result |= (self.window & mask) << shift;
            // Avoid the `>>= 64` no-op pitfall.
            if take == 64 {
                self.window = 0;
            } else {
                self.window >>= take;
            }
            self.bits_in_window -= take;
            remaining -= take;
            shift += take;
        }
        self.bits_read += n as u64;
        Ok(result)
    }

    /// Read `n` bits and sign-extend (two's complement). `n` must be ≤ 64.
    #[inline]
    pub fn read_signed(&mut self, n: u32) -> Result<i64> {
        let unsigned = self.read_bits(n)?;
        if n == 0 || n == 64 {
            return Ok(unsigned as i64);
        }
        let sign_bit = 1u64 << (n - 1);
        let extended = if unsigned & sign_bit != 0 {
            unsigned | (u64::MAX << n)
        } else {
            unsigned
        };
        Ok(extended as i64)
    }

    /// Pull bytes into the window until at least `want` bits are buffered or
    /// the source runs dry. Returns whether the demand was satisfied.
    #[inline]
    fn ensure_bits(&mut self, want: u32) -> bool {
        while self.bits_in_window < want
            && self.bits_in_window <= 56
            && self.byte_pos < self.bytes.len()
        {
            let b = self.bytes[self.byte_pos] as u64;
            self.byte_pos += 1;
            self.window |= b << self.bits_in_window;
            self.bits_in_window += 8;
        }
        self.bits_in_window >= want
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCode;

    #[test]
    fn single_bits_lsb_first() {
        // Byte 0b1010_0001: bits are read low-to-high → 1, 0, 0, 0, 0, 1, 0, 1
        let bytes = [0b1010_0001u8];
        let mut r = BitReader::new(&bytes);
        let order = [1, 0, 0, 0, 0, 1, 0, 1];
        for (i, expected) in order.iter().enumerate() {
            assert_eq!(r.read_bit().unwrap(), *expected, "bit {}", i);
        }
        // Past-end yields an error.
        assert_eq!(r.read_bit().unwrap_err().code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn read_bits_groups_lsb_first() {
        // Two bytes: 0xAC, 0x02 (the canonical varint(300) but interpreted
        // here as a raw bit stream). Read 8 bits → 0xAC, then 4 bits → 0x02 & 0xF = 0x02.
        let bytes = [0xAC, 0x02];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(8).unwrap(), 0xAC);
        assert_eq!(r.read_bits(4).unwrap(), 0x02);
    }

    #[test]
    fn read_bits_spans_byte_boundary() {
        // 0xFF 0x01 → first 12 bits LSB-first = 0b0001_1111_1111 = 0x1FF.
        let bytes = [0xFF, 0x01];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(12).unwrap(), 0x1FF);
    }

    #[test]
    fn read_signed_sign_extends() {
        // 7-bit value 0b1000000 (0x40) → signed -64.
        let bytes = [0x40];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_signed(7).unwrap(), -64);

        // 7-bit value 0b0111111 (63) → +63.
        let bytes = [0b0011_1111];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_signed(7).unwrap(), 63);
    }

    #[test]
    fn read_64_bits_works() {
        let bytes = 0x0102_0304_0506_0708u64.to_le_bytes();
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(64).unwrap(), 0x0102_0304_0506_0708);
        assert!(r.read_bit().is_err()); // exhausted
    }

    #[test]
    fn bit_position_and_bytes_consumed() {
        let bytes = [0xFFu8, 0xFF, 0xFF];
        let mut r = BitReader::new(&bytes);
        let _ = r.read_bits(13).unwrap();
        assert_eq!(r.bit_position(), 13);
        assert_eq!(r.bytes_consumed(), 2); // ceil(13/8) = 2
    }

    #[test]
    fn n_zero_returns_zero() {
        let bytes = [0u8; 0];
        let mut r = BitReader::new(&bytes);
        assert_eq!(r.read_bits(0).unwrap(), 0);
        assert_eq!(r.bit_position(), 0);
    }

    #[test]
    fn over_64_bits_rejected() {
        let bytes = [0u8; 16];
        let mut r = BitReader::new(&bytes);
        assert_eq!(
            r.read_bits(65).unwrap_err().code(),
            ErrorCode::ProtocolError
        );
    }

    #[test]
    fn read_past_end_in_read_bits_errors() {
        let bytes = [0xFFu8];
        let mut r = BitReader::new(&bytes);
        let _ = r.read_bits(7).unwrap();
        assert!(r.read_bits(2).is_err()); // would need 9 bits total, have 8
    }
}
