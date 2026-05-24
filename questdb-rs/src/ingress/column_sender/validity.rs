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

//! Validity bitmap helpers for the column-major sender.
//!
//! Users pass validity in **Arrow shape**: bit = 1 means valid, LSB-first
//! inside each byte. The QWP wire shape is the inverse: bit = 1 means
//! NULL. The conversion happens here; helpers below also count non-null
//! rows and stream Arrow-bit-set positions for the gather path.

use crate::{Result, error};

/// Public validity bitmap. See `doc/COLUMN_SENDER_FFI_ABI.md` §2.4 for the
/// Arrow semantics the API accepts.
#[derive(Debug)]
pub struct Validity<'a> {
    pub(crate) bits: &'a [u8],
    pub(crate) bit_len: usize,
}

impl<'a> Validity<'a> {
    /// Borrow `bits` as a validity bitmap of length `bit_len` rows.
    ///
    /// `bits.len()` must be at least `ceil(bit_len / 8)`. Bits past
    /// `bit_len` are ignored by the encoder, so callers do not need to
    /// zero them.
    pub fn from_bitmap(bits: &'a [u8], bit_len: usize) -> Result<Self> {
        let required_bytes = bit_len.div_ceil(8);
        if bits.len() < required_bytes {
            return Err(error::fmt!(
                InvalidApiCall,
                "validity bitmap too short: {} bytes for {} bits (need at least {})",
                bits.len(),
                bit_len,
                required_bytes
            ));
        }
        Ok(Self { bits, bit_len })
    }

    /// Logical length in bits / rows.
    pub fn bit_len(&self) -> usize {
        self.bit_len
    }

    /// `true` iff bit `idx` is set (row `idx` is **valid**, Arrow shape).
    #[inline]
    pub(crate) fn is_valid(&self, idx: usize) -> bool {
        debug_assert!(idx < self.bit_len);
        let byte = self.bits[idx / 8];
        (byte >> (idx % 8)) & 1 == 1
    }

    /// Count non-null (i.e. valid) rows.
    pub(crate) fn non_null_count(&self) -> usize {
        let full_bytes = self.bit_len / 8;
        let trailing_bits = self.bit_len % 8;
        let mut count: usize = 0;
        for &byte in &self.bits[..full_bytes] {
            count += byte.count_ones() as usize;
        }
        if trailing_bits != 0 {
            let mask = (1u8 << trailing_bits) - 1;
            count += (self.bits[full_bytes] & mask).count_ones() as usize;
        }
        count
    }

    /// Write the QWP-shape null bitmap (bit = 1 means NULL) for this
    /// validity into `out`. Always writes `ceil(bit_len / 8)` bytes; the
    /// last byte's high bits past `bit_len` are masked to zero.
    pub(crate) fn write_qwp_bitmap(&self, out: &mut Vec<u8>) {
        let full_bytes = self.bit_len / 8;
        let trailing_bits = self.bit_len % 8;
        for &byte in &self.bits[..full_bytes] {
            out.push(!byte);
        }
        if trailing_bits != 0 {
            let mask = (1u8 << trailing_bits) - 1;
            let inverted = !self.bits[full_bytes] & mask;
            out.push(inverted);
        }
    }
}

/// Validate that a caller-supplied `data` length matches a chunk's locked
/// row count and any validity bitmap. Returns the row count to use.
pub(crate) fn check_row_count(
    locked: Option<usize>,
    data_len: usize,
    validity: Option<&Validity<'_>>,
) -> Result<usize> {
    let row_count = data_len;
    if let Some(existing) = locked
        && existing != row_count
    {
        return Err(error::fmt!(
            InvalidApiCall,
            "Column length mismatch: chunk row_count is {} but this column has {} rows",
            existing,
            row_count
        ));
    }
    if let Some(v) = validity
        && v.bit_len != row_count
    {
        return Err(error::fmt!(
            InvalidApiCall,
            "Validity bitmap length ({} bits) does not match column data length ({} rows)",
            v.bit_len,
            row_count
        ));
    }
    Ok(row_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_null_count_handles_trailing_bits() {
        // 9 bits: 0b1010_1010, 0b0000_0001 — bits 1,3,5,7 valid in byte 0;
        // bit 8 (== row 8) valid in byte 1.  Trailing bits past row 8 must
        // be masked.
        let bits = [0b1010_1010, 0xFFu8]; // second byte has every bit set
        let v = Validity::from_bitmap(&bits, 9).unwrap();
        assert_eq!(v.non_null_count(), 4 + 1);
    }

    #[test]
    fn write_qwp_bitmap_inverts_arrow_semantics() {
        // Arrow: bit=1 valid. QWP wire: bit=1 NULL. Trailing high bits of
        // the last byte are masked to 0.
        let bits = [0b1100_1100, 0b0000_0011];
        let v = Validity::from_bitmap(&bits, 12).unwrap();
        let mut out = Vec::new();
        v.write_qwp_bitmap(&mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], !0b1100_1100);
        // Last byte: invert and mask to 4 valid bits (rows 8..12).
        assert_eq!(out[1], (!0b0000_0011) & 0b0000_1111);
    }

    #[test]
    fn from_bitmap_rejects_short_buffer() {
        let err = Validity::from_bitmap(&[0u8], 9).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::InvalidApiCall);
    }
}
