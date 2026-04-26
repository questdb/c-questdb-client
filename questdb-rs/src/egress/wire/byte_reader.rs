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

//! Bounds-checked sequential reader over an untrusted byte slice.
//!
//! Used by the various message decoders so each one can stay focused on
//! the layout instead of repeating bounds-check boilerplate. All reads
//! return [`Error`](crate::egress::Error) with [`ErrorCode::ProtocolError`]
//! on underrun.

use crate::egress::error::{Result, fmt};
use crate::egress::wire::varint;

pub(crate) struct ByteReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> &'a [u8] {
        &self.bytes[self.pos..]
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    pub(crate) fn advance(&mut self, n: usize) -> Result<()> {
        let new_pos = self
            .pos
            .checked_add(n)
            .ok_or_else(|| fmt!(ProtocolError, "byte reader pos overflow"))?;
        if new_pos > self.bytes.len() {
            return Err(fmt!(
                ProtocolError,
                "frame truncated: need {} bytes, have {}",
                n,
                self.bytes.len() - self.pos
            ));
        }
        self.pos = new_pos;
        Ok(())
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.bytes.len() {
            return Err(fmt!(ProtocolError, "frame truncated reading u8"));
        }
        let v = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub(crate) fn read_u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_bytes(2)?.try_into().unwrap()))
    }

    pub(crate) fn read_u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_bytes(4)?.try_into().unwrap()))
    }

    pub(crate) fn read_u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    pub(crate) fn read_i64_le(&mut self) -> Result<i64> {
        Ok(i64::from_le_bytes(self.read_bytes(8)?.try_into().unwrap()))
    }

    pub(crate) fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| fmt!(ProtocolError, "byte reader pos overflow"))?;
        if end > self.bytes.len() {
            return Err(fmt!(
                ProtocolError,
                "frame truncated: need {} bytes, have {}",
                n,
                self.bytes.len() - self.pos
            ));
        }
        let s = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub(crate) fn read_varint_u64(&mut self) -> Result<u64> {
        let (v, n) = varint::decode_u64(self.remaining())?;
        self.advance(n)?;
        Ok(v)
    }

    pub(crate) fn read_varint_usize(&mut self) -> Result<usize> {
        let (v, n) = varint::decode_usize(self.remaining())?;
        self.advance(n)?;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;

    #[test]
    fn reads_in_order() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_u8().unwrap(), 0xDE);
        assert_eq!(r.read_u8().unwrap(), 0xAD);
        assert_eq!(r.read_u16_le().unwrap(), 0xEFBE);
        assert_eq!(r.read_u32_le().unwrap(), 0x04030201);
        assert_eq!(r.read_u8().unwrap(), 0x05);
        assert!(r.is_empty());
    }

    #[test]
    fn truncation_is_protocol_error() {
        let bytes = [0x01u8, 0x02];
        let mut r = ByteReader::new(&bytes);
        let err = r.read_u32_le().unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn varint_via_reader() {
        // varint(300) = 0xAC, 0x02
        let bytes = [0xAC, 0x02, 0xFF];
        let mut r = ByteReader::new(&bytes);
        assert_eq!(r.read_varint_u64().unwrap(), 300);
        assert_eq!(r.remaining(), &[0xFF]);
    }
}
