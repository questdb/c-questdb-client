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

//! 12-byte QWP frame header. All multi-byte fields little-endian.
//!
//! ```text
//! Offset Size Field          Description
//! 0      4    magic          "QWP1" = 0x31_50_57_51 LE
//! 4      1    version        Negotiated QWP version
//! 5      1    flags          Per-message flag bits
//! 6      2    table_count    1 for RESULT_BATCH; 0 otherwise
//! 8      4    payload_length Payload size in bytes
//! ```

use crate::egress::error::{Result, fmt};

/// `"QWP1"` interpreted as a little-endian `u32`.
pub const MAGIC: u32 = u32::from_le_bytes(*b"QWP1");

/// The single QWP protocol version. Every frame's `version` byte is written
/// as this value and validated to equal it on parse.
pub const PROTOCOL_VERSION: u8 = 1;

/// Length of the wire frame header in bytes.
pub const HEADER_LEN: usize = 12;

/// Per-frame flag bits (`flags` byte).
pub mod flags {
    /// Timestamp/date columns may use delta-of-delta (Gorilla) encoding.
    pub const GORILLA: u8 = 0x04;
    /// `RESULT_BATCH` carries a delta symbol-dict section.
    pub const DELTA_SYMBOL_DICT: u8 = 0x08;
    /// Payload (after `msg_kind/request_id/batch_seq`) is zstd-compressed.
    pub const ZSTD: u8 = 0x10;
}

/// Parsed wire frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub version: u8,
    pub flags: u8,
    pub table_count: u16,
    pub payload_length: u32,
}

impl FrameHeader {
    /// Parse a header from exactly [`HEADER_LEN`] bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(fmt!(
                ProtocolError,
                "frame header truncated: got {} bytes, need {}",
                bytes.len(),
                HEADER_LEN
            ));
        }
        let magic = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if magic != MAGIC {
            return Err(fmt!(
                ProtocolError,
                "bad frame magic: 0x{:08X} (expected 0x{:08X})",
                magic,
                MAGIC
            ));
        }
        // QWP runs at a single version. Each frame fails fast on its own here,
        // independently of the negotiated version checked in `transport.rs`.
        let version = bytes[4];
        if version != PROTOCOL_VERSION {
            return Err(fmt!(
                ProtocolError,
                "unsupported QWP frame version {} (expected {})",
                version,
                PROTOCOL_VERSION
            ));
        }
        Ok(FrameHeader {
            version,
            flags: bytes[5],
            table_count: u16::from_le_bytes([bytes[6], bytes[7]]),
            payload_length: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        })
    }

    /// Serialize this header into the first [`HEADER_LEN`] bytes of `out`.
    ///
    /// The `version` byte is always written as [`PROTOCOL_VERSION`] — the only
    /// value [`FrameHeader::parse`] accepts — and `self.version` is
    /// debug-asserted to match, so a header built with a stale version can't
    /// serialize bytes this module would then refuse to parse.
    pub fn write(self, out: &mut [u8; HEADER_LEN]) {
        debug_assert_eq!(
            self.version, PROTOCOL_VERSION,
            "FrameHeader::write must only serialize the pinned protocol version"
        );
        out[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        out[4] = PROTOCOL_VERSION;
        out[5] = self.flags;
        out[6..8].copy_from_slice(&self.table_count.to_le_bytes());
        out[8..12].copy_from_slice(&self.payload_length.to_le_bytes());
    }

    /// Convenience: write into a fresh `[u8; 12]`.
    pub fn to_bytes(self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        self.write(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;

    #[test]
    fn magic_is_qwp1_le() {
        assert_eq!(&MAGIC.to_le_bytes(), b"QWP1");
    }

    #[test]
    fn roundtrip() {
        let h = FrameHeader {
            version: 1,
            flags: flags::GORILLA | flags::DELTA_SYMBOL_DICT,
            table_count: 1,
            payload_length: 0xDEAD_BEEF,
        };
        let bytes = h.to_bytes();
        let parsed = FrameHeader::parse(&bytes).unwrap();
        assert_eq!(parsed, h);
    }

    #[test]
    fn truncated_rejected() {
        let bytes = [0u8; HEADER_LEN - 1];
        assert_eq!(
            FrameHeader::parse(&bytes).unwrap_err().code(),
            ErrorCode::ProtocolError
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = [0u8; HEADER_LEN];
        bytes[0..4].copy_from_slice(b"NOPE");
        assert_eq!(
            FrameHeader::parse(&bytes).unwrap_err().code(),
            ErrorCode::ProtocolError
        );
    }

    #[test]
    fn wrong_version_rejected() {
        // Any version byte other than the pinned one — below it (0) or
        // above it (2, 0xFF) — must be rejected per-frame, independently
        // of the handshake-level check.
        let valid = FrameHeader {
            version: PROTOCOL_VERSION,
            flags: 0,
            table_count: 0,
            payload_length: 0,
        }
        .to_bytes();
        for wrong in [0u8, 2, 0xFF] {
            let mut bytes = valid;
            bytes[4] = wrong;
            let err = FrameHeader::parse(&bytes).unwrap_err();
            assert_eq!(err.code(), ErrorCode::ProtocolError);
            assert!(
                err.msg().contains(&format!("version {wrong}")),
                "message should name the rejected version {wrong}: {}",
                err.msg()
            );
        }
    }

    #[test]
    fn extra_bytes_ignored() {
        let h = FrameHeader {
            version: 1,
            flags: 0,
            table_count: 0,
            payload_length: 0,
        };
        let mut buf = vec![0u8; HEADER_LEN + 8];
        let mut hdr_buf = [0u8; HEADER_LEN];
        h.write(&mut hdr_buf);
        buf[..HEADER_LEN].copy_from_slice(&hdr_buf);
        let parsed = FrameHeader::parse(&buf).unwrap();
        assert_eq!(parsed, h);
    }
}
