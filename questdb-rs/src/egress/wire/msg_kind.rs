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

//! Message kind discriminator (first byte of frame payload).
//!
//! ABI-stable: variants append-only, never reorder.

use crate::egress::error::{Result, fmt};

/// Message kind code (uint8). `repr(u8)` keeps wire transcoding trivial.
///
/// `#[non_exhaustive]` because the QWP message-kind table is
/// append-only across protocol revisions.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MsgKind {
    /// Client → Server: initiate cursor with SQL + binds.
    QueryRequest = 0x10,
    /// Server → Client: one table block of results.
    ResultBatch = 0x11,
    /// Server → Client: successful stream termination.
    ResultEnd = 0x12,
    /// Server → Client: failure at any lifecycle point.
    QueryError = 0x13,
    /// Client → Server: request query termination.
    Cancel = 0x14,
    /// Client → Server: extend byte-credit window.
    Credit = 0x15,
    /// Server → Client: non-SELECT acknowledgement.
    ExecDone = 0x16,
    /// Server → Client: clear connection caches.
    CacheReset = 0x17,
    /// Server → Client: role + cluster identity (v2+).
    ServerInfo = 0x18,
}

impl MsgKind {
    /// Parse a wire byte into a known kind.
    pub fn from_u8(byte: u8) -> Result<Self> {
        Ok(match byte {
            0x10 => MsgKind::QueryRequest,
            0x11 => MsgKind::ResultBatch,
            0x12 => MsgKind::ResultEnd,
            0x13 => MsgKind::QueryError,
            0x14 => MsgKind::Cancel,
            0x15 => MsgKind::Credit,
            0x16 => MsgKind::ExecDone,
            0x17 => MsgKind::CacheReset,
            0x18 => MsgKind::ServerInfo,
            other => return Err(fmt!(ProtocolError, "unknown msg_kind 0x{:02X}", other)),
        })
    }

    /// Wire byte for this kind.
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// QWP status codes carried by `QUERY_ERROR` (and surfaced to clients).
///
/// `#[non_exhaustive]` because the status table is append-only across
/// protocol revisions.
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StatusCode {
    SchemaMismatch = 0x03,
    ParseError = 0x05,
    InternalError = 0x06,
    SecurityError = 0x08,
    Cancelled = 0x0A,
    LimitExceeded = 0x0B,
}

impl StatusCode {
    pub fn from_u8(byte: u8) -> Result<Self> {
        Ok(match byte {
            0x03 => StatusCode::SchemaMismatch,
            0x05 => StatusCode::ParseError,
            0x06 => StatusCode::InternalError,
            0x08 => StatusCode::SecurityError,
            0x0A => StatusCode::Cancelled,
            0x0B => StatusCode::LimitExceeded,
            other => {
                return Err(fmt!(
                    ProtocolError,
                    "unknown QWP status code 0x{:02X}",
                    other
                ));
            }
        })
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_kind_roundtrip() {
        for &k in &[
            MsgKind::QueryRequest,
            MsgKind::ResultBatch,
            MsgKind::ResultEnd,
            MsgKind::QueryError,
            MsgKind::Cancel,
            MsgKind::Credit,
            MsgKind::ExecDone,
            MsgKind::CacheReset,
            MsgKind::ServerInfo,
        ] {
            let b = k.as_u8();
            assert_eq!(MsgKind::from_u8(b).unwrap(), k);
        }
    }

    #[test]
    fn unknown_msg_kind_rejected() {
        assert!(MsgKind::from_u8(0x00).is_err());
        assert!(MsgKind::from_u8(0xFF).is_err());
        assert!(MsgKind::from_u8(0x09).is_err());
    }

    #[test]
    fn status_code_roundtrip() {
        for &s in &[
            StatusCode::SchemaMismatch,
            StatusCode::ParseError,
            StatusCode::InternalError,
            StatusCode::SecurityError,
            StatusCode::Cancelled,
            StatusCode::LimitExceeded,
        ] {
            assert_eq!(StatusCode::from_u8(s.as_u8()).unwrap(), s);
        }
    }
}
