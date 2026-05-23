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

//! Canonical `SERVER_INFO.role` byte values and matching ASCII tokens.
//!
//! Wire-egress.md §11.8 fixes the four role bytes; failover.md §5 fixes
//! the ASCII tokens used in the `X-QuestDB-Role` HTTP response header on
//! `421` upgrade rejects. Keeping both forms in one module is the
//! cross-language convention (mirrors `QwpEgressMsgKind` in the Java
//! reference client).

/// `STANDALONE` — single-node, no replication configured. OSS default;
/// routes as a primary.
pub const STANDALONE: u8 = 0x00;

/// `PRIMARY` — authoritative writer; reads see latest commits.
pub const PRIMARY: u8 = 0x01;

/// `REPLICA` — read-only follower; may lag the primary.
pub const REPLICA: u8 = 0x02;

/// `PRIMARY_CATCHUP` — promotion in flight; classifies as
/// `TransientReject` on the host tracker (see failover.md §2).
pub const PRIMARY_CATCHUP: u8 = 0x03;

/// Sentinel for unrecognised role names seen on a `421 + X-QuestDB-Role`
/// upgrade reject. Not a wire-defined value: the spec assigns 0x00..=0x03
/// today and reserves the rest, so `0xFF` will never collide with a future
/// named byte unless the spec also adds a new ASCII token. Callers
/// classify these via `role_name` (case-insensitive), not `role_byte`.
pub const UNKNOWN_NAME: u8 = 0xFF;

/// Wire-token for `STANDALONE` on `X-QuestDB-Role`.
pub const NAME_STANDALONE: &str = "STANDALONE";
/// Wire-token for `PRIMARY` on `X-QuestDB-Role`.
pub const NAME_PRIMARY: &str = "PRIMARY";
/// Wire-token for `REPLICA` on `X-QuestDB-Role`.
pub const NAME_REPLICA: &str = "REPLICA";
/// Wire-token for `PRIMARY_CATCHUP` on `X-QuestDB-Role`.
pub const NAME_PRIMARY_CATCHUP: &str = "PRIMARY_CATCHUP";

/// Map an uppercased role token (as seen on `X-QuestDB-Role`) to its wire
/// byte. Returns `None` for unrecognised tokens; callers use
/// [`UNKNOWN_NAME`] as the byte and classify via case-insensitive name
/// match. Caller is responsible for uppercasing.
pub fn byte_for_name(name: &str) -> Option<u8> {
    match name {
        NAME_STANDALONE => Some(STANDALONE),
        NAME_PRIMARY => Some(PRIMARY),
        NAME_REPLICA => Some(REPLICA),
        NAME_PRIMARY_CATCHUP => Some(PRIMARY_CATCHUP),
        _ => None,
    }
}

/// Map a role byte to its wire token. Returns `None` for unknown bytes;
/// callers render those as `UNKNOWN(<byte>)` or similar so the raw byte is
/// still recoverable from logs.
pub fn name_for_byte(byte: u8) -> Option<&'static str> {
    match byte {
        STANDALONE => Some(NAME_STANDALONE),
        PRIMARY => Some(NAME_PRIMARY),
        REPLICA => Some(NAME_REPLICA),
        PRIMARY_CATCHUP => Some(NAME_PRIMARY_CATCHUP),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_named_roles() {
        for (byte, name) in [
            (STANDALONE, NAME_STANDALONE),
            (PRIMARY, NAME_PRIMARY),
            (REPLICA, NAME_REPLICA),
            (PRIMARY_CATCHUP, NAME_PRIMARY_CATCHUP),
        ] {
            assert_eq!(byte_for_name(name), Some(byte));
            assert_eq!(name_for_byte(byte), Some(name));
        }
    }

    #[test]
    fn unknown_byte_and_name() {
        assert!(byte_for_name("FOO").is_none());
        assert!(byte_for_name("primary").is_none()); // caller must uppercase
        assert!(name_for_byte(0x04).is_none());
        assert!(name_for_byte(UNKNOWN_NAME).is_none());
    }

    #[test]
    fn byte_values_match_spec() {
        // Pin the wire bytes against wire-egress.md §11.8.
        assert_eq!(STANDALONE, 0x00);
        assert_eq!(PRIMARY, 0x01);
        assert_eq!(REPLICA, 0x02);
        assert_eq!(PRIMARY_CATCHUP, 0x03);
    }
}
