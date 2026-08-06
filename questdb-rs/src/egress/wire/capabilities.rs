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

//! `SERVER_INFO` (0x18) capability bits. See wire-egress.md §11.8.
//!
//! A server or client with no extensions sets `capabilities` to zero. Each
//! defined bit gates an optional trailing field or a protocol extension. A
//! client MUST ignore any capability bit it doesn't recognise — newer fields
//! are always appended after the existing layout, so a reader that knows only
//! the older bits sees the same prefix it always did.

/// Server appends `zone_id_len: uint16` + `zone_id: bytes` after `node_id`.
/// Identifies the server's geographic / logical zone (e.g. `eu-west-1a`,
/// `dc-amsterdam`); used by clients with `zone=` set on the connection
/// string to prefer same-zone endpoints. See failover.md §2 and §5.
pub const CAP_ZONE: u32 = 0x0000_0001;

/// True if the given capabilities word advertises a trailing `zone_id`.
pub fn has_zone(capabilities: u32) -> bool {
    capabilities & CAP_ZONE != 0
}

/// Server parses the optional `query_flags: varint` trailer appended to
/// `QUERY_REQUEST` after the bind section. Clients append the trailer only
/// when this bit is set, so a server without it sees the baseline layout.
pub const CAP_QUERY_FLAGS: u32 = 0x0000_0002;

/// True if the server parses the `QUERY_REQUEST` `query_flags` trailer.
pub fn has_query_flags(capabilities: u32) -> bool {
    capabilities & CAP_QUERY_FLAGS != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_zone_predicate() {
        assert!(!has_zone(0));
        assert!(has_zone(CAP_ZONE));
        // Future bits set alongside CAP_ZONE must still trip the predicate.
        assert!(has_zone(CAP_ZONE | 0x8000_0000));
        // Future bits with CAP_ZONE clear must not trip it.
        assert!(!has_zone(0xFFFF_FFFE));
    }
}
