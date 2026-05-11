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

//! Server → client message decoders and the top-level [`decode_frame`]
//! dispatcher. RESULT_BATCH (`0x11`) decoding lives in
//! [`crate::egress::decoder`]; everything else is here.

use crate::egress::decoder::{DecodedBatch, ZstdScratch, decode_result_batch};
use crate::egress::error::{Result, fmt};
use crate::egress::schema::SchemaRegistry;
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::wire::ByteReader;
use crate::egress::wire::cache_reset::{resets_dict, resets_schemas};
use crate::egress::wire::header::FrameHeader;
use crate::egress::wire::msg_kind::{MsgKind, StatusCode};
use bytes::Bytes;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// QuestDB cluster role advertised by `SERVER_INFO` (v2+).
///
/// `#[non_exhaustive]` because new role bytes may be added in future
/// protocol revisions; a future revision might also promote a known
/// `Other(_)` byte to a named variant. Both should be additive.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ServerRole {
    Standalone,
    Primary,
    Replica,
    PrimaryCatchup,
    /// Forward-compat: a future role byte we don't recognise.
    Other(u8),
}

impl ServerRole {
    pub fn from_u8(byte: u8) -> Self {
        match byte {
            0x00 => ServerRole::Standalone,
            0x01 => ServerRole::Primary,
            0x02 => ServerRole::Replica,
            0x03 => ServerRole::PrimaryCatchup,
            other => ServerRole::Other(other),
        }
    }
}

/// Body of a `SERVER_INFO` frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    pub role: ServerRole,
    pub epoch: u64,
    pub capabilities: u32,
    pub server_wall_ns: i64,
    pub cluster_id: String,
    pub node_id: String,
}

/// Single decoded server message.
///
/// One frame in, one event out. The dispatcher applies state mutations
/// (symbol dict deltas, schema-registry inserts, cache resets) before
/// returning so callers can treat each event idempotently.
#[derive(Debug, Clone)]
pub enum ServerEvent {
    /// `RESULT_BATCH` (`0x11`).
    Batch(DecodedBatch),
    /// `RESULT_END` (`0x12`).
    End {
        request_id: i64,
        final_seq: u64,
        total_rows: u64,
    },
    /// `QUERY_ERROR` (`0x13`).
    Error {
        request_id: i64,
        status: StatusCode,
        message: String,
    },
    /// `EXEC_DONE` (`0x16`).
    ExecDone {
        request_id: i64,
        op_type: u8,
        rows_affected: u64,
    },
    /// `CACHE_RESET` (`0x17`). Mask bits already applied to dict/registry.
    CacheReset {
        // `mask` is matched literally by tests (pattern `mask: 0x01`)
        // but never read by the consumers — `decode_frame` performs
        // the resets in place before returning the event. Marked
        // `allow(dead_code)` so the wire-level visibility stays
        // honest without tripping `-D dead_code`.
        #[allow(dead_code)]
        mask: u8,
    },
    /// `SERVER_INFO` (`0x18`).
    ServerInfo(ServerInfo),
}

// ---------------------------------------------------------------------------
// Top-level dispatcher
// ---------------------------------------------------------------------------

/// Decode one full frame (already split into header + payload).
///
/// `dict` and `registry` are mutated in place where the message demands it
/// (delta dict, full schema, cache reset). The returned event is what the
/// caller's cursor / state machine should react to.
pub fn decode_frame(
    header: FrameHeader,
    payload: &Bytes,
    dict: &mut SymbolDict,
    registry: &mut SchemaRegistry,
    zstd_scratch: &mut ZstdScratch,
) -> Result<ServerEvent> {
    if payload.is_empty() {
        return Err(fmt!(ProtocolError, "frame payload is empty"));
    }
    let kind_byte = payload[0];
    let kind = MsgKind::from_u8(kind_byte)?;
    // Per `wire/header.rs`, `table_count` is `1` for `RESULT_BATCH` (the
    // only frame that carries an actual table block) and `0` everywhere
    // else. Catch frame-vs-kind drift up front rather than letting it
    // surface as a confusing per-message decode failure downstream.
    let expected_tc = if matches!(kind, MsgKind::ResultBatch) {
        1
    } else {
        0
    };
    if header.table_count != expected_tc {
        return Err(fmt!(
            ProtocolError,
            "frame for msg_kind 0x{:02X} has table_count {} (expected {})",
            kind_byte,
            header.table_count,
            expected_tc
        ));
    }
    match kind {
        MsgKind::ResultBatch => Ok(ServerEvent::Batch(decode_result_batch(
            payload,
            header.flags,
            dict,
            registry,
            zstd_scratch,
        )?)),
        MsgKind::ResultEnd => decode_result_end(payload),
        MsgKind::QueryError => decode_query_error(payload),
        MsgKind::ExecDone => decode_exec_done(payload),
        MsgKind::CacheReset => decode_cache_reset(payload, dict, registry),
        MsgKind::ServerInfo => decode_server_info(payload),
        // Server should never send these to us.
        MsgKind::QueryRequest | MsgKind::Cancel | MsgKind::Credit => Err(fmt!(
            ProtocolError,
            "server sent client-only message kind 0x{:02X}",
            kind_byte
        )),
    }
}

// ---------------------------------------------------------------------------
// Per-message decoders
// ---------------------------------------------------------------------------

fn decode_result_end(payload: &[u8]) -> Result<ServerEvent> {
    let mut r = ByteReader::new(payload);
    expect_kind(&mut r, MsgKind::ResultEnd)?;
    let request_id = r.read_i64_le()?;
    let final_seq = r.read_varint_u64()?;
    let total_rows = r.read_varint_u64()?;
    expect_eof(&r, "RESULT_END")?;
    Ok(ServerEvent::End {
        request_id,
        final_seq,
        total_rows,
    })
}

fn decode_query_error(payload: &[u8]) -> Result<ServerEvent> {
    let mut r = ByteReader::new(payload);
    expect_kind(&mut r, MsgKind::QueryError)?;
    let request_id = r.read_i64_le()?;
    let status = StatusCode::from_u8(r.read_u8()?)?;
    let msg_len = r.read_u16_le()? as usize;
    let bytes = r.read_bytes(msg_len)?;
    let message = std::str::from_utf8(bytes)
        .map_err(|e| fmt!(InvalidUtf8, "QUERY_ERROR message not valid UTF-8: {}", e))?
        .to_string();
    expect_eof(&r, "QUERY_ERROR")?;
    Ok(ServerEvent::Error {
        request_id,
        status,
        message,
    })
}

fn decode_exec_done(payload: &[u8]) -> Result<ServerEvent> {
    let mut r = ByteReader::new(payload);
    expect_kind(&mut r, MsgKind::ExecDone)?;
    let request_id = r.read_i64_le()?;
    let op_type = r.read_u8()?;
    let rows_affected = r.read_varint_u64()?;
    expect_eof(&r, "EXEC_DONE")?;
    Ok(ServerEvent::ExecDone {
        request_id,
        op_type,
        rows_affected,
    })
}

fn decode_cache_reset(
    payload: &[u8],
    dict: &mut SymbolDict,
    registry: &mut SchemaRegistry,
) -> Result<ServerEvent> {
    let mut r = ByteReader::new(payload);
    expect_kind(&mut r, MsgKind::CacheReset)?;
    let mask = r.read_u8()?;
    expect_eof(&r, "CACHE_RESET")?;
    // Per spec §11.7: "Reserved bits MUST be zero on transmit; recipients
    // MUST ignore any reserved bits that are set." Apply the bits we know;
    // ignore everything else so a future spec revision adding e.g.
    // `RESET_MASK_PREPARED` doesn't make older clients reject every
    // CACHE_RESET that carries the new bit alongside the known ones.
    if resets_dict(mask) {
        dict.reset();
    }
    if resets_schemas(mask) {
        registry.reset();
    }
    Ok(ServerEvent::CacheReset { mask })
}

fn decode_server_info(payload: &[u8]) -> Result<ServerEvent> {
    let mut r = ByteReader::new(payload);
    expect_kind(&mut r, MsgKind::ServerInfo)?;
    let role = ServerRole::from_u8(r.read_u8()?);
    let epoch = r.read_u64_le()?;
    let capabilities = r.read_u32_le()?;
    let server_wall_ns = r.read_i64_le()?;
    let cluster_id = read_u16_string(&mut r, "cluster_id")?;
    let node_id = read_u16_string(&mut r, "node_id")?;
    expect_eof(&r, "SERVER_INFO")?;
    Ok(ServerEvent::ServerInfo(ServerInfo {
        role,
        epoch,
        capabilities,
        server_wall_ns,
        cluster_id,
        node_id,
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn expect_kind(r: &mut ByteReader<'_>, expected: MsgKind) -> Result<()> {
    let got = r.read_u8()?;
    if got != expected.as_u8() {
        return Err(fmt!(
            ProtocolError,
            "expected msg_kind 0x{:02X}, got 0x{:02X}",
            expected.as_u8(),
            got
        ));
    }
    Ok(())
}

fn expect_eof(r: &ByteReader<'_>, msg_name: &str) -> Result<()> {
    if !r.is_empty() {
        return Err(fmt!(
            ProtocolError,
            "{} has {} trailing bytes",
            msg_name,
            r.remaining().len()
        ));
    }
    Ok(())
}

fn read_u16_string(r: &mut ByteReader<'_>, field: &str) -> Result<String> {
    let len = r.read_u16_le()? as usize;
    let bytes = r.read_bytes(len)?;
    std::str::from_utf8(bytes)
        .map_err(|e| fmt!(InvalidUtf8, "{} not valid UTF-8: {}", field, e))
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::error::ErrorCode;
    use crate::egress::wire::header::HEADER_LEN;
    use crate::egress::wire::varint::encode_u64;

    fn header(payload_len: usize) -> FrameHeader {
        FrameHeader {
            version: 2,
            flags: 0,
            table_count: 0,
            payload_length: payload_len as u32,
        }
    }

    // --- RESULT_END ---------------------------------------------------------

    fn build_result_end(rid: i64, final_seq: u64, total_rows: u64) -> Bytes {
        let mut p = vec![MsgKind::ResultEnd.as_u8()];
        p.extend_from_slice(&rid.to_le_bytes());
        encode_u64(final_seq, &mut p);
        encode_u64(total_rows, &mut p);
        Bytes::from(p)
    }

    #[test]
    fn decode_result_end_ok() {
        let payload = build_result_end(42, 7, 1_000);
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let event = decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        match event {
            ServerEvent::End {
                request_id,
                final_seq,
                total_rows,
            } => {
                assert_eq!(request_id, 42);
                assert_eq!(final_seq, 7);
                assert_eq!(total_rows, 1000);
            }
            _ => panic!("wrong event"),
        }
    }

    // --- QUERY_ERROR --------------------------------------------------------

    fn build_query_error(rid: i64, status: StatusCode, msg: &str) -> Bytes {
        let mut p = vec![MsgKind::QueryError.as_u8()];
        p.extend_from_slice(&rid.to_le_bytes());
        p.push(status.as_u8());
        p.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        p.extend_from_slice(msg.as_bytes());
        Bytes::from(p)
    }

    #[test]
    fn decode_query_error_ok() {
        let payload = build_query_error(9, StatusCode::ParseError, "bad SQL");
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let event = decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        match event {
            ServerEvent::Error {
                request_id,
                status,
                message,
            } => {
                assert_eq!(request_id, 9);
                assert_eq!(status, StatusCode::ParseError);
                assert_eq!(message, "bad SQL");
            }
            _ => panic!("wrong event"),
        }
    }

    #[test]
    fn query_error_truncated_message_rejected() {
        let payload = build_query_error(1, StatusCode::InternalError, "details");
        let truncated = payload.slice(..payload.len() - 3);
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err =
            decode_frame(header(truncated.len()), &truncated, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn query_error_invalid_utf8_rejected() {
        let mut p = vec![MsgKind::QueryError.as_u8()];
        p.extend_from_slice(&1i64.to_le_bytes());
        p.push(StatusCode::InternalError.as_u8());
        p.extend_from_slice(&2u16.to_le_bytes());
        p.extend_from_slice(&[0xFF, 0xFE]);
        let p = Bytes::from(p);
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_frame(header(p.len()), &p, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidUtf8);
    }

    // --- EXEC_DONE ----------------------------------------------------------

    #[test]
    fn decode_exec_done_ok() {
        let mut p = vec![MsgKind::ExecDone.as_u8()];
        p.extend_from_slice(&5i64.to_le_bytes());
        p.push(0xAB); // op_type
        encode_u64(0, &mut p); // rows_affected for DDL
        let p = Bytes::from(p);
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let event = decode_frame(header(p.len()), &p, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        match event {
            ServerEvent::ExecDone {
                request_id,
                op_type,
                rows_affected,
            } => {
                assert_eq!(request_id, 5);
                assert_eq!(op_type, 0xAB);
                assert_eq!(rows_affected, 0);
            }
            _ => panic!("wrong event"),
        }
    }

    // --- CACHE_RESET --------------------------------------------------------

    fn build_cache_reset(mask: u8) -> Bytes {
        Bytes::from(vec![MsgKind::CacheReset.as_u8(), mask])
    }

    #[test]
    fn cache_reset_clears_dict_only() {
        let mut dict = SymbolDict::new();
        dict.apply_delta(0, [b"x".as_slice()]).unwrap();
        let mut reg = SchemaRegistry::new();
        reg.insert(1, crate::egress::schema::Schema::new());

        let payload = build_cache_reset(0x01);
        let event = decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        assert!(matches!(event, ServerEvent::CacheReset { mask: 0x01 }));
        assert_eq!(dict.len(), 0);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn cache_reset_clears_schemas_only() {
        let mut dict = SymbolDict::new();
        dict.apply_delta(0, [b"x".as_slice()]).unwrap();
        let mut reg = SchemaRegistry::new();
        reg.insert(1, crate::egress::schema::Schema::new());

        let payload = build_cache_reset(0x02);
        decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        assert_eq!(dict.len(), 1);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn cache_reset_clears_both() {
        let mut dict = SymbolDict::new();
        dict.apply_delta(0, [b"x".as_slice()]).unwrap();
        let mut reg = SchemaRegistry::new();
        reg.insert(1, crate::egress::schema::Schema::new());

        let payload = build_cache_reset(0x03);
        decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        assert_eq!(dict.len(), 0);
        assert_eq!(reg.len(), 0);
    }

    #[test]
    fn cache_reset_ignores_reserved_bits() {
        // Spec §11.7: "Reserved bits MUST be zero on transmit; recipients
        // MUST ignore any reserved bits that are set." A future spec
        // revision adding a new reset bit alongside the known ones must
        // not break older clients — the known bits still apply, unknown
        // bits are silently dropped.
        let mut dict = SymbolDict::new();
        dict.apply_delta(0, [b"x".as_slice()]).unwrap();
        let mut reg = SchemaRegistry::new();
        reg.insert(1, crate::egress::schema::Schema::new());

        // 0x83 = bit 0 (DICT) + bit 1 (SCHEMAS) + bit 7 (reserved future).
        let payload = build_cache_reset(0x83);
        let event = decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        assert!(matches!(event, ServerEvent::CacheReset { mask: 0x83 }));
        assert_eq!(
            dict.len(),
            0,
            "DICT bit must apply even with reserved bit set"
        );
        assert_eq!(
            reg.len(),
            0,
            "SCHEMAS bit must apply even with reserved bit set"
        );
    }

    // --- SERVER_INFO --------------------------------------------------------

    fn build_server_info(role: u8, cluster: &str, node: &str) -> Bytes {
        let mut p = vec![MsgKind::ServerInfo.as_u8()];
        p.push(role);
        p.extend_from_slice(&7u64.to_le_bytes()); // epoch
        p.extend_from_slice(&0u32.to_le_bytes()); // capabilities
        p.extend_from_slice(&123_456_789i64.to_le_bytes()); // server_wall_ns
        p.extend_from_slice(&(cluster.len() as u16).to_le_bytes());
        p.extend_from_slice(cluster.as_bytes());
        p.extend_from_slice(&(node.len() as u16).to_le_bytes());
        p.extend_from_slice(node.as_bytes());
        Bytes::from(p)
    }

    #[test]
    fn decode_server_info_primary() {
        let payload = build_server_info(0x01, "cluster-A", "node-1");
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let event = decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        let ServerEvent::ServerInfo(info) = event else {
            panic!()
        };
        assert_eq!(info.role, ServerRole::Primary);
        assert_eq!(info.epoch, 7);
        assert_eq!(info.capabilities, 0);
        assert_eq!(info.server_wall_ns, 123_456_789);
        assert_eq!(info.cluster_id, "cluster-A");
        assert_eq!(info.node_id, "node-1");
    }

    #[test]
    fn unknown_role_byte_is_other_variant() {
        let payload = build_server_info(0x55, "c", "n");
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let event = decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap();
        let ServerEvent::ServerInfo(info) = event else {
            panic!()
        };
        assert_eq!(info.role, ServerRole::Other(0x55));
    }

    // --- Dispatcher edge cases ---------------------------------------------

    #[test]
    fn empty_payload_rejected() {
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let empty = Bytes::new();
        let err = decode_frame(header(0), &empty, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn unknown_msg_kind_rejected() {
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let p = Bytes::from(vec![0xAA]);
        let err = decode_frame(header(1), &p, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    #[test]
    fn client_only_kinds_rejected_from_server() {
        for k in [
            MsgKind::QueryRequest.as_u8(),
            MsgKind::Cancel.as_u8(),
            MsgKind::Credit.as_u8(),
        ] {
            let mut dict = SymbolDict::new();
            let mut reg = SchemaRegistry::new();
            let p = Bytes::from(vec![k]);
            let err = decode_frame(header(1), &p, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap_err();
            assert_eq!(err.code(), ErrorCode::ProtocolError);
            assert!(err.msg().contains("client-only"));
        }
    }

    #[test]
    fn trailing_bytes_rejected_for_simple_messages() {
        let payload = build_result_end(1, 0, 0);
        let mut bytes_vec: Vec<u8> = payload.to_vec();
        bytes_vec.push(0xFF);
        let payload = Bytes::from(bytes_vec);
        let mut dict = SymbolDict::new();
        let mut reg = SchemaRegistry::new();
        let err = decode_frame(header(payload.len()), &payload, &mut dict, &mut reg, &mut ZstdScratch::new()).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProtocolError);
    }

    // Sanity: HEADER_LEN constant still wired up.
    #[test]
    fn header_len_is_12() {
        assert_eq!(HEADER_LEN, 12);
    }
}
