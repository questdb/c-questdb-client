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

//! Pure-bytes WebSocket + QWP-response codec shared by the sync and async
//! QWP/WebSocket transports. Nothing in this file performs I/O — it's all
//! buffer-in / buffer-out, so the same routines drive both transports without
//! coupling them to a particular runtime.

use crate::error;
use crate::ingress::QwpWsRoleReject;

pub(super) const SEC_WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub(super) const WS_PATH: &str = "/api/v4/write";

pub(super) const WS_OPCODE_CONTINUATION: u8 = 0x0;
pub(super) const WS_OPCODE_TEXT: u8 = 0x1;
pub(super) const WS_OPCODE_BINARY: u8 = 0x2;
pub(super) const WS_OPCODE_CLOSE: u8 = 0x8;
pub(super) const WS_OPCODE_PING: u8 = 0x9;
pub(super) const WS_OPCODE_PONG: u8 = 0xA;

pub(super) const WS_STATUS_OK: u8 = 0x00;
pub(super) const WS_STATUS_DURABLE_ACK: u8 = 0x02;
pub(super) const WS_STATUS_SCHEMA_MISMATCH: u8 = 0x03;
pub(super) const WS_STATUS_PARSE_ERROR: u8 = 0x05;
pub(super) const WS_STATUS_INTERNAL_ERROR: u8 = 0x06;
pub(super) const WS_STATUS_SECURITY_ERROR: u8 = 0x08;
pub(super) const WS_STATUS_WRITE_ERROR: u8 = 0x09;

/// 256 MiB cap on a single inbound frame -- well above QWP's 16 MB batch limit
/// but small enough to refuse obviously bogus declared lengths early.
pub(super) const MAX_INBOUND_FRAME_BYTES: u64 = 256 * 1024 * 1024;

// ---------- SHA-1 / Sec-WebSocket-Accept ----------

fn sha1(input: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len() + 64);
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut w = [0u32; 80];
    for chunk in padded.chunks_exact(64) {
        for (i, word) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    for (i, h) in [h0, h1, h2, h3, h4].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&h.to_be_bytes());
    }
    out
}

pub(super) fn b64_encode(input: &[u8]) -> String {
    use base64ct::{Base64, Encoding};
    Base64::encode_string(input)
}

pub(super) fn compute_accept(key_b64: &str) -> String {
    let mut combined = String::with_capacity(key_b64.len() + SEC_WS_GUID.len());
    combined.push_str(key_b64);
    combined.push_str(SEC_WS_GUID);
    b64_encode(&sha1(combined.as_bytes()))
}

// ---------- frame builder (pure bytes) ----------

/// Format a complete (FIN-set) WebSocket frame into `out`. The frame is masked
/// per RFC 6455 client → server requirements; the mask is sourced from `mask`,
/// which the caller chooses (random in production, deterministic in tests).
pub(super) fn write_frame_to_buf(
    out: &mut Vec<u8>,
    fin: bool,
    opcode: u8,
    payload: &[u8],
    mask: [u8; 4],
) {
    out.clear();
    let fin_bit: u8 = if fin { 0x80 } else { 0x00 };
    out.push(fin_bit | (opcode & 0x0F));

    let mask_bit: u8 = 0x80;
    let plen = payload.len();
    if plen <= 125 {
        out.push(mask_bit | (plen as u8));
    } else if plen <= 0xFFFF {
        out.push(mask_bit | 126);
        out.extend_from_slice(&(plen as u16).to_be_bytes());
    } else {
        out.push(mask_bit | 127);
        out.extend_from_slice(&(plen as u64).to_be_bytes());
    }

    out.extend_from_slice(&mask);
    let masked_start = out.len();
    out.extend_from_slice(payload);
    for (i, b) in out[masked_start..].iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
}

// ---------- HTTP upgrade request builder ----------

pub(super) fn build_upgrade_request(
    host_header: &str,
    key_b64: &str,
    auth_header: Option<&str>,
    max_version: u32,
    client_id: Option<&str>,
    request_durable_ack: bool,
) -> String {
    let mut req = String::new();
    req.push_str(&format!("GET {WS_PATH} HTTP/1.1\r\n"));
    req.push_str(&format!("Host: {host_header}\r\n"));
    req.push_str("Upgrade: websocket\r\n");
    req.push_str("Connection: Upgrade\r\n");
    req.push_str(&format!("Sec-WebSocket-Key: {key_b64}\r\n"));
    req.push_str("Sec-WebSocket-Version: 13\r\n");
    req.push_str(&format!("X-QWP-Max-Version: {max_version}\r\n"));
    if let Some(cid) = client_id {
        req.push_str(&format!("X-QWP-Client-Id: {cid}\r\n"));
    }
    if request_durable_ack {
        req.push_str("X-QWP-Request-Durable-Ack: true\r\n");
    }
    if let Some(auth) = auth_header {
        req.push_str(&format!("Authorization: {auth}\r\n"));
    }
    req.push_str("\r\n");
    req
}

// ---------- HTTP response parsing (header block already in memory) ----------

pub(super) struct ParsedHttpHeaders {
    pub(super) status: u16,
    pub(super) headers: Vec<(String, String)>,
}

pub(super) fn parse_http_header_block(block: &[u8]) -> crate::Result<ParsedHttpHeaders> {
    let header_text = std::str::from_utf8(block)
        .map_err(|_| error::fmt!(SocketError, "Upgrade response headers are not UTF-8"))?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().ok_or_else(|| {
        error::fmt!(
            SocketError,
            "WebSocket upgrade response missing status line"
        )
    })?;
    let mut parts = status_line.splitn(3, ' ');
    let _http_ver = parts.next();
    let status: u16 = parts
        .next()
        .ok_or_else(|| error::fmt!(SocketError, "Missing HTTP status code"))?
        .parse()
        .map_err(|_| error::fmt!(SocketError, "Invalid HTTP status code"))?;

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok(ParsedHttpHeaders { status, headers })
}

pub(super) fn validate_upgrade_response(
    parsed: &ParsedHttpHeaders,
    expected_accept: &str,
    max_version: u32,
    request_durable_ack: bool,
) -> crate::Result<u8> {
    if parsed.status == 401 || parsed.status == 403 {
        return Err(error::fmt!(
            AuthError,
            "WebSocket upgrade authentication failed: HTTP status {}",
            parsed.status
        ));
    }
    if parsed.status == 421
        && let Some((_, role)) = parsed
            .headers
            .iter()
            .find(|(k, v)| k.eq_ignore_ascii_case("x-questdb-role") && !v.trim().is_empty())
    {
        let zone = parsed
            .headers
            .iter()
            .find(|(k, v)| k.eq_ignore_ascii_case("x-questdb-zone") && !v.trim().is_empty())
            .map(|(_, v)| v.trim());
        let role = role.trim();
        let role_reject = QwpWsRoleReject::new(role, zone);
        let err = match zone {
            Some(zone) => error::fmt!(
                SocketError,
                "QWP/WebSocket upgrade rejected by role={} zone={}",
                role,
                zone
            ),
            None => error::fmt!(
                SocketError,
                "QWP/WebSocket upgrade rejected by role={}",
                role
            ),
        };
        return Err(err.with_qwp_ws_role_reject(role_reject));
    }
    if parsed.status != 101 {
        return Err(error::fmt!(
            SocketError,
            "WebSocket upgrade failed: HTTP status {}",
            parsed.status
        ));
    }
    let upgrade_ok = parsed
        .headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"));
    if !upgrade_ok {
        return Err(error::fmt!(
            SocketError,
            "WebSocket upgrade failed: missing or invalid Upgrade header"
        ));
    }
    let connection_upgrade = parsed.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("connection")
            && v.split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    });
    if !connection_upgrade {
        return Err(error::fmt!(
            SocketError,
            "WebSocket upgrade failed: missing or invalid Connection header"
        ));
    }
    let accept_ok = parsed
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("sec-websocket-accept"))
        .map(|(_, v)| v.trim() == expected_accept)
        .unwrap_or(false);
    if !accept_ok {
        return Err(error::fmt!(
            SocketError,
            "WebSocket upgrade failed: invalid Sec-WebSocket-Accept"
        ));
    }
    let version_str = parsed
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("x-qwp-version"))
        .map(|(_, v)| v.trim().to_string());
    let version: u8 = match version_str {
        Some(v) => v.parse().map_err(|_| {
            error::fmt!(
                SocketError,
                "Server returned invalid X-QWP-Version: {:?}",
                v
            )
        })?,
        None => 1,
    };
    if version == 0 {
        return Err(error::fmt!(
            SocketError,
            "Server returned invalid X-QWP-Version: 0"
        ));
    }
    if u32::from(version) > max_version {
        return Err(error::fmt!(
            SocketError,
            "Server returned unsupported X-QWP-Version: {} [max_supported={}]",
            version,
            max_version
        ));
    }
    if request_durable_ack {
        let durable_ack_enabled = parsed.headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("x-qwp-durable-ack") && v.eq_ignore_ascii_case("enabled")
        });
        if !durable_ack_enabled {
            return Err(error::fmt!(
                ProtocolVersionError,
                "WebSocket upgrade failed: server did not enable durable ACK"
            ));
        }
    }
    Ok(version)
}

pub(super) fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub(super) fn ws_close_details(payload: &[u8]) -> (Option<u16>, String) {
    if payload.len() >= 2 {
        let code = u16::from_be_bytes([payload[0], payload[1]]);
        let reason = std::str::from_utf8(&payload[2..]).unwrap_or("");
        (Some(code), reason.to_string())
    } else {
        (None, String::new())
    }
}

// ---------- QWP response decoding ----------

/// Parse a QWP/WebSocket response and return the sequence so callers can
/// dispatch the result to the matching in-flight request.
pub(super) struct PipelinedError {
    pub(super) sequence: u64,
    pub(super) status: u8,
    pub(super) message: String,
    pub(super) err: crate::Error,
}

pub(super) enum PipelinedResponse {
    Ok { sequence: u64 },
    DurableAck,
    Error(PipelinedError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PipelinedTableEntryKind {
    Ok,
    DurableAck,
}

pub(super) fn parse_pipelined_response(payload: &[u8]) -> crate::Result<PipelinedResponse> {
    parse_pipelined_response_with_table_handler(payload, None)
}

type PipelinedTableEntryHandler<'a> =
    &'a mut dyn FnMut(PipelinedTableEntryKind, &str, i64) -> crate::Result<()>;

pub(super) fn parse_pipelined_response_with_table_handler(
    payload: &[u8],
    on_table_entry: Option<PipelinedTableEntryHandler<'_>>,
) -> crate::Result<PipelinedResponse> {
    if payload.is_empty() {
        return Err(error::fmt!(SocketError, "Empty QWP response frame"));
    }
    let status = payload[0];
    match status {
        WS_STATUS_OK => {
            if payload.len() < 1 + 8 + 2 {
                return Err(error::fmt!(SocketError, "QWP OK response truncated"));
            }
            let seq = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            handle_table_seq_txn_entries(
                payload,
                9,
                "QWP OK response",
                PipelinedTableEntryKind::Ok,
                on_table_entry,
            )?;
            Ok(PipelinedResponse::Ok { sequence: seq })
        }
        WS_STATUS_DURABLE_ACK => {
            handle_table_seq_txn_entries(
                payload,
                1,
                "QWP durable ACK response",
                PipelinedTableEntryKind::DurableAck,
                on_table_entry,
            )?;
            Ok(PipelinedResponse::DurableAck)
        }
        _ => {
            let (sequence, msg) = parse_error_body(payload)?;
            let err = map_error_status(status, &msg);
            Ok(PipelinedResponse::Error(PipelinedError {
                sequence,
                status,
                message: msg,
                err,
            }))
        }
    }
}

fn handle_table_seq_txn_entries(
    payload: &[u8],
    table_count_offset: usize,
    context: &str,
    kind: PipelinedTableEntryKind,
    on_entry: Option<PipelinedTableEntryHandler<'_>>,
) -> crate::Result<()> {
    validate_table_seq_txn_entries(payload, table_count_offset, context)?;
    if let Some(on_entry) = on_entry {
        visit_table_seq_txn_entries(
            payload,
            table_count_offset,
            context,
            &mut |table, seq_txn| on_entry(kind, table, seq_txn),
        )?;
    }
    Ok(())
}

fn validate_table_seq_txn_entries(
    payload: &[u8],
    table_count_offset: usize,
    context: &str,
) -> crate::Result<()> {
    visit_table_seq_txn_entries(payload, table_count_offset, context, &mut |_, _| Ok(()))
}

fn visit_table_seq_txn_entries(
    payload: &[u8],
    table_count_offset: usize,
    context: &str,
    on_entry: &mut impl FnMut(&str, i64) -> crate::Result<()>,
) -> crate::Result<()> {
    let table_count_end = table_count_offset
        .checked_add(2)
        .ok_or_else(|| error::fmt!(SocketError, "{context} table count offset overflow"))?;
    if payload.len() < table_count_end {
        return Err(error::fmt!(SocketError, "{context} truncated"));
    }

    let table_count = u16::from_le_bytes(
        payload[table_count_offset..table_count_end]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut pos = table_count_end;
    for _ in 0..table_count {
        let name_len_end = pos
            .checked_add(2)
            .ok_or_else(|| error::fmt!(SocketError, "{context} table entry offset overflow"))?;
        if payload.len() < name_len_end {
            return Err(error::fmt!(SocketError, "{context} table entry truncated"));
        }
        let name_len = u16::from_le_bytes(payload[pos..name_len_end].try_into().unwrap()) as usize;
        pos = name_len_end;
        if name_len == 0 {
            return Err(error::fmt!(SocketError, "{context} table name is empty"));
        }

        let name_end = pos
            .checked_add(name_len)
            .ok_or_else(|| error::fmt!(SocketError, "{context} table name length overflow"))?;
        let seq_txn_end = name_end
            .checked_add(8)
            .ok_or_else(|| error::fmt!(SocketError, "{context} table entry length overflow"))?;
        if payload.len() < seq_txn_end {
            return Err(error::fmt!(SocketError, "{context} table entry truncated"));
        }

        let table = std::str::from_utf8(&payload[pos..name_end])
            .map_err(|_| error::fmt!(SocketError, "{context} table name is not UTF-8"))?;
        let seq_txn = i64::from_le_bytes(payload[name_end..seq_txn_end].try_into().unwrap());
        on_entry(table, seq_txn)?;
        pos = seq_txn_end;
    }

    if pos != payload.len() {
        return Err(error::fmt!(
            SocketError,
            "{context} has trailing bytes after table entries"
        ));
    }

    Ok(())
}

fn parse_error_body(payload: &[u8]) -> crate::Result<(u64, String)> {
    if payload.len() < 1 + 8 + 2 {
        return Err(error::fmt!(SocketError, "QWP error response truncated"));
    }
    let seq = u64::from_le_bytes(payload[1..9].try_into().unwrap());
    let msg_len = u16::from_le_bytes(payload[9..11].try_into().unwrap()) as usize;
    if msg_len > 1024 {
        return Err(error::fmt!(
            SocketError,
            "QWP error response message too long (declared {} bytes, max 1024)",
            msg_len
        ));
    }
    let msg_end = 11usize
        .checked_add(msg_len)
        .ok_or_else(|| error::fmt!(SocketError, "QWP error response message length overflow"))?;
    if payload.len() < msg_end {
        return Err(error::fmt!(
            SocketError,
            "QWP error response truncated (declared {} bytes)",
            msg_len
        ));
    }
    if payload.len() != msg_end {
        return Err(error::fmt!(
            SocketError,
            "QWP error response has trailing bytes after message"
        ));
    }
    let msg = std::str::from_utf8(&payload[11..msg_end])
        .map_err(|_| error::fmt!(SocketError, "QWP error message is not UTF-8"))?
        .to_string();
    Ok((seq, msg))
}

fn map_error_status(status: u8, msg: &str) -> crate::Error {
    match status {
        WS_STATUS_SCHEMA_MISMATCH => error::fmt!(InvalidApiCall, "QWP schema mismatch: {}", msg),
        WS_STATUS_PARSE_ERROR => error::fmt!(InvalidApiCall, "QWP parse error: {}", msg),
        WS_STATUS_INTERNAL_ERROR => {
            error::fmt!(ServerFlushError, "QWP server internal error: {}", msg)
        }
        WS_STATUS_SECURITY_ERROR => error::fmt!(AuthError, "QWP authorization failure: {}", msg),
        WS_STATUS_WRITE_ERROR => error::fmt!(ServerFlushError, "QWP write error: {}", msg),
        other => error::fmt!(
            ServerFlushError,
            "QWP error (status 0x{:02x}): {}",
            other,
            msg
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_websocket_accept_matches_rfc6455_example() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let expected = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
        assert_eq!(compute_accept(key), expected);
    }

    #[test]
    fn upgrade_request_includes_durable_ack_opt_in_header_when_requested() {
        let request = build_upgrade_request("localhost:9000", "key", None, 1, None, true);

        assert!(request.contains("X-QWP-Request-Durable-Ack: true\r\n"));
    }

    #[test]
    fn upgrade_response_requires_durable_ack_echo_when_requested() {
        let expected_accept = "accept";
        let mut parsed = valid_upgrade_headers(expected_accept);

        validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap();
        let err = validate_upgrade_response(&parsed, expected_accept, 1, true).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::ProtocolVersionError);
        assert!(
            err.msg().contains("server did not enable durable ACK"),
            "got: {}",
            err.msg()
        );

        parsed
            .headers
            .push(("X-QWP-Durable-Ack".to_string(), "enabled".to_string()));
        validate_upgrade_response(&parsed, expected_accept, 1, true).unwrap();
    }

    #[test]
    fn upgrade_response_validates_qwp_version_before_durable_ack_echo() {
        let expected_accept = "accept";
        let mut parsed = valid_upgrade_headers(expected_accept);
        parsed
            .headers
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case("x-qwp-version"))
            .unwrap()
            .1 = "2".to_string();

        let err = validate_upgrade_response(&parsed, expected_accept, 1, true).unwrap_err();

        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("unsupported X-QWP-Version"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn upgrade_response_classifies_role_reject_and_retryable_status() {
        let expected_accept = "accept";
        let mut parsed = valid_upgrade_headers(expected_accept);

        parsed.status = 421;
        parsed
            .headers
            .push(("X-QuestDB-Role".to_string(), "PRIMARY_CATCHUP".to_string()));
        parsed
            .headers
            .push(("X-QuestDB-Zone".to_string(), "az-a".to_string()));
        let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.msg().contains("role=PRIMARY_CATCHUP"));
        let role_reject = err.qwp_ws_role_reject().unwrap();
        assert_eq!(role_reject.role, "PRIMARY_CATCHUP");
        assert_eq!(role_reject.zone.as_deref(), Some("az-a"));
        assert!(role_reject.is_transient());

        parsed
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("x-questdb-role"));
        let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.qwp_ws_role_reject().is_none());
        assert!(err.msg().contains("HTTP status 421"));

        parsed.status = 500;
        let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.msg().contains("HTTP status 500"));
    }

    #[test]
    fn upgrade_response_rejects_invalid_or_unsupported_versions_as_socket_errors() {
        let expected_accept = "accept";
        for (version, expected_msg) in [
            ("not-a-version", "invalid X-QWP-Version"),
            ("0", "invalid X-QWP-Version"),
            ("2", "unsupported X-QWP-Version"),
        ] {
            let mut parsed = valid_upgrade_headers(expected_accept);
            parsed
                .headers
                .iter_mut()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-qwp-version"))
                .unwrap()
                .1 = version.to_string();

            let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
            assert_eq!(err.code(), crate::ErrorCode::SocketError);
            assert!(err.msg().contains(expected_msg), "got: {}", err.msg());
        }
    }

    #[test]
    fn upgrade_response_requires_connection_upgrade_header() {
        let expected_accept = "accept";
        let mut parsed = valid_upgrade_headers(expected_accept);
        parsed
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("connection"));

        let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("missing or invalid Connection header"),
            "got: {}",
            err.msg()
        );

        parsed
            .headers
            .push(("Connection".to_string(), "keep-alive".to_string()));
        let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("missing or invalid Connection header"),
            "got: {}",
            err.msg()
        );

        parsed.headers.last_mut().unwrap().1 = "keep-alive, Upgrade".to_string();
        validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap();
    }

    #[test]
    fn malformed_101_upgrade_headers_are_socket_errors() {
        let expected_accept = "accept";
        let mut parsed = valid_upgrade_headers(expected_accept);
        parsed
            .headers
            .retain(|(name, _)| !name.eq_ignore_ascii_case("upgrade"));

        let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.msg().contains("missing or invalid Upgrade header"));

        let mut parsed = valid_upgrade_headers(expected_accept);
        parsed
            .headers
            .iter_mut()
            .find(|(name, _)| name.eq_ignore_ascii_case("sec-websocket-accept"))
            .unwrap()
            .1 = "wrong".to_string();

        let err = validate_upgrade_response(&parsed, expected_accept, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.msg().contains("invalid Sec-WebSocket-Accept"));
    }

    #[test]
    fn frame_short_payload_round_trip() {
        let mut out = Vec::new();
        let mask = [0x12, 0x34, 0x56, 0x78];
        let payload = b"hello";
        write_frame_to_buf(&mut out, true, WS_OPCODE_BINARY, payload, mask);
        assert_eq!(out[0], 0x82); // FIN | binary
        assert_eq!(out[1] & 0x80, 0x80);
        assert_eq!(out[1] & 0x7F, 5);
        let mut decoded = vec![0u8; payload.len()];
        for (i, b) in out[6..].iter().enumerate() {
            decoded[i] = b ^ mask[i & 3];
        }
        assert_eq!(decoded, payload);
    }

    #[test]
    fn frame_extended_lengths() {
        let mut out = Vec::new();
        let mask = [0; 4];
        write_frame_to_buf(&mut out, true, WS_OPCODE_BINARY, &[0u8; 200], mask);
        assert_eq!(out[1] & 0x7F, 126);

        let mut out = Vec::new();
        let big = vec![0u8; 70_000];
        write_frame_to_buf(&mut out, true, WS_OPCODE_BINARY, &big, mask);
        assert_eq!(out[1] & 0x7F, 127);
    }

    #[test]
    fn ok_response_requires_table_count() {
        let mut payload = vec![WS_STATUS_OK];
        payload.extend_from_slice(&7u64.to_le_bytes());

        assert!(parse_pipelined_response(&payload).is_err());
    }

    #[test]
    fn ok_response_parses_table_entries() {
        let mut payload = vec![WS_STATUS_OK];
        payload.extend_from_slice(&7u64.to_le_bytes());
        append_table_entries(&mut payload, &[("table_a", 42), ("table_b", -7)]);

        let mut table_seq_txns = Vec::new();
        let mut handler = |kind, table: &str, seq_txn| {
            table_seq_txns.push((kind, table.to_string(), seq_txn));
            Ok(())
        };
        match parse_pipelined_response_with_table_handler(&payload, Some(&mut handler)).unwrap() {
            PipelinedResponse::Ok { sequence } => {
                assert_eq!(sequence, 7);
                assert_eq!(
                    table_seq_txns,
                    vec![
                        (PipelinedTableEntryKind::Ok, "table_a".to_string(), 42),
                        (PipelinedTableEntryKind::Ok, "table_b".to_string(), -7),
                    ]
                );
            }
            _ => panic!("expected OK response"),
        }
    }

    #[test]
    fn non_durable_ok_response_validates_without_returning_table_entries() {
        let mut payload = vec![WS_STATUS_OK];
        payload.extend_from_slice(&7u64.to_le_bytes());
        append_table_entries(&mut payload, &[("table_a", 42), ("table_b", -7)]);

        match parse_pipelined_response(&payload).unwrap() {
            PipelinedResponse::Ok { sequence } => assert_eq!(sequence, 7),
            _ => panic!("expected OK response"),
        }
    }

    #[test]
    fn durable_ack_response_requires_table_count() {
        assert!(parse_pipelined_response(&[WS_STATUS_DURABLE_ACK]).is_err());
    }

    #[test]
    fn durable_ack_response_parses_table_entries() {
        let mut payload = vec![WS_STATUS_DURABLE_ACK];
        append_table_entries(&mut payload, &[("wal_table", 123)]);

        let mut table_seq_txns = Vec::new();
        let mut handler = |kind, table: &str, seq_txn| {
            table_seq_txns.push((kind, table.to_string(), seq_txn));
            Ok(())
        };
        match parse_pipelined_response_with_table_handler(&payload, Some(&mut handler)).unwrap() {
            PipelinedResponse::DurableAck => {
                assert_eq!(
                    table_seq_txns,
                    vec![(
                        PipelinedTableEntryKind::DurableAck,
                        "wal_table".to_string(),
                        123
                    )]
                );
            }
            _ => panic!("expected durable ACK response"),
        }
    }

    #[test]
    fn table_entries_reject_trailing_bytes() {
        let mut payload = vec![WS_STATUS_DURABLE_ACK];
        append_table_entries(&mut payload, &[]);
        payload.push(0);

        assert!(parse_pipelined_response(&payload).is_err());
    }

    #[test]
    fn table_entry_handler_is_not_called_for_structurally_invalid_payload() {
        let mut payload = vec![WS_STATUS_DURABLE_ACK];
        append_table_entries(&mut payload, &[("wal_table", 123)]);
        payload.push(0);

        let mut calls = 0;
        let mut handler = |_, _: &str, _| {
            calls += 1;
            Ok(())
        };
        assert!(parse_pipelined_response_with_table_handler(&payload, Some(&mut handler)).is_err());
        assert_eq!(calls, 0);
    }

    #[test]
    fn table_entries_reject_non_utf8_names() {
        let mut payload = vec![WS_STATUS_DURABLE_ACK];
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.push(0xff);
        payload.extend_from_slice(&1i64.to_le_bytes());

        assert!(parse_pipelined_response(&payload).is_err());
    }

    #[test]
    fn table_entries_reject_empty_names() {
        let mut payload = vec![WS_STATUS_DURABLE_ACK];
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&1i64.to_le_bytes());

        assert!(parse_pipelined_response(&payload).is_err());
    }

    #[test]
    fn error_response_rejects_messages_over_1024_bytes() {
        let mut payload = vec![WS_STATUS_INTERNAL_ERROR];
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload.extend_from_slice(&1025u16.to_le_bytes());
        payload.extend(std::iter::repeat_n(b'x', 1025));

        assert!(parse_pipelined_response(&payload).is_err());
    }

    #[test]
    fn error_response_accepts_1024_byte_message() {
        let mut payload = vec![WS_STATUS_INTERNAL_ERROR];
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload.extend_from_slice(&1024u16.to_le_bytes());
        payload.extend(std::iter::repeat_n(b'x', 1024));

        match parse_pipelined_response(&payload).unwrap() {
            PipelinedResponse::Error(error) => {
                assert_eq!(error.sequence, 7);
                assert_eq!(error.message.len(), 1024);
            }
            _ => panic!("expected error response"),
        }
    }

    #[test]
    fn error_response_rejects_trailing_bytes() {
        let mut payload = vec![WS_STATUS_INTERNAL_ERROR];
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(b"bad");
        payload.push(0);

        assert!(parse_pipelined_response(&payload).is_err());
    }

    fn append_table_entries(payload: &mut Vec<u8>, entries: &[(&str, i64)]) {
        payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        for (table, seq_txn) in entries {
            payload.extend_from_slice(&(table.len() as u16).to_le_bytes());
            payload.extend_from_slice(table.as_bytes());
            payload.extend_from_slice(&seq_txn.to_le_bytes());
        }
    }

    fn valid_upgrade_headers(expected_accept: &str) -> ParsedHttpHeaders {
        ParsedHttpHeaders {
            status: 101,
            headers: vec![
                ("Upgrade".to_string(), "websocket".to_string()),
                ("Connection".to_string(), "Upgrade".to_string()),
                (
                    "Sec-WebSocket-Accept".to_string(),
                    expected_accept.to_string(),
                ),
                ("X-QWP-Version".to_string(), "1".to_string()),
            ],
        }
    }
}
