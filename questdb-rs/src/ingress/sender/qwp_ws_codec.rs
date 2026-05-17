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
#[cfg(test)]
use crate::ws::crypto;
use crate::ws::frame;

// Re-export opcode constants from the shared `ws::frame` module so existing
// `WS_OPCODE_*` call sites in qwp_ws.rs and qwp_ws_driver.rs keep working
// with zero churn after the Phase A consolidation.
pub(super) use crate::ws::frame::Opcode;
pub(super) use crate::ws::frame::{
    OPCODE_BINARY as WS_OPCODE_BINARY, OPCODE_CLOSE as WS_OPCODE_CLOSE,
    OPCODE_CONTINUATION as WS_OPCODE_CONTINUATION, OPCODE_PING as WS_OPCODE_PING,
    OPCODE_PONG as WS_OPCODE_PONG, OPCODE_TEXT as WS_OPCODE_TEXT,
};

pub(super) const WS_PATH: &str = "/api/v4/write";

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

// ---------- Sec-WebSocket-Accept (delegating to shared `ws::crypto`) ----------

/// Compute the Sec-WebSocket-Accept value per RFC 6455 §4.2.2. Thin wrapper
/// over [`crate::ws::crypto::compute_accept`] kept here so existing
/// `codec::compute_accept` call sites in qwp_ws.rs / qwp_ws_driver.rs keep
/// working with no churn.
///
/// Test-only: production code now drives `crate::ws::handshake::upgrade`
/// directly, which validates the accept value internally. Test fixtures
/// in qwp_ws / qwp_ws_driver still need to sign mocked responses, so the
/// wrapper stays available under `cfg(test)`.
#[cfg(test)]
pub(super) fn compute_accept(key_b64: &str) -> String {
    crypto::compute_accept(key_b64)
}

// ---------- frame builder (pure bytes) ----------

/// Format a complete WebSocket client frame into `out`. Thin wrapper over
/// [`crate::ws::frame::encode_client_frame`]; the shared encoder always
/// sets FIN=1 and ingress never sends fragmented frames, so there is no
/// `fin` parameter to get wrong. `opcode` is a typed [`Opcode`], so
/// invalid values cannot be expressed at the call site.
pub(super) fn write_frame_to_buf(out: &mut Vec<u8>, opcode: Opcode, payload: &[u8], mask: [u8; 4]) {
    out.clear();
    frame::encode_client_frame(out, opcode, mask, payload);
}

// ---------- HTTP upgrade request: extra QWP-specific headers ----------

/// X-QWP-* + Authorization headers the ingress sender appends to the RFC
/// 6455 baseline. Pass the result as `extra_headers` to
/// [`crate::ws::handshake::upgrade`].
pub(super) fn qwp_extra_headers(
    auth_header: Option<&str>,
    max_version: u32,
    client_id: Option<&str>,
    request_durable_ack: bool,
) -> Vec<(&'static str, String)> {
    let mut extras = Vec::with_capacity(4);
    extras.push(("X-QWP-Max-Version", max_version.to_string()));
    if let Some(cid) = client_id {
        extras.push(("X-QWP-Client-Id", cid.to_owned()));
    }
    if request_durable_ack {
        extras.push(("X-QWP-Request-Durable-Ack", "true".to_owned()));
    }
    if let Some(auth) = auth_header {
        extras.push(("Authorization", auth.to_owned()));
    }
    extras
}

// ---------- HTTP response validation (post-shared-handshake) ----------

/// QWP-specific post-validation on a successful 101 response. Returns the
/// negotiated protocol version (defaults to 1 when the server omits
/// X-QWP-Version, matching the spec). Errors when the server returns an
/// out-of-range version or fails to echo `X-QWP-Durable-Ack: enabled`
/// after the client requested it.
pub(super) fn validate_qwp_handshake_headers(
    headers: &crate::ws::handshake::Headers,
    max_version: u32,
    request_durable_ack: bool,
) -> crate::Result<u8> {
    let version: u8 = match headers.find_ci("x-qwp-version") {
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
        let enabled = headers
            .find_ci("x-qwp-durable-ack")
            .is_some_and(|v| v.eq_ignore_ascii_case("enabled"));
        if !enabled {
            return Err(error::fmt!(
                ProtocolVersionError,
                "WebSocket upgrade failed: server did not enable durable ACK"
            ));
        }
    }
    Ok(version)
}

/// Map a non-101 HTTP response (from
/// [`crate::ws::handshake::HandshakeError::HttpStatus`]) to the matching
/// ingress error code. Handles QWP-specific 421 role rejection (carries
/// X-QuestDB-Role / X-QuestDB-Zone hints), 401/403 auth failure, and
/// falls back to a generic SocketError for everything else.
pub(super) fn classify_qwp_handshake_reject(
    reject: crate::ws::handshake::HttpReject,
) -> crate::Error {
    if reject.status == 401 || reject.status == 403 {
        return error::fmt!(
            AuthError,
            "WebSocket upgrade authentication failed: HTTP status {}",
            reject.status
        );
    }
    if reject.status == 421
        && let Some(role) = reject
            .headers
            .find_ci("x-questdb-role")
            .filter(|v| !v.is_empty())
    {
        let zone = reject
            .headers
            .find_ci("x-questdb-zone")
            .filter(|v| !v.is_empty());
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
        return err.with_qwp_ws_role_reject(role_reject);
    }
    error::fmt!(
        SocketError,
        "WebSocket upgrade failed: HTTP status {}",
        reject.status
    )
}

/// Map a [`crate::ws::handshake::HandshakeError`] from the shared handshake
/// module to the matching ingress error.
pub(super) fn handshake_error_to_ingress(e: crate::ws::handshake::HandshakeError) -> crate::Error {
    use crate::ws::handshake::HandshakeError;
    match e {
        HandshakeError::Io(io) => {
            // macOS reports SO_RCVTIMEO expiry as `WouldBlock` (EAGAIN, os
            // error 35), Linux/Windows report `TimedOut`. Surface both as
            // the same explicit timeout error so the failure mode does not
            // look platform-specific to the caller.
            if matches!(
                io.kind(),
                std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
            ) {
                error::fmt!(SocketError, "WebSocket upgrade response read timed out")
            } else {
                error::fmt!(SocketError, "WebSocket upgrade IO failed: {}", io)
            }
        }
        HandshakeError::Protocol(msg) => {
            error::fmt!(SocketError, "WebSocket upgrade failed: {}", msg)
        }
        HandshakeError::HttpStatus(reject) => classify_qwp_handshake_reject(reject),
        HandshakeError::BadAccept => error::fmt!(
            SocketError,
            "WebSocket upgrade failed: invalid Sec-WebSocket-Accept"
        ),
    }
}

/// Parse a CLOSE frame payload per RFC 6455 §5.5.1 and §7.4.
///
/// Returns Ok((code, reason)) for well-formed payloads. Returns Err with a
/// human-readable message when the payload is malformed: reserved or
/// out-of-range close code, or non-UTF-8 reason bytes. Callers translate the
/// Err into a WsMessageError::ProtocolViolation, which routes through the
/// driver as a terminal Halt.
///
/// A zero-byte payload is valid (no code, empty reason). A 1-byte payload is
/// already rejected upstream by validate_control_frame_header, but is
/// rejected here defensively for callers that bypass that check.
pub(super) fn parse_ws_close_payload(payload: &[u8]) -> Result<(Option<u16>, String), String> {
    if payload.is_empty() {
        return Ok((None, String::new()));
    }
    if payload.len() < 2 {
        return Err(
            "WebSocket close frame payload length must be 0 or at least 2 bytes".to_string(),
        );
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    if !is_valid_wire_ws_close_code(code) {
        return Err(format!(
            "WebSocket close frame uses reserved or out-of-range close code: {code}"
        ));
    }
    let reason = std::str::from_utf8(&payload[2..])
        .map_err(|_| "WebSocket close frame reason is not valid UTF-8".to_string())?;
    Ok((Some(code), reason.to_string()))
}

// Codes 1004, 1005, 1006, 1015 are reserved sentinels that must not appear on
// the wire. 1016–2999 are reserved for future protocol-level extensions.
// 3000–3999 are framework-registered; 4000–4999 are private-use.
fn is_valid_wire_ws_close_code(code: u16) -> bool {
    matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999)
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

    use crate::ws::handshake::{Headers, HttpReject};

    #[test]
    fn qwp_extra_headers_includes_durable_ack_when_requested() {
        let extras = qwp_extra_headers(None, 1, None, true);
        assert!(
            extras
                .iter()
                .any(|(name, value)| *name == "X-QWP-Request-Durable-Ack" && value == "true"),
            "{:?}",
            extras
        );
    }

    #[test]
    fn qwp_extra_headers_omits_durable_ack_by_default() {
        let extras = qwp_extra_headers(None, 1, None, false);
        assert!(
            !extras
                .iter()
                .any(|(name, _)| *name == "X-QWP-Request-Durable-Ack"),
            "{:?}",
            extras
        );
    }

    #[test]
    fn qwp_extra_headers_includes_authorization_when_provided() {
        let extras = qwp_extra_headers(Some("Basic dXNlcjpwYXNz"), 1, None, false);
        assert!(
            extras
                .iter()
                .any(|(name, value)| *name == "Authorization" && value == "Basic dXNlcjpwYXNz"),
            "{:?}",
            extras
        );
    }

    #[test]
    fn validate_qwp_handshake_headers_negotiates_version() {
        let headers = Headers::from_pairs([("X-QWP-Version", "1")]);
        assert_eq!(
            validate_qwp_handshake_headers(&headers, 1, false).unwrap(),
            1
        );
    }

    #[test]
    fn validate_qwp_handshake_headers_rejects_version_above_max() {
        let headers = Headers::from_pairs([("X-QWP-Version", "2")]);
        let err = validate_qwp_handshake_headers(&headers, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("unsupported X-QWP-Version"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn validate_qwp_handshake_headers_rejects_zero_version() {
        let headers = Headers::from_pairs([("X-QWP-Version", "0")]);
        let err = validate_qwp_handshake_headers(&headers, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("invalid X-QWP-Version"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn validate_qwp_handshake_headers_rejects_invalid_version_string() {
        let headers = Headers::from_pairs([("X-QWP-Version", "not-a-version")]);
        let err = validate_qwp_handshake_headers(&headers, 1, false).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("invalid X-QWP-Version"),
            "got: {}",
            err.msg()
        );
    }

    #[test]
    fn validate_qwp_handshake_headers_defaults_to_v1_when_missing() {
        let headers = Headers::default();
        assert_eq!(
            validate_qwp_handshake_headers(&headers, 1, false).unwrap(),
            1
        );
    }

    #[test]
    fn validate_qwp_handshake_headers_requires_durable_ack_echo_when_requested() {
        let headers = Headers::from_pairs([("X-QWP-Version", "1")]);
        let err = validate_qwp_handshake_headers(&headers, 1, true).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::ProtocolVersionError);
        assert!(
            err.msg().contains("server did not enable durable ACK"),
            "got: {}",
            err.msg()
        );

        let headers =
            Headers::from_pairs([("X-QWP-Version", "1"), ("X-QWP-Durable-Ack", "enabled")]);
        assert_eq!(
            validate_qwp_handshake_headers(&headers, 1, true).unwrap(),
            1
        );
    }

    #[test]
    fn validate_qwp_handshake_headers_allows_missing_durable_ack_by_default() {
        let headers = Headers::from_pairs([("X-QWP-Version", "1")]);
        assert_eq!(
            validate_qwp_handshake_headers(&headers, 1, false).unwrap(),
            1
        );
    }

    #[test]
    fn classify_qwp_handshake_reject_extracts_role_with_zone_hint_for_421() {
        let reject = HttpReject {
            status: 421,
            headers: Headers::from_pairs([
                ("X-QuestDB-Role", "PRIMARY_CATCHUP"),
                ("X-QuestDB-Zone", "az-a"),
            ]),
            body: vec![],
        };
        let err = classify_qwp_handshake_reject(reject);
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.msg().contains("role=PRIMARY_CATCHUP"));
        assert!(err.msg().contains("zone=az-a"));
        let role_reject = err.qwp_ws_role_reject().unwrap();
        assert_eq!(role_reject.role, "PRIMARY_CATCHUP");
        assert_eq!(role_reject.zone.as_deref(), Some("az-a"));
        assert!(role_reject.is_transient());
    }

    #[test]
    fn classify_qwp_handshake_reject_extracts_role_without_zone_for_421() {
        let reject = HttpReject {
            status: 421,
            headers: Headers::from_pairs([("X-QuestDB-Role", "PRIMARY_CATCHUP")]),
            body: vec![],
        };
        let err = classify_qwp_handshake_reject(reject);
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(err.msg().contains("role=PRIMARY_CATCHUP"));
        assert!(!err.msg().contains("zone="));
        let role_reject = err.qwp_ws_role_reject().unwrap();
        assert_eq!(role_reject.role, "PRIMARY_CATCHUP");
        assert!(role_reject.zone.is_none());
    }

    #[test]
    fn classify_qwp_handshake_reject_returns_auth_error_for_401_403() {
        for status in [401u16, 403u16] {
            let reject = HttpReject {
                status,
                headers: Headers::default(),
                body: vec![],
            };
            let err = classify_qwp_handshake_reject(reject);
            assert_eq!(err.code(), crate::ErrorCode::AuthError);
            assert!(
                err.msg().contains(&format!("HTTP status {status}")),
                "got: {}",
                err.msg()
            );
        }
    }

    #[test]
    fn classify_qwp_handshake_reject_returns_socket_error_for_other_status() {
        // 421 without an X-QuestDB-Role hint must NOT be classified as a
        // role reject; it falls through to the generic socket-error path.
        for status in [421u16, 500u16, 503u16] {
            let reject = HttpReject {
                status,
                headers: Headers::default(),
                body: vec![],
            };
            let err = classify_qwp_handshake_reject(reject);
            assert_eq!(err.code(), crate::ErrorCode::SocketError);
            assert!(err.qwp_ws_role_reject().is_none());
            assert!(
                err.msg().contains(&format!("HTTP status {status}")),
                "got: {}",
                err.msg()
            );
        }
    }

    #[test]
    fn frame_short_payload_round_trip() {
        let mut out = Vec::new();
        let mask = [0x12, 0x34, 0x56, 0x78];
        let payload = b"hello";
        write_frame_to_buf(&mut out, Opcode::Binary, payload, mask);
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
        write_frame_to_buf(&mut out, Opcode::Binary, &[0u8; 200], mask);
        assert_eq!(out[1] & 0x7F, 126);

        let mut out = Vec::new();
        let big = vec![0u8; 70_000];
        write_frame_to_buf(&mut out, Opcode::Binary, &big, mask);
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
}
