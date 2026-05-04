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
) -> crate::Result<u8> {
    if parsed.status != 101 {
        return Err(error::fmt!(
            ProtocolVersionError,
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
            ProtocolVersionError,
            "WebSocket upgrade failed: missing or invalid Upgrade header"
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
            ProtocolVersionError,
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
                ProtocolVersionError,
                "Server returned invalid X-QWP-Version: {:?}",
                v
            )
        })?,
        None => 1,
    };
    if version == 0 {
        return Err(error::fmt!(
            ProtocolVersionError,
            "Server returned invalid X-QWP-Version: 0"
        ));
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

pub(super) fn parse_pipelined_response(payload: &[u8]) -> crate::Result<PipelinedResponse> {
    if payload.is_empty() {
        return Err(error::fmt!(SocketError, "Empty QWP response frame"));
    }
    let status = payload[0];
    match status {
        WS_STATUS_OK => {
            if payload.len() < 1 + 8 {
                return Err(error::fmt!(SocketError, "QWP OK response truncated"));
            }
            let seq = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            Ok(PipelinedResponse::Ok { sequence: seq })
        }
        WS_STATUS_DURABLE_ACK => Ok(PipelinedResponse::DurableAck),
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

fn parse_error_body(payload: &[u8]) -> crate::Result<(u64, String)> {
    if payload.len() < 1 + 8 + 2 {
        return Err(error::fmt!(SocketError, "QWP error response truncated"));
    }
    let seq = u64::from_le_bytes(payload[1..9].try_into().unwrap());
    let msg_len = u16::from_le_bytes(payload[9..11].try_into().unwrap()) as usize;
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
}
