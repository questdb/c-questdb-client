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

//! Sync QWP/WebSocket (RFC 6455) sender. Hand-rolled HTTP/1.1 upgrade and binary
//! framing — no external WebSocket dependency. See QWP_SPECIFICATION §2 (transport),
//! §3 (version negotiation) and §13 (response format).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rand::RngCore;

use crate::error;
use crate::ingress::SyncProtocolHandler;
use crate::ingress::buffer::{QwpBuffer, QwpWsEncodeScratch, SchemaRegistry, SymbolGlobalDict};
use crate::ingress::conf::QwpWsConfig;
use crate::ingress::tls::{TlsSettings, configure_tls};

use super::qwp_ws_codec::{
    self as codec, MAX_INBOUND_FRAME_BYTES, ResponseAction, WS_OPCODE_BINARY, WS_OPCODE_CLOSE,
    WS_OPCODE_CONTINUATION, WS_OPCODE_PING, WS_OPCODE_PONG, WS_OPCODE_TEXT,
};

// ---------- transport ----------

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

pub(crate) enum WsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl WsStream {
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()> {
        let sock = match self {
            WsStream::Plain(s) => s,
            WsStream::Tls(s) => s.get_ref(),
        };
        sock.set_read_timeout(read)?;
        sock.set_write_timeout(write)?;
        Ok(())
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.read(buf),
            WsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.write(buf),
            WsStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsStream::Plain(s) => s.flush(),
            WsStream::Tls(s) => s.flush(),
        }
    }
}

// ---------- handler state ----------

pub(crate) struct SyncQwpWsHandlerState {
    pub(crate) stream: WsStream,
    #[allow(dead_code)]
    pub(crate) request_timeout: Duration,
    pub(crate) negotiated_version: u8,
    pub(crate) global_dict: SymbolGlobalDict,
    pub(crate) schema_registry: SchemaRegistry,
    pub(crate) scratch: QwpWsEncodeScratch,
    pub(crate) recv: Vec<u8>,
    pub(crate) send_buf: Vec<u8>,
    #[allow(dead_code)]
    pub(crate) request_durable_ack: bool,
    pub(crate) sequence: u64,
    /// Inputs needed to re-establish the connection on a failover. Populated
    /// at construction time so a flush mid-stream doesn't have to re-read
    /// `SenderBuilder` state.
    pub(crate) reconnect: ReconnectParams,
    /// Latched once we exhaust failover and the sender becomes unusable.
    pub(crate) terminal_error: Option<crate::Error>,
}

#[derive(Clone)]
pub(crate) struct ReconnectParams {
    pub(crate) host: String,
    pub(crate) port: String,
    pub(crate) use_tls: bool,
    pub(crate) tls_settings: Option<crate::ingress::tls::TlsSettings>,
    pub(crate) auth_header: Option<String>,
    pub(crate) qwp_ws: crate::ingress::conf::QwpWsConfig,
    pub(crate) on_failover_reset: Option<crate::ingress::FailoverCallback>,
}

// ---------- minimal SHA-1 for Sec-WebSocket-Accept ----------

// ---------- frame I/O ----------

fn random_mask() -> [u8; 4] {
    let mut mask = [0u8; 4];
    rand::rng().fill_bytes(&mut mask);
    mask
}

/// Write a single binary frame (FIN=1, opcode=0x2). Mask-bit set as required for
/// client → server frames. `out` is a scratch buffer; the frame is then written
/// to `stream` in one or more `write_all` calls.
pub(crate) fn write_binary_frame<W: Write>(
    stream: &mut W,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> std::io::Result<()> {
    codec::write_frame_to_buf(out, true, WS_OPCODE_BINARY, payload, random_mask());
    stream.write_all(out)
}

/// Read one full WebSocket message into `out`. Reassembles fragmented frames.
/// Replies to PING with PONG and treats CLOSE as an error. Returns the opcode
/// of the first data frame (text/binary).
pub(crate) fn read_message<S: Read + Write>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> crate::Result<u8> {
    out.clear();
    let mut first_opcode: Option<u8> = None;
    loop {
        let (fin, opcode, payload) = read_frame(stream)?;
        match opcode {
            WS_OPCODE_PING => {
                codec::write_frame_to_buf(scratch, true, WS_OPCODE_PONG, &payload, random_mask());
                stream.write_all(scratch).map_err(|io| {
                    error::fmt!(SocketError, "Could not send WebSocket PONG: {}", io)
                })?;
                continue;
            }
            WS_OPCODE_PONG => continue,
            WS_OPCODE_CLOSE => {
                let reason = codec::ws_close_reason(&payload);
                return Err(error::fmt!(
                    SocketError,
                    "WebSocket connection closed by server{}",
                    reason
                ));
            }
            WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
                if first_opcode.is_some() {
                    return Err(error::fmt!(
                        SocketError,
                        "Unexpected new data frame mid-message"
                    ));
                }
                first_opcode = Some(opcode);
                out.extend_from_slice(&payload);
            }
            WS_OPCODE_CONTINUATION => {
                if first_opcode.is_none() {
                    return Err(error::fmt!(
                        SocketError,
                        "Continuation frame without prior data frame"
                    ));
                }
                out.extend_from_slice(&payload);
            }
            other => {
                return Err(error::fmt!(
                    SocketError,
                    "Unknown WebSocket opcode: 0x{:x}",
                    other
                ));
            }
        }
        if fin {
            return Ok(first_opcode.unwrap());
        }
    }
}

fn read_frame<R: Read>(stream: &mut R) -> crate::Result<(bool, u8, Vec<u8>)> {
    let mut hdr = [0u8; 2];
    read_exact_io(stream, &mut hdr, "WebSocket frame header")?;
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    let len_short = hdr[1] & 0x7F;
    let payload_len: u64 = match len_short {
        126 => {
            let mut b = [0u8; 2];
            read_exact_io(stream, &mut b, "WebSocket frame length")?;
            u16::from_be_bytes(b) as u64
        }
        127 => {
            let mut b = [0u8; 8];
            read_exact_io(stream, &mut b, "WebSocket frame length")?;
            u64::from_be_bytes(b)
        }
        n => n as u64,
    };

    if payload_len > MAX_INBOUND_FRAME_BYTES {
        return Err(error::fmt!(
            SocketError,
            "WebSocket frame too large: {} bytes",
            payload_len
        ));
    }

    let mut mask = [0u8; 4];
    if masked {
        read_exact_io(stream, &mut mask, "WebSocket frame mask")?;
    }

    let mut payload = vec![0u8; payload_len as usize];
    if !payload.is_empty() {
        read_exact_io(stream, &mut payload, "WebSocket frame payload")?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((fin, opcode, payload))
}

fn read_exact_io<R: Read>(stream: &mut R, buf: &mut [u8], what: &str) -> crate::Result<()> {
    stream
        .read_exact(buf)
        .map_err(|io| error::fmt!(SocketError, "Could not read {}: {}", what, io))
}

// ---------- HTTP/1.1 upgrade ----------

#[allow(clippy::too_many_arguments)]
pub(crate) fn perform_upgrade<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    auth_header: Option<&str>,
    max_version: u32,
    client_id: Option<&str>,
    request_durable_ack: bool,
) -> crate::Result<u8> {
    // RFC 6455 only requires a 16-byte random nonce that the client base64-
    // encodes. It is not a security boundary.
    let mut key_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut key_bytes);
    let key_b64 = codec::b64_encode(&key_bytes);

    let req = codec::build_upgrade_request(
        host_header,
        &key_b64,
        auth_header,
        max_version,
        client_id,
        request_durable_ack,
    );

    stream.write_all(req.as_bytes()).map_err(|io| {
        error::fmt!(
            SocketError,
            "Could not send WebSocket upgrade request: {}",
            io
        )
    })?;

    let header_block = read_http_header_block(stream)?;
    let parsed = codec::parse_http_header_block(&header_block)?;
    let expected_accept = codec::compute_accept(&key_b64);
    codec::validate_upgrade_response(&parsed, &expected_accept)
}

fn read_http_header_block<R: Read>(stream: &mut R) -> crate::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|io| error::fmt!(SocketError, "Could not read upgrade response: {}", io))?;
        if n == 0 {
            return Err(error::fmt!(
                SocketError,
                "Connection closed before WebSocket upgrade completed"
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = codec::find_subsequence(&buf, b"\r\n\r\n") {
            buf.truncate(pos);
            return Ok(buf);
        }
        if buf.len() > 8192 {
            return Err(error::fmt!(
                SocketError,
                "WebSocket upgrade response exceeds 8 KiB header limit"
            ));
        }
    }
}

// ---------- connect ----------

/// Establish a fresh QWP/WebSocket connection: TCP → optional TLS → HTTP
/// upgrade. Returns the connected stream and the version the server picked.
fn establish_connection(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<&str>,
) -> crate::Result<(WsStream, u8)> {
    use std::net::ToSocketAddrs;

    let connect_timeout = *qwp_ws.connect_timeout;
    let request_timeout = *qwp_ws.request_timeout;

    let addr = (
        host,
        port.parse::<u16>()
            .map_err(|_| error::fmt!(ConfigError, "Invalid port: {:?}", port))?,
    )
        .to_socket_addrs()
        .map_err(|io| {
            error::fmt!(
                CouldNotResolveAddr,
                "Could not resolve {}:{}: {}",
                host,
                port,
                io
            )
        })?
        .next()
        .ok_or_else(|| {
            error::fmt!(
                CouldNotResolveAddr,
                "No address found for {}:{}",
                host,
                port
            )
        })?;

    let tcp = TcpStream::connect_timeout(&addr, connect_timeout)
        .map_err(|io| error::fmt!(SocketError, "Could not connect to {}: {}", addr, io))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(request_timeout)).ok();
    tcp.set_write_timeout(Some(request_timeout)).ok();

    let mut stream = if use_tls {
        let tls = tls_settings.ok_or_else(|| {
            error::fmt!(ConfigError, "TLS settings missing for QWP/WebSocket Secure")
        })?;
        let cfg: Arc<rustls::ClientConfig> = configure_tls(tls)?;
        let server_name = host
            .to_string()
            .try_into()
            .map_err(|e| error::fmt!(TlsError, "Invalid TLS server name {:?}: {}", host, e))?;
        let conn = rustls::ClientConnection::new(cfg, server_name)
            .map_err(|e| error::fmt!(TlsError, "TLS handshake setup failed: {}", e))?;
        WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        WsStream::Plain(tcp)
    };

    let host_header = if (use_tls && port == "443") || (!use_tls && port == "80") {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let max_version = *qwp_ws.max_protocol_version;
    let client_id = qwp_ws.client_id.as_deref();
    let request_durable_ack = *qwp_ws.request_durable_ack;

    let negotiated_version = perform_upgrade(
        &mut stream,
        &host_header,
        auth_header,
        max_version,
        client_id,
        request_durable_ack,
    )?;

    stream
        .set_timeouts(Some(request_timeout), Some(request_timeout))
        .ok();

    Ok((stream, negotiated_version))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn connect_qwp_ws(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
    on_failover_reset: Option<crate::ingress::FailoverCallback>,
) -> crate::Result<SyncProtocolHandler> {
    let (stream, negotiated_version) = establish_connection(
        host,
        port,
        use_tls,
        tls_settings.clone(),
        qwp_ws,
        auth_header.as_deref(),
    )?;

    Ok(SyncProtocolHandler::SyncQwpWs(Box::new(
        SyncQwpWsHandlerState {
            stream,
            request_timeout: *qwp_ws.request_timeout,
            negotiated_version,
            global_dict: SymbolGlobalDict::new(),
            schema_registry: SchemaRegistry::new(),
            scratch: QwpWsEncodeScratch::new(),
            recv: Vec::new(),
            send_buf: Vec::with_capacity(16 * 1024),
            request_durable_ack: *qwp_ws.request_durable_ack,
            sequence: 0,
            reconnect: ReconnectParams {
                host: host.to_string(),
                port: port.to_string(),
                use_tls,
                tls_settings,
                auth_header,
                qwp_ws: qwp_ws.clone(),
                on_failover_reset,
            },
            terminal_error: None,
        },
    )))
}

// ---------- send / receive ----------

/// Public flush entry point: dispatches to the failover loop when enabled, or
/// to a single attempt otherwise.
pub(crate) fn flush_qwp_ws(
    state: &mut SyncQwpWsHandlerState,
    buffer: &QwpBuffer,
) -> crate::Result<()> {
    if let Some(err) = &state.terminal_error {
        return Err(err.clone());
    }

    match flush_once(state, buffer) {
        Ok(()) => Ok(()),
        Err(err) if is_transport_error(&err) && *state.reconnect.qwp_ws.failover => {
            attempt_failover(state, buffer, err)
        }
        Err(err) => {
            if is_transport_error(&err) {
                // failover=off: latch a terminal error so subsequent flushes
                // surface it directly (the user must rebuild the sender).
                state.terminal_error = Some(err.clone());
            }
            Err(err)
        }
    }
}

fn is_transport_error(err: &crate::Error) -> bool {
    matches!(err.code(), crate::ErrorCode::SocketError)
}

fn flush_once(state: &mut SyncQwpWsHandlerState, buffer: &QwpBuffer) -> crate::Result<()> {
    let seq = state.sequence;
    state.sequence = state.sequence.wrapping_add(1);

    state.scratch.message.clear();
    buffer.encode_ws_message(
        &mut state.scratch,
        &mut state.global_dict,
        &mut state.schema_registry,
        state.negotiated_version,
    )?;

    write_binary_frame(
        &mut state.stream,
        &mut state.send_buf,
        &state.scratch.message,
    )
    .map_err(|io| error::fmt!(SocketError, "Could not send WebSocket frame: {}", io))?;
    state
        .stream
        .flush()
        .map_err(|io| error::fmt!(SocketError, "Could not flush WebSocket frame: {}", io))?;

    // Read response frames until we see a non-durable-ack response.
    loop {
        let opcode = read_message(&mut state.stream, &mut state.send_buf, &mut state.recv)?;
        if opcode != WS_OPCODE_BINARY {
            return Err(error::fmt!(
                SocketError,
                "QWP/WS expected binary response frame, got opcode 0x{:x}",
                opcode
            ));
        }
        match codec::parse_response(&state.recv, seq)? {
            ResponseAction::Ok => return Ok(()),
            ResponseAction::DurableAck => {
                // Durable-acks are notifications; keep reading until we see the
                // matching OK/error for this sequence number.
                continue;
            }
        }
    }
}

/// Reconnect loop: bounded number of attempts, exponential backoff capped at
/// `failover_max_backoff`, total wall-clock budget. On each attempt we drop
/// the dead stream, re-establish the connection (TCP/TLS/upgrade), reset all
/// connection-scoped encoder state, and replay the user's buffer through
/// `flush_once`. The first success returns `Ok` and fires the user callback.
fn attempt_failover(
    state: &mut SyncQwpWsHandlerState,
    buffer: &QwpBuffer,
    initial_err: crate::Error,
) -> crate::Result<()> {
    let attempts = *state.reconnect.qwp_ws.max_failover_attempts;
    let mut backoff = *state.reconnect.qwp_ws.failover_initial_backoff;
    let max_backoff = *state.reconnect.qwp_ws.failover_max_backoff;
    let deadline = std::time::Instant::now() + *state.reconnect.qwp_ws.failover_total_budget;

    let mut last_err = initial_err;
    for _ in 0..attempts {
        if std::time::Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(backoff);
        backoff = backoff.saturating_mul(2).min(max_backoff);

        match reconnect_and_replay(state, buffer) {
            Ok(()) => {
                if let Some(cb) = &state.reconnect.on_failover_reset {
                    (cb.0)();
                }
                return Ok(());
            }
            Err(e) => last_err = e,
        }
    }
    state.terminal_error = Some(last_err.clone());
    Err(last_err)
}

fn reconnect_and_replay(
    state: &mut SyncQwpWsHandlerState,
    buffer: &QwpBuffer,
) -> crate::Result<()> {
    let (stream, version) = establish_connection(
        &state.reconnect.host,
        &state.reconnect.port,
        state.reconnect.use_tls,
        state.reconnect.tls_settings.clone(),
        &state.reconnect.qwp_ws,
        state.reconnect.auth_header.as_deref(),
    )?;
    state.stream = stream;
    state.negotiated_version = version;
    // Server resets connection-scoped state on its end; we must too.
    state.global_dict = SymbolGlobalDict::new();
    state.schema_registry = SchemaRegistry::new();
    state.sequence = 0;
    flush_once(state, buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_short_payload_is_masked() {
        let mut out = Vec::new();
        let payload = b"hello";
        codec::write_frame_to_buf(&mut out, true, WS_OPCODE_BINARY, payload, [0; 4]);
        assert_eq!(out[0], 0x82); // FIN | binary
        assert_eq!(out[1] & 0x80, 0x80); // masked
        assert_eq!(out[1] & 0x7F, 5); // length
    }
}
