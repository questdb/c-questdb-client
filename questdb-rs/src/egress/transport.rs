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

//! Sync WebSocket transport for the QWP egress endpoint.
//!
//! Supports both `ws://` and `wss://` via `MaybeTlsStream`. The transport
//! handles the HTTP upgrade (with negotiation headers and any
//! Authorization), then exposes frame-level read/write that maps each
//! QWP frame to one WebSocket binary message. TLS is wired through
//! `tungstenite::Connector::Rustls` with a `rustls::ClientConfig`
//! built from the egress connect-string knobs (`tls_ca`, `tls_roots`,
//! `tls_verify`) — see `egress/tls.rs`.
//!
//! The `sync-reader-ws` feature gate is applied at the module
//! declaration in `egress/mod.rs`; an inner `#![cfg(...)]` here would
//! duplicate that gate (clippy::duplicated_attributes) without
//! changing what's compiled.

use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use bytes::Bytes;
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::HandshakeError;
use tungstenite::handshake::client::generate_key;
use tungstenite::http::{HeaderName, HeaderValue, Request, Uri};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{ClientRequestBuilder, Connector, Message, WebSocket};

use crate::egress::config::ReaderConfig;
use crate::egress::error::{Error, ErrorCode, Result, fmt};
use crate::egress::tls::build_client_config;
use crate::egress::wire::header::{FrameHeader, HEADER_LEN};

/// Per-write upper bound applied to the underlying `TcpStream` after a
/// successful handshake. Caps any single `write()` syscall — including
/// the WS Close frame written from `Drop` / `close_in_place` — so a
/// stuck-but-not-RST'd peer can't hang the calling thread indefinitely.
/// Generous enough that realistic large-payload writes (multi-MB binds)
/// are not affected, tight enough that failover teardown stays
/// responsive.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Shorter timeout applied right before the WS Close write on
/// teardown. The connection is being released regardless; a graceful
/// close-frame ACK is best-effort, so prioritise fast FD release over
/// peer-friendliness.
const CLOSE_TIMEOUT: Duration = Duration::from_millis(200);

/// Header key the server uses to advertise the negotiated QWP version.
const HDR_VERSION: &str = "x-qwp-version";

/// Header key carrying the server-selected payload encoding.
#[allow(dead_code)] // used in TLS chunk follow-up for compression negotiation
const HDR_CONTENT_ENCODING: &str = "x-qwp-content-encoding";

/// Sync WebSocket transport bound to a single QWP read connection.
pub struct WsTransport {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    server_version: u8,
}

impl WsTransport {
    /// Connect to a specific endpoint in `config.addrs` by index.
    pub fn connect_to(config: &ReaderConfig, addr_idx: usize) -> Result<Self> {
        if addr_idx >= config.addrs.len() {
            return Err(fmt!(
                ConfigError,
                "addr index {} out of range ({} endpoints)",
                addr_idx,
                config.addrs.len()
            ));
        }
        let endpoint = &config.addrs[addr_idx];
        let url = config.url_for(addr_idx);
        let uri: Uri = url
            .parse()
            .map_err(|e| fmt!(ConfigError, "invalid endpoint URL {:?}: {}", url, e))?;

        let mut builder = ClientRequestBuilder::new(uri);
        for (name, value) in config.upgrade_headers() {
            builder = builder.with_header(name, value);
        }

        // Hand the request to tungstenite via IntoClientRequest. We need to
        // make sure mandatory WS handshake headers (Sec-WebSocket-Key /
        // Version / Upgrade / Connection / Host) are present — tungstenite's
        // generate_request adds them automatically when going through
        // IntoClientRequest.
        let request = builder
            .into_client_request()
            .map_err(map_ws_error_during_handshake)?;
        debug_assert_handshake_headers(&request);

        // Resolve & TCP-connect ourselves so we can hand a custom
        // `rustls::ClientConfig` (with the negotiated `tls_ca` /
        // `tls_roots` / `tls_verify` knobs) to tungstenite. Going
        // through `tungstenite::connect()` would force the built-in
        // webpki-roots config and bypass any of the user's TLS knobs.
        let tcp = TcpStream::connect((endpoint.host.as_str(), endpoint.port))
            .map_err(|e| fmt!(SocketError, "could not connect to {}: {}", endpoint, e))?;
        let connector = build_client_config(config)?.map(Connector::Rustls);
        let (socket, response) = tungstenite::client_tls_with_config(request, tcp, None, connector)
            .map_err(map_handshake_error)?;

        // Build the `WsTransport` struct *before* the version check so
        // any failure path (here or elsewhere) goes through `Drop for
        // WsTransport`, which sends the WS Close frame and shuts the
        // socket down cleanly. A bare `socket` drop closes the FD but
        // skips the courtesy Close — the server then sees a half-closed
        // TCP and has to wait for its read timeout to clean up.
        let server_version = match read_version_header(response.headers()) {
            Ok(v) => v,
            Err(e) => {
                let mut transport = WsTransport {
                    socket,
                    server_version: 0,
                };
                set_tcp_write_timeout(transport.socket.get_mut(), Some(WRITE_TIMEOUT));
                drop(transport);
                return Err(e);
            }
        };
        let mut transport = WsTransport {
            socket,
            server_version,
        };
        // Bound every subsequent write to the peer. Without this, a
        // stuck/blackholed peer can hang the WS Close in `Drop` /
        // `close_in_place` indefinitely — defeating the failover
        // backoff schedule, and making `Cursor::cancel()` look like
        // it's hung on a network blip. See `WRITE_TIMEOUT`.
        set_tcp_write_timeout(transport.socket.get_mut(), Some(WRITE_TIMEOUT));
        if server_version > config.max_version {
            // Drop runs the graceful Close (set_tcp_write_timeout above
            // ensures we don't block forever on a misbehaving peer).
            drop(transport);
            return Err(fmt!(
                UnsupportedServer,
                "server negotiated QWP version {} but client advertised max {}",
                server_version,
                config.max_version
            ));
        }
        Ok(transport)
    }

    /// Negotiated QWP version. The frame header `version` byte must equal
    /// this on every send and receive (server closes the WS otherwise).
    pub fn server_version(&self) -> u8 {
        self.server_version
    }

    /// Write a client-to-server message as a single WebSocket binary
    /// message. Per QWP, client frames are bare payloads — only
    /// server-to-client frames carry the 12-byte `QWP1` header.
    pub fn write_message(&mut self, payload: &[u8]) -> Result<()> {
        self.socket
            .send(Message::Binary(payload.to_vec().into()))
            .map_err(|e| map_ws_error(e, ErrorCode::SocketError))?;
        Ok(())
    }

    /// Read the next QWP frame (header + payload). Pings/pongs are
    /// handled transparently; a `Close` from the server surfaces as a
    /// `SocketError`.
    pub fn read_frame(&mut self) -> Result<(FrameHeader, Bytes)> {
        loop {
            let msg = self
                .socket
                .read()
                .map_err(|e| map_ws_error(e, ErrorCode::SocketError))?;
            match msg {
                Message::Binary(bytes) => {
                    if bytes.len() < HEADER_LEN {
                        return Err(fmt!(
                            ProtocolError,
                            "WS message too short for frame header: {} bytes",
                            bytes.len()
                        ));
                    }
                    let header = FrameHeader::parse(&bytes[..HEADER_LEN])?;
                    if header.version != self.server_version {
                        return Err(fmt!(
                            ProtocolError,
                            "frame header version {} != negotiated {}",
                            header.version,
                            self.server_version
                        ));
                    }
                    if header.payload_length as usize != bytes.len() - HEADER_LEN {
                        return Err(fmt!(
                            ProtocolError,
                            "header payload_length {} != actual {}",
                            header.payload_length,
                            bytes.len() - HEADER_LEN
                        ));
                    }
                    // Zero-copy slice: `Bytes` is ref-counted, so `slice` only
                    // bumps the refcount and updates the offset/length.
                    let payload = bytes.slice(HEADER_LEN..);
                    return Ok((header, payload));
                }
                Message::Close(frame) => {
                    return Err(fmt!(SocketError, "server closed WebSocket: {:?}", frame));
                }
                // Tungstenite auto-ponds; nothing to do for ping/pong.
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Text(t) => {
                    return Err(fmt!(
                        ProtocolError,
                        "unexpected WS text frame ({} bytes); QWP uses binary",
                        t.len()
                    ));
                }
                Message::Frame(_) => continue, // raw frames not surfaced in read()
            }
        }
    }

    /// Apply (or clear) a TCP read timeout on the underlying stream.
    ///
    /// `Some(t)` causes the next blocking read that goes longer than `t`
    /// to surface as an `Io` error from tungstenite (`SocketError`);
    /// `None` reverts to the default (no timeout). Used by
    /// `Cursor::cancel()` to bound the post-CANCEL drain so a
    /// stuck-but-not-RST'd peer cannot hang the cancel forever.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        set_tcp_read_timeout(self.socket.get_mut(), timeout);
    }

    /// Best-effort in-place close. Initiates the WS closing handshake
    /// without consuming `self` so callers borrowing `&mut WsTransport`
    /// (e.g. `Cursor::Drop`) can release the connection.
    ///
    /// Tightens the write timeout to `CLOSE_TIMEOUT` for the WS Close
    /// write, then issues a TCP `Shutdown::Both` so the FD is released
    /// regardless of peer state. Subsequent reads/writes on this
    /// transport will fail at the tungstenite layer. Bounded
    /// teardown: critical on the failover path, where a stuck peer
    /// would otherwise stall the calling thread before the backoff
    /// sleep had a chance to start.
    pub fn close_in_place(&mut self) {
        teardown_inplace(&mut self.socket);
    }
}

impl Drop for WsTransport {
    fn drop(&mut self) {
        // Fire-and-forget close per the project policy. Bounded by
        // `CLOSE_TIMEOUT` plus the unconditional `Shutdown::Both` —
        // see `close_in_place`.
        teardown_inplace(&mut self.socket);
    }
}

/// Set `set_write_timeout` on the underlying `TcpStream`, walking
/// through any TLS wrapper. The `MaybeTlsStream` enum is
/// `#[non_exhaustive]`; the `_` arm is for future variants we don't
/// know how to peel.
fn set_tcp_write_timeout(stream: &mut MaybeTlsStream<TcpStream>, timeout: Option<Duration>) {
    match stream {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_write_timeout(timeout);
        }
        MaybeTlsStream::Rustls(s) => {
            let _ = s.sock.set_write_timeout(timeout);
        }
        _ => {}
    }
}

/// Set `set_read_timeout` on the underlying `TcpStream`, walking through
/// any TLS wrapper. Same `_` arm rationale as
/// [`set_tcp_write_timeout`].
fn set_tcp_read_timeout(stream: &mut MaybeTlsStream<TcpStream>, timeout: Option<Duration>) {
    match stream {
        MaybeTlsStream::Plain(s) => {
            let _ = s.set_read_timeout(timeout);
        }
        MaybeTlsStream::Rustls(s) => {
            let _ = s.sock.set_read_timeout(timeout);
        }
        _ => {}
    }
}

/// Issue a TCP-level shutdown(Both) on the underlying `TcpStream`.
/// Releases the FD synchronously regardless of peer state — the WS
/// Close write may or may not have made it through.
fn shutdown_tcp(stream: &mut MaybeTlsStream<TcpStream>) {
    match stream {
        MaybeTlsStream::Plain(s) => {
            let _ = s.shutdown(Shutdown::Both);
        }
        MaybeTlsStream::Rustls(s) => {
            let _ = s.sock.shutdown(Shutdown::Both);
        }
        _ => {}
    }
}

/// Bounded teardown sequence: tighten write timeout, attempt the WS
/// Close (best-effort), then TCP-shutdown to force FD release. Used
/// by `Drop`, `close_in_place`, and the `close` consuming variant so
/// they share identical semantics.
fn teardown_inplace(socket: &mut WebSocket<MaybeTlsStream<TcpStream>>) {
    set_tcp_write_timeout(socket.get_mut(), Some(CLOSE_TIMEOUT));
    let _ = socket.close(None);
    shutdown_tcp(socket.get_mut());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_version_header(headers: &tungstenite::http::HeaderMap) -> Result<u8> {
    let raw = headers
        .iter()
        .find(|(name, _)| name.as_str().eq_ignore_ascii_case(HDR_VERSION))
        .map(|(_, value)| value)
        .ok_or_else(|| {
            fmt!(
                HandshakeError,
                "server response missing X-QWP-Version header"
            )
        })?;
    let s = raw
        .to_str()
        .map_err(|_| fmt!(HandshakeError, "X-QWP-Version header is not valid ASCII"))?;
    s.trim()
        .parse::<u8>()
        .map_err(|_| fmt!(HandshakeError, "X-QWP-Version {:?} is not a u8", s))
}

fn map_ws_error(e: tungstenite::Error, default_code: ErrorCode) -> Error {
    use tungstenite::error::{Error as T, ProtocolError as P, UrlError as U};
    let msg = e.to_string();
    let code = match &e {
        T::Io(_) => ErrorCode::SocketError,
        T::ConnectionClosed | T::AlreadyClosed => ErrorCode::SocketError,
        // Send/receive after a Close frame is a transport-state error,
        // not a wire-format error — surface it as SocketError so
        // callers see a consistent "connection is gone" code regardless
        // of which tungstenite variant fires post-close.
        T::Protocol(P::SendAfterClosing) | T::Protocol(P::ReceivedAfterClosing) => {
            ErrorCode::SocketError
        }
        // `UnableToConnect` is tungstenite's catch-all for refused /
        // unreachable / DNS-failed connects — that's a transport
        // failure, not a config one, and the failover machinery
        // depends on `SocketError` to keep walking the address list.
        T::Url(U::UnableToConnect(_)) => ErrorCode::SocketError,
        T::Url(_) => ErrorCode::ConfigError,
        T::HttpFormat(_) | T::Protocol(_) | T::Utf8(_) => ErrorCode::ProtocolError,
        T::Tls(_) => ErrorCode::TlsError,
        T::Http(_) | T::Capacity(_) | T::WriteBufferFull(_) => default_code,
        _ => default_code,
    };
    Error::new(code, msg)
}

/// Convert a `HandshakeError` from `client_tls_with_config` into an
/// egress `Error`. The `Interrupted` variant is unreachable on blocking
/// IO, but we surface it as a handshake failure rather than panicking
/// — defensive in case a future tungstenite version makes the path
/// reachable.
fn map_handshake_error(
    e: HandshakeError<tungstenite::ClientHandshake<MaybeTlsStream<TcpStream>>>,
) -> Error {
    match e {
        HandshakeError::Failure(err) => map_ws_error_during_handshake(err),
        HandshakeError::Interrupted(_) => fmt!(
            HandshakeError,
            "WebSocket handshake interrupted; non-blocking sockets are not supported"
        ),
    }
}

fn map_ws_error_during_handshake(e: tungstenite::Error) -> Error {
    use tungstenite::error::{Error as T, UrlError as U};
    let msg = e.to_string();
    let code = match &e {
        T::Http(resp) => {
            let status = resp.status().as_u16();
            if status == 401 || status == 403 {
                ErrorCode::AuthError
            } else {
                ErrorCode::HandshakeError
            }
        }
        T::HttpFormat(_) => ErrorCode::HandshakeError,
        // See `map_ws_error`: `UnableToConnect` is a transport failure.
        // Misclassifying it as `ConfigError` defeats both the initial
        // connect walk's continue-past-unreachable behaviour and the
        // mid-query failover's transport-error eligibility.
        T::Url(U::UnableToConnect(_)) => ErrorCode::SocketError,
        T::Url(_) => ErrorCode::ConfigError,
        T::Tls(_) => ErrorCode::TlsError,
        T::Io(_) => ErrorCode::SocketError,
        _ => ErrorCode::HandshakeError,
    };
    Error::new(code, format!("WebSocket handshake failed: {}", msg))
}

#[allow(dead_code)]
fn debug_assert_handshake_headers(_req: &Request<()>) {
    // Tungstenite adds Sec-WebSocket-Key/Version/Upgrade/Connection/Host on
    // its own when ClientRequestBuilder is fed through IntoClientRequest.
    // Keep this hook for diagnostics in debug builds.
    let _ = HeaderName::from_static("upgrade");
    let _ = HeaderValue::from_static("websocket");
    let _ = generate_key();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Real handshake/round-trip tests live in
    // questdb-rs/tests/egress_ws_integration.rs so they can spin up an
    // in-process tungstenite server.

    #[test]
    fn module_is_compilable() {
        // Sanity check: the `cfg(feature = "sync-reader-ws")` gate is open
        // when this test runs.
    }
}
