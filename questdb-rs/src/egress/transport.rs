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

use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::time::Duration;

use bytes::Bytes;
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::HandshakeError;
use tungstenite::handshake::client::generate_key;
use tungstenite::http::{HeaderName, HeaderValue, Request, Uri};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{ClientRequestBuilder, Connector, Message, WebSocket};

use crate::egress::config::ReaderConfig;
use crate::egress::error::{Error, ErrorCode, Result, UpgradeReject, fmt};
use crate::egress::tls::build_client_config;
use crate::egress::wire::MsgKind;
use crate::egress::wire::header::{FrameHeader, HEADER_LEN};
use crate::egress::wire::roles;

/// Per-write upper bound applied to the underlying `TcpStream` after a
/// successful handshake. Caps any single `write()` syscall — including
/// the WS Close frame written from `Drop` / `close_in_place` — so a
/// stuck-but-not-RST'd peer can't hang the calling thread indefinitely.
/// Generous enough that realistic large-payload writes (multi-MB binds)
/// are not affected, tight enough that failover teardown stays
/// responsive.
pub(crate) const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// Shorter timeout applied right before the WS Close write on
/// teardown. The connection is being released regardless; a graceful
/// close-frame ACK is best-effort, so prioritise fast FD release over
/// peer-friendliness.
pub(crate) const CLOSE_TIMEOUT: Duration = Duration::from_millis(200);

/// Per-batch wire-size ceiling we accept on the read side.
///
/// Spec §16 lists `Max RESULT_BATCH wire size: 16 MiB`. We pad a 4× margin
/// (matching the `MAX_ZSTD_DECOMPRESSED` cap in `decoder.rs`) so legitimate
/// frames near the spec ceiling never trip the guard, while a malformed or
/// hostile server can't get the client to allocate gigabytes from a single
/// `header.payload_length` value (which is itself a u32 — i.e. up to 4 GiB
/// of raw wire bytes if left unbounded). Applied at two layers:
///
/// - `WebSocketConfig::max_message_size`, so tungstenite refuses to even
///   buffer an oversized frame (defends against out-of-memory before any
///   QWP parsing runs).
/// - An explicit `header.payload_length` check in `read_frame`, so a
///   future tungstenite default change can't silently raise our ceiling.
const MAX_BATCH_WIRE_BYTES: usize = 64 * 1024 * 1024;

/// Header key the server uses to advertise the negotiated QWP version.
const HDR_VERSION: &str = "x-qwp-version";

/// Header key carrying the server-selected payload encoding (per spec §3:
/// `raw` / `identity` / `zstd[;level=N]`). Validated at handshake time so
/// a missing-feature failure surfaces here, not on the first batch.
const HDR_CONTENT_ENCODING: &str = "x-qwp-content-encoding";

/// Header key carrying the server's cluster role on a `421` upgrade
/// reject (failover.md §5). The value SHOULD be one of
/// `STANDALONE` / `PRIMARY` / `REPLICA` / `PRIMARY_CATCHUP`; the client
/// matches `PRIMARY_CATCHUP` case-insensitively and treats every other
/// non-empty value as topological.
const HDR_ROLE: &str = "x-questdb-role";

/// Optional header on a `421` upgrade reject identifying the server's
/// zone. Compared case-insensitively against the client's `zone=`
/// connect-string knob. Absent (or empty after trimming) leaves the
/// host's zone tier as `Unknown`.
const HDR_ZONE: &str = "x-questdb-zone";

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
        //
        // Resolve and connect as separate steps so a name-resolution
        // failure surfaces as `CouldNotResolveAddr` (distinct from a
        // connect-time `SocketError`). `TcpStream::connect((host, port))`
        // collapses both into a single `io::Error` whose `kind()` is
        // `Other` — losing the user-actionable distinction.
        let mut addrs = (endpoint.host.as_str(), endpoint.port)
            .to_socket_addrs()
            .map_err(|e| fmt!(CouldNotResolveAddr, "could not resolve {}: {}", endpoint, e))?;
        let tcp = match addrs.next() {
            Some(addr) => TcpStream::connect(addr)
                .map_err(|e| fmt!(SocketError, "could not connect to {}: {}", endpoint, e))?,
            None => {
                return Err(fmt!(
                    CouldNotResolveAddr,
                    "name resolution returned no addresses for {}",
                    endpoint
                ));
            }
        };
        // Bound the WS upgrade-response read with `auth_timeout_ms` per
        // failover.md §1.1. This catches the "TCP accepts but server
        // never replies" blackhole that the OS connect timeout misses —
        // a stuck peer would otherwise hang the calling thread for the
        // process default (often minutes). The timeout applies to
        // tungstenite's read of the 101-Switching-Protocols response;
        // it is cleared post-upgrade so subsequent batch reads run
        // without artificial deadlines.
        //
        // Failures here are swallowed (best-effort): if the platform's
        // socket layer rejects the timeout (vanishingly rare on the
        // supported targets), the upgrade still proceeds with the OS
        // default. Surfacing the SetTimeout error as a connect failure
        // would be more obstructive than helpful.
        let _ = tcp.set_read_timeout(Some(Duration::from_millis(config.auth_timeout_ms)));
        let connector = build_client_config(config)?.map(Connector::Rustls);
        // Pin tungstenite's per-message size ceiling explicitly. Without
        // this we inherit the library default (currently 64 MiB but
        // unstable across versions); a defaulting drift would silently
        // change the protocol-level cap we documented in
        // `MAX_BATCH_WIRE_BYTES`. Pin it so the protocol cap and the
        // transport cap are the same number.
        let ws_config = WebSocketConfig::default().max_message_size(Some(MAX_BATCH_WIRE_BYTES));
        let (socket, response) =
            tungstenite::client_tls_with_config(request, tcp, Some(ws_config), connector)
                .map_err(map_handshake_error)?;

        // Build the `WsTransport` struct *before* the version check so
        // any failure path (here or elsewhere) goes through `Drop for
        // WsTransport`, which sends the WS Close frame and shuts the
        // socket down cleanly. A bare `socket` drop closes the FD but
        // skips the courtesy Close — the server then sees a half-closed
        // TCP and has to wait for its read timeout to clean up.
        let handshake_check = read_version_header(response.headers())
            .and_then(|v| validate_content_encoding(response.headers()).map(|_| v));
        let server_version = match handshake_check {
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
        // Clear the per-upgrade read deadline now that the handshake
        // is done. The post-upgrade read path is driven by `Cursor`
        // and `Cursor::cancel()` toggles its own timeout via
        // `set_read_timeout`; leaving the `auth_timeout_ms` value in
        // place would mean every batch-read would silently fault after
        // that interval of server silence (legitimate on slow queries).
        set_tcp_read_timeout(transport.socket.get_mut(), None);
        if server_version > config.max_version {
            // Drop runs the graceful Close (set_tcp_write_timeout above
            // ensures we don't block forever on a misbehaving peer).
            drop(transport);
            // Per failover.md §6 (2026-05-08 change): version-out-of-range
            // is per-endpoint transient, not cluster-wide terminal. One
            // mid-rolling-upgrade node speaking a newer version while
            // peers haven't caught up MUST NOT lock the client out of
            // compatible siblings. Surface as `HandshakeError` so the
            // failover walk treats it as a transport-class transient and
            // keeps trying other endpoints; if every peer disagrees the
            // round-exhaustion error surfaces the version detail.
            return Err(fmt!(
                HandshakeError,
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
    ///
    /// Takes `Bytes` by value so the caller can hand off a refcounted
    /// buffer with no internal copy. Small one-shot frames (CREDIT,
    /// CANCEL) construct a fresh `Vec<u8>` and convert via
    /// `Bytes::from(vec)` (zero-copy move). The QUERY_REQUEST replay
    /// path keeps the encoded body wrapped as `Bytes` across reconnects
    /// and patches the request_id in place via `Bytes::try_into_mut`
    /// then `BytesMut::freeze`, so the multi-MB bind payload is never
    /// copied per failover.
    pub fn write_message(&mut self, payload: Bytes) -> Result<()> {
        self.socket
            .send(Message::Binary(payload))
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
                    // Belt-and-suspenders check: tungstenite's
                    // `max_message_size` already guards the buffer, but
                    // anchoring the protocol-level cap at the parser
                    // makes the ceiling testable without standing up a
                    // socket. Spec §16 caps RESULT_BATCH at 16 MiB; our
                    // 4x-margin cap surfaces server bugs / wire corruption
                    // as a clean ProtocolError instead of either a silent
                    // multi-GiB allocation or a tungstenite-layer error
                    // that's harder to map to "frame too large".
                    if bytes.len() > MAX_BATCH_WIRE_BYTES {
                        return Err(fmt!(
                            LimitExceeded,
                            "frame size {} bytes exceeds client cap {} (spec §16: \
                             RESULT_BATCH max 16 MiB; client allows 4x margin)",
                            bytes.len(),
                            MAX_BATCH_WIRE_BYTES
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

    /// Apply (or clear) a TCP write timeout on the underlying stream.
    ///
    /// `Some(t)` caps any subsequent blocking `write()` syscall at `t`,
    /// surfacing as a transport error if exceeded; `None` reverts to no
    /// timeout. Used by `Cursor::cancel()` to tighten the post-CANCEL
    /// credit-nudge write so a stuck peer cannot inflate the worst-case
    /// cancel latency by an extra `WRITE_TIMEOUT`.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        set_tcp_write_timeout(self.socket.get_mut(), timeout);
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

    /// Best-effort CANCEL frame, tightly bounded for use from Drop.
    ///
    /// Tightens the write timeout to `CLOSE_TIMEOUT` first so an
    /// unresponsive peer can't hold the dropping thread for the full
    /// `WRITE_TIMEOUT` (60 s). All errors are swallowed: this runs
    /// after the user has already abandoned the cursor, so reporting a
    /// failure has nowhere to go. The caller must follow up with
    /// `close_in_place` (or rely on `WsTransport::Drop`) to actually
    /// tear the socket down — this method only sends the frame.
    pub fn try_write_cancel(&mut self, request_id: i64) {
        set_tcp_write_timeout(self.socket.get_mut(), Some(CLOSE_TIMEOUT));
        let mut payload = Vec::with_capacity(9);
        payload.push(MsgKind::Cancel.as_u8());
        payload.extend_from_slice(&request_id.to_le_bytes());
        let _ = self.socket.send(Message::Binary(Bytes::from(payload)));
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

/// Validate the server's chosen body encoding against the features the
/// client was actually built with.
///
/// Spec §3: the server echoes its choice in `X-QWP-Content-Encoding`
/// (omitted means `raw`). Tokens are `name` or `name;param=value`;
/// `raw` and `identity` are aliases for "no compression"; for `zstd`
/// the spec example explicitly shows the server emitting
/// `zstd;level=3`, where the level is a server-side encoder setting
/// (the zstd bitstream is self-describing on the decompress side, so
/// the client doesn't need the level to decode).
///
/// The check fails fast at handshake when the server selected a codec
/// this client build can't handle (e.g. `zstd` against a binary built
/// without the `compression-zstd` feature) so the operator sees a
/// clear "this build can't talk to that server" error before any
/// query runs. Parameters attached to a recognised codec are
/// tolerated and ignored: they're server-side state, and the
/// runtime decoder pulls everything it needs from the frame itself.
fn validate_content_encoding(headers: &tungstenite::http::HeaderMap) -> Result<()> {
    let raw = match headers
        .iter()
        .find(|(name, _)| name.as_str().eq_ignore_ascii_case(HDR_CONTENT_ENCODING))
    {
        Some((_, v)) => v,
        // Header absent => spec §3 default = `raw`. No constraint.
        None => return Ok(()),
    };
    let s = raw.to_str().map_err(|_| {
        fmt!(
            HandshakeError,
            "X-QWP-Content-Encoding header is not valid ASCII"
        )
    })?;
    // Token = name `;` params... — the name selects the codec; the
    // params are codec-scoped server-side state. The QuestDB server
    // emits e.g. `zstd;level=3` per spec §3 example. We do not act on
    // the parameter at decode time (zstd's bitstream carries its own
    // header), so tolerating unknown parameters on a recognised codec
    // is safe and forward-compatible — a future spec revision that
    // adds e.g. `zstd;dict=<id>` will still let this client decode
    // its way through every batch whose dict happens to be the
    // default.
    //
    // Splitting off the codec name keeps the unknown-codec error
    // message tidy (no trailing parameter noise).
    let mut parts = s.split(';');
    let name = parts.next().unwrap_or("").trim();
    // RFC 7231 §3.1.2.1: "All content-codings are case-insensitive."
    // A standards-compliant server or any transparent proxy along
    // the path may rewrite the casing (`Zstd`, `ZSTD`, `Identity`).
    // Compare ignoring ASCII case so the handshake doesn't fail on
    // capitalisation alone. The original (preserved-case) `name`
    // still flows into the unknown-codec error message so the
    // diagnostic mirrors what the server actually emitted.
    if name.eq_ignore_ascii_case("raw") || name.eq_ignore_ascii_case("identity") || name.is_empty()
    {
        // `raw` and `identity` are spec-aliases for no compression.
        Ok(())
    } else if name.eq_ignore_ascii_case("zstd") {
        #[cfg(feature = "compression-zstd")]
        {
            Ok(())
        }
        #[cfg(not(feature = "compression-zstd"))]
        {
            Err(fmt!(
                HandshakeError,
                "server selected X-QWP-Content-Encoding {:?} but this client was built \
                 without the `compression-zstd` feature",
                s
            ))
        }
    } else {
        Err(fmt!(
            HandshakeError,
            "server selected X-QWP-Content-Encoding {:?} (unknown codec {:?})",
            s,
            name
        ))
    }
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
    // 421 carries an `X-QuestDB-Role` upgrade-reject (failover.md §5).
    // Handled out-of-line so the mapped Error can attach `UpgradeReject`.
    if let T::Http(resp) = &e
        && resp.status().as_u16() == 421
        && let Some(reject) = parse_upgrade_reject(resp.headers())
    {
        return Error::new(
            ErrorCode::RoleMismatch,
            format!(
                "server rejected WebSocket upgrade with 421 + X-QuestDB-Role={} \
                 (zone={:?}); host is in {} state",
                reject.role_name,
                reject.zone,
                if reject.is_transient() {
                    "transient (PRIMARY_CATCHUP)"
                } else {
                    "topological"
                },
            ),
        )
        .with_upgrade_reject(reject);
    }
    let code = match &e {
        T::Http(resp) => {
            let status = resp.status().as_u16();
            if status == 401 || status == 403 {
                ErrorCode::AuthError
            } else {
                // Covers 421-without-role-header, 404, 503, 426, and every
                // other 4xx/5xx that isn't 401/403. Per failover.md §6 all
                // of these are transient/per-endpoint — `HandshakeError`
                // is failover-eligible.
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
        // Tungstenite-with-rustls reports cert validation / handshake
        // failures via its `Io` variant (rustls wraps its own errors
        // in `io::Error`). Peel the IO jacket so cert problems don't
        // get misclassified as `SocketError` — failover keeps walking
        // on `SocketError`, but a TLS-class failure (untrusted cert,
        // hostname mismatch, protocol version mismatch) is a config
        // problem the user has to fix, not a transient one to retry.
        T::Io(io_err) if is_tls_io_error(io_err) => ErrorCode::TlsError,
        T::Io(_) => ErrorCode::SocketError,
        _ => ErrorCode::HandshakeError,
    };
    Error::new(code, format!("WebSocket handshake failed: {}", msg))
}

/// Extract `X-QuestDB-Role` (and the optional `X-QuestDB-Zone`) from a
/// `421` upgrade reject response. Returns `None` when the role header is
/// absent or empty after trimming — that case degrades to a generic
/// transient transport error per failover.md §5, letting the failover
/// walk continue without recording a topology classification.
///
/// Header lookup is case-insensitive (RFC 7230); whitespace around the
/// value is trimmed. The role value is uppercased to match the spec's
/// enum tokens (`PRIMARY_CATCHUP` etc.), which gives us a stable
/// `role_name` field regardless of whether the server emits mixed case.
fn parse_upgrade_reject(headers: &tungstenite::http::HeaderMap) -> Option<UpgradeReject> {
    let role_raw = lookup_header(headers, HDR_ROLE)?;
    let role_trimmed = role_raw.trim();
    if role_trimmed.is_empty() {
        return None;
    }
    let role_name = role_trimmed.to_ascii_uppercase();
    // Unrecognised token: keep the wire bytes (uppercased) so the operator
    // can see exactly what the server said; the byte falls back to
    // `roles::UNKNOWN_NAME` as a sentinel for "byte is unknown" and the
    // tracker still classifies via `is_transient()`, which inspects the
    // case-insensitive name. See failover.md §5.
    let role_byte = roles::byte_for_name(&role_name).unwrap_or(roles::UNKNOWN_NAME);
    let zone = lookup_header(headers, HDR_ZONE).and_then(|v| {
        let trimmed = v.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    Some(UpgradeReject::new(role_byte, role_name, zone))
}

/// Case-insensitive single-header lookup that decodes the value as
/// ASCII. Returns `None` on missing header or non-ASCII value (the
/// HTTP/1.1 wire form for these headers is ASCII; we don't try to
/// rescue mojibake).
fn lookup_header<'h>(headers: &'h tungstenite::http::HeaderMap, name: &str) -> Option<&'h str> {
    headers
        .iter()
        .find(|(n, _)| n.as_str().eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.to_str().ok())
}

/// Best-effort classifier: does this `io::Error` actually carry a
/// rustls TLS failure underneath? Rustls returns its errors via
/// `io::Error::other(rustls::Error)` (or wraps them in
/// `ErrorKind::InvalidData` for cert-validation failures), so
/// downcasting through `get_ref()` is the canonical way to recover
/// the TLS classification. Falls back to a substring check on the
/// rendered message for older tungstenite/rustls combinations that
/// don't preserve the source chain.
fn is_tls_io_error(e: &std::io::Error) -> bool {
    if let Some(src) = e.get_ref() {
        if src.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        // Walk the chain — some rustls errors are double-wrapped
        // (e.g. `io::Error -> io::Error -> rustls::Error`) by the
        // tungstenite TLS adapter.
        let mut cur: Option<&(dyn std::error::Error + 'static)> = src.source();
        while let Some(s) = cur {
            if s.downcast_ref::<rustls::Error>().is_some() {
                return true;
            }
            cur = s.source();
        }
    }
    let msg = e.to_string();
    msg.contains("invalid peer certificate") || msg.contains("rustls")
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

    use super::validate_content_encoding;
    use crate::egress::error::ErrorCode;
    use tungstenite::http::{HeaderMap, HeaderValue};

    fn header_map(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            "X-QWP-Content-Encoding",
            HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    #[test]
    fn module_is_compilable() {
        // Sanity check: the `cfg(feature = "sync-reader-ws")` gate is open
        // when this test runs.
    }

    #[test]
    fn content_encoding_absent_is_ok() {
        validate_content_encoding(&HeaderMap::new()).unwrap();
    }

    #[test]
    fn content_encoding_raw_is_ok() {
        validate_content_encoding(&header_map("raw")).unwrap();
        validate_content_encoding(&header_map("identity")).unwrap();
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn content_encoding_zstd_bare_is_ok() {
        validate_content_encoding(&header_map("zstd")).unwrap();
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn content_encoding_zstd_with_level_parameter_is_ok() {
        // Spec §3 example: server echoes `zstd;level=3`. The `level`
        // is server-side encoder state — the decompressor pulls
        // everything it needs from the frame header — so the client
        // must accept and ignore it.
        validate_content_encoding(&header_map("zstd;level=3")).unwrap();
        validate_content_encoding(&header_map("zstd; level=3")).unwrap();
        validate_content_encoding(&header_map("zstd;level=1")).unwrap();
        validate_content_encoding(&header_map("zstd;level=9")).unwrap();
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn content_encoding_zstd_with_unknown_parameter_is_ok() {
        // Future-compat: parameters not defined at this spec revision
        // (e.g. `dict=<id>`) MUST NOT block the handshake. Server-side
        // parameters are tolerated unconditionally on a recognised
        // codec — the decoder reads what it needs from the frame.
        validate_content_encoding(&header_map("zstd;dict=42")).unwrap();
        validate_content_encoding(&header_map("zstd;foo=bar;baz=qux")).unwrap();
        // Even an out-of-spec level value is informational and
        // tolerated — the server has already clamped on the wire side.
        validate_content_encoding(&header_map("zstd;level=99")).unwrap();
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn content_encoding_trailing_semicolon_is_ok() {
        // Empty post-`;` segments are tolerated (whitespace / accidental
        // trailing separator).
        validate_content_encoding(&header_map("zstd;")).unwrap();
        validate_content_encoding(&header_map("zstd; ; ")).unwrap();
    }

    #[test]
    fn content_encoding_unknown_codec_rejected() {
        let err = validate_content_encoding(&header_map("brotli")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::HandshakeError);
        assert!(err.msg().contains("unknown codec"), "got: {}", err.msg());
    }

    /// RFC 7231 §3.1.2.1: content codings are case-insensitive. A
    /// server (or transparent proxy that rewrites the response
    /// headers) sending mixed- or upper-case codec names must not
    /// trip the handshake — the codec choice is identical, only the
    /// spelling differs.
    #[test]
    fn content_encoding_codec_name_is_case_insensitive() {
        validate_content_encoding(&header_map("RAW")).unwrap();
        validate_content_encoding(&header_map("Raw")).unwrap();
        validate_content_encoding(&header_map("IDENTITY")).unwrap();
        validate_content_encoding(&header_map("Identity")).unwrap();
    }

    #[cfg(feature = "compression-zstd")]
    #[test]
    fn content_encoding_zstd_case_insensitive() {
        validate_content_encoding(&header_map("ZSTD")).unwrap();
        validate_content_encoding(&header_map("Zstd")).unwrap();
        validate_content_encoding(&header_map("zStd")).unwrap();
        // Mixed case on the codec name with a lowercase parameter
        // (the parameter side is server-state and isn't matched on).
        validate_content_encoding(&header_map("Zstd;level=3")).unwrap();
    }

    #[cfg(not(feature = "compression-zstd"))]
    #[test]
    fn content_encoding_zstd_case_insensitive_rejected_without_feature() {
        // A client built without `compression-zstd` must reject `Zstd`
        // / `ZSTD` the same way it rejects `zstd` — the rejection
        // logic must not silently accept the mixed-case form.
        let err = validate_content_encoding(&header_map("ZSTD")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::HandshakeError);
        let err = validate_content_encoding(&header_map("Zstd")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::HandshakeError);
    }

    #[test]
    fn content_encoding_unknown_codec_with_parameters_still_rejected() {
        // The codec name itself is unknown — the parameter tail
        // doesn't rescue it.
        let err = validate_content_encoding(&header_map("brotli;q=1.0")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::HandshakeError);
        assert!(err.msg().contains("unknown codec"), "got: {}", err.msg());
    }
}
