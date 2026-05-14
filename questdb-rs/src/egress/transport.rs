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
//! Supports both `ws://` and `wss://` via a small custom `Stream` enum
//! (plain TCP / rustls-wrapped TCP). The transport handles the HTTP
//! upgrade (with negotiation headers and any Authorization), then
//! exposes frame-level read/write that maps each QWP frame to one
//! WebSocket binary message.
//!
//! TLS is wired through `rustls::StreamOwned` directly with a
//! `rustls::ClientConfig` built from the egress connect-string knobs
//! (`tls_ca`, `tls_roots`, `tls_verify`) — see `egress/tls.rs`.
//!
//! The previous tungstenite-based implementation has been removed in
//! favour of a purpose-built RFC 6455 client in [`crate::egress::ws`].
//! Motivation: tungstenite's general-purpose defaults (128 KiB recv
//! buffer with eager `BytesMut::resize` zero-fill before every syscall,
//! full opcode-dispatch state machine, control-frame handling on every
//! read) were measurably costly on the streaming hot path — see the PR
//! 140 perf write-up.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use crate::egress::config::ReaderConfig;
use crate::egress::error::{Error, ErrorCode, Result, UpgradeReject, fmt};
use crate::egress::tls::build_client_config;
use crate::egress::wire::MsgKind;
use crate::egress::wire::header::{FrameHeader, HEADER_LEN};
use crate::egress::wire::roles;
use crate::egress::ws::client::{Stream, WsClient, WsReadError};
use crate::egress::ws::handshake::{
    self, HandshakeError as WsHandshakeError, Headers, HttpReject,
};
use crate::egress::ws::mask::build_from_system_random;

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
/// - [`WsClient`]'s frame-length guard, so the parser refuses to keep
///   reading into the buffer past the cap before any QWP parsing runs.
/// - An explicit `header.payload_length` check in [`WsTransport::read_frame`],
///   pinning the cap independently of the framing layer so a future
///   `WsClient` default change can't silently raise our ceiling.
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
    socket: WsClient,
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

        // Resolve & TCP-connect ourselves so a name-resolution failure
        // surfaces as `CouldNotResolveAddr` (distinct from a connect-time
        // `SocketError`). `TcpStream::connect((host, port))` collapses
        // both into a single `io::Error` whose `kind()` is `Other` —
        // losing the user-actionable distinction.
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

        // Bound the upgrade-response read with `auth_timeout_ms` per
        // failover.md §1.1. Catches the "TCP accepts but server never
        // replies" blackhole that the OS connect timeout misses — a
        // stuck peer would otherwise hang the calling thread for the
        // process default (often minutes). The timeout applies to the
        // handshake read; it is cleared post-upgrade so subsequent
        // batch reads run without artificial deadlines.
        //
        // Failures here are swallowed (best-effort): if the platform's
        // socket layer rejects the timeout (vanishingly rare on the
        // supported targets), the upgrade still proceeds with the OS
        // default. Surfacing the SetTimeout error as a connect failure
        // would be more obstructive than helpful.
        let _ = tcp.set_read_timeout(Some(Duration::from_millis(config.auth_timeout_ms)));

        // Build the framed stream: plain TCP or rustls-over-TCP. The
        // rustls handshake runs lazily on the first read/write — i.e.
        // it happens transparently during the WS upgrade write below.
        let mut stream = build_stream(&tcp, endpoint.host.as_str(), config)?;

        // Run the WebSocket upgrade. The handshake module owns request
        // construction, response parsing, and Sec-WebSocket-Accept
        // validation.
        let host_header = endpoint.to_string();
        let path = config.path.clone();
        let extra_headers = config.upgrade_headers();
        let handshake_result =
            handshake::upgrade(&mut stream, &host_header, &path, &extra_headers);

        let handshake = match handshake_result {
            Ok(h) => h,
            Err(e) => return Err(map_handshake_error(e)),
        };

        // Validate negotiated headers BEFORE we hand the stream over to
        // WsClient — if either check fails we want to tear down here
        // and surface the diagnostic, not stash the new state.
        let server_version = match read_version_header(&handshake.headers)
            .and_then(|v| validate_content_encoding(&handshake.headers).map(|_| v))
        {
            Ok(v) => v,
            Err(e) => {
                set_tcp_write_timeout(stream.tcp_mut(), Some(CLOSE_TIMEOUT));
                stream.shutdown();
                return Err(e);
            }
        };

        if server_version > config.max_version {
            set_tcp_write_timeout(stream.tcp_mut(), Some(CLOSE_TIMEOUT));
            stream.shutdown();
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

        // Bound every subsequent write to the peer. Without this, a
        // stuck/blackholed peer can hang the WS Close in `Drop` /
        // `close_in_place` indefinitely — defeating the failover
        // backoff schedule, and making `Cursor::cancel()` look like
        // it's hung on a network blip.
        set_tcp_write_timeout(stream.tcp_mut(), Some(WRITE_TIMEOUT));
        // Clear the per-upgrade read deadline now that the handshake
        // is done. The post-upgrade read path is driven by `Cursor`
        // and `Cursor::cancel()` toggles its own timeout via
        // `set_read_timeout`; leaving the `auth_timeout_ms` value in
        // place would mean every batch-read would silently fault after
        // that interval of server silence (legitimate on slow queries).
        set_tcp_read_timeout(stream.tcp_mut(), None);

        let mask_rng = build_from_system_random()?;
        let socket = WsClient::new(stream, handshake.leftover, mask_rng, MAX_BATCH_WIRE_BYTES);

        Ok(WsTransport {
            socket,
            server_version,
        })
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
    /// buffer with no internal copy. The current `WsClient::write_binary_frame`
    /// takes `&[u8]` so we deref the `Bytes` (zero-copy reference into the
    /// underlying buffer).
    pub fn write_message(&mut self, payload: Bytes) -> Result<()> {
        self.socket
            .write_binary_frame(&payload)
            .map_err(|e| map_io_error(e, ErrorCode::SocketError))
    }

    /// Read the next QWP frame (header + payload). Pings/pongs are
    /// handled transparently; a `Close` from the server surfaces as a
    /// `SocketError`.
    pub fn read_frame(&mut self) -> Result<(FrameHeader, Bytes)> {
        let bytes = match self.socket.read_binary_frame() {
            Ok(b) => b,
            Err(e) => return Err(map_ws_read_error(e)),
        };

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
        // Belt-and-suspenders check: `WsClient` already guards
        // `max_payload`, but anchoring the protocol-level cap at the
        // parser too makes the ceiling testable without standing up a
        // socket. Spec §16 caps RESULT_BATCH at 16 MiB; our 4x-margin
        // cap surfaces server bugs / wire corruption as a clean
        // ProtocolError instead of either a silent multi-GiB
        // allocation or a transport-layer error that's harder to map
        // to "frame too large".
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
        Ok((header, payload))
    }

    /// Apply (or clear) a TCP read timeout on the underlying stream.
    ///
    /// `Some(t)` causes the next blocking read that goes longer than `t`
    /// to surface as an `Io` error (`SocketError`); `None` reverts to
    /// the default (no timeout). Used by `Cursor::cancel()` to bound
    /// the post-CANCEL drain so a stuck-but-not-RST'd peer cannot hang
    /// the cancel forever.
    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        set_tcp_read_timeout(self.socket.stream_mut().tcp_mut(), timeout);
    }

    /// Apply (or clear) a TCP write timeout on the underlying stream.
    ///
    /// `Some(t)` caps any subsequent blocking `write()` syscall at `t`,
    /// surfacing as a transport error if exceeded; `None` reverts to no
    /// timeout. Used by `Cursor::cancel()` to tighten the post-CANCEL
    /// credit-nudge write so a stuck peer cannot inflate the worst-case
    /// cancel latency by an extra `WRITE_TIMEOUT`.
    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) {
        set_tcp_write_timeout(self.socket.stream_mut().tcp_mut(), timeout);
    }

    /// Best-effort in-place close. Initiates the WS closing handshake
    /// without consuming `self` so callers borrowing `&mut WsTransport`
    /// (e.g. `Cursor::Drop`) can release the connection.
    ///
    /// Tightens the write timeout to `CLOSE_TIMEOUT` for the WS Close
    /// write, then issues a TCP `Shutdown::Both` so the FD is released
    /// regardless of peer state. Subsequent reads/writes on this
    /// transport will fail at the WS layer. Bounded teardown: critical
    /// on the failover path, where a stuck peer would otherwise stall
    /// the calling thread before the backoff sleep had a chance to
    /// start.
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
        set_tcp_write_timeout(self.socket.stream_mut().tcp_mut(), Some(CLOSE_TIMEOUT));
        let mut payload = Vec::with_capacity(9);
        payload.push(MsgKind::Cancel.as_u8());
        payload.extend_from_slice(&request_id.to_le_bytes());
        let _ = self.socket.write_binary_frame(&payload);
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

fn build_stream(tcp: &TcpStream, host: &str, config: &ReaderConfig) -> Result<Stream> {
    // Clone the TCP socket so the stream owns its own handle for the
    // rustls wrapper without losing the original; both halves point at
    // the same FD, so timeouts set on one apply to the other.
    let owned = tcp
        .try_clone()
        .map_err(|e| fmt!(SocketError, "could not clone TCP socket: {}", e))?;

    if let Some(client_config) = build_client_config(config)? {
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|e| {
                fmt!(
                    ConfigError,
                    "invalid TLS server name {:?}: {}",
                    host,
                    e
                )
            })?;
        let conn = rustls::ClientConnection::new(Arc::clone(&client_config), server_name)
            .map_err(|e| fmt!(TlsError, "rustls handshake setup failed: {}", e))?;
        let stream_owned = rustls::StreamOwned::new(conn, owned);
        Ok(Stream::Tls(Box::new(stream_owned)))
    } else {
        Ok(Stream::Plain(owned))
    }
}

/// Set `set_write_timeout` on the `TcpStream`. Swallows errors per
/// the same best-effort policy as the connect-time timeout: if the
/// platform's socket layer rejects the call the OS default applies
/// and subsequent writes will eventually error on their own.
fn set_tcp_write_timeout(stream: &mut TcpStream, timeout: Option<Duration>) {
    let _ = stream.set_write_timeout(timeout);
}

fn set_tcp_read_timeout(stream: &mut TcpStream, timeout: Option<Duration>) {
    let _ = stream.set_read_timeout(timeout);
}

/// Bounded teardown sequence: tighten the write timeout, attempt the
/// WS Close (best-effort), then TCP-shutdown to force FD release. Used
/// by `Drop`, `close_in_place`, and the `close` consuming variant so
/// they share identical semantics.
fn teardown_inplace(socket: &mut WsClient) {
    set_tcp_write_timeout(socket.stream_mut().tcp_mut(), Some(CLOSE_TIMEOUT));
    // 1000 = "Normal Closure" per RFC 6455 §7.4.1. We don't attach a
    // reason — the body of close frames is ignored by every QWP
    // server we've tested.
    let _ = socket.send_close(1000);
    socket.stream_mut().shutdown();
}

// ---------------------------------------------------------------------------
// Helpers — operate on our `Headers` type from `ws::handshake`.
// ---------------------------------------------------------------------------

fn read_version_header(headers: &Headers) -> Result<u8> {
    let raw = headers
        .find_ci(HDR_VERSION)
        .ok_or_else(|| fmt!(HandshakeError, "server response missing X-QWP-Version header"))?;
    raw.parse::<u8>()
        .map_err(|_| fmt!(HandshakeError, "X-QWP-Version {:?} is not a u8", raw))
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
fn validate_content_encoding(headers: &Headers) -> Result<()> {
    let raw = match headers.find_ci(HDR_CONTENT_ENCODING) {
        Some(v) => v,
        // Header absent => spec §3 default = `raw`. No constraint.
        None => return Ok(()),
    };
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
    let mut parts = raw.split(';');
    let name = parts.next().unwrap_or("").trim();
    // RFC 7231 §3.1.2.1: "All content-codings are case-insensitive."
    // A standards-compliant server or any transparent proxy along
    // the path may rewrite the casing (`Zstd`, `ZSTD`, `Identity`).
    // Compare ignoring ASCII case so the handshake doesn't fail on
    // capitalisation alone.
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
                raw
            ))
        }
    } else {
        Err(fmt!(
            HandshakeError,
            "server selected X-QWP-Content-Encoding {:?} (unknown codec {:?})",
            raw,
            name
        ))
    }
}

/// Map a stream-level IO error to the public egress `Error`. The
/// `default_code` is used as the fallback when we can't infer something
/// more specific from the io::Error's kind.
fn map_io_error(e: std::io::Error, default_code: ErrorCode) -> Error {
    let msg = e.to_string();
    Error::new(default_code, msg)
}

fn map_ws_read_error(e: WsReadError) -> Error {
    match e {
        WsReadError::Io(io_err) => Error::new(ErrorCode::SocketError, io_err.to_string()),
        WsReadError::Protocol(msg) => Error::new(ErrorCode::ProtocolError, msg),
        WsReadError::ServerClose { code } => Error::new(
            ErrorCode::SocketError,
            match code {
                Some(c) => format!("server closed WebSocket (code={})", c),
                None => "server closed WebSocket".to_string(),
            },
        ),
    }
}

/// Convert a [`WsHandshakeError`] into the public egress `Error`,
/// preserving the existing classification rules (401/403 → AuthError,
/// 421 + X-QuestDB-Role → RoleMismatch with structured body, other
/// 4xx/5xx → HandshakeError, TLS / connect failures keep their codes).
fn map_handshake_error(e: WsHandshakeError) -> Error {
    match e {
        WsHandshakeError::Io(io_err) => {
            // rustls reports cert validation / handshake failures via
            // `io::Error::other(rustls::Error)` (or wraps them in
            // `ErrorKind::InvalidData` for cert-validation failures).
            // Peel the IO jacket so cert problems don't get
            // misclassified as `SocketError` — failover keeps walking
            // on `SocketError`, but a TLS-class failure (untrusted
            // cert, hostname mismatch, protocol version mismatch) is a
            // config problem the user has to fix, not a transient one
            // to retry.
            let code = if is_tls_io_error(&io_err) {
                ErrorCode::TlsError
            } else {
                ErrorCode::SocketError
            };
            Error::new(
                code,
                format!("WebSocket handshake IO error: {}", io_err),
            )
        }
        WsHandshakeError::Protocol(msg) => Error::new(
            ErrorCode::HandshakeError,
            format!("WebSocket handshake protocol error: {}", msg),
        ),
        WsHandshakeError::BadAccept => fmt!(
            HandshakeError,
            "WebSocket handshake response had invalid Sec-WebSocket-Accept (server not speaking WS \
             RFC 6455 or signing with the wrong key)"
        ),
        WsHandshakeError::HttpStatus(reject) => map_http_reject(reject),
    }
}

fn map_http_reject(reject: HttpReject) -> Error {
    let HttpReject { status, headers, body: _ } = reject;
    // 421 carries an `X-QuestDB-Role` upgrade-reject (failover.md §5).
    // Handled out-of-line so the mapped Error can attach `UpgradeReject`.
    if status == 421
        && let Some(upgrade_reject) = parse_upgrade_reject(&headers)
    {
        return Error::new(
            ErrorCode::RoleMismatch,
            format!(
                "server rejected WebSocket upgrade with 421 + X-QuestDB-Role={} \
                 (zone={:?}); host is in {} state",
                upgrade_reject.role_name,
                upgrade_reject.zone,
                if upgrade_reject.is_transient() {
                    "transient (PRIMARY_CATCHUP)"
                } else {
                    "topological"
                },
            ),
        )
        .with_upgrade_reject(upgrade_reject);
    }
    let code = if status == 401 || status == 403 {
        ErrorCode::AuthError
    } else {
        // Covers 421-without-role-header, 404, 503, 426, and every
        // other 4xx/5xx that isn't 401/403. Per failover.md §6 all
        // of these are transient/per-endpoint — `HandshakeError`
        // is failover-eligible.
        ErrorCode::HandshakeError
    };
    Error::new(
        code,
        format!("WebSocket handshake failed with HTTP {}", status),
    )
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
fn parse_upgrade_reject(headers: &Headers) -> Option<UpgradeReject> {
    let role_raw = headers.find_ci(HDR_ROLE)?;
    if role_raw.is_empty() {
        return None;
    }
    let role_name = role_raw.to_ascii_uppercase();
    // Unrecognised token: keep the wire bytes (uppercased) so the operator
    // can see exactly what the server said; the byte falls back to
    // `roles::UNKNOWN_NAME` as a sentinel for "byte is unknown" and the
    // tracker still classifies via `is_transient()`, which inspects the
    // case-insensitive name. See failover.md §5.
    let role_byte = roles::byte_for_name(&role_name).unwrap_or(roles::UNKNOWN_NAME);
    let zone = headers.find_ci(HDR_ZONE).and_then(|v| {
        if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        }
    });
    Some(UpgradeReject::new(role_byte, role_name, zone))
}

/// Best-effort classifier: does this `io::Error` actually carry a
/// rustls TLS failure underneath? Rustls returns its errors via
/// `io::Error::other(rustls::Error)` (or wraps them in
/// `ErrorKind::InvalidData` for cert-validation failures), so
/// downcasting through `get_ref()` is the canonical way to recover
/// the TLS classification. Falls back to a substring check on the
/// rendered message for older rustls combinations that don't preserve
/// the source chain.
fn is_tls_io_error(e: &std::io::Error) -> bool {
    if let Some(src) = e.get_ref() {
        if src.downcast_ref::<rustls::Error>().is_some() {
            return true;
        }
        // Walk the chain — some rustls errors are double-wrapped
        // (e.g. `io::Error -> io::Error -> rustls::Error`) when they
        // bubble through stream adapters.
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    // Real handshake/round-trip tests live in
    // questdb-rs/tests/egress_failover.rs and egress_tls.rs so they
    // can spin up an in-process tungstenite server. Tungstenite stays
    // available as a dev-dependency for those tests.

    use super::*;

    fn header_map(value: &str) -> Headers {
        Headers::from_pairs([("X-QWP-Content-Encoding", value)])
    }

    #[test]
    fn module_is_compilable() {
        // Sanity check: the `cfg(feature = "sync-reader-ws")` gate is open
        // when this test runs.
    }

    #[test]
    fn content_encoding_absent_is_ok() {
        validate_content_encoding(&Headers::default()).unwrap();
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
    }
}
