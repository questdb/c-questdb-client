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

//! Post-handshake WebSocket client.
//!
//! Owns the underlying byte stream (plain TCP or rustls-wrapped TCP),
//! a single growing recv buffer with no zero-fill, and a per-connection
//! [`MaskKeySource`]. Exposes `read_binary_frame` (transparently handling
//! Ping/Pong/Close) and `write_binary_frame` (mask + write in one
//! `write_all`).
//!
//! What this deliberately doesn't do:
//! - **No fragmentation handling.** QWP frames are always FIN=1; the
//!   parser rejects continuation opcodes upstream.
//! - **No Close handshake.** Per project policy we send Close best-
//!   effort, then `Shutdown::Both` the TCP socket — the server's
//!   echo (or lack thereof) doesn't change our flow.
//! - **No nonblocking / WouldBlock retry.** The underlying stream is
//!   set to blocking with explicit `set_read_timeout` / `set_write_timeout`
//!   via the transport layer; this client surfaces timeouts as
//!   `io::ErrorKind::WouldBlock` / `TimedOut` straight through.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};

use bytes::{Bytes, BytesMut};

use crate::ws::frame::{FrameError, FrameHeader, Opcode, encode_client_frame};
use crate::ws::mask::MaskKeySource;
use crate::ws::nosigpipe::NoSigpipeTcp;

/// Initial recv buffer capacity. Sized to fit a typical multi-MB QWP
/// `RESULT_BATCH` in a single `read()` syscall: the batch wire cap is
/// 64 MiB (`MAX_BATCH_WIRE_BYTES` in `transport.rs`), real-world
/// batches at the spec's default `max_batch_rows` land in the 2–4 MiB
/// range under zstd, and the steady-state Linux TCP recv socket buffer
/// is also a few MiB — so a 4 MiB user-space buffer lets the kernel
/// hand us most of a batch in one go. Smaller values force multiple
/// `read()` calls per batch (the previous default was 1 MiB, which
/// meant 4× the syscalls on a 4 MiB batch); larger values trade
/// per-connection memory (4 MiB × concurrent readers) for fewer
/// syscalls. The 4 MiB pick balances both for the single-reader /
/// few-reader case that QWP egress is built for. See PR 140 for the
/// original perf write-up.
const INITIAL_RECV_CAPACITY: usize = 4 * 1024 * 1024;

/// How many spare bytes we reserve before each `read()`. Caps the size
/// of a single read syscall: bigger values mean fewer syscalls but a
/// hostile peer that streams continuous bytes could otherwise force us
/// to keep growing. Matches [`INITIAL_RECV_CAPACITY`] so the
/// steady-state pattern is "read 4 MiB, consume some, top back up".
const READ_CHUNK: usize = 4 * 1024 * 1024;

/// Plain TCP or rustls-wrapped TCP. Replaces `tungstenite::stream::MaybeTlsStream`.
///
/// We need a Read+Write enum so the upper layers can stay generic over
/// the TLS feature, while still letting us reach the underlying
/// `TcpStream` for `set_read_timeout` / `set_write_timeout` /
/// `shutdown`. The `Tls` arm holds a `rustls::StreamOwned` that
/// internally owns the `ClientConnection` + [`NoSigpipeTcp`].
///
/// The TCP half is wrapped in [`NoSigpipeTcp`] so multi-write teardown
/// paths (e.g. `Cursor::Drop` emitting `CANCEL` then `Close`) cannot
/// kill an FFI host process with `SIGPIPE` — see `nosigpipe.rs`.
pub(crate) enum Stream {
    Plain(NoSigpipeTcp),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, NoSigpipeTcp>>),
}

impl Stream {
    /// Borrow the underlying `TcpStream`. Used for socket-level knobs
    /// (timeouts, `shutdown`) that aren't exposed on the rustls wrapper.
    pub(crate) fn tcp_mut(&mut self) -> &mut TcpStream {
        match self {
            Stream::Plain(s) => s.tcp_mut(),
            Stream::Tls(s) => s.sock.tcp_mut(),
        }
    }

    /// Best-effort TCP `Shutdown::Both` — releases the FD synchronously
    /// regardless of TLS state. Errors are swallowed: this is called
    /// from `Drop` / teardown paths where there's nowhere to report.
    pub(crate) fn shutdown(&mut self) {
        let _ = self.tcp_mut().shutdown(Shutdown::Both);
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

/// Why a `read_binary_frame` call returned without yielding a Binary
/// payload. Internal-only — the public API surfaces these as
/// crate-wide [`Error`](crate::Error) variants in the transport layer.
#[derive(Debug)]
pub(crate) enum WsReadError {
    /// Underlying stream returned an `io::Error` (read failure,
    /// timeout, EOF mid-frame).
    Io(io::Error),
    /// Wire-format violation (bad header, masked from server,
    /// oversize frame, etc.).
    Protocol(String),
    /// Server sent a Close frame. Carries the optional close code.
    /// Caller decides whether to surface as `SocketError` or treat as
    /// graceful.
    ServerClose { code: Option<u16> },
}

impl From<io::Error> for WsReadError {
    fn from(e: io::Error) -> Self {
        WsReadError::Io(e)
    }
}

/// Post-handshake WebSocket connection over `S`. The handshake itself
/// runs separately via [`super::handshake::upgrade`]; constructing a
/// `WsClient` is what happens after a successful handshake.
pub(crate) struct WsClient {
    stream: Stream,
    /// Recv buffer. Uses [`BytesMut`] so frame payloads can be served
    /// to callers as zero-copy `Bytes` slices via `split_to(...).freeze()`.
    /// We `reserve` capacity on demand and use `spare_capacity_mut` +
    /// `advance_mut` to avoid the `BytesMut::resize` zero-fill pattern
    /// that bit us in the tungstenite default config — see PR 140.
    recv: BytesMut,
    mask_keys: MaskKeySource,
    /// Hard ceiling on a single frame's payload length. Inherited
    /// from the transport-level `MAX_BATCH_WIRE_BYTES` cap; surfaces
    /// as a `Protocol` error rather than letting the buffer grow
    /// unboundedly under a corrupted-frame scenario.
    max_payload: usize,
}

impl WsClient {
    /// Build a fresh client over `stream`. `leftover` is any pre-fetched
    /// bytes returned by the handshake parser (typically empty) — they
    /// get prepended to the recv buffer so the first frame read sees
    /// them.
    pub(crate) fn new(
        stream: Stream,
        leftover: Vec<u8>,
        mask_keys: MaskKeySource,
        max_payload: usize,
    ) -> Self {
        let mut recv = BytesMut::with_capacity(INITIAL_RECV_CAPACITY.max(leftover.len()));
        recv.extend_from_slice(&leftover);
        Self {
            stream,
            recv,
            mask_keys,
            max_payload,
        }
    }

    pub(crate) fn stream_mut(&mut self) -> &mut Stream {
        &mut self.stream
    }

    /// Read the next Binary frame from the peer, returning its payload
    /// as a zero-copy `Bytes`. Ping frames are echoed as Pong on the
    /// fly and the read loop continues. Pong frames (unsolicited) are
    /// dropped. Close frames surface as `WsReadError::ServerClose`.
    pub(crate) fn read_binary_frame(&mut self) -> Result<Bytes, WsReadError> {
        loop {
            // Try to parse a header from whatever we have. If
            // incomplete, fill more. If protocol-level bad, bail.
            let header = match FrameHeader::parse(&self.recv) {
                Ok(h) => h,
                Err(FrameError::Incomplete) => {
                    self.fill_more()?;
                    continue;
                }
                Err(FrameError::Protocol(msg)) => {
                    return Err(WsReadError::Protocol(msg.to_string()));
                }
            };

            let payload_len = header.payload_len as usize;
            if payload_len > self.max_payload {
                return Err(WsReadError::Protocol(format!(
                    "WS payload {} bytes exceeds cap {}",
                    payload_len, self.max_payload
                )));
            }
            let total = header.header_len + payload_len;
            if self.recv.len() < total {
                self.fill_more()?;
                continue;
            }

            // Consume the header bytes from the buffer; the next
            // `payload_len` bytes are the payload.
            self.recv.advance_to(header.header_len);
            let payload = self.recv.split_to(payload_len).freeze();

            match header.opcode {
                Opcode::Binary => {
                    if !header.fin {
                        return Err(WsReadError::Protocol(
                            "fragmented binary frame; QWP frames are never fragmented".to_string(),
                        ));
                    }
                    return Ok(payload);
                }
                Opcode::Ping => {
                    // RFC 6455 §5.5.2: A Pong frame sent in response to a
                    // Ping frame must have identical "Application data".
                    // We echo synchronously — for QWP the Ping path is
                    // rare and the payload is ≤ 125 bytes, so the
                    // amortised cost is negligible.
                    self.send_frame(Opcode::Pong, &payload)?;
                    continue;
                }
                Opcode::Pong => {
                    // Unsolicited pong (or response to a Ping we sent —
                    // we currently don't initiate keepalive pings, but
                    // the server may). Drop it.
                    continue;
                }
                Opcode::Close => {
                    // RFC §5.5.1: Close payload may be empty, or
                    // start with a 2-byte big-endian status code. We
                    // surface the code; reason text is not used by
                    // the transport layer.
                    let code = if payload.len() >= 2 {
                        Some(u16::from_be_bytes([payload[0], payload[1]]))
                    } else {
                        None
                    };
                    return Err(WsReadError::ServerClose { code });
                }
            }
        }
    }

    /// Send one Binary frame. Allocates a single Vec for the wire bytes
    /// (header + masked payload) and writes in one `write_all`. For the
    /// multi-MB QUERY_REQUEST replay path the extra alloc is amortised
    /// across the rest of the failover (reconnect, dial, TLS handshake);
    /// for CREDIT / CANCEL the payload is 9 bytes and the alloc fits
    /// in a single small-bin allocator slot.
    pub(crate) fn write_binary_frame(&mut self, payload: &[u8]) -> io::Result<()> {
        self.send_frame(Opcode::Binary, payload)
    }

    /// Send a Close frame with `code` and empty reason, best-effort.
    /// The follow-up TCP shutdown is the caller's responsibility (we
    /// don't wait for the server's echo per project policy — bounded
    /// teardown lives in `transport.rs`).
    pub(crate) fn send_close(&mut self, code: u16) -> io::Result<()> {
        let bytes = code.to_be_bytes();
        self.send_frame(Opcode::Close, &bytes)
    }

    fn send_frame(&mut self, opcode: Opcode, payload: &[u8]) -> io::Result<()> {
        let mut out = Vec::with_capacity(payload.len() + 14);
        let mask_key = self
            .mask_keys
            .next_key()
            .map_err(|e| io::Error::other(e.0))?;
        encode_client_frame(&mut out, opcode, mask_key, payload);
        self.stream.write_all(&out)?;
        Ok(())
    }

    /// Read more bytes from the stream into the recv buffer. Returns
    /// `Err(Io(UnexpectedEof))` if the stream returns 0 bytes
    /// (peer closed mid-frame).
    fn fill_more(&mut self) -> Result<(), WsReadError> {
        // Defence-in-depth bound on cumulative recv-buffer growth.
        // The upstream `payload_len > max_payload` check in
        // `read_binary_frame` already rejects single oversized frames,
        // so the steady-state buffer should never exceed roughly one
        // frame-in-flight plus one read chunk. Cap at `2 * max_payload`
        // to bound any future parser bug that lets state accumulate
        // (e.g. a regression that fails to consume a frame after
        // splitting its payload). `BytesMut::reserve` aborts on
        // allocator OOM and `bytes` doesn't expose `try_reserve`, so
        // this is the only place we can intercept runaway growth.
        let target = self.recv.len().saturating_add(READ_CHUNK);
        if target > self.max_payload.saturating_mul(2) {
            return Err(WsReadError::Protocol(format!(
                "WS recv buffer would grow to {target} bytes, exceeds {} (2 * max_payload)",
                self.max_payload * 2
            )));
        }
        self.recv.reserve(READ_CHUNK);
        let spare = self.recv.spare_capacity_mut();
        // SAFETY: `reserve(READ_CHUNK)` above ensures `spare_capacity_mut`
        // returns at least `READ_CHUNK` bytes of owned, allocated (but
        // uninitialised) memory backing `self.recv`. Reconstituting it
        // as `&mut [u8]` is the contested pre-`read_buf` pattern: the
        // construction itself is undecided in Rust's abstract machine
        // (UCG hasn't ruled on `&mut u8` over uninit), and the cast is
        // not target-specific. We accept it because (a) we never read
        // from `slice` before `stream.read` writes into it, and (b) the
        // only `Read` impls reachable through `self.stream` are
        // `TcpStream::read` (→ `recv(2)` / `WSARecv`) and
        // `rustls::StreamOwned::read` (→ AEAD decrypt into destination),
        // both of which write the buffer without reading it. The
        // `set_len` below commits exactly the prefix that `read`
        // reported as filled. TODO: switch to `Read::read_buf` once it
        // stabilises (rust-lang/rust#78485, #117693).
        let slice =
            unsafe { std::slice::from_raw_parts_mut(spare.as_mut_ptr() as *mut u8, spare.len()) };
        let n = self.stream.read(slice)?;
        if n == 0 {
            return Err(WsReadError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "WS peer closed connection mid-frame",
            )));
        }
        // SAFETY: `stream.read` returned `n` valid bytes via the
        // mutable spare-capacity slice. Marking them as initialised
        // is what `advance_mut` does.
        unsafe { self.recv.set_len(self.recv.len() + n) };
        Ok(())
    }
}

/// `BytesMut::advance(usize)` requires `Buf` to be in scope.
/// Helper trait to keep the import surface tiny in callers.
trait AdvanceTo {
    fn advance_to(&mut self, n: usize);
}

impl AdvanceTo for BytesMut {
    fn advance_to(&mut self, n: usize) {
        use bytes::Buf;
        Buf::advance(self, n);
    }
}

#[cfg(test)]
mod tests {
    use crate::ws::frame::Opcode;

    // Exercising the frame-read state machine end-to-end requires
    // either a generic Stream type parameter (and we don't want to
    // leak that through `Reader`'s public API) or a real TcpStream
    // pair. The transport layer's integration tests
    // (egress_failover.rs, egress_tls.rs) exercise this code path
    // against an in-process WS server, which is the right place to
    // assert behaviour. The module-level tests below cover the pieces
    // that DON'T need a live stream: framing, masking, handshake.
    // Keeping it that way avoids smuggling generics into the public
    // API just for tests.

    /// Build the bytes a *server* would send for a frame with the
    /// given opcode and payload. No mask bit (server→client frames
    /// are unmasked per RFC §5.1).
    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len() + 10);
        // FIN=1, opcode.
        out.push(0x80 | opcode);
        let len = payload.len();
        if len <= 125 {
            out.push(len as u8);
        } else if len <= 0xFFFF {
            out.push(126);
            out.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            out.push(127);
            out.extend_from_slice(&(len as u64).to_be_bytes());
        }
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn server_frame_helper_round_trips() {
        // Sanity check: the helper produces parser-acceptable bytes.
        let bytes = server_frame(0x02, b"hello");
        let header = crate::ws::frame::FrameHeader::parse(&bytes).unwrap();
        assert_eq!(header.opcode, Opcode::Binary);
        assert_eq!(header.payload_len, 5);
    }
}
