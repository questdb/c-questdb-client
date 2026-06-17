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

//! Dedicated pipelined QWP/WebSocket connection for the column-major
//! sender.
//!
//! `ColumnConn` owns its socket end-to-end. Each `publish_qwp` writes a
//! single QWP frame into the connection's reusable write buffer, masks it
//! per RFC 6455, and `write_all`s to the socket — then returns immediately
//! without waiting for the server's ack. Between publishes, ready acks
//! are drained non-blocking via `try_drain_acks`. When the in-flight
//! count hits the protocol cap (128), the next non-deferred publish
//! blocks until one ack frees a slot. Deferred publishes reserve one
//! in-flight slot for the later commit-triggering frame. An explicit
//! `sync_all_acks` blocks until every in-flight frame is acknowledged.
//!
//! No replay queue, no background thread — single-thread, single-socket,
//! pipelined.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::time::Duration;

use crate::ingress::SenderBuilder;
use crate::ingress::sender::qwp_ws::WsStream;
use crate::ws::frame::{self, FrameError, FrameHeader, Opcode, encode_client_frame};
use crate::ws::mask::{MaskKeySource, apply_mask};
use crate::{Result, error};

use super::sender::AckLevel;

/// Bytes the encoder leaves untouched at the start of `write_buf` so the
/// WS header can be prepended in place without a copy. RFC 6455 §5.2: the
/// client-to-server header is at most 14 bytes (1 flag + 1 len + 8 ext len
/// + 4 mask key).
pub(crate) const WS_HEADER_RESERVE: usize = 14;

// Status bytes from the QWP/WS response opcode table. Duplicated here per
// the "no row-API code reuse" stance — the column sender never reaches
// into `crate::ingress::sender::qwp_ws_codec`.
const QWP_STATUS_OK: u8 = 0x00;
const QWP_STATUS_DURABLE_ACK: u8 = 0x02;
const QWP_STATUS_SCHEMA_MISMATCH: u8 = 0x03;
const QWP_STATUS_PARSE_ERROR: u8 = 0x05;
const QWP_STATUS_INTERNAL_ERROR: u8 = 0x06;
const QWP_STATUS_SECURITY_ERROR: u8 = 0x08;
const QWP_STATUS_WRITE_ERROR: u8 = 0x09;

/// Cap on a single inbound WS frame. Well above QWP's 16 MiB batch limit
/// but small enough to refuse obviously bogus declared lengths early.
const MAX_INBOUND_FRAME_BYTES: u64 = 256 * 1024 * 1024;

/// QWP spec §Protocol limits: max in-flight batches per connection.
const MAX_IN_FLIGHT: u32 = 128;

/// Best-effort write budget for the Close frame on Drop. Short enough
/// that a wedged peer cannot block deallocation of the connection.
const CLOSE_TIMEOUT: Duration = Duration::from_millis(200);

/// RFC 6455 §7.4.1 normal closure status, big-endian.
const WS_CLOSE_STATUS_NORMAL: [u8; 2] = 1000u16.to_be_bytes();

/// Metadata for one published-but-unacked frame. Pushed on publish,
/// popped (front) when the matching OK arrives.
struct PendingAck {
    fsn: u64,
}

/// One pipelined QWP/WebSocket connection owned by the column-major
/// sender. See module docs.
pub(crate) struct ColumnConn {
    stream: WsStream,
    /// Bytes the WS handshake read past the upgrade response, plus any
    /// bytes from inbound WS frames already consumed past their header.
    /// Drained before reading more from the socket.
    leftover: Vec<u8>,
    /// Reusable outbound buffer. Bytes 0..WS_HEADER_RESERVE are reserved
    /// for the WS header; the encoder writes the QWP frame body from
    /// offset WS_HEADER_RESERVE onwards.
    write_buf: Vec<u8>,
    /// Reusable inbound scratch (one ack frame's worth).
    read_buf: Vec<u8>,
    mask_keys: MaskKeySource,
    /// Sequence assigned to the next published frame. QWP server numbers
    /// client frames starting at 0; first publish gets fsn 0.
    next_fsn: u64,
    /// Published-but-unacked frames, ordered by fsn. Pushed on publish,
    /// popped (front) when the matching OK arrives.
    pending_acks: VecDeque<PendingAck>,
    /// Number of published-but-unacked frames. Redundant with
    /// `pending_acks.len()` but avoids a cast for the 128 cap check.
    in_flight: u32,
    /// For ack_level=Durable: per-table seq_txn watermark the server has
    /// reported reaching durable storage.
    durable_watermarks: HashMap<String, i64>,
    /// Per-table seq_txn high-water mark observed in OK acks but not yet
    /// confirmed durable. Populated by every Ok ack regardless of the
    /// caller's `ack_level`, so a later `sync(Durable)` can still wait
    /// for earlier frames that were drained by `sync(Ok)` or
    /// `try_drain_acks`. Satisfied entries are removed once
    /// `durable_watermarks` reaches them.
    pending_durable_targets: HashMap<String, i64>,
    /// Sticky: once `true`, the connection cannot be used for further
    /// publishes; the pool drops the slot on return.
    must_close: bool,
    max_buf_size: usize,
    request_timeout: Duration,
    durable_ack_opt_in: bool,
}

impl ColumnConn {
    /// Open a fresh column-sender connection. The pool layer
    /// ([`super::QuestDb::connect`]) has already extracted pool-specific
    /// knobs and refused `sf_*` keys; this function only reaches the
    /// remaining QWP/WS settings via [`SenderBuilder::from_conf`].
    pub(crate) fn connect(conf: &str) -> Result<Self> {
        let builder = SenderBuilder::from_conf(conf)?;
        let raw = builder.build_qwp_ws_raw_stream()?;
        let mask_keys = MaskKeySource::new()
            .map_err(|e| error::fmt!(SocketError, "MaskKeySource init failed: {}", e.0))?;
        Ok(Self {
            stream: raw.stream,
            leftover: raw.leftover,
            write_buf: Vec::with_capacity(64 * 1024),
            read_buf: Vec::with_capacity(4 * 1024),
            mask_keys,
            next_fsn: 0,
            pending_acks: VecDeque::new(),
            in_flight: 0,
            durable_watermarks: HashMap::new(),
            pending_durable_targets: HashMap::new(),
            must_close: false,
            max_buf_size: raw.max_buf_size,
            request_timeout: raw.request_timeout,
            durable_ack_opt_in: raw.durable_ack_opt_in,
        })
    }

    /// Build a connection around an already-open `stream` without the
    /// handshake. The socket is never touched by the ack-bookkeeping
    /// logic, so tests can drive `process_response` / `push_pending`
    /// against a dummy connected pair.
    #[cfg(test)]
    pub(crate) fn for_test(stream: WsStream, durable_ack_opt_in: bool) -> Self {
        Self {
            stream,
            leftover: Vec::new(),
            write_buf: Vec::new(),
            read_buf: Vec::new(),
            mask_keys: MaskKeySource::new().expect("test mask key source"),
            next_fsn: 0,
            pending_acks: VecDeque::new(),
            in_flight: 0,
            durable_watermarks: HashMap::new(),
            pending_durable_targets: HashMap::new(),
            must_close: false,
            max_buf_size: 1 << 20,
            request_timeout: Duration::from_secs(30),
            durable_ack_opt_in,
        }
    }

    #[cfg(test)]
    pub(crate) fn pending_durable_target_count(&self) -> usize {
        self.pending_durable_targets.len()
    }

    pub(crate) fn must_close(&self) -> bool {
        self.must_close
    }

    /// Force the connection into the terminal `must_close` state so
    /// the pool drops it on return instead of recycling it. Used by
    /// the higher-level error-recovery path when a mid-call failure
    /// leaves the conn with in-flight uncommitted data that the next
    /// borrower would otherwise commit alongside their own.
    pub(crate) fn mark_must_close(&mut self) {
        self.must_close = true;
    }

    /// Hand `encode` a `&mut Vec<u8>` with `WS_HEADER_RESERVE` bytes
    /// pre-reserved at the front; `encode` appends the QWP frame body to
    /// it. Frame the result as a WS binary frame (mask in place), write
    /// the bytes to the socket, return the assigned FSN.
    ///
    /// On any socket or protocol failure the connection is latched as
    /// `must_close` and the original error is returned.
    pub(crate) fn publish_qwp<F>(&mut self, encode: F) -> Result<PublishedFrame>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<()>,
    {
        if self.must_close {
            return Err(error::fmt!(
                SocketError,
                "QWP/WebSocket connection latched as terminal; \
                 return the sender to the pool and acquire a fresh one."
            ));
        }

        // Set up the buffer: 14 zero bytes that the WS header will
        // overwrite once we know the actual payload length.
        self.write_buf.clear();
        self.write_buf.resize(WS_HEADER_RESERVE, 0);

        // Caller writes the QWP frame body.
        encode(&mut self.write_buf).inspect_err(|_| {
            // Encode failure leaves the connection usable — the bytes
            // never hit the wire — but the buffer state needs resetting
            // so the next publish starts clean.
            self.write_buf.clear();
        })?;

        let payload_len = self.write_buf.len() - WS_HEADER_RESERVE;
        if payload_len > self.max_buf_size {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP frame ({} bytes) exceeds max_buf_size ({} bytes)",
                payload_len,
                self.max_buf_size
            ));
        }

        let mask_key = self.mask_keys.next_key().map_err(|e| {
            self.latch(error::fmt!(SocketError, "mask key entropy failed: {}", e.0))
        })?;

        // Apply the mask to the QWP frame body in place.
        apply_mask(&mut self.write_buf[WS_HEADER_RESERVE..], mask_key, 0);

        // Compute the WS header byte count for this payload length.
        let ws_header_len = ws_header_len_for(payload_len);
        let header_offset = WS_HEADER_RESERVE - ws_header_len;
        write_ws_header(
            &mut self.write_buf[header_offset..WS_HEADER_RESERVE],
            payload_len,
            mask_key,
        );

        self.set_timeouts(Some(self.request_timeout), Some(self.request_timeout))?;
        self.stream
            .write_all(&self.write_buf[header_offset..])
            .map_err(|e| {
                self.latch(error::fmt!(
                    SocketError,
                    "QWP/WebSocket socket write failed: {}",
                    e
                ))
            })?;
        self.stream.flush().map_err(|e| {
            self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket socket flush failed: {}",
                e
            ))
        })?;

        let fsn = self.next_fsn;
        self.next_fsn = self.next_fsn.wrapping_add(1);
        Ok(PublishedFrame { fsn })
    }

    /// Record a just-published frame as in-flight. Called by
    /// `ColumnSender::flush` after `publish_qwp` succeeds.
    pub(crate) fn push_pending(&mut self, fsn: u64) {
        self.pending_acks.push_back(PendingAck { fsn });
        self.in_flight += 1;
    }

    /// Number of published-but-unacked frames.
    pub(crate) fn in_flight(&self) -> u32 {
        self.in_flight
    }

    /// `true` when a deferred publish can still leave one in-flight slot
    /// for the later non-deferred sync commit frame.
    pub(crate) fn has_sync_commit_slot(&self) -> bool {
        self.in_flight < MAX_IN_FLIGHT - 1
    }

    pub(crate) fn validate_ack_level(&self, ack_level: AckLevel) -> Result<()> {
        if ack_level == AckLevel::Durable && !self.durable_ack_opt_in {
            return Err(error::fmt!(
                InvalidApiCall,
                "AckLevel::Durable requires the pool to be opened with \
                 `request_durable_ack=on` in the connect string."
            ));
        }
        Ok(())
    }

    /// Drain any QWP responses available without blocking. Returns the
    /// number of responses consumed (OK acks, durable acks, etc.).
    pub(crate) fn try_drain_acks(&mut self) -> Result<u32> {
        let mut drained = 0u32;
        loop {
            match self.try_recv_qwp_response()? {
                None => return Ok(drained),
                Some(response) => {
                    self.process_response(response)?;
                    drained += 1;
                }
            }
        }
    }

    /// Block until at least one OK ack arrives. Used when
    /// `in_flight == MAX_IN_FLIGHT` to free a slot.
    pub(crate) fn drain_one_ack_blocking(&mut self) -> Result<()> {
        self.set_timeouts(Some(self.request_timeout), Some(self.request_timeout))?;
        loop {
            let response = self.recv_qwp_response()?;
            match &response {
                QwpResponse::Ok { .. } => {
                    self.process_response(response)?;
                    return Ok(());
                }
                _ => {
                    self.process_response(response)?;
                }
            }
        }
    }

    /// Block until all in-flight frames are OK-acked. For
    /// `AckLevel::Durable`, also wait for durable watermarks to reach
    /// every pending frame's seq_txn.
    pub(crate) fn sync_all_acks(&mut self, ack_level: AckLevel) -> Result<()> {
        if self.must_close {
            return Err(error::fmt!(
                SocketError,
                "QWP/WebSocket connection latched as terminal."
            ));
        }
        self.validate_ack_level(ack_level)?;

        // Arm the blocking-read timeout explicitly rather than relying on a
        // prior `publish_qwp` having set it on this socket; a sync with no
        // preceding publish must not block forever on a dead peer.
        self.set_timeouts(Some(self.request_timeout), Some(self.request_timeout))?;

        while self.in_flight > 0 {
            let response = self.recv_qwp_response()?;
            self.process_response(response)?;
        }

        if ack_level == AckLevel::Durable {
            while !self.durability_satisfied() {
                let response = self.recv_qwp_response()?;
                self.process_response(response)?;
            }
        }

        // Prune on every sync: without this a durable-ack connection driven
        // only with `sync(Ok)` retains one target per table for its pooled life.
        self.drop_satisfied_durable_targets();

        Ok(())
    }

    fn durability_satisfied(&self) -> bool {
        self.pending_durable_targets.iter().all(|(t, target)| {
            self.durable_watermarks.get(t).copied().unwrap_or(i64::MIN) >= *target
        })
    }

    fn drop_satisfied_durable_targets(&mut self) {
        let watermarks = &self.durable_watermarks;
        self.pending_durable_targets
            .retain(|t, target| watermarks.get(t).copied().unwrap_or(i64::MIN) < *target);
    }

    /// Dispatch a parsed QWP response: validate OK sequence, update
    /// in-flight tracking, absorb durable watermarks (DurableAck only),
    /// latch on error.
    fn process_response(&mut self, response: QwpResponse) -> Result<()> {
        match response {
            QwpResponse::Ok { sequence, tables } => {
                let mut popped = 0u32;
                while let Some(front) = self.pending_acks.front() {
                    if front.fsn > sequence {
                        break;
                    }
                    self.pending_acks.pop_front();
                    popped += 1;
                }
                if popped == 0 {
                    return Err(self.latch(error::fmt!(
                        SocketError,
                        "QWP OK sequence {} has no matching pending frame (next pending: {:?})",
                        sequence,
                        self.pending_acks.front().map(|p| p.fsn)
                    )));
                }
                // Invariant: `pending_acks.len() + popped == in_flight_before`.
                // A future refactor that desynchronises the two would
                // otherwise silently wrap in release builds.
                self.in_flight = self.in_flight.checked_sub(popped).ok_or_else(|| {
                    self.must_close = true;
                    error::fmt!(
                        SocketError,
                        "QWP in-flight accounting underflow: {} acked, {} tracked",
                        popped,
                        self.in_flight
                    )
                })?;
                // Only meaningful when durable acks are enabled: a later
                // `sync(Durable)` waits on these targets. Without the
                // opt-in, `Durable` is rejected up front and the map is
                // never pruned, so accumulating here would leak one entry
                // per distinct table for the life of a pooled connection.
                if self.durable_ack_opt_in {
                    for (t, seq_txn) in tables {
                        self.pending_durable_targets
                            .entry(t)
                            .and_modify(|w| {
                                if seq_txn > *w {
                                    *w = seq_txn;
                                }
                            })
                            .or_insert(seq_txn);
                    }
                }
                Ok(())
            }
            QwpResponse::DurableAck { tables } => {
                for (t, seq_txn) in tables {
                    self.durable_watermarks
                        .entry(t)
                        .and_modify(|w| {
                            if seq_txn > *w {
                                *w = seq_txn;
                            }
                        })
                        .or_insert(seq_txn);
                }
                Ok(())
            }
            QwpResponse::Error {
                sequence,
                status,
                message,
            } => {
                let err = map_error_status(status, &message);
                Err(self.latch(crate::Error::new(
                    err.code(),
                    format!(
                        "QWP server error on fsn {}: status=0x{:02x}, message={:?}",
                        sequence, status, message
                    ),
                )))
            }
        }
    }

    /// `true` when the in-flight count has hit the protocol cap and a
    /// blocking drain is needed before the next publish.
    pub(crate) fn at_in_flight_cap(&self) -> bool {
        self.in_flight >= MAX_IN_FLIGHT
    }

    /// Latches the connection as terminal and returns the originating
    /// error. Used by every socket-side failure path.
    fn latch(&mut self, err: crate::Error) -> crate::Error {
        self.must_close = true;
        err
    }

    fn set_timeouts(&mut self, read: Option<Duration>, write: Option<Duration>) -> Result<()> {
        self.stream.set_timeouts(read, write).map_err(|e| {
            self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket socket set_timeouts failed: {}",
                e
            ))
        })
    }

    /// Non-blocking attempt to read one QWP/WS data frame. Returns
    /// `Ok(None)` if no complete frame is available yet (WouldBlock).
    fn try_recv_qwp_response(&mut self) -> Result<Option<QwpResponse>> {
        loop {
            match FrameHeader::parse(&self.leftover) {
                Ok(h) => {
                    if !h.fin {
                        return Err(self.latch(error::fmt!(
                            SocketError,
                            "QWP/WebSocket server sent a fragmented frame; QWP is FIN-only"
                        )));
                    }
                    if h.payload_len > MAX_INBOUND_FRAME_BYTES {
                        return Err(self.latch(error::fmt!(
                            SocketError,
                            "WS frame declared {} payload bytes (max {})",
                            h.payload_len,
                            MAX_INBOUND_FRAME_BYTES
                        )));
                    }
                    let payload_len = h.payload_len as usize;
                    let header_len = h.header_len;
                    // Check if we have enough leftover for header + payload.
                    if self.leftover.len() < header_len + payload_len {
                        // We have the header but not the full payload yet.
                        // Try one non-blocking read to get more.
                        if !self.try_fill_leftover()? {
                            return Ok(None);
                        }
                        continue;
                    }
                    // Consume header + payload from leftover.
                    self.leftover.drain(..header_len);
                    self.read_buf.clear();
                    if self.read_buf.try_reserve(payload_len).is_err() {
                        return Err(self.latch(error::fmt!(
                            SocketError,
                            "could not allocate {} bytes for inbound QWP frame",
                            payload_len
                        )));
                    }
                    self.read_buf
                        .extend_from_slice(&self.leftover[..payload_len]);
                    self.leftover.drain(..payload_len);
                    match h.opcode {
                        Opcode::Binary => {
                            return parse_qwp_response(&self.read_buf)
                                .inspect_err(|_| {
                                    self.must_close = true;
                                })
                                .map(Some);
                        }
                        Opcode::Ping => {
                            self.send_pong(payload_len)?;
                            continue;
                        }
                        Opcode::Pong => continue,
                        Opcode::Close => {
                            self.must_close = true;
                            return Err(error::fmt!(
                                SocketError,
                                "QWP/WebSocket server closed the connection"
                            ));
                        }
                    }
                }
                Err(FrameError::Incomplete) => {
                    if !self.try_fill_leftover()? {
                        return Ok(None);
                    }
                }
                Err(FrameError::Protocol(msg)) => {
                    return Err(self.latch(error::fmt!(
                        SocketError,
                        "QWP/WebSocket frame parse error: {}",
                        msg
                    )));
                }
            }
        }
    }

    /// Read one QWP/WS data frame's payload and decode the QWP response.
    /// Ping frames are answered transparently; pong frames are dropped;
    /// close frames latch the connection.
    fn recv_qwp_response(&mut self) -> Result<QwpResponse> {
        loop {
            let header = self.read_ws_frame_header()?;
            if !header.fin {
                return Err(self.latch(error::fmt!(
                    SocketError,
                    "QWP/WebSocket server sent a fragmented frame; QWP is FIN-only"
                )));
            }
            let payload_len = header.payload_len as usize;
            if header.payload_len > MAX_INBOUND_FRAME_BYTES {
                return Err(self.latch(error::fmt!(
                    SocketError,
                    "WS frame declared {} payload bytes (max {})",
                    header.payload_len,
                    MAX_INBOUND_FRAME_BYTES
                )));
            }
            self.read_buf.clear();
            if self.read_buf.try_reserve(payload_len).is_err() {
                return Err(self.latch(error::fmt!(
                    SocketError,
                    "could not allocate {} bytes for inbound QWP frame",
                    payload_len
                )));
            }
            self.read_buf.resize(payload_len, 0);
            self.read_exact_into_buf(payload_len)?;
            match header.opcode {
                Opcode::Binary => {
                    return parse_qwp_response(&self.read_buf).inspect_err(|_| {
                        // Parse error: not a transport failure; the
                        // server gave us bytes that don't conform to the
                        // QWP response schema. Latch and surface.
                        self.must_close = true;
                    });
                }
                Opcode::Ping => {
                    self.send_pong(payload_len)?;
                    continue;
                }
                Opcode::Pong => {
                    continue;
                }
                Opcode::Close => {
                    self.must_close = true;
                    return Err(error::fmt!(
                        SocketError,
                        "QWP/WebSocket server closed the connection"
                    ));
                }
            }
        }
    }

    /// Read a complete WS frame header from `leftover` / the socket.
    fn read_ws_frame_header(&mut self) -> Result<FrameHeader> {
        // Need at most 10 bytes for any header we'd parse (server frames
        // are unmasked).
        loop {
            match FrameHeader::parse(&self.leftover) {
                Ok(h) => {
                    // Trim the header bytes from leftover and return.
                    let header_len = h.header_len;
                    self.leftover.drain(..header_len);
                    return Ok(h);
                }
                Err(FrameError::Incomplete) => {
                    self.fill_leftover()?;
                }
                Err(FrameError::Protocol(msg)) => {
                    return Err(self.latch(error::fmt!(
                        SocketError,
                        "QWP/WebSocket frame parse error: {}",
                        msg
                    )));
                }
            }
        }
    }

    /// Fill `read_buf[..len]` from `leftover` + the socket.
    fn read_exact_into_buf(&mut self, len: usize) -> Result<()> {
        let from_leftover = self.leftover.len().min(len);
        self.read_buf[..from_leftover].copy_from_slice(&self.leftover[..from_leftover]);
        self.leftover.drain(..from_leftover);
        let mut filled = from_leftover;
        while filled < len {
            let n = self
                .stream
                .read(&mut self.read_buf[filled..])
                .map_err(|e| {
                    self.latch(error::fmt!(
                        SocketError,
                        "QWP/WebSocket socket read failed: {}",
                        e
                    ))
                })?;
            if n == 0 {
                return Err(self.latch(error::fmt!(
                    SocketError,
                    "QWP/WebSocket socket closed unexpectedly during frame read"
                )));
            }
            filled += n;
        }
        Ok(())
    }

    /// Non-blocking attempt to read more bytes from the socket into
    /// `leftover`. Returns `Ok(true)` if data was read, `Ok(false)` on
    /// WouldBlock.
    fn try_fill_leftover(&mut self) -> Result<bool> {
        let mut chunk = [0u8; 4096];
        match self.stream.read_nonblocking_once(&mut chunk) {
            Ok(0) => Err(self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket socket closed unexpectedly"
            ))),
            Ok(n) => {
                self.leftover.extend_from_slice(&chunk[..n]);
                Ok(true)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(e) => Err(self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket non-blocking read failed: {}",
                e
            ))),
        }
    }

    /// Read at least one more byte from the socket into `leftover`.
    fn fill_leftover(&mut self) -> Result<()> {
        let mut chunk = [0u8; 1024];
        let n = self.stream.read(&mut chunk).map_err(|e| {
            self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket socket read failed: {}",
                e
            ))
        })?;
        if n == 0 {
            return Err(self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket socket closed unexpectedly while reading frame header"
            )));
        }
        self.leftover.extend_from_slice(&chunk[..n]);
        Ok(())
    }

    fn send_pong(&mut self, payload_len: usize) -> Result<()> {
        // The pong payload must echo the ping payload, which is in
        // read_buf[..payload_len].
        let mask_key = self.mask_keys.next_key().map_err(|e| {
            self.latch(error::fmt!(SocketError, "mask key entropy failed: {}", e.0))
        })?;
        // Use a small scratch buffer to encode the pong; pongs are tiny
        // (≤ 125 bytes by RFC) so this allocation is negligible.
        let mut pong = Vec::with_capacity(WS_HEADER_RESERVE + payload_len);
        frame::encode_client_frame(
            &mut pong,
            Opcode::Pong,
            mask_key,
            &self.read_buf[..payload_len],
        );
        self.stream.write_all(&pong).map_err(|e| {
            self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket pong write failed: {}",
                e
            ))
        })?;
        self.stream.flush().map_err(|e| {
            self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket pong flush failed: {}",
                e
            ))
        })?;
        Ok(())
    }
}

impl Drop for ColumnConn {
    fn drop(&mut self) {
        let _ = self
            .stream
            .set_timeouts(Some(CLOSE_TIMEOUT), Some(CLOSE_TIMEOUT));
        let Ok(mask_key) = self.mask_keys.next_key() else {
            return;
        };
        self.write_buf.clear();
        encode_client_frame(
            &mut self.write_buf,
            Opcode::Close,
            mask_key,
            &WS_CLOSE_STATUS_NORMAL,
        );
        let _ = self.stream.write_all(&self.write_buf);
        let _ = self.stream.flush();
        self.stream.shutdown_tls();
    }
}

/// Outcome of a successful publish call.
pub(crate) struct PublishedFrame {
    pub(crate) fsn: u64,
}

#[derive(Debug)]
enum QwpResponse {
    Ok {
        sequence: u64,
        tables: Vec<(String, i64)>,
    },
    DurableAck {
        tables: Vec<(String, i64)>,
    },
    Error {
        sequence: u64,
        status: u8,
        message: String,
    },
}

/// Parse a QWP/WS response payload (the body of a binary WS frame).
fn parse_qwp_response(payload: &[u8]) -> Result<QwpResponse> {
    if payload.is_empty() {
        return Err(error::fmt!(SocketError, "Empty QWP response frame"));
    }
    let status = payload[0];
    match status {
        QWP_STATUS_OK => {
            if payload.len() < 1 + 8 + 2 {
                return Err(error::fmt!(SocketError, "QWP OK response truncated"));
            }
            let sequence = u64::from_le_bytes(payload[1..9].try_into().unwrap());
            let tables = parse_table_entries(payload, 9, "QWP OK response")?;
            Ok(QwpResponse::Ok { sequence, tables })
        }
        QWP_STATUS_DURABLE_ACK => {
            let tables = parse_table_entries(payload, 1, "QWP durable ACK response")?;
            Ok(QwpResponse::DurableAck { tables })
        }
        _ => {
            let (sequence, message) = parse_error_body(payload)?;
            Ok(QwpResponse::Error {
                sequence,
                status,
                message,
            })
        }
    }
}

fn parse_table_entries(
    payload: &[u8],
    table_count_offset: usize,
    context: &'static str,
) -> Result<Vec<(String, i64)>> {
    let table_count_end = table_count_offset
        .checked_add(2)
        .ok_or_else(|| error::fmt!(SocketError, "{} table count offset overflow", context))?;
    if payload.len() < table_count_end {
        return Err(error::fmt!(SocketError, "{} truncated", context));
    }
    let table_count = u16::from_le_bytes(
        payload[table_count_offset..table_count_end]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut pos = table_count_end;
    let mut entries = Vec::with_capacity(table_count);
    for _ in 0..table_count {
        let name_len_end = pos
            .checked_add(2)
            .ok_or_else(|| error::fmt!(SocketError, "{} table entry offset overflow", context))?;
        if payload.len() < name_len_end {
            return Err(error::fmt!(
                SocketError,
                "{} table entry truncated",
                context
            ));
        }
        let name_len = u16::from_le_bytes(payload[pos..name_len_end].try_into().unwrap()) as usize;
        pos = name_len_end;
        if name_len == 0 {
            return Err(error::fmt!(SocketError, "{} table name is empty", context));
        }
        let name_end = pos
            .checked_add(name_len)
            .ok_or_else(|| error::fmt!(SocketError, "{} table name length overflow", context))?;
        let seq_txn_end = name_end
            .checked_add(8)
            .ok_or_else(|| error::fmt!(SocketError, "{} table entry length overflow", context))?;
        if payload.len() < seq_txn_end {
            return Err(error::fmt!(
                SocketError,
                "{} table entry truncated",
                context
            ));
        }
        let name = std::str::from_utf8(&payload[pos..name_end])
            .map_err(|_| error::fmt!(SocketError, "{} table name not UTF-8", context))?
            .to_owned();
        let seq_txn = i64::from_le_bytes(payload[name_end..seq_txn_end].try_into().unwrap());
        entries.push((name, seq_txn));
        pos = seq_txn_end;
    }
    if pos != payload.len() {
        return Err(error::fmt!(
            SocketError,
            "{} has trailing bytes after table entries",
            context
        ));
    }
    Ok(entries)
}

fn parse_error_body(payload: &[u8]) -> Result<(u64, String)> {
    if payload.len() < 1 + 8 + 2 {
        return Err(error::fmt!(SocketError, "QWP error response truncated"));
    }
    let sequence = u64::from_le_bytes(payload[1..9].try_into().unwrap());
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
    let message = std::str::from_utf8(&payload[11..msg_end])
        .map_err(|_| error::fmt!(SocketError, "QWP error message not UTF-8"))?
        .to_owned();
    Ok((sequence, message))
}

fn map_error_status(status: u8, msg: &str) -> crate::Error {
    match status {
        QWP_STATUS_SCHEMA_MISMATCH => {
            error::fmt!(InvalidApiCall, "QWP schema mismatch: {}", msg)
        }
        QWP_STATUS_PARSE_ERROR => error::fmt!(InvalidApiCall, "QWP parse error: {}", msg),
        QWP_STATUS_INTERNAL_ERROR => error::fmt!(ServerFlushError, "QWP internal error: {}", msg),
        QWP_STATUS_SECURITY_ERROR => error::fmt!(AuthError, "QWP security error: {}", msg),
        QWP_STATUS_WRITE_ERROR => error::fmt!(ServerFlushError, "QWP write error: {}", msg),
        _ => error::fmt!(
            ServerFlushError,
            "QWP unrecognised error status 0x{:02x}: {}",
            status,
            msg
        ),
    }
}

/// On-wire byte count of the client-to-server WS header for a given
/// payload length (mask bit always set ⇒ +4 bytes for the mask key).
#[inline]
fn ws_header_len_for(payload_len: usize) -> usize {
    if payload_len <= 125 {
        2 + 4
    } else if payload_len <= 0xFFFF {
        4 + 4
    } else {
        10 + 4
    }
}

/// Write the RFC 6455 binary-frame client header into `out`. `out.len()`
/// must equal [`ws_header_len_for(payload_len)`].
fn write_ws_header(out: &mut [u8], payload_len: usize, mask_key: [u8; 4]) {
    const FIN_BIT: u8 = 0x80;
    const BINARY_OPCODE: u8 = 0x2;
    const MASK_BIT: u8 = 0x80;
    out[0] = FIN_BIT | BINARY_OPCODE;
    let len_bytes;
    let mask_offset;
    if payload_len <= 125 {
        out[1] = MASK_BIT | (payload_len as u8);
        mask_offset = 2;
        len_bytes = 0;
    } else if payload_len <= 0xFFFF {
        out[1] = MASK_BIT | 126;
        out[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        mask_offset = 4;
        len_bytes = 2;
    } else {
        out[1] = MASK_BIT | 127;
        out[2..10].copy_from_slice(&(payload_len as u64).to_be_bytes());
        mask_offset = 10;
        len_bytes = 8;
    }
    let _ = len_bytes;
    out[mask_offset..mask_offset + 4].copy_from_slice(&mask_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_header_len_matches_payload_length_class() {
        assert_eq!(ws_header_len_for(0), 6);
        assert_eq!(ws_header_len_for(125), 6);
        assert_eq!(ws_header_len_for(126), 8);
        assert_eq!(ws_header_len_for(0xFFFF), 8);
        assert_eq!(ws_header_len_for(0x1_0000), 14);
        assert_eq!(ws_header_len_for(1 << 24), 14);
    }

    #[test]
    fn write_ws_header_short_form() {
        let mut buf = [0u8; 6];
        write_ws_header(&mut buf, 5, [0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(buf[0], 0x82); // FIN=1, opcode=Binary
        assert_eq!(buf[1], 0x80 | 5); // MASK=1, len=5
        assert_eq!(&buf[2..6], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn write_ws_header_16bit_form() {
        let mut buf = [0u8; 8];
        write_ws_header(&mut buf, 200, [1, 2, 3, 4]);
        assert_eq!(buf[0], 0x82);
        assert_eq!(buf[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([buf[2], buf[3]]), 200);
        assert_eq!(&buf[4..8], &[1, 2, 3, 4]);
    }

    #[test]
    fn write_ws_header_64bit_form() {
        let mut buf = [0u8; 14];
        write_ws_header(&mut buf, 0x1_0000, [9, 8, 7, 6]);
        assert_eq!(buf[0], 0x82);
        assert_eq!(buf[1], 0x80 | 127);
        assert_eq!(
            u64::from_be_bytes([
                buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9]
            ]),
            0x1_0000
        );
        assert_eq!(&buf[10..14], &[9, 8, 7, 6]);
    }

    #[test]
    fn parse_qwp_ok_with_one_table() {
        // status=OK, sequence=42, table_count=1, name_len=2, "tx", seq_txn=7
        let mut payload = vec![0u8];
        payload.extend_from_slice(&42u64.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(b"tx");
        payload.extend_from_slice(&7i64.to_le_bytes());
        let response = parse_qwp_response(&payload).unwrap();
        match response {
            QwpResponse::Ok { sequence, tables } => {
                assert_eq!(sequence, 42);
                assert_eq!(tables, vec![("tx".to_owned(), 7)]);
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn parse_qwp_durable_ack_empty() {
        // status=DurableAck, table_count=0
        let mut payload = vec![QWP_STATUS_DURABLE_ACK];
        payload.extend_from_slice(&0u16.to_le_bytes());
        let response = parse_qwp_response(&payload).unwrap();
        match response {
            QwpResponse::DurableAck { tables } => {
                assert!(tables.is_empty());
            }
            other => panic!("expected DurableAck, got {other:?}"),
        }
    }

    #[test]
    fn parse_qwp_error_truncated_rejected() {
        // status=PARSE_ERROR but only the status byte present
        let err = parse_qwp_response(&[QWP_STATUS_PARSE_ERROR]).unwrap_err();
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
    }

    fn dummy_ws_stream() -> WsStream {
        use crate::ws::nosigpipe::NoSigpipeTcp;
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let client = TcpStream::connect(addr).expect("connect");
        // Keep the accepted peer alive only long enough to complete the
        // connect; the ack-bookkeeping path never touches the socket.
        let _server = listener.accept().expect("accept");
        WsStream::Plain(NoSigpipeTcp::new(client).expect("nosigpipe"))
    }

    #[test]
    fn process_ok_pops_pending_and_tracks_durable_when_opted_in() {
        let mut conn = ColumnConn::for_test(dummy_ws_stream(), true);
        conn.push_pending(0);
        conn.process_response(QwpResponse::Ok {
            sequence: 0,
            tables: vec![("trades".to_string(), 7)],
        })
        .expect("matching ok");
        assert_eq!(conn.in_flight(), 0);
        assert_eq!(conn.pending_durable_target_count(), 1);
        assert!(!conn.must_close());
    }

    #[test]
    fn process_ok_skips_durable_targets_without_opt_in() {
        let mut conn = ColumnConn::for_test(dummy_ws_stream(), false);
        conn.push_pending(0);
        conn.process_response(QwpResponse::Ok {
            sequence: 0,
            tables: vec![("trades".to_string(), 7), ("quotes".to_string(), 3)],
        })
        .expect("matching ok");
        assert_eq!(conn.in_flight(), 0);
        assert_eq!(
            conn.pending_durable_target_count(),
            0,
            "durable targets must not accumulate without request_durable_ack"
        );
    }

    #[test]
    fn process_unmatched_ok_latches_connection() {
        let mut conn = ColumnConn::for_test(dummy_ws_stream(), false);
        // No pending frame: an OK that matches nothing is a protocol error.
        let err = conn
            .process_response(QwpResponse::Ok {
                sequence: 0,
                tables: vec![],
            })
            .expect_err("unmatched ok must error");
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(conn.must_close());
    }

    #[test]
    fn process_stale_ok_below_pending_fsn_latches() {
        let mut conn = ColumnConn::for_test(dummy_ws_stream(), false);
        conn.push_pending(5);
        // An OK whose sequence precedes the oldest pending frame matches
        // nothing and must latch rather than silently drop.
        let err = conn
            .process_response(QwpResponse::Ok {
                sequence: 3,
                tables: vec![],
            })
            .expect_err("stale ok must error");
        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(conn.must_close());
    }

    #[test]
    fn process_error_frame_maps_status_and_latches() {
        for (status, expected) in [
            (QWP_STATUS_SCHEMA_MISMATCH, crate::ErrorCode::InvalidApiCall),
            (
                QWP_STATUS_INTERNAL_ERROR,
                crate::ErrorCode::ServerFlushError,
            ),
            (QWP_STATUS_SECURITY_ERROR, crate::ErrorCode::AuthError),
            (QWP_STATUS_WRITE_ERROR, crate::ErrorCode::ServerFlushError),
        ] {
            let mut conn = ColumnConn::for_test(dummy_ws_stream(), false);
            let err = conn
                .process_response(QwpResponse::Error {
                    sequence: 0,
                    status,
                    message: "boom".to_string(),
                })
                .expect_err("server error must surface");
            assert_eq!(err.code(), expected, "status 0x{status:02x}");
            assert!(conn.must_close(), "error must latch the connection");
        }
    }
}
