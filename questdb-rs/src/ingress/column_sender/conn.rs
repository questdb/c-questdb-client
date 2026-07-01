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
use std::time::{Duration, Instant};

use crate::ingress::RawQwpWsRoundStream;
use crate::ingress::sender::qwp_ws::WsStream;
use crate::ws::frame::{self, FrameError, FrameHeader, Opcode, encode_client_frame};
use crate::ws::mask::{MaskKeySource, apply_mask};
use crate::{Result, error};

use crate::ingress::AckLevel;

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
    /// Sticky: set when `must_close` was latched by a **transport-level**
    /// failure (socket write/read error, EOF, server-closed, framing/parse
    /// error) — i.e. the cases that surface as `FailoverRetry`. The pool reads
    /// this on return to decide whether to mark the connection's endpoint
    /// unhealthy: a transport death rotates future borrows away from the dead
    /// peer, but a server-data rejection (schema / `ServerFlushError`) or a
    /// pool-driven `mark_must_close` (un-sync'd pending frames) leaves the
    /// endpoint healthy.
    transport_dead: bool,
    /// Index into the pool's configured endpoint list this connection was
    /// opened against. The pool marks this endpoint unhealthy in its shared
    /// health tracker when the connection dies, so subsequent borrows rotate
    /// to a live endpoint instead of re-hitting the dead peer.
    endpoint_idx: usize,
    max_buf_size: usize,
    request_timeout: Duration,
    durable_ack_opt_in: bool,
}

impl ColumnConn {
    /// Wrap an already-connected, endpoint-tagged raw QWP/WS stream
    /// ([`RawQwpWsRoundStream`]) opened by the pool's shared
    /// [`crate::ingress::QwpWsConnector`]. Endpoint selection, TLS, auth, and
    /// the HTTP→WS upgrade have already happened; this only attaches the
    /// per-connection ack-bookkeeping state.
    pub(crate) fn from_round_stream(raw: RawQwpWsRoundStream) -> Result<Self> {
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
            transport_dead: false,
            endpoint_idx: raw.endpoint_idx,
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
            transport_dead: false,
            endpoint_idx: 0,
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

    /// `true` when `must_close` was latched by a transport-level failure (the
    /// pool then marks this connection's endpoint unhealthy).
    pub(crate) fn transport_dead(&self) -> bool {
        self.transport_dead
    }

    /// Index of the pool endpoint this connection was opened against.
    pub(crate) fn endpoint_idx(&self) -> usize {
        self.endpoint_idx
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
    ///
    /// The error half of the result distinguishes whether any byte of the
    /// frame could have reached the wire ([`PublishError::DuringWrite`]) from a
    /// failure proven to precede transmission ([`PublishError::BeforeWrite`]).
    /// Publish-only callers treat both alike; the ACKing flush path uses the
    /// distinction to classify delivery certainty (see `FlushFailure`).
    pub(crate) fn publish_qwp<F>(
        &mut self,
        encode: F,
    ) -> std::result::Result<PublishedFrame, PublishError>
    where
        F: FnOnce(&mut Vec<u8>) -> Result<()>,
    {
        if self.must_close {
            return Err(PublishError::BeforeWrite(error::fmt!(
                SocketError,
                "QWP/WebSocket connection latched as terminal; \
                 return the sender to the pool and acquire a fresh one."
            )));
        }

        // Set up the buffer: 14 zero bytes that the WS header will
        // overwrite once we know the actual payload length.
        self.write_buf.clear();
        self.write_buf.resize(WS_HEADER_RESERVE, 0);

        // Caller writes the QWP frame body.
        if let Err(e) = encode(&mut self.write_buf) {
            // Encode failure leaves the connection usable — the bytes
            // never hit the wire — but the buffer state needs resetting
            // so the next publish starts clean.
            self.write_buf.clear();
            return Err(PublishError::BeforeWrite(e));
        }

        let payload_len = self.write_buf.len() - WS_HEADER_RESERVE;
        if payload_len > self.max_buf_size {
            return Err(PublishError::BeforeWrite(error::fmt!(
                BatchTooLarge,
                "QWP frame ({} bytes) exceeds max_buf_size ({} bytes)",
                payload_len,
                self.max_buf_size
            )));
        }

        let mask_key = match self.mask_keys.next_key() {
            Ok(k) => k,
            Err(e) => {
                return Err(PublishError::BeforeWrite(self.latch(error::fmt!(
                    SocketError,
                    "mask key entropy failed: {}",
                    e.0
                ))));
            }
        };

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

        // Arming the write timeout still precedes any byte hitting the wire.
        if let Err(e) = self.set_timeouts(Some(self.request_timeout), Some(self.request_timeout)) {
            return Err(PublishError::BeforeWrite(e));
        }
        if let Err(e) = self.stream.write_all(&self.write_buf[header_offset..]) {
            return Err(PublishError::DuringWrite(self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket socket write failed: {}",
                e
            ))));
        }
        if let Err(e) = self.stream.flush() {
            return Err(PublishError::DuringWrite(self.latch(error::fmt!(
                SocketError,
                "QWP/WebSocket socket flush failed: {}",
                e
            ))));
        }

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

    /// Drain any QWP responses available without blocking, processing each
    /// (OK acks, durable acks, etc.) into the in-flight bookkeeping.
    pub(crate) fn try_drain_acks(&mut self) -> Result<()> {
        while let Some(response) = self.try_recv_qwp_response()? {
            self.process_response(response)?;
        }
        Ok(())
    }

    /// Block until the in-flight count drops by at least one, freeing a
    /// publish slot. Used when `in_flight == MAX_IN_FLIGHT`.
    ///
    /// "Saw an OK frame" is not the same as "freed a slot": a cumulative OK
    /// that advances no pending frame (handled as a no-op by `process_response`)
    /// frees nothing, so the loop waits for `in_flight` to actually fall rather
    /// than for the first OK. A no-progress deadline bounds the wait so a peer
    /// that stays alive yet never advances cannot block the caller forever.
    pub(crate) fn drain_one_ack_blocking(&mut self) -> Result<()> {
        self.set_timeouts(Some(self.request_timeout), Some(self.request_timeout))?;
        let target = self.in_flight;
        let deadline_anchor = Instant::now();
        loop {
            let response = self.recv_qwp_response()?;
            self.process_response(response)?;
            if self.in_flight < target {
                return Ok(());
            }
            if !self.request_timeout.is_zero() && deadline_anchor.elapsed() >= self.request_timeout
            {
                return Err(self.latch(error::fmt!(
                    SocketError,
                    "QWP/WebSocket connection received no slot-freeing ack within {:?}",
                    self.request_timeout
                )));
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

        // No-progress deadline. The per-read `request_timeout` only bounds
        // waiting for *any* frame; a peer that keeps the socket live with
        // non-advancing OK/durable frames would never trip it and the loop
        // would spin forever. Reset the anchor on every real advance (in-flight
        // drops, or a durable watermark moves) and fail over once neither moves
        // for one `request_timeout` window. `request_timeout == 0` (no socket
        // timeout configured) preserves the legacy unbounded behaviour.
        let bounded = !self.request_timeout.is_zero();

        let mut deadline_anchor = Instant::now();
        let mut last_in_flight = self.in_flight;
        while self.in_flight > 0 {
            let response = self.recv_qwp_response()?;
            self.process_response(response)?;
            if self.in_flight < last_in_flight {
                last_in_flight = self.in_flight;
                deadline_anchor = Instant::now();
            } else if bounded && deadline_anchor.elapsed() >= self.request_timeout {
                return Err(self.latch(error::fmt!(
                    SocketError,
                    "QWP/WebSocket sync stalled: {} frame(s) unacked with no progress for {:?}",
                    self.in_flight,
                    self.request_timeout
                )));
            }
        }

        if ack_level == AckLevel::Durable {
            let mut deadline_anchor = Instant::now();
            let mut last_mark = self.durable_progress_mark();
            while !self.durability_satisfied() {
                let response = self.recv_qwp_response()?;
                self.process_response(response)?;
                let mark = self.durable_progress_mark();
                if mark != last_mark {
                    last_mark = mark;
                    deadline_anchor = Instant::now();
                } else if bounded && deadline_anchor.elapsed() >= self.request_timeout {
                    return Err(self.latch(error::fmt!(
                        SocketError,
                        "QWP/WebSocket durable sync stalled: no watermark progress for {:?}",
                        self.request_timeout
                    )));
                }
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

    /// Fingerprint of durable progress: table count plus the sum of per-table
    /// watermarks. Durable acks only ever add tables or raise watermarks, so
    /// any genuine advance changes this, letting the sync loop distinguish a
    /// peer that is progressing from one that is idle-chattering.
    fn durable_progress_mark(&self) -> (usize, i128) {
        let sum: i128 = self.durable_watermarks.values().map(|&v| v as i128).sum();
        (self.durable_watermarks.len(), sum)
    }

    fn drop_satisfied_durable_targets(&mut self) {
        let watermarks = &self.durable_watermarks;
        self.pending_durable_targets
            .retain(|t, target| watermarks.get(t).copied().unwrap_or(i64::MIN) < *target);
        // `durable_watermarks` is deliberately NOT pruned here. A watermark must
        // outlive its satisfied pending target: a later redundant OK that
        // re-reports an already-durable table would otherwise re-insert a
        // pending target with no matching watermark and strand `sync(Durable)`
        // forever. The map grows by at most one entry per distinct table over
        // the connection's life, matching the row sender's `DurableAckTracker`.
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
                    // QWP OK acks are cumulative ("completed through
                    // `sequence`"). An OK that advances no pending frame is a
                    // redundant/non-advancing progress ack the server may emit;
                    // tolerate it as a no-op (matching the row API) rather than
                    // tearing down the connection. It must NOT contribute a
                    // durable target: it only re-reports already-acked tables,
                    // so re-inserting one whose watermark was already satisfied
                    // would strand a later `sync(Durable)` forever.
                    return Ok(());
                }
                // Only a progress-advancing OK contributes durable targets — it
                // is the wire event paired with a following DurableAck. Opt-in
                // only; otherwise `Durable` is rejected up front and the targets
                // map is never pruned, so accumulating would leak one entry per
                // table for the connection's life.
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
    /// error. Used by every socket-side failure path. A `SocketError` is a
    /// transport death (reconnectable), so it also flags `transport_dead` for
    /// the pool's endpoint-health bookkeeping; server-data rejections
    /// (`ServerFlushError` / schema) latch without that flag.
    fn latch(&mut self, err: crate::Error) -> crate::Error {
        self.must_close = true;
        if err.code() == crate::ErrorCode::SocketError {
            self.transport_dead = true;
        }
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
                            self.transport_dead = true;
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
                    self.transport_dead = true;
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
        // Skip the Close frame unless the write timeout pins — a hung peer
        // would otherwise block deallocation for the OS default.
        if self
            .stream
            .set_timeouts(Some(CLOSE_TIMEOUT), Some(CLOSE_TIMEOUT))
            .is_ok()
            && let Ok(mask_key) = self.mask_keys.next_key()
        {
            self.write_buf.clear();
            encode_client_frame(
                &mut self.write_buf,
                Opcode::Close,
                mask_key,
                &WS_CLOSE_STATUS_NORMAL,
            );
            let _ = self.stream.write_all(&self.write_buf);
            let _ = self.stream.flush();
        }
        self.stream.shutdown_tls();
    }
}

/// Outcome of a successful publish call.
pub(crate) struct PublishedFrame {
    pub(crate) fsn: u64,
}

/// Failure of [`ColumnConn::publish_qwp`], carrying whether the current frame
/// could already be on the wire.
pub(crate) enum PublishError {
    /// No byte of the frame was transmitted: the connection was already
    /// latched, encode failed, the frame was oversized, mask-key entropy
    /// failed, or arming the socket timeout failed. The frame is provably
    /// un-sent.
    BeforeWrite(crate::Error),
    /// `write_all`/`flush` failed after the write began — bytes may already be
    /// on the wire. The connection has been latched `must_close`.
    DuringWrite(crate::Error),
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
    // Reserve fallibly, bounded by what the payload can actually hold (every
    // entry is at least 2 name-len + 1 name + 8 seq_txn bytes), so a lying
    // `table_count` can neither abort on OOM nor over-allocate.
    let max_entries = payload.len().saturating_sub(table_count_end) / 11;
    let mut entries: Vec<(String, i64)> = Vec::new();
    if entries.try_reserve(table_count.min(max_entries)).is_err() {
        return Err(error::fmt!(
            SocketError,
            "{} could not allocate {} table entries",
            context,
            table_count
        ));
    }
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
/// must equal `ws_header_len_for(payload_len)`.
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
    fn process_unmatched_ok_is_tolerated_as_noop() {
        let mut conn = ColumnConn::for_test(dummy_ws_stream(), false);
        // No pending frame: a cumulative OK that advances nothing is a
        // redundant progress ack, not a fatal error. It is a no-op and
        // leaves the connection reusable.
        conn.process_response(QwpResponse::Ok {
            sequence: 0,
            tables: vec![],
        })
        .expect("redundant ok must be tolerated");
        assert!(!conn.must_close());
    }

    #[test]
    fn process_stale_ok_below_pending_fsn_is_noop_and_keeps_pending() {
        let mut conn = ColumnConn::for_test(dummy_ws_stream(), false);
        conn.push_pending(5);
        // An OK whose sequence precedes the oldest pending frame advances
        // nothing; it is tolerated as a no-op and the pending frame stays
        // in flight for its real ack.
        conn.process_response(QwpResponse::Ok {
            sequence: 3,
            tables: vec![],
        })
        .expect("stale ok must be tolerated");
        assert!(!conn.must_close());
        assert_eq!(conn.in_flight(), 1);
        conn.process_response(QwpResponse::Ok {
            sequence: 5,
            tables: vec![],
        })
        .expect("matching ok must pop");
        assert_eq!(conn.in_flight(), 0);
    }

    #[test]
    fn sync_all_acks_fails_fast_on_non_advancing_peer() {
        use crate::ws::nosigpipe::NoSigpipeTcp;
        use std::net::{TcpListener, TcpStream};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::mpsc;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        // The peer floods non-advancing OK frames (sequence 0) while the conn
        // waits for fsn 5: in_flight never drops and reads never time out, so
        // only the no-progress deadline can end the wait. Without it,
        // sync_all_acks spins forever.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_writer = Arc::clone(&stop);
        let flood = thread::spawn(move || {
            let mut server = server;
            let mut payload = vec![QWP_STATUS_OK];
            payload.extend_from_slice(&0u64.to_le_bytes());
            payload.extend_from_slice(&0u16.to_le_bytes());
            let mut ws_frame = vec![0x82u8, payload.len() as u8];
            ws_frame.extend_from_slice(&payload);
            while !stop_writer.load(Ordering::Relaxed) {
                if server.write_all(&ws_frame).is_err() {
                    break;
                }
            }
        });

        let mut conn = ColumnConn::for_test(
            WsStream::Plain(NoSigpipeTcp::new(client).expect("nosigpipe")),
            false,
        );
        conn.request_timeout = Duration::from_millis(150);
        conn.push_pending(5);

        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let code = conn.sync_all_acks(AckLevel::Ok).err().map(|e| e.code());
            let _ = tx.send(code);
        });

        let outcome = rx.recv_timeout(Duration::from_secs(5));
        stop.store(true, Ordering::Relaxed);
        let _ = worker.join();
        let _ = flood.join();

        match outcome {
            Ok(Some(code)) => assert_eq!(code, crate::ErrorCode::SocketError),
            Ok(None) => panic!("sync_all_acks unexpectedly succeeded against a non-advancing peer"),
            Err(_) => panic!("sync_all_acks hung: the no-progress deadline did not fire"),
        }
    }

    #[test]
    fn redundant_ok_after_durable_prune_does_not_strand_sync() {
        let mut conn = ColumnConn::for_test(dummy_ws_stream(), true);
        // Table `t` runs the full OK -> DurableAck -> satisfied cycle; its
        // satisfied pending target is pruned (the prune `sync_all_acks` runs).
        conn.push_pending(0);
        conn.process_response(QwpResponse::Ok {
            sequence: 0,
            tables: vec![("t".to_string(), 7)],
        })
        .expect("ok ack");
        conn.process_response(QwpResponse::DurableAck {
            tables: vec![("t".to_string(), 7)],
        })
        .expect("durable ack");
        conn.drop_satisfied_durable_targets();
        assert_eq!(
            conn.pending_durable_targets.len(),
            0,
            "satisfied pending targets must be pruned"
        );

        // A later redundant OK advances no pending frame but re-reports `t`.
        // It must stay a no-op for durable tracking: re-inserting a pending
        // target whose watermark was pruned would strand `sync(Durable)`.
        conn.process_response(QwpResponse::Ok {
            sequence: 0,
            tables: vec![("t".to_string(), 7)],
        })
        .expect("redundant ok");
        assert_eq!(
            conn.pending_durable_targets.len(),
            0,
            "a redundant OK must not resurrect a satisfied durable target"
        );
        assert_eq!(
            conn.durable_watermarks.get("t").copied(),
            Some(7),
            "durable watermarks must outlive their satisfied pending target"
        );
        assert!(
            conn.durability_satisfied(),
            "no pending targets => durability is trivially satisfied"
        );
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
