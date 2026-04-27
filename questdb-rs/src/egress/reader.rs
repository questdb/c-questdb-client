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

//! `Reader` (per-connection) + `Cursor` (per-query) public API.
//!
//! Phase 1: a single in-flight query per connection (runtime-checked, not
//! type-encoded). `Cursor::cancel()` issues a CANCEL frame and drains
//! until the terminal frame, leaving the Reader reusable. Dropping a
//! cursor before it has reached a terminal closes the underlying
//! WebSocket: subsequent operations on the Reader fail at the transport
//! layer (open a fresh Reader to recover). Call `Cursor::cancel()` (or
//! read until `next_batch()` returns `None`) before drop if you want to
//! keep the existing connection alive.

#![cfg(feature = "sync-reader-ws")]

use std::net::Ipv4Addr;

use crate::egress::binds::Bind;
use crate::egress::column::ColumnView;
use crate::egress::column_kind::ColumnKind;
use crate::egress::config::{ReaderConfig, Target};
use crate::egress::decoder::DecodedBatch;
use crate::egress::error::{Result, fmt};
use crate::egress::query_request::{QueryRequest, QueryRequestBuilder};
use crate::egress::schema::{Schema, SchemaRegistry};
use crate::egress::server_event::{ServerEvent, ServerInfo, ServerRole, decode_frame};
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::transport::WsTransport;
use crate::egress::wire::header::HEADER_LEN;
use crate::egress::wire::msg_kind::MsgKind;
use crate::egress::wire::varint;

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Per-connection reader. Owns the WebSocket transport and the
/// connection-scoped symbol dictionary + schema registry.
pub struct Reader {
    transport: WsTransport,
    dict: SymbolDict,
    registry: SchemaRegistry,
    next_request_id: i64,
    cursor_active: bool,
    /// Server's `SERVER_INFO` (`0x18`) — `None` when negotiated v1.
    /// Captured eagerly during connect so multi-addr role filtering
    /// can dismiss endpoints whose role doesn't match `target`.
    server_info: Option<ServerInfo>,
    /// Total wire bytes (header + payload) consumed since connect.
    /// Updated on every frame the reader pulls off the transport.
    bytes_received: u64,
    /// Total bytes granted to the server via CREDIT (`0x15`) frames
    /// since connect. Sums every per-batch auto-replenishment, every
    /// `Cursor::add_credit` call, and the cancel-time wake nudge. Used
    /// by tests to catch regressions where cancel keeps topping up the
    /// budget while draining frames it intends to discard.
    credit_granted_total: u64,
    /// Diagnostic: nanoseconds spent in `transport.read_frame()` since
    /// connect. Useful for splitting "wait on the socket" from "decode
    /// CPU" in throughput benchmarks.
    read_ns: u128,
    /// Diagnostic: nanoseconds spent in `decode_frame()` since connect.
    decode_ns: u128,
}

impl Reader {
    /// Open a new connection from a connect string.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let cfg = ReaderConfig::from_conf(conf)?;
        Self::from_config(&cfg)
    }

    /// Walk `cfg.addrs` in order, opening each endpoint and eagerly
    /// consuming the v2 `SERVER_INFO` frame. Accepts the first endpoint
    /// whose role matches `cfg.target`. Returns:
    ///
    /// - `RoleMismatch` if every endpoint connected but none advertised
    ///   a matching role (last-seen role surfaced in the message).
    /// - `SocketError` if every endpoint failed at the transport layer
    ///   (refused / timed out / TLS error / etc.).
    /// - whatever the last attempt returned otherwise.
    pub fn from_config(cfg: &ReaderConfig) -> Result<Self> {
        let mut last_transport_err: Option<crate::egress::Error> = None;
        let mut last_mismatched: Option<ServerInfo> = None;
        let mut saw_v1_with_filter = false;

        for idx in 0..cfg.addrs.len() {
            let transport = match WsTransport::connect_to(cfg, idx) {
                Ok(t) => t,
                Err(e) => {
                    last_transport_err = Some(e);
                    continue;
                }
            };
            let mut reader = Reader {
                transport,
                dict: SymbolDict::new(),
                registry: SchemaRegistry::new(),
                next_request_id: 1,
                cursor_active: false,
                server_info: None,
                bytes_received: 0,
                credit_granted_total: 0,
                read_ns: 0,
                decode_ns: 0,
            };
            // Eagerly consume the unsolicited SERVER_INFO frame on v2+.
            if reader.transport.server_version() >= 2 {
                match reader.consume_server_info() {
                    Ok(()) => {}
                    Err(e) => {
                        last_transport_err = Some(e);
                        continue;
                    }
                }
            }

            // Role filter.
            if !matches!(cfg.target, Target::Any) {
                let Some(info) = reader.server_info.as_ref() else {
                    // v1 server can't satisfy a specific-role filter.
                    saw_v1_with_filter = true;
                    continue;
                };
                if !target_matches(cfg.target, info.role) {
                    last_mismatched = Some(info.clone());
                    continue;
                }
            }
            return Ok(reader);
        }

        if let Some(info) = last_mismatched {
            return Err(fmt!(
                RoleMismatch,
                "no endpoint matches target={:?}; last observed role={:?} cluster={:?}",
                cfg.target,
                info.role,
                info.cluster_id
            ));
        }
        if saw_v1_with_filter {
            return Err(fmt!(
                RoleMismatch,
                "no endpoint matches target={:?}; at least one endpoint negotiated v1 and cannot supply a role",
                cfg.target
            ));
        }
        Err(last_transport_err
            .unwrap_or_else(|| fmt!(SocketError, "all {} endpoints unreachable", cfg.addrs.len())))
    }

    /// Total wire bytes (frame header + payload) read off the transport
    /// since this connection was opened. Useful for benchmarking the
    /// effective throughput a query produces.
    pub fn bytes_received(&self) -> u64 {
        self.bytes_received
    }

    /// Total bytes granted to the server via CREDIT (`0x15`) frames
    /// since this connection was opened. Useful for verifying that
    /// flow-control replenishment behaves as expected — in particular,
    /// that `Cursor::cancel()` doesn't continue topping up the server's
    /// budget while draining frames it's about to discard.
    pub fn credit_granted_total(&self) -> u64 {
        self.credit_granted_total
    }

    /// Diagnostic accumulators (nanoseconds): time spent in
    /// `transport.read_frame()` and `decode_frame()` respectively.
    /// Reset to zero by `reset_timing()`.
    pub fn read_ns(&self) -> u128 {
        self.read_ns
    }
    pub fn decode_ns(&self) -> u128 {
        self.decode_ns
    }
    pub fn reset_timing(&mut self) {
        self.read_ns = 0;
        self.decode_ns = 0;
    }

    /// Read one frame and expect it to be `SERVER_INFO`; store it.
    fn consume_server_info(&mut self) -> Result<()> {
        let (header, payload) = self.transport.read_frame()?;
        self.bytes_received += HEADER_LEN as u64 + header.payload_length as u64;
        let event = decode_frame(header, &payload, &mut self.dict, &mut self.registry)?;
        match event {
            ServerEvent::ServerInfo(info) => {
                self.server_info = Some(info);
                Ok(())
            }
            other => Err(fmt!(
                ProtocolError,
                "expected SERVER_INFO as first v2 frame, got {:?}",
                std::mem::discriminant(&other)
            )),
        }
    }

    /// `SERVER_INFO` (`0x18`) captured at connect time, when negotiated
    /// version >= 2. `None` for v1 servers.
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.server_info.as_ref()
    }

    /// Negotiated QWP version this connection is using.
    pub fn server_version(&self) -> u8 {
        self.transport.server_version()
    }

    /// Connection-scoped symbol dictionary.
    pub fn symbol_dict(&self) -> &SymbolDict {
        &self.dict
    }

    /// Connection-scoped schema registry.
    pub fn schema_registry(&self) -> &SchemaRegistry {
        &self.registry
    }

    /// Begin building a query. The returned `ReaderQuery` exclusively
    /// borrows the reader; only one in-flight cursor at a time (Phase 1).
    pub fn query<S: Into<String>>(&mut self, sql: S) -> ReaderQuery<'_> {
        ReaderQuery {
            reader: self,
            builder: QueryRequest::builder(sql),
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Query builder
// ---------------------------------------------------------------------------

/// Borrows a `Reader` exclusively while the query is being constructed and
/// (eventually) the cursor is live.
pub struct ReaderQuery<'r> {
    reader: &'r mut Reader,
    builder: QueryRequestBuilder,
    /// First fatal error (if any) deferred until `execute`, so the fluent
    /// chain stays clean.
    error: Option<crate::egress::Error>,
}

macro_rules! bind_method {
    ($name:ident, $($arg:ident : $ty:ty),*) => {
        pub fn $name(mut self, $($arg : $ty),*) -> Self {
            // Manually re-assign because QueryRequestBuilder consumes self.
            self.builder = self.builder.$name($($arg),*);
            self
        }
    };
}

impl<'r> ReaderQuery<'r> {
    /// Override the `initial_credit` (bytes; `0` = unbounded).
    pub fn initial_credit(mut self, credit: u64) -> Self {
        self.builder = self.builder.initial_credit(credit);
        self
    }

    /// Append a typed bind parameter.
    pub fn bind(mut self, value: Bind) -> Self {
        self.builder = self.builder.bind(value);
        self
    }

    bind_method!(bind_null, kind: ColumnKind);
    bind_method!(bind_bool, v: bool);
    bind_method!(bind_i8, v: i8);
    bind_method!(bind_i16, v: i16);
    bind_method!(bind_i32, v: i32);
    bind_method!(bind_i64, v: i64);
    bind_method!(bind_f32, v: f32);
    bind_method!(bind_f64, v: f64);
    bind_method!(bind_timestamp_micros, v: i64);
    bind_method!(bind_timestamp_nanos, v: i64);
    bind_method!(bind_date_millis, v: i64);
    bind_method!(bind_uuid_bytes, v: [u8; 16]);
    bind_method!(bind_long256, v: [u8; 32]);
    bind_method!(bind_char, v: u16);
    bind_method!(bind_ipv4, v: Ipv4Addr);

    pub fn bind_varchar<S: Into<String>>(mut self, v: S) -> Self {
        self.builder = self.builder.bind_varchar(v);
        self
    }

    pub fn bind_decimal64(mut self, value: i64, scale: i8) -> Self {
        self.builder = self.builder.bind_decimal64(value, scale);
        self
    }

    pub fn bind_decimal128(mut self, value: i128, scale: i8) -> Self {
        self.builder = self.builder.bind_decimal128(value, scale);
        self
    }

    pub fn bind_decimal256(mut self, bytes: [u8; 32], scale: i8) -> Self {
        self.builder = self.builder.bind_decimal256(bytes, scale);
        self
    }

    pub fn bind_geohash(mut self, value: u64, precision_bits: u8) -> Self {
        self.builder = self.builder.bind_geohash(value, precision_bits);
        self
    }

    pub fn bind_binary<B: Into<Vec<u8>>>(mut self, v: B) -> Self {
        self.builder = self.builder.bind_binary(v);
        self
    }

    pub fn bind_null_varchar(mut self) -> Self {
        self.builder = self.builder.bind_null_varchar();
        self
    }

    pub fn bind_null_binary(mut self) -> Self {
        self.builder = self.builder.bind_null_binary();
        self
    }

    pub fn bind_null_decimal64(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal64(scale);
        self
    }

    pub fn bind_null_decimal128(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal128(scale);
        self
    }

    pub fn bind_null_decimal256(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal256(scale);
        self
    }

    pub fn bind_null_geohash(mut self, precision_bits: u8) -> Self {
        self.builder = self.builder.bind_null_geohash(precision_bits);
        self
    }

    /// Send the QUERY_REQUEST and return a streaming `Cursor`.
    pub fn execute(self) -> Result<Cursor<'r>> {
        if let Some(e) = self.error {
            return Err(e);
        }
        if self.reader.cursor_active {
            return Err(fmt!(
                InvalidApiCall,
                "another cursor is already in flight on this connection (Phase 1 single-in-flight)"
            ));
        }
        let request_id = self.reader.next_request_id;
        // Skip 0 and negatives on wrap. Practically unreachable on a
        // single connection, but keeps `request_id` strictly positive
        // — `0` is the sentinel some server-side code paths use for
        // "no active streaming request".
        let next = self.reader.next_request_id.wrapping_add(1);
        self.reader.next_request_id = if next <= 0 { 1 } else { next };

        let req = self.builder.request_id(request_id).build()?;
        let credit_enabled = req.initial_credit() > 0;
        let mut buf = Vec::with_capacity(64);
        req.encode(&mut buf)?;
        self.reader.transport.write_message(&buf)?;

        self.reader.cursor_active = true;
        Ok(Cursor {
            reader: self.reader,
            request_id,
            last_batch: None,
            terminal: None,
            credit_enabled,
            cancelling: false,
            done: false,
        })
    }
}

// ---------------------------------------------------------------------------
// Cursor + BatchView
// ---------------------------------------------------------------------------

/// Reason the stream ended. Surfaced via [`Cursor::terminal`] once
/// `next_batch` returns `None`.
#[derive(Debug, Clone)]
pub enum Terminal {
    /// `RESULT_END` (`0x12`).
    End { final_seq: u64, total_rows: u64 },
    /// `EXEC_DONE` (`0x16`) — non-SELECT acknowledgement.
    ExecDone { op_type: u8, rows_affected: u64 },
}

/// Streaming cursor over `RESULT_BATCH` frames.
///
/// `next_batch` advances the stream by one batch, returning `None` once a
/// terminal frame arrives (which is then accessible via [`Cursor::terminal`]).
/// `cancel` sends a `CANCEL` frame and drains until the server's terminal.
pub struct Cursor<'r> {
    reader: &'r mut Reader,
    request_id: i64,
    last_batch: Option<DecodedBatch>,
    terminal: Option<Terminal>,
    /// `true` when the QUERY_REQUEST set `initial_credit > 0`. The
    /// cursor then auto-emits a CREDIT (`0x15`) frame after each
    /// RESULT_BATCH consumed, replenishing the server's per-request
    /// budget by exactly the wire size of the batch we just received
    /// (12-byte header + payload).
    credit_enabled: bool,
    /// Set once `cancel()` has written its CANCEL frame and entered the
    /// drain loop. Suppresses auto-credit replenishment for the rest of
    /// the cursor's life so the server's budget is allowed to drain to
    /// zero — this is the backpressure that hastens the post-cancel
    /// terminal. Without this, every drained batch would top the budget
    /// back up and the server could keep streaming at full rate until
    /// it finally observed the CANCEL on its input socket.
    cancelling: bool,
    /// Set once any terminal frame has been observed for this cursor:
    /// `RESULT_END`, `EXEC_DONE`, or `QUERY_ERROR` (including the
    /// `STATUS_CANCELLED` reply to `cancel()`). Drives the early
    /// return in `next_batch()` so a follow-up call doesn't try to
    /// read another frame off a server that has already finished with
    /// this `request_id`. `terminal` (the public lifecycle accessor)
    /// only stores the success terminals — error terminals are
    /// surfaced via the `Err` return and don't need a structured
    /// representation here.
    done: bool,
}

impl<'r> Cursor<'r> {
    pub fn request_id(&self) -> i64 {
        self.request_id
    }

    /// `Some` after a `RESULT_END` or `EXEC_DONE` has been observed.
    pub fn terminal(&self) -> Option<&Terminal> {
        self.terminal.as_ref()
    }

    /// Pass-through to [`Reader::credit_granted_total`]. Exists so
    /// callers holding the cursor's mutable borrow on the reader can
    /// still observe the connection-level CREDIT-bytes counter.
    pub fn credit_granted_total(&self) -> u64 {
        self.reader.credit_granted_total
    }

    /// Advance the cursor by one batch. Returns `Ok(None)` when the stream
    /// has terminated (success). `QUERY_ERROR` becomes `Err`.
    pub fn next_batch(&mut self) -> Result<Option<BatchView<'_>>> {
        if self.done {
            return Ok(None);
        }
        loop {
            let t0 = std::time::Instant::now();
            let (header, payload) = self.reader.transport.read_frame()?;
            self.reader.read_ns += t0.elapsed().as_nanos();
            // Capture wire size BEFORE decode (header is consumed).
            let wire_bytes = HEADER_LEN as u64 + header.payload_length as u64;
            self.reader.bytes_received += wire_bytes;
            let t1 = std::time::Instant::now();
            let event = decode_frame(
                header,
                &payload,
                &mut self.reader.dict,
                &mut self.reader.registry,
            )?;
            self.reader.decode_ns += t1.elapsed().as_nanos();
            match event {
                ServerEvent::Batch(b) => {
                    if b.request_id != self.request_id {
                        return Err(fmt!(
                            ProtocolError,
                            "RESULT_BATCH request_id {} != cursor {}",
                            b.request_id,
                            self.request_id
                        ));
                    }
                    // Replenish the server's per-request byte budget for
                    // the bytes we just took off the wire. The wire bytes
                    // are no longer pinned in our buffer; sending CREDIT
                    // here matches the server's "release on drain" policy.
                    //
                    // Suppress replenishment once `cancel()` has started
                    // draining: topping the server's budget back up while
                    // we're throwing the bytes away defeats the very
                    // backpressure that should be hastening cancellation.
                    if self.credit_enabled && !self.cancelling {
                        self.send_credit_frame(wire_bytes)?;
                    }
                    self.last_batch = Some(b);
                    let last = self.last_batch.as_ref().unwrap();
                    let schema = self.reader.registry.get(last.schema_id).ok_or_else(|| {
                        fmt!(
                            ProtocolError,
                            "RESULT_BATCH references schema {} not in registry",
                            last.schema_id
                        )
                    })?;
                    return Ok(Some(BatchView {
                        decoded: last,
                        dict: &self.reader.dict,
                        schema,
                    }));
                }
                ServerEvent::End {
                    request_id,
                    final_seq,
                    total_rows,
                } => {
                    self.check_rid(request_id, "RESULT_END")?;
                    self.terminal = Some(Terminal::End {
                        final_seq,
                        total_rows,
                    });
                    self.reader.cursor_active = false;
                    self.done = true;
                    return Ok(None);
                }
                ServerEvent::ExecDone {
                    request_id,
                    op_type,
                    rows_affected,
                } => {
                    self.check_rid(request_id, "EXEC_DONE")?;
                    self.terminal = Some(Terminal::ExecDone {
                        op_type,
                        rows_affected,
                    });
                    self.reader.cursor_active = false;
                    self.done = true;
                    return Ok(None);
                }
                ServerEvent::Error {
                    request_id,
                    status,
                    message,
                } => {
                    self.check_rid(request_id, "QUERY_ERROR")?;
                    self.reader.cursor_active = false;
                    self.done = true;
                    return Err(map_server_status(status, message));
                }
                ServerEvent::CacheReset { .. } | ServerEvent::ServerInfo(_) => {
                    // State already mutated by decode_frame; keep reading.
                    continue;
                }
            }
        }
    }

    /// Send a CANCEL frame and drain until the server emits a terminal
    /// frame for this request.
    pub fn cancel(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(9);
        payload.push(MsgKind::Cancel.as_u8());
        payload.extend_from_slice(&self.request_id.to_le_bytes());
        self.reader.transport.write_message(&payload)?;
        // Wake the server in case it's already credit-suspended. The
        // server's `handleCancel` only sets a flag; the cancel takes
        // effect when `streamResults` is next re-entered, which on a
        // credit-suspended stream happens only via `handleCredit`. A
        // 1-byte top-up is enough — `streamResults` checks the cancel
        // flag before the credit check, so the abort path fires
        // immediately and emits the terminal QUERY_ERROR. Without this
        // nudge a `cancel()` against a credit-suspended server would
        // deadlock.
        if self.credit_enabled {
            self.send_credit_frame(1)?;
        }
        // Stop topping up the server's credit window for the rest of
        // the drain — once the server has been told to cancel, we want
        // the remaining budget to bleed off so it stops generating new
        // batches rather than continuing to stream behind the cancel.
        self.cancelling = true;

        // Drain until any terminal frame (RESULT_END / EXEC_DONE /
        // QUERY_ERROR including STATUS_CANCELLED) — swallow batches
        // between CANCEL and the server's acknowledgement. `done` is
        // the right guard here, not `terminal`: an error terminal
        // sets `done` but leaves `terminal` as `None`.
        while !self.done {
            match self.next_batch() {
                Ok(Some(_)) => {} // discarded
                Ok(None) => break,
                Err(e) => {
                    if matches!(e.code(), crate::egress::ErrorCode::Cancelled) {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    /// Manually grant the server `additional_bytes` of read budget on
    /// this cursor's request. Useful when the user wants a larger
    /// outstanding window than the per-batch auto-replenishment would
    /// give them, or when initial_credit was 0 but the user changes
    /// their mind mid-stream.
    pub fn add_credit(&mut self, additional_bytes: u64) -> Result<()> {
        self.send_credit_frame(additional_bytes)
    }

    fn send_credit_frame(&mut self, additional_bytes: u64) -> Result<()> {
        let mut payload = Vec::with_capacity(16);
        payload.push(MsgKind::Credit.as_u8());
        payload.extend_from_slice(&self.request_id.to_le_bytes());
        varint::encode_u64(additional_bytes, &mut payload);
        self.reader.transport.write_message(&payload)?;
        self.reader.credit_granted_total =
            self.reader.credit_granted_total.saturating_add(additional_bytes);
        Ok(())
    }

    fn check_rid(&self, got: i64, what: &str) -> Result<()> {
        if got != self.request_id {
            return Err(fmt!(
                ProtocolError,
                "{} request_id {} != cursor {}",
                what,
                got,
                self.request_id
            ));
        }
        Ok(())
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // `cursor_active` is cleared by `next_batch()` on every terminal
        // path (RESULT_END, EXEC_DONE, QUERY_ERROR) and by `cancel()`
        // once it's drained. If it's still set at drop time, this cursor
        // was abandoned mid-stream: query frames are still en route on
        // the WS, and reusing the Reader for a new query would let the
        // next cursor pick them up and trip the request_id check.
        //
        // Tear down the WebSocket so the server stops streaming and
        // releases request-scoped resources. Subsequent operations on
        // this Reader will fail at the transport layer — the user must
        // open a fresh Reader to recover.
        if self.reader.cursor_active {
            self.reader.transport.close_in_place();
            self.reader.cursor_active = false;
        }
    }
}

/// Borrowed view over the most recently decoded batch.
pub struct BatchView<'c> {
    decoded: &'c DecodedBatch,
    dict: &'c SymbolDict,
    schema: &'c Schema,
}

impl<'c> BatchView<'c> {
    pub fn request_id(&self) -> i64 {
        self.decoded.request_id
    }

    pub fn batch_seq(&self) -> u64 {
        self.decoded.batch_seq
    }

    /// Per-batch wire flags from the frame header. Useful for asserting
    /// that compression / Gorilla paths were actually exercised.
    pub fn flags(&self) -> u8 {
        self.decoded.flags
    }

    pub fn schema(&self) -> &'c Schema {
        self.schema
    }

    pub fn row_count(&self) -> usize {
        self.decoded.row_count
    }

    pub fn column_count(&self) -> usize {
        self.decoded.columns.len()
    }

    /// Project a single column to a typed view.
    pub fn column(&self, idx: usize) -> Result<ColumnView<'_>> {
        self.decoded.column_view(idx, self.dict)
    }
}

/// Per the Java reference (`QwpQueryClient.matchesTarget`):
/// `STANDALONE` counts as `PRIMARY` so single-node OSS deployments work
/// with `target=primary`.
fn target_matches(target: Target, role: ServerRole) -> bool {
    match target {
        Target::Any => true,
        Target::Primary => matches!(
            role,
            ServerRole::Primary | ServerRole::PrimaryCatchup | ServerRole::Standalone
        ),
        Target::Replica => matches!(role, ServerRole::Replica),
    }
}

fn map_server_status(
    status: crate::egress::wire::msg_kind::StatusCode,
    message: String,
) -> crate::egress::Error {
    use crate::egress::ErrorCode as C;
    use crate::egress::wire::msg_kind::StatusCode as S;
    let code = match status {
        S::SchemaMismatch => C::ServerSchemaMismatch,
        S::ParseError => C::ServerParseError,
        S::InternalError => C::ServerInternalError,
        S::SecurityError => C::ServerSecurityError,
        S::Cancelled => C::Cancelled,
        S::LimitExceeded => C::ServerLimitExceeded,
    };
    crate::egress::Error::new(code, message)
}
