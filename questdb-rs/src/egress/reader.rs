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
//! Each `Reader` allows at most one in-flight cursor at a time
//! (runtime-checked, not type-encoded). `Cursor::cancel()` issues a
//! CANCEL frame and drains until the terminal frame, leaving the
//! Reader reusable. Dropping a cursor before it has reached a
//! terminal closes the underlying WebSocket: subsequent operations
//! on the Reader fail at the transport layer (open a fresh Reader to
//! recover). Call `Cursor::cancel()` (or read until `next_batch()`
//! returns `None`) before drop if you want to keep the existing
//! connection alive.
//!
//! The `sync-reader-ws` feature gate is applied at the module
//! declaration in `egress/mod.rs`; an inner `#![cfg(...)]` here would
//! duplicate that gate (clippy::duplicated_attributes) without
//! changing what's compiled.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use crate::egress::binds::Bind;
use crate::egress::column::ColumnView;
use crate::egress::column_kind::ColumnKind;
use crate::egress::config::{Endpoint, ReaderConfig, Target};
use crate::egress::decoder::DecodedBatch;
use crate::egress::error::{Error, ErrorCode, Result, fmt};
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
    /// Snapshot of the config used to open this connection. Owned (not
    /// borrowed) because the cursor's failover machinery needs to outlive
    /// the original `from_config` call and reach back into the address
    /// list / failover knobs after the user has dropped their builder.
    ///
    /// Wrapped in [`Arc`] so reconnect attempts share a single
    /// allocation: each attempt would otherwise deep-clone the addr
    /// vec, the path string, and the boxed auth payload — with
    /// `failover_max_attempts` up to `1024`, that's thousands of
    /// allocations per failure event. Reference-count bumps are free
    /// in comparison.
    cfg: Arc<ReaderConfig>,
    /// Index into [`ReaderConfig::addrs`] this connection is bound to.
    /// Updated on mid-query failover so the cursor walks the list in the
    /// right order ("skip the failed one first") on the next failure.
    addr_idx: usize,
    /// Live WS transport. `Option` only so that mid-query failover
    /// can take the dead transport out via [`Option::take`] (releasing
    /// its TCP FD) **before** sleeping on the backoff. Outside of the
    /// brief reconnect window inside [`Reader::reconnect_with_failover`],
    /// this is always `Some`. Use [`Reader::transport`] /
    /// [`Reader::transport_mut`] to access — they assert this invariant.
    transport: Option<WsTransport>,
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
    ///
    /// The initial connect deliberately does **not** apply the failover
    /// backoff schedule — it walks every address once and reports back.
    /// Mid-query failover (via [`Cursor::next_batch`]) is what uses
    /// `failover_backoff_*` to space retries.
    pub fn from_config(cfg: &ReaderConfig) -> Result<Self> {
        // Single deep clone at the API boundary. Every subsequent
        // reconnect attempt — initial walk, mid-query failover, inner
        // replay cycle — shares the same allocation via `Arc::clone`.
        let cfg = Arc::new(cfg.clone());
        let mut last_transport_err: Option<Error> = None;
        let mut last_role_mismatch: Option<Error> = None;
        let mut last_auth_err: Option<Error> = None;

        for idx in 0..cfg.addrs.len() {
            match Self::connect_endpoint(&cfg, idx) {
                Ok(reader) => return Ok(reader),
                Err(e) => match e.code() {
                    // Keep the most-recent (richest) role-mismatch
                    // message; keep walking the address list past it
                    // — another endpoint may match the target.
                    ErrorCode::RoleMismatch => {
                        last_role_mismatch = Some(e);
                    }
                    // AuthError is *usually* a cluster-wide credentials
                    // problem, but not always — heterogeneous clusters
                    // (mixed-version nodes, partial credential rotation)
                    // can have one endpoint reject auth while another
                    // accepts. Walk past it and surface it on exhaustion
                    // only if no later endpoint succeeded.
                    ErrorCode::AuthError => {
                        last_auth_err = Some(e);
                    }
                    // Truly identical-on-every-endpoint failures: bad
                    // connect-string parse, wholly unsupported server
                    // build. No point walking — return immediately.
                    ErrorCode::ConfigError | ErrorCode::UnsupportedServer => {
                        return Err(e);
                    }
                    _ => {
                        last_transport_err = Some(e);
                    }
                },
            }
        }

        // Surface the most diagnostic error we saw. Auth-rejected tells
        // the user *what to fix* (credentials), so it ranks above a
        // role mismatch (which ranks above a generic transport flop).
        if let Some(e) = last_auth_err {
            return Err(e);
        }
        if let Some(e) = last_role_mismatch {
            return Err(e);
        }
        Err(last_transport_err
            .unwrap_or_else(|| fmt!(SocketError, "all {} endpoints unreachable", cfg.addrs.len())))
    }

    /// Open a single endpoint by index. Used by both the initial
    /// connect walk and mid-query failover. On success, the returned
    /// reader has consumed the v2 `SERVER_INFO` (when applicable) and
    /// satisfied the configured `target` role filter. On role
    /// mismatch, a `RoleMismatch` error carrying the observed role is
    /// surfaced (so the failover loop can decide to try the next
    /// endpoint).
    ///
    /// `cfg` is taken as `&Arc<ReaderConfig>` so storing it on the
    /// returned `Reader` is a refcount bump rather than a deep clone
    /// of the addr list / auth payload.
    fn connect_endpoint(cfg: &Arc<ReaderConfig>, idx: usize) -> Result<Self> {
        let transport = WsTransport::connect_to(cfg.as_ref(), idx)?;
        let mut reader = Reader {
            cfg: Arc::clone(cfg),
            addr_idx: idx,
            transport: Some(transport),
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
        if reader.transport_mut()?.server_version() >= 2 {
            reader.consume_server_info()?;
        }
        if !matches!(cfg.target, Target::Any) {
            match reader.server_info.as_ref() {
                None => {
                    return Err(fmt!(
                        RoleMismatch,
                        "endpoint {} negotiated v1 and cannot supply a role for target={:?}",
                        idx,
                        cfg.target
                    ));
                }
                Some(info) if !target_matches(cfg.target, info.role) => {
                    return Err(fmt!(
                        RoleMismatch,
                        "endpoint {} role={:?} cluster={:?} does not match target={:?}",
                        idx,
                        info.role,
                        info.cluster_id,
                        cfg.target
                    ));
                }
                _ => {}
            }
        }
        Ok(reader)
    }

    /// Reconnect this Reader in place after a mid-query transport
    /// failure. Tries the address list rotated to skip the failed
    /// endpoint first (`(failed_idx + 1 + attempt) % N`), with
    /// exponential backoff between attempts. On success, the old
    /// transport has been closed, the new transport + `SERVER_INFO`
    /// are bound, dict / registry are reset to empty, and `addr_idx`
    /// reflects the new endpoint. The caller must re-issue the
    /// `QUERY_REQUEST` with a freshly-allocated `request_id`.
    ///
    /// The `failed_idx` argument is the address index that just
    /// failed — typically the value of `self.addr_idx` immediately
    /// before this call. Pass it explicitly to keep the rotation
    /// independent of where `self.addr_idx` happens to point.
    fn reconnect_with_failover(&mut self, failed_idx: usize) -> Result<u32> {
        // Refcount bump (not a deep clone). The local `cfg` lets us
        // pass `&Arc<ReaderConfig>` to `connect_endpoint` without
        // borrowing `self.cfg` for the lifetime of the loop, which
        // would conflict with `self.transport` mutation below.
        let cfg = Arc::clone(&self.cfg);
        // `cfg.addrs` is non-empty by construction: `from_conf` rejects
        // an empty list, and the `Arc<ReaderConfig>` is private to the
        // Reader (the user can't mutate it post-construction even
        // though `addrs` is `pub` on the struct).
        let n = cfg.addrs.len();
        let attempts_total = cfg.failover_max_attempts.saturating_add(1);
        let mut backoff_ms = cfg.failover_backoff_initial_ms;
        let mut last_err: Option<Error> = None;
        // Track role-mismatch separately. RoleMismatch is "soft" for
        // rotation (we want to keep walking the address list past a
        // mismatched endpoint), but it carries far more diagnostic
        // value than a generic transport error — so on budget
        // exhaustion we prefer to surface a RoleMismatch over a
        // SocketError, even if the LAST attempt happened to be a
        // socket error.
        let mut last_role_mismatch: Option<Error> = None;
        // Drop the dead transport entirely **before** sleeping on the
        // backoff. `Drop for WsTransport` already issues a fire-and-
        // forget WS Close, so the explicit `drop(dead)` is what
        // releases the underlying TCP FD. Without this `take`, every
        // reconnect attempt against a dead cluster would hold the
        // dead FD for the whole
        // `failover_max_attempts × failover_backoff_max_ms` window.
        if let Some(dead) = self.transport.take() {
            drop(dead);
        }
        for attempt in 0..attempts_total {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(backoff_ms));
                backoff_ms = backoff_ms
                    .saturating_mul(2)
                    .min(cfg.failover_backoff_max_ms);
            }
            // Rotate "skip the failed one first": try (failed+1), (failed+2),
            // ... — wrapping past the failed endpoint is fine, the failed
            // endpoint may have come back up by then.
            //
            // Overflow analysis (32-bit usize): `failed_idx < n <= MAX_ADDRS`
            // (1024); `attempt < attempts_total <= MAX_FAILOVER_MAX_ATTEMPTS + 1`
            // (1025). Worst-case sum: 1023 + 1 + 1024 = 2048 — well below
            // `usize::MAX` on every supported target. Both caps are
            // enforced at config-parse time.
            let try_idx = (failed_idx + 1 + attempt as usize) % n;
            match Self::connect_endpoint(&cfg, try_idx) {
                Ok(new_reader) => {
                    // Splice the new connection's state into self,
                    // preserving counters that callers query
                    // (`bytes_received`, `credit_granted_total`,
                    // `read_ns`, `decode_ns`, `next_request_id`).
                    self.transport = new_reader.transport;
                    self.server_info = new_reader.server_info;
                    self.dict = new_reader.dict;
                    self.registry = new_reader.registry;
                    self.addr_idx = try_idx;
                    return Ok(attempt + 1);
                }
                Err(e) => match e.code() {
                    ErrorCode::RoleMismatch => {
                        last_role_mismatch = Some(e);
                    }
                    code if !is_failover_eligible(code) => {
                        // Hard error (auth, config, unsupported server,
                        // etc.). Don't keep bouncing — these will fail
                        // identically on every endpoint.
                        return Err(e);
                    }
                    _ => {
                        last_err = Some(e);
                    }
                },
            }
        }
        Err(last_role_mismatch.or(last_err).unwrap_or_else(|| {
            fmt!(
                SocketError,
                "failover exhausted after {} attempts",
                attempts_total
            )
        }))
    }

    /// The endpoint this connection is currently bound to. Borrowed
    /// from the configured address list, so the borrow lives as long
    /// as `&self`. Stable across connect-string reorderings, unlike
    /// the (deliberately not exposed) underlying address-list index.
    pub fn current_addr(&self) -> &Endpoint {
        &self.cfg.addrs[self.addr_idx]
    }

    /// Mutable access to the live transport. Returns `SocketError`
    /// when the transport is `None`, which happens after a mid-query
    /// failover exhausted its retry budget — the Reader is left in
    /// a "poisoned" state and the user must open a fresh Reader to
    /// recover. Inside `reconnect_with_failover` the transport is
    /// only briefly absent (between dropping the dead one and
    /// splicing in a new one); that path uses `self.transport`
    /// directly and never goes through this accessor.
    fn transport_mut(&mut self) -> Result<&mut WsTransport> {
        self.transport.as_mut().ok_or_else(|| {
            fmt!(
                SocketError,
                "Reader transport is closed after a failed mid-query failover; open a fresh Reader to recover"
            )
        })
    }

    /// Read access to the live transport. See [`Reader::transport_mut`].
    fn transport_ref(&self) -> Result<&WsTransport> {
        self.transport.as_ref().ok_or_else(|| {
            fmt!(
                SocketError,
                "Reader transport is closed after a failed mid-query failover; open a fresh Reader to recover"
            )
        })
    }

    /// Allocate the next `request_id`, skipping `0` and negatives on
    /// wrap. `0` is the server-side sentinel for "no active streaming
    /// request" and must never be used by the client.
    fn alloc_request_id(&mut self) -> i64 {
        let id = self.next_request_id;
        let next = self.next_request_id.wrapping_add(1);
        self.next_request_id = if next <= 0 { 1 } else { next };
        id
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
        let (header, payload) = self.transport_mut()?.read_frame()?;
        self.bytes_received = self
            .bytes_received
            .saturating_add(HEADER_LEN as u64 + header.payload_length as u64);
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

    /// Negotiated QWP version this connection is using. Returns
    /// `SocketError` when the Reader is poisoned after a failed
    /// mid-query failover.
    pub fn server_version(&self) -> Result<u8> {
        Ok(self.transport_ref()?.server_version())
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
    /// borrows the reader; only one in-flight cursor at a time.
    pub fn query<S: Into<String>>(&mut self, sql: S) -> ReaderQuery<'_> {
        ReaderQuery {
            reader: self,
            builder: QueryRequest::builder(sql),
            error: None,
            on_failover_reset: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Query builder
// ---------------------------------------------------------------------------

/// Notification delivered to the [`ReaderQuery::on_failover_reset`]
/// callback right before replayed batches start arriving on a new
/// connection. Mirrors the Java `onFailoverReset(newNode)` contract:
/// the user-side handler is responsible for discarding any rows it
/// had accumulated from the previous (now-dead) connection, since the
/// query restarts from `batch_seq=0` against the new endpoint.
///
/// Marked `#[non_exhaustive]` so we can add fields without breaking
/// downstream pattern matches.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FailoverEvent {
    /// Endpoint that just failed. Use `failed_addr.host` /
    /// `failed_addr.port` directly; the [`Endpoint`] struct replaces
    /// the older `(String, u16)` tuple.
    ///
    /// The address-list index is deliberately not exposed: indices
    /// are brittle if the connect string is reordered between runs,
    /// and the endpoint host/port is stable.
    pub failed_addr: Endpoint,
    /// Endpoint of the new connection.
    pub new_addr: Endpoint,
    /// `SERVER_INFO` of the new endpoint (`None` for v1 servers).
    pub new_server_info: Option<ServerInfo>,
    /// Newly-allocated `request_id` the cursor will receive frames for
    /// from now on. Different from `Cursor::request_id` *before* the
    /// failover.
    pub new_request_id: i64,
    /// Cumulative count of reconnect attempts the failover machinery
    /// burned before this success — summed across every internal
    /// replay cycle. `1` means the first reconnect attempt succeeded
    /// and its replay write went through cleanly. Larger values mean
    /// either earlier reconnects in this same cycle missed (rotating
    /// through endpoints), or a prior cycle reconnected but its
    /// replay write race-failed and we reconnected again. Pairs with
    /// [`elapsed`](Self::elapsed) — both are cumulative measures of
    /// the same failover event.
    pub attempts: u32,
    /// The error that triggered this failover (the failure of the
    /// previous connection). The full error — code + message — is
    /// preserved so callers can both route on the [`ErrorCode`] (for
    /// metrics / categorization) and log the raw message (for
    /// diagnostics: `errno` text on `SocketError`, peer info on
    /// `TlsError`, decode-site detail on `ProtocolError`, etc.). Use
    /// [`Error::code`] to extract just the category.
    ///
    /// Without this, the cause-of-death of the previous connection is
    /// lost forever once failover succeeds — it's not re-surfaced as
    /// `Err` anywhere else in the cursor's API.
    pub trigger: Error,
    /// Wall-clock time spent reconnecting (sleep + dial + handshake +
    /// SERVER_INFO read). Excludes the time from the cursor's last
    /// successful read until the failure was observed.
    pub elapsed: std::time::Duration,
}

/// Boxed user callback type for failover-reset notifications.
type FailoverResetCallback<'r> = Box<dyn FnMut(&FailoverEvent) + 'r>;

/// Borrows a `Reader` exclusively while the query is being constructed and
/// (eventually) the cursor is live.
pub struct ReaderQuery<'r> {
    reader: &'r mut Reader,
    builder: QueryRequestBuilder,
    /// First fatal error (if any) deferred until `execute`, so the fluent
    /// chain stays clean.
    error: Option<crate::egress::Error>,
    /// Optional handler called every time the cursor reconnects after a
    /// transport-level failure (see [`FailoverEvent`]).
    on_failover_reset: Option<FailoverResetCallback<'r>>,
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

    /// Install a callback fired every time the cursor's underlying
    /// connection is replaced via mid-query failover. The closure
    /// receives a [`FailoverEvent`] describing the new endpoint and
    /// runs *before* any replayed `RESULT_BATCH` arrives — the
    /// user-side handler must use this signal to discard rows it had
    /// accumulated from the previous (now-dead) connection. The query
    /// restarts from `batch_seq=0` against the new endpoint with a
    /// fresh `request_id`.
    ///
    /// Calling this method twice on the same `ReaderQuery` **replaces**
    /// the previous closure — only the most recent callback is invoked.
    ///
    /// Mirrors the Java client's `onFailoverReset(newNode)` contract.
    ///
    /// ```no_run
    /// use std::sync::{Arc, Mutex};
    /// use questdb::egress::{FailoverEvent, Reader};
    ///
    /// # fn ex() -> questdb::egress::Result<()> {
    /// let mut reader = Reader::from_conf(
    ///     "qwp::addr=db-a:9000,db-b:9000;target=primary",
    /// )?;
    /// // The handler accumulates rows in a buffer shared with the
    /// // callback. On failover the callback discards what was buffered
    /// // — the replayed query restarts at `batch_seq=0` against the
    /// // new endpoint, so anything already pushed would otherwise
    /// // double up.
    /// let rows: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    /// let rows_for_cb = Arc::clone(&rows);
    /// let mut cursor = reader
    ///     .query("select x from t order by ts")
    ///     .on_failover_reset(move |ev: &FailoverEvent| {
    ///         eprintln!(
    ///             "failover: {} → {} after {} attempt(s) ({:?}, trigger={:?}: {})",
    ///             ev.failed_addr, ev.new_addr,
    ///             ev.attempts, ev.elapsed,
    ///             ev.trigger.code(), ev.trigger.msg(),
    ///         );
    ///         rows_for_cb.lock().unwrap().clear();
    ///     })
    ///     .execute()?;
    /// while let Some(_batch) = cursor.next_batch()? {
    ///     // ... project `_batch` into `rows.lock().unwrap()` ...
    /// }
    /// # let _ = rows; Ok(())
    /// # }
    /// ```
    pub fn on_failover_reset<F>(mut self, callback: F) -> Self
    where
        F: FnMut(&FailoverEvent) + 'r,
    {
        self.on_failover_reset = Some(Box::new(callback));
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
                "another cursor is already in flight on this connection (only one cursor at a time per Reader)"
            ));
        }
        let request_id = self.reader.alloc_request_id();
        let req = self.builder.request_id(request_id).build()?;
        let credit_enabled = req.initial_credit() > 0;
        // Encode the QUERY_REQUEST once and stash the bytes on the
        // cursor. Mid-query failover replays the query by patching
        // the 8-byte `request_id` span in place and writing the same
        // buffer again — no builder clone, no bind clone, no
        // re-encode. The wire layout is:
        //   [0]   MsgKind::QueryRequest (1 byte)
        //   [1..9] request_id (i64 LE, 8 bytes)
        //   [9..]  varint sql_len, sql, varint initial_credit,
        //          varint binds_len, encoded binds...
        // Encoding can fail (e.g. an unsupported bind kind) — that
        // failure surfaces here and the cursor never starts.
        let mut encoded_request = Vec::with_capacity(64);
        req.encode(&mut encoded_request)?;
        // Layout invariant guard, runtime-checked in release too: the
        // failover-replay path patches `[REQUEST_ID_OFFSET..+8]` of
        // this buffer with a fresh request_id on every reconnect. If
        // `QueryRequest::encode` ever changes the prefix (adds a
        // length header, version byte, different MsgKind), patching
        // the wrong offset would silently corrupt every replayed
        // request — and the corruption surfaces as a `ProtocolError`
        // which is itself failover-eligible, so the cursor would
        // burn its retry budget bouncing through the cluster with
        // bad bytes. Fail loudly at execute() time instead.
        if encoded_request.len() < REQUEST_ID_OFFSET + 8
            || encoded_request[0] != MsgKind::QueryRequest.as_u8()
        {
            return Err(fmt!(
                ProtocolError,
                "QUERY_REQUEST encoding layout invariant violated (len={}, first={:?})",
                encoded_request.len(),
                encoded_request.first().copied(),
            ));
        }
        debug_assert_eq!(
            i64::from_le_bytes(
                encoded_request[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]
                    .try_into()
                    .expect("length checked above"),
            ),
            request_id,
            "request_id at byte offset {} doesn't match the value just encoded",
            REQUEST_ID_OFFSET,
        );
        self.reader
            .transport_mut()?
            .write_message(&encoded_request)?;

        self.reader.cursor_active = true;
        Ok(Cursor {
            reader: self.reader,
            request_id,
            last_batch: None,
            terminal: None,
            credit_enabled,
            cancelling: false,
            done: false,
            encoded_request,
            on_failover_reset: self.on_failover_reset,
            failover_resets: 0,
        })
    }
}

/// Byte offset of the `request_id` field inside the encoded
/// `QUERY_REQUEST` payload produced by [`QueryRequest::encode`].
/// The 8-byte little-endian id occupies `[REQUEST_ID_OFFSET..
/// REQUEST_ID_OFFSET + 8]`. Used by [`Cursor::failover_reconnect_and_replay`]
/// to patch the request_id on a stashed buffer instead of re-cloning
/// and re-encoding the entire builder + binds.
const REQUEST_ID_OFFSET: usize = 1;

/// Bounded read timeout applied to the underlying TCP stream for the
/// duration of [`Cursor::cancel`]'s post-CANCEL drain.
///
/// Without this, a stuck-but-not-RST'd peer that stops sending bytes
/// after we deliver the CANCEL frame would block the drain
/// indefinitely. The drain consumes whatever batches the server
/// already had in flight plus the terminal QUERY_ERROR; under healthy
/// operation each frame arrives within milliseconds. 30 s is far past
/// any realistic batch transit and short enough that an unresponsive
/// peer surfaces a clear error rather than appearing to hang.
const CANCEL_DRAIN_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    /// Pre-encoded `QUERY_REQUEST` payload from `execute()`, stashed
    /// so the cursor can resend the same query on a fresh connection
    /// after mid-query failover. The 8-byte `request_id` lives at
    /// `[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]`; replay just
    /// overwrites that span with a freshly-allocated id and writes
    /// the buffer verbatim. Avoids deep-cloning the builder + binds
    /// (potentially multi-MB `Bind::Binary` / `Bind::Varchar`
    /// payloads) on every reconnect.
    encoded_request: Vec<u8>,
    /// User callback fired right before replayed batches arrive on a
    /// new connection. See [`ReaderQuery::on_failover_reset`].
    on_failover_reset: Option<FailoverResetCallback<'r>>,
    /// Number of successful failover resets observed by this cursor
    /// since `execute()`. Useful for tests and for asserting the
    /// query did not silently restart under the user's feet.
    failover_resets: u32,
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
    ///
    /// On a transport-level failure (socket close, TLS error, WS
    /// framing error), the cursor will silently reconnect to the
    /// next address in the configured list (with exponential backoff
    /// and a bounded retry budget — see `failover_*` config keys),
    /// replay the `QUERY_REQUEST` with a fresh `request_id`, and
    /// resume from `batch_seq=0` on the new connection. The user-
    /// side handler is notified before any replayed batches arrive
    /// via the [`ReaderQuery::on_failover_reset`] callback. If
    /// failover is disabled (`failover=off`) or the retry budget is
    /// exhausted, the failure is surfaced as the underlying error.
    /// Decode errors (malformed payload, schema-ref miss, zstd
    /// corruption) are NOT routed through failover — they bubble up
    /// immediately and terminate the cursor, since reconnecting
    /// won't fix a wire-state bug.
    ///
    /// **Blocking time during failover.** When failover is engaged,
    /// this method blocks the calling thread for the duration of the
    /// reconnect cycle: each attempt sleeps the configured backoff
    /// (capped by `failover_backoff_max_ms`), then dials, handshakes,
    /// and reads `SERVER_INFO` against the next endpoint. The
    /// worst-case wall-clock blocking time is approximately
    /// `2 × failover_max_attempts × failover_backoff_max_ms` plus
    /// per-attempt connect+handshake overhead — with the parse-time
    /// caps that's up to ~2 hours. There is no per-call timeout, no
    /// AtomicBool cancel hook, and no progress callback today; if
    /// you need bounded latency, set `failover_max_attempts` and
    /// `failover_backoff_max_ms` to values appropriate for your SLA,
    /// or set `failover=off` and handle reconnect at the
    /// application layer.
    pub fn next_batch(&mut self) -> Result<Option<BatchView<'_>>> {
        if self.done {
            return Ok(None);
        }
        loop {
            // Transport read: a failure here (socket closed, TLS
            // reset, truncated WS frame) is what failover is for.
            let (header, payload) = match self.read_frame_raw() {
                Ok(hp) => hp,
                Err(e) => {
                    if self.cancelling
                        || !self.reader.cfg.failover
                        || !is_failover_eligible(e.code())
                    {
                        // Match every other terminal path in this loop:
                        // tear down the WS so the cursor's flags stay
                        // coherent with the transport state, no half-cooked
                        // cursors that defer cleanup to `Reader::Drop`.
                        self.terminate_with_close();
                        return Err(e);
                    }
                    self.failover_reconnect_and_replay(e)?;
                    continue;
                }
            };
            // Capture wire size BEFORE the decode consumes the header.
            let wire_bytes = HEADER_LEN as u64 + header.payload_length as u64;
            // Decode is **not** failover-eligible. Anything that comes
            // out as an error here (bad varint, unknown discriminant,
            // schema-ref miss, symbol-dict miss, zstd corruption) is
            // a wire/state bug that won't be fixed by reconnecting —
            // and silently retrying would mask it from the user. Bubble
            // it up as a hard failure with the cursor terminated.
            let t1 = std::time::Instant::now();
            let decode_result = decode_frame(
                header,
                &payload,
                &mut self.reader.dict,
                &mut self.reader.registry,
            );
            // Account for decode time on both arms — the error path is
            // rare and terminal, but skipping the sample makes the
            // metric subtly biased toward "successful decodes are slow."
            self.reader.decode_ns = self
                .reader
                .decode_ns
                .saturating_add(t1.elapsed().as_nanos());
            let event = match decode_result {
                Ok(ev) => ev,
                Err(e) => {
                    // Tear the WS down: the server is still streaming
                    // RESULT_BATCH frames for this `request_id`, and
                    // leaving the transport open would let a subsequent
                    // `Reader::query()` on this Reader read those stale
                    // frames and trip the cursor's `request_id` check.
                    self.terminate_with_close();
                    return Err(e);
                }
            };
            match event {
                ServerEvent::Batch(b) => {
                    if b.request_id != self.request_id {
                        let err = fmt!(
                            ProtocolError,
                            "RESULT_BATCH request_id {} != cursor {}",
                            b.request_id,
                            self.request_id
                        );
                        // Stale-rid frames mean the server is still
                        // streaming for an old request — keep reading
                        // would only deepen the corruption.
                        self.terminate_with_close();
                        return Err(err);
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
                    if self.credit_enabled
                        && !self.cancelling
                        && let Err(e) = self.send_credit_frame(wire_bytes)
                    {
                        // A failed credit write means the transport
                        // just died. Surface it as a hard cursor
                        // failure rather than leaving the cursor
                        // "active" (which would let the next
                        // `next_batch` call silently failover and
                        // mask the credit-write error from the user).
                        self.terminate_with_close();
                        return Err(e);
                    }
                    let schema_id = b.schema_id;
                    if self.reader.registry.get(schema_id).is_none() {
                        let err = fmt!(
                            ProtocolError,
                            "RESULT_BATCH references schema {} not in registry",
                            schema_id
                        );
                        self.terminate_with_close();
                        return Err(err);
                    }
                    self.last_batch = Some(b);
                    let last = self.last_batch.as_ref().unwrap();
                    // Re-lookup is infallible: existence was checked
                    // above and the registry isn't mutated in between.
                    let schema = self.reader.registry.get(schema_id).expect("schema present");
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
                    if let Err(e) = self.check_rid(request_id, "RESULT_END") {
                        self.terminate_with_close();
                        return Err(e);
                    }
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
                    if let Err(e) = self.check_rid(request_id, "EXEC_DONE") {
                        self.terminate_with_close();
                        return Err(e);
                    }
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
                    if let Err(e) = self.check_rid(request_id, "QUERY_ERROR") {
                        self.terminate_with_close();
                        return Err(e);
                    }
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

    /// Number of successful failover reconnects this cursor has
    /// observed since `execute()`. Useful for tests asserting the
    /// query did or did not silently restart.
    pub fn failover_resets(&self) -> u32 {
        self.failover_resets
    }

    /// The endpoint the cursor's underlying connection is currently
    /// bound to. While the cursor is live the `Reader` is mutably
    /// borrowed, so [`Reader::current_addr`] is unreachable from
    /// user code — this is the in-cursor accessor for "which
    /// endpoint did the last batch come from?". After mid-query
    /// failover, this reflects the new endpoint (matching the
    /// `new_addr` from the most recent
    /// [`FailoverEvent`](crate::egress::FailoverEvent)).
    pub fn current_addr(&self) -> &Endpoint {
        self.reader.current_addr()
    }

    /// Read one raw frame (header + payload) off the transport, with
    /// no decode. Errors here are transport-level (socket closed,
    /// truncated WS frame, TLS reset, etc.) and are the only failures
    /// that should drive failover. Decoding is deliberately NOT done
    /// here — the caller decides whether decode failures bubble up as
    /// hard errors or get routed through reconnect.
    fn read_frame_raw(
        &mut self,
    ) -> Result<(crate::egress::wire::header::FrameHeader, bytes::Bytes)> {
        let t0 = std::time::Instant::now();
        let (header, payload) = self.reader.transport_mut()?.read_frame()?;
        self.reader.read_ns = self.reader.read_ns.saturating_add(t0.elapsed().as_nanos());
        let wire_bytes = HEADER_LEN as u64 + header.payload_length as u64;
        self.reader.bytes_received = self.reader.bytes_received.saturating_add(wire_bytes);
        Ok((header, payload))
    }

    /// Mid-query failover: the underlying connection just died with
    /// `trigger`. Walk the address list (skipping the failed endpoint
    /// first), with exponential backoff, until a fresh connection is
    /// established; then reset the cursor for replay (new
    /// `request_id`, cleared `last_batch`), re-encode the original
    /// `QUERY_REQUEST`, and notify the user-side handler so it can
    /// discard accumulated rows. On exhausted budget or hard error,
    /// the cursor is marked terminal and the failure is propagated.
    fn failover_reconnect_and_replay(&mut self, mut trigger: Error) -> Result<()> {
        // Maximum number of (reconnect → replay-write) cycles to attempt
        // for a single in-flight failover event. Each cycle has its own
        // [`Reader::reconnect_with_failover`] budget; this outer cap
        // exists only to bound the rare case where every reconnect
        // succeeds but the immediate `write_message` fails (a TCP RST
        // racing between `accept` and the first write). One retry is
        // enough to absorb a transient race; more would just compound
        // the budget without helping a genuinely-broken endpoint.
        const MAX_REPLAY_CYCLES: u32 = 2;

        let started = std::time::Instant::now();
        let mut cycles_remaining = MAX_REPLAY_CYCLES;
        // Cumulative reconnect-attempt count across every replay cycle.
        // `reconnect_with_failover` returns a per-cycle count; if cycle 1
        // reconnects then its replay write fails, cycle 2's count alone
        // wouldn't capture cycle 1's budget burn. `FailoverEvent.elapsed`
        // is already cumulative (`started` is captured once outside the
        // loop), so `attempts` must be too — otherwise the user sees
        // "1 attempt took 5 seconds" when the truth is "1 attempt + 1
        // attempt + a write fail in between took 5 seconds."
        let mut total_attempts: u32 = 0;
        loop {
            cycles_remaining -= 1;
            let failed_idx = self.reader.addr_idx;
            // Snapshot the failing endpoint before reconnect mutates
            // `addr_idx` — `FailoverEvent` reports it back to the user.
            let failed_addr = self.reader.cfg.addrs[failed_idx].clone();
            let cycle_attempts = match self.reader.reconnect_with_failover(failed_idx) {
                Ok(n) => n,
                Err(e) => {
                    self.reader.cursor_active = false;
                    self.done = true;
                    // Surface the most diagnostic error. The original
                    // `trigger` is almost always a generic transport
                    // failure (socket close, decode error). Anything
                    // specific the reconnect saw — auth rejected, role
                    // mismatched on every endpoint, config-level issue —
                    // tells the user *what to fix* and should win over
                    // the original cause-of-death.
                    return Err(if prefer_over_trigger(e.code()) {
                        e
                    } else {
                        trigger
                    });
                }
            };
            total_attempts = total_attempts.saturating_add(cycle_attempts);
            // Reset connection-scoped state. The new connection has its
            // own (empty) dict + registry already (set up by
            // `connect_endpoint`). Drop any in-flight batch buffer so we
            // don't accidentally surface a stale view.
            self.last_batch = None;
            // Allocate a fresh request_id and re-issue the same
            // QUERY_REQUEST bytes. The cursor stashed the encoded
            // payload at `execute()` time; here we patch the 8-byte
            // request_id span in place and write the buffer
            // verbatim. No builder clone, no Bind clone, no
            // re-encode — the only allocation is the WS framing copy
            // inside `write_message`. With `failover_max_attempts`
            // up to `1024` and queries that may carry multi-MB
            // `Bind::Binary` payloads, this is the difference
            // between a few bytes and gigabytes of churn per
            // failure event.
            let new_rid = self.reader.alloc_request_id();
            self.request_id = new_rid;
            self.encoded_request[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]
                .copy_from_slice(&new_rid.to_le_bytes());
            let write_result = self
                .reader
                .transport_mut()
                .and_then(|t| t.write_message(&self.encoded_request));
            match write_result {
                Ok(()) => {
                    self.failover_resets = self.failover_resets.saturating_add(1);
                    if let Some(cb) = self.on_failover_reset.as_mut() {
                        let event = FailoverEvent {
                            failed_addr,
                            new_addr: self.reader.cfg.addrs[self.reader.addr_idx].clone(),
                            new_server_info: self.reader.server_info.clone(),
                            new_request_id: new_rid,
                            attempts: total_attempts,
                            trigger: trigger.clone(),
                            elapsed: started.elapsed(),
                        };
                        cb(&event);
                    }
                    return Ok(());
                }
                Err(e) => {
                    // Write (or build/encode) failed on the
                    // freshly-connected socket. Covers a TCP RST
                    // landing between `accept` and our first write.
                    // Treat it as the next failover trigger and start
                    // another cycle — provided the failure is
                    // transport-flavoured and we haven't already used
                    // our replay budget.
                    if cycles_remaining == 0 || !is_failover_eligible(e.code()) {
                        // Tear down the new transport: no
                        // QUERY_REQUEST was sent, so the server is
                        // sitting idle waiting for one. Letting it
                        // linger until `Reader` drops would hold the
                        // FD and leave the server's per-connection
                        // resources allocated longer than necessary.
                        // Once `cursor_active=false`, `Drop for Cursor`
                        // skips its `close_in_place`, so this is the
                        // last chance to close the WS cleanly. Take
                        // the transport out (instead of
                        // `close_in_place` + leaving the corpse
                        // behind) so the FD is released here rather
                        // than at the eventual Reader drop.
                        if let Some(dead) = self.reader.transport.take() {
                            drop(dead);
                        }
                        self.reader.cursor_active = false;
                        self.done = true;
                        return Err(e);
                    }
                    trigger = e;
                }
            }
        }
    }

    /// Send a CANCEL frame and drain until the server emits a terminal
    /// frame for this request.
    ///
    /// Blocking, but bounded. The CANCEL write inherits the transport's
    /// `WRITE_TIMEOUT`; the post-CANCEL drain runs with a TCP read
    /// timeout of [`CANCEL_DRAIN_READ_TIMEOUT`] installed for the
    /// duration of the loop, so a stuck-but-not-RST'd peer surfaces as
    /// a `SocketError` rather than hanging the calling thread. If the
    /// CANCEL write itself fails, the transport is torn down before
    /// the error is returned so the cursor's flags and the underlying
    /// connection state are left coherent.
    pub fn cancel(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        // Record the user's intent to cancel BEFORE attempting any
        // network write. If the CANCEL write (or the credit-nudge
        // write) fails because the transport just died, a subsequent
        // `next_batch` MUST NOT failover-replay the query — the user
        // explicitly asked to cancel it. The failover guard in
        // `next_batch` is keyed on `self.cancelling`; setting it after
        // the writes leaves a window where a failed write returns
        // `Err` with `cancelling=false`, and the next `next_batch`
        // call would silently reconnect to another endpoint and run
        // the query the user just cancelled.
        //
        // Side benefit (which used to be the only purpose of setting
        // this flag): from this point on the cursor stops topping up
        // the server's credit window, so the remaining budget bleeds
        // off and the server stops generating new batches behind the
        // cancel.
        self.cancelling = true;
        let mut payload = Vec::with_capacity(9);
        payload.push(MsgKind::Cancel.as_u8());
        payload.extend_from_slice(&self.request_id.to_le_bytes());

        // Capture the CANCEL write error explicitly: a `?` here would
        // leave `cancelling=true, done=false, transport=Some(broken)`,
        // and the half-broken transport would only be cleaned up when
        // `Reader::Drop` ran. Tearing it down here keeps the cursor's
        // flags and the transport in lockstep with the other terminal
        // paths in `next_batch`.
        let write_outcome = match self.reader.transport_mut() {
            Ok(t) => t.write_message(&payload),
            Err(e) => Err(e),
        };
        if let Err(e) = write_outcome {
            self.terminate_with_close();
            return Err(e);
        }
        // Wake the server in case it's already credit-suspended. The
        // server's `handleCancel` only sets a flag; the cancel takes
        // effect when `streamResults` is next re-entered, which on a
        // credit-suspended stream happens only via `handleCredit`. A
        // 1-byte top-up is enough — `streamResults` checks the cancel
        // flag before the credit check, so the abort path fires
        // immediately and emits the terminal QUERY_ERROR. Without this
        // nudge a `cancel()` against a credit-suspended server would
        // deadlock.
        // Best-effort: the CANCEL frame has already been accepted by
        // the server, so reporting the credit-nudge failure as the
        // user-visible result of `cancel()` would mislead — the user
        // would see "cancel failed" while the cancellation is in
        // fact under way. If the nudge write fails (transport just
        // died) the drain loop below will pick up the same transport
        // failure and either route through failover or terminate the
        // cursor (depending on `cancelling`, which we already set).
        // If the nudge succeeds the drain proceeds normally. Either
        // way, swallowing the error here gives the user the truthful
        // signal: the cancellation request was delivered.
        if self.credit_enabled {
            let _ = self.send_credit_frame(1);
        }

        // Bound the drain reads. tungstenite's `read()` is otherwise a
        // pure blocking syscall; only the TCP-level timeout can
        // interrupt it on a stuck peer. The credit-nudge write above
        // may have torn the transport down (best-effort `let _ =`),
        // so guard against `transport == None`.
        if let Some(t) = self.reader.transport.as_mut() {
            t.set_read_timeout(Some(CANCEL_DRAIN_READ_TIMEOUT));
        }

        // Drain until any terminal frame (RESULT_END / EXEC_DONE /
        // QUERY_ERROR including STATUS_CANCELLED) — swallow batches
        // between CANCEL and the server's acknowledgement. `done` is
        // the right guard here, not `terminal`: an error terminal
        // sets `done` but leaves `terminal` as `None`.
        let mut drain_result: Result<()> = Ok(());
        while !self.done {
            match self.next_batch() {
                Ok(Some(_)) => {} // discarded
                Ok(None) => break,
                Err(e) => {
                    if matches!(e.code(), crate::egress::ErrorCode::Cancelled) {
                        break;
                    }
                    drain_result = Err(e);
                    break;
                }
            }
        }

        // Restore the default (no-op) read timeout. If `next_batch`
        // hit a non-cancelled error, it has already called
        // `terminate_with_close` and the transport is `None`; nothing
        // to restore.
        if let Some(t) = self.reader.transport.as_mut() {
            t.set_read_timeout(None);
        }

        drain_result
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
        self.reader.transport_mut()?.write_message(&payload)?;
        self.reader.credit_granted_total = self
            .reader
            .credit_granted_total
            .saturating_add(additional_bytes);
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

    /// Mark the cursor terminal and tear down the underlying WS
    /// transport. Used on every irrecoverable post-read error path in
    /// `next_batch` so the cursor's `cursor_active` / `done` flags
    /// and the transport are always left coherent — no half-cooked
    /// cursors that rely on `Drop` to clean up, and no stale frames
    /// left buffered for a follow-up `Reader::query()` to pick up.
    fn terminate_with_close(&mut self) {
        if let Some(t) = self.reader.transport.as_mut() {
            t.close_in_place();
        }
        self.reader.cursor_active = false;
        self.done = true;
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
            // Defensive: while the cursor invariant says transport is
            // `Some` whenever `cursor_active` is true (the failover
            // paths clear `cursor_active` whenever they leave the
            // transport `None`), `Drop` should never panic.
            if let Some(t) = self.reader.transport.as_mut() {
                t.close_in_place();
            }
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

/// Predicate for the failover trigger filter. Mirrors the Java
/// reference's "transport-level terminal failure" classification: any
/// failure that's plausibly fixable by reconnecting to a different
/// endpoint, but not failures that signal a hard problem (auth, bad
/// SQL, malformed binds, role-mismatch on a single-node config) which
/// would just bounce off every endpoint identically.
fn is_failover_eligible(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::SocketError
            | ErrorCode::HandshakeError
            | ErrorCode::TlsError
            | ErrorCode::ProtocolError
            | ErrorCode::CouldNotResolveAddr
            // RoleMismatch is "soft" for failover purposes: we just
            // skip this endpoint and try the next one (counting against
            // the budget). The eventual surfaced error is RoleMismatch
            // if the budget exhausts entirely on mismatching nodes.
            | ErrorCode::RoleMismatch
    )
}

/// Errors that carry more diagnostic value than a generic transport
/// `trigger` (the cause-of-death of the previous connection). When the
/// failover loop surfaces one of these, the user should see *that*,
/// not the original socket close — these tell the user *what to fix*
/// (credentials, cluster topology, server version, config, TLS / WS
/// handshake), whereas the trigger just says "the network broke at
/// some point."
///
/// `HandshakeError` and `TlsError` are preferred for the same reason
/// as `AuthError`: when every reachable endpoint rejects the WS
/// upgrade or fails certificate validation, the original
/// `SocketError` trigger ("connection dropped") is far less
/// actionable than the handshake/cert message that actually names
/// the problem.
fn prefer_over_trigger(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::AuthError
            | ErrorCode::RoleMismatch
            | ErrorCode::ConfigError
            | ErrorCode::UnsupportedServer
            | ErrorCode::HandshakeError
            | ErrorCode::TlsError
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Anchors `REQUEST_ID_OFFSET` to the actual `QueryRequest::encode`
    /// output. The failover-replay path in `Cursor::failover_reconnect_and_replay`
    /// patches `[REQUEST_ID_OFFSET..+8]` of the stashed encoded request
    /// to substitute a fresh request_id; if `encode` ever grows a prefix,
    /// the constant must move with it. This test fails red on any layout
    /// drift before the runtime guard in `execute()` would.
    #[test]
    fn request_id_offset_matches_encoder_layout() {
        const RID: i64 = 0x0123_4567_89AB_CDEF;
        let req = QueryRequest::builder("SELECT 1")
            .request_id(RID)
            .build()
            .expect("build");
        let mut buf = Vec::new();
        req.encode(&mut buf).expect("encode");

        assert!(buf.len() >= REQUEST_ID_OFFSET + 8);
        assert_eq!(buf[0], MsgKind::QueryRequest.as_u8());
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&buf[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]);
        assert_eq!(i64::from_le_bytes(id_bytes), RID);
    }

    /// Exhaustively pin `is_failover_eligible` against every
    /// `ErrorCode` variant. The function is a single `matches!` arm
    /// today; this guards against (a) silently dropping an arm
    /// during a refactor, (b) accidentally promoting a hard error
    /// (auth, config) into the eligible set, which would make the
    /// failover loop bounce off identical-failure endpoints. Adding
    /// a new `ErrorCode` variant later forces this test to be
    /// updated — that's the point.
    #[test]
    fn is_failover_eligible_matrix() {
        use ErrorCode::*;
        // Eligible: every transport-level failure that may differ
        // between endpoints, plus RoleMismatch (soft skip).
        for code in [
            SocketError,
            HandshakeError,
            TlsError,
            ProtocolError,
            CouldNotResolveAddr,
            RoleMismatch,
        ] {
            assert!(
                is_failover_eligible(code),
                "{:?} must be failover-eligible",
                code
            );
        }
        // Not eligible: failures that signal a hard problem
        // (credentials, config, server build) which would fail
        // identically on every endpoint, OR are client-side
        // validation errors / server-reported terminals that aren't
        // about transport.
        for code in [
            ConfigError,
            InvalidApiCall,
            AuthError,
            UnsupportedServer,
            InvalidUtf8,
            InvalidBind,
            InvalidTimestamp,
            InvalidDecimal,
            ServerSchemaMismatch,
            ServerParseError,
            ServerInternalError,
            ServerSecurityError,
            LimitExceeded,
            ServerLimitExceeded,
            Cancelled,
        ] {
            assert!(
                !is_failover_eligible(code),
                "{:?} must NOT be failover-eligible",
                code
            );
        }
    }

    /// Pin `prefer_over_trigger`: the failover loop surfaces these
    /// codes in place of the original transport `trigger` because
    /// they tell the user *what to fix* (credentials, topology,
    /// server build, config). Bouncing through the matrix locks the
    /// predicate so a refactor that drops `UnsupportedServer` or
    /// `ConfigError` from the preferred set goes red.
    #[test]
    fn prefer_over_trigger_matrix() {
        use ErrorCode::*;
        for code in [
            AuthError,
            RoleMismatch,
            ConfigError,
            UnsupportedServer,
            HandshakeError,
            TlsError,
        ] {
            assert!(
                prefer_over_trigger(code),
                "{:?} must be preferred over the trigger",
                code
            );
        }
        // Generic transport flops, decode failures, and client-side
        // validation errors are NOT more diagnostic than the trigger
        // — keep the original cause-of-death in those cases.
        for code in [
            SocketError,
            ProtocolError,
            CouldNotResolveAddr,
            InvalidApiCall,
            InvalidUtf8,
            InvalidBind,
            ServerInternalError,
            Cancelled,
        ] {
            assert!(
                !prefer_over_trigger(code),
                "{:?} must NOT be preferred over the trigger",
                code
            );
        }
    }
}
