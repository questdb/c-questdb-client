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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Bytes, BytesMut};

use crate::egress::binds::{Bind, SimpleNullKind};
use crate::egress::column::ColumnView;
use crate::egress::config::{Endpoint, ReaderConfig, Target};
use crate::egress::decoder::DecodedBatch;
use crate::egress::decoder::ZstdScratch;
use crate::egress::error::{Error, ErrorCode, Result, UpgradeReject, fmt};
use crate::egress::query_request::{QueryRequest, QueryRequestBuilder, REQUEST_ID_OFFSET};
use crate::egress::schema::Schema;
use crate::egress::server_event::{ServerEvent, ServerInfo, ServerRole, decode_frame};
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::tracker::HostHealthTracker;
use crate::egress::transport::{CLOSE_TIMEOUT, WRITE_TIMEOUT, WsTransport};
use crate::egress::wire::header::HEADER_LEN;
use crate::egress::wire::msg_kind::MsgKind;
use crate::egress::wire::varint;

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Diagnostic counters shared between a [`Reader`] and its FFI handle.
///
/// Held by the Reader via [`Arc`] so the FFI surface can clone it once
/// at handle-construction time and serve stat reads thereafter without
/// touching the `UnsafeCell<Reader>` that holds the Reader. That
/// decouples counter reads from the Reader's borrow stack: a stat
/// getter no longer synthesises a `&Reader` while a laundered
/// `&mut Reader` (held by an in-flight `ReaderQuery` / `Cursor`) is
/// still on the stack — eliminating the aliasing question entirely.
///
/// All four counters are `Relaxed` — pure counters with no associated
/// happens-before requirement.
#[derive(Debug, Default)]
pub struct ReaderStats {
    /// Total wire bytes (frame header + payload) read off the
    /// transport since this connection was opened.
    pub bytes_received: AtomicU64,
    /// Total bytes granted to the server via CREDIT (`0x15`) frames
    /// since this connection was opened.
    pub credit_granted_total: AtomicU64,
    /// Nanoseconds spent in `transport.read_frame()` since this
    /// connection was opened. Saturates at `u64::MAX`.
    pub read_ns: AtomicU64,
    /// Nanoseconds spent in `decode_frame()` since this connection
    /// was opened. Saturates at `u64::MAX`.
    pub decode_ns: AtomicU64,
}

/// Per-connection reader. Owns the WebSocket transport and the
/// connection-scoped symbol dictionary.
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
    /// Schema for the in-flight query. Populated from the first
    /// `RESULT_BATCH` (`batch_seq == 0`) and reused by continuation
    /// batches; `ReaderQuery::execute` clears it at query start and the
    /// reconnect path clears it on failover so a replayed query re-reads
    /// it from the new node's batch 0. A single slot suffices because a
    /// `Reader` runs one cursor at a time; pipelined `request_id`s would
    /// need a map keyed by request id.
    query_schema: Option<Schema>,
    next_request_id: i64,
    cursor_active: bool,
    /// Server's `SERVER_INFO` (`0x18`), captured eagerly during connect.
    /// The single QWP version always sends it as the first frame, so this
    /// is `Some` outside the brief reconnect window; multi-addr role
    /// filtering uses it to dismiss endpoints whose role doesn't match
    /// `target`.
    server_info: Option<ServerInfo>,
    /// Diagnostic counters (`bytes_received`, `credit_granted_total`,
    /// `read_ns`, `decode_ns`) shared with the FFI handle via `Arc` so
    /// that monitoring-thread stat reads can be served without ever
    /// touching the `UnsafeCell<Reader>` that the FFI uses to hold this
    /// `Reader`. Decoupling the counters from the Reader's borrow stack
    /// removes the aliasing question of "what happens when a stat
    /// getter synthesises a `&Reader` while a laundered `&mut Reader`
    /// is in flight": the stat getter doesn't touch the Reader at all.
    ///
    /// The one-thread-at-a-time rule that governs the rest of the
    /// Reader API is intentionally relaxed for these counters and
    /// `reset_timing`: their getters take `&self`, touch only atomics,
    /// and may be invoked concurrently from a monitoring thread while
    /// another thread is driving a cursor. Every other accessor
    /// (`current_addr`, `server_info`, `server_version`) reads
    /// non-atomic state and remains bound by the one-thread-at-a-time
    /// contract — racing them with an in-flight cursor is undefined
    /// behaviour. `Relaxed` is sufficient: these are pure counters with
    /// no associated happens-before requirement on other state.
    stats: Arc<ReaderStats>,
    /// Reusable zstd decompressor + output buffer. Keeps a persistent
    /// `ZSTD_DCtx` across batches (so we don't pay context init per
    /// `RESULT_BATCH`) and a `Vec<u8>` whose allocation is reused as
    /// successive frames decompress through it.
    zstd_scratch: ZstdScratch,
    /// Per-client host-health tracker shared across the initial connect
    /// and every mid-query reconnect. Implements the failover.md §2
    /// priority lattice — endpoints are picked by (state tier × zone
    /// tier × index), not by round-robin rotation; see
    /// [`HostHealthTracker`]. Classifications accumulate across
    /// Executes; only the round-attempted bits reset between walks.
    /// Lives on the Reader so long-lived clients converge on the
    /// healthiest endpoint over time.
    tracker: HostHealthTracker,
    /// Per-Reader PRNG for failover backoff jitter. Egress backoff
    /// uses **full-jitter** `[0, base)` per failover.md §3.1 — a
    /// query client is single-user and benefits from the lowest
    /// expected recovery time. Lives on the Reader so the state
    /// persists across reconnect cycles within a single Reader's
    /// lifetime.
    failover_rng: FailoverRng,
}

// Compile-time pin for the cross-thread contract the FFI and the public
// Rust API both depend on: `Reader` may be migrated to a worker thread
// while a monitoring thread reads `bytes_received` / `read_ns` /
// `decode_ns` / `credit_granted_total` via the `Arc<ReaderStats>`.
//
// Without this assertion, a future field addition (`Rc<…>`, `RefCell<…>`,
// `MutexGuard<'static, …>`, a custom `!Send`/`!Sync` type) would silently
// flip Reader off `Send`/`Sync` and the PR description's claim that
// "the reader handle may be migrated between threads" would turn false
// without any signal — runtime tests would keep passing because nothing
// actually exercises the migration. Pinning it here makes the bound
// load-bearing: a regression breaks compilation.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Reader>();
    assert_send_sync::<ReaderStats>();
    assert_send_sync::<HostHealthTracker>();
};

impl Reader {
    /// Open a new connection from a connect string.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let cfg = ReaderConfig::from_conf(conf)?;
        Self::from_config(&cfg)
    }

    /// Open a new connection from the config string stored in the
    /// `QDB_CLIENT_CONF` environment variable. Format matches [`Reader::from_conf`].
    pub fn from_env() -> Result<Self> {
        let conf = std::env::var("QDB_CLIENT_CONF").map_err(|e| match e {
            std::env::VarError::NotPresent => {
                fmt!(ConfigError, "Environment variable QDB_CLIENT_CONF not set.")
            }
            std::env::VarError::NotUnicode(_) => fmt!(
                InvalidUtf8,
                "Environment variable QDB_CLIENT_CONF is set but its value is not valid UTF-8."
            ),
        })?;
        Self::from_conf(conf)
    }

    /// Walk `cfg.addrs` via the per-client host-health tracker, opening
    /// the highest-priority unattempted endpoint and eagerly consuming
    /// the `SERVER_INFO` frame. Accepts the first endpoint whose role
    /// matches `cfg.target`. Returns:
    ///
    /// - `RoleMismatch` if every endpoint connected but none advertised
    ///   a matching role (last-seen role surfaced in the message).
    /// - `AuthError` if at least one endpoint 401/403'd and every other
    ///   endpoint failed too (per-endpoint accumulation lets the message
    ///   name every endpoint that rejected credentials).
    /// - `SocketError` if every endpoint failed at the transport layer
    ///   (refused / timed out / TLS error / etc.).
    /// - whatever the last attempt returned otherwise.
    ///
    /// The initial connect deliberately does **not** apply the failover
    /// backoff schedule — it walks every address once and reports back.
    /// Mid-query failover (via [`Cursor::next_batch`]) is what uses
    /// `failover_backoff_*` to space retries.
    ///
    /// The tracker is constructed fresh here, so every host starts at
    /// `Unknown` state and the priority-based pick degenerates to the
    /// user-supplied `addr=` order. From this Reader onward, the
    /// tracker accumulates classifications across Executes per the
    /// failover.md §2 priority lattice.
    pub fn from_config(cfg: &ReaderConfig) -> Result<Self> {
        // Re-run cap and consistency checks. `from_conf` validated at
        // parse time, but `ReaderConfig`'s `pub` fields can be mutated
        // post-parse (`#[non_exhaustive]` blocks struct-literal
        // construction, not field assignment), so a caller could
        // otherwise sneak a `failover_backoff_max_ms = u64::MAX` past
        // the parse-time hard cap and induce multi-day `thread::sleep`s
        // during a failover storm.
        cfg.validate()?;
        // Single deep clone at the API boundary. Every subsequent
        // reconnect attempt — initial walk, mid-query failover —
        // shares the same allocation via `Arc::clone`.
        let cfg = Arc::new(cfg.clone());
        // Wire the `zone=` knob and the `target=primary` flag into the
        // tracker. Per failover.md §2, `target=primary` collapses every
        // host's zone tier to `Same` regardless of `zone=` — writers
        // must be followed across zones — so we pass the bool through.
        // Comparison against `SERVER_INFO.zone_id` / `X-QuestDB-Zone`
        // is case-insensitive and lives inside `HostHealthTracker`.
        let mut tracker = HostHealthTracker::new(
            cfg.addrs.len(),
            cfg.zone.as_deref(),
            matches!(cfg.target, Target::Primary),
        );
        let walk = walk_via_tracker(
            &mut tracker,
            &cfg,
            // Initial connect: no fall-through reset — every host
            // starts at `Unknown`, so a single pass exhausts the list.
            // Failover.md §2.2 / spec §11.9.3: the retry-after-reset
            // pass is only meaningful when classifications have
            // accumulated, which doesn't happen on a fresh tracker.
            false,
            // Spec §6 / §11.9.3 WalkTracker pseudocode: `AuthError`
            // is terminal — credentials are cluster-wide, retrying
            // every host floods server logs without recovery. Matches
            // the Java reference's `connect()` which rethrows on
            // `QwpAuthFailedException` immediately.
            &[
                ErrorCode::ConfigError,
                ErrorCode::UnsupportedServer,
                ErrorCode::AuthError,
            ],
        )?;
        Ok(Reader {
            cfg,
            addr_idx: walk.session.idx,
            transport: Some(walk.session.transport),
            dict: SymbolDict::new(),
            query_schema: None,
            next_request_id: 1,
            cursor_active: false,
            server_info: walk.session.server_info,
            stats: Arc::new(ReaderStats::default()),
            zstd_scratch: ZstdScratch::new(),
            tracker,
            failover_rng: FailoverRng::new(),
        })
    }

    /// Open a single endpoint by index. Used by [`walk_via_tracker`] on
    /// both initial connect and mid-query failover. On success, returns
    /// a [`TransportSession`] holding the bound socket plus the
    /// `SERVER_INFO` (when applicable); the caller decides whether to
    /// wrap it in a fresh `Reader` (initial connect) or splice into an
    /// existing one (reconnect). On role mismatch, a `RoleMismatch`
    /// error carrying the observed role + zone via `UpgradeReject` is
    /// surfaced so the tracker can classify identically to a `421`
    /// upgrade reject.
    fn connect_endpoint(cfg: &ReaderConfig, idx: usize) -> Result<TransportSession> {
        let mut transport = WsTransport::connect_to(cfg, idx).map_err(|e| {
            // Prepend the endpoint so a connect/handshake/auth failure
            // names the host it came from. Without this, aggregated
            // multi-endpoint diagnostics surface only the tungstenite
            // message ("HTTP error: 401") with no way to tell which
            // endpoint refused.
            let endpoint = &cfg.addrs[idx];
            let mut annotated = Error::new(e.code(), format!("endpoint {}: {}", endpoint, e.msg()));
            if let Some(r) = e.upgrade_reject() {
                annotated = annotated.with_upgrade_reject(r.clone());
            }
            if let Some(info) = e.server_info() {
                annotated = annotated.with_server_info(info.clone());
            }
            annotated
        })?;
        let server_info = if transport.server_version() >= 1 {
            Some(read_server_info_frame(
                &mut transport,
                Duration::from_millis(cfg.server_info_timeout_ms),
            )?)
        } else {
            None
        };
        if !matches!(cfg.target, Target::Any) {
            match server_info.as_ref() {
                None => {
                    // No SERVER_INFO was supplied, so there's no wire role
                    // to match against `target`. Surface a plain
                    // `RoleMismatch` without `UpgradeReject` — there's no
                    // role or zone to attach. With the single QWP version
                    // (which always sends SERVER_INFO) this is unreachable
                    // for a conformant server; it remains as a guard.
                    return Err(fmt!(
                        RoleMismatch,
                        "endpoint {} supplied no SERVER_INFO and cannot match target={:?}",
                        idx,
                        cfg.target
                    ));
                }
                Some(info) if !target_matches(cfg.target, info.role) => {
                    // The endpoint advertised a role that doesn't match `target=`.
                    // Attach `UpgradeReject` carrying the advertised role
                    // and zone so the host-health tracker classifies
                    // identically to a `421+role` response — same
                    // semantics, same data payload, regardless of which
                    // surface the rejection arrived on.
                    //
                    // Also attach the full `SERVER_INFO` so callers can
                    // see the cluster/node identity of the last endpoint
                    // that refused (wire-egress.md §11.9.3): `epoch`,
                    // `cluster_id`, `node_id`, `capabilities`,
                    // `server_wall_ns` — none of which fit on
                    // `UpgradeReject`. Lets operators distinguish "no
                    // endpoint matched target=" from "all endpoints
                    // unreachable".
                    let role = info.role;
                    let role_name = role.as_str();
                    let reject =
                        UpgradeReject::new(role.as_u8(), role_name.clone(), info.zone_id.clone());
                    return Err(Error::new(
                        ErrorCode::RoleMismatch,
                        format!(
                            "endpoint {} role={} cluster={:?} does not match target={:?}",
                            idx, role_name, info.cluster_id, cfg.target,
                        ),
                    )
                    .with_upgrade_reject(reject)
                    .with_server_info(info.clone()));
                }
                _ => {}
            }
        }
        Ok(TransportSession {
            idx,
            transport,
            server_info,
        })
    }

    /// Reconnect this Reader in place after a mid-query transport
    /// failure. Walks the configured endpoint list via the per-client
    /// [`HostHealthTracker`] (failover.md §2 priority lattice — Healthy
    /// → Unknown → TransientReject → TransportError → TopologyReject;
    /// same-zone preferred when zone is configured). On success, the
    /// old transport has been closed, the new transport + `SERVER_INFO`
    /// are bound, the symbol dict and per-query schema are reset to
    /// empty, and `addr_idx` reflects the new endpoint. The caller must
    /// re-issue the
    /// `QUERY_REQUEST` with a freshly-allocated `request_id`.
    ///
    /// The `failed_idx` argument is the address index that just failed
    /// — `record_mid_stream_failure` demotes it from `Healthy` to
    /// `TransportError` so the tracker won't reach for it first on the
    /// next walk.
    /// `on_attempt` is invoked once per outer-loop iteration right
    /// before the `walk_via_tracker` dial runs (after the inter-attempt
    /// backoff sleep, so the wall-clock cost of the backoff is included
    /// in the elapsed measurement the caller derives). Passed by `&mut
    /// dyn` instead of generic `impl FnMut` so adding the hook doesn't
    /// monomorphise this large function per call site — there is one
    /// non-trivial caller (`Cursor::failover_reconnect_and_replay`).
    fn reconnect_with_failover(
        &mut self,
        failed_idx: usize,
        on_attempt: &mut dyn FnMut(u32),
    ) -> Result<u32> {
        let cfg = Arc::clone(&self.cfg);
        // Mid-query path: `failover_max_attempts` counts reconnect
        // rounds (no initial connect to subtract — we already had one).
        let attempts_total = cfg.failover_max_attempts.max(1);
        let mut backoff_ms = cfg.failover_backoff_initial_ms;
        let mut last_err: Option<Error> = None;
        // Failover.md §11.9.1 wall-clock budget. `0` is the documented
        // "unbounded" sentinel — translate to `None` so the inner
        // arithmetic doesn't have to deal with a special case.
        let deadline: Option<std::time::Instant> = if cfg.failover_max_duration_ms == 0 {
            None
        } else {
            Some(std::time::Instant::now() + Duration::from_millis(cfg.failover_max_duration_ms))
        };
        let mut deadline_exhausted = false;
        // Spec invariant (failover.md §2.3): mid-stream demote MUST run
        // before the next `begin_round(forget=true)` — reversing the
        // order would let sticky-Healthy preserve the just-failed host
        // as priority pick. `walk_via_tracker` only calls
        // `begin_round(true)` on the fall-through reset, never before
        // the first `pick_next`, but the demote still has to land
        // before any walk so the first `pick_next` skips the dead host.
        self.tracker.record_mid_stream_failure(failed_idx);
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
        // Cumulative dial count across every outer attempt's walk.
        // `FailoverEvent.attempts` carries this back to the user so
        // long-running diagnostics see real dial pressure, not just the
        // attempt index that landed.
        let mut total_dials: u32 = 0;
        // Outer-attempt counter — i.e. how many `walk_via_tracker` rounds
        // actually fired. Distinct from `attempts_total` (the configured
        // cap) because the deadline branch below can break out of the
        // loop before issuing a walk, leaving the configured value
        // misleadingly higher than reality. Used by both exhaustion
        // error messages so diagnostics report real effort, not policy.
        let mut attempts_made: u32 = 0;
        for attempt in 0..attempts_total {
            if attempt > 0 {
                // Failover.md §11.9 + §3.1: full-jitter `[0, base)`.
                // Single-user egress benefits from the lowest expected
                // recovery time; thundering-herd damping isn't a
                // concern at one client per workload.
                let jittered_ms = self.failover_rng.full_jitter_ms(backoff_ms);
                // §11.9.1 deadline interplay: the sleep is clamped to
                // `deadline - now`. If `now >= deadline`, the failover
                // budget is exhausted — exit without sleeping or
                // walking again. Per spec, the deadline check gates
                // failover eligibility (not total Execute wall-clock).
                let sleep_dur = match deadline {
                    Some(dl) => match dl.checked_duration_since(std::time::Instant::now()) {
                        Some(remaining) if !remaining.is_zero() => {
                            std::cmp::min(Duration::from_millis(jittered_ms), remaining)
                        }
                        _ => {
                            deadline_exhausted = true;
                            break;
                        }
                    },
                    None => Duration::from_millis(jittered_ms),
                };
                std::thread::sleep(sleep_dur);
                backoff_ms = backoff_ms
                    .saturating_mul(2)
                    .min(cfg.failover_backoff_max_ms);
            }
            // Count the attempt only after the deadline gate above has
            // let us through; otherwise we'd over-report attempts in
            // the wall-clock-exhausted message.
            attempts_made = attempts_made.saturating_add(1);
            // Fire the per-attempt hook *after* the deadline gate (so
            // the count we report matches the one the exhaustion errors
            // report) and *before* the dial (so observers see "about
            // to dial attempt N" rather than retroactive "dial N
            // finished"). Pass the 1-based attempt number; the caller
            // already knows the trigger and start time.
            on_attempt(attempts_made);
            match walk_via_tracker(
                &mut self.tracker,
                &cfg,
                // Per failover.md §11.9.3, the WalkTracker fall-through
                // reset pass is for reconnects only — gives stale
                // `TransientReject` / `TopologyReject` hosts from prior
                // outages another shot before declaring the walk failed.
                true,
                // Spec §6: AuthError is terminal during reconnect
                // (cluster-wide credentials problem; retrying every
                // host floods server logs without recovery). Initial
                // connect accumulates instead — see `from_config`.
                &[
                    ErrorCode::ConfigError,
                    ErrorCode::UnsupportedServer,
                    ErrorCode::AuthError,
                ],
            ) {
                Ok(walk) => {
                    total_dials = total_dials.saturating_add(walk.dials);
                    // Splice the new transport state into self, keeping
                    // the counters callers query
                    // (`bytes_received`, `credit_granted_total`,
                    // `read_ns`, `decode_ns`, `next_request_id`).
                    self.transport = Some(walk.session.transport);
                    self.server_info = walk.session.server_info;
                    self.dict = SymbolDict::new();
                    self.query_schema = None;
                    self.addr_idx = walk.session.idx;
                    return Ok(total_dials);
                }
                Err(e) => match e.code() {
                    code if !is_failover_eligible(code) => {
                        // Hard error (auth, config, unsupported server,
                        // etc.). Don't keep bouncing — these will fail
                        // identically on every endpoint.
                        return Err(e);
                    }
                    _ => {
                        warn_on_protocol_error_failover(&e, "reconnect walk");
                        last_err = Some(e);
                    }
                },
            }
        }
        if deadline_exhausted {
            let last_msg = last_err
                .as_ref()
                .map(|e| e.msg().to_string())
                .unwrap_or_else(|| "<no error captured>".to_string());
            return Err(fmt!(
                SocketError,
                "failover wall-clock budget exhausted (failover_max_duration_ms={}) after {} attempt(s); last error: {}",
                cfg.failover_max_duration_ms,
                attempts_made,
                last_msg
            ));
        }
        Err(last_err.unwrap_or_else(|| {
            // `attempts_made` rather than `attempts_total` (the
            // configured cap): the two are equal on natural exhaustion,
            // but a future change to the loop's break conditions
            // shouldn't quietly turn this into a lie about how many
            // attempts actually ran.
            fmt!(
                SocketError,
                "failover exhausted after {} attempts",
                attempts_made
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
        self.stats.bytes_received.load(Ordering::Relaxed)
    }

    /// Total bytes granted to the server via CREDIT (`0x15`) frames
    /// since this connection was opened. Useful for verifying that
    /// flow-control replenishment behaves as expected — in particular,
    /// that `Cursor::cancel()` doesn't continue topping up the server's
    /// budget while draining frames it's about to discard.
    pub fn credit_granted_total(&self) -> u64 {
        self.stats.credit_granted_total.load(Ordering::Relaxed)
    }

    /// Diagnostic accumulator (nanoseconds): time spent in
    /// `transport.read_frame()`. Saturates at `u64::MAX` (~584 years).
    /// Reset to zero by [`Reader::reset_timing`].
    pub fn read_ns(&self) -> u64 {
        self.stats.read_ns.load(Ordering::Relaxed)
    }
    /// Diagnostic accumulator (nanoseconds): time spent in
    /// `decode_frame()`. Saturates at `u64::MAX`.
    /// Reset to zero by [`Reader::reset_timing`].
    pub fn decode_ns(&self) -> u64 {
        self.stats.decode_ns.load(Ordering::Relaxed)
    }
    /// Reset both `read_ns` and `decode_ns` accumulators to zero.
    pub fn reset_timing(&self) {
        self.stats.read_ns.store(0, Ordering::Relaxed);
        self.stats.decode_ns.store(0, Ordering::Relaxed);
    }

    /// Borrow the shared diagnostic counters. The FFI clones this at
    /// `line_reader_from_conf` time so its stat getters can read the
    /// counters without touching the `UnsafeCell<Reader>` that holds
    /// this Reader — eliminating the aliasing question of "what
    /// happens when a stat getter synthesises a `&Reader` while a
    /// laundered `&mut Reader` is in flight."
    pub fn stats(&self) -> &Arc<ReaderStats> {
        &self.stats
    }

    /// `SERVER_INFO` (`0x18`) captured at connect time. `None` only while
    /// a reconnect is in flight; the single QWP version always supplies it.
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

    /// Begin building a parametrised query. The returned `ReaderQuery`
    /// exclusively borrows the reader; only one in-flight cursor at a
    /// time. Append binds in placeholder order, then call `.execute()`.
    pub fn prepare<S: Into<String>>(&mut self, sql: S) -> ReaderQuery<'_> {
        ReaderQuery {
            reader: self,
            builder: QueryRequest::builder(sql),
            on_failover_reset: None,
            on_failover_progress: None,
            _not_send: std::marker::PhantomData,
        }
    }

    /// Execute a SQL statement with no binds and return a streaming
    /// cursor. Convenience for `self.prepare(sql).execute()`.
    pub fn execute<S: Into<String>>(&mut self, sql: S) -> Result<Cursor<'_>> {
        self.prepare(sql).execute()
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
    /// `SERVER_INFO` of the new endpoint (`None` only if the server
    /// omitted it).
    pub new_server_info: Option<ServerInfo>,
    /// Newly-allocated `request_id` the cursor will receive frames for
    /// from now on. Different from `Cursor::request_id` *before* the
    /// failover.
    pub new_request_id: i64,
    /// Count of reconnect attempts the failover machinery burned
    /// before this success — every dial inside the single
    /// `reconnect_with_failover` walk that landed. `1` means the
    /// first reconnect attempt succeeded and its replay write went
    /// through cleanly. Larger values mean earlier reconnects in
    /// this walk missed (rotating through endpoints) before one
    /// landed. Pairs with [`elapsed`](Self::elapsed) — both measure
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

/// Phase discriminant on [`FailoverProgressEvent`].
///
/// The same callback fires for every phase of a mid-query failover —
/// from the moment the cursor's connection dies through to either a
/// successful reconnect or an exhausted retry budget. Operators can
/// route on the phase to feed SLO dashboards ("disconnected for N
/// seconds" alerts), per-attempt retry telemetry, or a one-shot
/// "gave up" notifier.
///
/// Marked `#[non_exhaustive]` so we can add phases (e.g. a hypothetical
/// `Cancelled` for cancel-during-failover races) without breaking
/// downstream matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FailoverPhase {
    /// The cursor's connection just died. Fires once, *before* the
    /// retry loop runs.
    Disconnected = 0,
    /// A reconnect dial is about to be attempted. Fires once per
    /// outer-loop iteration of the retry walk, *after* the inter-
    /// attempt backoff sleep has elapsed.
    Retrying = 1,
    /// A reconnect succeeded; replayed batches will start arriving on
    /// the new connection. Fires immediately *before* the
    /// [`ReaderQuery::on_failover_reset`] callback (when both are
    /// installed) so a single sink sees the entire lifecycle.
    Reset = 2,
    /// The retry budget is exhausted. The cursor is terminal; the
    /// error returned to the caller is in
    /// [`FailoverProgressEvent::final_error`].
    GaveUp = 3,
}

/// Notification delivered to the
/// [`ReaderQuery::on_failover_progress`] callback at each transition
/// of a mid-query failover lifecycle. See [`FailoverPhase`] for the
/// per-variant semantics.
///
/// Several fields are populated only in certain phases — see the
/// per-field docs. Marked `#[non_exhaustive]` so we can add fields
/// without breaking downstream pattern matches.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FailoverProgressEvent {
    /// Which lifecycle phase fired this event.
    pub phase: FailoverPhase,
    /// Endpoint that died. Set on every phase — even `Reset` keeps it
    /// so a single sink can correlate the failed/new pair without
    /// remembering state across calls.
    pub failed_addr: Endpoint,
    /// New endpoint the cursor is now bound to. `Some` only on
    /// [`FailoverPhase::Reset`].
    pub new_addr: Option<Endpoint>,
    /// `SERVER_INFO` of the new endpoint. `Some` only on
    /// [`FailoverPhase::Reset`].
    pub new_server_info: Option<ServerInfo>,
    /// Newly-allocated `request_id`. `Some` only on
    /// [`FailoverPhase::Reset`].
    pub new_request_id: Option<i64>,
    /// 1-based attempt counter:
    ///
    /// - `0` on `Disconnected` (no attempt yet).
    /// - `N ≥ 1` on `Retrying` for the Nth dial.
    /// - On `Reset`, the attempt that landed.
    /// - On `GaveUp`, the total number of attempts burned. May be `0`
    ///   when the wall-clock deadline was already exhausted before any
    ///   walk fired.
    pub attempt: u32,
    /// The error that triggered the failover (the original
    /// cause-of-death of the previous connection). Preserved across
    /// every phase so subscribers see consistent context regardless of
    /// when they latch on.
    pub trigger: Error,
    /// Wall-clock time since the disconnect was observed (the start of
    /// the failover cycle). Monotonically non-decreasing across phases
    /// of the same event.
    pub elapsed: std::time::Duration,
    /// Final error returned to the caller. `Some` only on
    /// [`FailoverPhase::GaveUp`]; this is the value the next call to
    /// [`Cursor::next_batch`] (or `add_credit`) will surface.
    pub final_error: Option<Error>,
}

/// Boxed user callback type for failover-progress notifications.
type FailoverProgressCallback<'r> = Box<dyn FnMut(&FailoverProgressEvent) + 'r>;

/// Borrows a `Reader` exclusively while the query is being constructed and
/// (eventually) the cursor is live.
///
/// `ReaderQuery` is unconditionally `!Send`. The failover-reset callback
/// can capture non-`Send` state (the C FFI trampoline captures
/// `*mut c_void` `user_data`), so allowing the type to migrate threads
/// based on whether a callback is currently installed would be a leaky
/// abstraction. The `_not_send` marker pins the choice regardless of
/// callback presence.
#[must_use = "ReaderQuery does nothing until you call .execute(); dropping it discards \
              the prepared SQL and any binds without sending a QUERY_REQUEST"]
pub struct ReaderQuery<'r> {
    reader: &'r mut Reader,
    builder: QueryRequestBuilder,
    /// Optional handler called every time the cursor reconnects after a
    /// transport-level failure (see [`FailoverEvent`]).
    on_failover_reset: Option<FailoverResetCallback<'r>>,
    /// Optional progress handler invoked at every phase of a mid-query
    /// failover lifecycle — see [`FailoverProgressEvent`] /
    /// [`FailoverPhase`].
    on_failover_progress: Option<FailoverProgressCallback<'r>>,
    /// Pin `!Send` regardless of whether the callback is installed.
    _not_send: std::marker::PhantomData<*const ()>,
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
    /// **Installing this callback is the caller's opt-in to "I will
    /// handle replay-after-data-delivered correctly."** Without it,
    /// [`Cursor::next_batch`] refuses to fail over once any batch has
    /// been yielded — returning
    /// [`crate::egress::ErrorCode::FailoverWouldDuplicate`]
    /// instead — to avoid silently doubling up rows in the caller's
    /// accumulator. Initial-connect failover (before any batch is
    /// yielded) is transparent and does not require this callback.
    ///
    /// Calling this method twice on the same `ReaderQuery` **replaces**
    /// the previous closure — only the most recent callback is invoked.
    ///
    /// Mirrors the Java client's `onFailoverReset(newNode)` contract.
    ///
    /// # Panics from the callback
    ///
    /// The callback is invoked synchronously from inside
    /// [`Cursor::next_batch`] (specifically, from the failover-replay
    /// path). If the callback panics, the unwind propagates through
    /// `next_batch` to the caller. The cursor's [`Drop`] still runs,
    /// which closes the WebSocket cleanly, so no resources are leaked
    /// — but the `Cursor` is gone. There is no "swallow and resume"
    /// behavior; treat a panicking callback as a bug and either
    /// `catch_unwind` inside the callback yourself or ensure the
    /// callback is panic-free. The C FFI binding wraps the callback in
    /// `catch_unwind` + `abort()` (panics across the C boundary are
    /// undefined behavior); the pure-Rust API leaves them as normal
    /// unwinds.
    ///
    /// ```no_run
    /// use std::sync::{Arc, Mutex};
    /// use questdb::egress::{FailoverEvent, Reader};
    ///
    /// # fn ex() -> questdb::egress::Result<()> {
    /// let mut reader = Reader::from_conf(
    ///     "ws::addr=db-a:9000,db-b:9000;target=primary",
    /// )?;
    /// // The handler accumulates rows in a buffer shared with the
    /// // callback. On failover the callback discards what was buffered
    /// // — the replayed query restarts at `batch_seq=0` against the
    /// // new endpoint, so anything already pushed would otherwise
    /// // double up.
    /// let rows: Arc<Mutex<Vec<i64>>> = Arc::new(Mutex::new(Vec::new()));
    /// let rows_for_cb = Arc::clone(&rows);
    /// let mut cursor = reader
    ///     .prepare("select x from t order by ts")
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

    /// Install a callback fired at every phase of a mid-query failover
    /// lifecycle: `Disconnected` when the cursor's connection dies,
    /// `Retrying` before each reconnect dial attempt, `Reset` after a
    /// successful failover (immediately before
    /// [`Self::on_failover_reset`] runs), and `GaveUp` when the retry
    /// budget is exhausted.
    ///
    /// **Replay opt-in.** Installing this callback also opts the cursor
    /// in to "I will handle replay-after-data-delivered correctly," the
    /// same way [`Self::on_failover_reset`] does — both callbacks fire
    /// on `Reset`, and either being installed clears the silent-
    /// duplicate guard documented on [`Cursor::next_batch`]. If you
    /// only want telemetry and not replay semantics, set
    /// `failover=off` instead.
    ///
    /// Calling this method twice on the same `ReaderQuery` **replaces**
    /// the previous closure — only the most recent callback is invoked.
    ///
    /// # Reentrancy
    ///
    /// The callback is invoked synchronously on the cursor's drive
    /// thread, while [`Cursor::next_batch`] (or `add_credit`) is
    /// mid-mutation of the underlying `Reader`. The same contract as
    /// [`Self::on_failover_reset`] applies:
    ///
    /// - **Must not** call back into the originating reader, query, or
    ///   cursor — including read-only stat getters.
    /// - **Must not** panic / `longjmp` / unwind across the boundary
    ///   (the FFI trampoline `catch_unwind` + `abort`s on escape).
    /// - **Must not** block indefinitely — every batch read, CREDIT
    ///   grant, and cancel waits until the callback returns.
    pub fn on_failover_progress<F>(mut self, callback: F) -> Self
    where
        F: FnMut(&FailoverProgressEvent) + 'r,
    {
        self.on_failover_progress = Some(Box::new(callback));
        self
    }

    /// Append a typed bind parameter.
    pub fn bind(mut self, value: Bind) -> Self {
        self.builder = self.builder.bind(value);
        self
    }

    bind_method!(bind_null, kind: SimpleNullKind);
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
    bind_method!(bind_uuid, v: [u8; 16]);
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
        if self.reader.cursor_active {
            return Err(fmt!(
                InvalidApiCall,
                "another cursor is already in flight on this connection (only one cursor at a time per Reader)"
            ));
        }
        let request_id = self.reader.alloc_request_id();
        // The schema rides the first RESULT_BATCH (batch_seq == 0) of each
        // query; clear any schema left from the prior query so a stray
        // continuation batch can't bind rows to a stale schema.
        self.reader.query_schema = None;
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
        // Wrap the encoded request as Bytes once. `Bytes::from(Vec)` is
        // a zero-copy move; cloning a Bytes is a refcount bump so the
        // initial write and the stashed copy share one allocation.
        let encoded_request: Bytes = encoded_request.into();
        self.reader
            .transport_mut()?
            .write_message(encoded_request.clone())?;

        self.reader.cursor_active = true;
        Ok(Cursor {
            reader: self.reader,
            request_id,
            last_batch: None,
            terminal: None,
            credit_enabled,
            cancelling: false,
            done: false,
            terminal_error: None,
            encoded_request,
            on_failover_reset: self.on_failover_reset,
            on_failover_progress: self.on_failover_progress,
            failover_resets: 0,
            data_delivered: false,
            _not_send: std::marker::PhantomData,
        })
    }
}

/// Patch the request_id span of a stashed `QUERY_REQUEST` payload in
/// place and return it as fresh `Bytes`.
///
/// Fast path: `Bytes::try_into_mut` recovers the underlying `BytesMut`
/// zero-copy when the buffer is uniquely owned (the previous
/// `write_message` clone has been dropped). Patching mutates 8 bytes in
/// place, then `BytesMut::freeze` returns to `Bytes` zero-copy. The
/// multi-MB bind payload is never copied across reconnects.
///
/// Slow path: tungstenite still holds a reference (e.g., a partial write
/// flushed only after this routine ran). `try_into_mut` returns the
/// original `Bytes` back via `Err`; we fall back to a one-time
/// allocate-and-copy via `Bytes::copy_from_slice`. Same cost as the
/// pre-fix code, but unreachable in the steady state where every
/// `write_message` returns with the WS frame fully flushed.
fn patch_request_id(buf: Bytes, new_rid: i64) -> Bytes {
    let mut buf = match buf.try_into_mut() {
        Ok(buf_mut) => buf_mut,
        Err(shared) => BytesMut::from(&shared[..]),
    };
    buf[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8].copy_from_slice(&new_rid.to_le_bytes());
    buf.freeze()
}

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
///
/// `#[non_exhaustive]` because future protocol revisions may add
/// terminal kinds (e.g. server-side timeouts).
#[derive(Debug, Clone)]
#[non_exhaustive]
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
///
/// `Cursor` is unconditionally `!Send`. The failover-reset callback can
/// capture non-`Send` state (the C FFI trampoline captures
/// `*mut c_void` `user_data`); pinning `!Send` regardless of whether a
/// callback is currently installed avoids a leaky abstraction whereby
/// a Cursor that happens not to have a callback would be `Send` and
/// then suddenly stop being so when one is installed.
#[must_use = "Cursor must be drained via next_batch() or cancelled via cancel(); \
              dropping mid-stream sends a best-effort CANCEL and closes the WebSocket, \
              tearing down the connection for the next query on this Reader"]
pub struct Cursor<'r> {
    reader: &'r mut Reader,
    request_id: i64,
    last_batch: Option<DecodedBatch>,
    terminal: Option<Terminal>,
    /// Pre-encoded `QUERY_REQUEST` payload from `execute()`, stashed
    /// so the cursor can resend the same query on a fresh connection
    /// after mid-query failover. The 8-byte `request_id` lives at
    /// `[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]`; replay recovers
    /// `BytesMut` via [`Bytes::try_into_mut`], overwrites that span
    /// with a freshly-allocated id, and re-freezes — so the multi-MB
    /// `Bind::Binary` / `Bind::Varchar` payload is never copied
    /// across reconnects, only the 8-byte request_id span is mutated
    /// in place.
    encoded_request: Bytes,
    /// User callback fired right before replayed batches arrive on a
    /// new connection. See [`ReaderQuery::on_failover_reset`].
    on_failover_reset: Option<FailoverResetCallback<'r>>,
    /// User callback fired at every phase of a mid-query failover
    /// lifecycle. See [`ReaderQuery::on_failover_progress`].
    on_failover_progress: Option<FailoverProgressCallback<'r>>,
    /// Number of successful failover resets observed by this cursor
    /// since `execute()`. Useful for tests and for asserting the
    /// query did not silently restart under the user's feet.
    failover_resets: u32,
    /// Sticky: set the first time a `RESULT_BATCH` is yielded to the
    /// caller and never reset. Drives the safety check in
    /// [`Cursor::next_batch`] that refuses mid-query failover when no
    /// [`ReaderQuery::on_failover_reset`] callback is installed —
    /// silently replaying after the caller already received rows
    /// would deliver duplicates the caller has no way to detect.
    /// Distinct from `last_batch.is_some()`, which is cleared at the
    /// start of every replay; this flag must NOT reset, because the
    /// hazard is "the caller saw data at some point during this
    /// query," not "on the current connection."
    data_delivered: bool,
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
    /// `STATUS_CANCELLED` reply to `cancel()`). Also set on the
    /// failover-give-up path and on every other error-terminal in
    /// `next_batch`. Drives the early return in `next_batch()` so a
    /// follow-up call doesn't try to read another frame off a server
    /// that has already finished with this `request_id`. `terminal`
    /// (the public lifecycle accessor) only stores the success
    /// terminals; error terminals are stashed in `terminal_error`
    /// instead and re-raised from any subsequent `next_batch` /
    /// `add_credit` call so a transient-retry caller can't mistake
    /// an errored cursor for a clean RESULT_END.
    done: bool,
    /// `Some(err)` iff the cursor terminated with an error (failover
    /// give-up, server `QUERY_ERROR`, decode failure, stale-rid, etc).
    /// Clone-replayed by every public method that would otherwise
    /// short-circuit on `self.done` — without this, the first call
    /// surfaces the error and every subsequent call returns
    /// `Ok(None)`, looking indistinguishable from a clean RESULT_END
    /// to a caller with a retry-on-transient-error loop.
    ///
    /// Captured at most once (the first error wins) so a follow-up
    /// failure during teardown can't overwrite the originating cause.
    terminal_error: Option<Error>,
    /// Pin `!Send` regardless of whether the callback is installed.
    _not_send: std::marker::PhantomData<*const ()>,
}

/// Borrow-free outcome of `next_batch_inner`. The wrapper in
/// `next_batch` matches on this and constructs the public `BatchView`
/// (which holds borrows into `self`) only in the `HaveBatch` arm —
/// keeping the inner result borrow-free is what lets the `Err` arm
/// mutate `self.terminal_error` to stash the cursor-killing error
/// for replay on subsequent calls.
enum NextOutcome {
    HaveBatch,
    Done,
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
        self.reader
            .stats
            .credit_granted_total
            .load(Ordering::Relaxed)
    }

    /// Advance the cursor by one batch. Returns `Ok(None)` when the stream
    /// has terminated (success). `QUERY_ERROR` becomes `Err`.
    ///
    /// On a transport-level failure (socket close, TLS error, WS
    /// framing error), the cursor will reconnect to the next address
    /// in the configured list (with exponential backoff and a bounded
    /// retry budget — see `failover_*` config keys), replay the
    /// `QUERY_REQUEST` with a fresh `request_id`, and resume from
    /// `batch_seq=0` on the new connection. The user-side handler is
    /// notified before any replayed batches arrive via the
    /// [`ReaderQuery::on_failover_reset`] callback. If failover is
    /// disabled (`failover=off`) or the retry budget is exhausted,
    /// the failure is surfaced as the underlying error.
    ///
    /// **Silent-duplicate guard.** If a batch has already been
    /// yielded to the caller and no `on_failover_reset` callback was
    /// installed, the cursor refuses to fail over and returns
    /// [`crate::egress::ErrorCode::FailoverWouldDuplicate`]
    /// instead. Replay would otherwise re-deliver rows the caller
    /// already consumed — with no signal — because the server
    /// restarts streaming from `batch_seq=0` on the new connection.
    /// Install the callback (and discard partial state on each
    /// invocation) to opt in to seeing replays; otherwise re-execute
    /// the query from scratch when this error fires. Failover that
    /// happens before the first batch is yielded — including initial
    /// connect failover — is unaffected and remains transparent.
    ///
    /// Decode errors (malformed payload, missing batch-0 schema, zstd
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
        // Replay-on-terminal guard. If the cursor previously terminated
        // with an error, surface that error on every subsequent call
        // rather than collapsing to `Ok(None)` (which is the clean-EOF
        // signal — a retry-on-transient-error caller would silently
        // treat an incomplete result set as complete).
        if self.done {
            return match self.terminal_error.as_ref() {
                Some(e) => Err(e.clone()),
                None => Ok(None),
            };
        }
        // Inner returns a borrow-free discriminant so the borrow
        // checker can split the lifetime — the Err arm needs to
        // mutate `self.terminal_error`, which it can't if the
        // inner result still holds a reference into `self`.
        // Capture is conditioned on `self.done` (set by every
        // error-terminal path, either directly or via
        // `terminate_with_close`) and on `terminal_error.is_none()`
        // so the FIRST cause wins — a follow-up teardown failure
        // can't overwrite the originating error.
        match self.next_batch_inner() {
            Ok(NextOutcome::HaveBatch) => {
                // `next_batch_inner` populates `last_batch` (via `.insert`)
                // and verifies `query_schema` is `Some` before returning
                // `HaveBatch`, so both are present here. Re-check with the
                // inner's *soft* pattern rather than `.expect()`: a panic
                // would abort the whole process across the FFI boundary
                // (`panic=abort`), so a future refactor that breaks the
                // invariant must surface a terminal `ProtocolError`, not
                // kill the host.
                if self.last_batch.is_none() || self.reader.query_schema.is_none() {
                    let err = fmt!(
                        ProtocolError,
                        "internal invariant: next_batch produced a batch without a decoded view or schema"
                    );
                    self.terminate_with_close();
                    if self.done && self.terminal_error.is_none() {
                        self.terminal_error = Some(err.clone());
                    }
                    return Err(err);
                }
                Ok(Some(BatchView {
                    decoded: self.last_batch.as_ref().unwrap(),
                    dict: &self.reader.dict,
                    schema: self.reader.query_schema.as_ref().unwrap(),
                }))
            }
            Ok(NextOutcome::Done) => Ok(None),
            Err(e) => {
                if self.done && self.terminal_error.is_none() {
                    self.terminal_error = Some(e.clone());
                }
                Err(e)
            }
        }
    }

    fn next_batch_inner(&mut self) -> Result<NextOutcome> {
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
                    // Silent-duplicate guard. If at least one batch was
                    // already yielded to the caller and they didn't
                    // install an `on_failover_reset` callback, replay
                    // would deliver those rows again with no signal —
                    // see `ErrorCode::FailoverWouldDuplicate`. The
                    // exact-once contract is "rows surface to the
                    // caller at most once unless they explicitly
                    // opt in to seeing replays."
                    //
                    // The trigger error `e` is preserved in the message
                    // so the caller still learns *why* the cursor died;
                    // diagnostics shouldn't get worse just because we
                    // re-classified the surface.
                    if would_silently_duplicate(
                        self.data_delivered,
                        self.on_failover_reset.is_some() || self.on_failover_progress.is_some(),
                    ) {
                        let err = fmt!(
                            FailoverWouldDuplicate,
                            "mid-query failover would replay rows already delivered to the caller \
                             (install on_failover_reset or on_failover_progress to opt in to replays); \
                             cursor terminated. Trigger: {} ({:?})",
                            e.msg(),
                            e.code()
                        );
                        self.terminate_with_close();
                        return Err(err);
                    }
                    warn_on_protocol_error_failover(&e, "mid-query frame read");
                    self.failover_reconnect_and_replay(e)?;
                    continue;
                }
            };
            // Capture wire size BEFORE the decode consumes the header.
            let wire_bytes = HEADER_LEN as u64 + header.payload_length as u64;
            // Decode is **not** failover-eligible. Anything that comes
            // out as an error here (bad varint, unknown discriminant,
            // missing batch-0 schema, symbol-dict miss, zstd corruption) is
            // a wire/state bug that won't be fixed by reconnecting —
            // and silently retrying would mask it from the user. Bubble
            // it up as a hard failure with the cursor terminated.
            let t1 = std::time::Instant::now();
            let decode_result = decode_frame(
                header,
                &payload,
                &mut self.reader.dict,
                &mut self.reader.query_schema,
                &mut self.reader.zstd_scratch,
            );
            // Account for decode time on both arms — the error path is
            // rare and terminal, but skipping the sample makes the
            // metric subtly biased toward "successful decodes are slow."
            self.reader.stats.decode_ns.fetch_add(
                u64::try_from(t1.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
            let event = match decode_result {
                Ok(ev) => ev,
                Err(e) => {
                    // Tear the WS down: the server is still streaming
                    // RESULT_BATCH frames for this `request_id`, and
                    // leaving the transport open would let a subsequent
                    // `Reader::prepare()` on this Reader read those stale
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
                    // decode_result_batch guarantees `query_schema` is
                    // populated on Ok (batch_seq == 0 sets it; > 0 errors
                    // when it's absent). Defensive check rather than an
                    // `.expect()` so an internal-invariant violation can't
                    // abort the process across the FFI boundary.
                    if self.reader.query_schema.is_none() {
                        let err = fmt!(ProtocolError, "RESULT_BATCH decoded without a schema");
                        self.terminate_with_close();
                        return Err(err);
                    }
                    let last = self.last_batch.insert(b);
                    // Latch sticky `data_delivered` BEFORE yielding the
                    // batch view — a subsequent failover-eligible read
                    // error must see the latch already set, since by
                    // that point the caller has consumed at least one
                    // row from this query.
                    self.data_delivered = true;
                    // BatchView construction is hoisted to `next_batch`
                    // (the wrapper) so the inner returns a borrow-free
                    // discriminant; the wrapper re-acquires the borrows
                    // on `last_batch`, `dict`, and `query_schema` itself.
                    // `last` is still in scope here only for the side
                    // effects (insert + data_delivered).
                    let _ = last;
                    return Ok(NextOutcome::HaveBatch);
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
                    return Ok(NextOutcome::Done);
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
                    return Ok(NextOutcome::Done);
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
    /// [`crate::egress::FailoverEvent`]).
    pub fn current_addr(&self) -> &Endpoint {
        self.reader.current_addr()
    }

    /// Negotiated QWP version of the cursor's underlying connection. The
    /// in-cursor accessor for [`Reader::server_version`], unreachable from
    /// user code while the cursor holds the `Reader`'s mutable borrow.
    /// Reflects the renegotiated version after mid-query failover.
    pub fn server_version(&self) -> Result<u8> {
        self.reader.server_version()
    }

    /// `SERVER_INFO` of the cursor's currently connected endpoint;
    /// `None` only while a reconnect is in flight (the single QWP
    /// version always supplies it). The in-cursor accessor for
    /// [`Reader::server_info`], unreachable from user code while the
    /// cursor holds the `Reader`'s mutable borrow. Reflects the new
    /// endpoint after mid-query failover.
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.reader.server_info()
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
        self.reader.stats.read_ns.fetch_add(
            u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        let wire_bytes = HEADER_LEN as u64 + header.payload_length as u64;
        self.reader
            .stats
            .bytes_received
            .fetch_add(wire_bytes, Ordering::Relaxed);
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
    fn failover_reconnect_and_replay(&mut self, trigger: Error) -> Result<()> {
        let started = std::time::Instant::now();
        let failed_idx = self.reader.addr_idx;
        // Snapshot the failing endpoint before reconnect mutates
        // `addr_idx` — `FailoverEvent` reports it back to the user.
        let failed_addr = self.reader.cfg.addrs[failed_idx].clone();

        // Phase: Disconnected. Fires before the retry loop runs so an
        // SLO dashboard sees the outage *now*, not retroactively when
        // a reconnect lands or the budget exhausts.
        if let Some(cb) = self.on_failover_progress.as_mut() {
            let event = FailoverProgressEvent {
                phase: FailoverPhase::Disconnected,
                failed_addr: failed_addr.clone(),
                new_addr: None,
                new_server_info: None,
                new_request_id: None,
                attempt: 0,
                trigger: trigger.clone(),
                elapsed: started.elapsed(),
                final_error: None,
            };
            cb(&event);
        }

        // Phase: Retrying. The closure fires once per outer-loop
        // iteration of `reconnect_with_failover`. We split the borrow
        // on `self` so the closure can mutate the progress callback
        // while `reader.reconnect_with_failover` holds a `&mut Reader`.
        // `last_attempt` is tracked outside the closure so the GaveUp
        // event can report the final attempt count even when the
        // reconnect loop breaks out via the wall-clock-deadline path
        // (which doesn't surface the count in its `Err`).
        let mut last_attempt: u32 = 0;
        let reconnect_result = {
            let Self {
                reader,
                on_failover_progress,
                ..
            } = self;
            let failed_addr_ref = &failed_addr;
            let trigger_ref = &trigger;
            reader.reconnect_with_failover(failed_idx, &mut |attempt: u32| {
                last_attempt = attempt;
                if let Some(cb) = on_failover_progress.as_mut() {
                    let event = FailoverProgressEvent {
                        phase: FailoverPhase::Retrying,
                        failed_addr: failed_addr_ref.clone(),
                        new_addr: None,
                        new_server_info: None,
                        new_request_id: None,
                        attempt,
                        trigger: trigger_ref.clone(),
                        elapsed: started.elapsed(),
                        final_error: None,
                    };
                    cb(&event);
                }
            })
        };
        let attempts = match reconnect_result {
            Ok(n) => n,
            Err(e) => {
                // Phase: GaveUp. Fire before mutating state / returning
                // so the callback sees the cursor in its
                // about-to-be-terminal form and can correlate against
                // the error the caller is about to receive via
                // `next_batch`.
                if let Some(cb) = self.on_failover_progress.as_mut() {
                    let event = FailoverProgressEvent {
                        phase: FailoverPhase::GaveUp,
                        failed_addr: failed_addr.clone(),
                        new_addr: None,
                        new_server_info: None,
                        new_request_id: None,
                        attempt: last_attempt,
                        trigger: trigger.clone(),
                        elapsed: started.elapsed(),
                        final_error: Some(e.clone()),
                    };
                    cb(&event);
                }
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
        // Reset connection-scoped state. The new connection has its
        // own (empty) dict and per-query schema already (set up by
        // `connect_endpoint`). Drop any in-flight batch buffer so we
        // don't accidentally surface a stale view.
        self.last_batch = None;
        // Allocate a fresh request_id and re-issue the same
        // QUERY_REQUEST bytes. The cursor stashed the encoded
        // payload at `execute()` time; here we patch the 8-byte
        // request_id span in place and write the buffer
        // verbatim. No builder clone, no Bind clone, no
        // re-encode — and crucially no memcpy of the body
        // either: the previous `write_message` call has dropped
        // its `Bytes` clone, so this clone is uniquely owned and
        // `try_into_mut` recovers the underlying `BytesMut`
        // zero-copy. With `failover_max_attempts` up to `1024`
        // and queries that may carry multi-MB `Bind::Binary`
        // payloads, this is the difference between a few bytes
        // and gigabytes of churn per failure event.
        let new_rid = self.reader.alloc_request_id();
        self.request_id = new_rid;
        self.encoded_request = patch_request_id(std::mem::take(&mut self.encoded_request), new_rid);
        match self
            .reader
            .transport_mut()
            .and_then(|t| t.write_message(self.encoded_request.clone()))
        {
            Ok(()) => {
                self.failover_resets = self.failover_resets.saturating_add(1);
                let new_addr = self.reader.cfg.addrs[self.reader.addr_idx].clone();
                let new_server_info = self.reader.server_info.clone();
                // Phase: Reset. Fire BEFORE the legacy on_failover_reset
                // so a single sink that subscribes to both sees a
                // consistent ordering. The two callbacks carry the same
                // logical event; on_failover_progress is the modern
                // surface and on_failover_reset is preserved for
                // backward compat.
                if let Some(cb) = self.on_failover_progress.as_mut() {
                    let event = FailoverProgressEvent {
                        phase: FailoverPhase::Reset,
                        failed_addr: failed_addr.clone(),
                        new_addr: Some(new_addr.clone()),
                        new_server_info: new_server_info.clone(),
                        new_request_id: Some(new_rid),
                        attempt: attempts,
                        trigger: trigger.clone(),
                        elapsed: started.elapsed(),
                        final_error: None,
                    };
                    cb(&event);
                }
                if let Some(cb) = self.on_failover_reset.as_mut() {
                    let event = FailoverEvent {
                        failed_addr,
                        new_addr,
                        new_server_info,
                        new_request_id: new_rid,
                        attempts,
                        trigger,
                        elapsed: started.elapsed(),
                    };
                    cb(&event);
                }
                Ok(())
            }
            Err(e) => {
                // Write (or build/encode) failed on the freshly-
                // connected socket — typically a TCP RST landing
                // between `accept` and our first write. Tear down the
                // new transport: no QUERY_REQUEST was sent, so the
                // server is sitting idle waiting for one. Letting it
                // linger until `Reader` drops would hold the FD and
                // leave the server's per-connection resources
                // allocated longer than necessary. Once
                // `cursor_active=false`, `Drop for Cursor` skips its
                // `close_in_place`, so this is the last chance to
                // close the WS cleanly. Take the transport out so the
                // FD is released here rather than at the eventual
                // Reader drop. The original `trigger` already burned
                // one `failover_max_duration_ms` budget through
                // `reconnect_with_failover`; surfacing the write
                // failure (rather than spinning another inner cycle)
                // keeps that budget honest as a per-Execute bound and
                // mirrors the Java reference client.
                //
                // Phase: GaveUp. From the observer's perspective this
                // is also a terminal exhaustion — the reconnect itself
                // succeeded but the replay write failed, and we will
                // not loop again. Fire the same terminal phase so a
                // dashboard that watches GaveUp gets a single
                // consistent event for "cursor is dead, won't recover."
                if let Some(cb) = self.on_failover_progress.as_mut() {
                    let event = FailoverProgressEvent {
                        phase: FailoverPhase::GaveUp,
                        failed_addr: failed_addr.clone(),
                        new_addr: None,
                        new_server_info: None,
                        new_request_id: None,
                        attempt: attempts,
                        trigger: trigger.clone(),
                        elapsed: started.elapsed(),
                        final_error: Some(e.clone()),
                    };
                    cb(&event);
                }
                if let Some(dead) = self.reader.transport.take() {
                    drop(dead);
                }
                self.reader.cursor_active = false;
                self.done = true;
                Err(e)
            }
        }
    }

    /// Send a CANCEL frame and drain until the server emits a terminal
    /// frame for this request.
    ///
    /// Blocking, but bounded. The CANCEL write inherits the transport's
    /// `WRITE_TIMEOUT`; immediately after the CANCEL is accepted by
    /// the kernel send buffer, the read timeout is tightened to
    /// `CANCEL_DRAIN_READ_TIMEOUT` and the write timeout to
    /// `CLOSE_TIMEOUT` for the duration of the credit-nudge + drain.
    /// That bounds the worst-case latency at one `WRITE_TIMEOUT`
    /// (CANCEL) + `CLOSE_TIMEOUT` (nudge) + `CANCEL_DRAIN_READ_TIMEOUT`
    /// (drain) — installing the drain bounds before the nudge avoids
    /// a second `WRITE_TIMEOUT` window on a stuck TLS peer. If the
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
            Ok(t) => t.write_message(Bytes::from(payload)),
            Err(e) => Err(e),
        };
        if let Err(e) = write_outcome {
            self.terminate_with_close();
            return Err(e);
        }
        // Bound the drain reads AND the credit-nudge write before
        // anything else can block. tungstenite's `read()` is otherwise
        // a pure blocking syscall, and a stuck-but-not-RST'd TLS peer
        // whose kernel send buffer is still draining can absorb the
        // credit-nudge write for the full `WRITE_TIMEOUT` (60 s)
        // before the drain timeout would otherwise have a chance to
        // fire. Tightening to `CLOSE_TIMEOUT` here caps the worst-case
        // cancel() latency at `WRITE_TIMEOUT` (CANCEL) + `CLOSE_TIMEOUT`
        // (nudge) + `CANCEL_DRAIN_READ_TIMEOUT` (drain) instead of
        // 2 × `WRITE_TIMEOUT` + drain.
        if let Some(t) = self.reader.transport.as_mut() {
            t.set_read_timeout(Some(CANCEL_DRAIN_READ_TIMEOUT));
            t.set_write_timeout(Some(CLOSE_TIMEOUT));
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
            // No-accounting variant: this 1-byte nudge exists only to
            // unstick a credit-suspended server so it can deliver the
            // QUERY_ERROR for our CANCEL. Bumping
            // `stats.credit_granted_total` here would violate the
            // counter's documented purpose ("cancel doesn't continue
            // topping up the server's budget"). See
            // `write_credit_frame_raw`.
            let _ = self.write_credit_frame_raw(1);
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

        // Restore the default timeouts. If `next_batch` hit a
        // non-cancelled error, it has already called
        // `terminate_with_close` and the transport is `None`; nothing
        // to restore.
        if let Some(t) = self.reader.transport.as_mut() {
            t.set_read_timeout(None);
            t.set_write_timeout(Some(WRITE_TIMEOUT));
        }

        drain_result
    }

    /// Manually grant the server `additional_bytes` of read budget on
    /// this cursor's request. Useful when the user wants a larger
    /// outstanding window than the per-batch auto-replenishment would
    /// give them, or when initial_credit was 0 but the user changes
    /// their mind mid-stream.
    ///
    /// Mirrors [`Self::next_batch`]'s failover policy: a transport-
    /// class write failure on the current connection triggers a
    /// reconnect-and-replay (when the connect string declares
    /// failover endpoints), after which the credit frame is re-sent
    /// on the new connection so the user's grant is preserved. If the
    /// reconnect fails or the failure is not failover-eligible
    /// (auth/config/protocol), the cursor is torn down so a follow-up
    /// `next_batch` sees a dead cursor instead of silently failing
    /// over.
    pub fn add_credit(&mut self, additional_bytes: u64) -> Result<()> {
        if self.done {
            return Err(match self.terminal_error.as_ref() {
                Some(e) => e.clone(),
                None => fmt!(InvalidApiCall, "cursor is terminal; add_credit not allowed"),
            });
        }
        let first_err = match self.send_credit_frame(additional_bytes) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        if self.cancelling || !self.reader.cfg.failover || !is_failover_eligible(first_err.code()) {
            self.terminate_with_close();
            return Err(first_err);
        }
        // Mirrors the silent-duplicate guard in `next_batch`. Once data
        // has been delivered to the caller without an
        // `on_failover_reset` callback, a reconnect-and-replay would
        // re-deliver those rows with no signal — violating the
        // exact-once contract. The trigger error is preserved in the
        // message so the caller still learns why the cursor died.
        if would_silently_duplicate(
            self.data_delivered,
            self.on_failover_reset.is_some() || self.on_failover_progress.is_some(),
        ) {
            let err = fmt!(
                FailoverWouldDuplicate,
                "mid-query failover would replay rows already delivered to the caller \
                 (install on_failover_reset or on_failover_progress to opt in to replays); \
                 cursor terminated. Trigger: {} ({:?})",
                first_err.msg(),
                first_err.code()
            );
            self.terminate_with_close();
            return Err(err);
        }
        warn_on_protocol_error_failover(&first_err, "add_credit write");
        self.failover_reconnect_and_replay(first_err)?;
        // Replay succeeded; the user's grant intent applies to the new
        // request now in flight. Re-send on the new connection. If
        // *that* fails too, treat it as a sticky terminal failure
        // rather than recursing — one failover per user call keeps the
        // latency bound predictable.
        match self.send_credit_frame(additional_bytes) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.terminate_with_close();
                Err(e)
            }
        }
    }

    fn send_credit_frame(&mut self, additional_bytes: u64) -> Result<()> {
        self.write_credit_frame_raw(additional_bytes)?;
        self.reader
            .stats
            .credit_granted_total
            .fetch_add(additional_bytes, Ordering::Relaxed);
        Ok(())
    }

    /// Wire-only CREDIT emit, **without** bumping
    /// `stats.credit_granted_total`. Used by `cancel()`'s wake nudge so
    /// the counter's documented invariant — "`cancel()` doesn't
    /// continue topping up the server's budget" — holds exactly,
    /// without a "modulo the 1-byte cancel nudge" caveat. Every other
    /// CREDIT path goes through `send_credit_frame` and is accounted for.
    fn write_credit_frame_raw(&mut self, additional_bytes: u64) -> Result<()> {
        let mut payload = Vec::with_capacity(16);
        payload.push(MsgKind::Credit.as_u8());
        payload.extend_from_slice(&self.request_id.to_le_bytes());
        varint::encode_u64(additional_bytes, &mut payload);
        self.reader
            .transport_mut()?
            .write_message(Bytes::from(payload))?;
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
    /// left buffered for a follow-up `Reader::prepare()` to pick up.
    ///
    /// `take()` + explicit `drop` matches `reconnect_with_failover`'s
    /// pattern: `close_in_place` issues the WS Close frame but leaves
    /// the `WsTransport` (and its TCP `FD` + tungstenite read/write
    /// buffers) alive until the value is dropped. Leaving the dead
    /// transport in `self.reader.transport = Some(_)` would pin the
    /// FD and several MiB of buffers until the entire `Reader` is
    /// dropped — a bounded but real leak per terminated cursor.
    /// Taking ownership and dropping here releases both immediately.
    fn terminate_with_close(&mut self) {
        if let Some(mut t) = self.reader.transport.take() {
            t.close_in_place();
            drop(t);
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
        // Send a best-effort CANCEL frame before tearing the WebSocket
        // down. Without this, the server keeps streaming `RESULT_BATCH`
        // frames for the abandoned request until it observes the WS
        // close — holding dictionary + schema + flow-control state for
        // a request the user no longer cares about. The CANCEL gets the
        // server to release that state immediately. `try_write_cancel`
        // tightens the write timeout so a stuck peer can't hold this
        // dropping thread for the full `WRITE_TIMEOUT`, and swallows
        // every error: Drop has nowhere to surface them.
        //
        // Defensive: while the cursor invariant says transport is
        // `Some` whenever `cursor_active` is true (the failover
        // paths clear `cursor_active` whenever they leave the
        // transport `None`), `Drop` should never panic.
        if self.reader.cursor_active {
            if let Some(t) = self.reader.transport.as_mut() {
                if !self.cancelling {
                    t.try_write_cancel(self.request_id);
                }
                t.close_in_place();
            }
            self.reader.cursor_active = false;
        }
    }
}

/// Borrowed view over the most recently decoded batch.
#[must_use = "BatchView is a borrowed projection; dropping it without iterating \
              the rows or calling its accessors throws away the just-decoded batch"]
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

    /// Connection-scoped symbol dictionary backing every SYMBOL column
    /// in this batch; a `SymbolColumn`'s codes index into it.
    pub fn dict(&self) -> &'c SymbolDict {
        self.dict
    }
}

/// Predicate for the failover trigger filter. Mirrors the Java
/// reference's "transport-level terminal failure" classification: any
/// failure that's plausibly fixable by reconnecting to a different
/// endpoint, but not failures that signal a hard problem (auth, bad
/// SQL, malformed binds, role-mismatch on a single-node config) which
/// would just bounce off every endpoint identically.
/// Predicate gating the silent-duplicate guard in
/// [`Cursor::next_batch`]: returns `true` when a mid-query failover
/// would silently re-deliver rows the caller has already consumed.
///
/// Replay restarts at `batch_seq=0` against the new endpoint, so the
/// caller's accumulator would see every previously-yielded row again.
/// The opt-in for "I will discard partial state on each replay" is
/// installing either [`ReaderQuery::on_failover_reset`] or
/// [`ReaderQuery::on_failover_progress`] — both fire immediately
/// before the first replayed batch arrives on the new connection, so
/// either signal gives the caller the chance to clear its accumulator.
/// Without one of them, the only safe response is to terminate the
/// cursor and let the caller re-execute from scratch.
///
/// Extracted as a free function so the truth table is unit-testable
/// without needing a live transport.
fn would_silently_duplicate(data_delivered: bool, has_replay_aware_callback: bool) -> bool {
    data_delivered && !has_replay_aware_callback
}

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

/// `ProtocolError` is failover-eligible because it most often signals
/// transient wire-frame corruption (truncated WS frame, malformed
/// varint mid-stream) that a fresh connection will recover from. The
/// same code, however, also fires on deterministic protocol bugs
/// (unknown `MsgKind`, mismatched lengths) — and the silent-duplicate
/// guard in [`Cursor::next_batch`] only blocks replay when *no*
/// `on_failover_reset` callback is installed. With a callback set,
/// replay proceeds even for deterministic violations.
///
/// Emit a stderr warning whenever a `ProtocolError` actually triggers
/// failover so operators can spot masked corruption in logs.
fn warn_on_protocol_error_failover(err: &Error, context: &str) {
    if err.code() == ErrorCode::ProtocolError {
        eprintln!(
            "questdb-rs: warning: ProtocolError triggered failover ({}): {} — \
             reconnecting may mask transient wire-frame corruption \
             (truncated frames, malformed varints) or a deterministic \
             protocol violation; check server logs if this recurs.",
            context,
            err.msg()
        );
    }
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

/// Splitmix64 PRNG state for failover backoff jitter. Lives on the
/// `Reader`; each instance gets a distinct seed at construction time.
/// Splitmix64 is the simplest non-trivial 64-bit generator with good
/// statistical properties for this use case (uniform draws over small
/// integer ranges); avoids pulling `rand` into the `sync-reader-ws`
/// feature.
///
/// The state is mutated on every draw. Splitmix64 is full-period
/// (cycles through all 2^64 values), so deterministic seeding is fine
/// — the only requirement is that draws within a single reconnect
/// round are uncorrelated.
#[derive(Debug)]
pub(crate) struct FailoverRng {
    state: u64,
}

impl FailoverRng {
    /// Seed from process time + a per-process monotonic counter so two
    /// Readers built in the same nanosecond still get distinct streams.
    pub(crate) fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let now_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        let bump = COUNTER.fetch_add(1, Ordering::Relaxed);
        // XOR-mix the two so neither's alone determines the seed —
        // SystemTime can be coarse on some platforms; the counter
        // alone would make collisions across processes likely.
        Self {
            state: now_ns ^ bump.wrapping_mul(0x9E37_79B9_7F4A_7C15),
        }
    }

    /// Splitmix64 step. Returns a uniformly-distributed `u64`.
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Full-jitter draw per failover.md §3.1: `FullJitter(base) =
    /// uniform_long[0, base)`. Returns the random milliseconds to
    /// sleep before the next reconnect attempt. `base = 0` returns 0
    /// (sleeping for zero is a no-op).
    pub(crate) fn full_jitter_ms(&mut self, base: u64) -> u64 {
        if base == 0 {
            return 0;
        }
        // Modulo is safe: the bias for tiny `base` against the 2^64
        // value space is far below the resolution we care about for a
        // backoff jitter (sub-microsecond bias on a millisecond
        // schedule).
        self.next_u64() % base
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

/// Bound socket + decoded `SERVER_INFO` for one endpoint. Internal
/// intermediate produced by [`Reader::connect_endpoint`] and consumed
/// by [`walk_via_tracker`] / [`Reader::from_config`] /
/// [`Reader::reconnect_with_failover`].
struct TransportSession {
    idx: usize,
    transport: WsTransport,
    server_info: Option<ServerInfo>,
}

/// Result of a successful tracker walk.
struct WalkOutcome {
    session: TransportSession,
    /// Number of `connect_endpoint` calls the walk made before
    /// landing on a successful endpoint. Includes failed picks before
    /// the success. The `FailoverEvent.attempts` field carries this
    /// value back to the user (cumulative across outer reconnect
    /// cycles).
    dials: u32,
}

/// Walk the tracker until either an endpoint accepts or the round is
/// exhausted. Shared between [`Reader::from_config`] (initial connect)
/// and [`Reader::reconnect_with_failover`] (mid-query failover).
///
/// `allow_reset_pass`: when `true`, on exhaustion call
/// `tracker.begin_round(forget=true)` once and walk the list one more
/// time (failover.md §11.9.3). Initial connect passes `false` (the
/// tracker is fresh — every host already starts at `Unknown` and a
/// second pass would be a no-op anyway).
///
/// `terminal_codes`: error codes that abort the walk immediately
/// rather than being recorded into the tracker. Both callers pass
/// `[ConfigError, UnsupportedServer, AuthError]` — `AuthError` is
/// cluster-wide (credentials don't differ per host); the others are
/// build-level (client built without a feature the server requires)
/// or config-level (bad URL / unresolved name). Retrying every host
/// against any of these floods server logs without recovery, so the
/// walk bails on the first occurrence per spec §6 / §11.9.3.
fn walk_via_tracker(
    tracker: &mut HostHealthTracker,
    cfg: &Arc<ReaderConfig>,
    allow_reset_pass: bool,
    terminal_codes: &[ErrorCode],
) -> Result<WalkOutcome> {
    // Reset the within-round attempted bits. Topology classifications
    // accumulated by prior Executes are preserved (the within-outage
    // reset per failover.md §11.9.2). The fall-through pass below is
    // what re-evaluates stale classifications.
    tracker.begin_round(false);
    let mut last_role_mismatch: Option<Error> = None;
    let mut last_transport_err: Option<Error> = None;
    let mut retried_after_reset = false;
    let mut dials: u32 = 0;
    loop {
        let idx = match tracker.pick_next() {
            Some(i) => i,
            None => {
                if allow_reset_pass && !retried_after_reset {
                    // Failover.md §11.9.3 fall-through reset: give
                    // stale `TransientReject` / `TopologyReject` hosts
                    // from prior outages another shot before declaring
                    // the entire walk failed. Only one reset, then fail.
                    tracker.begin_round(true);
                    retried_after_reset = true;
                    continue;
                }
                break;
            }
        };
        dials = dials.saturating_add(1);
        match Reader::connect_endpoint(cfg.as_ref(), idx) {
            Ok(session) => {
                // Update zone tier from `SERVER_INFO.zone_id` when the
                // server advertised one (gated by `CAP_ZONE`). `record_zone`
                // with `None`/empty is a no-op, so passing the field
                // unconditionally is safe even when the server advertised
                // no zone (CAP_ZONE=0).
                if let Some(info) = session.server_info.as_ref() {
                    tracker.record_zone(idx, info.zone_id.as_deref());
                }
                tracker.record_success(idx);
                return Ok(WalkOutcome { session, dials });
            }
            Err(e) => {
                let code = e.code();
                if terminal_codes.contains(&code) {
                    // Hard error (config, unsupported server, auth).
                    // Bail out before recording into the tracker;
                    // there's no point preserving classifications when
                    // the walk is about to fail outright.
                    return Err(e);
                }
                match code {
                    ErrorCode::RoleMismatch => {
                        // Pull the role/zone bytes out of `UpgradeReject`
                        // (set by both the SERVER_INFO target-mismatch path
                        // and the `421 + X-QuestDB-Role` upgrade-reject path
                        // in transport.rs). A mismatch with no
                        // `UpgradeReject` (the no-SERVER_INFO guard)
                        // defaults to topological.
                        let reject = e.upgrade_reject();
                        let transient = reject.is_some_and(|r| r.is_transient());
                        if let Some(r) = reject {
                            tracker.record_zone(idx, r.zone.as_deref());
                        }
                        tracker.record_role_reject(idx, transient);
                        last_role_mismatch = Some(e);
                    }
                    _ => {
                        tracker.record_transport_error(idx);
                        last_transport_err = Some(e);
                    }
                }
            }
        }
    }
    // Walk exhausted (and reset pass, if any, exhausted too). Prefer
    // surfacing the last RoleMismatch (carries `UpgradeReject` with the
    // advertised role + zone, useful for diagnosing "no endpoint
    // matched target=") over a generic transport flop.
    if let Some(e) = last_role_mismatch {
        return Err(e);
    }
    Err(last_transport_err
        .unwrap_or_else(|| fmt!(SocketError, "all {} endpoints unreachable", cfg.addrs.len())))
}

/// Read one frame off a fresh transport and expect `SERVER_INFO`.
/// Called once per successful upgrade. Uses throwaway dict / schema /
/// zstd scratch since `SERVER_INFO` itself
/// never carries symbols, schemas, or compressed payload — those state
/// machines only kick in once the Reader is assembled and starts
/// pulling `RESULT_BATCH` frames.
///
/// Bounded by `timeout` (sourced from
/// [`ReaderConfig::server_info_timeout_ms`], default 5 s per
/// failover.md §1.1). The `auth_timeout_ms` knob covers the HTTP
/// upgrade-response read only, and a server that accepts the upgrade
/// but then never sends the `SERVER_INFO` binary frame would
/// otherwise stall the connect indefinitely. The timeout is applied
/// as a TCP read deadline; on expiry the underlying read surfaces as
/// an `io::ErrorKind::WouldBlock` / `TimedOut` and tungstenite
/// renders it as `Error::Io` — which the transport mapper classifies
/// as `SocketError` (failover-eligible so the walk continues to the
/// next host).
///
/// The deadline is cleared on the way out so subsequent
/// `Cursor::next_batch` reads (which can legitimately block for as
/// long as the server takes to plan and execute the query) aren't
/// subject to it.
fn read_server_info_frame(transport: &mut WsTransport, timeout: Duration) -> Result<ServerInfo> {
    transport.set_read_timeout(Some(timeout));
    let result = transport.read_frame();
    transport.set_read_timeout(None);
    let (header, payload) = result?;
    let mut dict = SymbolDict::new();
    let mut query_schema: Option<Schema> = None;
    let mut zstd_scratch = ZstdScratch::new();
    let event = decode_frame(
        header,
        &payload,
        &mut dict,
        &mut query_schema,
        &mut zstd_scratch,
    )?;
    match event {
        ServerEvent::ServerInfo(info) => Ok(info),
        other => Err(fmt!(
            ProtocolError,
            "expected SERVER_INFO as the first frame, got {:?}",
            std::mem::discriminant(&other)
        )),
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

    /// `ReaderStats` lives behind `Arc` so the FFI handle can clone it
    /// once and read counters without touching the `UnsafeCell<Reader>`
    /// that owns the Reader. This test pins the contract that writes
    /// through one clone are observable through any other — the
    /// premise the FFI relies on for `_bytes_received` / `_read_ns` /
    /// etc. to return up-to-date values without crossing the cell.
    #[test]
    fn reader_stats_arc_clones_share_storage() {
        let stats = Arc::new(ReaderStats::default());
        let alias = Arc::clone(&stats);
        stats.bytes_received.fetch_add(42, Ordering::Relaxed);
        stats.credit_granted_total.fetch_add(7, Ordering::Relaxed);
        stats.read_ns.fetch_add(1_000, Ordering::Relaxed);
        stats.decode_ns.fetch_add(500, Ordering::Relaxed);
        assert_eq!(alias.bytes_received.load(Ordering::Relaxed), 42);
        assert_eq!(alias.credit_granted_total.load(Ordering::Relaxed), 7);
        assert_eq!(alias.read_ns.load(Ordering::Relaxed), 1_000);
        assert_eq!(alias.decode_ns.load(Ordering::Relaxed), 500);
        // Reset via the inner Reader's API is visible through the
        // FFI's clone too (the contract of `line_reader_reset_timing`).
        alias.read_ns.store(0, Ordering::Relaxed);
        alias.decode_ns.store(0, Ordering::Relaxed);
        assert_eq!(stats.read_ns.load(Ordering::Relaxed), 0);
        assert_eq!(stats.decode_ns.load(Ordering::Relaxed), 0);
    }

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

    /// Confirm `patch_request_id` mutates the request_id span and
    /// preserves every other byte, on both the unique-owner fast path
    /// and the shared-owner fallback path. This is what makes
    /// failover-replay zero-copy on the body: the multi-MB tail must
    /// be byte-identical to the original after a patch.
    #[test]
    fn patch_request_id_preserves_body_and_updates_id() {
        const OLD_RID: i64 = 0x1111_2222_3333_4444;
        const NEW_RID: i64 = 0x5555_6666_7777_8888;
        // Build a realistic encoded request so the test exercises the
        // same layout the production replay path patches.
        let req = QueryRequest::builder("SELECT * FROM big_table WHERE x > $1")
            .request_id(OLD_RID)
            .build()
            .expect("build");
        let mut original = Vec::with_capacity(64);
        req.encode(&mut original).expect("encode");
        let original = Bytes::from(original);

        // Unique-owner fast path: only this Bytes references the buffer,
        // so try_into_mut succeeds and the patch is in-place.
        let patched = patch_request_id(original.clone(), NEW_RID);
        // The cloned `original` we kept around drops at scope end; the
        // call above received its own clone which write_message would
        // consume. Verify the returned Bytes carries the new id.
        assert_eq!(patched[0], MsgKind::QueryRequest.as_u8());
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&patched[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]);
        assert_eq!(i64::from_le_bytes(id_bytes), NEW_RID);
        // Body before and after the request_id span is byte-identical.
        assert_eq!(
            &patched[..REQUEST_ID_OFFSET],
            &original[..REQUEST_ID_OFFSET]
        );
        assert_eq!(
            &patched[REQUEST_ID_OFFSET + 8..],
            &original[REQUEST_ID_OFFSET + 8..]
        );

        // Shared-owner fallback: hold an extra clone alive across the
        // call so try_into_mut returns Err and patch_request_id falls
        // back to BytesMut::from(&shared[..]). Same correctness.
        let _hold = patched.clone();
        let patched_again = patch_request_id(patched, OLD_RID);
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&patched_again[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]);
        assert_eq!(i64::from_le_bytes(id_bytes), OLD_RID);
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

    /// Pin the `StatusCode` → `ErrorCode` mapping. Every server-reported
    /// terminal status maps to a distinct `ErrorCode`; a refactor that
    /// merges two arms (e.g. lumps `LimitExceeded` and `InternalError`
    /// together) would silently swallow useful per-status discrimination.
    /// Adding a new `StatusCode` variant later forces this test to be
    /// updated — that's the point.
    #[test]
    fn map_server_status_matrix() {
        use crate::egress::wire::msg_kind::StatusCode as S;
        use ErrorCode as C;

        let cases: &[(S, C)] = &[
            (S::SchemaMismatch, C::ServerSchemaMismatch),
            (S::ParseError, C::ServerParseError),
            (S::InternalError, C::ServerInternalError),
            (S::SecurityError, C::ServerSecurityError),
            (S::Cancelled, C::Cancelled),
            (S::LimitExceeded, C::ServerLimitExceeded),
        ];

        for (status, expected_code) in cases {
            let err = map_server_status(*status, "msg".to_string());
            assert_eq!(
                err.code(),
                *expected_code,
                "status {:?} should map to {:?}",
                status,
                expected_code
            );
            assert_eq!(err.msg(), "msg");
        }

        // Sanity: each ErrorCode in the table is unique. If two
        // statuses ever collapse to the same code, this assertion
        // surfaces it — the matrix above could be wrong-but-passing if
        // both sides changed in lockstep.
        let mut seen = std::collections::HashSet::new();
        for (_, code) in cases {
            assert!(
                seen.insert(*code),
                "ErrorCode {:?} mapped from two distinct StatusCode values",
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

    /// `base = 0` MUST return 0 without touching the splitmix state.
    /// A backoff of zero is the documented "sleep is a no-op" sentinel
    /// and the caller passes it whenever `failover_backoff_initial_ms`
    /// has been driven to zero by repeated doubling under saturation.
    #[test]
    fn full_jitter_ms_zero_base_returns_zero() {
        let mut rng = FailoverRng::new();
        for _ in 0..32 {
            assert_eq!(rng.full_jitter_ms(0), 0);
        }
    }

    /// Every draw lies in `[0, base)` — the full-jitter contract from
    /// failover.md §3.1. SF ingress uses a different scheme (centered
    /// jitter, `[base/2, 3*base/2)`, in `qwp_ws_driver.rs`); this test
    /// pins the egress full-jitter contract, which — unlike that — may
    /// wait near zero. 10k samples per base across several bases
    /// (powers of two, near-`u32::MAX`, and primes that exercise the
    /// `% base` reduction) catches both off-by-one and signed/unsigned
    /// mix-ups.
    #[test]
    fn full_jitter_ms_draws_are_in_range() {
        let mut rng = FailoverRng::new();
        for &base in &[1u64, 2, 80, 100, 1_000, 65_537, u32::MAX as u64] {
            for _ in 0..10_000 {
                let d = rng.full_jitter_ms(base);
                assert!(
                    d < base,
                    "full_jitter_ms({}) returned {}, which is >= base \
                     (full-jitter draws must be in [0, base))",
                    base,
                    d
                );
            }
        }
    }

    /// The draws span the full `[0, base)` range, not a clamped sub-
    /// interval. With `base = 100` and 10k samples drawn from a
    /// Splitmix64-derived uniform, statistical guarantees are
    /// effectively certain: P(no sample < 10) = (0.9)^10000 ≈ 10^-457,
    /// and likewise for >= 90. A regression to a constant or a
    /// half-range clamp would fail one of the two assertions
    /// deterministically. This replaces the prior wall-clock-based
    /// `failover_backoff_uses_full_jitter` test, which had to drown
    /// scheduler noise out of an integration measurement.
    #[test]
    fn full_jitter_ms_distribution_covers_full_range() {
        let mut rng = FailoverRng::new();
        let mut saw_low = false;
        let mut saw_high = false;
        for _ in 0..10_000 {
            let d = rng.full_jitter_ms(100);
            if d < 10 {
                saw_low = true;
            }
            if d >= 90 {
                saw_high = true;
            }
            if saw_low && saw_high {
                break;
            }
        }
        assert!(
            saw_low,
            "expected at least one draw < 10 out of 10k samples"
        );
        assert!(
            saw_high,
            "expected at least one draw >= 90 out of 10k samples"
        );
    }

    /// Truth-table coverage for the silent-duplicate guard.
    ///
    /// The four input combinations cover every reachable cursor state
    /// at the moment a failover-eligible transport error fires.
    /// "Replay-aware callback" means *either* `on_failover_reset` or
    /// `on_failover_progress` is installed — both fire on a successful
    /// reset and either is enough to opt the cursor in to replays.
    ///
    /// | data_delivered | replay-aware cb installed | refuses replay? |
    /// |----------------|---------------------------|-----------------|
    /// | false          | false                     | no — initial-connect-style failover, transparent |
    /// | false          | true                      | no — caller will be notified anyway |
    /// | true           | false                     | **YES** — silent duplicates would otherwise reach the caller |
    /// | true           | true                      | no — caller opted in to replays |
    ///
    /// A regression that flipped the predicate (e.g. inverted the
    /// callback check or removed the data-delivered latch) would fail
    /// at least one row of this matrix.
    #[test]
    fn would_silently_duplicate_truth_table() {
        // No data yet — failover is always safe, regardless of callback.
        assert!(!would_silently_duplicate(false, false));
        assert!(!would_silently_duplicate(false, true));
        // Data already delivered — only the callback unlocks replay.
        assert!(would_silently_duplicate(true, false));
        assert!(!would_silently_duplicate(true, true));
    }
}
