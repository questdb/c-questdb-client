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

//! Column-sender connection pool.
//!
//! `QuestDb` is a thread-safe pool of [`crate::ingress::Sender`] handles to
//! a single QuestDB QWP/WebSocket endpoint. The pool eagerly opens
//! `pool_size` connections at `connect`, auto-grows up to `pool_max` on
//! demand, and (under `pool_reap=auto`) runs a background thread that closes
//! above-`pool_size` connections after they have been idle for
//! `pool_idle_timeout_ms`.
//!
//! Each pool slot is handed out as a [`BorrowedColumnSender<'_>`] which returns
//! itself to the pool on `Drop`. Slots whose underlying connection has
//! latched into `must_close=true` are dropped on return instead of being
//! recycled.
//!
//! The same `QuestDb` can also hand out **row-major**
//! [`crate::ingress::Sender`] handles via [`QuestDb::borrow_row_sender`]
//! ([`BorrowedRowSender`]) — the classic ILP `Buffer` + `flush` API. These
//! live in an independent, lazily-grown free list (rebuilt from the connect
//! string), capped separately by `pool_max`, so a caller can pull either a
//! column-major or a row-major sender from one shared pool handle.

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(feature = "_egress")]
use crate::egress::Reader;
use crate::ingress::sender::qwp_ws::QwpWsHostHealthTracker;
use crate::ingress::{QwpWsConnector, RawQwpWsRoundStream};
use crate::ingress::{Sender, SenderBuilder};
// The reconnect backoff helpers are only consumed by the retry-capable borrow
// paths: the row-major polars `reborrow_with_retry` and the FFI owned
// `*_with_retry` entry points. Keep the import unconditional (so the shared
// re-export chain that feeds it stays live) but quiet the unused-import lint in
// the plain library build that compiles neither retry path.
#[cfg_attr(
    not(any(feature = "polars", feature = "ffi-support")),
    allow(unused_imports)
)]
use crate::ingress::{reconnect_backoff_step, reconnect_error_is_terminal};
use crate::{Result, error};

use super::conf::{self, PoolReap};
use super::conn::ColumnConn;
use super::sender::ColumnSender;

/// Lower bound on the reaper's wake interval.
const REAPER_MIN_TICK: Duration = Duration::from_secs(5);

/// Poison-tolerant lock helper. The pool must survive a panic in another
/// thread's locked region: under `panic=abort` (FFI consumers) poisoning
/// can never be observed, but `questdb-rs` library consumers run with
/// `panic=unwind` and a single panicking thread would otherwise turn
/// every subsequent borrow/return into a panic via `.expect("poisoned")`.
fn lock_state(m: &Mutex<PoolState>) -> std::sync::MutexGuard<'_, PoolState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock_health(
    m: &Mutex<QwpWsHostHealthTracker>,
) -> std::sync::MutexGuard<'_, QwpWsHostHealthTracker> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(feature = "_egress")]
fn lock_reader_state(m: &Mutex<ReaderPoolState>) -> std::sync::MutexGuard<'_, ReaderPoolState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn lock_row_sender_state(
    m: &Mutex<RowSenderPoolState>,
) -> std::sync::MutexGuard<'_, RowSenderPoolState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// RAII guard that increments `state.in_use` on construction and
/// decrements it on drop unless [`InUseSlot::commit`] is called first.
/// Closes the leak window between `state.in_use += 1` and the connect
/// round: a panic in the connect path (allocator OOM,
/// TLS handshake panic) would otherwise skip the matching decrement
/// and permanently strand a pool slot.
struct InUseSlot<'a> {
    state: &'a Mutex<PoolState>,
    armed: bool,
}

impl InUseSlot<'_> {
    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for InUseSlot<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut state = lock_state(self.state);
            state.in_use = state.in_use.saturating_sub(1);
        }
    }
}

#[cfg(feature = "_egress")]
struct ReaderInUseSlot<'a> {
    state: &'a Mutex<ReaderPoolState>,
    armed: bool,
}

#[cfg(feature = "_egress")]
impl<'a> ReaderInUseSlot<'a> {
    fn reserve_within_cap(
        state: &'a Mutex<ReaderPoolState>,
        pool_max: usize,
    ) -> std::result::Result<Self, usize> {
        let mut guard = lock_reader_state(state);
        if guard.total() >= pool_max {
            return Err(guard.in_use);
        }
        guard.in_use += 1;
        Ok(Self { state, armed: true })
    }

    fn commit(mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "_egress")]
impl Drop for ReaderInUseSlot<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut state = lock_reader_state(self.state);
            state.in_use = state.in_use.saturating_sub(1);
        }
    }
}

/// Row-major sender equivalent of [`ReaderInUseSlot`]: reserves an `in_use`
/// slot under the cap and releases it on drop unless `commit` is called.
struct RowSenderInUseSlot<'a> {
    state: &'a Mutex<RowSenderPoolState>,
    armed: bool,
}

impl<'a> RowSenderInUseSlot<'a> {
    fn reserve_within_cap(
        state: &'a Mutex<RowSenderPoolState>,
        pool_max: usize,
    ) -> std::result::Result<Self, usize> {
        let mut guard = lock_row_sender_state(state);
        if guard.total() >= pool_max {
            return Err(guard.in_use);
        }
        guard.in_use += 1;
        Ok(Self { state, armed: true })
    }

    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for RowSenderInUseSlot<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut state = lock_row_sender_state(self.state);
            state.in_use = state.in_use.saturating_sub(1);
        }
    }
}

/// Connection pool for the column-major sender API.
///
/// Construct with [`QuestDb::connect`]. Share the pool across threads — its
/// internal state is `Mutex`-guarded so [`QuestDb::borrow_column_sender`] /
/// [`QuestDb::reap_idle`] / Drop-driven returns are safe to interleave.
///
/// Each borrow ([`BorrowedColumnSender`]) is **not** `Send` — it belongs to the
/// thread that borrowed it. To ingest in parallel, borrow one sender per
/// worker thread from the same `QuestDb`.
pub struct QuestDb {
    inner: Arc<DbInner>,
    reaper: Option<JoinHandle<()>>,
}

struct DbInner {
    /// Original connect string. Kept verbatim so the reader pool
    /// (`Reader::from_conf`) and the row-major sender pool
    /// (`SenderBuilder::from_conf`) can spin up a new connection with the
    /// same settings — both parsers accept the writer's scheme prefixes and
    /// ignore pool_* keys, so no translation is needed. The column-sender
    /// pool connects through the pre-resolved `connector` instead.
    conf: String,
    /// Resolved, reusable QWP/WebSocket connect ingredients (endpoint list,
    /// TLS, auth, config). Every sender connection — eager-open, auto-grow,
    /// and failover re-borrow — opens through this connector so it rotates
    /// across the configured endpoints. A single-endpoint pool behaves
    /// exactly as before (one endpoint, no rotation).
    connector: QwpWsConnector,
    /// One health tracker shared by every connect attempt. A connect failure
    /// or a mid-stream transport death marks the offending endpoint unhealthy
    /// so subsequent borrows skip it until it re-probes healthy; role rejects
    /// rotate to the writable primary. Pool-level (not per-conn) so the pool
    /// stops handing out connections to a dead peer rather than rediscovering
    /// it one connection at a time.
    health: Mutex<QwpWsHostHealthTracker>,
    pool_size: usize,
    pool_max: usize,
    sfa_mode: bool,
    pool_idle_timeout: Duration,
    state: Mutex<PoolState>,
    /// Reader pool. Lazy-init: starts empty, populated on first
    /// `borrow_reader_owned` call. Applies the same `pool_size` /
    /// `pool_max` / `pool_idle_timeout` values as the sender pool but
    /// tracks and caps them on an independent free list, so heavy ingest
    /// can't starve queries. The caps are enforced separately, so the
    /// combined live connection count across the column-sender, reader, and
    /// row-major-sender pools can reach up to `3 * pool_max`.
    #[cfg(feature = "_egress")]
    reader_state: Mutex<ReaderPoolState>,
    /// Row-major (`crate::ingress::Sender`) pool. Lazy-init, independent free
    /// list and `pool_max` cap, rebuilt from `conf` via
    /// `SenderBuilder::from_conf`. Lets callers borrow a classic ILP row
    /// sender from the same `QuestDb` handle as the column-major senders.
    row_sender_state: Mutex<RowSenderPoolState>,
    /// Wakes the reaper thread on `shutdown` and lets a future blocking
    /// borrow wait for a free slot once we grow `borrow_column_sender` past
    /// fail-fast (not in v1).
    cv: Condvar,
    shutdown: AtomicBool,
}

#[derive(Default)]
struct PoolState {
    /// Idle connections. Borrow/return is LIFO on the back (push/pop);
    /// the reaper drains the oldest entries from the front. Keeps hot
    /// connections warm in the common case while the reaper still
    /// retires entries in age order.
    free: Vec<PoolEntry>,
    /// Sum of currently-borrowed senders + in-flight grow operations.
    in_use: usize,
}

impl PoolState {
    fn total(&self) -> usize {
        self.free.len() + self.in_use
    }
}

struct PoolEntry {
    sender: ColumnSender,
    last_idle_at: Instant,
}

#[cfg(feature = "_egress")]
#[derive(Default)]
struct ReaderPoolState {
    /// Idle readers, oldest at front, newest at back (push on return /
    /// pop on borrow). Same FIFO/LIFO discipline as the sender free list.
    free: Vec<ReaderPoolEntry>,
    /// Currently-borrowed readers + in-flight grow operations.
    in_use: usize,
}

#[cfg(feature = "_egress")]
impl ReaderPoolState {
    fn total(&self) -> usize {
        self.free.len() + self.in_use
    }
}

#[cfg(feature = "_egress")]
struct ReaderPoolEntry {
    /// The reader carries its own per-connection state (symbol dict,
    /// schema registry, request-id sequence) inside itself, so unlike
    /// the sender pool we don't need to track them as separate fields.
    reader: Reader,
    last_idle_at: Instant,
}

#[derive(Default)]
struct RowSenderPoolState {
    /// Idle row-major senders, oldest at front, newest at back (push on
    /// return / pop on borrow). Same FIFO/LIFO discipline as the column
    /// sender free list.
    free: Vec<RowSenderPoolEntry>,
    /// Currently-borrowed row senders + in-flight grow operations.
    in_use: usize,
}

impl RowSenderPoolState {
    fn total(&self) -> usize {
        self.free.len() + self.in_use
    }
}

struct RowSenderPoolEntry {
    /// A classic ILP row sender. It owns its connection and per-connection
    /// state internally, so (like the reader pool) we don't track extra
    /// fields alongside it.
    sender: Sender,
    last_idle_at: Instant,
}

impl QuestDb {
    /// Open a pool against `conf`.
    ///
    /// The connect string must use a QWP/WebSocket schema (`qwpws::` /
    /// `qwpwss::` / `ws::` / `wss::`). Pool-specific keys are recognised:
    ///
    /// | Key                    | Default | Meaning                                                        |
    /// |------------------------|---------|----------------------------------------------------------------|
    /// | `pool_size`            | 1       | Warm / minimum connections, opened eagerly here.               |
    /// | `pool_max`             | 64      | Hard cap on auto-grow. Borrow at the cap returns `InvalidApiCall`. |
    /// | `pool_idle_timeout_ms` | 60000   | Above-`pool_size` idle connections are closed after this long. |
    /// | `pool_reap`            | `auto`  | `auto` runs a background reaper; `manual` requires `reap_idle`. |
    ///
    /// `sf_dir` opts the column sender into store-and-forward mode. In that
    /// mode v1 supports one active borrower: explicit `pool_size > 1` or
    /// `pool_max > 1` is rejected, and an omitted `pool_max` is treated as 1.
    /// `sender_id` and other `sf_*` keys require explicit `sf_dir`.
    ///
    pub fn connect(conf: &str) -> Result<Self> {
        let parsed = conf::parse(conf)?;
        let sfa_mode = parsed.store_and_forward;
        let pool_cfg = parsed.pool;

        let connector = SenderBuilder::from_conf(conf)?.build_qwp_ws_connector()?;
        let mut health = QwpWsHostHealthTracker::new(connector.endpoint_count());

        let mut free = Vec::with_capacity(pool_cfg.pool_size);
        let now = Instant::now();
        if sfa_mode {
            let state = connector.connect_sfa_background().map_err(|err| {
                crate::Error::new(
                    err.code(),
                    format!(
                        "Failed to open store-and-forward column sender: {}",
                        err.msg()
                    ),
                )
            })?;
            free.push(PoolEntry {
                sender: ColumnSender::new_store_and_forward(
                    state,
                    connector.max_buf_size(),
                    connector.request_durable_ack(),
                    connector.request_timeout(),
                ),
                last_idle_at: now,
            });
        } else {
            for slot in 0..pool_cfg.pool_size {
                let conn = connect_conn(&connector, &mut health).map_err(|err| {
                    crate::Error::new(
                        err.code(),
                        format!(
                            "Failed to open pool slot {} of {}: {}",
                            slot + 1,
                            pool_cfg.pool_size,
                            err.msg()
                        ),
                    )
                })?;
                free.push(PoolEntry {
                    sender: ColumnSender::new_direct(
                        conn,
                        crate::ingress::buffer::SymbolGlobalDict::new(),
                        super::encoder::EncodeScratch::new(),
                        false,
                    ),
                    last_idle_at: now,
                });
            }
        }

        let inner = Arc::new(DbInner {
            conf: conf.to_owned(),
            connector,
            health: Mutex::new(health),
            pool_size: pool_cfg.pool_size,
            pool_max: pool_cfg.pool_max,
            sfa_mode,
            pool_idle_timeout: pool_cfg.pool_idle_timeout,
            state: Mutex::new(PoolState { free, in_use: 0 }),
            #[cfg(feature = "_egress")]
            reader_state: Mutex::new(ReaderPoolState::default()),
            row_sender_state: Mutex::new(RowSenderPoolState::default()),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
        });

        let reaper = match pool_cfg.pool_reap {
            PoolReap::Auto => Some(spawn_reaper(Arc::clone(&inner)).map_err(|err| {
                inner.shutdown.store(true, Ordering::SeqCst);
                crate::Error::new(
                    crate::ErrorCode::SocketError,
                    format!("Failed to spawn pool reaper thread: {err}"),
                )
            })?),
            PoolReap::Manual => None,
        };

        Ok(Self { inner, reaper })
    }

    /// Borrow a sender.
    ///
    /// Selection: pop the most-recently-returned slot from the free list;
    /// failing that, open a new connection if we are below `pool_max`;
    /// failing that, return `InvalidApiCall` (fail-fast at cap).
    pub fn borrow_column_sender(&self) -> Result<BorrowedColumnSender<'_>> {
        let cs = self.pick_column_sender()?;
        Ok(BorrowedColumnSender::new(self, cs))
    }

    /// Borrow a **row-major** ([`crate::ingress::Sender`]) ILP sender from the
    /// pool, the companion to the column-major [`Self::borrow_column_sender`].
    ///
    /// The row-sender pool is lazy: it starts empty and opens a fresh
    /// `Sender` (via `SenderBuilder::from_conf` on the original connect
    /// string) on demand, recycling returned senders through an independent
    /// free list and `pool_max` cap. Borrow at the cap returns
    /// [`ErrorCode::InvalidApiCall`](crate::ErrorCode::InvalidApiCall).
    ///
    /// The returned [`BorrowedRowSender`] derefs to `Sender`, so the usual
    /// `Buffer` build + `flush` flow works unchanged, and returns the sender
    /// to the pool on `Drop` (unless its connection latched `must_close`, or
    /// [`BorrowedRowSender::mark_must_close`] was called, in which case it is
    /// dropped and the next borrow opens a fresh one).
    pub fn borrow_row_sender(&self) -> Result<BorrowedRowSender<'_>> {
        let sender = self.pick_row_sender()?;
        Ok(BorrowedRowSender::new(self, sender))
    }

    /// FFI escape hatch: like [`Self::borrow_column_sender`] but the returned
    /// handle is not lifetime-bound to `&self`. Carries an `Arc<DbInner>`
    /// internally so it can outlive the user-facing `QuestDb` pointer
    /// (the pool's return path stays alive as long as any borrow is
    /// outstanding; after pool close, returned handles are dropped instead of
    /// recycled).
    ///
    /// Hidden from the Rust API because Rust callers should prefer the
    /// lifetime-bound `borrow_column_sender`, which catches use-after-close at
    /// compile time. C callers reach this through `questdb_db_borrow_column_sender`.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_column_sender_owned(&self) -> Result<OwnedColumnSender> {
        let cs = self.pick_column_sender()?;
        Ok(OwnedColumnSender {
            inner: Arc::clone(&self.inner),
            sender: Some(cs),
        })
    }

    /// Like [`borrow_column_sender_owned`] but retries the connect within `budget`
    /// using the row API's reconnect backoff (the cluster may be electing a
    /// primary). Backs the C ABI's `questdb_db_borrow_column_sender_with_retry`, so
    /// C / C++ / Python callers fail over with the same backoff and budget as
    /// the row sender.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_column_sender_owned_with_retry(
        &self,
        budget: Duration,
    ) -> Result<OwnedColumnSender> {
        let deadline = Instant::now().checked_add(budget);
        Ok(OwnedColumnSender {
            inner: Arc::clone(&self.inner),
            sender: Some(reconnect_pick(&self.inner, deadline)?),
        })
    }

    /// FFI escape hatch: like [`Self::borrow_row_sender`] but the returned
    /// handle is not lifetime-bound to `&self` (it carries an `Arc<DbInner>`
    /// so it can outlive the user-facing `QuestDb` pointer). Backs the C ABI's
    /// `questdb_db_borrow_row_sender`. See [`Self::borrow_column_sender_owned`]
    /// for the owned-handle rationale.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_row_sender_owned(&self) -> Result<OwnedRowSender> {
        let sender = self.pick_row_sender()?;
        Ok(OwnedRowSender {
            inner: Arc::clone(&self.inner),
            sender: Some(sender),
            must_close: false,
        })
    }

    /// Like [`Self::borrow_row_sender_owned`] but retries the connect within
    /// `budget` using the pool's reconnect backoff (the cluster may be electing
    /// a primary; `AuthError` / protocol-version errors are terminal). Backs
    /// the C ABI's `questdb_db_borrow_row_sender_with_retry`. `budget`
    /// `Duration::ZERO` makes a single attempt.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_row_sender_owned_with_retry(
        &self,
        budget: Duration,
    ) -> Result<OwnedRowSender> {
        let deadline = Instant::now().checked_add(budget);
        let policy = self.inner.connector.reconnect_policy();
        let mut backoff = policy.initial_backoff();
        loop {
            match self.pick_row_sender() {
                Ok(sender) => {
                    return Ok(OwnedRowSender {
                        inner: Arc::clone(&self.inner),
                        sender: Some(sender),
                        must_close: false,
                    });
                }
                Err(e)
                    if reconnect_error_is_terminal(&e) || reconnect_deadline_expired(deadline) =>
                {
                    return Err(e);
                }
                Err(e) => {
                    let (sleep_for, next) = reconnect_backoff_step(
                        &e,
                        policy.initial_backoff(),
                        policy.max_backoff(),
                        backoff,
                    );
                    sleep_until_deadline(sleep_for, deadline);
                    backoff = next;
                }
            }
        }
    }

    fn pick_column_sender(&self) -> Result<ColumnSender> {
        pick_column_sender_inner(&self.inner)
    }

    fn pick_row_sender(&self) -> Result<Sender> {
        let mut state = lock_row_sender_state(&self.inner.row_sender_state);
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QuestDb pool is closed; cannot borrow row sender"
            ));
        }
        if let Some(entry) = state.free.pop() {
            state.in_use += 1;
            drop(state);
            return Ok(entry.sender);
        }
        drop(state);

        let slot = match RowSenderInUseSlot::reserve_within_cap(
            &self.inner.row_sender_state,
            self.inner.pool_max,
        ) {
            Ok(slot) => slot,
            Err(in_use) => {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "Row-sender pool exhausted: {} row senders are currently borrowed \
                     and the pool is at its `pool_max` cap of {}. Return a sender or \
                     raise `pool_max`.",
                    in_use,
                    self.inner.pool_max
                ));
            }
        };
        let sender = SenderBuilder::from_conf(&self.inner.conf)?.build()?;
        slot.commit();
        Ok(sender)
    }

    fn pick_replacement_sender(&self) -> Result<ColumnSender> {
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QuestDb pool is closed; cannot replace column sender"
            ));
        }
        if self.inner.sfa_mode {
            return Err(error::fmt!(
                InvalidApiCall,
                "column sender store-and-forward manages reconnects in its background runner"
            ));
        }
        // Same-handle replacement: the BorrowedColumnSender already owns one logical
        // in-use slot, so this must not reserve another one or pool_max=1 would
        // reject replacing a dead connection.
        if let Some(entry) = lock_state(&self.inner.state).free.pop() {
            return Ok(entry.sender);
        }

        let conn = connect_conn_pool(&self.inner)?;
        Ok(ColumnSender::new(
            conn,
            crate::ingress::buffer::SymbolGlobalDict::new(),
            super::encoder::EncodeScratch::new(),
            false,
        ))
    }

    /// Manually reap idle connections.
    ///
    /// Closes free-list entries that have been idle longer than
    /// `pool_idle_timeout_ms`, never shrinking total connection count below
    /// `pool_size`. Returns the number of connections closed.
    ///
    /// Under the default `pool_reap=auto`, a background thread invokes this
    /// logic periodically and this call is harmless. Under
    /// `pool_reap=manual`, callers that want shrinking must invoke this on
    /// their own cadence.
    pub fn reap_idle(&self) -> usize {
        reap_idle_inner(&self.inner)
    }

    /// Close the pool: stop the reaper (if any), reject future borrows, drop
    /// all idle connections, and consume `self`.
    ///
    /// FFI-owned outstanding handles remain return/drop-safe through their
    /// internal pool reference, but return after close drops the connection
    /// instead of recycling it.
    ///
    /// Drop has the same effect; `close` exists for parity with the C ABI
    /// (where `Drop` is not available) and to give callers a place to handle
    /// any reaper-join errors explicitly in the future.
    pub fn close(self) {
        drop(self);
    }

    /// The pool's reconnect backoff budget, parsed from the connect string's
    /// `reconnect_*` keys.
    #[cfg(feature = "polars")]
    pub(crate) fn reconnect_policy(&self) -> crate::ingress::ReconnectPolicy {
        self.inner.connector.reconnect_policy()
    }

    /// The pool's failover budget (`reconnect_max_duration`, default 300s).
    /// Exposed so the C ABI can let callers bound an overall failover deadline.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn reconnect_max_duration(&self) -> Duration {
        self.inner.connector.reconnect_policy().max_duration()
    }

    /// Snapshot the number of idle (free) connections currently in the pool.
    #[cfg(test)]
    pub(crate) fn free_count(&self) -> usize {
        lock_state(&self.inner.state).free.len()
    }

    /// Snapshot the number of currently-borrowed (or in-flight-being-built)
    /// connections.
    #[cfg(test)]
    pub(crate) fn in_use_count(&self) -> usize {
        lock_state(&self.inner.state).in_use
    }

    /// Snapshot the number of idle (free) row senders currently in the pool.
    #[cfg(test)]
    pub(crate) fn row_sender_free_count(&self) -> usize {
        lock_row_sender_state(&self.inner.row_sender_state)
            .free
            .len()
    }

    /// Snapshot the number of currently-borrowed row senders.
    #[cfg(test)]
    pub(crate) fn row_sender_in_use_count(&self) -> usize {
        lock_row_sender_state(&self.inner.row_sender_state).in_use
    }

    /// Borrow a query [`Reader`] from the egress pool.
    ///
    /// Egress companion to [`Self::borrow_column_sender`] (column-major ingest) and
    /// [`Self::borrow_row_sender`] (row-major ingest): pulls a [`Reader`]
    /// from the pool's reader free list, lazily opening a fresh connection
    /// (via `Reader::from_conf` on the original connect string) when the
    /// free list is empty and the pool is below `pool_max`. The reader pool
    /// is lazily grown and capped **independently** of the two sender pools,
    /// so heavy ingest can't starve queries and vice versa (the combined
    /// live-connection ceiling across all three pools is `3 * pool_max`).
    ///
    /// Borrow at the cap returns
    /// [`InvalidApiCall`](crate::egress::error::ErrorCode::InvalidApiCall).
    ///
    /// The returned [`BorrowedReader`] derefs to `Reader`, so the usual
    /// `prepare` / `execute` cursor flow works unchanged, and returns the
    /// reader to the pool on `Drop` — unless its transport has been torn
    /// down (or [`BorrowedReader::mark_must_close`] was called), in which
    /// case it is dropped and the next borrow opens a fresh one.
    ///
    /// Like [`BorrowedColumnSender`], [`BorrowedReader`] is **not** `Send` or
    /// `Sync`: borrow one reader per worker thread from the same `QuestDb`.
    #[cfg(feature = "_egress")]
    pub fn borrow_reader(&self) -> crate::egress::error::Result<BorrowedReader<'_>> {
        let reader = self.pick_reader()?;
        Ok(BorrowedReader::new(self, reader))
    }

    /// FFI escape hatch: borrow a reader from the egress pool.
    ///
    /// Same shape as [`Self::borrow_column_sender_owned`] but pulls a
    /// [`Reader`] from the reader free list (lazily opens one if the
    /// free list is empty and total < `pool_max`). Returned via
    /// [`OwnedReader`]'s Drop: see the sender variant for the same
    /// pattern.
    #[cfg(all(feature = "_egress", feature = "ffi-support"))]
    pub(crate) fn borrow_reader_owned(&self) -> crate::egress::error::Result<OwnedReader> {
        let reader = self.pick_reader()?;
        Ok(OwnedReader {
            inner: Arc::clone(&self.inner),
            reader: Some(reader),
            must_close: false,
        })
    }

    /// Construct an opaque pool reference that downstream code (the
    /// FFI's `reader` wrapper, in particular) can hold to return
    /// readers without having to expose [`DbInner`].
    #[cfg(all(feature = "_egress", feature = "ffi-support"))]
    pub(crate) fn reader_pool_handle(&self) -> ReaderPoolHandle {
        ReaderPoolHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    #[cfg(feature = "_egress")]
    fn pick_reader(&self) -> crate::egress::error::Result<Reader> {
        use crate::egress::error::{Error as EgressError, ErrorCode as EgressErrorCode};
        let mut state = lock_reader_state(&self.inner.reader_state);
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(EgressError::new(
                EgressErrorCode::InvalidApiCall,
                "QuestDb pool is closed; cannot borrow reader",
            ));
        }
        if let Some(entry) = state.free.pop() {
            state.in_use += 1;
            drop(state);
            return Ok(entry.reader);
        }
        drop(state);

        let slot = match ReaderInUseSlot::reserve_within_cap(
            &self.inner.reader_state,
            self.inner.pool_max,
        ) {
            Ok(slot) => slot,
            Err(in_use) => {
                return Err(EgressError::new(
                    EgressErrorCode::InvalidApiCall,
                    format!(
                        "Reader pool exhausted: {} readers are currently borrowed and \
                         the pool is at its `pool_max` cap of {}. \
                         Release a reader or raise `pool_max`.",
                        in_use, self.inner.pool_max
                    ),
                ));
            }
        };
        let reader = Reader::from_conf(&self.inner.conf)?;
        slot.commit();
        Ok(reader)
    }

    /// Snapshot the number of idle (free) readers currently in the pool.
    #[cfg(all(feature = "_egress", any(test, feature = "ffi-support")))]
    pub(crate) fn reader_free_count(&self) -> usize {
        lock_reader_state(&self.inner.reader_state).free.len()
    }

    /// Snapshot the number of currently-borrowed readers.
    #[cfg(all(feature = "_egress", any(test, feature = "ffi-support")))]
    pub(crate) fn reader_in_use_count(&self) -> usize {
        lock_reader_state(&self.inner.reader_state).in_use
    }
}

impl Debug for QuestDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let state = lock_state(&self.inner.state);
        f.debug_struct("QuestDb")
            .field("pool_size", &self.inner.pool_size)
            .field("pool_max", &self.inner.pool_max)
            .field("free", &state.free.len())
            .field("in_use", &state.in_use)
            .finish()
    }
}

impl Drop for QuestDb {
    fn drop(&mut self) {
        // Wake the reaper and let it observe shutdown.
        self.inner.shutdown.store(true, Ordering::SeqCst);
        // Notifying under the mutex avoids the lost-wakeup race where the
        // reaper has just released the lock and is about to wait.
        {
            let _g = lock_state(&self.inner.state);
            self.inner.cv.notify_all();
        }
        if let Some(handle) = self.reaper.take() {
            let _ = handle.join();
        }
        // Close idle resources now. Outstanding borrows hold their own Arc and
        // will be dropped instead of recycled when they return after shutdown.
        drain_idle_inner(&self.inner);
    }
}

/// A sender borrowed from a [`QuestDb`] pool.
///
/// On `Drop` the underlying connection is returned to the pool unless it
/// has latched into `must_close=true`, in which case it is dropped (and
/// auto-grow will open a fresh one for the next borrow).
///
/// `BorrowedColumnSender` is **not** `Send` or `Sync`. The borrowed connection
/// belongs to the borrowing thread for the duration of the borrow.
pub struct BorrowedColumnSender<'a> {
    db: &'a QuestDb,
    sender: Option<ColumnSender>,
    /// !Send / !Sync marker — `Rc<()>` poisons both auto traits without any
    /// runtime cost.
    _not_send: PhantomData<Rc<()>>,
}

impl<'a> BorrowedColumnSender<'a> {
    fn new(db: &'a QuestDb, sender: ColumnSender) -> Self {
        Self {
            db,
            sender: Some(sender),
            _not_send: PhantomData,
        }
    }

    /// The pool's reconnect backoff budget; see [`QuestDb::reconnect_policy`].
    #[cfg(feature = "polars")]
    pub(crate) fn reconnect_policy(&self) -> crate::ingress::ReconnectPolicy {
        self.db.reconnect_policy()
    }

    /// Drop the current connection (and its paired connection-scoped
    /// `SymbolGlobalDict`) back to the pool and obtain a fresh one **behind
    /// the same handle**, so the caller's `BorrowedColumnSender` stays valid.
    ///
    /// This is the column sender's failover primitive: after a transient
    /// (`ErrorCode::FailoverRetry`) flush/sync failure, call this to swap onto
    /// a live connection — the pool's connect path rotates across endpoints,
    /// skips the dead one, and follows the writable primary. The dropped
    /// connection's dict is discarded with it; the fresh connection brings its
    /// own dict, consistent with the server it talks to, so the unchanged
    /// delta-dict encoder re-drives correctly on the re-iterated source.
    ///
    /// The current connection stays behind this handle until a replacement has
    /// been opened. If replacement connect fails, the handle remains populated
    /// (possibly with a terminal connection) so later safe calls report errors
    /// instead of panicking. Once replacement succeeds, a failed connection is
    /// dropped (not recycled); a clean connection with un-sync'd in-flight
    /// frames is also dropped, mirroring [`Drop`], so the next borrower never
    /// commits this caller's data.
    pub fn reborrow_from_pool(&mut self) -> Result<()> {
        if let Some(sender) = self.sender.as_mut() {
            if sender.is_store_and_forward() {
                return Ok(());
            }
            if sender.in_flight() > 0 {
                sender.mark_must_close();
            }
            record_sender_transport_failure(&self.db.inner, sender);
        }
        let fresh = self.db.pick_replacement_sender()?;
        if let Some(old) = self.sender.replace(fresh) {
            finish_replaced_sender(&self.db.inner, old);
        }
        Ok(())
    }

    /// Retry [`reborrow_from_pool`] within `deadline` using the row API's
    /// reconnect backoff (centered-jittered, role-reject reset; `AuthError` /
    /// `ProtocolVersionError` terminal). On terminal failure or budget
    /// exhaustion the handle stays populated (per [`reborrow_from_pool`]), so a
    /// later call reports a typed error rather than panicking.
    #[cfg(feature = "polars")]
    pub(crate) fn reborrow_with_retry(&mut self, deadline: Option<Instant>) -> Result<()> {
        let policy = self.reconnect_policy();
        let mut backoff = policy.initial_backoff();
        loop {
            match self.reborrow_from_pool() {
                Ok(()) => return Ok(()),
                Err(e)
                    if reconnect_error_is_terminal(&e) || reconnect_deadline_expired(deadline) =>
                {
                    return Err(e);
                }
                Err(e) => {
                    let (sleep_for, next) = reconnect_backoff_step(
                        &e,
                        policy.initial_backoff(),
                        policy.max_backoff(),
                        backoff,
                    );
                    sleep_until_deadline(sleep_for, deadline);
                    backoff = next;
                }
            }
        }
    }
}

impl Debug for BorrowedColumnSender<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedColumnSender")
            .field("sender", &self.sender)
            .finish()
    }
}

impl Deref for BorrowedColumnSender<'_> {
    type Target = ColumnSender;

    fn deref(&self) -> &Self::Target {
        self.sender
            .as_ref()
            .expect("borrowed sender already returned")
    }
}

impl DerefMut for BorrowedColumnSender<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.sender
            .as_mut()
            .expect("borrowed sender already returned")
    }
}

impl Drop for BorrowedColumnSender<'_> {
    fn drop(&mut self) {
        let Some(mut sender) = self.sender.take() else {
            return;
        };
        // A drop with un-sync'd deferred frames would let the next
        // borrower's first flush commit the previous borrower's data
        // attributed to whatever table the new borrower targets.
        // Latch must_close so the connection is discarded instead.
        if sender.in_flight() > 0 {
            log::warn!(
                "column sender dropped with {} un-sync'd deferred frame(s); \
                 their data is discarded. Call sync() (or flush_and_wait() on \
                 the final chunk) before the borrow goes out of scope.",
                sender.in_flight()
            );
            sender.mark_must_close();
        }
        return_to_pool(&self.db.inner, sender);
    }
}

/// Owned (lifetime-free) variant of [`BorrowedColumnSender`] used by the C FFI.
///
/// Holds an `Arc<DbInner>` so the pool's return path outlives the
/// user-facing `QuestDb` pointer — the C ABI can free its `questdb_db*`
/// before dropping outstanding `column_sender*` handles. After pool close,
/// returned handles are dropped instead of recycled.
#[cfg(feature = "ffi-support")]
pub struct OwnedColumnSender {
    inner: Arc<DbInner>,
    sender: Option<ColumnSender>,
}

#[cfg(feature = "ffi-support")]
impl OwnedColumnSender {
    /// Borrow the underlying [`ColumnSender`] mutably. Always returns a
    /// live reference until `Drop` runs.
    pub fn get_mut(&mut self) -> &mut ColumnSender {
        self.sender
            .as_mut()
            .expect("OwnedColumnSender already returned to the pool")
    }

    /// Inspect the wrapped sender without taking ownership.
    pub fn get(&self) -> &ColumnSender {
        self.sender
            .as_ref()
            .expect("OwnedColumnSender already returned to the pool")
    }

    /// `true` after the originating pool has been closed. FFI callers use
    /// this to reject new work on checked-out handles while still allowing
    /// return/drop to clean up safely.
    pub fn pool_closed(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "ffi-support")]
impl Drop for OwnedColumnSender {
    fn drop(&mut self) {
        if let Some(mut sender) = self.sender.take() {
            if sender.in_flight() > 0 {
                log::warn!(
                    "column sender dropped with {} un-sync'd deferred \
                     frame(s); their data is discarded. Call sync() (or \
                     flush_and_wait() on the final chunk) before dropping \
                     the handle.",
                    sender.in_flight()
                );
                sender.mark_must_close();
            }
            return_to_pool(&self.inner, sender);
        }
    }
}

/// A row-major [`crate::ingress::Sender`] borrowed from a [`QuestDb`] pool.
///
/// Companion to [`BorrowedColumnSender`] (the column-major handle). Derefs to
/// `Sender`, so the usual `Buffer` build + `flush` flow works unchanged. On
/// `Drop` the sender is returned to the row-sender pool, unless its connection
/// has latched `must_close` (or [`Self::mark_must_close`] was called), in which
/// case it is dropped and the next borrow opens a fresh one.
///
/// `BorrowedRowSender` is **not** `Send` or `Sync`: the borrowed connection
/// belongs to the borrowing thread for the duration of the borrow.
pub struct BorrowedRowSender<'a> {
    db: &'a QuestDb,
    sender: Option<Sender>,
    must_close: bool,
    /// !Send / !Sync marker, mirroring [`BorrowedColumnSender`].
    _not_send: PhantomData<Rc<()>>,
}

impl<'a> BorrowedRowSender<'a> {
    fn new(db: &'a QuestDb, sender: Sender) -> Self {
        Self {
            db,
            sender: Some(sender),
            must_close: false,
            _not_send: PhantomData,
        }
    }

    /// Force this sender to be dropped (not recycled) when the borrow ends.
    /// Use after an error that may have left the connection unusable.
    pub fn mark_must_close(&mut self) {
        self.must_close = true;
    }
}

impl Debug for BorrowedRowSender<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedRowSender")
            .field("sender", &self.sender)
            .finish()
    }
}

impl Deref for BorrowedRowSender<'_> {
    type Target = Sender;

    fn deref(&self) -> &Self::Target {
        self.sender
            .as_ref()
            .expect("borrowed row sender already returned")
    }
}

impl DerefMut for BorrowedRowSender<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.sender
            .as_mut()
            .expect("borrowed row sender already returned")
    }
}

impl Drop for BorrowedRowSender<'_> {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            return_row_sender_to_pool(&self.db.inner, sender, self.must_close);
        }
    }
}

fn return_row_sender_to_pool(inner: &Arc<DbInner>, sender: Sender, must_close: bool) {
    let must_close = must_close || sender.must_close();
    let mut state = lock_row_sender_state(&inner.row_sender_state);
    state.in_use = state.in_use.saturating_sub(1);
    if !must_close && !inner.shutdown.load(Ordering::SeqCst) {
        state.free.push(RowSenderPoolEntry {
            sender,
            last_idle_at: Instant::now(),
        });
    }
    drop(state);
}

/// Owned, non-lifetime-bound row-major [`Sender`] borrowed from a [`QuestDb`]
/// pool — the row-sender analogue of [`OwnedColumnSender`].
///
/// Holds an `Arc<DbInner>` so the pool's return path outlives the
/// user-facing `QuestDb` pointer: the C ABI can free its `questdb_db*`
/// before dropping outstanding `row_sender*` handles. On `Drop` the sender
/// is returned to the row-sender pool unless it (or the caller, via
/// [`Self::mark_must_close`]) marked it must-close, or the pool has been
/// closed, in which case it is dropped and the next borrow opens a fresh one.
#[cfg(feature = "ffi-support")]
pub struct OwnedRowSender {
    inner: Arc<DbInner>,
    sender: Option<Sender>,
    must_close: bool,
}

#[cfg(feature = "ffi-support")]
impl OwnedRowSender {
    /// Borrow the underlying [`Sender`] mutably. Always returns a live
    /// reference until `Drop` runs.
    pub fn get_mut(&mut self) -> &mut Sender {
        self.sender
            .as_mut()
            .expect("OwnedRowSender already returned to the pool")
    }

    /// Inspect the wrapped sender without taking ownership.
    pub fn get(&self) -> &Sender {
        self.sender
            .as_ref()
            .expect("OwnedRowSender already returned to the pool")
    }

    /// Force this sender to be dropped (not recycled) when it is returned.
    /// Use after an error that may have left the connection unusable.
    pub fn mark_must_close(&mut self) {
        self.must_close = true;
    }

    /// `true` if this sender will be dropped rather than recycled on return —
    /// either marked explicitly, its connection latched must-close, or the
    /// originating pool has been closed.
    pub fn must_close(&self) -> bool {
        self.must_close
            || self.inner.shutdown.load(Ordering::SeqCst)
            || self.sender.as_ref().is_some_and(|s| s.must_close())
    }

    /// `true` after the originating pool has been closed.
    pub fn pool_closed(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }
}

#[cfg(feature = "ffi-support")]
impl Drop for OwnedRowSender {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            return_row_sender_to_pool(&self.inner, sender, self.must_close);
        }
    }
}

/// A query [`Reader`] borrowed from a [`QuestDb`] pool.
///
/// Egress companion to [`BorrowedColumnSender`] (column-major) and
/// [`BorrowedRowSender`] (row-major). Derefs to `Reader`, so the usual
/// `prepare` / `execute` cursor flow works unchanged. On `Drop` the reader
/// is returned to the reader pool, unless its transport has been torn down
/// (or [`Self::mark_must_close`] was called), in which case it is dropped
/// and the next borrow opens a fresh one.
///
/// `BorrowedReader` is **not** `Send` or `Sync`: the borrowed connection
/// belongs to the borrowing thread for the duration of the borrow.
#[cfg(feature = "_egress")]
pub struct BorrowedReader<'a> {
    db: &'a QuestDb,
    reader: Option<Reader>,
    must_close: bool,
    /// !Send / !Sync marker, mirroring [`BorrowedColumnSender`].
    _not_send: PhantomData<Rc<()>>,
}

#[cfg(feature = "_egress")]
impl<'a> BorrowedReader<'a> {
    fn new(db: &'a QuestDb, reader: Reader) -> Self {
        Self {
            db,
            reader: Some(reader),
            must_close: false,
            _not_send: PhantomData,
        }
    }

    /// Force this reader to be dropped (not recycled) when the borrow ends.
    /// Use after an error that may have left the connection unusable.
    pub fn mark_must_close(&mut self) {
        self.must_close = true;
    }
}

#[cfg(feature = "_egress")]
impl Debug for BorrowedReader<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        // `Reader` is not `Debug`; surface only the handle state.
        f.debug_struct("BorrowedReader")
            .field("borrowed", &self.reader.is_some())
            .field("must_close", &self.must_close)
            .finish()
    }
}

#[cfg(feature = "_egress")]
impl Deref for BorrowedReader<'_> {
    type Target = Reader;

    fn deref(&self) -> &Self::Target {
        self.reader
            .as_ref()
            .expect("borrowed reader already returned")
    }
}

#[cfg(feature = "_egress")]
impl DerefMut for BorrowedReader<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.reader
            .as_mut()
            .expect("borrowed reader already returned")
    }
}

#[cfg(feature = "_egress")]
impl Drop for BorrowedReader<'_> {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            return_reader_to_pool(&self.db.inner, reader, self.must_close);
        }
    }
}

/// Owned (lifetime-free) variant of a borrowed reader used by the C FFI.
///
/// Holds an `Arc<DbInner>` for the same reason [`OwnedColumnSender`] does: the
/// C ABI can free its `questdb_db*` pointer before dropping outstanding
/// reader handles. After pool close, returned readers are dropped instead of
/// recycled.
///
/// `must_close` short-circuits the return path: when set, the reader is
/// dropped instead of being returned to the pool. Pool shutdown has the same
/// effect. The egress-side
/// cursor lifecycle uses this to force-close readers whose underlying
/// transport has been torn down by a mid-stream cursor drop.
#[cfg(all(feature = "_egress", feature = "ffi-support"))]
pub struct OwnedReader {
    inner: Arc<DbInner>,
    reader: Option<Reader>,
    must_close: bool,
}

#[cfg(all(feature = "_egress", feature = "ffi-support"))]
impl OwnedReader {
    /// Inspect the wrapped reader without taking ownership.
    pub fn get(&self) -> &Reader {
        self.reader
            .as_ref()
            .expect("OwnedReader already returned to the pool")
    }

    /// Borrow the underlying reader mutably.
    pub fn get_mut(&mut self) -> &mut Reader {
        self.reader
            .as_mut()
            .expect("OwnedReader already returned to the pool")
    }

    /// Mark this reader for must-close: it will be dropped on Drop
    /// instead of returned to the pool.
    pub fn mark_must_close(&mut self) {
        self.must_close = true;
    }

    /// Take the inner reader, leaving the wrapper inert. Used by the
    /// FFI to expose the raw `Reader` to other call sites that don't
    /// know about the pool (e.g. monitoring stat getters).
    ///
    /// After this call, `Drop` no longer decrements the pool's
    /// `in_use` counter — the caller has assumed responsibility for
    /// either dropping the returned `Reader` into oblivion (e.g.
    /// `reader_close`'s leak-on-active branch) or routing it
    /// back to the pool via [`ReaderPoolHandle::return_reader`].
    /// Forgetting both permanently burns one pool slot.
    pub fn take(mut self) -> Option<Reader> {
        self.reader.take()
    }
}

#[cfg(all(feature = "_egress", feature = "ffi-support"))]
impl Drop for OwnedReader {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            return_reader_to_pool(&self.inner, reader, self.must_close);
        }
    }
}

/// Opaque handle to a [`QuestDb`] pool, used by the FFI's
/// `reader` wrapper to return readers without exposing
/// `DbInner`. Cheap to clone (just bumps the inner `Arc`).
#[cfg(all(feature = "_egress", feature = "ffi-support"))]
#[derive(Clone)]
pub struct ReaderPoolHandle {
    inner: Arc<DbInner>,
}

#[cfg(all(feature = "_egress", feature = "ffi-support"))]
impl ReaderPoolHandle {
    /// Return a [`Reader`] to the pool it came from. If `must_close`
    /// is set the reader is dropped instead of recycled — matching
    /// the [`OwnedReader::mark_must_close`] semantics.
    pub fn return_reader(&self, reader: Reader, must_close: bool) {
        return_reader_to_pool(&self.inner, reader, must_close);
    }

    /// `true` after the originating pool has been closed.
    pub fn pool_closed(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }

    /// Release the `in_use` slot that was reserved when this reader
    /// was borrowed, without returning the `Reader` itself. Used by
    /// the FFI leak-on-active path: when a `reader_close` arrives
    /// with a cursor still live, the underlying `Reader` cannot be
    /// extracted (UnsafeCell aliasing with the in-flight `&mut Reader`),
    /// so it leaks — but the pool's borrow accounting must still drop
    /// the slot or `pool_max` is permanently burned.
    pub fn release_leaked_slot(&self) {
        let mut state = lock_reader_state(&self.inner.reader_state);
        state.in_use = state.in_use.saturating_sub(1);
    }
}

#[cfg(feature = "_egress")]
fn return_reader_to_pool(inner: &Arc<DbInner>, reader: Reader, must_close: bool) {
    let must_close = must_close || reader.transport_torn_down();
    let mut state = lock_reader_state(&inner.reader_state);
    state.in_use = state.in_use.saturating_sub(1);
    if !must_close && !inner.shutdown.load(Ordering::SeqCst) {
        state.free.push(ReaderPoolEntry {
            reader,
            last_idle_at: Instant::now(),
        });
    }
    drop(state);
}

/// Pop a free connection or open a fresh one within `pool_max`. Reserves the
/// pool slot under one lock so a concurrent return can't race past `pool_size`.
fn pick_column_sender_inner(inner: &Arc<DbInner>) -> Result<ColumnSender> {
    let slot = {
        let mut state = lock_state(&inner.state);
        if inner.shutdown.load(Ordering::SeqCst) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QuestDb pool is closed; cannot borrow column sender"
            ));
        }
        if let Some(entry) = state.free.pop() {
            state.in_use += 1;
            drop(state);
            return Ok(entry.sender);
        }
        if inner.sfa_mode {
            if state.in_use == 0 {
                state.in_use += 1;
                InUseSlot {
                    state: &inner.state,
                    armed: true,
                }
            } else {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "column sender store-and-forward supports one active borrower in v1; \
                     return the borrowed sender before borrowing another"
                ));
            }
        } else {
            if state.total() >= inner.pool_max {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "Connection pool exhausted: {} sender(s) in use, pool_max={}. \
                     Drop a BorrowedColumnSender or increase pool_max.",
                    state.in_use,
                    inner.pool_max
                ));
            }
            state.in_use += 1;
            InUseSlot {
                state: &inner.state,
                armed: true,
            }
        }
    };
    if inner.sfa_mode {
        let sender = connect_sfa_pool(inner)?;
        slot.commit();
        return Ok(sender);
    }
    let conn = connect_conn_pool(inner)?;
    slot.commit();
    Ok(ColumnSender::new_direct(
        conn,
        crate::ingress::buffer::SymbolGlobalDict::new(),
        super::encoder::EncodeScratch::new(),
        false,
    ))
}

fn connect_sfa_pool(inner: &Arc<DbInner>) -> Result<ColumnSender> {
    let state = inner.connector.connect_sfa_background().map_err(|err| {
        crate::Error::new(
            err.code(),
            format!(
                "Failed to open store-and-forward column sender: {}",
                err.msg()
            ),
        )
    })?;
    Ok(ColumnSender::new_store_and_forward(
        state,
        inner.connector.max_buf_size(),
        inner.connector.request_durable_ack(),
        inner.connector.request_timeout(),
    ))
}

/// Re-acquire a live connection within `deadline`, retrying with the row API's
/// reconnect backoff: a failed pick (every endpoint role-rejecting while the
/// cluster elects a primary, or a transient transport error) backs off and
/// retries; `AuthError` / `ProtocolVersionError` and deadline exhaustion are
/// terminal.
#[cfg(feature = "ffi-support")]
fn reconnect_pick(inner: &Arc<DbInner>, deadline: Option<Instant>) -> Result<ColumnSender> {
    let policy = inner.connector.reconnect_policy();
    let mut backoff = policy.initial_backoff();
    loop {
        match pick_column_sender_inner(inner) {
            Ok(cs) => return Ok(cs),
            Err(e) if reconnect_error_is_terminal(&e) || reconnect_deadline_expired(deadline) => {
                return Err(e);
            }
            Err(e) => {
                let (sleep_for, next) = reconnect_backoff_step(
                    &e,
                    policy.initial_backoff(),
                    policy.max_backoff(),
                    backoff,
                );
                sleep_until_deadline(sleep_for, deadline);
                backoff = next;
            }
        }
    }
}

#[cfg(any(feature = "polars", feature = "ffi-support"))]
fn reconnect_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

#[cfg(any(feature = "polars", feature = "ffi-support"))]
fn sleep_until_deadline(sleep_for: Duration, deadline: Option<Instant>) {
    let d = match deadline {
        Some(dl) => sleep_for.min(dl.saturating_duration_since(Instant::now())),
        None => sleep_for,
    };
    if !d.is_zero() {
        thread::sleep(d);
    }
}

/// Open one connection through `connector`, driving `health` so it rotates
/// across endpoints and skips unhealthy / role-rejecting ones. Used by the
/// eager-open loop where the tracker is still owned by value.
fn connect_conn(
    connector: &QwpWsConnector,
    health: &mut QwpWsHostHealthTracker,
) -> Result<ColumnConn> {
    let raw: RawQwpWsRoundStream = connector.connect_round(health)?;
    ColumnConn::from_round_stream(raw)
}

/// Same as [`connect_conn`] but takes the live pool. The shared health tracker
/// is locked only per tracker operation (pick/claim/record), never across the
/// blocking TCP+TLS+WS-upgrade handshake — so concurrent cold-start borrows do
/// not serialize end-to-end, and dead-sender returns that also grab
/// `inner.health` (via [`record_sender_transport_failure`]) are not stalled
/// behind one slow / black-holed connect.
fn connect_conn_pool(inner: &Arc<DbInner>) -> Result<ColumnConn> {
    let raw: RawQwpWsRoundStream = inner.connector.connect_round_pooled(&inner.health)?;
    ColumnConn::from_round_stream(raw)
}

fn return_to_pool(inner: &Arc<DbInner>, sender: ColumnSender) {
    let must_close = sender.must_close();
    // A transport-dead connection marks its endpoint unhealthy in the shared
    // tracker so the next borrow rotates away from the dead peer (until it
    // re-probes healthy). A pool-driven `mark_must_close` (un-sync'd pending
    // frames) or a server-data rejection leaves the endpoint healthy.
    record_sender_transport_failure(inner, &sender);
    let mut state = lock_state(&inner.state);
    state.in_use = state.in_use.saturating_sub(1);
    if !must_close && !inner.shutdown.load(Ordering::SeqCst) {
        state.free.push(PoolEntry {
            sender,
            last_idle_at: Instant::now(),
        });
    }
    drop(state);
}

fn finish_replaced_sender(inner: &Arc<DbInner>, sender: ColumnSender) {
    let must_close = sender.must_close();
    record_sender_transport_failure(inner, &sender);
    let mut state = lock_state(&inner.state);
    if !must_close && !inner.shutdown.load(Ordering::SeqCst) && state.total() < inner.pool_max {
        state.free.push(PoolEntry {
            sender,
            last_idle_at: Instant::now(),
        });
    }
    drop(state);
}

fn record_sender_transport_failure(inner: &Arc<DbInner>, sender: &ColumnSender) {
    if sender.transport_dead()
        && let Some(idx) = sender.endpoint_idx()
    {
        lock_health(&inner.health).record_mid_stream_failure(idx);
    }
}

fn spawn_reaper(inner: Arc<DbInner>) -> std::io::Result<JoinHandle<()>> {
    let tick = reaper_tick(inner.pool_idle_timeout);
    thread::Builder::new()
        .name("questdb-column-sender-pool-reaper".to_string())
        .spawn(move || reaper_loop(inner, tick))
}

fn reaper_tick(idle_timeout: Duration) -> Duration {
    let twelfth = idle_timeout / 12;
    if twelfth > REAPER_MIN_TICK {
        twelfth
    } else {
        REAPER_MIN_TICK
    }
}

fn reaper_loop(inner: Arc<DbInner>, tick: Duration) {
    loop {
        // Check shutdown WHILE holding the lock so a concurrent Drop's
        // notify-under-lock is never lost: Drop sets `shutdown` then
        // acquires the same lock to notify, so either we observe
        // `shutdown=true` before sleeping or we are sleeping when the
        // notify arrives.
        let state = lock_state(&inner.state);
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        let (state, _) = inner
            .cv
            .wait_timeout(state, tick)
            .unwrap_or_else(|e| e.into_inner());
        if inner.shutdown.load(Ordering::SeqCst) {
            break;
        }
        drop(state);
        reap_idle_inner(&inner);
    }
}

fn reap_idle_inner(inner: &DbInner) -> usize {
    let mut dropped = reap_idle_senders(inner);
    dropped += reap_idle_row_senders(inner);
    #[cfg(feature = "_egress")]
    {
        dropped += reap_idle_readers(inner);
    }
    dropped
}

fn drain_idle_inner(inner: &DbInner) -> usize {
    let mut dropped = drain_idle_senders(inner);
    dropped += drain_idle_row_senders(inner);
    #[cfg(feature = "_egress")]
    {
        dropped += drain_idle_readers(inner);
    }
    dropped
}

fn drain_idle_senders(inner: &DbInner) -> usize {
    let to_drop: Vec<ColumnSender> = {
        let mut state = lock_state(&inner.state);
        state.free.drain(..).map(|entry| entry.sender).collect()
    };
    let dropped = to_drop.len();
    drop(to_drop);
    dropped
}

fn drain_idle_row_senders(inner: &DbInner) -> usize {
    let to_drop: Vec<Sender> = {
        let mut state = lock_row_sender_state(&inner.row_sender_state);
        state.free.drain(..).map(|entry| entry.sender).collect()
    };
    let dropped = to_drop.len();
    drop(to_drop);
    dropped
}

#[cfg(feature = "_egress")]
fn drain_idle_readers(inner: &DbInner) -> usize {
    let to_drop: Vec<Reader> = {
        let mut state = lock_reader_state(&inner.reader_state);
        state.free.drain(..).map(|entry| entry.reader).collect()
    };
    let dropped = to_drop.len();
    drop(to_drop);
    dropped
}

fn reap_idle_senders(inner: &DbInner) -> usize {
    // Drop the to-be-closed connections OUTSIDE the lock so closing a connection
    // (which may take an unbounded amount of time) does not stall concurrent
    // borrows.
    let to_drop: Vec<ColumnSender> = {
        let mut state = lock_state(&inner.state);
        let mut to_drop = Vec::new();
        let now = Instant::now();
        // Free-list is oldest at front, newest at back (push on return /
        // pop on borrow). We must protect `total() >= pool_size` after the
        // drop, so we count current total once and only drop if total stays
        // above the floor.
        let mut i = 0;
        while i < state.free.len() {
            if state.total() <= inner.pool_size {
                break;
            }
            let idle_for = now.saturating_duration_since(state.free[i].last_idle_at);
            if idle_for > inner.pool_idle_timeout {
                let entry = state.free.remove(i);
                to_drop.push(entry.sender);
            } else {
                i += 1;
            }
        }
        to_drop
    };
    let dropped = to_drop.len();
    drop(to_drop);
    dropped
}

fn reap_idle_row_senders(inner: &DbInner) -> usize {
    // Row-sender pool is lazy-init (no pre-population at connect), so there is
    // no warm-min floor to preserve — reap any sender parked longer than the
    // idle timeout.
    let to_drop: Vec<Sender> = {
        let mut state = lock_row_sender_state(&inner.row_sender_state);
        let mut to_drop = Vec::new();
        let now = Instant::now();
        let mut i = 0;
        while i < state.free.len() {
            let idle_for = now.saturating_duration_since(state.free[i].last_idle_at);
            if idle_for > inner.pool_idle_timeout {
                let entry = state.free.remove(i);
                to_drop.push(entry.sender);
            } else {
                i += 1;
            }
        }
        to_drop
    };
    let dropped = to_drop.len();
    drop(to_drop);
    dropped
}

#[cfg(feature = "_egress")]
fn reap_idle_readers(inner: &DbInner) -> usize {
    // Reader pool is lazy-init (no pre-population at connect), so there
    // is no warm-min floor to preserve — reap any reader that has been
    // parked longer than the idle timeout.
    let to_drop: Vec<Reader> = {
        let mut state = lock_reader_state(&inner.reader_state);
        let mut to_drop = Vec::new();
        let now = Instant::now();
        let mut i = 0;
        while i < state.free.len() {
            let idle_for = now.saturating_duration_since(state.free[i].last_idle_at);
            if idle_for > inner.pool_idle_timeout {
                let entry = state.free.remove(i);
                to_drop.push(entry.reader);
            } else {
                i += 1;
            }
        }
        to_drop
    };
    let dropped = to_drop.len();
    drop(to_drop);
    dropped
}

const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<QuestDb>();
    #[cfg(feature = "ffi-support")]
    {
        fn assert_send<T: Send>() {}
        assert_send::<OwnedColumnSender>();
    }
};

const _: fn() = || {
    trait AmbiguousIfSend<A> {
        fn _disambiguate() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}
    fn assert_not_send<T: ?Sized>() {
        let _: fn() = <T as AmbiguousIfSend<_>>::_disambiguate;
    }
    assert_not_send::<BorrowedColumnSender<'_>>();
    assert_not_send::<BorrowedRowSender<'_>>();
    #[cfg(feature = "_egress")]
    assert_not_send::<BorrowedReader<'_>>();
    assert_not_send::<crate::ingress::column_sender::Chunk<'_>>();
};
