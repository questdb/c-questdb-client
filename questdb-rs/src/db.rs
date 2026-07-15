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

//! QWP ingestion connection pool.
//!
//! `QuestDb` is a thread-safe pool of store-and-forward producer handles to a
//! single QuestDB QWP/WebSocket endpoint. The pool is lazy: `connect` performs
//! no blocking network I/O. In disk-backed store-and-forward mode it may
//! pre-open parked recovery senders whose initial connect and replay run in the
//! background. Borrowing [`QuestDb::borrow_sender`] creates a local
//! store-and-forward producer immediately and lets its background runner connect
//! later, so callers can buffer while the server is absent. Direct ingestion
//! senders and readers still open their transport on first borrow.
//! The pools auto-grow up to `pool_max` on demand and (under `pool_reap=auto`)
//! run a background thread that closes above-`pool_size` idle entries after
//! `pool_idle_timeout_ms`.
//!
//! Each pool slot is handed out as a [`BorrowedSender`] which returns
//! itself to the pool on `Drop`. Slots whose underlying connection has
//! latched terminal state are dropped on return instead of being
//! recycled.

use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
#[cfg(feature = "_egress")]
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(feature = "_egress")]
use crate::egress::Reader;
use crate::ingress::conn_events;
use crate::ingress::sender::is_candidate_orphan;
use crate::ingress::sender::qwp_ws::QwpWsHostHealthTracker;
use crate::ingress::{Buffer, SenderBuilder};
use crate::ingress::{
    QwpWsConnector, QwpWsManagedSlotExclusion, RawQwpWsRoundStream, ReconnectReason,
};
// The reconnect backoff helpers are only consumed by the retry-capable borrow
// paths: Polars `reborrow_with_retry` and the FFI owned
// `*_with_retry` entry points. Keep the import unconditional (so the shared
// re-export chain that feeds it stays live) but quiet the unused-import lint in
// the plain library build that compiles neither retry path.
#[cfg_attr(
    not(any(
        feature = "polars-ingress",
        feature = "polars-egress",
        feature = "ffi-support"
    )),
    allow(unused_imports)
)]
use crate::ingress::{reconnect_backoff_step, reconnect_error_is_terminal};
use crate::{Result, error};

/// Connect-string parsing for the [`QuestDb`] pool. Shared by every borrow
/// kind (store-and-forward ingestion, direct ingestion, reader), so it lives
/// with the pool rather than under a payload encoder.
mod conf;

use crate::ingress::AckLevel;
use crate::ingress::column_sender::conn::ColumnConn;
use crate::ingress::column_sender::{DirectSenderCore, PooledSenderCore};
use conf::PoolReap;

/// FFI escape-hatch surface: owned (lifetime-free) pool handles and the entry
/// points that mint them, for the `questdb-rs-ffi` C-ABI crate. Hidden,
/// feature-gated, and not part of the public Rust API — normal Rust users
/// borrow lifetime-bound handles via [`QuestDb::borrow_sender`] (and, with
/// egress, `QuestDb::borrow_reader`).
/// Only `questdb-rs-ffi` enables the `ffi-support` feature.
#[cfg(feature = "ffi-support")]
#[doc(hidden)]
pub mod ffi_support;

/// Lower bound on the reaper's wake interval.
const REAPER_MIN_TICK: Duration = Duration::from_secs(5);

/// Poison-tolerant lock helper. The pool must survive a panic in another
/// thread's locked region: under `panic=abort` (FFI consumers) poisoning
/// can never be observed, but `questdb-rs` library consumers run with
/// `panic=unwind` and a single panicking thread would otherwise turn
/// every subsequent borrow/return into a panic via `.expect("poisoned")`.
fn lock_state<S>(m: &Mutex<PoolState<S>>) -> std::sync::MutexGuard<'_, PoolState<S>> {
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

/// RAII guard that increments `state.in_use` on construction and
/// decrements it on drop unless [`InUseSlot::commit`] is called first.
/// Closes the leak window between `state.in_use += 1` and the connect
/// round: a panic in the connect path (allocator OOM,
/// TLS handshake panic) would otherwise skip the matching decrement
/// and permanently strand a pool slot.
struct InUseSlot<'a, S> {
    state: &'a Mutex<PoolState<S>>,
    cv: &'a Condvar,
    slot_index: Option<usize>,
    armed: bool,
}

impl<S> InUseSlot<'_, S> {
    fn commit(mut self) {
        self.armed = false;
    }
}

impl<S> Drop for InUseSlot<'_, S> {
    fn drop(&mut self) {
        if self.armed {
            let mut state = lock_state(self.state);
            state.in_use = state.in_use.saturating_sub(1);
            state.free_slot_index(self.slot_index);
            self.cv.notify_all();
        }
    }
}

#[cfg(feature = "_egress")]
struct ReaderInUseSlot<'a> {
    state: &'a Mutex<ReaderPoolState>,
    armed: bool,
}

#[cfg(feature = "_egress")]
impl ReaderInUseSlot<'_> {
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

struct SenderSlotRelease<'a> {
    inner: &'a DbInner,
    slot_index: Option<usize>,
    decrement_in_use: bool,
    decrement_closing: bool,
}

impl Drop for SenderSlotRelease<'_> {
    fn drop(&mut self) {
        if self.slot_index.is_none() && !self.decrement_in_use && !self.decrement_closing {
            return;
        }
        let mut state = lock_state(&self.inner.state);
        if self.decrement_in_use {
            state.in_use = state.in_use.saturating_sub(1);
        }
        if self.decrement_closing {
            state.closing = state.closing.saturating_sub(1);
        }
        state.free_slot_index(self.slot_index);
        self.inner.cv.notify_all();
    }
}

/// Connection pool for QWP/WebSocket ingestion and egress.
///
/// Construct with [`QuestDb::connect`]. Share the pool across threads — its
/// internal state is `Mutex`-guarded so [`QuestDb::borrow_sender`] /
/// [`QuestDb::reap_idle`] / Drop-driven returns are safe to interleave.
///
/// Each borrow ([`BorrowedSender`] / the internal direct sender) is **not**
/// `Send` — it belongs to the thread that borrowed it. To ingest in parallel,
/// borrow one sender per worker thread from the same `QuestDb`.
pub struct QuestDb {
    inner: Arc<DbInner>,
    reaper: Option<JoinHandle<()>>,
}

struct DbInner {
    /// Original connect string. Kept verbatim so the reader pool
    /// (`Reader::from_conf`) can spin up a new connection with the same
    /// settings. The sender pools connect through pre-parsed builders so they
    /// can override only the managed disk-SF slot id.
    #[cfg(feature = "_egress")]
    conf: String,
    /// Resolved, reusable QWP/WebSocket connect ingredients (endpoint list,
    /// TLS, auth, config). Every sender connection — first-borrow open,
    /// auto-grow, and failover re-borrow — opens through this connector so it rotates
    /// across the configured endpoints. A single-endpoint pool behaves
    /// exactly as before (one endpoint, no rotation).
    connector: QwpWsConnector,
    /// Buffer-factory configuration retained directly on the pool root so a
    /// caller can create a QWP/WebSocket Buffer without borrowing a sender.
    buffer_max_name_len: usize,
    /// One health tracker shared by every connect attempt. A connect failure
    /// or a mid-stream transport death marks the offending endpoint unhealthy
    /// so subsequent borrows skip it until it re-probes healthy; role rejects
    /// rotate to the writable primary. Pool-level (not per-conn) so the pool
    /// stops handing out connections to a dead peer rather than rediscovering
    /// it one connection at a time.
    health: Mutex<QwpWsHostHealthTracker>,
    pool_size: usize,
    pool_max: usize,
    /// `sf_dir` set: store-and-forward senders use pool-minted disk slots.
    sf_disk: bool,
    /// Configured `sender_id` kept as the slot base. Disk-backed pool slots are
    /// minted as `<base>-ingest-<index>`.
    slot_base_id: String,
    /// Managed ingestion slot range excluded from orphan scans so sibling
    /// senders do not adopt each other's live pool slots.
    managed_slot_exclusion: Option<QwpWsManagedSlotExclusion>,
    pool_idle_timeout: Duration,
    /// Optional connection lifecycle event source (dispatcher + attempt
    /// counter + success-classification state). Set at most once via
    /// [`QuestDb::set_connection_listener`]; every ingress pool connect
    /// and transport-death return reports through it.
    conn_events: OnceLock<conn_events::ConnectionEventSource>,
    state: Mutex<PoolState<PooledSenderCore>>,
    /// Always-direct column-sender pool, independent of `sf_dir`. Backs
    /// [`QuestDb::borrow_direct_column_sender`] (DataFrame ingestion). Lazy-init
    /// like the reader pool: starts empty, opens a direct
    /// connection on demand, recycles through its own free list and the shared
    /// `pool_max` cap. Kept separate from `state` so DataFrame ingest always
    /// gets a plain pipelined connection even when `state` is in
    /// store-and-forward mode.
    direct_state: Mutex<PoolState<DirectSenderCore>>,
    /// Reader pool. Lazy-init: starts empty, populated on first
    /// `borrow_reader_owned` call. Applies the same `pool_size` /
    /// `pool_max` / `pool_idle_timeout` values as the sender pool but
    /// tracks and caps them on an independent free list, so heavy ingest
    /// can't starve queries. The caps are enforced separately, so the
    /// combined live connection count across the store-and-forward ingress,
    /// direct ingestion, and reader pools can reach up to `3 * pool_max`.
    #[cfg(feature = "_egress")]
    reader_state: Mutex<ReaderPoolState>,
    /// Wakes the reaper thread on `shutdown` and lets a disk-SF borrow wait
    /// briefly for an in-flight slot close to release its flock.
    cv: Condvar,
    shutdown: AtomicBool,
}

#[derive(Default)]
struct SlotReservations(Option<Vec<bool>>);

impl SlotReservations {
    fn with_disk_slots(pool_max: usize) -> Self {
        Self(Some(vec![false; pool_max]))
    }

    fn reserved_total(&self, fallback_total: usize) -> usize {
        match &self.0 {
            Some(slots) => slots.iter().filter(|in_use| **in_use).count(),
            None => fallback_total,
        }
    }

    fn allocate(&mut self) -> Option<usize> {
        let slots = self.0.as_mut()?;
        let index = slots.iter().position(|in_use| !*in_use)?;
        slots[index] = true;
        Some(index)
    }

    fn reserve(&mut self, index: usize) -> bool {
        let Some(slots) = self.0.as_mut() else {
            return false;
        };
        let Some(slot) = slots.get_mut(index) else {
            return false;
        };
        if *slot {
            return false;
        }
        *slot = true;
        true
    }

    fn free(&mut self, slot_index: Option<usize>) {
        if let (Some(slots), Some(index)) = (&mut self.0, slot_index)
            && let Some(slot) = slots.get_mut(index)
        {
            *slot = false;
        }
    }
}

struct PoolState<S> {
    /// Idle connections. Borrow/return is LIFO on the back (push/pop);
    /// the reaper drains the oldest entries from the front. Keeps hot
    /// connections warm in the common case while the reaper still
    /// retires entries in age order.
    free: Vec<PoolEntry<S>>,
    /// Sum of currently-borrowed senders + in-flight grow operations.
    in_use: usize,
    /// Reserved disk slots whose sender has started close/drop but has not yet
    /// released the slot flock. Borrowers at cap may wait for this to complete.
    closing: usize,
    /// Disk-backed store-and-forward slot reservations. Empty for in-memory
    /// SF and direct senders; populated for pool-minted disk slot indices.
    slots: SlotReservations,
}

impl<S> Default for PoolState<S> {
    fn default() -> Self {
        Self {
            free: Vec::new(),
            in_use: 0,
            closing: 0,
            slots: SlotReservations::default(),
        }
    }
}

impl<S> PoolState<S> {
    fn total(&self) -> usize {
        self.free.len() + self.in_use
    }

    fn with_disk_slots(pool_max: usize) -> Self {
        Self {
            free: Vec::new(),
            in_use: 0,
            closing: 0,
            slots: SlotReservations::with_disk_slots(pool_max),
        }
    }

    fn reserved_total(&self) -> usize {
        self.slots.reserved_total(self.total())
    }

    fn allocate_slot_index(&mut self) -> Option<usize> {
        self.slots.allocate()
    }

    fn reserve_slot_index(&mut self, index: usize) -> bool {
        self.slots.reserve(index)
    }

    fn free_slot_index(&mut self, slot_index: Option<usize>) {
        self.slots.free(slot_index);
    }
}

struct PoolEntry<S> {
    sender: S,
    slot_index: Option<usize>,
    last_idle_at: Instant,
}

struct PooledSender<S> {
    sender: S,
    slot_index: Option<usize>,
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

/// Connection counts for a single pool inside a [`QuestDb`], part of the
/// unstable diagnostics snapshot returned by [`QuestDb::dbg_pool_counts`].
///
/// **Not semver-stable.** `#[doc(hidden)]` and `#[non_exhaustive]`; exists for
/// soak / leak harnesses to assert the pool drains back to a steady baseline
/// after load and failover episodes.
#[doc(hidden)]
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DbgPoolCount {
    /// Idle connections parked on the free list.
    pub free: usize,
    /// Borrowed connections plus in-flight grow operations.
    pub in_use: usize,
    /// Disk store-and-forward slots that have begun close/drop but have not
    /// yet released their slot flock. Always 0 for the direct and reader
    /// pools (they hold no disk slots).
    pub closing: usize,
}

/// Per-pool connection-count snapshot for a [`QuestDb`], for soak / leak
/// diagnostics. **Not semver-stable** (`#[doc(hidden)]`, `#[non_exhaustive]`).
///
/// Each pool is capped independently at `pool_max`, so `free + in_use` summed
/// across all three fields can reach `3 * pool_max` when egress is enabled.
#[doc(hidden)]
#[non_exhaustive]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DbgPoolCounts {
    /// Store-and-forward ingestion pool (the pool behind `borrow_sender`).
    pub ingress: DbgPoolCount,
    /// Always-direct column-sender pool (DataFrame ingest, the pool behind
    /// `borrow_direct_column_sender`).
    pub column_direct: DbgPoolCount,
    /// Reader (egress) pool. Always zero when the crate is built without an
    /// egress feature.
    pub reader: DbgPoolCount,
}

struct ManagedSlotRecoveryCandidate {
    index: usize,
    path: PathBuf,
}

#[derive(Default)]
struct ManagedSlotRecoveryScan {
    in_range: Vec<ManagedSlotRecoveryCandidate>,
    out_of_range: Vec<PathBuf>,
}

fn managed_slot_exclusion(base: &str, pool_max: usize) -> QwpWsManagedSlotExclusion {
    QwpWsManagedSlotExclusion::new(managed_slot_prefix(base), pool_max)
}

fn managed_slot_id(base: &str, index: usize) -> String {
    managed_slot_exclusion(base, usize::MAX).slot_name(index)
}

fn managed_slot_prefix(base: &str) -> String {
    format!("{base}-ingest-")
}

fn parse_managed_slot_id(base: &str, name: &str) -> Option<usize> {
    managed_slot_exclusion(base, usize::MAX).parse_index(name)
}

fn managed_slot_recovery_candidates(inner: &DbInner) -> Vec<PathBuf> {
    if !inner.sf_disk {
        return Vec::new();
    }
    let Some(sf_dir) = inner.connector.sf_dir() else {
        return Vec::new();
    };
    managed_slot_recovery_candidates_from(sf_dir, &inner.slot_base_id, inner.pool_max)
}

fn managed_slot_recovery_candidates_from(
    sf_dir: &Path,
    base: &str,
    pool_max: usize,
) -> Vec<PathBuf> {
    managed_slot_recovery_scan_from(sf_dir, base, pool_max).out_of_range
}

fn managed_slot_recovery_scan_from(
    sf_dir: &Path,
    base: &str,
    pool_max: usize,
) -> ManagedSlotRecoveryScan {
    let Ok(entries) = std::fs::read_dir(sf_dir) else {
        return ManagedSlotRecoveryScan::default();
    };
    let mut scan = ManagedSlotRecoveryScan::default();
    for entry in entries.flatten() {
        let slot_path = entry.path();
        if !slot_path.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(index) = parse_managed_slot_id(base, &name) else {
            continue;
        };
        if !is_candidate_orphan(&slot_path) {
            continue;
        }
        // In-range managed slots are owned by this live pool even when they
        // are not currently borrowed. They are pre-opened by connect-time
        // recovery, so a sibling drainer must not take their flock.
        if index < pool_max {
            scan.in_range.push(ManagedSlotRecoveryCandidate {
                index,
                path: slot_path,
            });
        } else {
            // This scan runs for every managed sender build, so the warning may
            // repeat for the same directory until one drainer drains it. A
            // DbInner-level dedupe set is a follow-up, not part of this fix.
            log::warn!(
                "adopting out-of-range store-and-forward slot `{}`; \
                 `<sender_id>-ingest-*` directories under \
                 sf_dir belong to the QuestDb pool namespace, so use a unique \
                 sender_id for pools sharing an sf_dir",
                slot_path.display()
            );
            scan.out_of_range.push(slot_path);
        }
    }
    scan
}

/// Pre-open dirty in-range disk-SF slots at connect so a restart at lower
/// concurrency still replays all recoverable queued frames without waiting for
/// the exact high index to be borrowed again.
///
/// Recovery senders count toward the ingestion pool total like ordinary parked
/// senders. They are reaped only after their queues are delivered and idle past
/// the timeout, and drain on pool close via `drain_sfa_senders_bounded`. Each
/// pre-opened sender also enrolls out-of-range managed slots in its
/// orphan-drainer set, so those slots may begin replay at connect as well.
fn preopen_recovery_senders(inner: &Arc<DbInner>) {
    if !inner.sf_disk {
        return;
    }
    let Some(sf_dir) = inner.connector.sf_dir() else {
        return;
    };
    let scan = managed_slot_recovery_scan_from(sf_dir, &inner.slot_base_id, inner.pool_max);
    for candidate in scan.in_range {
        preopen_recovery_sender(inner, candidate.index, &candidate.path, &scan.out_of_range);
    }
}

fn preopen_recovery_sender(
    inner: &Arc<DbInner>,
    index: usize,
    slot_path: &Path,
    recovery_candidates: &[PathBuf],
) {
    let slot = {
        let mut state = lock_state(&inner.state);
        if !state.reserve_slot_index(index) {
            return;
        }
        state.in_use += 1;
        InUseSlot {
            state: &inner.state,
            cv: &inner.cv,
            slot_index: Some(index),
            armed: true,
        }
    };

    match connect_sfa_pool_with_recovery_candidates(inner, Some(index), recovery_candidates) {
        Ok(sender) => {
            let slot_index = slot.slot_index;
            {
                let mut state = lock_state(&inner.state);
                state.in_use = state.in_use.saturating_sub(1);
                state.free.push(PoolEntry {
                    sender,
                    slot_index,
                    last_idle_at: Instant::now(),
                });
            }
            slot.commit();
            inner.cv.notify_all();
        }
        Err(err) => {
            log::warn!(
                "skipping parked store-and-forward ingestion slot `{}` during recovery: {}",
                slot_path.display(),
                err
            );
        }
    }
}

impl QuestDb {
    /// Open a pool against `conf`.
    ///
    /// The connect string must use a QWP/WebSocket schema (`ws::` /
    /// `wss::` / `ws::` / `wss::`). Pool-specific keys are recognised:
    ///
    /// | Key                    | Default | Meaning                                                        |
    /// |------------------------|---------|----------------------------------------------------------------|
    /// | `pool_size`            | 1       | Warm / minimum entries once opened. |
    /// | `pool_max`             | 64      | Hard cap on auto-grow. |
    /// | `pool_idle_timeout_ms` | 60000   | Above-`pool_size` idle connections are closed after this long. |
    /// | `pool_reap`            | `auto`  | `auto` runs a background reaper; `manual` requires `reap_idle`. |
    ///
    /// [`Self::borrow_sender`] is always store-and-forward (in-memory when no
    /// `sf_dir`, disk-backed when set). Setting `sf_dir` gives every pooled
    /// sender its own slot directory, minted from the configured `sender_id`
    /// base as `<base>-ingest-<index>`. Those `<sender_id>-ingest-*`
    /// directories are reserved for this pool namespace under `sf_dir`; use a
    /// unique `sender_id` for each pool that shares an `sf_dir`.
    /// `pool_size` / `pool_max` apply once to this unified ingestion pool. At
    /// cap, borrows return `InvalidApiCall` except disk-backed
    /// ingestion borrows can wait up to `close_flush_timeout` (default 5s)
    /// while an in-flight slot close releases its lock. For a plain pipelined
    /// (non-SF) connection — used by DataFrame ingestion — see
    /// [`Self::borrow_direct_column_sender`].
    ///
    /// Pools are **lazy**: `connect` performs no blocking network I/O. In
    /// disk-backed store-and-forward mode, it may pre-open parked recovery
    /// senders whose initial connect and replay run in the background. The
    /// store-and-forward ingestion pool creates a local producer on first borrow
    /// and starts its initial connect in the background, so the borrower can
    /// buffer immediately even while the server is absent. Direct senders and
    /// readers still open their transport on first borrow. `pool_size` is the
    /// warm minimum the reaper keeps once entries have been opened.
    ///
    /// # Store-and-forward durability
    ///
    /// Disk store-and-forward (`sf_dir`) writes queued frames and their symbol
    /// dictionary to disk but does **not** `fsync` — the data is *page-cache
    /// durable*, matching the standalone QWP/WebSocket sender. That survives a **process / JVM
    /// crash** (unacked frames replay on the next borrow / recovery), but **not**
    /// a **host / power crash**, which can lose or tear unflushed pages. A
    /// recovery that finds a torn symbol dictionary (or a frame whose dictionary
    /// cannot be re-registered on the fresh server) fails loudly with a
    /// **terminal, resend-required** error —
    /// [`StoreResendRequired`](crate::ErrorCode::StoreResendRequired), a code
    /// *distinct from* the transient [`SocketError`](crate::ErrorCode::SocketError)
    /// you would retry, so callers can branch on it directly. The sender's own
    /// reconnect/failover loops treat it as terminal (they stop) rather than
    /// retrying it to their deadline. Those rows must be re-ingested from their
    /// source, not retried in place.
    /// In-memory store-and-forward (no `sf_dir`) has no cross-restart durability.
    ///
    pub fn connect(conf: &str) -> Result<Self> {
        let parsed = conf::parse(conf)?;
        // The public ingestion pool is always store-and-forward: in-memory
        // queues when no `sf_dir`, disk-backed pool-minted slots when set.
        let sf_disk = parsed.sf_disk;
        let pool_cfg = parsed.pool;

        let builder = SenderBuilder::from_conf(conf)?;
        let buffer_max_name_len = builder.configured_max_name_len();
        let connector = builder.build_qwp_ws_connector()?;
        let health = QwpWsHostHealthTracker::new(connector.endpoint_count());
        let slot_base_id = connector.sender_id().to_owned();
        let managed_slot_exclusion = if sf_disk {
            Some(managed_slot_exclusion(&slot_base_id, pool_cfg.pool_max))
        } else {
            None
        };

        // Start empty; connect-time recovery may pre-open dirty disk-SF slots
        // after `inner` exists, otherwise the pools open on first borrow.
        let free = Vec::new();

        let inner = Arc::new(DbInner {
            #[cfg(feature = "_egress")]
            conf: conf.to_owned(),
            connector,
            buffer_max_name_len,
            health: Mutex::new(health),
            pool_size: pool_cfg.pool_size,
            pool_max: pool_cfg.pool_max,
            sf_disk,
            slot_base_id,
            managed_slot_exclusion,
            pool_idle_timeout: pool_cfg.pool_idle_timeout,
            state: Mutex::new(if sf_disk {
                PoolState::with_disk_slots(pool_cfg.pool_max)
            } else {
                PoolState {
                    free,
                    ..PoolState::default()
                }
            }),
            direct_state: Mutex::new(PoolState::default()),
            #[cfg(feature = "_egress")]
            reader_state: Mutex::new(ReaderPoolState::default()),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
            conn_events: OnceLock::new(),
        });

        preopen_recovery_senders(&inner);

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

    /// Create a caller-owned QWP/WebSocket row buffer using this pool's
    /// configured table/column name limit. The buffer is independent of any
    /// particular sender borrow and may be filled or moved before it is
    /// published by a store-and-forward sender from this pool.
    pub fn new_buffer(&self) -> Buffer {
        Buffer::qwp_ws_with_max_name_len(self.inner.buffer_max_name_len)
    }

    /// Configured name limit used by [`Self::new_buffer`]. Exposed for the C++
    /// wrapper so a moved-from buffer can lazily recreate the same kind of
    /// buffer without retaining a pool reference.
    #[doc(hidden)]
    pub fn buffer_max_name_len(&self) -> usize {
        self.inner.buffer_max_name_len
    }

    /// Borrow a sender.
    ///
    /// Selection: pop the most-recently-returned slot from the free list;
    /// failing that, open a new connection if we are below `pool_max`;
    /// failing that, in disk-backed store-and-forward mode only, wait up to
    /// `close_flush_timeout` (default 5s) while an in-flight slot close
    /// releases its lock; failing that, return `InvalidApiCall`.
    pub fn borrow_sender(&self) -> Result<BorrowedSender<'_>> {
        let cs = self.pick_sender()?;
        Ok(BorrowedSender(SenderHandle::new(self, cs)))
    }

    /// Borrow a **direct** (non-store-and-forward) column sender from the
    /// always-direct pool, independent of `sf_dir`.
    ///
    /// Not part of the public API: the direct sender is the transport behind
    /// [`Self::flush_arrow_batch`] / [`Self::flush_polars_dataframe`], which own
    /// their own commit + replay. Hidden from the docs; callers ingest through
    /// those entry points rather than handling a sender.
    #[doc(hidden)]
    pub fn borrow_direct_column_sender(&self) -> Result<BorrowedDirectColumnSender<'_>> {
        let cs = pick_direct_sender(&self.inner)?;
        Ok(BorrowedDirectColumnSender(DirectSenderHandle::new(
            self, cs,
        )))
    }

    /// Flush a single Arrow [`RecordBatch`](arrow::array::RecordBatch) to
    /// `table` in one call.
    ///
    /// This is the recommended entry point for one-off Arrow ingestion: it
    /// borrows a direct column sender from the pool, publishes the batch as a
    /// commit boundary, waits for the server `Ok` ack, and returns the sender
    /// to the pool — callers never handle a sender.
    ///
    /// `timestamp_column` selects where each row's designated timestamp comes
    /// from:
    /// * `Some(col)` — source it from the named `Timestamp(_)` column of
    ///   `batch` (mirrors the old `flush_arrow_batch_at_column`).
    /// * `None` — let the server stamp each row on arrival (mirrors the old
    ///   `flush_arrow_batch_at_now`).
    ///
    /// `overrides` carries per-column wire-type hints (e.g. promote a UTF-8
    /// column to SYMBOL, or a UInt32 to IPv4); pass `&[]` when the Arrow schema
    /// is self-describing.
    ///
    /// `ack_level` chooses how far the call blocks before returning:
    /// * `None` — wait for the connect string's default, i.e. the same level
    ///   the store-and-forward senders use: [`AckLevel::Durable`] when
    ///   `request_durable_ack=on`, otherwise [`AckLevel::Ok`].
    /// * `Some(level)` — wait for exactly `level`. Requesting
    ///   [`AckLevel::Durable`] without `request_durable_ack=on` is rejected with
    ///   [`ErrorCode::InvalidApiCall`].
    ///
    /// The call publishes the batch as a commit boundary and blocks until the
    /// resolved ack level is reached, so the rows are durable when it returns
    /// `Ok(())`. On a transient [`ErrorCode::FailoverRetry`] it surfaces the
    /// error rather than replaying (the batch is fully owned by the caller, so
    /// retrying is a plain re-call); the DataFrame path
    /// ([`Self::flush_polars_dataframe`]) re-drives automatically instead.
    ///
    /// [`ErrorCode::FailoverRetry`]: crate::ErrorCode::FailoverRetry
    /// [`ErrorCode::InvalidApiCall`]: crate::ErrorCode::InvalidApiCall
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch<'t, T>(
        &self,
        table: T,
        batch: &arrow::array::RecordBatch,
        timestamp_column: Option<crate::ingress::ColumnName<'_>>,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
        ack_level: Option<AckLevel>,
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let ack = ack_level.unwrap_or_else(|| self.default_ack_level());
        let mut sender = self.borrow_direct_column_sender()?;
        // `table` is moved into exactly one arm, so the generic `T` flows
        // straight through to the chosen `_and_wait` method unchanged.
        match timestamp_column {
            Some(ts) => {
                sender.flush_arrow_batch_at_column_and_wait(table, batch, ts, overrides, ack)
            }
            None => sender.flush_arrow_batch_at_now_and_wait(table, batch, overrides, ack),
        }
    }

    /// The ack level these convenience flushes wait for when the caller does
    /// not name one: [`AckLevel::Durable`] when the connect string set
    /// `request_durable_ack=on`, otherwise [`AckLevel::Ok`]. Mirrors the level
    /// the store-and-forward senders use for the same pool.
    #[cfg(feature = "arrow-ingress")]
    pub(crate) fn default_ack_level(&self) -> AckLevel {
        if self.inner.connector.request_durable_ack() {
            AckLevel::Durable
        } else {
            AckLevel::Ok
        }
    }

    /// FFI escape hatch: like [`Self::borrow_sender`] but the returned
    /// handle is not lifetime-bound to `&self`. Carries an `Arc<DbInner>`
    /// internally so it can outlive the user-facing `QuestDb` pointer
    /// (the pool's return path stays alive as long as any borrow is
    /// outstanding; after pool close, returned handles are dropped instead of
    /// recycled).
    ///
    /// Hidden from the Rust API because Rust callers should prefer the
    /// lifetime-bound `borrow_sender`, which catches use-after-close at
    /// compile time. C callers reach this through `questdb_db_borrow_sender`.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_sender_owned(&self) -> Result<OwnedSender> {
        let cs = self.pick_sender()?;
        Ok(OwnedSender::new(Arc::clone(&self.inner), cs))
    }

    /// Like [`borrow_sender_owned`] but retries the connect within `budget`
    /// using the pool's reconnect backoff (the cluster may be electing a
    /// primary). Backs the C ABI's `questdb_db_borrow_sender_with_retry`.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_sender_owned_with_retry(&self, budget: Duration) -> Result<OwnedSender> {
        let deadline = Instant::now().checked_add(budget);
        let cs = reconnect_pick(&self.inner, deadline, pick_sfa_sender)?;
        Ok(OwnedSender::new(Arc::clone(&self.inner), cs))
    }

    /// FFI escape hatch: like [`Self::borrow_direct_column_sender`] but the
    /// returned handle is not lifetime-bound to `&self` (carries an
    /// `Arc<DbInner>` so it can outlive the user-facing `QuestDb` pointer).
    /// Backs the C ABI's `questdb_db_borrow_direct_column_sender`. Hidden from
    /// the Rust API; Rust callers should prefer the lifetime-bound
    /// [`Self::borrow_direct_column_sender`].
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_direct_column_sender_owned(&self) -> Result<OwnedDirectColumnSender> {
        let cs = pick_direct_sender(&self.inner)?;
        Ok(OwnedDirectColumnSender::new(Arc::clone(&self.inner), cs))
    }

    /// Like [`borrow_direct_column_sender_owned`] but retries the connect
    /// within `budget` using the reconnect backoff. Backs the C ABI's
    /// `questdb_db_borrow_direct_column_sender_with_retry`.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_direct_column_sender_owned_with_retry(
        &self,
        budget: Duration,
    ) -> Result<OwnedDirectColumnSender> {
        let deadline = Instant::now().checked_add(budget);
        let cs = reconnect_pick(&self.inner, deadline, pick_direct_sender)?;
        Ok(OwnedDirectColumnSender::new(Arc::clone(&self.inner), cs))
    }

    fn pick_sender(&self) -> Result<PooledSender<PooledSenderCore>> {
        pick_sfa_sender(&self.inner)
    }

    fn pick_replacement_sender(&self) -> Result<PooledSender<DirectSenderCore>> {
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QuestDb pool is closed; cannot replace sender"
            ));
        }
        // Same-handle replacement: the borrowed direct sender already owns one
        // logical in-use slot, so this must not reserve another one or
        // pool_max=1 would reject replacing a dead direct connection.
        if let Some(entry) = lock_state(&self.inner.direct_state).free.pop() {
            return Ok(PooledSender {
                sender: entry.sender,
                slot_index: entry.slot_index,
            });
        }

        let conn = connect_conn_pool(&self.inner)?;
        Ok(PooledSender {
            sender: DirectSenderCore::new(
                conn,
                crate::ingress::SymbolGlobalDict::new(),
                crate::ingress::column_sender::encoder::EncodeScratch::new(),
                false,
            ),
            slot_index: None,
        })
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

    /// Register a connection lifecycle listener for this pool's ingress
    /// connections. Events (see
    /// [`ConnectionEventKind`](crate::ingress::ConnectionEventKind)) are
    /// delivered on a dedicated dispatcher thread through a bounded
    /// inbox — a slow listener can never stall connect, publish, or
    /// reconnect paths; on overflow the oldest undelivered event is
    /// dropped (counted by [`Self::connection_events_dropped`]).
    ///
    /// `inbox_capacity == 0` selects the default (64). At most one
    /// listener per pool; a second registration fails. Register before
    /// the first borrow to observe the initial
    /// [`Connected`](crate::ingress::ConnectionEventKind::Connected)
    /// event.
    pub fn set_connection_listener(
        &self,
        listener: crate::ingress::ConnectionListener,
        inbox_capacity: usize,
    ) -> Result<()> {
        let source = conn_events::ConnectionEventSource::new(listener, inbox_capacity);
        self.inner.conn_events.set(source).map_err(|_| {
            crate::Error::new(
                crate::ErrorCode::InvalidApiCall,
                "a connection listener is already registered on this pool".to_string(),
            )
        })
    }

    /// Total connection events discarded by the listener inbox's
    /// drop-oldest policy. `0` when no listener is registered.
    pub fn connection_events_dropped(&self) -> u64 {
        self.inner
            .conn_events
            .get()
            .map(|events| events.dropped())
            .unwrap_or(0)
    }

    /// Total connection events delivered to the listener. `0` when no
    /// listener is registered.
    pub fn connection_events_delivered(&self) -> u64 {
        self.inner
            .conn_events
            .get()
            .map(|events| events.delivered())
            .unwrap_or(0)
    }

    /// Snapshot per-pool connection counts for diagnostics.
    ///
    /// Soak / leak harnesses read this on a cadence and assert every pool
    /// returns to a steady baseline after load and failover episodes (an FD /
    /// connection leak shows up as `in_use` or `free` failing to fall back).
    ///
    /// Each pool's lock is taken in turn (never two at once), so every field
    /// is internally consistent but the three are not a single atomic instant —
    /// fine for a monitoring snapshot. **Not semver-stable** (`#[doc(hidden)]`,
    /// `#[non_exhaustive]` result); mirrors the `questdb_db_dbg_reader_*_count`
    /// FFI diagnostics precedent.
    #[doc(hidden)]
    pub fn dbg_pool_counts(&self) -> DbgPoolCounts {
        let ingress = {
            let s = lock_state(&self.inner.state);
            DbgPoolCount {
                free: s.free.len(),
                in_use: s.in_use,
                closing: s.closing,
            }
        };
        let column_direct = {
            let s = lock_state(&self.inner.direct_state);
            DbgPoolCount {
                free: s.free.len(),
                in_use: s.in_use,
                closing: s.closing,
            }
        };
        #[cfg(feature = "_egress")]
        let reader = {
            let s = lock_reader_state(&self.inner.reader_state);
            DbgPoolCount {
                free: s.free.len(),
                in_use: s.in_use,
                closing: 0,
            }
        };
        #[cfg(not(feature = "_egress"))]
        let reader = DbgPoolCount::default();
        DbgPoolCounts {
            ingress,
            column_direct,
            reader,
        }
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
    #[cfg(any(feature = "polars-ingress", feature = "polars-egress"))]
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

    /// Snapshot the number of disk store-and-forward column slots currently
    /// waiting for their close/drop path to release the slot flock.
    #[cfg(all(test, feature = "ffi-support"))]
    pub(crate) fn closing_count(&self) -> usize {
        lock_state(&self.inner.state).closing
    }

    /// Snapshot the number of idle (free) senders in the always-direct pool.
    #[cfg(test)]
    pub(crate) fn direct_free_count(&self) -> usize {
        lock_state(&self.inner.direct_state).free.len()
    }

    /// Snapshot the number of currently-borrowed senders in the always-direct
    /// pool.
    #[cfg(test)]
    pub(crate) fn direct_in_use_count(&self) -> usize {
        lock_state(&self.inner.direct_state).in_use
    }

    /// Borrow a query [`Reader`] from the egress pool.
    ///
    /// Egress companion to [`Self::borrow_sender`]: pulls a [`Reader`]
    /// from the pool's reader free list, lazily opening a fresh connection
    /// (via `Reader::from_conf` on the original connect string) when the
    /// free list is empty and the pool is below `pool_max`. The reader pool
    /// is lazily grown and capped **independently** of the two ingestion pools,
    /// so heavy ingest can't starve queries and vice versa (the combined
    /// live-connection ceiling across all three pools is `3 * pool_max`).
    ///
    /// Borrow at the cap returns
    /// [`InvalidApiCall`](crate::ErrorCode::InvalidApiCall).
    ///
    /// The returned [`BorrowedReader`] derefs to `Reader`, so the usual
    /// `prepare` / `execute` cursor flow works unchanged, and returns the
    /// reader to the pool on `Drop` — unless its transport has been torn
    /// down (or [`BorrowedReader::drop_on_return`] was called), in which
    /// case it is dropped and the next borrow opens a fresh one.
    ///
    /// Like [`BorrowedSender`], [`BorrowedReader`] is **not** `Send` or
    /// `Sync`: borrow one reader per worker thread from the same `QuestDb`.
    #[cfg(feature = "_egress")]
    pub fn borrow_reader(&self) -> crate::error::Result<BorrowedReader<'_>> {
        let reader = self.pick_reader()?;
        Ok(BorrowedReader::new(self, reader))
    }

    /// FFI escape hatch: borrow a reader from the egress pool.
    ///
    /// Same shape as [`Self::borrow_sender_owned`] but pulls a
    /// [`Reader`] from the reader free list (lazily opens one if the
    /// free list is empty and total < `pool_max`). Returned via
    /// [`OwnedReader`]'s Drop: see the sender variant for the same
    /// pattern.
    #[cfg(all(feature = "_egress", feature = "ffi-support"))]
    pub(crate) fn borrow_reader_owned(&self) -> crate::error::Result<OwnedReader> {
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
    fn pick_reader(&self) -> crate::error::Result<Reader> {
        use crate::{Error, ErrorCode};
        let slot = {
            let mut state = lock_reader_state(&self.inner.reader_state);
            if self.inner.shutdown.load(Ordering::SeqCst) {
                return Err(Error::new(
                    ErrorCode::InvalidApiCall,
                    "QuestDb pool is closed; cannot borrow reader",
                ));
            }
            if let Some(entry) = state.free.pop() {
                state.in_use += 1;
                drop(state);
                return Ok(entry.reader);
            }
            if state.total() >= self.inner.pool_max {
                return Err(Error::new(
                    ErrorCode::InvalidApiCall,
                    format!(
                        "Reader pool exhausted: {} readers are currently borrowed and \
                         the pool is at its `pool_max` cap of {}. \
                         Release a reader or raise `pool_max`.",
                        state.in_use, self.inner.pool_max
                    ),
                ));
            }
            state.in_use += 1;
            ReaderInUseSlot {
                state: &self.inner.reader_state,
                armed: true,
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

struct SenderHandle<'a> {
    db: &'a QuestDb,
    sender: Option<PooledSenderCore>,
    slot_index: Option<usize>,
    _not_send: PhantomData<Rc<()>>,
}

impl<'a> SenderHandle<'a> {
    fn new(db: &'a QuestDb, sender: PooledSender<PooledSenderCore>) -> Self {
        Self {
            db,
            sender: Some(sender.sender),
            slot_index: sender.slot_index,
            _not_send: PhantomData,
        }
    }

    fn inner_mut(&mut self) -> &mut PooledSenderCore {
        self.sender
            .as_mut()
            .expect("borrowed sender already returned")
    }

    fn inner_ref(&self) -> &PooledSenderCore {
        self.sender
            .as_ref()
            .expect("borrowed sender already returned")
    }
}

struct DirectSenderHandle<'a> {
    db: &'a QuestDb,
    sender: Option<DirectSenderCore>,
    _not_send: PhantomData<Rc<()>>,
}

impl<'a> DirectSenderHandle<'a> {
    fn new(db: &'a QuestDb, sender: PooledSender<DirectSenderCore>) -> Self {
        debug_assert!(sender.slot_index.is_none());
        Self {
            db,
            sender: Some(sender.sender),
            _not_send: PhantomData,
        }
    }

    fn inner_mut(&mut self) -> &mut DirectSenderCore {
        self.sender
            .as_mut()
            .expect("borrowed direct sender already returned")
    }

    #[cfg(test)]
    fn inner_ref(&self) -> &DirectSenderCore {
        self.sender
            .as_ref()
            .expect("borrowed direct sender already returned")
    }

    #[cfg(any(feature = "polars-ingress", feature = "polars-egress"))]
    pub(crate) fn reconnect_policy(&self) -> crate::ingress::ReconnectPolicy {
        self.db.reconnect_policy()
    }

    /// Drop the current connection (and its paired connection-scoped
    /// `SymbolGlobalDict`) back to the pool and obtain a fresh one **behind
    /// the same handle**, so the caller's borrowed direct sender stays valid.
    ///
    /// This is the direct sender's failover primitive: after a transient
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
            // reborrow is a failover path, not a forced rotate. A healthy,
            // fully-sync'd connection needs no replacement; replacing it would
            // open a fresh connection and recycle this one, growing the pool.
            if sender.in_flight() == 0 && !sender.must_close() && !sender.transport_dead() {
                return Ok(());
            }
            if sender.in_flight() > 0 {
                log::warn!(
                    "direct sender failover dropped a connection with un-sync'd \
                     deferred frame(s); their data is discarded. Re-drive the source \
                     from the last successful sync(), not from the failing chunk."
                );
                sender.mark_must_close();
            }
            record_sender_transport_failure(&self.db.inner, sender);
        }
        let fresh = self.db.pick_replacement_sender()?;
        debug_assert!(fresh.slot_index.is_none());
        if let Some(old) = self.sender.replace(fresh.sender) {
            finish_replaced_sender(&self.db.inner, old);
        }
        Ok(())
    }

    /// Retry [`reborrow_from_pool`] within `deadline` using the row API's
    /// reconnect backoff (centered-jittered, role-reject reset; `AuthError` /
    /// `ProtocolVersionError` terminal). On terminal failure or budget
    /// exhaustion the handle stays populated (per [`reborrow_from_pool`]), so a
    /// later call reports a typed error rather than panicking.
    #[cfg(any(feature = "polars-ingress", feature = "polars-egress"))]
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

impl Debug for SenderHandle<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("SenderHandle")
            .field("sender", &self.sender)
            .finish()
    }
}

impl Debug for DirectSenderHandle<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectSenderHandle")
            .field("sender", &self.sender)
            .finish()
    }
}

/// Store-and-forward QWP sender borrowed from a [`QuestDb`] pool — the
/// handle returned by [`QuestDb::borrow_sender`].
///
/// [`Self::flush`] appends a frame to the connection's store-and-forward queue
/// and returns as soon as it is accepted locally (no server round-trip); the
/// connection's background runner delivers it asynchronously. While the handle
/// is borrowed or parked in the pool the runner keeps delivering, so returning
/// or dropping the handle does not by itself lose accepted frames.
///
/// Delivery is completed best-effort when the pool is closed or the connection
/// is retired, bounded by `close_flush_timeout` (default 5s): an in-memory
/// queue whose server stays unreachable past that window drops its undelivered
/// tail, logging a warning. For a hard guarantee, call [`Self::wait`] before
/// closing the pool — it blocks until the frames published so far reach the
/// requested [`AckLevel`], i.e. confirms delivery — or configure `sf_dir` for
/// crash-durable on-disk persistence with replay. [`Self::flush_and_wait`]
/// combines the two ("publish this batch and return once it is delivered");
/// its wait is bounded by the pool-wide `request_timeout` setting, so compose
/// [`Self::flush`] then [`Self::wait`] if you want to pass an explicit
/// timeout instead.
/// Use FSNs only for non-blocking progress tracking while this borrowed sender
/// is still held: they are stream watermarks, not portable receipts to check
/// through an arbitrary later pool borrow.
///
/// Not `Send` or `Sync`.
///
/// The lease cannot outlive its pool:
///
/// ```compile_fail
/// use questdb::{BorrowedSender, QuestDb};
///
/// fn escape() -> BorrowedSender<'static> {
///     let db = QuestDb::connect("ws::addr=localhost:9000;").unwrap();
///     db.borrow_sender().unwrap()
/// }
/// ```
///
/// It cannot be moved to another thread:
///
/// ```compile_fail
/// use questdb::QuestDb;
///
/// let db = QuestDb::connect("ws::addr=localhost:9000;").unwrap();
/// let sender = db.borrow_sender().unwrap();
/// std::thread::scope(|scope| {
///     scope.spawn(move || drop(sender));
/// });
/// ```
///
/// Nor can a shared reference be sent to another thread:
///
/// ```compile_fail
/// use questdb::QuestDb;
///
/// let db = QuestDb::connect("ws::addr=localhost:9000;").unwrap();
/// let sender = db.borrow_sender().unwrap();
/// std::thread::scope(|scope| {
///     scope.spawn(|| std::hint::black_box(&sender));
/// });
/// ```
pub struct BorrowedSender<'a>(SenderHandle<'a>);

impl<'a> BorrowedSender<'a> {
    /// Create a caller-owned QWP/WebSocket [`Buffer`] using the pool's
    /// configured name limit. The buffer is not tied to this lease and may be
    /// flushed by another sender borrowed from the same pool.
    pub fn new_buffer(&self) -> Buffer {
        self.0.db.new_buffer()
    }

    /// Encode and publish `chunk` into the store-and-forward queue, returning
    /// as soon as the frame is accepted locally (no server round-trip). On
    /// success `chunk` is cleared; on a delivery-uncertain failure the error
    /// is tagged [`in_doubt`](crate::Error::in_doubt).
    pub fn flush(&mut self, chunk: &mut crate::ingress::column_sender::Chunk<'_>) -> Result<()> {
        self.0.inner_mut().flush(chunk)
    }

    /// Publish a caller-owned QWP/WebSocket [`Buffer`] into this sender's local
    /// store-and-forward queue and clear it after local acceptance.
    pub fn flush_buffer(&mut self, buffer: &mut Buffer) -> Result<()> {
        self.0.inner_mut().flush_buffer(buffer)
    }

    /// Publish a caller-owned QWP/WebSocket [`Buffer`] without clearing it.
    pub fn flush_buffer_and_keep(&mut self, buffer: &Buffer) -> Result<()> {
        self.0.inner_mut().flush_buffer_and_keep(buffer)
    }

    /// Publish and clear a QWP/WebSocket [`Buffer`], returning its local frame
    /// sequence number. Empty buffers publish no frame and return `None`.
    pub fn flush_buffer_and_get_fsn(&mut self, buffer: &mut Buffer) -> Result<Option<u64>> {
        self.0.inner_mut().flush_buffer_and_get_fsn(buffer)
    }

    /// Publish a QWP/WebSocket [`Buffer`] without clearing it and return its
    /// local frame sequence number. Empty buffers return `None`.
    pub fn flush_buffer_and_keep_and_get_fsn(&mut self, buffer: &Buffer) -> Result<Option<u64>> {
        self.0.inner_mut().flush_buffer_and_keep_and_get_fsn(buffer)
    }

    /// Publish and clear a QWP/WebSocket [`Buffer`], then wait for the requested
    /// ACK boundary using the pool's configured request timeout.
    pub fn flush_buffer_and_wait(
        &mut self,
        buffer: &mut Buffer,
        ack_level: AckLevel,
    ) -> Result<()> {
        self.0.inner_mut().flush_buffer_and_wait(buffer, ack_level)
    }

    /// Publish `chunk` into the store-and-forward queue as a completion
    /// boundary, then wait until every frame published on this handle so far
    /// reaches `ack_level` — [`Self::flush`] followed by [`Self::wait`] in one
    /// call. Unlike [`Self::wait`], which takes an explicit timeout argument,
    /// this call's wait is bounded by the pool-wide `request_timeout` setting
    /// (the no-progress timeout fires when the ack watermark stops advancing
    /// for that long); compose the two calls yourself to choose the timeout
    /// per call.
    ///
    /// `AckLevel::Durable` requires the pool to be opened with
    /// `request_durable_ack=on`; otherwise the call is rejected up front
    /// (`InvalidApiCall`) before `chunk` is touched.
    ///
    /// Failure contract: if local publication fails, `chunk` is untouched and
    /// retryable. Once the frame is accepted into the queue `chunk` is cleared
    /// even if the wait then fails. On the no-progress timeout
    /// ([`ErrorCode::FailoverRetry`](crate::ErrorCode)) the frames remain
    /// queued and the background runner keeps delivering them — recover by
    /// calling [`Self::wait`] until it returns `Ok`, not by re-flushing
    /// (which would deliver the same rows twice). A terminal server rejection
    /// or transport failure instead ends delivery on this sender: drop the
    /// borrow and recover per the rejection policy.
    pub fn flush_and_wait(
        &mut self,
        chunk: &mut crate::ingress::column_sender::Chunk<'_>,
        ack_level: AckLevel,
    ) -> Result<()> {
        self.0.inner_mut().flush_and_wait(chunk, ack_level)
    }

    /// Encode and publish `chunk` into the store-and-forward queue and return
    /// the highest published frame sequence number.
    ///
    /// This is the non-blocking progress-tracking form of [`Self::flush`]:
    /// success means the frame was accepted locally, not that the server has
    /// ACKed it. If the chunk is split into multiple frames, the returned FSN
    /// is the final frame boundary; cumulative ACK coverage of that boundary
    /// covers the whole chunk. Use [`Self::wait`] when you only need a simple
    /// blocking barrier for everything published so far. Treat the returned
    /// FSN as meaningful only with this sender stream while this borrow is
    /// held.
    pub fn flush_and_get_fsn(
        &mut self,
        chunk: &mut crate::ingress::column_sender::Chunk<'_>,
    ) -> Result<Option<u64>> {
        self.0.inner_mut().flush_and_get_fsn(chunk)
    }

    /// Return the highest frame sequence number published locally by this
    /// sender, or `None` if no frame has been published.
    ///
    /// This is a stream watermark for the currently borrowed sender, not a
    /// portable receipt to check through an arbitrary later pool borrow.
    pub fn published_fsn(&self) -> Result<Option<u64>> {
        self.0.inner_ref().published_fsn()
    }

    /// Return the highest frame sequence number completed by server ACK or
    /// server-side reject-and-continue, or `None` if no frame has completed.
    ///
    /// In durable-ACK mode this watermark advances after durable ACK coverage;
    /// use [`Self::wait`] when you need an explicit [`AckLevel::Ok`] or
    /// [`AckLevel::Durable`] barrier. Compare it only with FSNs produced by
    /// this same sender stream.
    pub fn acked_fsn(&self) -> Result<Option<u64>> {
        self.0.inner_ref().acked_fsn()
    }

    /// Wait up to `timeout` for every frame published on this handle so far to
    /// reach `ack_level`. Short-circuits when nothing is pending or the
    /// watermark already covers the latest frame. `AckLevel::Durable` requires
    /// the pool to have been opened with `request_durable_ack=on`.
    ///
    /// `timeout` is a no-progress deadline (it fires only if the ack watermark
    /// fails to advance for that long); `Duration::ZERO` waits indefinitely.
    /// On expiry it returns an [`ErrorCode::FailoverRetry`](crate::ErrorCode)
    /// error; the frames remain queued and the background runner keeps
    /// delivering them, so recover by calling `wait()` again until it returns
    /// `Ok` — not by re-flushing, which would deliver the same rows twice.
    pub fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()> {
        self.0.inner_mut().wait(ack_level, timeout)
    }

    /// Force this borrowed connection to be dropped (not recycled) on return.
    ///
    /// Use normal `Drop` for healthy connections: the return path already
    /// retires connections that latched terminal state, or whose pool has been
    /// closed. Call this after abandoning work or handling an error where the
    /// next borrower must not inherit this backend. If queued
    /// store-and-forward frames must not be lost, call [`Self::wait`] first or
    /// configure `sf_dir` for replay.
    pub fn drop_on_return(&mut self) {
        self.0.inner_mut().mark_must_close()
    }

    #[cfg(test)]
    pub(crate) fn must_close_for_test(&self) -> bool {
        self.0.inner_ref().must_close()
    }

    /// Always `true` for an SF handle (it wraps a store-and-forward backend).
    /// Retained for symmetry with [`BorrowedDirectColumnSender`] and test assertions.
    #[cfg(test)]
    pub(crate) fn is_store_and_forward(&self) -> bool {
        true
    }

    /// In-flight (published-but-unacked) frame count. Always 0 for the SF
    /// backend, whose queue tracks delivery internally.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u32 {
        0
    }

    /// Encode and publish an Arrow [`RecordBatch`](arrow::array::RecordBatch)
    /// into the queue, letting the server stamp each row's designated
    /// timestamp on arrival. Publish-only; call [`Self::wait`] for an ack.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_now(table, batch, overrides)
    }

    /// ACKing counterpart of [`Self::flush_arrow_batch_at_now`]: publish the
    /// batch as a completion boundary, then wait for `ack_level`. The same
    /// contract as [`Self::flush_and_wait`] applies.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now_and_wait<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_now_and_wait(table, batch, overrides, ack_level)
    }

    /// Arrow counterpart of [`Self::flush_and_get_fsn`], letting the server
    /// stamp each row's designated timestamp on arrival.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now_and_get_fsn<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
    ) -> Result<Option<u64>>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_now_and_get_fsn(table, batch, overrides)
    }

    /// Encode and publish an Arrow [`RecordBatch`](arrow::array::RecordBatch)
    /// into the queue, sourcing the designated timestamp from the named
    /// column. Publish-only; call [`Self::wait`] for an ack.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        ts_column: crate::ingress::ColumnName<'_>,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_column(table, batch, ts_column, overrides)
    }

    /// ACKing counterpart of [`Self::flush_arrow_batch_at_column`]: publish
    /// the batch as a completion boundary, then wait for `ack_level`. The same
    /// contract as [`Self::flush_and_wait`] applies.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column_and_wait<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        ts_column: crate::ingress::ColumnName<'_>,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_column_and_wait(table, batch, ts_column, overrides, ack_level)
    }

    /// Arrow counterpart of [`Self::flush_and_get_fsn`], sourcing the
    /// designated timestamp from the named column.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column_and_get_fsn<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        ts_column: crate::ingress::ColumnName<'_>,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
    ) -> Result<Option<u64>>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_column_and_get_fsn(table, batch, ts_column, overrides)
    }
}

impl Debug for BorrowedSender<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BorrowedSender").field(&self.0).finish()
    }
}

/// Direct (pipelined, non-store-and-forward) column sender borrowed from a
/// [`QuestDb`] pool — the handle returned by
/// [`QuestDb::borrow_direct_column_sender`], used by DataFrame ingestion.
///
/// [`Self::flush`] pipelines a deferred frame; [`Self::commit`] (or
/// [`Self::flush_and_wait`] on the final chunk) sends the commit boundary and
/// waits for `ack_level`. Normal `Drop` makes a best-effort commit of
/// uncommitted deferred frames at the pool's default ack level. If that commit
/// fails, or if [`Self::drop_on_return`] was requested, those frames are
/// discarded; for deterministic error handling, call [`Self::commit`] or
/// [`Self::flush_and_wait`] yourself and re-drive from the last successful
/// commit after failure.
///
/// Not `Send` or `Sync`.
pub struct BorrowedDirectColumnSender<'a>(DirectSenderHandle<'a>);

impl<'a> BorrowedDirectColumnSender<'a> {
    /// Encode and pipeline `chunk` as a deferred frame without waiting. The
    /// frame is not committed until [`Self::commit`] / [`Self::flush_and_wait`].
    pub fn flush(&mut self, chunk: &mut crate::ingress::column_sender::Chunk<'_>) -> Result<()> {
        self.0.inner_mut().flush(chunk)
    }

    /// Publish `chunk` as a non-deferred commit boundary and block until it
    /// (and all prior pipelined frames) reach `ack_level`.
    pub fn flush_and_wait(
        &mut self,
        chunk: &mut crate::ingress::column_sender::Chunk<'_>,
        ack_level: AckLevel,
    ) -> Result<()> {
        self.0.inner_mut().flush_and_wait(chunk, ack_level)
    }

    /// Send the commit boundary for all pipelined frames and block until they
    /// reach `ack_level`. This is the direct sender's explicit durability
    /// checkpoint; normal `Drop` attempts the same kind of commit best-effort,
    /// but callers that need deterministic error handling should call
    /// `commit()` themselves.
    pub fn commit(&mut self, ack_level: AckLevel) -> Result<()> {
        self.0.inner_mut().sync(ack_level)
    }

    /// Failover primitive: swap onto a fresh connection from the pool behind
    /// the same handle after a transient flush failure. No-op on a healthy,
    /// fully-committed connection.
    pub fn reborrow_from_pool(&mut self) -> Result<()> {
        self.0.reborrow_from_pool()
    }

    #[cfg(any(feature = "polars-ingress", feature = "polars-egress"))]
    pub(crate) fn reborrow_with_retry(&mut self, deadline: Option<Instant>) -> Result<()> {
        self.0.reborrow_with_retry(deadline)
    }

    #[cfg(any(feature = "polars-ingress", feature = "polars-egress"))]
    pub(crate) fn reconnect_policy(&self) -> crate::ingress::ReconnectPolicy {
        self.0.reconnect_policy()
    }

    /// The pool's default ack level (see [`QuestDb::default_ack_level`]),
    /// reached through the handle's owning `QuestDb`.
    #[cfg(feature = "polars-ingress")]
    pub(crate) fn default_ack_level(&self) -> AckLevel {
        self.0.db.default_ack_level()
    }

    /// Force this borrowed connection to be dropped (not recycled) on return.
    ///
    /// Use normal `Drop` for healthy connections: the return path already
    /// retires connections that latched terminal state, or whose pool has been
    /// closed. Call this after abandoning deferred frames or handling an error
    /// where the next borrower must not inherit this backend. Call this only
    /// after you are done using the handle. To preserve deferred frames, commit
    /// them successfully with [`Self::commit`] or [`Self::flush_and_wait`]
    /// before calling `drop_on_return()`; after this call the connection is
    /// terminal and later commit/flush attempts may fail.
    pub fn drop_on_return(&mut self) {
        self.0.inner_mut().mark_must_close()
    }

    #[cfg(test)]
    pub(crate) fn must_close_for_test(&self) -> bool {
        self.0.inner_ref().must_close()
    }

    /// Always `false` for a direct handle. Retained for symmetry with
    /// [`BorrowedSender`] and test assertions.
    #[cfg(test)]
    pub(crate) fn is_store_and_forward(&self) -> bool {
        false
    }

    /// In-flight (published-but-unacked) deferred frame count.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u32 {
        self.0.inner_ref().in_flight()
    }

    /// Publish-only Arrow flush (server-stamped). Pair with [`Self::commit`].
    /// Only the DataFrame checkpoint loop pipelines publish-only frames, so this
    /// is gated on `polars-ingress` (a plain `arrow-ingress` build reaches the
    /// server only through the ACKing `flush_arrow_batch`).
    #[cfg(feature = "polars-ingress")]
    pub(crate) fn flush_arrow_batch_at_now<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_now(table, batch, overrides)
    }

    /// Publish-only Arrow flush (column-stamped). Pair with [`Self::commit`].
    /// `polars-ingress`-gated for the same reason as
    /// [`Self::flush_arrow_batch_at_now`].
    #[cfg(feature = "polars-ingress")]
    pub(crate) fn flush_arrow_batch_at_column<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        ts_column: crate::ingress::ColumnName<'_>,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_column(table, batch, ts_column, overrides)
    }

    /// ACKing Arrow flush (server-stamped): publish as a commit boundary and
    /// wait for `ack_level`.
    #[cfg(feature = "arrow-ingress")]
    pub(crate) fn flush_arrow_batch_at_now_and_wait<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_now_and_wait(table, batch, overrides, ack_level)
    }

    /// ACKing Arrow flush (column-stamped): publish as a commit boundary and
    /// wait for `ack_level`.
    #[cfg(feature = "arrow-ingress")]
    pub(crate) fn flush_arrow_batch_at_column_and_wait<'t, T>(
        &mut self,
        table: T,
        batch: &arrow::array::RecordBatch,
        ts_column: crate::ingress::ColumnName<'_>,
        overrides: &[crate::ingress::column_sender::ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> Result<()>
    where
        T: TryInto<crate::ingress::TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        self.0
            .inner_mut()
            .flush_arrow_batch_at_column_and_wait(table, batch, ts_column, overrides, ack_level)
    }
}

impl Debug for BorrowedDirectColumnSender<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BorrowedDirectColumnSender")
            .field(&self.0)
            .finish()
    }
}

impl Drop for SenderHandle<'_> {
    fn drop(&mut self) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        return_sfa_to_pool(&self.db.inner, sender, self.slot_index);
    }
}

impl Drop for DirectSenderHandle<'_> {
    fn drop(&mut self) {
        let Some(mut sender) = self.sender.take() else {
            return;
        };
        commit_in_flight_on_drop(self.db.inner.connector.request_durable_ack(), &mut sender);
        return_direct_to_pool(&self.db.inner, sender);
    }
}

/// Owned (lifetime-free) variant of a borrowed sender used by the C FFI.
///
/// Holds an `Arc<DbInner>` so the pool's return path outlives the
/// user-facing `QuestDb` pointer — the C ABI can free its `questdb_db*`
/// before dropping outstanding `qwp_sender*` or `direct_column_sender*`
/// handles. After pool close, returned handles are dropped instead of recycled.
#[cfg(feature = "ffi-support")]
pub struct OwnedSender {
    inner: Arc<DbInner>,
    sender: Option<PooledSenderCore>,
    slot_index: Option<usize>,
}

#[cfg(feature = "ffi-support")]
impl OwnedSender {
    fn new(inner: Arc<DbInner>, sender: PooledSender<PooledSenderCore>) -> Self {
        Self {
            inner,
            sender: Some(sender.sender),
            slot_index: sender.slot_index,
        }
    }

    /// Borrow the underlying [`PooledSenderCore`] mutably. Always returns a
    /// live reference until `Drop` runs.
    pub fn get_mut(&mut self) -> &mut PooledSenderCore {
        self.sender
            .as_mut()
            .expect("OwnedSender already returned to the pool")
    }

    /// Inspect the wrapped sender without taking ownership.
    pub fn get(&self) -> &PooledSenderCore {
        self.sender
            .as_ref()
            .expect("OwnedSender already returned to the pool")
    }

    /// `true` after the originating pool has been closed. FFI callers use
    /// this to reject new work on checked-out handles while still allowing
    /// return/drop to clean up safely.
    pub fn pool_closed(&self) -> bool {
        self.inner.shutdown.load(Ordering::SeqCst)
    }

    /// Force this sender to be dropped instead of recycled when the owned FFI
    /// handle is released.
    pub fn mark_must_close(&mut self) {
        self.get_mut().mark_must_close();
    }

    /// `true` when this sender cannot be returned to the pool, either because
    /// the sender is terminal or because its originating pool has closed.
    pub fn must_close(&self) -> bool {
        self.pool_closed() || self.get().must_close()
    }
}

#[cfg(feature = "ffi-support")]
impl Drop for OwnedSender {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            return_sfa_to_pool(&self.inner, sender, self.slot_index);
        }
    }
}

/// Backing of an [`OwnedDirectColumnSender`]: either a slot returned to a
/// pool, or a poolless connection owned outright.
#[cfg(feature = "ffi-support")]
enum DirectBacking {
    Pool(Arc<DbInner>),
    Standalone { request_durable_ack: bool },
}

/// Owned variant of the hidden direct sender used by the C FFI. Either
/// borrowed from a [`QuestDb`] pool or built standalone from a config string.
#[cfg(feature = "ffi-support")]
pub struct OwnedDirectColumnSender {
    backing: DirectBacking,
    sender: Option<DirectSenderCore>,
}

#[cfg(feature = "ffi-support")]
impl OwnedDirectColumnSender {
    fn new(inner: Arc<DbInner>, sender: PooledSender<DirectSenderCore>) -> Self {
        debug_assert!(sender.slot_index.is_none());
        Self {
            backing: DirectBacking::Pool(inner),
            sender: Some(sender.sender),
        }
    }

    /// Build a direct column sender from a QWP/WebSocket config string,
    /// opening its own connection and owning it outright — no pool.
    pub fn from_conf(conf: &str) -> Result<Self> {
        Self::from_builder(&SenderBuilder::from_conf(conf)?)
    }

    /// Build a direct column sender from an already-configured
    /// [`SenderBuilder`] (which carries auth/TLS applied programmatically,
    /// not just what a config string encodes), owning its own connection
    /// with no pool. The builder is only borrowed.
    pub fn from_builder(builder: &SenderBuilder) -> Result<Self> {
        let connector = builder.build_qwp_ws_connector()?;
        let health = Mutex::new(QwpWsHostHealthTracker::new(connector.endpoint_count()));
        let raw = connector.connect_round_pooled(&health, None)?;
        let conn = ColumnConn::from_round_stream(raw)?;
        let sender = DirectSenderCore::new(
            conn,
            crate::ingress::SymbolGlobalDict::new(),
            crate::ingress::column_sender::encoder::EncodeScratch::new(),
            false,
        );
        Ok(Self {
            backing: DirectBacking::Standalone {
                request_durable_ack: connector.request_durable_ack(),
            },
            sender: Some(sender),
        })
    }

    pub fn get_mut(&mut self) -> &mut DirectSenderCore {
        self.sender
            .as_mut()
            .expect("OwnedDirectColumnSender already released")
    }

    pub fn get(&self) -> &DirectSenderCore {
        self.sender
            .as_ref()
            .expect("OwnedDirectColumnSender already released")
    }

    pub fn pool_closed(&self) -> bool {
        match &self.backing {
            DirectBacking::Pool(inner) => inner.shutdown.load(Ordering::SeqCst),
            DirectBacking::Standalone { .. } => false,
        }
    }

    pub fn mark_must_close(&mut self) {
        self.get_mut().mark_must_close();
    }

    pub fn must_close(&self) -> bool {
        self.pool_closed() || self.get().must_close()
    }
}

#[cfg(feature = "ffi-support")]
impl Drop for OwnedDirectColumnSender {
    fn drop(&mut self) {
        let Some(mut sender) = self.sender.take() else {
            return;
        };
        match &self.backing {
            DirectBacking::Pool(inner) => {
                commit_in_flight_on_drop(inner.connector.request_durable_ack(), &mut sender);
                return_direct_to_pool(inner, sender);
            }
            DirectBacking::Standalone {
                request_durable_ack,
            } => {
                commit_in_flight_on_drop(*request_durable_ack, &mut sender);
            }
        }
    }
}

/// A query [`Reader`] borrowed from a [`QuestDb`] pool.
///
/// Egress companion to [`BorrowedSender`]. Derefs to `Reader`, so the usual
/// `prepare` / `execute` cursor flow works unchanged. On `Drop` the reader
/// is returned to the reader pool, unless its transport has been torn down
/// (or [`Self::drop_on_return`] was called), in which case it is dropped
/// and the next borrow opens a fresh one.
///
/// `BorrowedReader` is **not** `Send` or `Sync`: the borrowed connection
/// belongs to the borrowing thread for the duration of the borrow.
#[cfg(feature = "_egress")]
pub struct BorrowedReader<'a> {
    db: &'a QuestDb,
    reader: Option<Reader>,
    must_close: bool,
    /// !Send / !Sync marker, mirroring [`BorrowedSender`].
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

    /// Force this borrowed reader to be dropped (not recycled) when the borrow
    /// ends.
    ///
    /// Use normal `Drop` for healthy readers: the return path already retires
    /// readers whose transport was torn down, or whose pool has been closed.
    /// Call this after abandoning work or handling an error where the next
    /// borrower must not inherit this connection.
    pub fn drop_on_return(&mut self) {
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
/// Holds an `Arc<DbInner>` for the same reason [`OwnedSender`] does: the
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
fn pick_sender_inner<S>(
    inner: &Arc<DbInner>,
    pool: &Mutex<PoolState<S>>,
    sfa: bool,
    connect: impl FnOnce(Option<usize>) -> Result<S>,
) -> Result<PooledSender<S>> {
    let slot = {
        let mut state = lock_state(pool);
        let mut close_wait_deadline = None;
        loop {
            if inner.shutdown.load(Ordering::SeqCst) {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "QuestDb pool is closed; cannot borrow sender"
                ));
            }
            if let Some(entry) = state.free.pop() {
                state.in_use += 1;
                drop(state);
                return Ok(PooledSender {
                    sender: entry.sender,
                    slot_index: entry.slot_index,
                });
            }
            if state.reserved_total() < inner.pool_max {
                break;
            }
            let wait_timeout = inner.connector.close_flush_timeout();
            if sfa
                && inner.sf_disk
                && state.closing > 0
                && let Some(wait_for) = remaining_close_wait(&mut close_wait_deadline, wait_timeout)
            {
                let (next_state, _) = match inner.cv.wait_timeout(state, wait_for) {
                    Ok((guard, result)) => (guard, result),
                    Err(poisoned) => poisoned.into_inner(),
                };
                state = next_state;
                continue;
            }
            return Err(error::fmt!(
                InvalidApiCall,
                "Connection pool exhausted: {} sender(s) in use, pool_max={}. \
                 Drop a borrowed sender or increase pool_max.",
                state.in_use,
                inner.pool_max
            ));
        }
        let slot_index = state.allocate_slot_index();
        debug_assert_eq!(slot_index.is_some(), sfa && inner.sf_disk);
        state.in_use += 1;
        InUseSlot {
            state: pool,
            cv: &inner.cv,
            slot_index,
            armed: true,
        }
    };
    let sender = connect(slot.slot_index)?;
    let slot_index = slot.slot_index;
    slot.commit();
    Ok(PooledSender { sender, slot_index })
}

fn pick_sfa_sender(inner: &Arc<DbInner>) -> Result<PooledSender<PooledSenderCore>> {
    pick_sender_inner(inner, &inner.state, true, |slot_index| {
        connect_sfa_pool(inner, slot_index)
    })
}

fn pick_direct_sender(inner: &Arc<DbInner>) -> Result<PooledSender<DirectSenderCore>> {
    pick_sender_inner(inner, &inner.direct_state, false, |_slot_index| {
        let conn = connect_conn_pool(inner)?;
        Ok(DirectSenderCore::new(
            conn,
            crate::ingress::SymbolGlobalDict::new(),
            crate::ingress::column_sender::encoder::EncodeScratch::new(),
            false,
        ))
    })
}

fn connect_sfa_pool(inner: &Arc<DbInner>, slot_index: Option<usize>) -> Result<PooledSenderCore> {
    let recovery_candidates = managed_slot_recovery_candidates(inner);
    connect_sfa_pool_with_recovery_candidates(inner, slot_index, &recovery_candidates)
}

fn connect_sfa_pool_with_recovery_candidates(
    inner: &Arc<DbInner>,
    slot_index: Option<usize>,
    recovery_candidates: &[PathBuf],
) -> Result<PooledSenderCore> {
    let sender_id = slot_index.map(|index| managed_slot_id(&inner.slot_base_id, index));
    let state = inner
        .connector
        .connect_sfa_background_with_pool_slot(
            sender_id.as_deref(),
            inner.managed_slot_exclusion.as_slice(),
            recovery_candidates,
        )
        .map_err(|err| {
            crate::Error::new(
                err.code(),
                format!("Failed to open store-and-forward sender: {}", err.msg()),
            )
        })?;
    PooledSenderCore::new_store_and_forward(
        state,
        inner.connector.max_buf_size(),
        inner.connector.request_durable_ack(),
        inner.connector.request_timeout(),
    )
}

/// Re-acquire a live connection within `deadline`, retrying with the pool's
/// reconnect backoff: a failed pick (every endpoint role-rejecting while the
/// cluster elects a primary, or a transient transport error) backs off and
/// retries; `AuthError` / `ProtocolVersionError` and deadline exhaustion are
/// terminal.
#[cfg(feature = "ffi-support")]
fn reconnect_pick<S>(
    inner: &Arc<DbInner>,
    deadline: Option<Instant>,
    mut pick: impl FnMut(&Arc<DbInner>) -> Result<PooledSender<S>>,
) -> Result<PooledSender<S>> {
    let policy = inner.connector.reconnect_policy();
    let mut backoff = policy.initial_backoff();
    loop {
        match pick(inner) {
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

#[cfg(any(
    feature = "polars-ingress",
    feature = "polars-egress",
    feature = "ffi-support"
))]
pub(crate) fn reconnect_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|d| Instant::now() >= d)
}

fn remaining_close_wait(deadline: &mut Option<Instant>, timeout: Duration) -> Option<Duration> {
    if timeout.is_zero() {
        return None;
    }
    let now = Instant::now();
    let deadline = deadline.get_or_insert_with(|| now.checked_add(timeout).unwrap_or(now));
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        None
    } else {
        Some(remaining)
    }
}

#[cfg(any(
    feature = "polars-ingress",
    feature = "polars-egress",
    feature = "ffi-support"
))]
fn sleep_until_deadline(sleep_for: Duration, deadline: Option<Instant>) {
    let d = match deadline {
        Some(dl) => sleep_for.min(dl.saturating_duration_since(Instant::now())),
        None => sleep_for,
    };
    if !d.is_zero() {
        thread::sleep(d);
    }
}

/// Open one direct connection through the live pool's `connector`. The shared
/// health tracker is locked only per tracker operation (pick/claim/record),
/// never across the
/// blocking TCP+TLS+WS-upgrade handshake — so concurrent cold-start borrows do
/// not serialize end-to-end, and dead-sender returns that also grab
/// `inner.health` (via [`record_sender_transport_failure`]) are not stalled
/// behind one slow / black-holed connect.
fn connect_conn_pool(inner: &Arc<DbInner>) -> Result<ColumnConn> {
    let raw: RawQwpWsRoundStream = inner
        .connector
        .connect_round_pooled(&inner.health, inner.conn_events.get())?;
    ColumnConn::from_round_stream(raw)
}

/// Best-effort commit of un-sync'd deferred frames on drop, so the natural
/// `flush()`-loop-then-drop path doesn't silently lose data. Commits at the
/// pool's default ack level so a `request_durable_ack=on` pool still waits for
/// the durability ACK instead of silently downgrading to `Ok`. On failure the
/// connection is latched `must_close` so the next borrower can't commit these
/// frames under a foreign table.
fn commit_in_flight_on_drop(request_durable_ack: bool, sender: &mut DirectSenderCore) {
    if sender.in_flight() == 0 {
        return;
    }
    let ack = if request_durable_ack {
        AckLevel::Durable
    } else {
        AckLevel::Ok
    };
    let committed = !sender.must_close() && !sender.transport_dead() && sender.sync(ack).is_ok();
    if !committed {
        log::warn!(
            "direct sender dropped with un-sync'd deferred frame(s) that could \
             not be committed; their data is discarded. Call sync() (or \
             flush_and_wait() on the final chunk) before the handle is dropped."
        );
        sender.mark_must_close();
    }
}

/// Best-effort delivery of a store-and-forward connection's queued frames just
/// before it is dropped (not recycled) — on pool shutdown or a `must_close`
/// return. While a connection is parked in the free list its background runner
/// keeps delivering, but dropping it stops the runner, so we give the queue a
/// bounded window (the configured `close_flush_timeout`) to finish. On timeout
/// or a terminal transport the undelivered frames are discarded with a warning,
/// mirroring [`commit_in_flight_on_drop`] for the direct backend.
fn drain_sfa_before_drop(inner: &DbInner, sender: &mut PooledSenderCore) {
    let timeout = inner.connector.close_flush_timeout();
    if timeout.is_zero() {
        return;
    }
    let durable = inner.connector.request_durable_ack();
    if sender.sfa_fully_delivered(durable) {
        return;
    }
    sender.begin_close();
    if let Err(err) = sender.drain_to_deadline(Instant::now().checked_add(timeout)) {
        log::warn!(
            "store-and-forward sender dropped with frame(s) that could \
             not be delivered within close_flush_timeout; their data is \
             discarded. Call wait() before closing the pool, or set sf_dir for \
             crash-durable persistence. Cause: {err}"
        );
    }
}

/// Batched [`drain_sfa_before_drop`] for the connections retired together when
/// the pool is closed. Every runner is signalled first (non-blocking) so their
/// deliveries overlap, then each is awaited under a *single* shared deadline —
/// so total close time is roughly one `close_flush_timeout` no matter how many
/// connections are draining, instead of the sum.
fn drain_sfa_senders_bounded(inner: &DbInner, senders: &mut [PooledSenderCore]) {
    let timeout = inner.connector.close_flush_timeout();
    if timeout.is_zero() || senders.is_empty() {
        return;
    }
    let durable = inner.connector.request_durable_ack();
    for sender in senders.iter() {
        sender.begin_close();
    }
    let deadline = Instant::now().checked_add(timeout);
    for sender in senders.iter_mut() {
        if sender.sfa_fully_delivered(durable) {
            continue;
        }
        if let Err(err) = sender.drain_to_deadline(deadline) {
            log::warn!(
                "store-and-forward sender dropped on pool close with \
                 frame(s) that could not be delivered within close_flush_timeout; \
                 their data is discarded. Call wait() before close, or set \
                 sf_dir for crash-durable persistence. Cause: {err}"
            );
        }
    }
}

fn return_sfa_to_pool(
    inner: &Arc<DbInner>,
    mut sender: PooledSenderCore,
    slot_index: Option<usize>,
) {
    let must_close = sender.must_close();
    let release_slot;
    {
        let mut state = lock_state(&inner.state);
        if !must_close && !inner.shutdown.load(Ordering::SeqCst) {
            state.in_use = state.in_use.saturating_sub(1);
            state.free.push(PoolEntry {
                sender,
                slot_index,
                last_idle_at: Instant::now(),
            });
            inner.cv.notify_all();
            return;
        }
        release_slot = slot_index.is_some();
        if release_slot {
            state.closing += 1;
        } else {
            state.in_use = state.in_use.saturating_sub(1);
        }
    }
    let _release = release_slot.then_some(SenderSlotRelease {
        inner: inner.as_ref(),
        slot_index,
        decrement_in_use: true,
        decrement_closing: true,
    });
    // Not recycling: this connection and its background runner are about to be
    // dropped, so drain its queue first (bounded, outside the pool lock).
    drain_sfa_before_drop(inner, &mut sender);
    drop(sender);
}

fn return_direct_to_pool(inner: &Arc<DbInner>, sender: DirectSenderCore) {
    let must_close = sender.must_close();
    record_sender_transport_failure(inner, &sender);
    let mut state = lock_state(&inner.direct_state);
    state.in_use = state.in_use.saturating_sub(1);
    if !must_close && !inner.shutdown.load(Ordering::SeqCst) {
        state.free.push(PoolEntry {
            sender,
            slot_index: None,
            last_idle_at: Instant::now(),
        });
        inner.cv.notify_all();
    }
}

fn finish_replaced_sender(inner: &Arc<DbInner>, sender: DirectSenderCore) {
    let must_close = sender.must_close();
    record_sender_transport_failure(inner, &sender);
    let mut state = lock_state(&inner.direct_state);
    if !must_close && !inner.shutdown.load(Ordering::SeqCst) && state.total() < inner.pool_max {
        state.free.push(PoolEntry {
            sender,
            slot_index: None,
            last_idle_at: Instant::now(),
        });
        inner.cv.notify_all();
    }
}

fn record_sender_transport_failure(inner: &Arc<DbInner>, sender: &DirectSenderCore) {
    if sender.transport_dead() {
        let idx = sender.endpoint_idx();
        lock_health(&inner.health)
            .record_mid_stream_failure(idx, Some(ReconnectReason::RetryableFailure));
        if let Some(events) = inner.conn_events.get()
            && let Some(endpoint) = inner.connector.endpoint(idx)
        {
            events.disconnected(&endpoint.host, &endpoint.port);
        }
    }
}

fn spawn_reaper(inner: Arc<DbInner>) -> std::io::Result<JoinHandle<()>> {
    let tick = reaper_tick(inner.pool_idle_timeout);
    thread::Builder::new()
        .name("questdb-ingress-pool-reaper".to_string())
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
    dropped += reap_idle_direct_senders(inner);
    #[cfg(feature = "_egress")]
    {
        dropped += reap_idle_readers(inner);
    }
    dropped
}

fn drain_idle_inner(inner: &DbInner) -> usize {
    let mut dropped = drain_idle_senders(inner);
    dropped += drain_idle_direct_senders(inner);
    #[cfg(feature = "_egress")]
    {
        dropped += drain_idle_readers(inner);
    }
    dropped
}

fn drain_idle_senders(inner: &DbInner) -> usize {
    let mut to_drop: Vec<PooledSenderCore> = {
        let mut state = lock_state(&inner.state);
        state.free.drain(..).map(|entry| entry.sender).collect()
    };
    let dropped = to_drop.len();
    // The Main pool is store-and-forward: deliver each connection's queued
    // frames (bounded by close_flush_timeout, shared across all of them) before
    // the runners are stopped on drop. Done outside the pool lock.
    drain_sfa_senders_bounded(inner, &mut to_drop);
    drop(to_drop);
    dropped
}

fn drain_idle_direct_senders(inner: &DbInner) -> usize {
    let to_drop: Vec<DirectSenderCore> = {
        let mut state = lock_state(&inner.direct_state);
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
    let durable = inner.connector.request_durable_ack();
    let mut dropped = 0;
    while let Some((sender, slot_index)) = take_reapable_column_sender(inner, durable) {
        let _release = slot_index.is_some().then_some(SenderSlotRelease {
            inner,
            slot_index,
            decrement_in_use: false,
            decrement_closing: true,
        });
        drop(sender);
        dropped += 1;
    }
    dropped
}

fn take_reapable_column_sender(
    inner: &DbInner,
    durable: bool,
) -> Option<(PooledSenderCore, Option<usize>)> {
    let mut state = lock_state(&inner.state);
    let now = Instant::now();
    // Free-list is oldest at front, newest at back (push on return /
    // pop on borrow). We must protect `total() >= pool_size` after the
    // drop, so we only remove an entry if total stays above the floor.
    let mut i = 0;
    while i < state.free.len() {
        if state.total() <= inner.pool_size {
            return None;
        }
        let idle_for = now.saturating_duration_since(state.free[i].last_idle_at);
        // Never evict a connection whose store-and-forward queue still holds
        // undelivered frames: its background runner is still delivering, and
        // dropping it now would lose that data. It becomes reapable once the
        // runner drains it (or the transport goes terminal). `sfa_fully_delivered`
        // is a lock-free progress read in the healthy case.
        if idle_for > inner.pool_idle_timeout && state.free[i].sender.sfa_fully_delivered(durable) {
            let entry = state.free.remove(i);
            if entry.slot_index.is_some() {
                state.closing += 1;
            }
            return Some((entry.sender, entry.slot_index));
        }
        i += 1;
    }
    None
}

fn reap_idle_direct_senders(inner: &DbInner) -> usize {
    // Direct pool is lazy-init (no pre-population at connect), so there is no
    // warm-min floor to preserve — reap any sender parked longer than the idle
    // timeout. The direct pool has no configured warm minimum.
    let to_drop: Vec<DirectSenderCore> = {
        let mut state = lock_state(&inner.direct_state);
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
        assert_send::<OwnedSender>();
        assert_send::<OwnedDirectColumnSender>();
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
    assert_not_send::<BorrowedSender<'_>>();
    assert_not_send::<BorrowedDirectColumnSender<'_>>();
    #[cfg(feature = "_egress")]
    assert_not_send::<BorrowedReader<'_>>();
    assert_not_send::<crate::ingress::column_sender::Chunk<'_>>();
};

const _: fn() = || {
    trait AmbiguousIfSync<A> {
        fn _disambiguate() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}
    fn assert_not_sync<T: ?Sized>() {
        let _: fn() = <T as AmbiguousIfSync<_>>::_disambiguate;
    }
    assert_not_sync::<BorrowedSender<'_>>();
    assert_not_sync::<BorrowedDirectColumnSender<'_>>();
    #[cfg(feature = "_egress")]
    assert_not_sync::<BorrowedReader<'_>>();
    assert_not_sync::<crate::ingress::column_sender::Chunk<'_>>();
};

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{SlotReservations, managed_slot_recovery_candidates_from};

    fn dirty_slot(root: &std::path::Path, name: &str) {
        let slot = root.join(name);
        fs::create_dir(&slot).unwrap();
        fs::write(slot.join("sf-0.sfa"), b"queued").unwrap();
    }

    #[test]
    fn managed_slot_recovery_candidates_exclude_live_pool_range() {
        let temp = TempDir::new().unwrap();
        dirty_slot(temp.path(), "default-ingest-0");
        dirty_slot(temp.path(), "default-ingest-1");
        dirty_slot(temp.path(), "default-ingest-2");
        dirty_slot(temp.path(), &format!("default-{}-2", "col"));
        dirty_slot(temp.path(), &format!("default-{}-2", "row"));

        let mut actual = managed_slot_recovery_candidates_from(temp.path(), "default", 2);
        actual.sort();

        assert_eq!(actual, vec![temp.path().join("default-ingest-2")]);
    }

    #[test]
    fn slot_reservations_reserve_specific_index() {
        let mut disk = SlotReservations::with_disk_slots(2);
        assert!(disk.reserve(1));
        assert!(!disk.reserve(1), "double-reserve must fail");
        assert!(!disk.reserve(2), "out-of-range reserve must fail");
        disk.free(Some(1));
        assert!(disk.reserve(1), "freed slot can be reserved again");

        let mut in_memory = SlotReservations::default();
        assert!(!in_memory.reserve(0));
    }
}
