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
//! `QuestDb` is a thread-safe pool of store-and-forward producer handles to a
//! single QuestDB QWP/WebSocket endpoint. The pool is lazy: `connect` performs
//! no blocking network I/O. In disk-backed store-and-forward mode it may
//! pre-open parked recovery senders whose initial connect and replay run in the
//! background. Borrowing [`QuestDb::borrow_column_sender`] creates a local
//! store-and-forward producer immediately and lets its background runner connect
//! later, so callers can buffer while the server is absent. Direct column
//! senders, readers, and row senders still open their transport on first borrow.
//! The pools auto-grow up to `pool_max` on demand and (under `pool_reap=auto`)
//! run a background thread that closes above-`pool_size` idle entries after
//! `pool_idle_timeout_ms`.
//!
//! Each pool slot is handed out as a [`BorrowedColumnSender`] which returns
//! itself to the pool on `Drop`. Slots whose underlying connection has
//! latched terminal state are dropped on return instead of being
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
#[cfg(feature = "_egress")]
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(feature = "_egress")]
use crate::egress::Reader;
use crate::ingress::sender::is_candidate_orphan;
use crate::ingress::sender::qwp_ws::QwpWsHostHealthTracker;
use crate::ingress::{Buffer, Sender, SenderBuilder};
use crate::ingress::{
    QwpWsConnector, QwpWsManagedSlotExclusion, RawQwpWsRoundStream, ReconnectReason,
};
// The reconnect backoff helpers are only consumed by the retry-capable borrow
// paths: the row-major polars `reborrow_with_retry` and the FFI owned
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
/// kind (column-major sender, row-major sender, reader), so it lives with the
/// pool rather than under the column sender.
mod conf;

use crate::ingress::AckLevel;
use crate::ingress::column_sender::ColumnSender;
use crate::ingress::column_sender::conn::ColumnConn;
use conf::PoolReap;

/// FFI escape-hatch surface: owned (lifetime-free) pool handles and the entry
/// points that mint them, for the `questdb-rs-ffi` C-ABI crate. Hidden,
/// feature-gated, and not part of the public Rust API — normal Rust users
/// borrow lifetime-bound handles via [`QuestDb::borrow_column_sender`] /
/// [`QuestDb::borrow_row_sender`] (and, with egress, `QuestDb::borrow_reader`).
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
fn lock_state(m: &Mutex<PoolState>) -> std::sync::MutexGuard<'_, PoolState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Which column-sender pool a borrow / return targets.
///
/// The two pools are structurally identical (`Mutex<PoolState>`) but differ in
/// what they hand out:
/// * [`ColumnPoolKind::Main`] — the general-purpose pool behind
///   [`QuestDb::borrow_column_sender`]: always store-and-forward — an
///   in-memory queue when no `sf_dir` is set (pools freely up to `pool_max`),
///   disk-backed with one managed slot directory per pooled sender when it is.
///   A parked connection's background runner keeps delivering, and pool close / reap
///   flush queued frames best-effort within `close_flush_timeout`; for a hard
///   delivery guarantee on an in-memory queue, call [`BorrowedColumnSender::wait`]
///   before close (or use `sf_dir`). `wait` is an ack-wait barrier (block until
///   the published frame reaches the requested [`AckLevel`]), not a
///   commit-or-lose-data step.
/// * [`ColumnPoolKind::Direct`] — the always-direct pool behind
///   [`QuestDb::borrow_direct_column_sender`], independent of `sf_dir`. Used by
///   DataFrame ingestion (Polars / Pandas), which drives its own replay from
///   the source frame and so wants a plain pipelined connection, never the SFA
///   queue.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ColumnPoolKind {
    Main,
    Direct,
}

/// Select the `PoolState` mutex for `kind`.
fn column_pool_state(inner: &DbInner, kind: ColumnPoolKind) -> &Mutex<PoolState> {
    match kind {
        ColumnPoolKind::Main => &inner.state,
        ColumnPoolKind::Direct => &inner.direct_state,
    }
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
    cv: &'a Condvar,
    slot_index: Option<usize>,
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

/// Row-major sender equivalent of `ReaderInUseSlot`: reserves an `in_use`
/// slot under the cap and releases it on drop unless `commit` is called.
struct RowSenderInUseSlot<'a> {
    state: &'a Mutex<RowSenderPoolState>,
    cv: &'a Condvar,
    slot_index: Option<usize>,
    armed: bool,
}

impl RowSenderInUseSlot<'_> {
    fn commit(mut self) {
        self.armed = false;
    }
}

impl Drop for RowSenderInUseSlot<'_> {
    fn drop(&mut self) {
        if self.armed {
            let mut state = lock_row_sender_state(self.state);
            state.in_use = state.in_use.saturating_sub(1);
            state.free_slot_index(self.slot_index);
            self.cv.notify_all();
        }
    }
}

struct ColumnSlotRelease<'a> {
    inner: &'a DbInner,
    kind: ColumnPoolKind,
    slot_index: Option<usize>,
    decrement_in_use: bool,
    decrement_closing: bool,
}

impl Drop for ColumnSlotRelease<'_> {
    fn drop(&mut self) {
        if self.slot_index.is_none() && !self.decrement_in_use && !self.decrement_closing {
            return;
        }
        let mut state = lock_state(column_pool_state(self.inner, self.kind));
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

struct RowSlotRelease<'a> {
    inner: &'a DbInner,
    slot_index: Option<usize>,
    decrement_in_use: bool,
    decrement_closing: bool,
}

impl Drop for RowSlotRelease<'_> {
    fn drop(&mut self) {
        if self.slot_index.is_none() && !self.decrement_in_use && !self.decrement_closing {
            return;
        }
        let mut state = lock_row_sender_state(&self.inner.row_sender_state);
        if self.decrement_in_use {
            state.in_use = state.in_use.saturating_sub(1);
        }
        if self.decrement_closing {
            state.closing = state.closing.saturating_sub(1);
        }
        state.free_slot_index(self.slot_index);
        self.inner.row_cv.notify_all();
    }
}

/// Connection pool for the column-major sender API.
///
/// Construct with [`QuestDb::connect`]. Share the pool across threads — its
/// internal state is `Mutex`-guarded so [`QuestDb::borrow_column_sender`] /
/// [`QuestDb::reap_idle`] / Drop-driven returns are safe to interleave.
///
/// Each borrow ([`BorrowedColumnSender`] / the internal direct sender) is **not** `Send` — it belongs to the
/// thread that borrowed it. To ingest in parallel, borrow one sender per
/// worker thread from the same `QuestDb`.
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
    /// Parsed row-sender builder retained so the pool can build row-major
    /// senders with the same validated config while overriding only the
    /// managed disk-SF slot id.
    row_sender_builder: SenderBuilder,
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
    /// minted as `<base>-col-<index>` and `<base>-row-<index>`.
    slot_base_id: String,
    /// Managed row/column slot ranges excluded from orphan scans so sibling
    /// senders do not adopt each other's live pool slots.
    managed_slot_exclusions: Vec<QwpWsManagedSlotExclusion>,
    pool_idle_timeout: Duration,
    state: Mutex<PoolState>,
    /// Always-direct column-sender pool, independent of `sf_dir`. Backs
    /// [`QuestDb::borrow_direct_column_sender`] (DataFrame ingestion). Lazy-init
    /// like the reader / row-sender pools: starts empty, opens a direct
    /// connection on demand, recycles through its own free list and the shared
    /// `pool_max` cap. Kept separate from `state` so DataFrame ingest always
    /// gets a plain pipelined connection even when `state` is in
    /// store-and-forward mode.
    direct_state: Mutex<PoolState>,
    /// Reader pool. Lazy-init: starts empty, populated on first
    /// `borrow_reader_owned` call. Applies the same `pool_size` /
    /// `pool_max` / `pool_idle_timeout` values as the sender pool but
    /// tracks and caps them on an independent free list, so heavy ingest
    /// can't starve queries. The caps are enforced separately, so the
    /// combined live connection count across the column-sender, direct
    /// column-sender, reader, and row-major-sender pools can reach up to
    /// `4 * pool_max`.
    #[cfg(feature = "_egress")]
    reader_state: Mutex<ReaderPoolState>,
    /// Row-major (`crate::ingress::Sender`) pool. Lazy-init, independent free
    /// list and `pool_max` cap, rebuilt from `conf` via
    /// `SenderBuilder::from_conf`. Lets callers borrow a classic ILP row
    /// sender from the same `QuestDb` handle as the column-major senders.
    row_sender_state: Mutex<RowSenderPoolState>,
    /// Row-sender counterpart to `cv`; kept separate because a Rust `Condvar`
    /// must not be waited on with multiple mutexes.
    row_cv: Condvar,
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

#[derive(Default)]
struct PoolState {
    /// Idle connections. Borrow/return is LIFO on the back (push/pop);
    /// the reaper drains the oldest entries from the front. Keeps hot
    /// connections warm in the common case while the reaper still
    /// retires entries in age order.
    free: Vec<PoolEntry>,
    /// Sum of currently-borrowed senders + in-flight grow operations.
    in_use: usize,
    /// Reserved disk slots whose sender has started close/drop but has not yet
    /// released the slot flock. Borrowers at cap may wait for this to complete.
    closing: usize,
    /// Disk-backed store-and-forward slot reservations. Empty for in-memory
    /// SF and direct senders; populated for pool-minted disk slot indices.
    slots: SlotReservations,
}

impl PoolState {
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

struct PoolEntry {
    sender: ColumnSender,
    slot_index: Option<usize>,
    last_idle_at: Instant,
}

struct PooledColumnSender {
    sender: ColumnSender,
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

#[derive(Default)]
struct RowSenderPoolState {
    /// Idle row-major senders, oldest at front, newest at back (push on
    /// return / pop on borrow). Same FIFO/LIFO discipline as the column
    /// sender free list.
    free: Vec<RowSenderPoolEntry>,
    /// Currently-borrowed row senders + in-flight grow operations.
    in_use: usize,
    /// Reserved disk slots whose sender has started close/drop but has not yet
    /// released the slot flock.
    closing: usize,
    /// Disk-backed store-and-forward slot reservations, as in [`PoolState`].
    slots: SlotReservations,
}

impl RowSenderPoolState {
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

struct RowSenderPoolEntry {
    /// A classic ILP row sender. It owns its connection and per-connection
    /// state internally, so (like the reader pool) we don't track extra
    /// fields alongside it.
    sender: Sender,
    slot_index: Option<usize>,
    last_idle_at: Instant,
}

struct PooledRowSender {
    sender: Sender,
    slot_index: Option<usize>,
}

#[derive(Clone, Copy)]
enum ManagedSlotKind {
    Column,
    Row,
}

impl ManagedSlotKind {
    fn label(self) -> &'static str {
        match self {
            Self::Column => "col",
            Self::Row => "row",
        }
    }
}

const MANAGED_SLOT_KINDS: [ManagedSlotKind; 2] = [ManagedSlotKind::Column, ManagedSlotKind::Row];

struct ManagedSlotRecoveryCandidate {
    kind: ManagedSlotKind,
    index: usize,
    path: PathBuf,
}

#[derive(Default)]
struct ManagedSlotRecoveryScan {
    in_range: Vec<ManagedSlotRecoveryCandidate>,
    out_of_range: Vec<PathBuf>,
}

fn managed_slot_exclusions(base: &str, pool_max: usize) -> Vec<QwpWsManagedSlotExclusion> {
    vec![
        managed_slot_exclusion(base, ManagedSlotKind::Column, pool_max),
        managed_slot_exclusion(base, ManagedSlotKind::Row, pool_max),
    ]
}

fn managed_slot_exclusion(
    base: &str,
    kind: ManagedSlotKind,
    pool_max: usize,
) -> QwpWsManagedSlotExclusion {
    QwpWsManagedSlotExclusion::new(managed_slot_prefix(base, kind), pool_max)
}

fn managed_slot_id(base: &str, kind: ManagedSlotKind, index: usize) -> String {
    managed_slot_exclusion(base, kind, usize::MAX).slot_name(index)
}

fn managed_slot_prefix(base: &str, kind: ManagedSlotKind) -> String {
    format!("{}-{}-", base, kind.label())
}

fn parse_managed_slot_id(base: &str, name: &str) -> Option<(ManagedSlotKind, usize)> {
    for kind in MANAGED_SLOT_KINDS {
        let exclusion = QwpWsManagedSlotExclusion::new(managed_slot_prefix(base, kind), usize::MAX);
        if let Some(index) = exclusion.parse_index(name) {
            return Some((kind, index));
        }
    }
    None
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
        let Some((kind, index)) = parse_managed_slot_id(base, &name) else {
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
                kind,
                index,
                path: slot_path,
            });
        } else {
            // This scan runs for every managed sender build, so the warning may
            // repeat for the same directory until one drainer drains it. A
            // DbInner-level dedupe set is a follow-up, not part of this fix.
            log::warn!(
                "adopting out-of-range store-and-forward slot `{}`; \
                 `<sender_id>-col-*` and `<sender_id>-row-*` directories under \
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
/// The recovery senders count toward the pool total like ordinary parked
/// senders: the column pool keeps up to `pool_size` warm, and excess senders
/// are reaped only after their queues are delivered and idle past the timeout.
/// Parked column recovery senders drain on pool close via
/// `drain_sfa_senders_bounded`; row queues remain persisted on disk and recover
/// on the next connect. Each pre-opened sender also enrolls out-of-range managed
/// slots in its orphan-drainer set, so those slots may begin replay at connect
/// as well. In the worst case this temporarily starts roughly `2 * pool_max`
/// background runners, bounded by the configured row and column slot caps.
fn preopen_recovery_senders(inner: &Arc<DbInner>) {
    if !inner.sf_disk {
        return;
    }
    let Some(sf_dir) = inner.connector.sf_dir() else {
        return;
    };
    let scan = managed_slot_recovery_scan_from(sf_dir, &inner.slot_base_id, inner.pool_max);
    for candidate in scan.in_range {
        match candidate.kind {
            ManagedSlotKind::Column => preopen_column_recovery_sender(
                inner,
                candidate.index,
                &candidate.path,
                &scan.out_of_range,
            ),
            ManagedSlotKind::Row => preopen_row_recovery_sender(
                inner,
                candidate.index,
                &candidate.path,
                &scan.out_of_range,
            ),
        }
    }
}

fn preopen_column_recovery_sender(
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
                "skipping parked store-and-forward column slot `{}` during recovery: {}",
                slot_path.display(),
                err
            );
        }
    }
}

fn preopen_row_recovery_sender(
    inner: &Arc<DbInner>,
    index: usize,
    slot_path: &Path,
    recovery_candidates: &[PathBuf],
) {
    let slot = {
        let mut state = lock_row_sender_state(&inner.row_sender_state);
        if !state.reserve_slot_index(index) {
            return;
        }
        state.in_use += 1;
        RowSenderInUseSlot {
            state: &inner.row_sender_state,
            cv: &inner.row_cv,
            slot_index: Some(index),
            armed: true,
        }
    };

    let sender_id = managed_slot_id(&inner.slot_base_id, ManagedSlotKind::Row, index);
    match inner.row_sender_builder.build_with_qwp_ws_pool_slot(
        Some(sender_id.as_str()),
        &inner.managed_slot_exclusions,
        recovery_candidates,
        true,
    ) {
        Ok(sender) => {
            let slot_index = slot.slot_index;
            {
                let mut state = lock_row_sender_state(&inner.row_sender_state);
                state.in_use = state.in_use.saturating_sub(1);
                state.free.push(RowSenderPoolEntry {
                    sender,
                    slot_index,
                    last_idle_at: Instant::now(),
                });
            }
            slot.commit();
            inner.row_cv.notify_all();
        }
        Err(err) => {
            log::warn!(
                "skipping parked store-and-forward row slot `{}` during recovery: {}",
                slot_path.display(),
                err
            );
        }
    }
}

impl QuestDb {
    /// Open a pool against `conf`.
    ///
    /// The connect string must use a QWP/WebSocket schema (`qwpws::` /
    /// `qwpwss::` / `ws::` / `wss::`). Pool-specific keys are recognised:
    ///
    /// | Key                    | Default | Meaning                                                        |
    /// |------------------------|---------|----------------------------------------------------------------|
    /// | `pool_size`            | 1       | Warm / minimum entries once opened. |
    /// | `pool_max`             | 64      | Hard cap on auto-grow. |
    /// | `pool_idle_timeout_ms` | 60000   | Above-`pool_size` idle connections are closed after this long. |
    /// | `pool_reap`            | `auto`  | `auto` runs a background reaper; `manual` requires `reap_idle`. |
    ///
    /// [`Self::borrow_column_sender`] is always store-and-forward (in-memory
    /// when no `sf_dir`, disk-backed when set), mirroring the row-major sender.
    /// Setting `sf_dir` selects disk-backed SF: every pooled row or column
    /// sender gets its own slot directory, minted from the configured
    /// `sender_id` base as `<base>-row-<index>` or `<base>-col-<index>`.
    /// Those `<sender_id>-row-*` and `<sender_id>-col-*` directories are
    /// reserved for this pool namespace under `sf_dir`; use a unique
    /// `sender_id` for each pool that shares an `sf_dir`.
    /// `pool_size` / `pool_max` keep the same per-kind meaning as in memory
    /// mode. At cap, borrows return `InvalidApiCall` except disk-backed
    /// row/column SF borrows can wait up to `close_flush_timeout` (default 5s)
    /// while an in-flight slot close releases its lock. For a plain pipelined
    /// (non-SF) connection — used by DataFrame ingestion — see
    /// [`Self::borrow_direct_column_sender`].
    ///
    /// Pools are **lazy**: `connect` performs no blocking network I/O. In
    /// disk-backed store-and-forward mode, it may pre-open parked recovery
    /// senders whose initial connect and replay run in the background. The
    /// store-and-forward column pool creates a local producer on first borrow
    /// and starts its initial connect in the background, so the borrower can
    /// buffer immediately even while the server is absent. Direct column
    /// senders, readers, and row senders still open their transport on first
    /// borrow, except for parked disk-SF recovery senders pre-opened at
    /// connect. `pool_size` is the warm minimum the reaper keeps once entries
    /// have been opened.
    ///
    pub fn connect(conf: &str) -> Result<Self> {
        let parsed = conf::parse(conf)?;
        // The main column and row pools are always store-and-forward:
        // in-memory queues when no `sf_dir`, disk-backed pool-minted slots when
        // set. Disk slots are kind-scoped (`<base>-col-N`, `<base>-row-N`) so
        // row and column pools do not churn each other's replay directories.
        let sf_disk = parsed.sf_disk;
        let pool_cfg = parsed.pool;

        let row_sender_builder = SenderBuilder::from_conf(conf)?;
        let connector = row_sender_builder.build_qwp_ws_connector()?;
        let health = QwpWsHostHealthTracker::new(connector.endpoint_count());
        let slot_base_id = connector.sender_id().to_owned();
        let managed_slot_exclusions = if sf_disk {
            managed_slot_exclusions(&slot_base_id, pool_cfg.pool_max)
        } else {
            Vec::new()
        };

        // Start empty; connect-time recovery may pre-open dirty disk-SF slots
        // after `inner` exists, otherwise the pools open on first borrow.
        let free = Vec::new();

        let inner = Arc::new(DbInner {
            #[cfg(feature = "_egress")]
            conf: conf.to_owned(),
            connector,
            row_sender_builder,
            health: Mutex::new(health),
            pool_size: pool_cfg.pool_size,
            pool_max: pool_cfg.pool_max,
            sf_disk,
            slot_base_id,
            managed_slot_exclusions,
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
            row_sender_state: Mutex::new(if sf_disk {
                RowSenderPoolState::with_disk_slots(pool_cfg.pool_max)
            } else {
                RowSenderPoolState::default()
            }),
            row_cv: Condvar::new(),
            cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
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

    /// Borrow a sender.
    ///
    /// Selection: pop the most-recently-returned slot from the free list;
    /// failing that, open a new connection if we are below `pool_max`;
    /// failing that, in disk-backed store-and-forward mode only, wait up to
    /// `close_flush_timeout` (default 5s) while an in-flight slot close
    /// releases its lock; failing that, return `InvalidApiCall`.
    pub fn borrow_column_sender(&self) -> Result<BorrowedColumnSender<'_>> {
        let cs = self.pick_column_sender()?;
        Ok(BorrowedColumnSender(ColumnSenderHandle::new(
            self,
            cs.sender,
            ColumnPoolKind::Main,
            cs.slot_index,
        )))
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
        let cs = pick_column_sender_inner(&self.inner, ColumnPoolKind::Direct)?;
        Ok(BorrowedDirectColumnSender(ColumnSenderHandle::new(
            self,
            cs.sender,
            ColumnPoolKind::Direct,
            cs.slot_index,
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

    /// Borrow a **row-major** ([`crate::ingress::Sender`]) ILP sender from the
    /// pool, the companion to the column-major [`Self::borrow_column_sender`].
    ///
    /// The row-sender pool is lazy except for disk-backed recovery senders
    /// pre-opened by [`Self::connect`]: it otherwise opens a fresh `Sender`
    /// (via `SenderBuilder::from_conf` on the original connect string) on
    /// demand, recycling returned senders through an independent free list and
    /// `pool_max` cap. In disk-backed store-and-forward mode, an at-cap borrow
    /// can wait up to `close_flush_timeout` (default 5s) while an in-flight slot
    /// close releases its lock; otherwise borrow at the cap returns
    /// [`ErrorCode::InvalidApiCall`](crate::ErrorCode::InvalidApiCall).
    ///
    /// The returned [`BorrowedRowSender`] exposes the usual `Buffer` build +
    /// `flush` flow directly, and returns the sender to the pool on `Drop`
    /// (unless its connection latched terminal state, or
    /// [`BorrowedRowSender::drop_on_return`] was called, in which case it is
    /// dropped and the next borrow opens a fresh one).
    pub fn borrow_row_sender(&self) -> Result<BorrowedRowSender<'_>> {
        let sender = self.pick_row_sender()?;
        Ok(BorrowedRowSender::new(
            self,
            sender.sender,
            sender.slot_index,
        ))
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
            sender: Some(cs.sender),
            kind: ColumnPoolKind::Main,
            slot_index: cs.slot_index,
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
        let cs = reconnect_pick(&self.inner, ColumnPoolKind::Main, deadline)?;
        Ok(OwnedColumnSender {
            inner: Arc::clone(&self.inner),
            sender: Some(cs.sender),
            kind: ColumnPoolKind::Main,
            slot_index: cs.slot_index,
        })
    }

    /// FFI escape hatch: like [`Self::borrow_direct_column_sender`] but the
    /// returned handle is not lifetime-bound to `&self` (carries an
    /// `Arc<DbInner>` so it can outlive the user-facing `QuestDb` pointer).
    /// Backs the C ABI's `questdb_db_borrow_direct_column_sender`. Hidden from
    /// the Rust API; Rust callers should prefer the lifetime-bound
    /// [`Self::borrow_direct_column_sender`].
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_direct_column_sender_owned(&self) -> Result<OwnedColumnSender> {
        let cs = pick_column_sender_inner(&self.inner, ColumnPoolKind::Direct)?;
        Ok(OwnedColumnSender {
            inner: Arc::clone(&self.inner),
            sender: Some(cs.sender),
            kind: ColumnPoolKind::Direct,
            slot_index: cs.slot_index,
        })
    }

    /// Like [`borrow_direct_column_sender_owned`] but retries the connect
    /// within `budget` using the reconnect backoff. Backs the C ABI's
    /// `questdb_db_borrow_direct_column_sender_with_retry`.
    #[cfg(feature = "ffi-support")]
    pub(crate) fn borrow_direct_column_sender_owned_with_retry(
        &self,
        budget: Duration,
    ) -> Result<OwnedColumnSender> {
        let deadline = Instant::now().checked_add(budget);
        let cs = reconnect_pick(&self.inner, ColumnPoolKind::Direct, deadline)?;
        Ok(OwnedColumnSender {
            inner: Arc::clone(&self.inner),
            sender: Some(cs.sender),
            kind: ColumnPoolKind::Direct,
            slot_index: cs.slot_index,
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
            sender: Some(sender.sender),
            must_close: false,
            slot_index: sender.slot_index,
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
                        sender: Some(sender.sender),
                        must_close: false,
                        slot_index: sender.slot_index,
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

    fn pick_column_sender(&self) -> Result<PooledColumnSender> {
        pick_column_sender_inner(&self.inner, ColumnPoolKind::Main)
    }

    fn pick_row_sender(&self) -> Result<PooledRowSender> {
        let slot = {
            let mut state = lock_row_sender_state(&self.inner.row_sender_state);
            let mut close_wait_deadline = None;
            loop {
                if self.inner.shutdown.load(Ordering::SeqCst) {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "QuestDb pool is closed; cannot borrow row sender"
                    ));
                }
                if let Some(entry) = state.free.pop() {
                    state.in_use += 1;
                    drop(state);
                    return Ok(PooledRowSender {
                        sender: entry.sender,
                        slot_index: entry.slot_index,
                    });
                }
                if state.reserved_total() < self.inner.pool_max {
                    break;
                }
                let wait_timeout = self.inner.connector.close_flush_timeout();
                if self.inner.sf_disk
                    && state.closing > 0
                    && let Some(wait_for) =
                        remaining_close_wait(&mut close_wait_deadline, wait_timeout)
                {
                    let (next_state, _) = match self.inner.row_cv.wait_timeout(state, wait_for) {
                        Ok((guard, result)) => (guard, result),
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    state = next_state;
                    continue;
                }
                return Err(error::fmt!(
                    InvalidApiCall,
                    "Row-sender pool exhausted: {} row senders are currently borrowed \
                     and the pool is at its `pool_max` cap of {}. Return a sender or \
                     raise `pool_max`.",
                    state.in_use,
                    self.inner.pool_max
                ));
            }
            let slot_index = state.allocate_slot_index();
            debug_assert_eq!(slot_index.is_some(), self.inner.sf_disk);
            state.in_use += 1;
            RowSenderInUseSlot {
                state: &self.inner.row_sender_state,
                cv: &self.inner.row_cv,
                slot_index,
                armed: true,
            }
        };
        let sender_id = slot
            .slot_index
            .map(|index| managed_slot_id(&self.inner.slot_base_id, ManagedSlotKind::Row, index));
        let recovery_candidates = managed_slot_recovery_candidates(&self.inner);
        let sender = self.inner.row_sender_builder.build_with_qwp_ws_pool_slot(
            sender_id.as_deref(),
            &self.inner.managed_slot_exclusions,
            &recovery_candidates,
            false,
        )?;
        let slot_index = slot.slot_index;
        slot.commit();
        Ok(PooledRowSender { sender, slot_index })
    }

    fn pick_replacement_sender(&self, kind: ColumnPoolKind) -> Result<PooledColumnSender> {
        if self.inner.shutdown.load(Ordering::SeqCst) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QuestDb pool is closed; cannot replace column sender"
            ));
        }
        // The main pool is always store-and-forward; its background runner owns
        // reconnects, so there is nothing to swap here.
        if kind == ColumnPoolKind::Main {
            return Err(error::fmt!(
                InvalidApiCall,
                "column sender store-and-forward manages reconnects in its background runner"
            ));
        }
        // Same-handle replacement: the borrowed column sender already owns one
        // logical in-use slot, so this must not reserve another one or
        // pool_max=1 would reject replacing a dead direct connection.
        if let Some(entry) = lock_state(column_pool_state(&self.inner, kind)).free.pop() {
            return Ok(PooledColumnSender {
                sender: entry.sender,
                slot_index: entry.slot_index,
            });
        }

        let conn = connect_conn_pool(&self.inner)?;
        Ok(PooledColumnSender {
            sender: ColumnSender::new(
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
    /// down (or [`BorrowedReader::drop_on_return`] was called), in which
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
        let slot = {
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
            if state.total() >= self.inner.pool_max {
                return Err(EgressError::new(
                    EgressErrorCode::InvalidApiCall,
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
        {
            let _g = lock_row_sender_state(&self.inner.row_sender_state);
            self.inner.row_cv.notify_all();
        }
        if let Some(handle) = self.reaper.take() {
            let _ = handle.join();
        }
        // Close idle resources now. Outstanding borrows hold their own Arc and
        // will be dropped instead of recycled when they return after shutdown.
        drain_idle_inner(&self.inner);
    }
}

/// Shared pool plumbing behind the two public column-sender handles
/// ([`BorrowedColumnSender`] and [`BorrowedDirectColumnSender`]). Holds the borrowed
/// [`ColumnSender`] plus the bookkeeping needed to return it to the pool on
/// drop / reborrow. The public wrappers expose only the mode-appropriate
/// method surface; this type is private.
///
/// On `Drop` the underlying connection is returned to the pool unless it
/// has latched terminal state, in which case it is dropped (and
/// auto-grow will open a fresh one for the next borrow).
///
/// Not `Send` or `Sync`: the borrowed connection belongs to the borrowing
/// thread for the duration of the borrow.
struct ColumnSenderHandle<'a> {
    db: &'a QuestDb,
    sender: Option<ColumnSender>,
    /// Which pool this handle returns to on drop / reborrow.
    kind: ColumnPoolKind,
    slot_index: Option<usize>,
    /// !Send / !Sync marker — `Rc<()>` poisons both auto traits without any
    /// runtime cost.
    _not_send: PhantomData<Rc<()>>,
}

impl<'a> ColumnSenderHandle<'a> {
    fn new(
        db: &'a QuestDb,
        sender: ColumnSender,
        kind: ColumnPoolKind,
        slot_index: Option<usize>,
    ) -> Self {
        Self {
            db,
            sender: Some(sender),
            kind,
            slot_index,
            _not_send: PhantomData,
        }
    }

    fn inner_mut(&mut self) -> &mut ColumnSender {
        self.sender
            .as_mut()
            .expect("borrowed column sender already returned")
    }

    fn inner_ref(&self) -> &ColumnSender {
        self.sender
            .as_ref()
            .expect("borrowed column sender already returned")
    }

    /// The pool's reconnect backoff budget; see [`QuestDb::reconnect_policy`].
    #[cfg(any(feature = "polars-ingress", feature = "polars-egress"))]
    pub(crate) fn reconnect_policy(&self) -> crate::ingress::ReconnectPolicy {
        self.db.reconnect_policy()
    }

    /// Drop the current connection (and its paired connection-scoped
    /// `SymbolGlobalDict`) back to the pool and obtain a fresh one **behind
    /// the same handle**, so the caller's borrowed column sender stays valid.
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
            // reborrow is a failover path, not a forced rotate. A healthy,
            // fully-sync'd connection needs no replacement; replacing it would
            // open a fresh connection and recycle this one, growing the pool.
            if sender.in_flight() == 0 && !sender.must_close() && !sender.transport_dead() {
                return Ok(());
            }
            if sender.in_flight() > 0 {
                log::warn!(
                    "column sender failover dropped a connection with un-sync'd \
                     deferred frame(s); their data is discarded. Re-drive the source \
                     from the last successful sync(), not from the failing chunk."
                );
                sender.mark_must_close();
            }
            record_sender_transport_failure(&self.db.inner, sender);
        }
        let fresh = self.db.pick_replacement_sender(self.kind)?;
        let old_slot_index = std::mem::replace(&mut self.slot_index, fresh.slot_index);
        if let Some(old) = self.sender.replace(fresh.sender) {
            finish_replaced_sender(&self.db.inner, old, self.kind, old_slot_index);
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

impl Debug for ColumnSenderHandle<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ColumnSenderHandle")
            .field("sender", &self.sender)
            .finish()
    }
}

/// Store-and-forward column sender borrowed from a [`QuestDb`] pool — the
/// handle returned by [`QuestDb::borrow_column_sender`].
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
pub struct BorrowedColumnSender<'a>(ColumnSenderHandle<'a>);

impl<'a> BorrowedColumnSender<'a> {
    /// Encode and publish `chunk` into the store-and-forward queue, returning
    /// as soon as the frame is accepted locally (no server round-trip). On
    /// success `chunk` is cleared; on a delivery-uncertain failure the error
    /// is tagged [`in_doubt`](crate::Error::in_doubt).
    pub fn flush(&mut self, chunk: &mut crate::ingress::column_sender::Chunk<'_>) -> Result<()> {
        self.0.inner_mut().flush(chunk)
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
        self.0.inner_ref().is_store_and_forward()
    }

    /// In-flight (published-but-unacked) frame count. Always 0 for the SF
    /// backend, whose queue tracks delivery internally.
    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u32 {
        self.0.inner_ref().in_flight()
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

impl Debug for BorrowedColumnSender<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BorrowedColumnSender")
            .field(&self.0)
            .finish()
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
pub struct BorrowedDirectColumnSender<'a>(ColumnSenderHandle<'a>);

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
    /// [`BorrowedColumnSender`] and test assertions.
    #[cfg(test)]
    pub(crate) fn is_store_and_forward(&self) -> bool {
        self.0.inner_ref().is_store_and_forward()
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

impl Drop for ColumnSenderHandle<'_> {
    fn drop(&mut self) {
        let Some(mut sender) = self.sender.take() else {
            return;
        };
        commit_in_flight_on_drop(&self.db.inner, &mut sender);
        return_to_pool(&self.db.inner, sender, self.kind, self.slot_index);
    }
}

/// Owned (lifetime-free) variant of a borrowed column sender used by the C FFI.
///
/// Holds an `Arc<DbInner>` so the pool's return path outlives the
/// user-facing `QuestDb` pointer — the C ABI can free its `questdb_db*`
/// before dropping outstanding `column_sender*` handles. After pool close,
/// returned handles are dropped instead of recycled.
#[cfg(feature = "ffi-support")]
pub struct OwnedColumnSender {
    inner: Arc<DbInner>,
    sender: Option<ColumnSender>,
    kind: ColumnPoolKind,
    slot_index: Option<usize>,
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
            commit_in_flight_on_drop(&self.inner, &mut sender);
            return_to_pool(&self.inner, sender, self.kind, self.slot_index);
        }
    }
}

/// A row-major [`crate::ingress::Sender`] borrowed from a [`QuestDb`] pool.
///
/// Companion to [`BorrowedColumnSender`] (the column-major handle). Exposes the row
/// ingestion and progress-tracking surface directly, except for the standalone
/// [`Sender::must_close`] lifecycle predicate. On `Drop` the sender is returned
/// to the row-sender pool, unless its connection has latched terminal state (or
/// [`Self::drop_on_return`] was called), in which case it is dropped and the
/// next borrow opens a fresh one.
///
/// Use [`Self::flush_and_wait`] for the common safe shape ("publish this
/// batch and return once it is acknowledged"). Use [`Self::wait`] as a
/// standalone blocking barrier for everything published so far through this
/// borrowed sender. Use FSNs for non-blocking
/// pipelining while you still hold the same borrowed sender: publish with
/// [`Self::flush_and_get_fsn`], keep doing work, then compare the saved FSN
/// with [`Self::acked_fsn`]. FSNs are stream watermarks, not portable receipts
/// to check through an arbitrary later pool borrow.
///
/// `BorrowedRowSender` is **not** `Send` or `Sync`: the borrowed connection
/// belongs to the borrowing thread for the duration of the borrow.
pub struct BorrowedRowSender<'a> {
    db: &'a QuestDb,
    sender: Option<Sender>,
    must_close: bool,
    slot_index: Option<usize>,
    /// !Send / !Sync marker, mirroring [`BorrowedColumnSender`].
    _not_send: PhantomData<Rc<()>>,
}

impl<'a> BorrowedRowSender<'a> {
    fn new(db: &'a QuestDb, sender: Sender, slot_index: Option<usize>) -> Self {
        Self {
            db,
            sender: Some(sender),
            must_close: false,
            slot_index,
            _not_send: PhantomData,
        }
    }

    fn sender_ref(&self) -> &Sender {
        self.sender
            .as_ref()
            .expect("borrowed row sender already returned")
    }

    fn sender_mut(&mut self) -> &mut Sender {
        self.sender
            .as_mut()
            .expect("borrowed row sender already returned")
    }

    /// Create a new row buffer using this sender's protocol settings.
    pub fn new_buffer(&self) -> Buffer {
        self.sender_ref().new_buffer()
    }

    /// Send the batch of rows in the buffer to the QuestDB server, and, if
    /// `transactional` is true, require a transactional flush.
    #[cfg(feature = "sync-sender-http")]
    pub fn flush_and_keep_with_flags(&mut self, buf: &Buffer, transactional: bool) -> Result<()> {
        self.sender_mut()
            .flush_and_keep_with_flags(buf, transactional)
    }

    /// Send the buffer of rows, then clear the buffer.
    pub fn flush(&mut self, buf: &mut Buffer) -> Result<()> {
        self.sender_mut().flush(buf)
    }

    /// Publish the buffer, clear it, then block until every frame published
    /// so far through this sender reaches `ack_level` — [`Self::flush`]
    /// followed by [`Self::wait`] in one call, the row-major counterpart of
    /// [`BorrowedColumnSender::flush_and_wait`]. Unlike [`Self::wait`], which
    /// takes an explicit timeout argument, this call's wait is bounded by
    /// the pool-wide `request_timeout` setting (the no-progress timeout
    /// fires when the ack watermark stops advancing for that long); compose
    /// the two calls yourself to choose the timeout per call.
    ///
    /// `AckLevel::Durable` requires the pool to be opened with
    /// `request_durable_ack=on`; otherwise the call is rejected up front
    /// (`InvalidApiCall`) before the buffer is touched, matching
    /// [`BorrowedColumnSender::flush_and_wait`].
    ///
    /// On a flush failure the buffer is retained. After publication, only the
    /// no-progress timeout ([`ErrorCode::FailoverRetry`](crate::ErrorCode))
    /// leaves the frames queued with the runner still delivering — recover
    /// from it by calling [`Self::wait`] until it returns `Ok`, not by
    /// re-flushing (which would deliver the same rows twice). A terminal
    /// server rejection or transport/protocol failure ends delivery on this
    /// sender: drop the borrow and re-drive undelivered rows on a fresh one.
    pub fn flush_and_wait(&mut self, buf: &mut Buffer, ack_level: AckLevel) -> Result<()> {
        validate_row_sender_ack_level(&self.db.inner, ack_level)?;
        let timeout = self.db.inner.connector.request_timeout();
        let sender = self.sender_mut();
        sender.flush(buf)?;
        sender.wait(ack_level, timeout)
    }

    /// Send the buffer of rows, keeping the buffer intact.
    pub fn flush_and_keep(&mut self, buf: &Buffer) -> Result<()> {
        self.sender_mut().flush_and_keep(buf)
    }

    /// Publish the QWP/WebSocket buffer, clear it, and return the highest
    /// published frame sequence number.
    ///
    /// This is the non-blocking progress-tracking form of [`Self::flush`]:
    /// success means the frame was accepted by this sender's local replay
    /// queue, not that the server has ACKed it. Keep the returned FSN while
    /// this borrowed sender is still held, then compare it with
    /// [`Self::acked_fsn`] to observe when the publication boundary has
    /// completed. Use [`Self::wait`] instead when you only need a simple
    /// blocking barrier for everything published so far.
    pub fn flush_and_get_fsn(&mut self, buf: &mut Buffer) -> Result<Option<u64>> {
        self.sender_mut().flush_and_get_fsn(buf)
    }

    /// Publish the QWP/WebSocket buffer without clearing it and return the
    /// highest published frame sequence number.
    ///
    /// The returned FSN has the same local-publication semantics as
    /// [`Self::flush_and_get_fsn`].
    pub fn flush_and_keep_and_get_fsn(&mut self, buf: &Buffer) -> Result<Option<u64>> {
        self.sender_mut().flush_and_keep_and_get_fsn(buf)
    }

    /// Return the highest frame sequence number published locally by this
    /// sender, or `None` if no frame has been published.
    ///
    /// This is a stream watermark for the currently borrowed sender. Treat
    /// saved FSNs as meaningful only with the sender stream that produced
    /// them; returning the handle to the pool does not create a portable
    /// receipt that can be checked through an arbitrary later borrow.
    pub fn published_fsn(&self) -> Result<Option<u64>> {
        self.sender_ref().published_fsn()
    }

    /// Return the highest frame sequence number completed by server ACK or
    /// server-side reject-and-continue, or `None` if no frame has completed.
    ///
    /// This is useful for non-blocking pipelining: after
    /// [`Self::flush_and_get_fsn`] returns `Some(fsn)`, that publication
    /// boundary has completed once this method returns a value greater than
    /// or equal to `fsn`. In durable-ACK mode this watermark advances after
    /// durable ACK coverage; use [`Self::wait`] when you need an explicit
    /// [`AckLevel::Ok`] or [`AckLevel::Durable`] barrier.
    pub fn acked_fsn(&self) -> Result<Option<u64>> {
        self.sender_ref().acked_fsn()
    }

    /// Block until every frame published so far through this sender reaches
    /// `ack_level`.
    ///
    /// Prefer this over FSN polling unless you need to keep publishing or doing
    /// other work while ACKs arrive. If it times out, the frames remain queued;
    /// retry `wait()` or keep observing the watermark rather than re-flushing
    /// the same data. `AckLevel::Durable` requires the pool to have been opened
    /// with `request_durable_ack=on`; otherwise the call is rejected even when
    /// no frames have been published.
    pub fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()> {
        self.sender_mut().wait(ack_level, timeout)
    }

    /// Force this borrowed sender to be dropped (not recycled) when the borrow
    /// ends.
    ///
    /// Use normal `Drop` for healthy senders: the return path already retires
    /// senders that latched terminal state, or whose pool has been closed.
    /// Call this after abandoning work or handling an error where the next
    /// borrower must not inherit this connection.
    pub fn drop_on_return(&mut self) {
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

impl Drop for BorrowedRowSender<'_> {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            return_row_sender_to_pool(&self.db.inner, sender, self.must_close, self.slot_index);
        }
    }
}

/// Durable-ack preflight shared by the row-sender `flush_and_wait` forms:
/// mirrors the column senders' `validate_ack_level`, rejecting
/// `AckLevel::Durable` before any publication when the pool did not opt in.
fn validate_row_sender_ack_level(inner: &DbInner, ack_level: AckLevel) -> Result<()> {
    if ack_level == AckLevel::Durable && !inner.connector.request_durable_ack() {
        return Err(error::fmt!(
            InvalidApiCall,
            "AckLevel::Durable requires the pool to be opened with \
             `request_durable_ack=on` in the connect string."
        ));
    }
    Ok(())
}

fn return_row_sender_to_pool(
    inner: &Arc<DbInner>,
    sender: Sender,
    must_close: bool,
    slot_index: Option<usize>,
) {
    let must_close = must_close || sender.must_close();
    let release_slot;
    {
        let mut state = lock_row_sender_state(&inner.row_sender_state);
        if !must_close && !inner.shutdown.load(Ordering::SeqCst) {
            state.in_use = state.in_use.saturating_sub(1);
            state.free.push(RowSenderPoolEntry {
                sender,
                slot_index,
                last_idle_at: Instant::now(),
            });
            inner.row_cv.notify_all();
            return;
        }
        release_slot = slot_index.is_some();
        if release_slot {
            state.closing += 1;
        } else {
            state.in_use = state.in_use.saturating_sub(1);
        }
    }
    let _release = release_slot.then_some(RowSlotRelease {
        inner: inner.as_ref(),
        slot_index,
        decrement_in_use: true,
        decrement_closing: true,
    });
    drop(sender);
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
    slot_index: Option<usize>,
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

    /// Combined [`Sender::flush`] + [`Sender::wait`] with the pool-wide
    /// `request_timeout` as the wait's no-progress deadline — the owned
    /// counterpart of [`BorrowedRowSender::flush_and_wait`] (same durable
    /// opt-in preflight and failure contract), used by the C FFI.
    pub fn flush_and_wait(&mut self, buf: &mut Buffer, ack_level: AckLevel) -> Result<()> {
        validate_row_sender_ack_level(&self.inner, ack_level)?;
        let timeout = self.inner.connector.request_timeout();
        let sender = self.get_mut();
        sender.flush(buf)?;
        sender.wait(ack_level, timeout)
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
            return_row_sender_to_pool(&self.inner, sender, self.must_close, self.slot_index);
        }
    }
}

/// A query [`Reader`] borrowed from a [`QuestDb`] pool.
///
/// Egress companion to [`BorrowedColumnSender`] (column-major) and
/// [`BorrowedRowSender`] (row-major). Derefs to `Reader`, so the usual
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
fn pick_column_sender_inner(
    inner: &Arc<DbInner>,
    kind: ColumnPoolKind,
) -> Result<PooledColumnSender> {
    // The main pool is always store-and-forward; the direct pool never is.
    let sfa = kind == ColumnPoolKind::Main;
    let pool = column_pool_state(inner, kind);
    let slot = {
        let mut state = lock_state(pool);
        let mut close_wait_deadline = None;
        loop {
            if inner.shutdown.load(Ordering::SeqCst) {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "QuestDb pool is closed; cannot borrow column sender"
                ));
            }
            if let Some(entry) = state.free.pop() {
                state.in_use += 1;
                drop(state);
                return Ok(PooledColumnSender {
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
                 Drop a borrowed column sender or increase pool_max.",
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
    if sfa {
        let sender = connect_sfa_pool(inner, slot.slot_index)?;
        let slot_index = slot.slot_index;
        slot.commit();
        return Ok(PooledColumnSender { sender, slot_index });
    }
    let conn = connect_conn_pool(inner)?;
    let slot_index = slot.slot_index;
    slot.commit();
    Ok(PooledColumnSender {
        sender: ColumnSender::new_direct(
            conn,
            crate::ingress::SymbolGlobalDict::new(),
            crate::ingress::column_sender::encoder::EncodeScratch::new(),
            false,
        ),
        slot_index,
    })
}

fn connect_sfa_pool(inner: &Arc<DbInner>, slot_index: Option<usize>) -> Result<ColumnSender> {
    let recovery_candidates = managed_slot_recovery_candidates(inner);
    connect_sfa_pool_with_recovery_candidates(inner, slot_index, &recovery_candidates)
}

fn connect_sfa_pool_with_recovery_candidates(
    inner: &Arc<DbInner>,
    slot_index: Option<usize>,
    recovery_candidates: &[PathBuf],
) -> Result<ColumnSender> {
    let sender_id = slot_index
        .map(|index| managed_slot_id(&inner.slot_base_id, ManagedSlotKind::Column, index));
    let state = inner
        .connector
        .connect_sfa_background_with_pool_slot(
            sender_id.as_deref(),
            &inner.managed_slot_exclusions,
            recovery_candidates,
        )
        .map_err(|err| {
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
fn reconnect_pick(
    inner: &Arc<DbInner>,
    kind: ColumnPoolKind,
    deadline: Option<Instant>,
) -> Result<PooledColumnSender> {
    let policy = inner.connector.reconnect_policy();
    let mut backoff = policy.initial_backoff();
    loop {
        match pick_column_sender_inner(inner, kind) {
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
    let raw: RawQwpWsRoundStream = inner.connector.connect_round_pooled(&inner.health)?;
    ColumnConn::from_round_stream(raw)
}

/// Best-effort commit of un-sync'd deferred frames on drop, so the natural
/// `flush()`-loop-then-drop path doesn't silently lose data. Commits at the
/// pool's default ack level so a `request_durable_ack=on` pool still waits for
/// the durability ACK instead of silently downgrading to `Ok`. On failure the
/// connection is latched `must_close` so the next borrower can't commit these
/// frames under a foreign table.
fn commit_in_flight_on_drop(inner: &Arc<DbInner>, sender: &mut ColumnSender) {
    if sender.in_flight() == 0 {
        return;
    }
    let ack = if inner.connector.request_durable_ack() {
        AckLevel::Durable
    } else {
        AckLevel::Ok
    };
    let committed = !sender.must_close() && !sender.transport_dead() && sender.sync(ack).is_ok();
    if !committed {
        log::warn!(
            "column sender dropped with un-sync'd deferred frame(s) that could \
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
/// mirroring [`commit_in_flight_on_drop`] for the direct backend. No-op for the
/// direct backend and for a connection that has already drained.
fn drain_sfa_before_drop(inner: &DbInner, sender: &mut ColumnSender) {
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
            "store-and-forward column sender dropped with frame(s) that could \
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
fn drain_sfa_senders_bounded(inner: &DbInner, senders: &mut [ColumnSender]) {
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
                "store-and-forward column sender dropped on pool close with \
                 frame(s) that could not be delivered within close_flush_timeout; \
                 their data is discarded. Call wait() before close, or set \
                 sf_dir for crash-durable persistence. Cause: {err}"
            );
        }
    }
}

fn return_to_pool(
    inner: &Arc<DbInner>,
    mut sender: ColumnSender,
    kind: ColumnPoolKind,
    slot_index: Option<usize>,
) {
    let must_close = sender.must_close();
    // A transport-dead connection marks its endpoint unhealthy in the shared
    // tracker so the next borrow rotates away from the dead peer (until it
    // re-probes healthy). A pool-driven `mark_must_close` (un-sync'd pending
    // frames) or a server-data rejection leaves the endpoint healthy.
    record_sender_transport_failure(inner, &sender);
    let release_slot;
    {
        let mut state = lock_state(column_pool_state(inner, kind));
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
    let _release = release_slot.then_some(ColumnSlotRelease {
        inner: inner.as_ref(),
        kind,
        slot_index,
        decrement_in_use: true,
        decrement_closing: true,
    });
    // Not recycling: this connection and its background runner are about to be
    // dropped. The store-and-forward (Main) pool owns a delivery contract, so
    // drain its queue first (bounded, outside the pool lock); the direct pool
    // discards uncommitted deferred frames by design, so this is a no-op there.
    drain_sfa_before_drop(inner, &mut sender);
    drop(sender);
}

fn finish_replaced_sender(
    inner: &Arc<DbInner>,
    sender: ColumnSender,
    kind: ColumnPoolKind,
    slot_index: Option<usize>,
) {
    debug_assert!(slot_index.is_none());
    let must_close = sender.must_close();
    record_sender_transport_failure(inner, &sender);
    {
        let mut state = lock_state(column_pool_state(inner, kind));
        if !must_close && !inner.shutdown.load(Ordering::SeqCst) && state.total() < inner.pool_max {
            state.free.push(PoolEntry {
                sender,
                slot_index: None,
                last_idle_at: Instant::now(),
            });
            inner.cv.notify_all();
            return;
        }
    }
    drop(sender);
}

fn record_sender_transport_failure(inner: &Arc<DbInner>, sender: &ColumnSender) {
    if sender.transport_dead()
        && let Some(idx) = sender.endpoint_idx()
    {
        lock_health(&inner.health)
            .record_mid_stream_failure(idx, Some(ReconnectReason::RetryableFailure));
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
    dropped += reap_idle_direct_senders(inner);
    dropped += reap_idle_row_senders(inner);
    #[cfg(feature = "_egress")]
    {
        dropped += reap_idle_readers(inner);
    }
    dropped
}

fn drain_idle_inner(inner: &DbInner) -> usize {
    let mut dropped = drain_idle_senders(inner);
    dropped += drain_idle_direct_senders(inner);
    dropped += drain_idle_row_senders(inner);
    #[cfg(feature = "_egress")]
    {
        dropped += drain_idle_readers(inner);
    }
    dropped
}

fn drain_idle_senders(inner: &DbInner) -> usize {
    let mut to_drop: Vec<ColumnSender> = {
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
    let to_drop: Vec<ColumnSender> = {
        let mut state = lock_state(&inner.direct_state);
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
    let durable = inner.connector.request_durable_ack();
    let mut dropped = 0;
    while let Some((sender, slot_index)) = take_reapable_column_sender(inner, durable) {
        let _release = slot_index.is_some().then_some(ColumnSlotRelease {
            inner,
            kind: ColumnPoolKind::Main,
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
) -> Option<(ColumnSender, Option<usize>)> {
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
    // timeout, mirroring the row-sender pool.
    let to_drop: Vec<ColumnSender> = {
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

fn reap_idle_row_senders(inner: &DbInner) -> usize {
    let durable = inner.connector.request_durable_ack();
    let mut dropped = 0;
    while let Some((sender, slot_index)) = take_reapable_row_sender(inner, durable) {
        let _release = slot_index.is_some().then_some(RowSlotRelease {
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

fn take_reapable_row_sender(inner: &DbInner, durable: bool) -> Option<(Sender, Option<usize>)> {
    // The row-sender pool has no warm-min floor to preserve, even when
    // connect-time recovery pre-opened dirty disk-SF slots. Reap only senders
    // parked longer than the idle timeout and whose store-and-forward queue has
    // no undelivered frames.
    let mut state = lock_row_sender_state(&inner.row_sender_state);
    let now = Instant::now();
    let mut i = 0;
    while i < state.free.len() {
        let idle_for = now.saturating_duration_since(state.free[i].last_idle_at);
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
    assert_not_send::<BorrowedDirectColumnSender<'_>>();
    assert_not_send::<BorrowedRowSender<'_>>();
    #[cfg(feature = "_egress")]
    assert_not_send::<BorrowedReader<'_>>();
    assert_not_send::<crate::ingress::column_sender::Chunk<'_>>();
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
        dirty_slot(temp.path(), "default-col-0");
        dirty_slot(temp.path(), "default-col-1");
        dirty_slot(temp.path(), "default-col-2");
        dirty_slot(temp.path(), "default-row-0");
        dirty_slot(temp.path(), "default-row-2");

        let mut actual = managed_slot_recovery_candidates_from(temp.path(), "default", 2);
        actual.sort();

        assert_eq!(
            actual,
            vec![
                temp.path().join("default-col-2"),
                temp.path().join("default-row-2")
            ]
        );
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
