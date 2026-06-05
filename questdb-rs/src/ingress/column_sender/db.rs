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
//! Each pool slot is handed out as a [`BorrowedSender<'_>`] which returns
//! itself to the pool on `Drop`. Slots whose underlying connection has
//! latched into `must_close=true` are dropped on return instead of being
//! recycled.

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

#[cfg(feature = "_egress")]
fn lock_reader_state(m: &Mutex<ReaderPoolState>) -> std::sync::MutexGuard<'_, ReaderPoolState> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// RAII guard that increments `state.in_use` on construction and
/// decrements it on drop unless [`InUseSlot::commit`] is called first.
/// Closes the leak window between `state.in_use += 1` and
/// `ColumnConn::connect`: a panic in the connect path (allocator OOM,
/// TLS handshake panic) would otherwise skip the matching decrement
/// and permanently strand a pool slot.
struct InUseSlot<'a> {
    state: &'a Mutex<PoolState>,
    armed: bool,
}

impl<'a> InUseSlot<'a> {
    /// Reserve a slot atomically with a cap check. Returns `Err` if
    /// `total() >= pool_max` already holds — preserving the documented
    /// fail-fast contract under concurrent borrows.
    fn reserve_within_cap(
        state: &'a Mutex<PoolState>,
        pool_max: usize,
    ) -> std::result::Result<Self, usize> {
        let mut guard = lock_state(state);
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

/// Connection pool for the column-major sender API.
///
/// Construct with [`QuestDb::connect`]. Share the pool across threads — its
/// internal state is `Mutex`-guarded so [`QuestDb::borrow_sender`] /
/// [`QuestDb::reap_idle`] / Drop-driven returns are safe to interleave.
///
/// Each borrow ([`BorrowedSender`]) is **not** `Send` — it belongs to the
/// thread that borrowed it. To ingest in parallel, borrow one sender per
/// worker thread from the same `QuestDb`.
pub struct QuestDb {
    inner: Arc<DbInner>,
    reaper: Option<JoinHandle<()>>,
}

struct DbInner {
    /// Original connect string. Kept verbatim so auto-grow can spin up a
    /// new connection with the same settings — for either the sender
    /// pool (`ColumnConn::connect`) or the reader pool
    /// (`Reader::from_conf`). The reader's parser accepts the writer's
    /// scheme prefixes and ignores pool_* keys, so no translation is
    /// needed.
    conf: String,
    pool_size: usize,
    pool_max: usize,
    pool_idle_timeout: Duration,
    state: Mutex<PoolState>,
    /// Reader pool. Lazy-init: starts empty, populated on first
    /// `borrow_reader_owned` call. Same `pool_size` / `pool_max` /
    /// `pool_idle_timeout` budget as the sender pool but a separate
    /// free list so heavy ingest doesn't starve queries.
    #[cfg(feature = "_egress")]
    reader_state: Mutex<ReaderPoolState>,
    /// Wakes the reaper thread on `shutdown` and lets a future blocking
    /// borrow wait for a free slot once we grow `borrow_sender` past
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
    conn: ColumnConn,
    /// Connection-scoped schema interner. Travels with the slot so its
    /// `(signature → id)` map stays coherent across borrow/return cycles;
    /// both client and server build the same map by first-emit order, so
    /// dropping it would resync the next FULL emit at id 0 and corrupt
    /// the server's schema table.
    schema_registry: super::encoder::SchemaRegistry,
    /// Connection-scoped global symbol dictionary — same coherence
    /// argument: the server tracks ids by first-emit order over the life
    /// of the WS connection, so the dict must travel with the slot.
    symbol_dict: crate::ingress::buffer::SymbolGlobalDict,
    /// Reusable encode scratch (signature, new-symbols, per-column
    /// resolution). Carried across borrow/return so its allocated
    /// capacity survives.
    scratch: super::encoder::EncodeScratch,
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
    /// Store-and-forward keys (`sf_*`, `sender_id`) are **refused** here —
    /// see `doc/COLUMN_SENDER_PLAN.md` §8. Use the row-major
    /// [`crate::ingress::Sender`] API if you need on-disk durability.
    pub fn connect(conf: &str) -> Result<Self> {
        let parsed = conf::parse(conf)?;
        let pool_cfg = parsed.pool;

        let mut free = Vec::with_capacity(pool_cfg.pool_size);
        let now = Instant::now();
        for slot in 0..pool_cfg.pool_size {
            let conn = ColumnConn::connect(conf).map_err(|err| {
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
                conn,
                schema_registry: super::encoder::SchemaRegistry::new(),
                symbol_dict: crate::ingress::buffer::SymbolGlobalDict::new(),
                scratch: super::encoder::EncodeScratch::new(),
                last_idle_at: now,
            });
        }

        let inner = Arc::new(DbInner {
            conf: conf.to_owned(),
            pool_size: pool_cfg.pool_size,
            pool_max: pool_cfg.pool_max,
            pool_idle_timeout: pool_cfg.pool_idle_timeout,
            state: Mutex::new(PoolState { free, in_use: 0 }),
            #[cfg(feature = "_egress")]
            reader_state: Mutex::new(ReaderPoolState::default()),
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
    pub fn borrow_sender(&self) -> Result<BorrowedSender<'_>> {
        let cs = self.pick_sender()?;
        Ok(BorrowedSender::new(self, cs))
    }

    /// FFI escape hatch: like [`Self::borrow_sender`] but the returned
    /// handle is not lifetime-bound to `&self`. Carries an `Arc<DbInner>`
    /// internally so it can outlive the user-facing `QuestDb` pointer
    /// (the pool's free list and reaper stay alive as long as any
    /// borrow is outstanding).
    ///
    /// Hidden from the Rust API because Rust callers should prefer the
    /// lifetime-bound `borrow_sender`, which catches use-after-close at
    /// compile time. C callers reach this through `questdb_db_borrow_sender`.
    #[doc(hidden)]
    pub fn borrow_sender_owned(&self) -> Result<OwnedSender> {
        let cs = self.pick_sender()?;
        Ok(OwnedSender {
            inner: Arc::clone(&self.inner),
            sender: Some(cs),
        })
    }

    fn pick_sender(&self) -> Result<ColumnSender> {
        let mut state = lock_state(&self.inner.state);
        if let Some(entry) = state.free.pop() {
            state.in_use += 1;
            drop(state);
            return Ok(ColumnSender::new(
                entry.conn,
                entry.schema_registry,
                entry.symbol_dict,
                entry.scratch,
            ));
        }
        drop(state);

        let slot = match InUseSlot::reserve_within_cap(&self.inner.state, self.inner.pool_max) {
            Ok(slot) => slot,
            Err(in_use) => {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "Connection pool exhausted: {} connections are currently borrowed and \
                     the pool is at its `pool_max` cap of {}. Return a sender or raise `pool_max`.",
                    in_use,
                    self.inner.pool_max
                ));
            }
        };
        let conn = ColumnConn::connect(&self.inner.conf)?;
        slot.commit();

        Ok(ColumnSender::new(
            conn,
            super::encoder::SchemaRegistry::new(),
            crate::ingress::buffer::SymbolGlobalDict::new(),
            super::encoder::EncodeScratch::new(),
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

    /// Close the pool: stop the reaper (if any), drop all idle connections,
    /// and consume `self`.
    ///
    /// Drop has the same effect; `close` exists for parity with the C ABI
    /// (where `Drop` is not available) and to give callers a place to handle
    /// any reaper-join errors explicitly in the future.
    pub fn close(self) {
        drop(self);
    }

    /// Snapshot the number of idle (free) connections currently in the pool.
    #[doc(hidden)]
    pub fn free_count(&self) -> usize {
        lock_state(&self.inner.state).free.len()
    }

    /// Snapshot the number of currently-borrowed (or in-flight-being-built)
    /// connections.
    #[doc(hidden)]
    pub fn in_use_count(&self) -> usize {
        lock_state(&self.inner.state).in_use
    }

    /// FFI escape hatch: borrow a reader from the egress pool.
    ///
    /// Same shape as [`Self::borrow_sender_owned`] but pulls a
    /// [`Reader`] from the reader free list (lazily opens one if the
    /// free list is empty and total < `pool_max`). Returned via
    /// [`OwnedReader`]'s Drop: see the sender variant for the same
    /// pattern.
    #[cfg(feature = "_egress")]
    #[doc(hidden)]
    pub fn borrow_reader_owned(&self) -> crate::egress::error::Result<OwnedReader> {
        let reader = self.pick_reader()?;
        Ok(OwnedReader {
            inner: Arc::clone(&self.inner),
            reader: Some(reader),
            must_close: false,
        })
    }

    /// Construct an opaque pool reference that downstream code (the
    /// FFI's `line_reader` wrapper, in particular) can hold to return
    /// readers without having to expose [`DbInner`].
    #[cfg(feature = "_egress")]
    #[doc(hidden)]
    pub fn reader_pool_handle(&self) -> ReaderPoolHandle {
        ReaderPoolHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    #[cfg(feature = "_egress")]
    fn pick_reader(&self) -> crate::egress::error::Result<Reader> {
        use crate::egress::error::{Error as EgressError, ErrorCode as EgressErrorCode};
        let mut state = lock_reader_state(&self.inner.reader_state);
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
    #[cfg(feature = "_egress")]
    #[doc(hidden)]
    pub fn reader_free_count(&self) -> usize {
        lock_reader_state(&self.inner.reader_state).free.len()
    }

    /// Snapshot the number of currently-borrowed readers.
    #[cfg(feature = "_egress")]
    #[doc(hidden)]
    pub fn reader_in_use_count(&self) -> usize {
        lock_reader_state(&self.inner.reader_state).in_use
    }
}

impl Debug for QuestDb {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let state = self.inner.state.lock();
        let (free, in_use) = match state {
            Ok(s) => (s.free.len(), s.in_use),
            Err(_) => (0, 0),
        };
        f.debug_struct("QuestDb")
            .field("pool_size", &self.inner.pool_size)
            .field("pool_max", &self.inner.pool_max)
            .field("free", &free)
            .field("in_use", &in_use)
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
        // Remaining free senders are dropped when `inner` (Arc) hits 0.
    }
}

/// A sender borrowed from a [`QuestDb`] pool.
///
/// On `Drop` the underlying connection is returned to the pool unless it
/// has latched into `must_close=true`, in which case it is dropped (and
/// auto-grow will open a fresh one for the next borrow).
///
/// `BorrowedSender` is **not** `Send` or `Sync`. The borrowed connection
/// belongs to the borrowing thread for the duration of the borrow.
pub struct BorrowedSender<'a> {
    db: &'a QuestDb,
    sender: Option<ColumnSender>,
    /// !Send / !Sync marker — `Rc<()>` poisons both auto traits without any
    /// runtime cost.
    _not_send: PhantomData<Rc<()>>,
}

impl<'a> BorrowedSender<'a> {
    fn new(db: &'a QuestDb, sender: ColumnSender) -> Self {
        Self {
            db,
            sender: Some(sender),
            _not_send: PhantomData,
        }
    }
}

impl Debug for BorrowedSender<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("BorrowedSender")
            .field("sender", &self.sender)
            .finish()
    }
}

impl Deref for BorrowedSender<'_> {
    type Target = ColumnSender;

    fn deref(&self) -> &Self::Target {
        self.sender
            .as_ref()
            .expect("borrowed sender already returned")
    }
}

impl DerefMut for BorrowedSender<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.sender
            .as_mut()
            .expect("borrowed sender already returned")
    }
}

impl Drop for BorrowedSender<'_> {
    fn drop(&mut self) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        return_to_pool(&self.db.inner, sender);
    }
}

/// Owned (lifetime-free) variant of [`BorrowedSender`] used by the C FFI.
///
/// Holds an `Arc<DbInner>` so the pool's state outlives the user-facing
/// `QuestDb` pointer — the C ABI can free its `questdb_db*` before
/// dropping outstanding `column_sender*` handles without invalidating the
/// free list / mutex.
#[doc(hidden)]
pub struct OwnedSender {
    inner: Arc<DbInner>,
    sender: Option<ColumnSender>,
}

impl OwnedSender {
    /// Borrow the underlying [`ColumnSender`] mutably. Always returns a
    /// live reference until `Drop` runs.
    pub fn get_mut(&mut self) -> &mut ColumnSender {
        self.sender
            .as_mut()
            .expect("OwnedSender already returned to the pool")
    }

    /// Inspect the wrapped sender without taking ownership.
    pub fn get(&self) -> &ColumnSender {
        self.sender
            .as_ref()
            .expect("OwnedSender already returned to the pool")
    }
}

impl Drop for OwnedSender {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            return_to_pool(&self.inner, sender);
        }
    }
}

/// Owned (lifetime-free) variant of a borrowed reader used by the C FFI.
///
/// Holds an `Arc<DbInner>` for the same reason [`OwnedSender`] does: the
/// C ABI can free its `questdb_db*` pointer before dropping outstanding
/// reader handles without invalidating the free list / mutex.
///
/// `must_close` short-circuits the return path: when set, the reader is
/// dropped instead of being returned to the pool. The egress-side
/// cursor lifecycle uses this to force-close readers whose underlying
/// transport has been torn down by a mid-stream cursor drop.
#[cfg(feature = "_egress")]
#[doc(hidden)]
pub struct OwnedReader {
    inner: Arc<DbInner>,
    reader: Option<Reader>,
    must_close: bool,
}

#[cfg(feature = "_egress")]
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
    pub fn take(mut self) -> Option<Reader> {
        self.reader.take()
    }
}

#[cfg(feature = "_egress")]
impl Drop for OwnedReader {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            return_reader_to_pool(&self.inner, reader, self.must_close);
        }
    }
}

/// Opaque handle to a [`QuestDb`] pool, used by the FFI's
/// `line_reader` wrapper to return readers without exposing
/// `DbInner`. Cheap to clone (just bumps the inner `Arc`).
#[cfg(feature = "_egress")]
#[doc(hidden)]
#[derive(Clone)]
pub struct ReaderPoolHandle {
    inner: Arc<DbInner>,
}

#[cfg(feature = "_egress")]
impl ReaderPoolHandle {
    /// Return a [`Reader`] to the pool it came from. If `must_close`
    /// is set the reader is dropped instead of recycled — matching
    /// the [`OwnedReader::mark_must_close`] semantics.
    pub fn return_reader(&self, reader: Reader, must_close: bool) {
        return_reader_to_pool(&self.inner, reader, must_close);
    }
}

#[cfg(feature = "_egress")]
fn return_reader_to_pool(inner: &Arc<DbInner>, reader: Reader, must_close: bool) {
    let must_close = must_close || reader.transport_torn_down();
    let mut state = lock_reader_state(&inner.reader_state);
    state.in_use = state.in_use.saturating_sub(1);
    if !must_close {
        state.free.push(ReaderPoolEntry {
            reader,
            last_idle_at: Instant::now(),
        });
    }
    drop(state);
}

fn return_to_pool(inner: &Arc<DbInner>, sender: ColumnSender) {
    let must_close = sender.must_close();
    let mut state = lock_state(&inner.state);
    state.in_use = state.in_use.saturating_sub(1);
    if !must_close {
        state.free.push(PoolEntry {
            conn: sender.conn,
            schema_registry: sender.schema_registry,
            symbol_dict: sender.symbol_dict,
            scratch: sender.scratch,
            last_idle_at: Instant::now(),
        });
    }
    drop(state);
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
    #[cfg_attr(not(feature = "_egress"), allow(unused_mut))]
    let mut dropped = reap_idle_senders(inner);
    #[cfg(feature = "_egress")]
    {
        dropped += reap_idle_readers(inner);
    }
    dropped
}

fn reap_idle_senders(inner: &DbInner) -> usize {
    // Drop the to-be-closed connections OUTSIDE the lock so closing a connection
    // (which may take an unbounded amount of time) does not stall concurrent
    // borrows.
    let to_drop: Vec<ColumnConn> = {
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
                to_drop.push(entry.conn);
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
    let to_drop: Vec<Reader> = {
        let mut state = lock_reader_state(&inner.reader_state);
        let mut to_drop = Vec::new();
        let now = Instant::now();
        // Reader pool is lazy-init so there is no warm-min floor to
        // preserve. We reap any idle reader that's been parked longer
        // than the timeout.
        let mut i = 0;
        while i < state.free.len() {
            // Apply the same floor as the sender pool — keep at most
            // `pool_size` warm readers around.
            if state.total() <= inner.pool_size {
                break;
            }
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
