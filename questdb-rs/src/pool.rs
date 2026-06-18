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

//! A small, allocation-light, blocking connection pool.
//!
//! This is the engine behind [`crate::db::Db`]; it is deliberately generic
//! (and free of any QuestDB specifics) so the ingress [`Sender`] pool and the
//! egress [`Reader`] pool share one battle-tested core, and so it can be
//! unit-tested against a mock connection without a live server.
//!
//! [`Sender`]: crate::ingress::Sender
//! [`Reader`]: crate::egress::reader::Reader
//!
//! # Design
//!
//! The pool mirrors the semantics of the reference Java client
//! (`SenderPool` / `QueryClientPool`):
//!
//! * **Elastic.** [`PoolConfig::min`] connections are pre-warmed eagerly; the
//!   pool then grows on demand up to [`PoolConfig::max`] and is shrunk back
//!   toward `min` by [`Pool::reap_idle`] (driven by a housekeeper thread in
//!   the `db` layer).
//! * **Blocking acquire.** [`Pool::borrow`] hands out an idle connection if
//!   one exists, otherwise opens a new one (up to `max`), otherwise blocks on
//!   a [`Condvar`] until a connection is returned or
//!   [`PoolConfig::acquire_timeout`] elapses.
//! * **Connect off-lock.** New connections are opened *without* the pool lock
//!   held — a slow TLS handshake or DNS lookup must not stall other borrowers.
//!   An `in_flight` counter keeps the capacity check correct meanwhile.
//! * **RAII return.** [`Pool::borrow`] returns a [`Pooled`] guard that derefs
//!   to the connection and returns it to the pool on `Drop` — the Rust
//!   equivalent of the Java `PooledSender.close()` decorator. A guard marked
//!   broken (or rejected by [`Manage::recycle`]) is discarded instead.
//!
//! The hot borrow/return path takes a single [`Mutex`] and performs no
//! per-call heap allocation: the free list is a [`VecDeque`] pre-sized to
//! `max` and connections are moved in and out of it by value.

use std::collections::VecDeque;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Teaches the pool how to create and validate a connection of type
/// [`Manage::Conn`]. Implementations are cheap, immutable handles (e.g. a
/// config string); the pool clones nothing per borrow.
pub trait Manage: Send + Sync + 'static {
    /// The pooled connection type. Must be [`Send`] so it can live behind the
    /// pool's [`Mutex`] and be borrowed from any thread.
    type Conn: Send + 'static;

    /// The error returned when opening a connection fails.
    type Error;

    /// Opens a brand-new connection. Called both during pre-warm and when the
    /// pool grows under load (the latter happens off the pool lock).
    fn connect(&self) -> Result<Self::Conn, Self::Error>;

    /// Decides whether a returned connection is safe to reuse. Returning
    /// `false` discards it (and frees a slot for a fresh one). The default
    /// keeps every connection.
    ///
    /// This runs on the returning thread *before* the pool lock is taken, so
    /// it must be cheap and must not block — a `must_close()`-style flag check,
    /// not a network round-trip.
    fn recycle(&self, _conn: &mut Self::Conn) -> bool {
        true
    }
}

/// Sizing and lifetime knobs for a [`Pool`].
#[derive(Debug, Clone, Copy)]
pub struct PoolConfig {
    /// Connections kept warm at all times. Pre-created eagerly by
    /// [`Pool::new`]; [`Pool::reap_idle`] never shrinks below this.
    pub min: usize,
    /// Hard cap on live connections (idle + leased + in-flight). Must be `>= 1`
    /// and `>= min`.
    pub max: usize,
    /// How long [`Pool::borrow`] blocks when the pool is exhausted before
    /// returning [`PoolError::Timeout`]. [`Duration::ZERO`] fails fast.
    pub acquire_timeout: Duration,
    /// Idle connections older than this are reaped. `None` disables idle
    /// reaping.
    pub idle_timeout: Option<Duration>,
    /// Connections whose total age exceeds this are reaped once idle. `None`
    /// disables age-based reaping.
    pub max_lifetime: Option<Duration>,
}

impl PoolConfig {
    fn validate(&self) -> Result<(), &'static str> {
        if self.max < 1 {
            return Err("pool max must be >= 1");
        }
        if self.min > self.max {
            return Err("pool min must be <= max");
        }
        Ok(())
    }
}

/// Failure modes of [`Pool::borrow`].
#[derive(Debug)]
pub enum PoolError<E> {
    /// The pool was exhausted and no connection became free within
    /// [`PoolConfig::acquire_timeout`].
    Timeout,
    /// The pool has been [`closed`](Pool::close).
    Closed,
    /// Opening a new connection failed; carries the underlying
    /// [`Manage::Error`].
    Connect(E),
}

impl<E: std::fmt::Display> std::fmt::Display for PoolError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PoolError::Timeout => write!(f, "timed out waiting for a connection from the pool"),
            PoolError::Closed => write!(f, "the pool is closed"),
            PoolError::Connect(e) => write!(f, "failed to open a pooled connection: {e}"),
        }
    }
}

impl<E: std::fmt::Debug + std::fmt::Display> std::error::Error for PoolError<E> {}

struct Slot<C> {
    conn: C,
    created_at: Instant,
    idle_since: Instant,
}

struct State<C> {
    /// Free connections, most-recently-returned at the back (LIFO borrow for
    /// cache warmth; oldest at the front for reaping).
    idle: VecDeque<Slot<C>>,
    /// Count of connections currently checked out via a live [`Pooled`].
    leased: usize,
    /// Count of `connect()` calls in progress off-lock.
    in_flight: usize,
    /// Count of discarded connections whose slot is still reserved while the
    /// connection is being closed (dropped) off-lock. Keeps the capacity cap
    /// honest: without it, a discard would free the slot accounting-wise
    /// *before* the OS resource is released, letting a concurrent borrow open a
    /// replacement and briefly exceed `max` real connections. Mirrors the Java
    /// client's `closingSlots`.
    closing: usize,
    closed: bool,
}

impl<C> State<C> {
    /// Connections that count against [`PoolConfig::max`]: idle + checked out +
    /// being opened + being closed. The cap is enforced against this so the
    /// number of *real* connections in existence never exceeds `max`.
    #[inline]
    fn live(&self) -> usize {
        self.idle.len() + self.leased + self.in_flight + self.closing
    }
}

struct Inner<M: Manage> {
    manage: M,
    cfg: PoolConfig,
    state: Mutex<State<M::Conn>>,
    cond: Condvar,
}

/// A blocking, elastic connection pool. Cheap to [`Clone`] (it is an
/// [`Arc`] internally); every clone shares the same connections.
pub struct Pool<M: Manage> {
    inner: Arc<Inner<M>>,
}

impl<M: Manage> Clone for Pool<M> {
    fn clone(&self) -> Self {
        Pool {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<M: Manage> Pool<M> {
    /// Builds a pool and eagerly pre-warms [`PoolConfig::min`] connections.
    ///
    /// If any pre-warm connection fails, the ones already created are closed
    /// and the error is returned.
    pub fn new(manage: M, cfg: PoolConfig) -> Result<Pool<M>, PoolError<M::Error>> {
        // Sizing is validated by the `db` builder before we get here; an
        // invalid config is a programmer error, so assert loudly in debug.
        debug_assert!(cfg.validate().is_ok(), "invalid PoolConfig: {cfg:?}");

        let inner = Arc::new(Inner {
            manage,
            cfg,
            state: Mutex::new(State {
                idle: VecDeque::with_capacity(cfg.max),
                leased: 0,
                in_flight: 0,
                closing: 0,
                closed: false,
            }),
            cond: Condvar::new(),
        });

        // Pre-warm runs single-threaded here; hold the lock for simplicity.
        {
            let mut st = inner.state.lock().unwrap();
            for _ in 0..cfg.min {
                match inner.manage.connect() {
                    Ok(conn) => {
                        let now = Instant::now();
                        st.idle.push_back(Slot {
                            conn,
                            created_at: now,
                            idle_since: now,
                        });
                    }
                    Err(e) => {
                        // Close what we already built before bailing.
                        let built: Vec<_> = st.idle.drain(..).map(|s| s.conn).collect();
                        drop(st);
                        drop(built);
                        return Err(PoolError::Connect(e));
                    }
                }
            }
        }

        Ok(Pool { inner })
    }

    /// Borrows a connection, blocking up to [`PoolConfig::acquire_timeout`].
    ///
    /// Returns a [`Pooled`] guard that derefs to the connection and returns it
    /// to the pool when dropped.
    pub fn borrow(&self) -> Result<Pooled<M>, PoolError<M::Error>> {
        let deadline = Instant::now().checked_add(self.inner.cfg.acquire_timeout);
        let mut st = self.inner.state.lock().unwrap();
        loop {
            if st.closed {
                return Err(PoolError::Closed);
            }

            // 1. Reuse a warm connection.
            if let Some(slot) = st.idle.pop_back() {
                st.leased += 1;
                drop(st);
                return Ok(Pooled::new(
                    Arc::clone(&self.inner),
                    slot.conn,
                    slot.created_at,
                ));
            }

            // 2. Grow the pool (open a new connection off-lock).
            if st.live() < self.inner.cfg.max {
                st.in_flight += 1;
                drop(st);

                let result = self.inner.manage.connect();

                let mut st2 = self.inner.state.lock().unwrap();
                st2.in_flight -= 1;
                match result {
                    Ok(conn) => {
                        if st2.closed {
                            drop(st2);
                            self.inner.cond.notify_all();
                            drop(conn);
                            return Err(PoolError::Closed);
                        }
                        st2.leased += 1;
                        drop(st2);
                        return Ok(Pooled::new(Arc::clone(&self.inner), conn, Instant::now()));
                    }
                    Err(e) => {
                        // A freed in_flight slot may now admit another waiter's
                        // creation attempt.
                        drop(st2);
                        self.inner.cond.notify_all();
                        return Err(PoolError::Connect(e));
                    }
                }
            }

            // 3. Exhausted: wait for a return (or time out).
            let now = Instant::now();
            let remaining = match deadline {
                Some(d) if d > now => d - now,
                // Either already past the deadline, or acquire_timeout was so
                // large it overflowed Instant — treat overflow as "effectively
                // forever" by waiting in bounded chunks.
                Some(_) => return Err(PoolError::Timeout),
                None => Duration::from_secs(3600),
            };
            let (guard, wait) = self.inner.cond.wait_timeout(st, remaining).unwrap();
            st = guard;
            if wait.timed_out() && deadline.is_some() && Instant::now() >= deadline.unwrap() {
                // Re-check the fast paths one last time before giving up: a
                // connection may have been returned in the wakeup race.
                if !st.closed && (!st.idle.is_empty() || st.live() < self.inner.cfg.max) {
                    continue;
                }
                return Err(PoolError::Timeout);
            }
        }
    }

    /// Closes idle connections that have exceeded [`PoolConfig::idle_timeout`]
    /// or [`PoolConfig::max_lifetime`], never shrinking below
    /// [`PoolConfig::min`]. Leased connections are untouched. Called by the
    /// housekeeper.
    pub fn reap_idle(&self) {
        let now = Instant::now();
        let idle_timeout = self.inner.cfg.idle_timeout;
        let max_lifetime = self.inner.cfg.max_lifetime;
        if idle_timeout.is_none() && max_lifetime.is_none() {
            return;
        }

        let mut to_close: Vec<M::Conn> = Vec::new();
        {
            let mut st = self.inner.state.lock().unwrap();
            if st.closed {
                return;
            }
            // Most we may remove without dropping below `min`.
            let mut removable = st.live().saturating_sub(self.inner.cfg.min);
            if removable == 0 {
                return;
            }
            let mut kept: VecDeque<Slot<M::Conn>> = VecDeque::with_capacity(st.idle.len());
            while let Some(slot) = st.idle.pop_front() {
                let idle_expired = idle_timeout
                    .is_some_and(|t| now.saturating_duration_since(slot.idle_since) >= t);
                let over_age = max_lifetime
                    .is_some_and(|t| now.saturating_duration_since(slot.created_at) >= t);
                if removable > 0 && (idle_expired || over_age) {
                    removable -= 1;
                    to_close.push(slot.conn);
                } else {
                    kept.push_back(slot);
                }
            }
            st.idle = kept;
        }
        // Close outside the lock.
        drop(to_close);
    }

    /// Permanently closes the pool. Idle connections are closed immediately;
    /// leased connections are closed as their guards drop. Blocked borrowers
    /// wake with [`PoolError::Closed`]. Idempotent.
    pub fn close(&self) {
        let drained: Vec<M::Conn> = {
            let mut st = self.inner.state.lock().unwrap();
            if st.closed {
                return;
            }
            st.closed = true;
            st.idle.drain(..).map(|s| s.conn).collect()
        };
        self.inner.cond.notify_all();
        drop(drained);
    }

    /// Total live connections (idle + leased + in-flight). For tests and
    /// introspection.
    pub fn size(&self) -> usize {
        self.inner.state.lock().unwrap().live()
    }

    /// Number of idle (immediately borrowable) connections. For tests and
    /// introspection.
    pub fn idle(&self) -> usize {
        self.inner.state.lock().unwrap().idle.len()
    }

    /// Whether the pool has been closed.
    pub fn is_closed(&self) -> bool {
        self.inner.state.lock().unwrap().closed
    }
}

/// An RAII handle to a borrowed connection. Derefs to the connection; returns
/// it to the pool on drop (or discards it if [`Pooled::mark_broken`] was
/// called or [`Manage::recycle`] rejects it).
pub struct Pooled<M: Manage> {
    inner: Arc<Inner<M>>,
    conn: Option<M::Conn>,
    created_at: Instant,
    broken: bool,
}

impl<M: Manage> Pooled<M> {
    fn new(inner: Arc<Inner<M>>, conn: M::Conn, created_at: Instant) -> Self {
        Pooled {
            inner,
            conn: Some(conn),
            created_at,
            broken: false,
        }
    }

    /// Marks this connection unfit for reuse: it will be discarded (not
    /// returned to the pool) when the guard drops. Use after an error that may
    /// have left the connection in an inconsistent state.
    pub fn mark_broken(&mut self) {
        self.broken = true;
    }

    /// Whether the connection has been marked broken.
    pub fn is_broken(&self) -> bool {
        self.broken
    }
}

impl<M: Manage> Deref for Pooled<M> {
    type Target = M::Conn;

    fn deref(&self) -> &M::Conn {
        // `conn` is `Some` for the whole guard lifetime; only `Drop` takes it.
        self.conn.as_ref().unwrap()
    }
}

impl<M: Manage> DerefMut for Pooled<M> {
    fn deref_mut(&mut self) -> &mut M::Conn {
        self.conn.as_mut().unwrap()
    }
}

impl<M: Manage> Drop for Pooled<M> {
    fn drop(&mut self) {
        let mut conn = match self.conn.take() {
            Some(c) => c,
            None => return,
        };

        // Decide fitness off-lock (recycle must be cheap/non-blocking).
        let discard = self.broken || !self.inner.manage.recycle(&mut conn);

        let mut st = self.inner.state.lock().unwrap();
        st.leased -= 1;
        if discard || st.closed {
            // Keep the slot reserved (via `closing`) across the off-lock close
            // so a concurrent borrow can't open a replacement until this
            // connection's resources are actually released — otherwise real
            // connections could momentarily exceed `max`.
            st.closing += 1;
            drop(st);
            // Close (drop) the connection outside the lock.
            drop(conn);
            let mut st2 = self.inner.state.lock().unwrap();
            st2.closing -= 1;
            drop(st2);
            self.inner.cond.notify_all();
        } else {
            let now = Instant::now();
            st.idle.push_back(Slot {
                conn,
                created_at: self.created_at,
                idle_since: now,
            });
            drop(st);
            self.inner.cond.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    /// Shared, atomically-tracked stats for the mock connection. The key
    /// invariant under test is `max_live <= pool.max`: the pool must never
    /// have more connections alive at once than its cap allows.
    #[derive(Default)]
    struct Stats {
        connects: AtomicUsize,
        live: AtomicUsize,
        max_live: AtomicUsize,
        fail: AtomicBool,
        /// Inverted so `Default` (false) means "recycle keeps the connection".
        recycle_rejects: AtomicBool,
    }

    impl Stats {
        fn connects(&self) -> usize {
            self.connects.load(Ordering::SeqCst)
        }
        fn live(&self) -> usize {
            self.live.load(Ordering::SeqCst)
        }
        fn max_live(&self) -> usize {
            self.max_live.load(Ordering::SeqCst)
        }
    }

    struct MockConn {
        stats: Arc<Stats>,
    }

    impl Drop for MockConn {
        fn drop(&mut self) {
            self.stats.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct MockManager {
        stats: Arc<Stats>,
        connect_delay: Duration,
    }

    impl MockManager {
        fn new() -> (MockManager, Arc<Stats>) {
            Self::with_delay(Duration::ZERO)
        }

        fn with_delay(delay: Duration) -> (MockManager, Arc<Stats>) {
            let stats = Arc::new(Stats::default());
            (
                MockManager {
                    stats: Arc::clone(&stats),
                    connect_delay: delay,
                },
                stats,
            )
        }
    }

    impl Manage for MockManager {
        type Conn = MockConn;
        type Error = String;

        fn connect(&self) -> Result<MockConn, String> {
            if self.stats.fail.load(Ordering::SeqCst) {
                return Err("connect disabled".to_string());
            }
            if !self.connect_delay.is_zero() {
                std::thread::sleep(self.connect_delay);
            }
            self.stats.connects.fetch_add(1, Ordering::SeqCst);
            let n = self.stats.live.fetch_add(1, Ordering::SeqCst) + 1;
            self.stats.max_live.fetch_max(n, Ordering::SeqCst);
            Ok(MockConn {
                stats: Arc::clone(&self.stats),
            })
        }

        fn recycle(&self, _conn: &mut MockConn) -> bool {
            !self.stats.recycle_rejects.load(Ordering::SeqCst)
        }
    }

    fn cfg(min: usize, max: usize, acquire_ms: u64) -> PoolConfig {
        PoolConfig {
            min,
            max,
            acquire_timeout: Duration::from_millis(acquire_ms),
            idle_timeout: None,
            max_lifetime: None,
        }
    }

    // -----------------------------------------------------------------------
    // Single-threaded behavioural tests.
    // -----------------------------------------------------------------------

    #[test]
    fn prewarms_min() {
        let (m, stats) = MockManager::new();
        let pool = Pool::new(m, cfg(2, 4, 1000)).unwrap();
        assert_eq!(stats.connects(), 2);
        assert_eq!(pool.idle(), 2);
        assert_eq!(pool.size(), 2);
    }

    #[test]
    fn borrow_reuses_then_grows() {
        let (m, stats) = MockManager::new();
        let pool = Pool::new(m, cfg(1, 3, 1000)).unwrap();
        assert_eq!(stats.connects(), 1);

        let a = pool.borrow().unwrap(); // reuse warm
        assert_eq!(stats.connects(), 1);
        let b = pool.borrow().unwrap(); // grow
        let c = pool.borrow().unwrap(); // grow
        assert_eq!(stats.connects(), 3);
        assert_eq!(pool.size(), 3);
        assert_eq!(pool.idle(), 0);
        drop((a, b, c));
        assert_eq!(pool.idle(), 3);
    }

    #[test]
    fn returns_to_pool_on_drop() {
        let (m, stats) = MockManager::new();
        let pool = Pool::new(m, cfg(0, 2, 1000)).unwrap();
        {
            let _g = pool.borrow().unwrap();
            assert_eq!(pool.size(), 1);
            assert_eq!(pool.idle(), 0);
        }
        assert_eq!(pool.idle(), 1);
        let _g = pool.borrow().unwrap();
        assert_eq!(stats.connects(), 1); // reused, no new connect
    }

    #[test]
    fn broken_is_discarded() {
        let (m, stats) = MockManager::new();
        let pool = Pool::new(m, cfg(0, 2, 1000)).unwrap();
        {
            let mut g = pool.borrow().unwrap();
            g.mark_broken();
            assert!(g.is_broken());
        }
        assert_eq!(pool.idle(), 0);
        assert_eq!(pool.size(), 0);
        let _g = pool.borrow().unwrap();
        assert_eq!(stats.connects(), 2); // fresh one
    }

    #[test]
    fn recycle_false_discards() {
        let (m, stats) = MockManager::new();
        let pool = Pool::new(m, cfg(0, 2, 1000)).unwrap();
        stats.recycle_rejects.store(true, Ordering::SeqCst);
        {
            let _g = pool.borrow().unwrap();
        }
        assert_eq!(pool.idle(), 0);
        assert_eq!(pool.size(), 0);
        assert_eq!(stats.live(), 0);
    }

    #[test]
    fn exhausted_times_out() {
        let (m, _stats) = MockManager::new();
        let pool = Pool::new(m, cfg(0, 1, 50)).unwrap();
        let _g = pool.borrow().unwrap();
        let start = Instant::now();
        match pool.borrow() {
            Err(PoolError::Timeout) => {}
            Err(other) => panic!("expected Timeout, got {other:?}"),
            Ok(_) => panic!("expected Timeout, got a connection"),
        }
        assert!(start.elapsed() >= Duration::from_millis(40));
    }

    #[test]
    fn blocked_borrow_wakes_on_return() {
        let (m, _stats) = MockManager::new();
        let pool = Pool::new(m, cfg(0, 1, 2000)).unwrap();
        let g = pool.borrow().unwrap();
        let pool2 = pool.clone();
        let handle = std::thread::spawn(move || {
            let start = Instant::now();
            let _g2 = pool2.borrow().unwrap();
            start.elapsed()
        });
        std::thread::sleep(Duration::from_millis(100));
        drop(g);
        let waited = handle.join().unwrap();
        assert!(waited >= Duration::from_millis(80));
        assert!(waited < Duration::from_millis(1500));
    }

    #[test]
    fn connect_failure_surfaces() {
        let (m, stats) = MockManager::new();
        let pool = Pool::new(m, cfg(0, 2, 1000)).unwrap();
        stats.fail.store(true, Ordering::SeqCst);
        match pool.borrow() {
            Err(PoolError::Connect(e)) => assert!(e.contains("disabled")),
            Err(other) => panic!("expected Connect error, got {other:?}"),
            Ok(_) => panic!("expected Connect error, got a connection"),
        }
        // `in_flight` was decremented; the pool is still usable.
        stats.fail.store(false, Ordering::SeqCst);
        let _g = pool.borrow().unwrap();
        assert_eq!(pool.size(), 1);
    }

    #[test]
    fn closed_pool_rejects_borrow() {
        let (m, _stats) = MockManager::new();
        let pool = Pool::new(m, cfg(1, 2, 1000)).unwrap();
        pool.close();
        assert!(pool.is_closed());
        assert!(matches!(pool.borrow(), Err(PoolError::Closed)));
        pool.close(); // idempotent
    }

    #[test]
    fn reap_respects_min() {
        let (m, _stats) = MockManager::new();
        let mut c = cfg(1, 4, 1000);
        c.idle_timeout = Some(Duration::from_millis(10));
        let pool = Pool::new(m, c).unwrap();
        let a = pool.borrow().unwrap();
        let b = pool.borrow().unwrap();
        let cc = pool.borrow().unwrap();
        drop((a, b, cc));
        assert_eq!(pool.idle(), 3);
        std::thread::sleep(Duration::from_millis(30));
        pool.reap_idle();
        assert_eq!(pool.size(), 1); // never below min
        assert_eq!(pool.idle(), 1);
    }

    #[test]
    fn reap_keeps_fresh() {
        let (m, _stats) = MockManager::new();
        let mut c = cfg(0, 4, 1000);
        c.idle_timeout = Some(Duration::from_secs(100));
        let pool = Pool::new(m, c).unwrap();
        let a = pool.borrow().unwrap();
        let b = pool.borrow().unwrap();
        drop((a, b));
        assert_eq!(pool.idle(), 2);
        pool.reap_idle();
        assert_eq!(pool.idle(), 2);
    }

    // -----------------------------------------------------------------------
    // Concurrency stress tests. These are the heart of "mission critical":
    // many threads hammering the pool must never error spuriously, never
    // exceed the capacity cap, never deadlock, and never leak connections.
    // -----------------------------------------------------------------------

    /// Asserts the standard end-of-test invariants for a quiesced pool: no
    /// connection is leased, the idle set matches the live connection count,
    /// and the cap was never breached.
    fn assert_quiesced(pool: &Pool<MockManager>, stats: &Stats, max: usize) {
        assert!(
            stats.max_live() <= max,
            "capacity breached: max_live={} > max={}",
            stats.max_live(),
            max
        );
        // Everything has been returned: size == idle (leased == 0), and the
        // tracked live count equals what the pool thinks is idle.
        assert_eq!(pool.size(), pool.idle(), "connections still leased");
        assert_eq!(
            stats.live(),
            pool.idle(),
            "tracked-live {} != pool idle {}",
            stats.live(),
            pool.idle()
        );
        assert!(pool.idle() <= max, "idle {} > max {}", pool.idle(), max);
    }

    #[test]
    fn concurrent_borrow_return_no_errors() {
        let (m, stats) = MockManager::new();
        let max = 4;
        let pool = Pool::new(m, cfg(1, max, 10_000)).unwrap();
        let threads = 16;
        let iters = 500;

        let mut handles = Vec::new();
        for _ in 0..threads {
            let p = pool.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..iters {
                    let g = p.borrow().expect("borrow must not fail under capacity");
                    // Touch the connection so the borrow isn't optimised away.
                    std::hint::black_box(&*g);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_quiesced(&pool, &stats, max);
        assert!(pool.idle() >= 1, "min should keep at least one warm");
        // No connection was ever discarded, so the total created can never
        // exceed the cap (reuse, not re-create).
        assert!(
            stats.connects() <= max,
            "connects {} exceeded max {} despite reuse",
            stats.connects(),
            max
        );
    }

    #[test]
    fn concurrent_capacity_never_exceeds_max() {
        // Far more threads than slots, each holding its connection briefly so
        // contention is real. The cap must hold regardless.
        let (m, stats) = MockManager::with_delay(Duration::from_micros(50));
        let max = 3;
        let pool = Pool::new(m, cfg(0, max, 10_000)).unwrap();
        let threads = 24;
        let iters = 100;

        let mut handles = Vec::new();
        for _ in 0..threads {
            let p = pool.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..iters {
                    let g = p.borrow().expect("borrow");
                    std::hint::black_box(&*g);
                    std::thread::sleep(Duration::from_micros(50));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_quiesced(&pool, &stats, max);
    }

    #[test]
    fn concurrent_random_breakage_self_heals() {
        // A fraction of borrows are marked broken and discarded, forcing
        // reconnects under load. The pool must stay healthy and bounded.
        let (m, stats) = MockManager::new();
        let max = 4;
        let pool = Pool::new(m, cfg(1, max, 10_000)).unwrap();
        let threads = 12;
        let iters = 300;

        let mut handles = Vec::new();
        for t in 0..threads {
            let p = pool.clone();
            handles.push(std::thread::spawn(move || {
                for i in 0..iters {
                    let mut g = p.borrow().expect("borrow");
                    std::hint::black_box(&*g);
                    // Deterministic ~25% breakage, decorrelated per thread.
                    if (t * 7 + i) % 4 == 0 {
                        g.mark_broken();
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_quiesced(&pool, &stats, max);
        // Discards forced reconnects, so total creations exceeded the cap.
        assert!(
            stats.connects() > max,
            "expected reconnects beyond the cap, got {}",
            stats.connects()
        );
    }

    #[test]
    fn concurrent_reap_during_load_no_deadlock() {
        // A reaper thread aggressively recycles idle connections while many
        // borrowers churn. Tests lock ordering / liveness, not just counts.
        let (m, stats) = MockManager::new();
        let max = 6;
        let mut c = cfg(1, max, 10_000);
        c.idle_timeout = Some(Duration::from_millis(1));
        let pool = Pool::new(m, c).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let reaper = {
            let p = pool.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    p.reap_idle();
                    std::thread::sleep(Duration::from_micros(200));
                }
            })
        };

        let threads = 8;
        let iters = 300;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let p = pool.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..iters {
                    let g = p.borrow().expect("borrow");
                    std::hint::black_box(&*g);
                    std::thread::sleep(Duration::from_micros(20));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        reaper.join().unwrap();

        // Let one more reap settle, then check invariants.
        pool.reap_idle();
        assert!(stats.max_live() <= max, "capacity breached under reaping");
        assert_eq!(pool.size(), pool.idle(), "connections still leased");
    }

    #[test]
    fn concurrent_close_no_panic_no_leak() {
        // Threads borrow in a loop while the pool is closed underneath them.
        // Every outcome must be a clean Ok/Closed (never a panic), and every
        // connection must be destroyed once the dust settles.
        let (m, stats) = MockManager::new();
        let max = 4;
        let pool = Pool::new(m, cfg(2, max, 2000)).unwrap();

        let threads = 12;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let p = pool.clone();
            handles.push(std::thread::spawn(move || {
                loop {
                    match p.borrow() {
                        Ok(g) => {
                            std::hint::black_box(&*g);
                            std::thread::sleep(Duration::from_micros(100));
                            // guard drops here
                        }
                        Err(PoolError::Closed) => break,
                        Err(PoolError::Timeout) => break,
                        Err(PoolError::Connect(e)) => panic!("unexpected connect error: {e}"),
                    }
                }
            }));
        }

        std::thread::sleep(Duration::from_millis(50));
        pool.close();

        for h in handles {
            h.join().unwrap();
        }

        // All idle were closed; all leased were discarded on guard drop.
        assert_eq!(stats.live(), 0, "leaked {} connections", stats.live());
        assert!(matches!(pool.borrow(), Err(PoolError::Closed)));
    }

    #[test]
    fn concurrent_growth_liveness_all_held_at_once() {
        // With max == threads and a barrier, every thread must successfully
        // hold its own connection simultaneously — proving the pool grows to
        // the cap and no thread is starved.
        let (m, stats) = MockManager::with_delay(Duration::from_micros(100));
        let threads = 8;
        let max = threads;
        let pool = Pool::new(m, cfg(0, max, 10_000)).unwrap();
        let barrier = Arc::new(Barrier::new(threads));

        let mut handles = Vec::new();
        for _ in 0..threads {
            let p = pool.clone();
            let b = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let g = p.borrow().expect("borrow");
                // Hold while every sibling also holds: peak concurrency.
                b.wait();
                std::hint::black_box(&*g);
                std::thread::sleep(Duration::from_millis(5));
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            stats.max_live(),
            max,
            "expected all {max} connections live at the barrier peak"
        );
        assert_quiesced(&pool, &stats, max);
    }

    #[test]
    fn concurrent_borrow_blocks_then_succeeds_under_tight_cap() {
        // max == 1 with many contenders and a generous timeout: every borrow
        // must eventually succeed (serialised), none time out.
        let (m, stats) = MockManager::new();
        let max = 1;
        let pool = Pool::new(m, cfg(1, max, 30_000)).unwrap();
        let threads = 10;
        let iters = 50;
        let ok = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..threads {
            let p = pool.clone();
            let ok = Arc::clone(&ok);
            handles.push(std::thread::spawn(move || {
                for _ in 0..iters {
                    let g = p.borrow().expect("must serialise, not time out");
                    std::hint::black_box(&*g);
                    std::thread::sleep(Duration::from_micros(50));
                    ok.fetch_add(1, Ordering::Relaxed);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(ok.load(Ordering::Relaxed), threads * iters);
        assert_eq!(stats.max_live(), 1, "tight cap must hold");
        assert_quiesced(&pool, &stats, max);
    }
}
