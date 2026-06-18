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

//! [`Db`]: a pooled, shareable handle to a QuestDB deployment.
//!
//! [`Db`] owns two elastic connection pools — one of ingest [`Sender`]s and
//! one of egress [`Reader`]s — plus a background housekeeper that reaps idle
//! connections. Construct it once and clone it freely across threads; callers
//! never open or close a connection themselves.
//!
//! This mirrors the reference Java client's `QuestDB` facade, but uses Rust
//! RAII ([`PooledSender`] / [`PooledReader`] return to the pool on drop)
//! instead of an explicit `close()`-to-return decorator, and runs queries
//! synchronously on the calling thread (the egress reader is sync/pull-based,
//! so no per-query worker thread is needed).
//!
//! ```no_run
//! use questdb::db::Db;
//! use questdb::ingress::TimestampNanos;
//!
//! # fn main() -> Result<(), questdb::db::DbError> {
//! // One handle for the whole deployment; ingest over HTTP, query over WS.
//! let db = Db::connect("http::addr=localhost:9000;", "ws::addr=localhost:9000;")?;
//!
//! // Ingest: borrow a sender, build rows, flush. Returns to the pool on drop.
//! {
//!     let mut sender = db.borrow_sender()?;
//!     let mut buf = sender.new_buffer();
//!     buf.table("trades")?
//!         .symbol("sym", "ETH-USD")?
//!         .column_f64("price", 2615.54)?
//!         .at(TimestampNanos::now())?;
//!     sender.flush(&mut buf)?;
//! }
//!
//! // Query: run a SELECT, consume batches. The reader returns to the pool.
//! let summary = db.execute_query("select * from trades limit 100", |batch| {
//!     println!("got {} rows", batch.row_count());
//!     true // keep streaming; return false to stop early
//! })?;
//! println!("total rows: {}", summary.rows);
//! # Ok(())
//! # }
//! ```

use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::egress::reader::{BatchView, Reader};
use crate::ingress::Sender;
use crate::pool::{Manage, Pool, PoolConfig, PoolError, Pooled};

// Both pooled connection types must be `Send` to live behind the pool's mutex
// and be borrowed from any thread. Pin it at compile time so a future field
// addition that flips either off `Send` breaks here, not at a confusing use
// site.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<Sender>();
    assert_send::<Reader>();
    assert_send::<Db>();
};

// ---------------------------------------------------------------------------
// Defaults (mirroring the Java client's QuestDBBuilder).
// ---------------------------------------------------------------------------

/// Default [`DbBuilder::acquire_timeout`]: how long a borrow blocks when the
/// pool is exhausted.
pub const DEFAULT_ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Default [`DbBuilder::housekeeper_interval`]: idle-reap sweep period.
pub const DEFAULT_HOUSEKEEPER_INTERVAL: Duration = Duration::from_secs(5);
/// Default [`DbBuilder::idle_timeout`]: idle connections older than this are
/// reaped.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Default [`DbBuilder::max_lifetime`]: connections older than this are
/// recycled once idle.
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(30 * 60);
/// Default minimum pool size (kept warm).
pub const DEFAULT_POOL_MIN: usize = 1;
/// Default maximum pool size.
pub const DEFAULT_POOL_MAX: usize = 4;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by [`Db`] operations.
#[derive(Debug)]
pub enum DbError {
    /// Invalid configuration (bad pool sizing or an unparseable unified
    /// connect string).
    Config(String),
    /// The pool was exhausted and no connection became free within the
    /// configured acquire timeout. `pool` is `"sender"` or `"query"`.
    AcquireTimeout {
        /// Which pool timed out.
        pool: &'static str,
    },
    /// The [`Db`] handle (or the underlying pool) has been closed.
    Closed,
    /// An ingest-side error (opening a [`Sender`] or a `flush`).
    Ingest(crate::Error),
    /// A query-side error (opening a [`Reader`] or executing a query).
    Query(crate::egress::Error),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Config(m) => write!(f, "invalid Db configuration: {m}"),
            DbError::AcquireTimeout { pool } => {
                write!(f, "timed out waiting for a connection from the {pool} pool")
            }
            DbError::Closed => write!(f, "the Db handle is closed"),
            DbError::Ingest(e) => write!(f, "ingest error: {e}"),
            DbError::Query(e) => write!(f, "query error: {e}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<crate::Error> for DbError {
    fn from(e: crate::Error) -> Self {
        DbError::Ingest(e)
    }
}

impl From<crate::egress::Error> for DbError {
    fn from(e: crate::egress::Error) -> Self {
        DbError::Query(e)
    }
}

// ---------------------------------------------------------------------------
// Pool managers
// ---------------------------------------------------------------------------

struct SenderManager {
    conf: String,
}

impl Manage for SenderManager {
    type Conn = Sender;
    type Error = crate::Error;

    fn connect(&self) -> crate::Result<Sender> {
        Sender::from_conf(&self.conf)
    }

    fn recycle(&self, sender: &mut Sender) -> bool {
        // A sender that has latched a fatal error must not be reused. This is
        // a cheap flag check (no I/O), as `recycle` requires.
        !sender.must_close()
    }
}

struct ReaderManager {
    conf: String,
}

impl Manage for ReaderManager {
    type Conn = Reader;
    type Error = crate::egress::Error;

    fn connect(&self) -> crate::egress::Result<Reader> {
        Reader::from_conf(&self.conf)
    }

    // No cheap liveness probe exists for a Reader, so reuse-fitness is driven
    // by `Pooled::mark_broken` from the query path instead of `recycle`.
}

// ---------------------------------------------------------------------------
// Pooled guards
// ---------------------------------------------------------------------------

/// A [`Sender`] leased from a [`Db`]'s ingest pool. Derefs to [`Sender`], so
/// the full ingest API is available directly. Returns to the pool on drop
/// (discarded instead if the sender has latched a fatal error).
pub struct PooledSender {
    inner: Pooled<SenderManager>,
}

impl std::ops::Deref for PooledSender {
    type Target = Sender;
    fn deref(&self) -> &Sender {
        &self.inner
    }
}

impl std::ops::DerefMut for PooledSender {
    fn deref_mut(&mut self) -> &mut Sender {
        &mut self.inner
    }
}

/// A [`Reader`] leased from a [`Db`]'s query pool. Derefs to [`Reader`].
///
/// Prefer [`Db::execute_query`] for the common case — it drives the query to
/// completion and guarantees the reader returns to the pool clean. When using
/// the reader directly and abandoning a cursor before it reaches a terminal
/// (which closes the underlying connection), call [`PooledReader::mark_broken`]
/// so the dead connection is discarded rather than returned.
pub struct PooledReader {
    inner: Pooled<ReaderManager>,
}

impl PooledReader {
    /// Marks the underlying reader unfit for reuse: it is discarded (not
    /// returned to the pool) when this guard drops.
    pub fn mark_broken(&mut self) {
        self.inner.mark_broken();
    }
}

impl std::ops::Deref for PooledReader {
    type Target = Reader;
    fn deref(&self) -> &Reader {
        &self.inner
    }
}

impl std::ops::DerefMut for PooledReader {
    fn deref_mut(&mut self) -> &mut Reader {
        &mut self.inner
    }
}

/// Outcome of a [`Db::execute_query`] call.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuerySummary {
    /// Total rows streamed across all batches.
    pub rows: u64,
    /// Number of `RESULT_BATCH` frames consumed.
    pub batches: u64,
    /// `true` if the caller's handler asked to stop before the stream ended.
    pub stopped_early: bool,
}

// ---------------------------------------------------------------------------
// Housekeeper
// ---------------------------------------------------------------------------

struct HkSignal {
    stop: Mutex<bool>,
    cv: Condvar,
}

struct Housekeeper {
    signal: Arc<HkSignal>,
    handle: Option<JoinHandle<()>>,
}

impl Housekeeper {
    fn start(
        senders: Pool<SenderManager>,
        readers: Pool<ReaderManager>,
        interval: Duration,
    ) -> Housekeeper {
        let signal = Arc::new(HkSignal {
            stop: Mutex::new(false),
            cv: Condvar::new(),
        });
        let sig = Arc::clone(&signal);
        let handle = thread::Builder::new()
            .name("questdb-pool-housekeeper".to_string())
            .spawn(move || {
                loop {
                    let stop = sig.stop.lock().unwrap();
                    if *stop {
                        return;
                    }
                    let (stop, _) = sig.cv.wait_timeout(stop, interval).unwrap();
                    let stopping = *stop;
                    drop(stop);
                    if stopping {
                        return;
                    }
                    // Reaping is best-effort; a closed pool is a no-op.
                    senders.reap_idle();
                    readers.reap_idle();
                }
            })
            .expect("failed to spawn questdb-pool-housekeeper thread");
        Housekeeper {
            signal,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        {
            let mut stop = self.signal.stop.lock().unwrap();
            *stop = true;
        }
        self.signal.cv.notify_all();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Db
// ---------------------------------------------------------------------------

struct DbInner {
    senders: Pool<SenderManager>,
    readers: Pool<ReaderManager>,
    housekeeper: Mutex<Housekeeper>,
}

impl Drop for DbInner {
    fn drop(&mut self) {
        if let Ok(mut hk) = self.housekeeper.lock() {
            hk.stop();
        }
        self.readers.close();
        self.senders.close();
    }
}

/// A pooled, cheaply-cloneable handle to a QuestDB deployment. See the
/// [module docs](self) for an overview.
#[derive(Clone)]
pub struct Db {
    inner: Arc<DbInner>,
}

impl Db {
    /// Starts a [`DbBuilder`] for advanced configuration (pool sizes,
    /// timeouts, differing ingest/query configs).
    pub fn builder() -> DbBuilder {
        DbBuilder::new()
    }

    /// Connects with explicit ingest and query configuration strings, using
    /// default pool sizing. `ingest_conf` is a [`Sender`] config (e.g.
    /// `"http::addr=host:9000;"`); `query_conf` is a [`Reader`] config (e.g.
    /// `"ws::addr=host:9000;"`).
    pub fn connect(ingest_conf: &str, query_conf: &str) -> Result<Db, DbError> {
        DbBuilder::new()
            .ingest_config(ingest_conf)
            .query_config(query_conf)
            .build()
    }

    /// Connects with a single unified config string used for both ingest and
    /// query. The scheme must be `http`, `https`, `ws`, or `wss`; the other
    /// half is derived (`http`<->`ws`, `https`<->`wss`).
    ///
    /// Only a portable subset of parameters is carried across (`addr`,
    /// `username`, `password`, `token`, and TLS settings). For transport-
    /// specific tuning, use [`Db::connect`] or [`Db::builder`] with explicit
    /// configs.
    pub fn from_conf(unified: &str) -> Result<Db, DbError> {
        DbBuilder::new().from_conf(unified)?.build()
    }

    /// Borrows a [`Sender`] from the ingest pool, blocking up to the
    /// configured acquire timeout. The returned guard returns the sender to
    /// the pool when dropped.
    pub fn borrow_sender(&self) -> Result<PooledSender, DbError> {
        match self.inner.senders.borrow() {
            Ok(inner) => Ok(PooledSender { inner }),
            Err(PoolError::Timeout) => Err(DbError::AcquireTimeout { pool: "sender" }),
            Err(PoolError::Closed) => Err(DbError::Closed),
            Err(PoolError::Connect(e)) => Err(DbError::Ingest(e)),
        }
    }

    /// Borrows a [`Reader`] from the query pool, blocking up to the configured
    /// acquire timeout. The returned guard returns the reader to the pool when
    /// dropped.
    ///
    /// For most queries, prefer [`Db::execute_query`] — it guarantees the
    /// reader returns clean. See [`PooledReader`] for the contract when
    /// driving the reader directly.
    pub fn borrow_reader(&self) -> Result<PooledReader, DbError> {
        match self.inner.readers.borrow() {
            Ok(inner) => Ok(PooledReader { inner }),
            Err(PoolError::Timeout) => Err(DbError::AcquireTimeout { pool: "query" }),
            Err(PoolError::Closed) => Err(DbError::Closed),
            Err(PoolError::Connect(e)) => Err(DbError::Query(e)),
        }
    }

    /// Runs a query, invoking `on_batch` for each result batch, and returns a
    /// [`QuerySummary`]. The handler returns `true` to keep streaming or
    /// `false` to stop early (the query is then cancelled cleanly).
    ///
    /// Borrows a reader for the duration and returns it to the pool clean on
    /// success, or discards it if the query errors. This is the recommended
    /// query entry point.
    pub fn execute_query<F>(&self, sql: &str, on_batch: F) -> Result<QuerySummary, DbError>
    where
        F: FnMut(&BatchView) -> bool,
    {
        let mut reader = self.borrow_reader()?;
        match run_query(&mut reader, sql, on_batch) {
            Ok(summary) => Ok(summary),
            Err(e) => {
                // A mid-stream error may have closed the connection; don't
                // hand a dead reader back to the next borrower.
                reader.mark_broken();
                Err(DbError::Query(e))
            }
        }
    }

    /// Closes both pools, releasing all idle connections. In-flight borrows
    /// are released as their guards drop. Idempotent. The handle is unusable
    /// afterwards (borrows return [`DbError::Closed`]). The housekeeper thread
    /// is stopped when the last [`Db`] clone is dropped.
    pub fn close(&self) {
        self.inner.readers.close();
        self.inner.senders.close();
    }

    /// Total live connections in the ingest pool (idle + leased). For tests
    /// and introspection.
    pub fn sender_pool_size(&self) -> usize {
        self.inner.senders.size()
    }

    /// Total live connections in the query pool (idle + leased). For tests and
    /// introspection.
    pub fn reader_pool_size(&self) -> usize {
        self.inner.readers.size()
    }
}

fn run_query<F>(
    reader: &mut Reader,
    sql: &str,
    mut on_batch: F,
) -> crate::egress::Result<QuerySummary>
where
    F: FnMut(&BatchView) -> bool,
{
    let mut cursor = reader.execute(sql)?;
    let mut rows: u64 = 0;
    let mut batches: u64 = 0;
    let mut stopped_early = false;
    while let Some(batch) = cursor.next_batch()? {
        rows += batch.row_count() as u64;
        batches += 1;
        if !on_batch(&batch) {
            stopped_early = true;
            break;
        }
    }
    if stopped_early {
        // Drain to terminal so the connection stays reusable (a bare drop
        // would close the socket).
        cursor.cancel()?;
    }
    Ok(QuerySummary {
        rows,
        batches,
        stopped_early,
    })
}

// ---------------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------------

/// Builder for [`Db`]. Defaults match the reference Java client: min 1 / max 4
/// per pool, 5s acquire timeout, 60s idle timeout, 30min max lifetime, 5s
/// housekeeper interval.
pub struct DbBuilder {
    ingest_conf: Option<String>,
    query_conf: Option<String>,
    sender_min: usize,
    sender_max: usize,
    query_min: usize,
    query_max: usize,
    acquire_timeout: Duration,
    idle_timeout: Option<Duration>,
    max_lifetime: Option<Duration>,
    housekeeper_interval: Duration,
}

impl Default for DbBuilder {
    fn default() -> Self {
        DbBuilder::new()
    }
}

impl DbBuilder {
    fn new() -> Self {
        DbBuilder {
            ingest_conf: None,
            query_conf: None,
            sender_min: DEFAULT_POOL_MIN,
            sender_max: DEFAULT_POOL_MAX,
            query_min: DEFAULT_POOL_MIN,
            query_max: DEFAULT_POOL_MAX,
            acquire_timeout: DEFAULT_ACQUIRE_TIMEOUT,
            idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            max_lifetime: Some(DEFAULT_MAX_LIFETIME),
            housekeeper_interval: DEFAULT_HOUSEKEEPER_INTERVAL,
        }
    }

    /// Sets the ingest-side [`Sender`] config string.
    pub fn ingest_config(mut self, conf: &str) -> Self {
        self.ingest_conf = Some(conf.to_string());
        self
    }

    /// Sets the query-side [`Reader`] config string.
    pub fn query_config(mut self, conf: &str) -> Self {
        self.query_conf = Some(conf.to_string());
        self
    }

    /// Derives both ingest and query configs from one unified string by schema
    /// translation. See [`Db::from_conf`].
    pub fn from_conf(mut self, unified: &str) -> Result<Self, DbError> {
        let (ingest, query) = derive_both_sides(unified)?;
        self.ingest_conf = Some(ingest);
        self.query_conf = Some(query);
        Ok(self)
    }

    /// Minimum ingest-pool size kept warm. Default 1.
    pub fn sender_pool_min(mut self, min: usize) -> Self {
        self.sender_min = min;
        self
    }

    /// Maximum ingest-pool size. Default 4.
    pub fn sender_pool_max(mut self, max: usize) -> Self {
        self.sender_max = max;
        self
    }

    /// Fixed ingest-pool size shortcut (`min == max == size`): eager, no
    /// growth or reaping.
    pub fn sender_pool_size(mut self, size: usize) -> Self {
        self.sender_min = size;
        self.sender_max = size;
        self
    }

    /// Minimum query-pool size kept warm. Default 1.
    pub fn query_pool_min(mut self, min: usize) -> Self {
        self.query_min = min;
        self
    }

    /// Maximum query-pool size. Default 4.
    pub fn query_pool_max(mut self, max: usize) -> Self {
        self.query_max = max;
        self
    }

    /// Fixed query-pool size shortcut (`min == max == size`): eager, no growth
    /// or reaping.
    pub fn query_pool_size(mut self, size: usize) -> Self {
        self.query_min = size;
        self.query_max = size;
        self
    }

    /// How long a borrow blocks when the pool is exhausted before returning
    /// [`DbError::AcquireTimeout`]. Default 5s; [`Duration::ZERO`] fails fast.
    pub fn acquire_timeout(mut self, timeout: Duration) -> Self {
        self.acquire_timeout = timeout;
        self
    }

    /// How long a connection may sit idle before the housekeeper reaps it
    /// (never below the pool minimum). [`Duration::ZERO`] disables idle
    /// reaping. Default 60s.
    pub fn idle_timeout(mut self, timeout: Duration) -> Self {
        self.idle_timeout = if timeout.is_zero() {
            None
        } else {
            Some(timeout)
        };
        self
    }

    /// Maximum age of a connection before it is recycled once idle.
    /// [`Duration::ZERO`] disables age-based recycling. Default 30min.
    pub fn max_lifetime(mut self, lifetime: Duration) -> Self {
        self.max_lifetime = if lifetime.is_zero() {
            None
        } else {
            Some(lifetime)
        };
        self
    }

    /// Housekeeper sweep interval. Default 5s.
    pub fn housekeeper_interval(mut self, interval: Duration) -> Self {
        self.housekeeper_interval = interval;
        self
    }

    /// Builds the [`Db`], eagerly pre-warming `min` connections in each pool.
    pub fn build(self) -> Result<Db, DbError> {
        let ingest_conf = self
            .ingest_conf
            .ok_or_else(|| DbError::Config("ingest configuration is required".to_string()))?;
        let query_conf = self
            .query_conf
            .ok_or_else(|| DbError::Config("query configuration is required".to_string()))?;

        validate_sizing("sender", self.sender_min, self.sender_max)?;
        validate_sizing("query", self.query_min, self.query_max)?;

        let sender_cfg = PoolConfig {
            min: self.sender_min,
            max: self.sender_max,
            acquire_timeout: self.acquire_timeout,
            idle_timeout: self.idle_timeout,
            max_lifetime: self.max_lifetime,
        };
        let query_cfg = PoolConfig {
            min: self.query_min,
            max: self.query_max,
            acquire_timeout: self.acquire_timeout,
            idle_timeout: self.idle_timeout,
            max_lifetime: self.max_lifetime,
        };

        let senders = Pool::new(SenderManager { conf: ingest_conf }, sender_cfg)
            .map_err(map_sender_pool_err)?;
        let readers = match Pool::new(ReaderManager { conf: query_conf }, query_cfg) {
            Ok(r) => r,
            Err(e) => {
                // Roll back the sender pool we already pre-warmed.
                senders.close();
                return Err(map_reader_pool_err(e));
            }
        };

        let housekeeper =
            Housekeeper::start(senders.clone(), readers.clone(), self.housekeeper_interval);

        Ok(Db {
            inner: Arc::new(DbInner {
                senders,
                readers,
                housekeeper: Mutex::new(housekeeper),
            }),
        })
    }
}

fn validate_sizing(name: &str, min: usize, max: usize) -> Result<(), DbError> {
    if max < 1 {
        return Err(DbError::Config(format!("{name} pool max must be >= 1")));
    }
    if min > max {
        return Err(DbError::Config(format!(
            "{name} pool min ({min}) must be <= max ({max})"
        )));
    }
    Ok(())
}

fn map_sender_pool_err(e: PoolError<crate::Error>) -> DbError {
    match e {
        PoolError::Connect(e) => DbError::Ingest(e),
        PoolError::Timeout => DbError::AcquireTimeout { pool: "sender" },
        PoolError::Closed => DbError::Closed,
    }
}

fn map_reader_pool_err(e: PoolError<crate::egress::Error>) -> DbError {
    match e {
        PoolError::Connect(e) => DbError::Query(e),
        PoolError::Timeout => DbError::AcquireTimeout { pool: "query" },
        PoolError::Closed => DbError::Closed,
    }
}

/// Parameters carried across when deriving both sides from a unified config.
/// Everything else is transport-specific and dropped; use explicit configs to
/// pass those.
const PORTABLE_KEYS: &[&str] = &[
    "addr",
    "username",
    "password",
    "token",
    "tls_verify",
    "tls_ca",
    "tls_roots",
    "tls_roots_password",
];

fn derive_both_sides(unified: &str) -> Result<(String, String), DbError> {
    let (scheme, params) = unified.split_once("::").ok_or_else(|| {
        DbError::Config(format!(
            "unified config must start with a scheme, e.g. \"http::addr=...\" (got {unified:?})"
        ))
    })?;

    let (ingest_scheme, query_scheme) = match scheme {
        "http" | "ws" => ("http", "ws"),
        "https" | "wss" => ("https", "wss"),
        other => {
            return Err(DbError::Config(format!(
                "unified config scheme must be http|https|ws|wss (got {other:?}); \
                 use Db::connect or Db::builder with explicit ingest/query configs"
            )));
        }
    };

    let mut carried: Vec<&str> = Vec::new();
    for part in params.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let key = part.split_once('=').map(|(k, _)| k).unwrap_or(part);
        if PORTABLE_KEYS.contains(&key) {
            carried.push(part);
        }
    }
    if !carried.iter().any(|p| p.starts_with("addr=")) {
        return Err(DbError::Config(
            "unified config must contain an addr= parameter".to_string(),
        ));
    }

    let suffix = {
        let mut s = String::new();
        for p in &carried {
            s.push_str(p);
            s.push(';');
        }
        s
    };

    Ok((
        format!("{ingest_scheme}::{suffix}"),
        format!("{query_scheme}::{suffix}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_http_to_both() {
        let (ingest, query) =
            derive_both_sides("http::addr=localhost:9000;username=u;password=p;").unwrap();
        assert_eq!(ingest, "http::addr=localhost:9000;username=u;password=p;");
        assert_eq!(query, "ws::addr=localhost:9000;username=u;password=p;");
    }

    #[test]
    fn derive_wss_to_both() {
        let (ingest, query) = derive_both_sides("wss::addr=h:9000;tls_verify=on;").unwrap();
        assert_eq!(ingest, "https::addr=h:9000;tls_verify=on;");
        assert_eq!(query, "wss::addr=h:9000;tls_verify=on;");
    }

    #[test]
    fn derive_drops_transport_specific_params() {
        // `compression` (reader-only) and `auto_flush_rows` (sender-only) are
        // dropped so neither side rejects the string.
        let (ingest, query) =
            derive_both_sides("ws::addr=h:9000;compression=zstd;auto_flush_rows=1000;").unwrap();
        assert_eq!(ingest, "http::addr=h:9000;");
        assert_eq!(query, "ws::addr=h:9000;");
    }

    #[test]
    fn derive_requires_addr() {
        assert!(matches!(
            derive_both_sides("http::username=u;"),
            Err(DbError::Config(_))
        ));
    }

    #[test]
    fn derive_rejects_unknown_scheme() {
        assert!(matches!(
            derive_both_sides("tcp::addr=h:9009;"),
            Err(DbError::Config(_))
        ));
    }

    #[test]
    fn derive_requires_scheme() {
        assert!(matches!(
            derive_both_sides("addr=h:9000;"),
            Err(DbError::Config(_))
        ));
    }

    #[test]
    fn builder_validates_sizing() {
        let err = DbBuilder::new()
            .ingest_config("http::addr=h:9000;")
            .query_config("ws::addr=h:9000;")
            .sender_pool_min(5)
            .sender_pool_max(2)
            .build();
        assert!(matches!(err, Err(DbError::Config(_))));
    }

    #[test]
    fn builder_requires_configs() {
        assert!(matches!(DbBuilder::new().build(), Err(DbError::Config(_))));
    }
}
