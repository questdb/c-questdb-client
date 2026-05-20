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

//! Pipelined (background-thread) QWP egress reader.
//!
//! **"Pipelined" here means decoupled via a dedicated OS thread, not
//! Rust `async fn` / futures / `.await`.** There is no executor and no
//! polling — the API is plain blocking method calls; the only
//! concurrency is that socket read + frame decode happen on a worker
//! thread while the user thread processes the previous batch.
//!
//! Direct port of the Java client's `QwpEgressIoThread` +
//! `QwpQueryClient` pair. Architectural mapping:
//!
//! | Java                    | Rust                                |
//! | ---                     | ---                                 |
//! | `QwpEgressIoThread`     | the worker thread spawned by [`PipelinedReader::from_conf`] |
//! | `QwpQueryClient`        | [`PipelinedReader`]                      |
//! | `submitQuery(...)`      | [`PipelinedQuery::execute`]              |
//! | `takeEvent()`           | [`PipelinedCursor::take_event`]          |
//! | `QueryEvent` (tagged)   | [`Event`] (enum)                     |
//! | `QwpBatchBuffer` + pool | refcounted `Bytes` slices owned by [`OwnedBatch`] |
//! | `requestCancel(rid)`    | [`PipelinedCursor::cancel`]              |
//! | `terminalFailureListener` | hard `Err` returned from [`PipelinedCursor::take_event`] |
//!
//! ## Why a thread instead of just calling `next_batch` faster
//!
//! With the synchronous [`crate::egress::Reader`] / [`crate::egress::Cursor`],
//! the user thread alternates between:
//!
//! 1. block in `read_frame` waiting for the next batch off the wire,
//! 2. decode it,
//! 3. hand it to the user code, which projects columns / runs business
//!    logic on the rows,
//! 4. go back to (1).
//!
//! Steps 1–2 and step 3 are entirely independent: nothing the user does
//! with batch N constrains how soon the I/O thread can be reading +
//! decoding batch N+1. This module pipelines them: the I/O thread runs
//! 1–2 ahead, and the user thread runs 3 in parallel. With a bounded
//! event channel (default capacity 4), the I/O thread reads ahead until
//! the channel fills, then naturally backpressures — TCP recv buffer
//! grows, server-side flow control engages (when `initial_credit > 0`).
//!
//! ## API at a glance
//!
//! ```no_run
//! use questdb::egress::pipelined_reader::{PipelinedReader, Event};
//!
//! # fn ex() -> questdb::egress::Result<()> {
//! let mut r = PipelinedReader::from_conf("ws::addr=localhost:9000;")?;
//! let mut cur = r.prepare("SELECT 42").execute()?;
//! loop {
//!     match cur.take_event()? {
//!         Event::Batch(b) => {
//!             for col_idx in 0..b.column_count() {
//!                 let _view = b.column(col_idx)?;
//!                 // ... project / consume rows ...
//!             }
//!         }
//!         Event::FailoverReset(_ev) => {
//!             // Replayed query starts from batch_seq=0 on a new endpoint;
//!             // discard any rows accumulated so far.
//!         }
//!         Event::End { .. } | Event::ExecDone { .. } => break,
//!         // `Event` is `#[non_exhaustive]` so a wildcard arm is
//!         // required; skip-and-continue is the recommended
//!         // forward-compat shape for unknown future variants.
//!         _ => continue,
//!     }
//! }
//! # Ok(())
//! # }
//! ```

use std::cell::UnsafeCell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bytes::Bytes;

use crate::egress::binds::{Bind, SimpleNullKind};
use crate::egress::column::ColumnView;
use crate::egress::config::{Endpoint, ReaderConfig};
use crate::egress::decoder::DecodedBatch;
use crate::egress::error::{Error, ErrorCode, Result, fmt};
use crate::egress::query_request::{QueryRequest, QueryRequestBuilder, REQUEST_ID_OFFSET};
use crate::egress::reader::{
    FailoverEvent, Reader, ReaderStats, is_failover_eligible, map_server_status,
    pipelined_internals, prefer_over_trigger, warn_on_protocol_error_failover,
};
use crate::egress::schema::Schema;
use crate::egress::server_event::ServerEvent;
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::wire::header::HEADER_LEN;
use crate::egress::wire::msg_kind::MsgKind;
use std::net::Ipv4Addr;

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------

/// Default capacity of the I/O thread → user channel. The I/O thread
/// blocks on send when the channel fills, which naturally engages
/// kernel-level TCP backpressure (server's writes stop draining the
/// peer's recv buffer once our local recv buffer fills). Mirrors the
/// Java client's `DEFAULT_BUFFER_POOL_SIZE = 4`.
///
/// **Memory note on symbol-heavy workloads:** every published
/// [`OwnedBatch`] retains an `Arc<SymbolDict>` snapshot taken at
/// batch-production time. Per-snapshot cap is
/// `MAX_CONN_DICT_HEAP_BYTES` (256 MiB arena) +
/// `MAX_CONN_DICT_SIZE * sizeof(Entry)` ≈ 320 MiB worst case (see
/// `egress::symbol_dict`). If a slow consumer stalls while
/// symbol-dict deltas keep landing, up to `capacity + 1` distinct
/// dict versions can be pinned simultaneously (`capacity` batches
/// in the channel + 1 the consumer holds), so worst-case retained
/// dict memory scales linearly with `capacity` — at default
/// `capacity = 4` that's ~1.6 GiB. Raising the capacity for
/// throughput buys backpressure headroom at the cost of this
/// linear blow-up; lower it (down to `1`) on memory-constrained
/// hosts running symbol-heavy queries. The per-snapshot cap itself
/// is enforced by the dict; only the multiplier across pending
/// snapshots scales here.
pub const DEFAULT_EVENT_CHANNEL_CAPACITY: usize = 4;

/// How long the I/O thread sleeps inside a single `read_frame` syscall
/// before returning to poll its cancel/shutdown atomics. The recv-side
/// state is preserved across calls (partial bytes stay in the WS recv
/// buffer), so this only affects how fast a `cancel()` or a `Drop`
/// makes its way to the worker — not throughput. Mirrors the Java
/// client's `POLL_TIMEOUT_MS = 100`.
const READ_POLL_TICK: Duration = Duration::from_millis(100);

/// How long the I/O thread sleeps between `try_send` retries when the
/// user-facing event channel is full. Deliberately MUCH shorter than
/// [`READ_POLL_TICK`] because this is the **producer-side hot path**:
/// every full-channel cycle stalls the worker for this long even
/// under steady-state matched producer/consumer rates (a single
/// consumer hiccup is enough to fill the [`DEFAULT_EVENT_CHANNEL_CAPACITY`]
/// = 4 slot channel, after which every publish pays this latency
/// until the consumer catches up).
///
/// At 100 ms (the previous value, shared with `READ_POLL_TICK`) the
/// throughput ceiling under any sustained backpressure was 4 slots /
/// 100 ms = **40 batches/sec** — a hard cap that defeated the entire
/// purpose of the pipelined path on the "millions of rows × dozens
/// of columns" workload the surface is built for. At 1 ms the
/// ceiling is ~4000 batches/sec, comfortably above any realistic
/// produce rate.
///
/// 1 ms is also a sane wake-up bound for `shutdown` polling (the
/// other reason the producer wakes periodically): a `close()` /
/// cursor-drop signalled while the worker is blocked on a full
/// channel unblocks within ~1 ms instead of ~100 ms. Stdlib's
/// `SyncSender` doesn't expose a `send_timeout` (still unstable
/// behind `std_internals`), so we drive a `try_send` / `sleep` loop
/// rather than the natural `Condvar`-style wake-on-drain.
const PUBLISH_POLL_TICK: Duration = Duration::from_millis(1);

/// `AtomicI64` sentinel meaning "no cancel pending." Real `request_id`
/// values are positive (the allocator skips 0 / negatives on wrap), so
/// a negative sentinel is unambiguous.
const NO_PENDING_CANCEL: i64 = -1;

/// Upper bound on how long [`PipelinedCursor::drop`] will block waiting
/// for the worker to publish a terminal frame for an abandoned cursor.
///
/// Drop's drain loop forwards cancel to the worker (via `cancel_slot`)
/// and then blocks on the event channel until a terminal `IoEvent`
/// arrives. Under healthy operation the server's `RESULT_END` /
/// `QUERY_ERROR` comes back within milliseconds of the CANCEL; this
/// budget exists for the pathological case where the server is wedged
/// (compute thread stuck, network partition that lets writes succeed
/// silently but never delivers reads) — without it `Drop` would block
/// the user thread indefinitely.
///
/// On budget expiry, `Drop` writes a stderr diagnostic, drops the
/// event-channel `Receiver` without returning it to the worker handle
/// (which causes the worker's next `publish` to fail and tear down the
/// transport), and returns. The `PipelinedReader` is then in a
/// deterministic broken state — the next `execute()` returns
/// `InvalidApiCall("event channel is closed")`. The user is expected
/// to either `close()` the reader or build a new one.
///
/// Matches the sync surface's `CANCEL_DRAIN_READ_TIMEOUT = 30 s` so
/// the bounded-cancel-wait story is consistent across both surfaces.
const CANCEL_DRAIN_BUDGET: Duration = Duration::from_secs(30);

/// Shared message literals for the two `InvalidApiCall` entry-guard
/// errors that `PipelinedCursor::take_event{,_timeout}` /
/// `try_take_event` produce when called on a cursor that is already
/// wound down (`self.done == true`) or whose event channel has
/// already been taken by `Drop`'s timed-out path
/// (`self.event_rx.is_none()`). Defined once so the three
/// accessors emit identical wording.
///
/// **Historical note.** An earlier revision of
/// `cancel_with_budget` classified a returned `InvalidApiCall` as
/// cancel-success by doing `msg.starts_with(ERR_PREFIX_*)` against
/// these constants. That coupling was brittle — any reword on the
/// producer side would silently flip the classification. The
/// current implementation routes around the entry-guard cases
/// directly via `if self.done || self.event_rx.is_none() { return
/// Ok(()) }` *before* calling `take_event_timeout`, so the matcher
/// no longer inspects message text and these constants are pure
/// formatting helpers — renaming them is safe (modulo the
/// user-visible message they produce).
const ERR_PREFIX_CURSOR_TERMINATED: &str = "PipelinedCursor has already terminated";
const ERR_PREFIX_EVENT_CHANNEL_TAKEN: &str = "PipelinedCursor event channel taken";

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Owned [`Schema`] reference shipped with each batch. `Arc` so cloning
/// the snapshot into the user-thread event is a refcount bump, not a
/// per-batch full clone.
pub type SchemaRef = Arc<Schema>;

/// Owned [`SymbolDict`] snapshot shipped with each batch.
///
/// The worker owns the live dict as `Arc<SymbolDict>` and applies
/// deltas through `Arc::make_mut`, so:
///
/// - **Steady state** (no new symbols arriving): publishing a batch
///   is a single `Arc::clone` — one atomic strong-count bump. No
///   allocation, no copy, regardless of how big the arena + entry
///   list have grown.
/// - **Delta state** (server sends a new symbol that wasn't in the
///   dict yet): if any prior batch's snapshot is still alive on the
///   user side (refcount > 1), `Arc::make_mut` clones the dict
///   once so the snapshot stays immutable while the live dict
///   picks up the delta. If the user has already dropped the prior
///   snapshot (refcount == 1, the common case under steady
///   consumption), the delta mutates in place.
///
/// **Operator note — CoW fragility under slow consumer + delta-heavy
/// traffic.** The "delta mutates in
/// place" steady-state assumes the user releases each batch (via
/// `Event::Batch(_)` going out of scope, or
/// [`PipelinedCursor::take_event`] being called again, both of
/// which drop the prior `Arc<SymbolDict>` clone) before the worker
/// publishes the next batch carrying a delta. With the default
/// 4-slot event channel and the worker reading ahead, up to ~5
/// dict snapshots can be alive concurrently. **Every
/// `DELTA_SYMBOL_DICT` that arrives while at least one of those
/// snapshots is still alive triggers a deep clone of the entire
/// dict arena + entries vector.** On a wide-symbol workload with
/// frequent deltas, a consumer that lets batches queue up will
/// pay one full dict clone per delta — silently turning an O(1)
/// publish into O(arena size) per batch. To keep the optimisation
/// active under delta-heavy traffic, drop each batch promptly
/// (don't hold `Event::Batch` references across long compute
/// windows). The per-connection dict arena is hard-capped at
/// 256 MiB (and 8 388 608 entries), so even the worst-case bound
/// is finite — but for wide schemas it can be significant (a few
/// hundred MB across all channel-pinned snapshots combined).
///
/// Snapshotting lives in
/// [`crate::egress::reader::pipelined_internals::dict_snapshot`];
/// the CoW chokepoint is
/// [`crate::egress::reader::pipelined_internals::decode_frame`].
pub type SymbolDictRef = Arc<SymbolDict>;

/// One owned batch — the user-thread analogue of [`crate::egress::BatchView`].
///
/// Holds the decoded column buffers (`bytes::Bytes` refcounted slices
/// into the per-frame payload that the I/O thread's
/// `WsClient::read_binary_frame` split off the recv buffer via
/// `split_to(..).freeze()` — independently owned, so a retained batch
/// pins only its own frame's allocation, not the whole recv buffer),
/// a snapshot of the schema, and a snapshot of the symbol dict.
/// Self-contained:
/// projecting columns does not require holding the PipelinedReader /
/// PipelinedCursor borrow, so the user can keep an OwnedBatch alive
/// across other `take_event` calls if their workflow needs to compare
/// adjacent batches.
///
/// **"Pipelined" = dedicated OS thread + blocking method calls, NOT
/// Rust `async fn` / `.await`.** See the [module docs](self).
pub struct OwnedBatch {
    /// Per-column [`ColumnView`] cache populated lazily by
    /// [`Self::column`]. Sized to `decoded.columns.len()` at
    /// construction; every entry starts as `None` and is filled on
    /// first access. This avoids the per-row pattern-match-and-rebuild
    /// cost on the column getters' hot path: at "millions of rows ×
    /// dozens of columns" scale the unmemoised version paid ~30M
    /// extra match cascades + symbol-dict reborrows per batch (see
    /// the C-FFI per-row getters in `egress_pipelined.rs`).
    ///
    /// **Declared first in the struct so it drops first** — Rust
    /// drops fields in declaration order, and the cache's slots
    /// hold `ColumnView<'static>` lifetime-laundered borrows into
    /// `self.decoded` / `self.dict` (see [`Self::column`]). Putting
    /// the cache ahead of its borrow targets keeps the lifetime
    /// launder sound under field-drop semantics even if a future
    /// `ColumnView` revision grows a `Drop` impl that dereferences
    /// the borrow. `ColumnView` is `Copy` today (so the cache could
    /// drop in any order without UB), but encoding the drop order
    /// in the layout documents the intent instead of relying on the
    /// next reader to spot the `Copy`-saves-us subtlety.
    ///
    /// `UnsafeCell` so a cache miss can mutate from inside an
    /// otherwise `&self` accessor — there is never any aliased `&mut`
    /// to the cache, and the cache slots are filled by exactly one
    /// thread (whichever happens to touch a given column index first;
    /// the pipelined API is single-thread-at-a-time per cursor per
    /// the module docs). `OwnedBatch` is `Send` (the channel
    /// publish moves it from worker to user thread); it is NOT `Sync`
    /// (the `UnsafeCell` blocks it). The send-once-then-single-reader
    /// usage pattern is exactly what `UnsafeCell` is sound under.
    ///
    /// The cached views are stored as `ColumnView<'static>` via
    /// lifetime laundering: they actually borrow from `self.decoded`
    /// and `self.dict`, both of which are immutable for the lifetime
    /// of `OwnedBatch`. Callers receive a `ColumnView<'_>` whose
    /// lifetime is the `&self` borrow — same effective contract as
    /// the pre-cache implementation.
    column_view_cache: UnsafeCell<Vec<Option<ColumnView<'static>>>>,
    decoded: DecodedBatch,
    schema: SchemaRef,
    dict: SymbolDictRef,
}

// SAFETY: `OwnedBatch` is moved across the worker→user thread channel.
// The only non-`Send`-derive field is `column_view_cache:
// UnsafeCell<Vec<Option<ColumnView<'static>>>>`. `UnsafeCell<T>: Send`
// iff `T: Send`; `Vec<Option<ColumnView<'static>>>: Send` iff
// `ColumnView<'static>: Send`; `ColumnView<'static>` contains only
// `&'static [u8]` and `&'static SymbolDict` (after the lifetime
// launder), both of which are `Send` because `[u8]: Sync` and
// `SymbolDict: Sync`. So `Send` is preserved.
//
// We intentionally do NOT impl `Sync` — the cache mutates through
// `&self` via the `UnsafeCell`, which is only sound under
// single-threaded `&` access.
unsafe impl Send for OwnedBatch {}

impl OwnedBatch {
    /// Eagerly size the column-view cache; populate-on-demand from
    /// [`Self::column`]. Called only by the worker's publish path.
    fn new(decoded: DecodedBatch, schema: SchemaRef, dict: SymbolDictRef) -> Self {
        let col_count = decoded.columns.len();
        OwnedBatch {
            column_view_cache: UnsafeCell::new(vec![None; col_count]),
            decoded,
            schema,
            dict,
        }
    }

    /// Test-only constructor exposed for the `questdb-rs-ffi` per-row
    /// getter unit tests (which need a synthetic `OwnedBatch` to drive
    /// `line_reader_pipelined_batch_get_*` without spinning up a real
    /// reader + worker + connection). The name and `#[doc(hidden)]`
    /// gate match the `_bench_internals` convention — same stability
    /// footing as `pub(crate)`; downstream code MUST NOT depend on it.
    /// Production code goes through [`Self::new`] directly inside the
    /// worker's publish path.
    #[doc(hidden)]
    pub fn _new_for_test(decoded: DecodedBatch, schema: SchemaRef, dict: SymbolDictRef) -> Self {
        Self::new(decoded, schema, dict)
    }

    /// `request_id` this batch belongs to. After a successful
    /// mid-query failover, this reflects the **replayed** query's
    /// id (the worker re-allocates a fresh rid via
    /// [`alloc_request_id_atomic`]). See
    /// [`PipelinedCursor::request_id`] for the full failover
    /// contract.
    pub fn request_id(&self) -> i64 {
        self.decoded.request_id
    }

    /// Monotonic batch sequence number from the wire (`batch_seq`).
    /// 0-indexed per query; resets to 0 after a successful mid-query
    /// failover (the replayed query starts at `batch_seq = 0`).
    pub fn batch_seq(&self) -> u64 {
        self.decoded.batch_seq
    }

    /// Per-batch wire flags from the frame header. Useful for
    /// asserting that compression / Gorilla / delta-dict paths were
    /// actually exercised on a given batch.
    ///
    /// Test each bit against the constants in
    /// [`crate::egress::wire::header::flags`]:
    ///
    /// - `GORILLA` (`0x04`) — at least one timestamp / date /
    ///   timestamp-nanos column in this batch is delta-of-delta
    ///   (Gorilla) encoded.
    /// - `DELTA_SYMBOL_DICT` (`0x08`) — the batch carries a
    ///   symbol-dict delta section (new symbols extending the
    ///   connection-scoped dict).
    /// - `ZSTD` (`0x10`) — the payload after the
    ///   `msg_kind`/`request_id`/`batch_seq` prefix is
    ///   zstd-compressed (decoded transparently before this batch
    ///   was published).
    ///
    /// Bits not listed above are reserved and currently always
    /// clear; treat them as "must be ignored" for forward compat.
    pub fn flags(&self) -> u8 {
        self.decoded.flags
    }

    /// Borrow the schema snapshot shipped with this batch. The
    /// returned `&Schema` lives for as long as `&self` — the
    /// underlying storage is held via `Arc<Schema>` on
    /// [`SchemaRef`], so cloning the batch does not deep-clone the
    /// schema (it is a refcount bump).
    pub fn schema(&self) -> &Schema {
        &self.schema
    }

    /// Number of rows in this batch — the upper bound for any
    /// per-row accessor's `row_idx` parameter (whether on
    /// [`Self::column`]'s returned [`ColumnView`] or on the FFI
    /// `line_reader_pipelined_batch_get_*` family). Computed from
    /// the wire header at decode time and constant for the batch's
    /// lifetime.
    pub fn row_count(&self) -> usize {
        self.decoded.row_count
    }

    /// Number of columns in this batch's schema — the upper bound
    /// for any per-column accessor's `col_idx` parameter. Always
    /// equal to `self.schema().len()`.
    pub fn column_count(&self) -> usize {
        self.decoded.columns.len()
    }

    /// Project a single column to a typed view. The returned view
    /// borrows from `self` (the column buffers and the symbol dict
    /// snapshot held by this batch); dropping `self` invalidates it.
    ///
    /// Memoised: the first call for a given `idx` populates an
    /// internal `Option<ColumnView<'static>>` slot in
    /// `column_view_cache`; subsequent calls return the cached
    /// view in `O(1)` without re-pattern-matching the underlying
    /// `DecodedColumn` or re-resolving the symbol dict. This is
    /// load-bearing for the per-row column getters in the C FFI
    /// (`line_reader_pipelined_batch_get_*`) — without the cache
    /// the per-row hot path paid one `column_view` rebuild per call
    /// (~30M wasted match cascades + symbol-dict reborrows per
    /// 1M-row × 30-column batch).
    pub fn column(&self, idx: usize) -> Result<ColumnView<'_>> {
        // SAFETY: `&mut *self.column_view_cache.get()` is sound iff no
        // other `&` or `&mut` to the cache exists right now. The cache
        // is private to this method (no other `Self` method touches it),
        // `OwnedBatch` is `!Sync` so no parallel `&self` accessors can
        // race this one, and the reference does not escape this scope.
        let cache = unsafe { &mut *self.column_view_cache.get() };
        // Bounds check against the cache (which is sized to
        // `decoded.columns.len()` at construction). Matches the OOB
        // diagnostic that `decoded.column_view` would have produced
        // on a miss; faster to short-circuit before laundering.
        if idx >= cache.len() {
            return Err(fmt!(
                InvalidApiCall,
                "column index {} out of range (column_count={})",
                idx,
                cache.len()
            ));
        }
        if let Some(view) = cache[idx] {
            // `ColumnView` is `Copy`. Launder the cached 'static
            // lifetime back to a `&self`-bound one for the return.
            // SAFETY: the cached view borrows from `self.decoded` and
            // `self.dict`, both of which are immutable for as long
            // as `self` is alive; the returned `ColumnView<'_>` is
            // bounded by `&self`, so the borrow cannot outlive the
            // memory it references.
            return Ok(unsafe { std::mem::transmute::<ColumnView<'static>, ColumnView<'_>>(view) });
        }
        let view = self.decoded.column_view(idx, &self.dict)?;
        // SAFETY: the cached view borrows from `self.decoded` and
        // `self.dict`. Both outlive `self.column_view_cache` at drop
        // time because the cache is declared FIRST in the struct
        // (see the field-order comment on `column_view_cache`) and
        // Rust drops fields in declaration order. Each cached
        // `ColumnView<'static>` is therefore released before the
        // storage it borrows from. Reordering the struct so the
        // cache is no longer declared first would break this
        // invariant — keep the layout in lockstep with this SAFETY
        // claim.
        let view_static: ColumnView<'static> =
            unsafe { std::mem::transmute::<ColumnView<'_>, ColumnView<'static>>(view) };
        cache[idx] = Some(view_static);
        Ok(view)
    }
}

impl std::fmt::Debug for OwnedBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedBatch")
            .field("request_id", &self.decoded.request_id)
            .field("batch_seq", &self.decoded.batch_seq)
            .field("row_count", &self.decoded.row_count)
            .field("column_count", &self.decoded.columns.len())
            .finish()
    }
}

/// One event pulled from [`PipelinedCursor::take_event`].
///
/// `#[non_exhaustive]` so future protocol additions (server-side
/// timeouts, progress beacons, …) don't break exhaustive matches.
///
/// **"Pipelined" = dedicated OS thread + blocking method calls, NOT
/// Rust `async fn` / `.await`.** See the [module docs](self).
#[non_exhaustive]
pub enum Event {
    /// One `RESULT_BATCH`. Drop the [`OwnedBatch`] before requesting
    /// the next event — the I/O thread can pipeline up to
    /// [`DEFAULT_EVENT_CHANNEL_CAPACITY`] batches ahead, but the
    /// backing recv buffer space is only released when their `Bytes`
    /// refcounts drop to zero.
    Batch(OwnedBatch),
    /// Mid-query failover succeeded; the cursor is now bound to a new
    /// endpoint and the query has been replayed with the
    /// `new_request_id` reported here. Any rows the user accumulated
    /// from pre-failover batches MUST be discarded — replay restarts
    /// at `batch_seq=0`.
    FailoverReset(FailoverEvent),
    /// `RESULT_END` — successful completion of a streaming query.
    /// Subsequent `take_event` calls fail with `InvalidApiCall`.
    End {
        request_id: i64,
        final_seq: u64,
        total_rows: u64,
    },
    /// `EXEC_DONE` — non-SELECT acknowledgement (DDL, INSERT, …).
    /// Subsequent `take_event` calls fail with `InvalidApiCall`.
    ExecDone {
        request_id: i64,
        op_type: u8,
        rows_affected: u64,
    },
}

impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Event::Batch(b) => f.debug_tuple("Batch").field(b).finish(),
            Event::FailoverReset(ev) => f.debug_tuple("FailoverReset").field(ev).finish(),
            Event::End {
                request_id,
                final_seq,
                total_rows,
            } => f
                .debug_struct("End")
                .field("request_id", request_id)
                .field("final_seq", final_seq)
                .field("total_rows", total_rows)
                .finish(),
            Event::ExecDone {
                request_id,
                op_type,
                rows_affected,
            } => f
                .debug_struct("ExecDone")
                .field("request_id", request_id)
                .field("op_type", op_type)
                .field("rows_affected", rows_affected)
                .finish(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-cursor user-callback type
// ---------------------------------------------------------------------------

/// User-provided failover-reset callback. Invoked on the I/O thread
/// (not the user thread) right before the first replayed batch is
/// published — so it MUST be `Send`. The Rust callback is also
/// surfaced indirectly via [`Event::FailoverReset`] on the user
/// thread; the callback exists for parity with the sync
/// [`crate::egress::Reader`] / [`crate::egress::ReaderQuery`] API and
/// is rarely needed when consuming events.
///
/// **Panic safety — depends on the panic strategy of the compiled
/// crate, NOT this library alone.** A panic out of this callback is
/// caught by the worker (`std::panic::catch_unwind`), surfaced as
/// `Err(InvalidApiCall)` to the user thread via the next
/// `take_event*` call, and the cursor is terminated. Without that
/// catch, an unwind would kill the worker thread — `Drop` would
/// swallow the join, and the user would see a generic
/// `SocketError("I/O thread terminated...")` with the real cause
/// lost. Prefer surfacing failures through your own channel /
/// logging rather than panicking; the catch is there to keep the
/// reader recoverable, not to make panic a normal control-flow tool.
///
/// **Important caveat for FFI consumers**: the `catch_unwind` only
/// fires under the default `panic = "unwind"` build profile. When
/// `questdb-rs` is compiled into the `questdb-rs-ffi` cdylib
/// (`questdb-rs-ffi/Cargo.toml` pins `panic = "abort"` in both
/// `dev` and `release`), panics never unwind — they abort the
/// process at the panic site. The `catch_unwind` is then dead code
/// and a panicking callback kills the host process directly. C/C++
/// callers in particular should treat their `on_failover_reset`
/// trampoline as a hard `noexcept` contract.
pub type PipelinedFailoverResetCallback = Box<dyn FnMut(&FailoverEvent) + Send>;

// ---------------------------------------------------------------------------
// Cross-thread message types
// ---------------------------------------------------------------------------

/// Control commands sent from a user thread to the I/O thread.
enum IoCommand {
    /// Begin streaming `request`. Carries the pre-encoded
    /// `QUERY_REQUEST` payload (so the I/O thread can replay it
    /// across failover) plus the user's `on_failover_reset` callback.
    Submit {
        request_id: i64,
        encoded_request: Bytes,
        initial_credit: u64,
        on_failover_reset: Option<PipelinedFailoverResetCallback>,
    },
    /// Shut down the I/O thread, closing the WS connection. Sent on
    /// [`PipelinedReader::close`] / `Drop`.
    Shutdown,
}

/// One event published from the I/O thread to the user thread.
/// Mirrors [`Event`] one-to-one for the happy path; the `Error` arm
/// exists so transport / decode / failover failures cross the channel
/// as a clean `Result`-like value rather than via a side-channel.
enum IoEvent {
    Batch(OwnedBatch),
    FailoverReset(FailoverEvent),
    End {
        request_id: i64,
        final_seq: u64,
        total_rows: u64,
    },
    ExecDone {
        request_id: i64,
        op_type: u8,
        rows_affected: u64,
    },
    /// Terminal error for the in-flight cursor. The I/O thread keeps
    /// running and waits for the next [`IoCommand::Submit`].
    Error(Error),
}

// ---------------------------------------------------------------------------
// PipelinedReader
// ---------------------------------------------------------------------------

/// Per-connection pipelined reader. Owns a background I/O thread that holds
/// the WS transport, dict, schema registry, and zstd scratch.
///
/// **"Pipelined" = dedicated OS thread + blocking method calls, NOT
/// Rust `async fn` / `.await`.** See the [module docs](self) for
/// the full distinction — repeated on every public item in this
/// module so a deep-link landing doesn't mistake this for a futures
/// type.
///
/// One cursor at a time per `PipelinedReader`, just like
/// [`crate::egress::Reader`].
pub struct PipelinedReader {
    /// `None` once [`Self::close`] has joined the worker. All public
    /// methods that touch the channel guard on this.
    worker: Option<WorkerHandle>,
    /// Shared diagnostic counters; mirror of what the worker thread's
    /// `Reader` writes into. Read from the user thread without going
    /// through the channel — these are documented as concurrent-stat
    /// safe.
    stats: Arc<ReaderStats>,
    /// Shared cancel slot. `AtomicI64` written by the user thread on
    /// [`PipelinedCursor::cancel`], polled by the I/O thread between
    /// `read_frame` ticks. `NO_PENDING_CANCEL` (`-1`) means no
    /// outstanding cancel; any positive value is a `request_id` the
    /// worker should CANCEL on its next tick.
    cancel_slot: Arc<AtomicI64>,
    /// Shared shutdown flag. Set by [`Self::close`] / `Drop`; the I/O
    /// thread checks it on every command-receive timeout and every
    /// in-query read tick.
    shutdown: Arc<AtomicBool>,
    /// Worker-published snapshot of the current endpoint index. Updated
    /// after every successful (re)connect so [`Self::current_addr`]
    /// can serve the value without going through the channel.
    current_addr_idx: Arc<AtomicUsize>,
    /// Shared `Arc<ReaderConfig>` (same `Arc` as on the worker's
    /// `Reader::cfg`) so [`Self::current_addr`] is a refcount-cheap
    /// lookup. The previous shape (`Arc<Vec<Endpoint>>` built via
    /// `Arc::new(reader.cfg.addrs.clone())` in
    /// `pipelined_internals::addrs_arc`) deep-cloned the Vec + every
    /// host `String` per `PipelinedReader` construction, even though
    /// the canonical `Arc<ReaderConfig>` was already trivially
    /// shareable. The config is immutable for the reader's lifetime,
    /// so sharing the Arc is sound — there is no writer to race.
    cfg: Arc<ReaderConfig>,
    /// Negotiated QWP server version (atomic so post-failover updates
    /// from the worker are observable). `0` means "not yet known"; the
    /// worker initialises this before publishing on the channel.
    server_version: Arc<AtomicU64>,
    /// `true` while a cursor is alive. Single-cursor enforcement on
    /// the user side; the worker enforces it implicitly via the
    /// single-slot command channel.
    cursor_active: bool,
    /// Per-connection monotonic `request_id` allocator. Shared with
    /// the worker via `Arc<AtomicI64>` so the user-side
    /// `execute()` path and the worker-side `failover_and_replay`
    /// path draw from the **same** sequence. A previous revision
    /// kept two independent `i64` counters here and on
    /// `Reader::next_request_id`; after a worker-side failover
    /// allocation the user side had no idea, and the next
    /// `execute()` could mint a `request_id` that collided with a
    /// rid the worker was still tracking from the previous query's
    /// replay — which would let a late-arriving stale frame match
    /// the new cursor's rid and get misattributed, and would crosswire
    /// `cancel_slot` between cursors. The shared atomic closes both
    /// races.
    ///
    /// **Write discipline.** This atomic is initialised to `1` (via
    /// `AtomicI64::new(1)` in [`Self::launch`]) and MUST only be
    /// mutated through [`alloc_request_id_atomic`] — that function
    /// preserves the "values handed out are always strictly
    /// positive" invariant the QWP protocol depends on (the server
    /// reserves `0` for "no active request"). Direct stores of `0`
    /// or a negative value would cause the next allocation to hand
    /// it out as a `request_id`. The allocator has a defensive
    /// `.max(1)` clamp, but the right place to keep the invariant
    /// honest is at every write site.
    next_request_id: Arc<AtomicI64>,
}

/// Per-thread bundle the user side owns. Separated from `PipelinedReader`
/// so `Drop for PipelinedReader` can `take` it cleanly and join the worker.
struct WorkerHandle {
    join: JoinHandle<()>,
    cmd_tx: SyncSender<IoCommand>,
    /// Event channel `Receiver`. Owned by the live `PipelinedCursor` while
    /// a cursor is active; otherwise lives here so the worker can
    /// continue to publish a synthesised error event for a cursor that
    /// the user has already drained but not dropped.
    event_rx: Option<Receiver<IoEvent>>,
}

impl PipelinedReader {
    /// Open a pipelined reader from a connect string. Same grammar as
    /// [`crate::egress::Reader::from_conf`]. Uses
    /// [`DEFAULT_EVENT_CHANNEL_CAPACITY`] as the I/O thread → user
    /// channel capacity.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let cfg = ReaderConfig::from_conf(conf)?;
        Self::from_config(&cfg)
    }

    /// Open a pipelined reader from the connect string in the
    /// `QDB_CLIENT_CONF` environment variable. Same as
    /// [`crate::egress::Reader::from_env`].
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

    /// Open a pipelined reader from a parsed config.
    pub fn from_config(cfg: &ReaderConfig) -> Result<Self> {
        Self::from_config_with_capacity(cfg, DEFAULT_EVENT_CHANNEL_CAPACITY)
    }

    /// Open with a non-default event channel capacity. `capacity` is
    /// the maximum number of unconsumed events the I/O thread may
    /// publish before backpressure kicks in. `0` would deadlock; we
    /// clamp to at least `1` (mirrors `sync_channel`'s requirement).
    ///
    /// **Memory trade-off on symbol-heavy workloads:** each
    /// published [`OwnedBatch`] retains an `Arc<SymbolDict>`
    /// snapshot from production time, so worst-case retained dict
    /// memory scales linearly with `capacity` — up to
    /// `(capacity + 1) × ~320 MiB` if the consumer stalls while
    /// dict deltas keep landing. See
    /// [`DEFAULT_EVENT_CHANNEL_CAPACITY`] for the full breakdown.
    /// Lower `capacity` on memory-constrained hosts running
    /// symbol-heavy queries; raise it when throughput backpressure
    /// matters more than peak retained dict memory.
    pub fn from_config_with_capacity(cfg: &ReaderConfig, capacity: usize) -> Result<Self> {
        let capacity = capacity.max(1);
        // Open the underlying connection synchronously so config /
        // auth / handshake errors surface up-front on the caller's
        // thread, not as a deferred error inside the worker. Same
        // setup path as the sync `Reader`.
        let reader = Reader::from_config(cfg)?;
        Self::launch(reader, capacity)
    }

    /// Spawn the worker thread and assemble the user-side handle.
    fn launch(reader: Reader, capacity: usize) -> Result<Self> {
        let stats = Arc::clone(reader.stats());
        let cfg = pipelined_internals::cfg_arc(&reader);
        let current_addr_idx = Arc::new(AtomicUsize::new(pipelined_internals::addr_idx(&reader)));
        let server_version = Arc::new(AtomicU64::new(
            pipelined_internals::transport_version(&reader).unwrap_or(0) as u64,
        ));
        let cancel_slot = Arc::new(AtomicI64::new(NO_PENDING_CANCEL));
        let shutdown = Arc::new(AtomicBool::new(false));
        // Shared `request_id` counter. Initialised to `1` so the
        // first allocation hands out `1` (matches the previous
        // per-side `i64` counter's starting point and the wire
        // protocol's "positive ids only, 0 reserved as sentinel"
        // contract). Both the user side and the worker side mint
        // ids through `alloc_request_id_atomic` against this same
        // `Arc`, so failover-side and execute-side allocations
        // never collide.
        let next_request_id = Arc::new(AtomicI64::new(1));

        // Single-slot command channel: only one `Submit` may be
        // outstanding at a time (single-cursor invariant). The worker
        // drains it in its idle loop.
        let (cmd_tx, cmd_rx) = sync_channel::<IoCommand>(1);
        let (event_tx, event_rx) = sync_channel::<IoEvent>(capacity);

        // The event channel has exactly two endpoints over its
        // lifetime: the worker's `event_tx` (Sender, moved into
        // `WorkerState` below) and the cursor's `event_rx` (Receiver,
        // shuttled between `WorkerHandle::event_rx` and live
        // `PipelinedCursor::event_rx`). No spare-sender clone is
        // kept on the user side — an earlier revision stored one as
        // `event_tx_template` with the intent of recreating the
        // channel after shutdown, but that recreation was never
        // implemented and the spare clone was load-bearing nowhere
        // (the worker holds its own clone, so dropping a user-side
        // template doesn't disconnect anything). See N10.
        let worker_state = WorkerState {
            reader,
            cmd_rx,
            event_tx,
            cancel_slot: Arc::clone(&cancel_slot),
            shutdown: Arc::clone(&shutdown),
            current_addr_idx: Arc::clone(&current_addr_idx),
            server_version: Arc::clone(&server_version),
            next_request_id: Arc::clone(&next_request_id),
        };
        let join = thread::Builder::new()
            .name("questdb-egress-io".into())
            .spawn(move || worker_state.run())
            .map_err(|e| fmt!(SocketError, "failed to spawn QWP egress I/O thread: {}", e))?;

        Ok(PipelinedReader {
            worker: Some(WorkerHandle {
                join,
                cmd_tx,
                event_rx: Some(event_rx),
            }),
            stats,
            cancel_slot,
            shutdown,
            current_addr_idx,
            cfg,
            server_version,
            cursor_active: false,
            next_request_id,
        })
    }

    /// Begin building a parametrised query. Single in-flight cursor at
    /// a time; calling [`PipelinedQuery::execute`] while a cursor is alive
    /// returns `InvalidApiCall`.
    pub fn prepare<S: Into<String>>(&mut self, sql: S) -> PipelinedQuery<'_> {
        PipelinedQuery {
            reader: self,
            builder: QueryRequest::builder(sql),
            on_failover_reset: None,
            initial_credit: 0,
        }
    }

    /// Execute a SQL statement with no binds. Convenience for
    /// `self.prepare(sql).execute()`.
    pub fn execute<S: Into<String>>(&mut self, sql: S) -> Result<PipelinedCursor<'_>> {
        self.prepare(sql).execute()
    }

    /// Total wire bytes read off the transport since this reader was
    /// opened. Concurrent-stat-safe — reads an atomic counter, may be
    /// called while a cursor is in flight from any thread.
    pub fn bytes_received(&self) -> u64 {
        self.stats.bytes_received.load(Ordering::Relaxed)
    }

    /// Total bytes granted to the server via CREDIT frames since this
    /// reader was opened. Concurrent-stat-safe.
    pub fn credit_granted_total(&self) -> u64 {
        self.stats.credit_granted_total.load(Ordering::Relaxed)
    }

    /// Cumulative time spent in `read_frame_or_timeout` on the
    /// worker thread, in nanoseconds (saturating). Includes the
    /// periodic poll-tick wakeups (`READ_POLL_TICK`) that wake the
    /// worker every ~100 ms to check `shutdown` / `cancel_slot` —
    /// on a busy stream those wakeups never fire (frame arrives
    /// well under the tick), so the counter accurately reflects
    /// "wire-read time"; on a quiet stream the counter accumulates
    /// at roughly real-time, correctly reflecting "time spent
    /// waiting for data on the wire" (matching the sync
    /// `Reader::read_ns()` definition, which has no timeout but
    /// blocks unboundedly on a quiet stream).
    ///
    /// Concurrent-stat-safe (atomic counter). See the `stats()`
    /// accessor for a detached close-safe handle suitable for
    /// cross-thread monitoring.
    pub fn read_ns(&self) -> u64 {
        self.stats.read_ns.load(Ordering::Relaxed)
    }

    /// Cumulative decode time in nanoseconds (saturating).
    /// Concurrent-stat-safe.
    pub fn decode_ns(&self) -> u64 {
        self.stats.decode_ns.load(Ordering::Relaxed)
    }

    /// Reset `read_ns` and `decode_ns` to zero. Concurrent-stat-safe.
    pub fn reset_timing(&self) {
        self.stats.read_ns.store(0, Ordering::Relaxed);
        self.stats.decode_ns.store(0, Ordering::Relaxed);
    }

    /// Shared stats handle, for FFI integration that wants to clone
    /// the `Arc` once at handle-construction time.
    pub fn stats(&self) -> &Arc<ReaderStats> {
        &self.stats
    }

    /// Endpoint the worker's connection is currently bound to. Updates
    /// across mid-query failover (with the same ordering caveat as
    /// the sync Reader's `current_addr`: this is a snapshot, may be
    /// stale by the time the call returns).
    ///
    /// Direct index into `self.cfg.addrs` without a defensive clamp.
    /// `ReaderConfig::from_conf` rejects empty address lists, and
    /// the worker only writes `current_addr_idx` values that came
    /// out of [`pipelined_internals::addr_idx`] on a successfully
    /// connected `Reader` (i.e. always in-range). A previous
    /// `idx.min(addrs.len().saturating_sub(1))` clamp gave a false
    /// sense of safety: with `addrs.len() == 0` (which can't
    /// happen) the saturating_sub still yielded `0` and the index
    /// op still panicked. Trust the invariants instead.
    pub fn current_addr(&self) -> &Endpoint {
        // `Acquire` pairs with the `Release` store on **this same
        // atomic** (`current_addr_idx`) in
        // `WorkerState::publish_post_connect_state` — Rust atomic
        // ordering requires Acquire/Release pairing on the same
        // atomic location, not across two different ones (an
        // earlier version of this comment claimed cross-atomic
        // pairing with `server_version`, which was incorrect). The
        // pairing guarantees that
        // observing a post-failover `current_addr_idx` value
        // here implies happens-before with every prior write the
        // worker made *before* its `Release` store on this atomic
        // — but says nothing about the value of `server_version`
        // (a separate atomic): an interleaved load could observe
        // the new `current_addr_idx` paired with a stale
        // `server_version` or vice versa. See `publish_post_connect_state`'s
        // body for the full ordering story.
        let idx = self.current_addr_idx.load(Ordering::Acquire);
        &self.cfg.addrs[idx]
    }

    /// Negotiated QWP version. Returns `SocketError` if the connection
    /// never became usable (the worker died during initial connect; in
    /// practice [`Self::from_config`] would have surfaced the error
    /// already and the reader wouldn't exist).
    pub fn server_version(&self) -> Result<u8> {
        // `Acquire` for the same reason as `current_addr` above.
        let v = self.server_version.load(Ordering::Acquire);
        if v == 0 {
            Err(fmt!(SocketError, "QWP server version unavailable"))
        } else {
            Ok(v as u8)
        }
    }

    /// `true` while a cursor produced by this reader is still alive.
    pub fn has_active_query(&self) -> bool {
        self.cursor_active
    }

    /// Idempotent close. Signals shutdown via the `shutdown` atomic
    /// the worker polls on every event-publish tick and on every
    /// read-loop iteration, and joins the worker. Safe to call
    /// multiple times.
    ///
    /// The safe-Rust API path cannot reach `close()` while a cursor
    /// is alive — the cursor holds `&'r mut PipelinedReader` and
    /// `close` requires `&mut self` — but the FFI launders that
    /// borrow to `'static`, so the worker MUST be able to terminate
    /// even when a cursor still owns the `Receiver` and the channel
    /// is full. The `shutdown` flag + the [`WorkerState::publish`]
    /// wrapper around every `event_tx.send` handles that: a blocked
    /// publish wakes once per [`PUBLISH_POLL_TICK`] (1 ms), sees
    /// `shutdown`, and returns `false`, which every call site treats
    /// as "tear down for this query and exit the worker loop."
    pub fn close(&mut self) {
        let worker = match self.worker.take() {
            Some(w) => w,
            None => return,
        };
        // Signal shutdown first so any subsequent worker iteration —
        // whether it's about to enter `read_frame`, `publish`, or
        // `cmd_rx.recv_timeout` — sees the flag on its next poll.
        // This atomic alone is sufficient to wake the worker; the
        // channel drops below are a fast path for the cursor-
        // already-returned-its-receiver case, not the wake signal.
        //
        // `cancel_slot` is intentionally NOT touched here. The
        // single-cursor invariant + the borrow checker (safe Rust)
        // / the C1 leak-on-active branch (FFI) together guarantee
        // that no cursor is alive when `close()` runs. The slot
        // MAY still hold a non-sentinel value: cursor `Drop`'s
        // happy path resets it, but the broken-state paths
        // (`cancel_with_budget` timeout, `Drop`'s `drain_timed_out`
        // branch — see the `broken_state` flag) deliberately do
        // NOT, to avoid racing the worker's `abort_check` read.
        // Whichever value is there is moot for `close()`: the
        // worker is about to be signalled `shutdown` and the
        // reader is going away. A redundant reset here would just
        // paper over the broken-state invariant if it ever crept
        // in — and would re-introduce the same cancel-slot race
        // for the (still possibly running) worker.
        // `Release` (not `SeqCst`) — the atomic carries only its own
        // value; no cross-atomic happens-before edge is needed.
        // Pairs with every `Acquire` load in `WorkerState::run`,
        // `WorkerState::drive_query`, and `publish_with_shutdown`.
        self.shutdown.store(true, Ordering::Release);
        // Best-effort send: if the worker has already exited its
        // command-recv loop the send fails, which is fine.
        let _ = worker.cmd_tx.send(IoCommand::Shutdown);
        // Dropping the `Receiver` we hold here is a fast-path: if the
        // cursor has already returned its `Receiver` to the worker
        // handle, this disconnects the channel and an in-flight
        // `event_tx.send` on the worker unblocks immediately with
        // `Err(SendError)`. If the cursor still owns the `Receiver`
        // (the FFI close-while-cursor-alive path), the channel
        // stays connected — but the worker's `publish` wrapper
        // polls `shutdown` every `READ_POLL_TICK` and bails on its
        // own, so the join below is still bounded.
        drop(worker.event_rx);
        let _ = worker.join.join();
    }
}

impl Drop for PipelinedReader {
    fn drop(&mut self) {
        self.close();
    }
}

// `PipelinedReader` is `Send`: every field is `Send`. We intentionally do
// NOT implement `Sync` — the public API is single-thread-at-a-time
// (analogous to the sync `Reader`), with the documented concurrent-stat
// exception for the counter getters which all go through the `Arc`-held
// atomics and are themselves `Sync`. Wrap in a `Mutex` if you need
// cross-thread sharing of the handle itself.

// ---------------------------------------------------------------------------
// PipelinedQuery (builder)
// ---------------------------------------------------------------------------

/// Builder mirroring [`crate::egress::ReaderQuery`]. See those docs
/// for the bind-method semantics; the only differences here are
/// (a) [`Self::on_failover_reset`] requires `Send` so the callback can
/// be invoked from the I/O thread, and (b) [`Self::execute`] returns
/// a [`PipelinedCursor`] backed by the I/O thread's event channel.
///
/// **"Pipelined" = dedicated OS thread + blocking method calls, NOT
/// Rust `async fn` / `.await`.** See the [module docs](self).
#[must_use = "PipelinedQuery does nothing until you call .execute(); dropping it discards \
              the prepared SQL and any binds without sending a QUERY_REQUEST"]
pub struct PipelinedQuery<'r> {
    reader: &'r mut PipelinedReader,
    builder: QueryRequestBuilder,
    on_failover_reset: Option<PipelinedFailoverResetCallback>,
    initial_credit: u64,
}

macro_rules! bind_method {
    // Doc-carrying form. `$doc` is forwarded via `#[doc = ...]` so
    // rustdoc picks it up as the generated method's rustdoc — the
    // bare `//` preamble above the call site does NOT attach to the
    // expanded item.
    ($doc:literal, $name:ident, $($arg:ident : $ty:ty),*) => {
        #[doc = $doc]
        pub fn $name(mut self, $($arg : $ty),*) -> Self {
            self.builder = self.builder.$name($($arg),*);
            self
        }
    };
}

impl<'r> PipelinedQuery<'r> {
    /// Override `initial_credit` (bytes; `0` = unbounded). Stored on
    /// the builder so the worker can determine whether per-batch
    /// CREDIT replenishment is required.
    pub fn initial_credit(mut self, credit: u64) -> Self {
        self.initial_credit = credit;
        self.builder = self.builder.initial_credit(credit);
        self
    }

    /// Install a `Send` callback fired on the I/O thread right before
    /// the first replayed batch arrives after a mid-query failover.
    ///
    /// Most users prefer matching on [`Event::FailoverReset`] in the
    /// user-thread loop; the callback exists for parity with the sync
    /// API. Both fire — the callback first (on the I/O thread), then
    /// `Event::FailoverReset` (on the user thread).
    pub fn on_failover_reset<F>(mut self, callback: F) -> Self
    where
        F: FnMut(&FailoverEvent) + Send + 'static,
    {
        self.on_failover_reset = Some(Box::new(callback));
        self
    }

    /// Append a typed bind parameter.
    pub fn bind(mut self, value: Bind) -> Self {
        self.builder = self.builder.bind(value);
        self
    }

    // ---------------------------------------------------------------
    // Positional bind methods.
    //
    // Every method below appends one parameter to the query's bind
    // list in call order; the SQL's `?` placeholders are filled
    // left-to-right at [`Self::execute`] time. Each method is a thin
    // forwarder to the corresponding
    // [`crate::egress::query_request::QueryRequestBuilder`] method
    // (e.g. `bind_i64` here → `QueryRequestBuilder::bind_i64`);
    // consult that crate-internal type for the precise wire-format
    // semantics of each kind.
    //
    // Builder-chained: each method consumes and returns `Self`, so
    // the conventional shape is:
    //
    // ```ignore
    // reader.prepare("SELECT ? + ?")
    //       .bind_i64(40)
    //       .bind_i64(2)
    //       .execute()?;
    // ```
    // ---------------------------------------------------------------

    bind_method!(
        "Append a typed NULL bind. Use this for the simple-typed \
         column kinds; for VARCHAR / DECIMAL* / GEOHASH null binds \
         see the dedicated `bind_null_*` methods below.",
        bind_null, kind: SimpleNullKind
    );
    bind_method!("Append a BOOLEAN bind.", bind_bool, v: bool);
    bind_method!("Append a BYTE (i8) bind.", bind_i8, v: i8);
    bind_method!("Append a SHORT (i16) bind.", bind_i16, v: i16);
    bind_method!("Append a INT (i32) bind.", bind_i32, v: i32);
    bind_method!("Append a LONG (i64) bind.", bind_i64, v: i64);
    bind_method!("Append a FLOAT (f32) bind.", bind_f32, v: f32);
    bind_method!("Append a DOUBLE (f64) bind.", bind_f64, v: f64);
    bind_method!(
        "Append a TIMESTAMP bind with microsecond precision \
         (microseconds since the Unix epoch).",
        bind_timestamp_micros, v: i64
    );
    bind_method!(
        "Append a TIMESTAMP bind with nanosecond precision \
         (nanoseconds since the Unix epoch).",
        bind_timestamp_nanos, v: i64
    );
    bind_method!(
        "Append a DATE bind (milliseconds since the Unix epoch).",
        bind_date_millis, v: i64
    );
    bind_method!(
        "Append a UUID bind (16 raw bytes, big-endian network order).",
        bind_uuid, v: [u8; 16]
    );
    bind_method!(
        "Append a LONG256 bind (32 raw bytes, little-endian).",
        bind_long256, v: [u8; 32]
    );
    bind_method!(
        "Append a CHAR bind (single Unicode codepoint in the BMP, \
         expressed as a `u16`).",
        bind_char, v: u16
    );
    bind_method!(
        "Append an IPV4 bind (4 octets in network order, encoded \
         as `Ipv4Addr`).",
        bind_ipv4, v: Ipv4Addr
    );

    /// Append a UTF-8 VARCHAR bind. `S: Into<String>` accepts owned
    /// `String`, `&str`, `Cow<str>` — the bytes are taken / copied
    /// into the builder.
    pub fn bind_varchar<S: Into<String>>(mut self, v: S) -> Self {
        self.builder = self.builder.bind_varchar(v);
        self
    }

    /// Append a DECIMAL64 bind: signed `i64` mantissa + `i8` scale
    /// (decimal exponent, conventionally `[0, 18]`).
    pub fn bind_decimal64(mut self, value: i64, scale: i8) -> Self {
        self.builder = self.builder.bind_decimal64(value, scale);
        self
    }

    /// Append a DECIMAL128 bind: signed `i128` mantissa + `i8` scale.
    pub fn bind_decimal128(mut self, value: i128, scale: i8) -> Self {
        self.builder = self.builder.bind_decimal128(value, scale);
        self
    }

    /// Append a DECIMAL256 bind: 32 raw mantissa bytes in
    /// little-endian (two's complement) + `i8` scale.
    pub fn bind_decimal256(mut self, bytes: [u8; 32], scale: i8) -> Self {
        self.builder = self.builder.bind_decimal256(bytes, scale);
        self
    }

    /// Append a GEOHASH bind: integer-packed bit representation +
    /// per-cell precision in bits (`1..=60`).
    pub fn bind_geohash(mut self, value: u64, precision_bits: u8) -> Self {
        self.builder = self.builder.bind_geohash(value, precision_bits);
        self
    }

    /// Append a BINARY bind. `B: Into<Vec<u8>>` takes ownership of
    /// the bytes (no copy on `Vec<u8>`).
    pub fn bind_binary<B: Into<Vec<u8>>>(mut self, v: B) -> Self {
        self.builder = self.builder.bind_binary(v);
        self
    }

    /// Append a typed NULL VARCHAR. For non-VARCHAR null binds, use
    /// the `bind_null(kind: SimpleNullKind)` method above instead.
    pub fn bind_null_varchar(mut self) -> Self {
        self.builder = self.builder.bind_null_varchar();
        self
    }

    /// Append a typed NULL BINARY.
    pub fn bind_null_binary(mut self) -> Self {
        self.builder = self.builder.bind_null_binary();
        self
    }

    /// Append a typed NULL DECIMAL64 (carries the column's scale so
    /// the server can preserve precision metadata across the null).
    pub fn bind_null_decimal64(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal64(scale);
        self
    }

    /// Append a typed NULL DECIMAL128. See `bind_null_decimal64`.
    pub fn bind_null_decimal128(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal128(scale);
        self
    }

    /// Append a typed NULL DECIMAL256. See `bind_null_decimal64`.
    pub fn bind_null_decimal256(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal256(scale);
        self
    }

    /// Append a typed NULL GEOHASH (carries the column's precision
    /// in bits so the server preserves the precision metadata
    /// across the null).
    pub fn bind_null_geohash(mut self, precision_bits: u8) -> Self {
        self.builder = self.builder.bind_null_geohash(precision_bits);
        self
    }

    /// Encode the QUERY_REQUEST, hand it to the I/O thread, and return
    /// a [`PipelinedCursor`] the user pulls events from.
    pub fn execute(self) -> Result<PipelinedCursor<'r>> {
        if self.reader.cursor_active {
            return Err(fmt!(
                InvalidApiCall,
                "another cursor is already in flight on this PipelinedReader (one at a time)"
            ));
        }
        // Allocate the request_id on the user thread so it's available
        // to the cursor without a round-trip to the worker. The
        // counter is shared with the worker via `Arc<AtomicI64>`, so
        // the worker's mid-query failover replays draw from the
        // same monotone sequence and can't collide with subsequent
        // user-side `execute()` allocations.
        let request_id = alloc_request_id_atomic(&self.reader.next_request_id);
        let req = self.builder.request_id(request_id).build()?;
        let mut encoded = Vec::with_capacity(64);
        req.encode(&mut encoded)?;
        // Layout invariant guard — mirrors `ReaderQuery::execute`.
        if encoded.len() < REQUEST_ID_OFFSET + 8 || encoded[0] != MsgKind::QueryRequest.as_u8() {
            return Err(fmt!(
                ProtocolError,
                "QUERY_REQUEST encoding layout invariant violated (len={}, first={:?})",
                encoded.len(),
                encoded.first().copied(),
            ));
        }
        let worker = self
            .reader
            .worker
            .as_mut()
            .ok_or_else(|| fmt!(InvalidApiCall, "PipelinedReader has been closed"))?;
        // The previous cursor's `event_rx` is returned to the worker
        // handle by its `Drop`; we re-take it here so the cursor
        // for this query owns the Receiver. If the worker handle
        // has no `event_rx` to give us — only reachable when
        // `close()` already dropped it — there's nothing to
        // recover from, so the `None` arm below short-circuits.
        let event_rx = match worker.event_rx.take() {
            Some(rx) => rx,
            None => {
                return Err(fmt!(
                    InvalidApiCall,
                    "PipelinedReader event channel is closed (was the worker shut down?)"
                ));
            }
        };
        // Restore `worker.event_rx` on command-send failure so a
        // subsequent `execute()` reports the real cause (the
        // worker exited and `cmd_tx.send` returns Disconnected)
        // rather than the misleading "event channel is closed"
        // path above — which would otherwise fire on every future
        // attempt because the `take` above already moved the
        // receiver out of the handle. The worker IS dead either
        // way (a `sync_channel` send fails only on Disconnected
        // and the next call will likewise fail), but the error
        // code progression is what we're fixing here: SocketError
        // → SocketError stays honest about cause-of-death, the
        // previous SocketError → InvalidApiCall sequence hid it
        // behind a stale-channel diagnostic.
        // Submit via `try_send` + poll loop bounded by
        // [`CANCEL_DRAIN_BUDGET`]. Pre-fix this used `send()`
        // (unbounded) — if the worker was wedged (stuck in
        // `WsTransport::Drop`'s `close(2)` syscall on a broken NIC,
        // stuck in a slow allocator inside `terminate_with_close`,
        // etc.) the user thread would hang forever with no recovery
        // and no diagnostic. The single-cursor invariant + Drop's
        // bounded drain ensure the worker is usually idle in
        // `cmd_rx.recv_timeout` by the time `execute()` runs, so
        // the steady-state path returns from the first `try_send`
        // with no sleep cost.
        //
        // The loop also polls `shutdown` (matching the
        // `publish_with_shutdown` pattern) so that if a
        // `PipelinedReader::close` is signalled from another path
        // — e.g. the FFI's `_close` setting `shutdown` while we're
        // mid-loop — the wait unblocks cleanly with a deterministic
        // `InvalidApiCall` rather than waiting out the full budget.
        let mut pending = IoCommand::Submit {
            request_id,
            encoded_request: Bytes::from(encoded),
            initial_credit: self.initial_credit,
            on_failover_reset: self.on_failover_reset,
        };
        // Reset the cancel slot BEFORE submitting. The worker reads
        // `cancel_slot` inside
        // `drive_query`'s read loop and inside `failover_and_replay`'s
        // `abort_check`; if any prior cursor's broken-state Drop left
        // a stale non-sentinel value (the `broken_state` path
        // deliberately skips the reset to avoid racing the worker's
        // in-flight reads — see `PipelinedCursor::Drop`'s `if
        // !self.broken_state` guard), the worker would observe the
        // stale cancel on the very first iteration of the new query
        // and immediately abort. Today this combinatorial argument
        // is held together by `broken_state` ALWAYS dropping
        // `event_rx` (so the next `execute()` short-circuits at the
        // `worker.event_rx.take().None` arm BEFORE reaching
        // `try_send`); reordering the reset here closes the window
        // unconditionally and removes the dependence on those two
        // co-occurring paths.
        self.reader
            .cancel_slot
            .store(NO_PENDING_CANCEL, Ordering::Release);
        let deadline = std::time::Instant::now() + CANCEL_DRAIN_BUDGET;
        let send_outcome: Result<()> = loop {
            if self.reader.shutdown.load(Ordering::Acquire) {
                break Err(fmt!(
                    InvalidApiCall,
                    "PipelinedReader was closed while execute() was \
                     submitting the new query"
                ));
            }
            match worker.cmd_tx.try_send(pending) {
                Ok(()) => break Ok(()),
                Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                    if std::time::Instant::now() >= deadline {
                        // `returned` is the original `IoCommand::Submit`
                        // (and therefore the encoded payload + the
                        // user's failover callback). Drop it — the
                        // worker is wedged, the bytes have no
                        // destination, and re-running `execute()`
                        // will re-encode them.
                        drop(returned);
                        break Err(fmt!(
                            SocketError,
                            "PipelinedReader::execute: worker did not accept \
                             the new command within {:?} (the worker thread \
                             is likely wedged — e.g. stuck in a transport \
                             teardown syscall); reconstruct the reader to \
                             recover",
                            CANCEL_DRAIN_BUDGET,
                        ));
                    }
                    pending = returned;
                    std::thread::sleep(PUBLISH_POLL_TICK);
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(returned)) => {
                    // Worker has exited and dropped its `cmd_rx`.
                    // Same recovery diagnostic as before — the
                    // user's next `execute()` will hit this same
                    // Disconnected branch and report the same
                    // error, surfacing the real cause-of-death.
                    drop(returned);
                    break Err(fmt!(
                        SocketError,
                        "I/O thread is no longer accepting commands (worker exited)"
                    ));
                }
            }
        };
        if let Err(e) = send_outcome {
            // Restore `worker.event_rx` on send failure so a
            // subsequent `execute()` reports the real cause rather
            // than the misleading "event channel is closed" path
            // above (which would otherwise fire on every future
            // attempt because the `take` above already moved the
            // receiver out of the handle).
            worker.event_rx = Some(event_rx);
            return Err(e);
        }
        self.reader.cursor_active = true;
        Ok(PipelinedCursor {
            reader: self.reader,
            request_id,
            event_rx: Some(event_rx),
            done: false,
            cancelling: false,
            terminal: None,
            broken_state: false,
        })
    }
}

// ---------------------------------------------------------------------------
// PipelinedCursor
// ---------------------------------------------------------------------------

/// Successful-completion sentinel attached to the cursor after a
/// terminal event. Mirrors [`crate::egress::Terminal`] but lives here
/// so the pipelined surface is self-contained.
///
/// **"Pipelined" = dedicated OS thread + blocking method calls, NOT
/// Rust `async fn` / `.await`.** See the [module docs](self).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PipelinedTerminal {
    /// `RESULT_END`.
    End { final_seq: u64, total_rows: u64 },
    /// `EXEC_DONE`.
    ExecDone { op_type: u8, rows_affected: u64 },
}

/// Consumer of events for a single in-flight query.
///
/// Calling [`Self::take_event`] blocks the user thread until the I/O
/// thread publishes the next [`Event`] (or terminal error). Drop
/// without draining sends a best-effort CANCEL on the worker (so the
/// server stops generating new batches for an abandoned request) and
/// returns the reader to the idle state — subsequent queries on the
/// same reader still work.
///
/// **Drop's drain is bounded by [`CANCEL_DRAIN_BUDGET`].** Under
/// healthy operation the server's terminal arrives within milliseconds
/// of the CANCEL; the budget exists for the pathological case where
/// the server is wedged or the network is one-way alive. On budget
/// expiry, Drop logs a stderr diagnostic, drops the event channel,
/// and returns — the `PipelinedReader` is then in a deterministic
/// broken state and the next `execute()` returns
/// `InvalidApiCall("event channel is closed")`. Re-construct the
/// reader to recover.
///
/// **"Pipelined" = dedicated OS thread + blocking method calls, NOT
/// Rust `async fn` / `.await`.** See the [module docs](self).
#[must_use = "PipelinedCursor must be drained via take_event() (until terminal) or cancelled \
              via cancel(); dropping mid-stream sends a best-effort CANCEL and waits up to \
              CANCEL_DRAIN_BUDGET for the server's terminal before tearing the channel down"]
pub struct PipelinedCursor<'r> {
    reader: &'r mut PipelinedReader,
    request_id: i64,
    /// `Receiver` end of the I/O thread → user event channel. Taken
    /// from the reader's `WorkerHandle` at `execute()` time and
    /// returned on `Drop` so the next query can re-take it.
    event_rx: Option<Receiver<IoEvent>>,
    /// Set once a terminal event (End / ExecDone / Error) has been
    /// observed. Subsequent `take_event` calls short-circuit with
    /// `InvalidApiCall` so the user can't accidentally read past the
    /// terminal.
    done: bool,
    /// `true` after the user called [`Self::cancel`]. Suppresses the
    /// best-effort cancel in `Drop`.
    cancelling: bool,
    /// Captured terminal (`End` / `ExecDone`) — observable via
    /// [`Self::terminal`] after the stream ends.
    terminal: Option<PipelinedTerminal>,
    /// Set when [`Self::cancel_with_budget`]'s timeout branch (or
    /// any other path that leaves the reader in the broken state
    /// documented at [`Self::cancel`]) takes the channel down
    /// without confirming a worker terminal. `Drop` reads this to
    /// decide whether to reset `cancel_slot` to
    /// [`NO_PENDING_CANCEL`]: when broken, the worker may still be
    /// inside `failover_and_replay`'s `abort_check` reading
    /// `cancel_slot`, and a reset would race that read
    /// non-deterministically.
    /// When unset (happy path), `Drop` resets the slot so the
    /// reader's next query starts clean.
    broken_state: bool,
}

impl<'r> PipelinedCursor<'r> {
    /// Current `request_id` on the wire for this cursor.
    ///
    /// Initially the id allocated by [`PipelinedQuery::execute`]. After
    /// a successful mid-query failover the worker re-allocates a fresh
    /// id for the replayed query and surfaces it via
    /// [`Event::FailoverReset::new_request_id`] (and on the
    /// [`PipelinedFailoverResetCallback`] if installed); consuming the
    /// `FailoverReset` event through any `take_event*` accessor
    /// updates the value returned by this method. To capture the
    /// originally-allocated id for logging across failovers, read this
    /// accessor before the first `take_event` call and snapshot it.
    pub fn request_id(&self) -> i64 {
        self.request_id
    }

    /// `Some` after the stream has ended cleanly via `RESULT_END` or
    /// `EXEC_DONE`. `None` while the stream is live, after an error,
    /// or after cancel.
    pub fn terminal(&self) -> Option<&PipelinedTerminal> {
        self.terminal.as_ref()
    }

    /// Block until the I/O thread publishes the next event.
    ///
    /// Returns `Ok(Event::End { .. })` or `Ok(Event::ExecDone { .. })`
    /// at clean termination; subsequent calls return
    /// `Err(InvalidApiCall)`. Returns `Err(_)` on transport failure
    /// (`SocketError`), failover exhaustion (`SocketError` /
    /// `AuthError` / `ConfigError` per the failover policy in
    /// `failover.md`), or a server-side `QUERY_ERROR` mapped to its
    /// corresponding [`ErrorCode`].
    ///
    /// **Note on `FailoverWouldDuplicate`**: the sync surface returns
    /// this code when a mid-query failover would silently replay rows
    /// already delivered to the caller and no `on_failover_reset`
    /// callback is installed. **The pipelined surface NEVER returns
    /// this code** — the worker unconditionally publishes
    /// `Event::FailoverReset` on every successful mid-query failover,
    /// so silent duplication is impossible on this surface by
    /// construction. Callers MUST observe `Event::FailoverReset(_)`
    /// (described below) to discard accumulated row state; they do
    /// NOT need a defensive `FailoverWouldDuplicate` branch.
    ///
    /// `Event::FailoverReset(_)` lands BETWEEN the last pre-failover
    /// `Event::Batch` and the first replayed batch — the caller MUST
    /// discard any accumulated row state on receiving it.
    pub fn take_event(&mut self) -> Result<Event> {
        if self.done {
            return Err(fmt!(
                InvalidApiCall,
                "{ERR_PREFIX_CURSOR_TERMINATED}; open a new query"
            ));
        }
        // Scope the `rx` borrow so the channel disconnect path below
        // can flip `self.done` via `&mut self`. Without the scope,
        // `rx` would keep `self.event_rx` borrowed for the rest of
        // the function and the disconnect handler couldn't take
        // `&mut self`.
        let recv_result = {
            let rx = self
                .event_rx
                .as_ref()
                .ok_or_else(|| fmt!(InvalidApiCall, "{ERR_PREFIX_EVENT_CHANNEL_TAKEN}"))?;
            rx.recv()
        };
        match recv_result {
            Ok(io_event) => self.dispatch(io_event),
            Err(_) => Err(self.finalize_on_channel_disconnect()),
        }
    }

    /// Non-blocking variant of [`Self::take_event`]. Returns
    /// `Ok(None)` when no event is currently buffered. Same terminal
    /// semantics as `take_event`: once `End` / `ExecDone` / `Err(_)`
    /// has been observed, subsequent calls return `InvalidApiCall`.
    pub fn try_take_event(&mut self) -> Result<Option<Event>> {
        if self.done {
            return Err(fmt!(
                InvalidApiCall,
                "{ERR_PREFIX_CURSOR_TERMINATED}; open a new query"
            ));
        }
        use std::sync::mpsc::TryRecvError;
        // Scope the `rx` borrow — see `take_event` for the rationale.
        let try_result = {
            let rx = self
                .event_rx
                .as_ref()
                .ok_or_else(|| fmt!(InvalidApiCall, "{ERR_PREFIX_EVENT_CHANNEL_TAKEN}"))?;
            rx.try_recv()
        };
        match try_result {
            Ok(io_event) => self.dispatch(io_event).map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(self.finalize_on_channel_disconnect()),
        }
    }

    /// Bounded-blocking variant of [`Self::take_event`]. Returns
    /// `Ok(None)` if no event arrives within `timeout`.
    ///
    /// `timeout == Duration::ZERO` is treated as "non-blocking" —
    /// the call delegates to [`Self::try_take_event`] (which uses
    /// `try_recv`) instead of `recv_timeout(Duration::ZERO)`. The
    /// stdlib documents `recv_timeout(ZERO)` as "wait up to the
    /// timeout"; behaviour across stdlib versions / platforms has
    /// historically varied on whether a value already buffered in
    /// the channel is observed in a zero-duration call. `try_recv`
    /// is the unambiguous "look once, no wait" primitive — matches
    /// POSIX `poll(2)` and the C ABI `_take_event_timeout`
    /// docstring's "non-blocking when timeout_ms == 0" promise.
    pub fn take_event_timeout(&mut self, timeout: Duration) -> Result<Option<Event>> {
        if self.done {
            return Err(fmt!(
                InvalidApiCall,
                "{ERR_PREFIX_CURSOR_TERMINATED}; open a new query"
            ));
        }
        if timeout.is_zero() {
            return self.try_take_event();
        }
        // Scope the `rx` borrow — see `take_event` for the rationale.
        let timed_result = {
            let rx = self
                .event_rx
                .as_ref()
                .ok_or_else(|| fmt!(InvalidApiCall, "{ERR_PREFIX_EVENT_CHANNEL_TAKEN}"))?;
            rx.recv_timeout(timeout)
        };
        match timed_result {
            Ok(io_event) => self.dispatch(io_event).map(Some),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Err(self.finalize_on_channel_disconnect()),
        }
    }

    /// Build the "I/O thread terminated without publishing a final
    /// event" error AND mark the cursor terminal in one step. The
    /// three takers all funnel their `Disconnected` paths through
    /// here so the documented terminal contract — "subsequent calls
    /// return `Err(InvalidApiCall)`" — holds even when the worker
    /// exits without publishing an End / ExecDone / Error event
    /// (e.g. a panic-driven thread death). Without flipping `done`,
    /// every subsequent `recv` / `try_recv` / `recv_timeout` would
    /// keep returning `Disconnected` and the caller would spin on
    /// identical `SocketError`s forever instead of hitting the
    /// documented `InvalidApiCall` short-circuit.
    fn finalize_on_channel_disconnect(&mut self) -> Error {
        self.done = true;
        fmt!(
            SocketError,
            "I/O thread terminated without publishing a final event"
        )
    }

    /// Shared event-dispatch from the three `*_event` accessors.
    fn dispatch(&mut self, io_event: IoEvent) -> Result<Event> {
        match io_event {
            IoEvent::Batch(b) => Ok(Event::Batch(b)),
            IoEvent::FailoverReset(ev) => {
                // Track the post-failover request_id so the public
                // `request_id()` accessor reports the id actually on
                // the wire rather than the (now stale) initial
                // submission id. The worker has already published
                // CANCEL/match against this new id; mirroring it on
                // the cursor keeps any user-side log correlation
                // honest.
                self.request_id = ev.new_request_id;
                Ok(Event::FailoverReset(ev))
            }
            IoEvent::End {
                request_id,
                final_seq,
                total_rows,
            } => {
                self.done = true;
                self.terminal = Some(PipelinedTerminal::End {
                    final_seq,
                    total_rows,
                });
                Ok(Event::End {
                    request_id,
                    final_seq,
                    total_rows,
                })
            }
            IoEvent::ExecDone {
                request_id,
                op_type,
                rows_affected,
            } => {
                self.done = true;
                self.terminal = Some(PipelinedTerminal::ExecDone {
                    op_type,
                    rows_affected,
                });
                Ok(Event::ExecDone {
                    request_id,
                    op_type,
                    rows_affected,
                })
            }
            IoEvent::Error(e) => {
                self.done = true;
                Err(e)
            }
        }
    }

    /// Ask the server to cancel the current query. Sets the cancel
    /// slot the I/O thread polls between reads. Then blocks, draining
    /// remaining events (which the worker discards once it sees the
    /// cancel flag), until a terminal event arrives.
    ///
    /// **Returns `Ok(())` for every code path the user implicitly
    /// asked for by calling `cancel()`** — the cursor winding down
    /// through any plausible terminal counts as cancel-success, not
    /// failure. Specifically: a clean server-side `RESULT_END` /
    /// `EXEC_DONE`, the `Cancelled` server status, a transport
    /// `SocketError` (the server closed the socket in response to
    /// our CANCEL frame instead of sending a terminal — semantically
    /// the same outcome), and the "cursor already wound down" cases
    /// (re-entered cancel after a previous `take_event` observed a
    /// terminal; Drop's timed-out path already tore the channel
    /// down). The wound-down cases are detected by a `self.done ||
    /// self.event_rx.is_none()` pre-check inside the drain loop
    /// rather than by inspecting an `Err`'s message — the producer
    /// and consumer of the bookkeeping signal are decoupled, so a
    /// future reword of the entry-guard `InvalidApiCall` message in
    /// `take_event_timeout` cannot silently flip the cancel
    /// classification.
    ///
    /// Other `Err(_)` codes — `ProtocolError` from a corrupted
    /// frame, `InvalidApiCall` from a panicked `on_failover_reset`
    /// callback, `InvalidApiCall` from PipelinedReader-closed-
    /// during-mid-query-failover-backoff — still propagate, because
    /// they indicate the cursor wound down for a reason **other
    /// than** the cancel the user requested. The classification used
    /// to widen to bare `InvalidApiCall`, which silently swallowed
    /// those diagnostics; the current classification narrows to
    /// `Cancelled | SocketError` after routing the benign-
    /// bookkeeping cases around `take_event_timeout` entirely.
    ///
    /// Pre-fix the user got
    /// `Err(SocketError)` from a successful cancel whenever the
    /// server's response to the CANCEL frame was a socket reset
    /// instead of a terminal — indistinguishable from an unrelated
    /// transport failure happening to coincide with the cancel.
    ///
    /// **Reader state after `cancel()` returns `Ok(())`**: the
    /// reader is fully usable for subsequent queries — with one
    /// edge case. If the cancel landed while the worker was
    /// mid-failover-backoff (the worker was waiting between
    /// reconnect attempts when the cancel_slot was set), the
    /// reader's transport was already taken at the start of that
    /// backoff and not restored. The reader is left in a
    /// "needs reconnect" state; the next `execute()` will dial a
    /// fresh endpoint via the standard initial-submission
    /// failover path. If failover has been disabled in the
    /// connect string, the next `execute()` instead returns
    /// `SocketError` indefinitely and the reader must be
    /// reconstructed.
    ///
    /// **Bounded wait**: the drain is capped by
    /// [`CANCEL_DRAIN_BUDGET`] (30 seconds, the same constant
    /// `Drop` uses for its bounded drain). On budget expiry —
    /// reachable only when the server is wedged and the worker's
    /// reads are returning `Ok(None)` forever — `cancel()` returns
    /// `Err(SocketError, "PipelinedCursor::cancel: worker did not
    /// publish a terminal frame within ...")`, marks the cursor
    /// terminal, drops the event channel, and the reader enters
    /// the same broken state described above. The user MUST
    /// `close()` and rebuild the reader to recover. Pre-fix this
    /// loop was unbounded — a wedged-server cancel would hang the
    /// user thread indefinitely with no recovery path.
    pub fn cancel(&mut self) -> Result<()> {
        self.cancel_with_budget(CANCEL_DRAIN_BUDGET)
    }

    /// Bounded-drain implementation backing [`Self::cancel`]. Lives
    /// as a private helper so the in-module test
    /// `cancel_returns_timeout_err_when_worker_never_publishes`
    /// can drive the timeout path with a millisecond budget
    /// without waiting the production [`CANCEL_DRAIN_BUDGET`].
    /// Production code MUST call `cancel()` (which passes the
    /// production budget); only tests are entitled to pick the
    /// budget.
    fn cancel_with_budget(&mut self, budget: Duration) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.cancelling = true;
        self.reader
            .cancel_slot
            .store(self.request_id, Ordering::Release);
        // Bound the drain by `budget` (production: `CANCEL_DRAIN_BUDGET`
        // = 30s, the same constant `Drop`'s C3 bounded drain uses).
        // The wall-clock deadline survives multiple
        // `take_event_timeout` polls; each poll passes the
        // *remaining* budget so the total wait never exceeds the
        // budget. Without this, the cancel loop was unbounded —
        // `cancel()` from a coordination thread would deadlock the
        // user thread forever if the worker was wedged (server-side
        // compute hung, one-way-alive socket where writes succeed
        // but no reads arrive).
        let deadline = std::time::Instant::now() + budget;
        loop {
            // Pre-check the two entry guards that `take_event_timeout`
            // itself would check — `self.done` and `event_rx.is_none()`.
            // Either condition signals "the cursor is already wound
            // down"; treat as cancel-success. Pre-checking here means
            // every `Err(InvalidApiCall, _)` returned by
            // `take_event_timeout` from inside the loop comes from
            // `dispatch(IoEvent::Error(e))` — i.e. a real worker-
            // published failure (panicked `on_failover_reset`
            // callback, closed-during-mid-query-failover-backoff) —
            // and propagates verbatim. This is the typed-signal
            // alternative to the earlier message-prefix matching: we
            // route around the benign-bookkeeping `InvalidApiCall`s
            // rather than catching them after the fact, so the
            // classifier in the `Err(e)` arm below never has to
            // distinguish "cursor bookkeeping" from "real failure"
            // by inspecting `e.msg()`.
            if self.done || self.event_rx.is_none() {
                return Ok(());
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                // Budget exhausted — same recovery shape as `Drop`'s
                // bounded-timeout path: mark `done` so the user's
                // subsequent `Drop` skips its own drain attempt
                // (would otherwise spend another `CANCEL_DRAIN_BUDGET`
                // re-draining the same wedged worker), and drop the
                // receiver so the worker's next `publish` returns
                // `Disconnected` and exits `drive_query` via
                // `terminate_with_close`. After this return the
                // reader is in the broken state documented above
                // (transport torn down; next `execute()` self-heals
                // via initial-submission failover if enabled, else
                // returns `SocketError` until reconstruct).
                //
                // Set `broken_state` so the upcoming `Drop` does
                // NOT reset `cancel_slot` to `NO_PENDING_CANCEL`.
                // The worker may still be inside
                // `failover_and_replay`'s `abort_check` reading
                // `cancel_slot`; an unconditional reset would race
                // that read non-deterministically. On this
                // path the receiver is already gone so no
                // subsequent cursor will ever observe the stale
                // slot value, and the next `execute()` overwrites
                // it before the worker reads.
                self.done = true;
                self.broken_state = true;
                drop(self.event_rx.take());
                return Err(fmt!(
                    SocketError,
                    "PipelinedCursor::cancel: worker did not publish a terminal frame \
                     within {:?} after CANCEL was sent (server is likely wedged or the \
                     CANCEL was lost in transit); the cursor's event channel has been \
                     torn down, the reader's transport is now closed",
                    budget
                ));
            }
            match self.take_event_timeout(remaining) {
                Ok(Some(Event::End { .. })) | Ok(Some(Event::ExecDone { .. })) => {
                    return Ok(());
                }
                // Discard batches / failover-reset between CANCEL and terminal.
                Ok(Some(_)) => continue,
                // `take_event_timeout` itself returned the timeout
                // sentinel — the inner `recv_timeout` saw no event
                // within the remaining budget. Loop and re-check the
                // wall-clock deadline at the top.
                Ok(None) => continue,
                Err(e) => {
                    // The user asked to cancel. Cursor wind-down
                    // through `Cancelled` (server status) or
                    // `SocketError` (server closed in response, or
                    // worker exited with the "I/O thread terminated
                    // without publishing a final event" diagnostic)
                    // counts as cancel-success. `InvalidApiCall` from
                    // here is always a real worker-published failure
                    // — the benign bookkeeping cases were already
                    // routed around by the `self.done ||
                    // self.event_rx.is_none()` short-circuit at the
                    // top of the loop, so message-prefix inspection
                    // is no longer needed and is not performed.
                    let is_cancel_success =
                        matches!(e.code(), ErrorCode::Cancelled | ErrorCode::SocketError,);
                    if is_cancel_success {
                        return Ok(());
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Endpoint the underlying connection is currently bound to. Same
    /// snapshot semantics as [`PipelinedReader::current_addr`].
    pub fn current_addr(&self) -> &Endpoint {
        self.reader.current_addr()
    }
}

impl Drop for PipelinedCursor<'_> {
    fn drop(&mut self) {
        // Cursor is being abandoned — if the stream hadn't terminated,
        // bump the cancel slot so the worker tells the server to stop
        // generating batches for this request. The worker will drain
        // residual events (without us reading them — the channel
        // backpressures the worker) and end the query naturally.
        //
        // `drain_timed_out` records whether the bounded drain below
        // gave up before a terminal arrived; on the unhappy path we
        // tear the channel down rather than returning the receiver
        // (see the post-drain block below for the rationale).
        let mut drain_timed_out = false;
        if !self.done && !self.cancelling {
            self.reader
                .cancel_slot
                .store(self.request_id, Ordering::Release);
            // Drain the channel ourselves so the worker isn't blocked
            // on `event_tx.send` after we drop the receiver — but
            // bound the wait by [`CANCEL_DRAIN_BUDGET`]. An earlier
            // revision used `rx.recv()` (unbounded), which let a
            // stuck server (compute thread wedged; one-way-alive
            // socket) block this thread indefinitely. The bounded-
            // budget cap surfaces a clear diagnostic on expiry.
            if let Some(rx) = self.event_rx.as_ref() {
                drain_timed_out = drain_to_terminal(rx, CANCEL_DRAIN_BUDGET);
            }
        }
        if drain_timed_out {
            // Worker did not publish a terminal within
            // `CANCEL_DRAIN_BUDGET`. The safe-Rust borrow checker (and
            // the FFI leak-on-active branch in `_close`) prevent any
            // external rescue; we MUST unblock the user thread here.
            //
            // Drop the receiver without returning it to
            // `worker.event_rx`: that causes the worker's next
            // `publish` to fail (`TrySendError::Disconnected`), which
            // takes the `if !self.publish(IoEvent::Batch(owned))`
            // branch in `WorkerState::drive_query` and calls
            // `terminate_with_close`, exiting `drive_query` cleanly.
            // The worker's outer loop then goes back to idle, ready
            // for a new `IoCommand::Submit` — but the next
            // `execute()` finds `worker.event_rx` is `None` and
            // returns `InvalidApiCall("event channel is closed")`,
            // giving the caller a deterministic broken-reader signal.
            // From there the caller's recovery is to `close()` and
            // build a new `PipelinedReader`.
            //
            // Stderr diagnostic so the user can correlate the broken
            // reader with the timeout. Drop has nowhere else to
            // surface the diagnostic. Uses `eprintln_lossy` instead
            // of `eprintln!` — the latter panics on stderr-write
            // failure (closed fd, broken pipe), which under
            // `panic = "abort"` would kill the host process from
            // inside a Drop.
            eprintln_lossy(format_args!(
                "PipelinedCursor::drop: worker did not publish a terminal \
                 frame within {:?} after cancel (request_id={}); dropping \
                 the event channel to unblock. The PipelinedReader is now \
                 in a broken state — re-construct it for further queries. \
                 Server is likely wedged or the CANCEL was lost in transit.",
                CANCEL_DRAIN_BUDGET, self.request_id,
            ));
            // Drop, do NOT return-to-worker. Mark `broken_state` so
            // the shared "skip cancel_slot reset on broken paths"
            // gate at the bottom of this `drop` honours the
            // cancel-slot race avoidance here too. Race recap: the
            // worker may still be inside `failover_and_replay`'s
            // `abort_check` closure reading `cancel_slot`, and a
            // reset interleaved against the `event_rx` drop above
            // is non-deterministic. The reader is now in the
            // broken state — the channel is gone, the next
            // `execute()` returns `InvalidApiCall("event channel
            // is closed")`, and no subsequent cursor will ever
            // observe the stale slot value.
            self.broken_state = true;
            drop(self.event_rx.take());
            self.reader.cursor_active = false;
            return;
        }
        // Happy path: terminal received (or the cursor was already done
        // and we never drained). Return the receiver to the worker
        // handle so the next `execute()` can re-take it. If the reader
        // has been closed since the cursor was created, `worker` is
        // `None` and we simply drop the receiver.
        if let Some(rx) = self.event_rx.take()
            && let Some(worker) = self.reader.worker.as_mut()
        {
            worker.event_rx = Some(rx);
        }
        self.reader.cursor_active = false;
        // Reset cancel slot so the next query starts clean — but
        // ONLY when the cursor exited cleanly. When `broken_state`
        // is set, the cursor's wind-down has already torn the
        // channel down without confirming a worker terminal, the
        // worker may still be inside `failover_and_replay`'s
        // `abort_check` reading `cancel_slot`, and resetting here
        // would race that read. On the broken path the slot value
        // is moot anyway: the next `execute()` returns
        // `InvalidApiCall("event channel is closed")` from the
        // `event_rx.is_none()` guard before the worker ever reads
        // `cancel_slot` for a new query. (`cancel_with_budget`'s
        // timeout branch deliberately does not reset, so `Drop`
        // must gate its own reset on `broken_state` instead of
        // unconditionally clearing the slot.)
        if !self.broken_state {
            self.reader
                .cancel_slot
                .store(NO_PENDING_CANCEL, Ordering::Release);
        }
    }
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

/// All state the worker thread owns. Lives on the worker stack after
/// [`Self::run`] takes ownership — no other thread touches these
/// fields directly. Cross-thread communication is through the
/// `Arc<Atomic*>` shared with the user side.
struct WorkerState {
    reader: Reader,
    cmd_rx: Receiver<IoCommand>,
    event_tx: SyncSender<IoEvent>,
    cancel_slot: Arc<AtomicI64>,
    shutdown: Arc<AtomicBool>,
    current_addr_idx: Arc<AtomicUsize>,
    server_version: Arc<AtomicU64>,
    /// Shared `request_id` counter (same `Arc` as on
    /// `PipelinedReader::next_request_id`). The worker mints rids
    /// from here on failover replay so they never collide with the
    /// user side's subsequent `execute()` allocations.
    ///
    /// Same write discipline as the user-side handle: mutate only
    /// through [`alloc_request_id_atomic`] to preserve the
    /// strictly-positive invariant.
    next_request_id: Arc<AtomicI64>,
}

impl WorkerState {
    /// Top-level worker loop. Alternates between blocking on the
    /// command channel and driving a single query to terminal.
    fn run(mut self) {
        // Re-publish the initial connect's negotiated version +
        // addr_idx as the worker's first action. For the
        // initial-connect case the same data is already observable
        // on the user side via the implicit acquire/release edge
        // that `thread::spawn` provides when it captures the
        // already-connected `Reader` into this closure — so this
        // first publish is *redundant* there. The publish is
        // load-bearing only for the post-failover case, where
        // there is no spawn-edge between the worker's reconnect-
        // completion and a subsequent user-thread `current_addr()`
        // / `server_version()` call; the `Release`/`Acquire`
        // pairing in `publish_post_connect_state` is what carries
        // the happens-before there.
        //
        // If the initial publish fails (worker-internal invariant
        // break — see the function's docstring), surface it on the
        // event channel and exit cleanly. We have not entered the
        // main loop yet, so there's no `terminate_with_close` to
        // run; just publish the error and return so the user's
        // first `take_event*` call sees a deterministic diagnostic
        // instead of a generic "I/O thread terminated" surrogate.
        if let Err(e) = self.publish_post_connect_state() {
            let _ = self.publish(IoEvent::Error(e));
            return;
        }
        loop {
            // `Acquire` (not `SeqCst`); pairs with the `Release`
            // store in `PipelinedReader::close`.
            if self.shutdown.load(Ordering::Acquire) {
                break;
            }
            // Block on the command channel; shutdown is checked on
            // every wakeup tick (idle path) and on every read tick
            // (in-query path). A blocked recv is woken either by a
            // real command or by the user side dropping cmd_tx, which
            // surfaces as `Err(_)` here.
            let cmd = match self.cmd_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(c) => c,
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            };
            match cmd {
                IoCommand::Shutdown => break,
                IoCommand::Submit {
                    request_id,
                    encoded_request,
                    initial_credit,
                    on_failover_reset,
                } => {
                    self.drive_query(
                        request_id,
                        encoded_request,
                        initial_credit,
                        on_failover_reset,
                    );
                }
            }
        }
        // Best-effort tear-down. The Reader's Drop closes the WS.
    }

    /// Publish the worker's view of `addr_idx` + `server_version` to
    /// the user side. Called once at startup and again after every
    /// successful failover.
    ///
    /// **Stores with `Release`**, paired with `Acquire` loads in
    /// [`PipelinedReader::current_addr`] and
    /// [`PipelinedReader::server_version`]. The pair establishes a
    /// happens-before edge between the worker's reconnect-completion
    /// (which mutated `Reader::addr_idx` / the negotiated server
    /// version) and the user-thread observation of the published
    /// snapshot. Earlier `Relaxed` stores worked for the initial
    /// connect by accident — the `thread::spawn` capturing the
    /// already-negotiated `Reader` provided an implicit
    /// acquire/release edge that made the values observable before
    /// the worker even ran — but the post-failover case had no
    /// channel-send / receive pair before the next user-thread
    /// `current_addr()` call, so a strictly-Relaxed reader could
    /// observe the pre-failover values.
    fn publish_post_connect_state(&self) -> Result<()> {
        // Both call sites of this function guarantee a live
        // transport: `WorkerState::run` calls it after a synchronous
        // `Reader::from_config` succeeded, and
        // `failover_and_replay` calls it on the success path
        // immediately after a successful `reconnect_with_failover`.
        // So `transport_version()` is not expected to return `Err`
        // here. Earlier revisions encoded that expectation as
        // `.expect(...)`, but under `panic = "abort"` (the
        // `questdb-rs-ffi` cdylib profile) a panic at this site
        // aborts the host process — converting a recoverable
        // worker-internal invariant violation into SIGABRT inside
        // the user's process (Python interpreter, etc.).
        //
        // The current shape returns `Result<()>` so callers route the
        // error through `publish(IoEvent::Error(...))` and
        // `terminate_with_close`, matching every other error path in
        // the worker. The two atomics still update atomically per-
        // call — either both update on the `Ok` arm, or neither
        // updates on the `Err` arm — so the "divergent
        // (current_addr_idx, server_version) pair" concern that
        // motivated the original `.expect()` is preserved by
        // construction.
        let idx = pipelined_internals::addr_idx(&self.reader);
        let v = pipelined_internals::transport_version(&self.reader)?;
        // Publish addr_idx FIRST then server_version. The current
        // accessors (`current_addr` / `server_version` on
        // `PipelinedReader`) load each atomic independently, so as
        // of today this ordering buys no observable guarantee — a
        // user-thread reader could still see "new addr_idx, old
        // server_version" or vice versa from interleaved loads.
        // The ordering exists to make the source-level intent
        // obvious ("server_version atomically reflects the live
        // addr") AND to give a deterministic publication order for
        // any future paired-load accessor (e.g. one that needs the
        // two values to refer to the same negotiated session): such
        // an accessor that loads `server_version` first (Acquire)
        // would, on observing the new value, have the happens-before
        // edge to also see the matching new `addr_idx`. (The
        // original wording of this note oversold the as-of-today
        // guarantee; the current text describes only the property
        // the code actually provides.)
        self.current_addr_idx.store(idx, Ordering::Release);
        self.server_version.store(v as u64, Ordering::Release);
        Ok(())
    }

    /// Drive a single submitted query to its terminal frame, publishing
    /// events as they come off the wire. Returns when a terminal event
    /// has been sent OR when the channel disconnects (user dropped the
    /// receiver).
    fn drive_query(
        &mut self,
        mut request_id: i64,
        mut encoded_request: Bytes,
        initial_credit: u64,
        mut on_failover_reset: Option<PipelinedFailoverResetCallback>,
    ) {
        let credit_enabled = initial_credit > 0;
        // (No `data_delivered` flag here: see the comment at the
        // failover-eligibility branch below — the pipelined
        // surface's event channel makes the sync-surface's
        // duplicate-detection invariant unnecessary.)
        // Write the QUERY_REQUEST. Failure here is treated like a
        // mid-query transport failure — same failover policy applies.
        if let Err(e) =
            pipelined_internals::write_request_bytes(&mut self.reader, encoded_request.clone())
        {
            // The submission write failed before any batch arrived;
            // we can still attempt failover-and-replay.
            if !is_failover_eligible(e.code())
                || !pipelined_internals::failover_enabled(&self.reader)
            {
                let _ = self.publish(IoEvent::Error(e));
                return;
            }
            warn_on_protocol_error_failover(&e, "initial QUERY_REQUEST submission");
            match self.failover_and_replay(
                e,
                &mut request_id,
                &mut encoded_request,
                on_failover_reset.as_mut(),
            ) {
                Ok(()) => {}
                Err(err) => {
                    let _ = self.publish(IoEvent::Error(err));
                    return;
                }
            }
        }
        pipelined_internals::mark_cursor_active(&mut self.reader, true);
        // `cancelling` is sticky across loop iterations once flipped:
        // it gates both the failover-suppression check below and the
        // CREDIT-replenishment suppression on `RESULT_BATCH`, and
        // both of those want the "user has asked to cancel" intent
        // to persist for the rest of the cursor's life. Declaring it
        // inside the loop body used to reset it every iteration,
        // which meant `cancel_in_place` re-fired on every tick after
        // the user called `cancel()` — ~5–30 redundant CANCEL frames
        // per cancel at the 100 ms poll tick, all targeting the same
        // request_id. The sticky flag now fires `cancel_in_place`
        // exactly once on the false→true transition. See H1 in the
        // egress review for the original report.
        //
        // Cross-failover case: if a successful `failover_and_replay`
        // mints a new `request_id` AFTER the user cancelled, the
        // worker exits failover with `cancelling == false` (the
        // failover path itself short-circuits if `cancelling` is
        // already set — see the `if cancelling || ...` branch
        // below) and the next loop iteration re-fires
        // `cancel_in_place` against the new `request_id`. After
        // that single re-fire, sticky takes over again. The user
        // therefore always gets one CANCEL frame per live
        // connection their query was running on, no more.
        //
        // Note: `cancel_in_place` writes the CANCEL frame and
        // nothing else — it deliberately does NOT touch transport
        // timeouts. An earlier revision tightened the read timeout
        // to `CANCEL_DRAIN_READ_TIMEOUT` (30 s) and the write
        // timeout to `CLOSE_TIMEOUT` (~200 ms), both of which were
        // dead code on this path: the next loop iteration sets the
        // read timeout to `READ_POLL_TICK` (100 ms) so the
        // tightened read deadline was clobbered immediately, and
        // with sticky `cancelling` (see the `!cancelling` guard
        // below) there are no more writes between the single
        // CANCEL and the cursor's imminent terminal frame so the
        // tightened write deadline never observed anything.
        let mut cancelling = false;
        // Apply the read-timeout tick ONCE before the in-query loop
        // and re-apply only after a successful failover (which
        // replaces the transport). Earlier revisions set + cleared
        // the timeout on every loop iteration — two `setsockopt`
        // syscalls per frame on the worker's hot read path, both
        // of which were noise: the per-iteration clear at the end
        // was already documented as "harmless [...] but explicit
        // is cheaper to reason about during teardown" (the actual
        // teardown path uses `terminate_with_close` which drops
        // the transport, so the clear was load-bearing nowhere).
        pipelined_internals::set_read_timeout(&mut self.reader, Some(READ_POLL_TICK));
        loop {
            // `Acquire` pairs with `Release` store in
            // `PipelinedReader::close`.
            if self.shutdown.load(Ordering::Acquire) {
                pipelined_internals::mark_cursor_active(&mut self.reader, false);
                let _ = self.publish(IoEvent::Error(fmt!(
                    InvalidApiCall,
                    "PipelinedReader was closed while a cursor was in flight"
                )));
                return;
            }
            // Honour any pending cancel BEFORE the next read so the
            // CANCEL frame goes out promptly even if the server is
            // already streaming back-to-back batches with no read-side
            // pause.
            //
            // Treat any non-sentinel value as "cancel the current
            // cursor" rather than comparing against `request_id`. The
            // user-side `PipelinedCursor` records the request_id it
            // was *executed* with; after a mid-query failover the
            // worker's `request_id` local has been updated to the
            // replayed id (see `failover_and_replay`) while the
            // cursor's stored value still reflects either the initial
            // submission OR the most-recent failover the user
            // observed via `Event::FailoverReset`. An equality check
            // would silently drop a cancel issued before the cursor
            // had consumed the matching `FailoverReset` event — and
            // would always drop a cancel issued from `Drop`, which
            // never consumes events through `dispatch`. The cursor's
            // single-in-flight invariant + the fact that
            // `cancel_slot` is reset to `NO_PENDING_CANCEL` at every
            // `execute()` and at cursor `Drop` means the only path
            // that can write a non-sentinel value during a live
            // query is the matching cursor's own cancel / Drop, so
            // "any positive value" unambiguously names the current
            // cursor. The CANCEL frame itself still carries the
            // worker's up-to-date `request_id` so the server can
            // match it to the live request.
            //
            // Sticky guard: only fire on the false→true edge so we
            // don't spam CANCEL on every poll tick while waiting for
            // the server's terminal.
            // `Acquire` pairs with the `Release` stores in
            // `PipelinedCursor::cancel` / `Drop` / `execute` —
            // `cancel_slot` carries only its own i64 value, no
            // cross-atomic ordering is needed. N7.
            if !cancelling && self.cancel_slot.load(Ordering::Acquire) != NO_PENDING_CANCEL {
                cancelling = true;
                pipelined_internals::cancel_in_place(&mut self.reader, request_id);
            }

            // Read the next frame with a periodic poll so we wake up
            // even when the server is silent. The recv-buffer state
            // survives timeouts so partial frames resume cleanly.
            // The timeout itself is set ONCE before the loop (and
            // re-applied after a successful failover, which
            // replaces the transport) — see the comment at the top
            // of this loop.
            //
            // Time the read for `stats.read_ns` accounting. Matches
            // the sync `Cursor::read_frame_raw` instrumentation
            // shape (`reader.rs::read_frame_raw`) — saturating
            // u64 conversion, `Relaxed` add. **Time every call**,
            // including the periodic poll-tick wakeups: on a busy
            // stream those wakeups never fire (frame arrives well
            // under `READ_POLL_TICK`); on a quiet stream they
            // correctly accumulate as "time spent waiting for data
            // on the wire", which is exactly what the sync side's
            // unbounded-blocking `read_frame` would accumulate.
            // Pre-fix this site had no timing wrapper — every
            // pipelined `read_ns` accessor (Rust, C FFI reader-
            // bound, C FFI detached stats, C++ wrapper) returned 0
            // forever.
            let read_t0 = std::time::Instant::now();
            let read_result = pipelined_internals::read_frame_or_timeout(&mut self.reader);
            self.reader.stats().read_ns.fetch_add(
                u64::try_from(read_t0.elapsed().as_nanos()).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );

            let frame_opt = match read_result {
                Ok(opt) => opt,
                Err(e) => {
                    if cancelling
                        || !pipelined_internals::failover_enabled(&self.reader)
                        || !is_failover_eligible(e.code())
                    {
                        pipelined_internals::terminate_with_close(&mut self.reader);
                        let _ = self.publish(IoEvent::Error(e));
                        return;
                    }
                    // NOTE: the sync surface checks
                    // `would_silently_duplicate(data_delivered,
                    // has_callback)` here and aborts the cursor with
                    // `FailoverWouldDuplicate` when the user has no way
                    // to learn about the failover. That check is
                    // **deliberately omitted** on the pipelined
                    // surface: the worker's success path in
                    // `failover_and_replay` unconditionally publishes
                    // `IoEvent::FailoverReset` on the event channel, so
                    // every pipelined consumer always observes the
                    // replay signal — regardless of whether they
                    // installed an `on_failover_reset` callback.
                    // Silent duplication is impossible on this surface
                    // by construction (see `Event::FailoverReset`
                    // docstring: "the caller MUST discard any
                    // accumulated row state on receiving it").
                    //
                    // Pre-fix this site reused the sync gate verbatim,
                    // which terminated every pipelined cursor that
                    // hit a mid-query failover after the first batch
                    // unless the user happened to also install the
                    // legacy callback — breaking the documented
                    // event-based pattern.
                    warn_on_protocol_error_failover(&e, "mid-query frame read");
                    match self.failover_and_replay(
                        e,
                        &mut request_id,
                        &mut encoded_request,
                        on_failover_reset.as_mut(),
                    ) {
                        Ok(()) => {
                            // Successful failover replaced the
                            // transport — the new one has no read
                            // timeout. Re-apply the tick before
                            // looping back to the next read so we
                            // continue to wake on `shutdown` /
                            // `cancel_slot` polls. An earlier
                            // per-iteration `set_read_timeout` did
                            // this implicitly; we need it explicit
                            // now that the timeout is set once-per-
                            // transport instead of once-per-read.
                            pipelined_internals::set_read_timeout(
                                &mut self.reader,
                                Some(READ_POLL_TICK),
                            );
                            continue;
                        }
                        Err(err) => {
                            let _ = self.publish(IoEvent::Error(err));
                            return;
                        }
                    }
                }
            };
            let (header, payload) = match frame_opt {
                Some(f) => f,
                None => continue, // timeout, just re-loop and re-check cancel/shutdown
            };
            let wire_bytes = HEADER_LEN as u64 + header.payload_length as u64;
            let event = match self.decode_frame_on_worker(header, &payload) {
                Ok(ev) => ev,
                Err(e) => {
                    pipelined_internals::terminate_with_close(&mut self.reader);
                    let _ = self.publish(IoEvent::Error(e));
                    return;
                }
            };
            match event {
                ServerEvent::Batch(b) => {
                    if b.request_id != request_id {
                        let err = fmt!(
                            ProtocolError,
                            "RESULT_BATCH request_id {} != cursor {}",
                            b.request_id,
                            request_id
                        );
                        pipelined_internals::terminate_with_close(&mut self.reader);
                        let _ = self.publish(IoEvent::Error(err));
                        return;
                    }
                    // Replenish CREDIT for the wire bytes we just
                    // consumed — but only if (a) the server is using
                    // credit-based flow control AND (b) the user
                    // hasn't asked us to cancel. Identical policy to
                    // the sync Cursor.
                    if credit_enabled
                        && !cancelling
                        && let Err(e) = pipelined_internals::send_credit_frame(
                            &mut self.reader,
                            request_id,
                            wire_bytes,
                        )
                    {
                        pipelined_internals::terminate_with_close(&mut self.reader);
                        let _ = self.publish(IoEvent::Error(e));
                        return;
                    }
                    let schema_id = b.schema_id;
                    let schema = match pipelined_internals::schema_arc(&self.reader, schema_id) {
                        Some(s) => s,
                        None => {
                            let err = fmt!(
                                ProtocolError,
                                "RESULT_BATCH references schema {} not in registry",
                                schema_id
                            );
                            pipelined_internals::terminate_with_close(&mut self.reader);
                            let _ = self.publish(IoEvent::Error(err));
                            return;
                        }
                    };
                    let dict = pipelined_internals::dict_snapshot(&self.reader);
                    let owned = OwnedBatch::new(b, schema, dict);
                    if !self.publish(IoEvent::Batch(owned)) {
                        // User dropped the receiver or `close()` was
                        // signalled. Tear the connection down so the
                        // server stops streaming for this request.
                        pipelined_internals::terminate_with_close(&mut self.reader);
                        return;
                    }
                }
                ServerEvent::End {
                    request_id: rid,
                    final_seq,
                    total_rows,
                } => {
                    if rid != request_id {
                        let err = fmt!(
                            ProtocolError,
                            "RESULT_END request_id {} != cursor {}",
                            rid,
                            request_id
                        );
                        pipelined_internals::terminate_with_close(&mut self.reader);
                        let _ = self.publish(IoEvent::Error(err));
                        return;
                    }
                    pipelined_internals::mark_cursor_active(&mut self.reader, false);
                    let _ = self.publish(IoEvent::End {
                        request_id: rid,
                        final_seq,
                        total_rows,
                    });
                    return;
                }
                ServerEvent::ExecDone {
                    request_id: rid,
                    op_type,
                    rows_affected,
                } => {
                    if rid != request_id {
                        let err = fmt!(
                            ProtocolError,
                            "EXEC_DONE request_id {} != cursor {}",
                            rid,
                            request_id
                        );
                        pipelined_internals::terminate_with_close(&mut self.reader);
                        let _ = self.publish(IoEvent::Error(err));
                        return;
                    }
                    pipelined_internals::mark_cursor_active(&mut self.reader, false);
                    let _ = self.publish(IoEvent::ExecDone {
                        request_id: rid,
                        op_type,
                        rows_affected,
                    });
                    return;
                }
                ServerEvent::Error {
                    request_id: rid,
                    status,
                    message,
                } => {
                    if rid != request_id {
                        let err = fmt!(
                            ProtocolError,
                            "QUERY_ERROR request_id {} != cursor {}",
                            rid,
                            request_id
                        );
                        pipelined_internals::terminate_with_close(&mut self.reader);
                        let _ = self.publish(IoEvent::Error(err));
                        return;
                    }
                    pipelined_internals::mark_cursor_active(&mut self.reader, false);
                    // Route through `publish` so a `PipelinedReader::close()`
                    // signalled while the channel is full unblocks within
                    // one poll tick — same shutdown contract as every other
                    // terminal-publish site in this loop. Raw `event_tx.send`
                    // here would only unblock on receiver-drop, which the
                    // FFI close-while-cursor-alive path is specifically
                    // documented (via the `publish` wrapper) to NOT rely on.
                    let _ = self.publish(IoEvent::Error(map_server_status(status, message)));
                    return;
                }
                ServerEvent::CacheReset { .. } | ServerEvent::ServerInfo(_) => {
                    // State already mutated by `decode_frame`; keep reading.
                    continue;
                }
            }
        }
    }

    /// Decode wrapper that also accounts for `decode_ns` and
    /// `bytes_received`, mirroring the sync `Cursor`'s accounting.
    fn decode_frame_on_worker(
        &mut self,
        header: crate::egress::wire::header::FrameHeader,
        payload: &Bytes,
    ) -> Result<ServerEvent> {
        let wire_bytes = HEADER_LEN as u64 + header.payload_length as u64;
        self.reader
            .stats()
            .bytes_received
            .fetch_add(wire_bytes, Ordering::Relaxed);
        let t0 = std::time::Instant::now();
        let r = pipelined_internals::decode_frame(&mut self.reader, header, payload);
        let elapsed = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.reader
            .stats()
            .decode_ns
            .fetch_add(elapsed, Ordering::Relaxed);
        r
    }

    /// Publish an event onto the user-facing channel, waking on
    /// [`PUBLISH_POLL_TICK`] cadence to poll `shutdown` (so a
    /// `PipelinedReader::close` signalled while the worker is blocked
    /// on a full channel still completes in bounded time).
    ///
    /// Returns `false` when the publish was abandoned because either
    /// (a) `shutdown` was signalled, or (b) the cursor's `Receiver`
    /// was dropped — both cases mean the caller should stop publishing
    /// for the current query and tear down. Callers treat the boolean
    /// identically to the old `event_tx.send(..).is_err()` semantics.
    ///
    /// The wake tick is [`PUBLISH_POLL_TICK`] (1 ms), **not**
    /// [`READ_POLL_TICK`] (100 ms). The two were unified at 100 ms
    /// in an earlier revision, which capped throughput at
    /// 4 slots / 100 ms = 40 batches/sec under any sustained
    /// producer-faster-than-consumer episode. See `PUBLISH_POLL_TICK`'s
    /// docstring for the full rationale.
    ///
    /// Without this wrapper, the `close()` path could only unblock
    /// the worker's `event_tx.send` by dropping the cursor's
    /// `Receiver` — which `close()` cannot do when a live
    /// `PipelinedCursor` still owns it. The borrow checker prevents
    /// reaching that state through the safe-Rust API (close
    /// requires `&mut self`, the cursor borrows it), but the FFI
    /// launders the borrow to `'static` so the FFI
    /// close-while-cursor-alive path can hit it directly. Wrapping
    /// every send in this helper makes `close()` bounded
    /// regardless of the channel/receiver state.
    fn publish(&self, event: IoEvent) -> bool {
        publish_with_shutdown(&self.event_tx, &self.shutdown, PUBLISH_POLL_TICK, event)
    }

    /// Mid-query failover + replay. Updates `request_id` and
    /// `encoded_request` to reflect the replayed query, publishes
    /// `Event::FailoverReset` to the user, and invokes the
    /// user-supplied callback if any.
    ///
    /// The publish is **unconditional** — both call sites (initial-
    /// submission failover at the top of `drive_query` and mid-stream
    /// failover on a read error) emit the event. The user-side
    /// `PipelinedCursor::request_id` field is updated only by
    /// dispatch of a consumed `FailoverReset` event; suppressing the
    /// event on the initial-submission path used to leave
    /// `cursor.request_id()` permanently stale (it reported the
    /// pre-failover rid while every batch on the channel carried the
    /// post-failover rid).
    fn failover_and_replay(
        &mut self,
        trigger: Error,
        request_id: &mut i64,
        encoded_request: &mut Bytes,
        on_failover_reset: Option<&mut PipelinedFailoverResetCallback>,
    ) -> Result<()> {
        let started = std::time::Instant::now();
        let failed_idx = pipelined_internals::addr_idx(&self.reader);
        let failed_addr = pipelined_internals::addr_at(&self.reader, failed_idx).clone();
        // Snapshot the failing rid before the replay re-allocates
        // `*request_id` below — `FailoverEvent::failed_request_id`
        // surfaces it so callers can correlate pre- and
        // post-failover frames by `(failed, new)` pair.
        let failed_request_id = *request_id;
        // Drive the reconnect through the cancellable wrapper so a
        // user-side `PipelinedReader::close` (shutdown) or
        // `PipelinedCursor::cancel` / `Drop` (cancel_slot) signalled
        // while we're mid-backoff aborts the failover loop in at
        // most one `READ_POLL_TICK` instead of waiting for the full
        // `failover_max_attempts × failover_backoff_max_ms` budget
        // (or forever, with `failover_max_duration_ms=0`). The
        // closure clones the `Arc`s up front so it does not borrow
        // `self` and can coexist with the `&mut self.reader` below.
        let shutdown = Arc::clone(&self.shutdown);
        let cancel_slot = Arc::clone(&self.cancel_slot);
        let attempts = match pipelined_internals::reconnect_with_failover_cancellable(
            &mut self.reader,
            failed_idx,
            READ_POLL_TICK,
            move || check_user_abort_during_failover(&shutdown, &cancel_slot, "backoff"),
        ) {
            Ok(n) => n,
            Err(e) => {
                // State-consistency cleanup matching every other
                // terminal error path in `drive_query` (see all the
                // other `terminate_with_close` + `publish(IoEvent::Error)`
                // sites in the read loop). The transport was already
                // taken by `reconnect_with_failover_cancellable` at the
                // start of its backoff loop (reader.rs:468-470), so the
                // `close_in_place` is a no-op — but
                // `terminate_with_close` ALSO clears
                // `cursor_active`, which is what we'd otherwise need a
                // separate `mark_cursor_active(false)` call for.
                // Calling it here instead makes this arm
                // syntactically identical to every other terminal
                // arm and folds the cursor_active reset into the
                // standard pattern.
                //
                // **Reader recovery semantics after this arm**: the
                // reader's `transport: Option<WsTransport>` is now
                // `None`. The next `execute()` on this reader
                // calls `write_request_bytes` → `transport_mut()?`
                // → `SocketError("transport closed after failed
                // mid-query failover")`. That error is
                // failover-eligible, so the initial-submission
                // failover path at `drive_query`'s top
                // (lines ~1731-1755) catches it and runs
                // `failover_and_replay` to dial a fresh endpoint —
                // self-healing IF failover is still enabled. If the
                // user disabled failover, the next `execute()`
                // returns `SocketError` indefinitely and the user
                // must reconstruct the reader (consistent with the
                // surface's "failover_disabled = no auto-recovery"
                // contract).
                pipelined_internals::terminate_with_close(&mut self.reader);
                // `Cancelled` and the shutdown `InvalidApiCall` are
                // user-initiated and ALWAYS supersede the original
                // transport `trigger` — the user wants the
                // cancellation reason, not the trigger that started
                // the doomed reconnect. `prefer_over_trigger` only
                // covers actionable cluster-level conditions
                // (auth/cert/role/etc.), so the abort codes need
                // their own branch.
                let from_abort =
                    matches!(e.code(), ErrorCode::Cancelled | ErrorCode::InvalidApiCall);
                return Err(if from_abort || prefer_over_trigger(e.code()) {
                    e
                } else {
                    trigger
                });
            }
        };
        // **Post-walk abort poll.**
        // `reconnect_with_failover_cancellable`'s internal
        // `abort_check` only polls `shutdown` / `cancel_slot` around
        // the inter-attempt backoff sleeps — the actual
        // `walk_via_tracker` body (TCP connect + TLS handshake) is
        // uninterruptible. If the user-thread cursor's `Drop`
        // stored `cancel_slot` while the worker was mid-walk and
        // the walk then completed `Ok` (e.g. a fast endpoint
        // accepted on the first attempt), the cancel went
        // unobserved by the inner abort_check. Without this guard
        // the worker would proceed past this point to invoke the
        // user-installed `on_failover_reset` callback — and on the
        // FFI surface that callback is a C trampoline holding a
        // `user_data` pointer into a heap object whose owning
        // `unique_ptr` the C++ destructor has already freed (the
        // cursor's broken-state Drop returned to C, then
        // `~pipelined_cursor()` ran). Result: UAF on `user_data`.
        //
        // Re-polling here gives the cancel a chance to fire AFTER
        // the walk, before any callback or event publish observes
        // freed state. The check mirrors the inner abort_check so
        // the error codes / messages match: `Cancelled` for cursor
        // cancel, `InvalidApiCall` for reader close.
        if let Some(err) =
            check_user_abort_during_failover(&self.shutdown, &self.cancel_slot, "walk")
        {
            pipelined_internals::terminate_with_close(&mut self.reader);
            return Err(err);
        }
        // Allocate a fresh id from the SHARED `next_request_id`
        // counter (not `Reader::alloc_request_id`, which advances
        // an unrelated per-connection `i64` on the Reader). The
        // shared atomic guarantees the replayed query's rid is
        // strictly greater than every rid the user side has handed
        // out so far, so a stale frame for an old rid can never
        // match a new live cursor's rid and get misattributed.
        let new_rid = alloc_request_id_atomic(&self.next_request_id);
        *request_id = new_rid;
        let patched = patch_request_id(std::mem::take(encoded_request), new_rid);
        *encoded_request = patched;
        // **Ordering note:**
        // publish_post_connect_state + the `on_failover_reset`
        // callback + `IoEvent::FailoverReset` ALL fire BEFORE the
        // post-reconnect `write_request_bytes`. Previously the
        // ordering was (write → publish → callback → emit), which
        // left the user thread observing stale `current_addr` /
        // `server_version` AND no `FailoverReset` event whenever
        // the post-reconnect write failed (peer reset mid-handshake-
        // grace, write buffer pressure, intermittent NIC). The
        // worker had committed to the new transport (reader.addr_idx
        // and reader.transport were already updated by the
        // successful reconnect), but the user-visible state lagged.
        //
        // With the new order, "reconnect succeeded" is the
        // observability moment: the user sees `FailoverReset` plus
        // the updated `current_addr` regardless of whether the
        // subsequent write succeeds. A write failure on the new
        // transport surfaces as the next `IoEvent::Error` on the
        // channel — accurately reporting "we failed over, then a
        // subsequent write died on the new endpoint", and the
        // cursor's `dispatch` will have already absorbed the rid
        // rotation via `FailoverReset` so subsequent diagnostics
        // attribute correctly.
        //
        // Publish-then-fail is safer than write-then-publish for
        // the same reason every other failover surface in this
        // codebase favours it: the user side's record of the
        // failover survives a transient post-reconnect failure.
        //
        // If `publish_post_connect_state` fails (worker-internal
        // invariant break — see its docstring), tear the transport
        // down and propagate the error to the caller, matching the
        // pattern every other terminal error path in this function
        // uses.
        if let Err(e) = self.publish_post_connect_state() {
            pipelined_internals::terminate_with_close(&mut self.reader);
            return Err(e);
        }
        let event = FailoverEvent {
            failed_addr,
            new_addr: pipelined_internals::addr_at(
                &self.reader,
                pipelined_internals::addr_idx(&self.reader),
            )
            .clone(),
            new_server_info: pipelined_internals::server_info(&self.reader).cloned(),
            failed_request_id,
            new_request_id: new_rid,
            attempts,
            trigger,
            elapsed: started.elapsed(),
        };
        if let Some(cb) = on_failover_reset {
            // The callback runs on the worker thread. A panic out
            // of it would unwind the worker, `PipelinedReader::Drop`
            // would silently swallow the join (`let _ =
            // worker.join.join();`), and the user thread would only
            // see a generic `SocketError("I/O thread terminated
            // without publishing a final event")` from `take_event*`
            // — the real cause-of-death lost.
            //
            // **Profile caveat.** Catching
            // the unwind here gives the documented clean
            // `Err(InvalidApiCall)` ONLY under the standalone
            // `questdb-rs` build's default `panic = "unwind"`
            // profile. Under the `questdb-rs-ffi` cdylib's
            // `panic = "abort"` profile, `catch_unwind` is a runtime
            // no-op (panics abort at the panic site rather than
            // unwinding), so a panicking user callback aborts the
            // host process (Python interpreter, etc.) before this
            // arm runs — surfacing as SIGABRT to the embedder, not
            // as `InvalidApiCall`. The behaviour matches every
            // other Rust-callback path the FFI surface exposes; the
            // `panic_guard` docstring in `questdb-rs-ffi/src/egress.rs`
            // explains the strategy at length. FFI consumers must
            // therefore audit their `on_failover_reset` callbacks
            // for panic-freedom; standalone Rust consumers get the
            // recovery path documented below.
            //
            // `AssertUnwindSafe` is sound because the panicked
            // callback is consumed and dropped on the failure path
            // — its possibly-poisoned internal state never gets
            // observed again.
            let cb_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cb(&event)));
            if let Err(payload) = cb_result {
                pipelined_internals::terminate_with_close(&mut self.reader);
                let payload_msg = panic_payload_to_string(&payload);
                return Err(fmt!(
                    InvalidApiCall,
                    "user-installed on_failover_reset callback panicked: {}; \
                     cursor terminated (the worker would otherwise have died \
                     with no diagnostic)",
                    payload_msg
                ));
            }
        }
        if !self.publish(IoEvent::FailoverReset(event)) {
            // User dropped the receiver during failover OR `close()`
            // was signalled — tear down.
            pipelined_internals::terminate_with_close(&mut self.reader);
            return Err(fmt!(
                SocketError,
                "user thread dropped the event receiver during failover"
            ));
        }
        // Replay the QUERY_REQUEST on the new transport. Done LAST
        // (after the publish above) so a write failure here does
        // not erase the user-visible record of the failover — see
        // the ordering note above. A write error propagates to
        // `drive_query`, which converts it to `IoEvent::Error` on
        // the next iteration, giving the user the sequence
        // `FailoverReset → Error`.
        pipelined_internals::write_request_bytes(&mut self.reader, encoded_request.clone())?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Poll the user-thread abort signals (`shutdown` and `cancel_slot`)
/// and translate the first set one into the corresponding `Error`.
/// Returns `None` if neither is set.
///
/// Single source of truth for the abort-check logic shared between:
/// * the inner `abort_check` closure passed to
///   `reconnect_with_failover_cancellable` (polled around backoff
///   sleeps); and
/// * the explicit post-walk poll inside `failover_and_replay`
///   (between the cancellable reconnect returning `Ok` and the
///   user-installed `on_failover_reset` callback firing — guards
///   against a UAF on the FFI surface's callback `user_data`).
///
/// `phase` is interpolated into the diagnostic message so the user
/// can tell *where* in the failover sequence the abort was
/// observed; pass `"backoff"` for the inner closure and `"walk"`
/// for the post-walk poll.
fn check_user_abort_during_failover(
    shutdown: &AtomicBool,
    cancel_slot: &AtomicI64,
    phase: &str,
) -> Option<Error> {
    if shutdown.load(Ordering::Acquire) {
        Some(fmt!(
            InvalidApiCall,
            "PipelinedReader was closed during mid-query failover {phase}"
        ))
    } else if cancel_slot.load(Ordering::Acquire) != NO_PENDING_CANCEL {
        Some(fmt!(
            Cancelled,
            "cursor cancelled during mid-query failover {phase}; the \
             reader's transport was taken at the start of the failover \
             loop and not restored — the next `execute()` will trigger \
             a fresh failover dial to recover (provided `failover` is \
             still enabled in the connect string)"
        ))
    } else {
        None
    }
}

/// Allocate a fresh positive `request_id` from a shared atomic
/// counter.
///
/// Mirrors [`crate::egress::reader::Reader::alloc_request_id`]'s
/// wrap-skips-zero-and-negatives semantics: the value handed out is
/// always strictly positive, so the [`NO_PENDING_CANCEL`] sentinel
/// can never collide with a real rid and the server's reserved-zero
/// rule for "no active request" is preserved.
///
/// CAS loop because the counter is shared between the user thread
/// (allocating for `execute()`) and the I/O thread (allocating for
/// `failover_and_replay`'s replay). The lossy `fetch_add` style
/// would skip ids on contention; while skips alone would be
/// harmless (still monotone, still unique), the wrap-around case
/// gets noticeably trickier to get right without the CAS.
///
/// **Invariant — write discipline on `next`.** This function is
/// the ONLY legitimate writer of the shared atomic in production.
/// Its correctness relies on the atomic being initialised to a
/// positive value (the `PipelinedReader::launch` constructor seeds
/// `AtomicI64::new(1)`) and never directly stored to with a
/// non-positive value from anywhere else. Direct stores of `0` or
/// a negative i64 would cause the next allocation to hand that
/// value out as a `request_id` — the server reserves `0` for "no
/// active request" so a `0`-rid query would corrupt session state
/// silently. Tests that pre-load the counter (e.g.
/// `alloc_request_id_atomic_skips_zero_and_negatives_on_wrap`,
/// which loads `i64::MAX` to drive the wrap branch) deliberately
/// violate this contract to exercise the wrap path; they MUST then
/// observe a positive value back from the next allocation. New
/// production write sites against `next_request_id` (none today
/// outside this function) are a contract violation and should
/// route through this function instead.
///
/// Defense-in-depth `cur.max(1)` on the return: if a future caller
/// breaks the invariant above and stores a non-positive value,
/// this clamp turns a wire-protocol violation (server sees
/// rid=0 = "no active request") into a benign rid-skip (the
/// affected allocation hands out `1` instead, and the next CAS
/// advances normally).
fn alloc_request_id_atomic(next: &AtomicI64) -> i64 {
    loop {
        let cur = next.load(Ordering::Acquire);
        let advanced = match cur.checked_add(1) {
            Some(n) if n > 0 => n,
            _ => 1,
        };
        if next
            .compare_exchange_weak(cur, advanced, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            // Defensive clamp — see rationale in the function
            // docstring. The happy path always observes
            // `cur > 0` (invariant preserved by the only production
            // writer, which is this function itself), so the
            // clamp is a no-op there; the test path that pre-loads
            // `i64::MAX` succeeds with `cur == i64::MAX`, which is
            // also > 0 and unaffected.
            return cur.max(1);
        }
    }
}

/// Free helper backing [`WorkerState::publish`]. Sends `event` on
/// `tx`, waking every `poll_tick` to check `shutdown`. Returns
/// `false` if `shutdown` was observed set or the receiver
/// disconnected before the send could complete; `true` on a
/// successful publish. Extracted so the shutdown-wakes-blocked-send
/// invariant can be unit-tested without spinning up a real worker.
///
/// Implementation note: `SyncSender::send_timeout` would be the
/// natural fit but is still unstable (`std_internals` feature), so
/// we drive a `try_send` loop with an explicit `thread::sleep`
/// between attempts when the channel is full. In the steady state
/// (channel has free slots) the first `try_send` returns `Ok` and
/// no sleep is performed; the polling cost is only paid while the
/// worker is actually backpressured by a slow consumer, which is
/// also the only situation in which `close()`-wakes-blocked-send
/// matters.
fn publish_with_shutdown<T>(
    tx: &SyncSender<T>,
    shutdown: &AtomicBool,
    poll_tick: Duration,
    event: T,
) -> bool {
    use std::sync::mpsc::TrySendError;
    let mut event = event;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return false;
        }
        match tx.try_send(event) {
            Ok(()) => return true,
            Err(TrySendError::Full(returned)) => {
                event = returned;
                thread::sleep(poll_tick);
            }
            Err(TrySendError::Disconnected(_)) => return false,
        }
    }
}

/// Crate-local alias for [`crate::eprintln_lossy`] — the canonical
/// implementation now lives at the workspace root of `questdb-rs`
/// (`src/lib.rs`) so the FFI crate can call it directly via the
/// existing `questdb-rs` dependency, without keeping a second copy
/// in lockstep. (The earlier "structural pin" claim was incorrect
/// — two tests in two crates cannot link against each other, so
/// deleting one copy could not fail the other's test build.)
fn eprintln_lossy(args: std::fmt::Arguments<'_>) {
    crate::eprintln_lossy(args)
}

/// Bounded drain backing [`PipelinedCursor`]'s `Drop` cancel path.
/// Polls `rx.recv_timeout` against a wall-clock deadline derived from
/// `budget`; discards non-terminal events; returns `true` if the
/// budget expired before a terminal arrived, `false` otherwise
/// (terminal observed OR channel disconnected — both indicate
/// "nothing more is coming").
///
/// Extracted as a free function so the wall-clock-budget invariant
/// can be unit-tested with a short timeout without waiting the full
/// production [`CANCEL_DRAIN_BUDGET`]. The Drop path passes the
/// production budget; tests pass milliseconds.
fn drain_to_terminal(rx: &Receiver<IoEvent>, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return true;
        }
        match rx.recv_timeout(remaining) {
            Ok(IoEvent::End { .. }) | Ok(IoEvent::ExecDone { .. }) | Ok(IoEvent::Error(_)) => {
                return false;
            }
            // Discard non-terminal events (batches, failover-reset);
            // the cursor is being abandoned, the user doesn't want them.
            Ok(_) => continue,
            Err(RecvTimeoutError::Timeout) => return true,
            // Worker exited or panicked without publishing a terminal.
            // Equivalent to "drained" for Drop's purposes — nothing more
            // is coming on this channel.
            Err(RecvTimeoutError::Disconnected) => return false,
        }
    }
}

/// Extract a human-readable message from a `Box<dyn Any + Send>`
/// panic payload — the value returned in the `Err` arm of
/// `std::panic::catch_unwind`. Rust panic payloads are typed as
/// `&'static str` (from `panic!("…")` with a string literal) or
/// `String` (from `panic!("{}", …)` formatting); other types fall
/// through to a generic placeholder so the diagnostic stays
/// readable even when the user panicked with a custom type. Keeps
/// the call site at `failover_and_replay` to a single line.
fn panic_payload_to_string(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

/// Patch the 8-byte `request_id` span of a stashed `QUERY_REQUEST`
/// payload. Same fast/slow path as `reader::patch_request_id`.
fn patch_request_id(buf: Bytes, new_rid: i64) -> Bytes {
    let mut buf_mut = match buf.try_into_mut() {
        Ok(b) => b,
        Err(shared) => bytes::BytesMut::from(&shared[..]),
    };
    buf_mut[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8].copy_from_slice(&new_rid.to_le_bytes());
    buf_mut.freeze()
}

// `FailoverEvent` is the only shared sub-type that callers might
// need to pattern-match on, and `crate::egress::mod` already
// re-exports it at the top-level public surface. The previous
// `pub use FailoverEvent as PipelinedFailoverEvent` alias had
// zero consumers — drop rather than maintain a redundant name.

// Compile-time check that PipelinedReader is Send.
#[allow(dead_code)]
fn _assert_pipelined_reader_send() {
    fn is_send<T: Send>() {}
    is_send::<PipelinedReader>();
    is_send::<PipelinedCursor<'_>>();
    is_send::<Event>();
    is_send::<OwnedBatch>();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an `Arc<ReaderConfig>` for the synthetic `PipelinedReader`
    /// fixtures. The config must be a real parsed one (not a
    /// hand-constructed empty struct) because `PipelinedReader::cfg`
    /// is now `Arc<ReaderConfig>` (previous fixtures stashed
    /// `Arc::new(Vec::new())` for an `Arc<Vec<Endpoint>>` field
    /// that no longer exists). Any well-formed connect string
    /// works; the tests below never actually `current_addr()`
    /// against it.
    fn test_cfg() -> Arc<crate::egress::config::ReaderConfig> {
        Arc::new(
            crate::egress::config::ReaderConfig::from_conf("ws::addr=h:1;")
                .expect("synthetic test config must parse"),
        )
    }

    /// Regression for the per-row column-view cache:
    /// `OwnedBatch::column` MUST be `O(1)` and
    /// allocation-free on every call after the first per column.
    /// Without the cache the per-row C-FFI getters in
    /// `egress_pipelined.rs` re-build the `ColumnView` (and re-resolve
    /// the `SymbolDict` reborrow for `Symbol` columns) on every call;
    /// at "millions of rows × dozens of columns" production scale
    /// that's ~30M wasted match cascades per batch. This test pins
    /// the no-allocation invariant via the in-tree counting allocator
    /// (`questdb-rs/src/lib.rs::alloc_counter`).
    ///
    /// Run with: `cargo test --features sync-reader-ws -- \
    ///   owned_batch_column_zero_alloc --ignored --test-threads=1`
    #[test]
    #[ignore = "requires single-threaded execution: --test-threads=1"]
    fn owned_batch_column_zero_alloc_on_warm_cache() {
        use crate::alloc_counter;
        use crate::egress::decoder::{ColumnBuffer, DecodedBatch, DecodedColumn};
        use crate::egress::schema::Schema;

        // 4 Long columns × 100 rows. We never read the values; only
        // the projection cost matters. 800 B per `values` Bytes is
        // plenty to make a hypothetical-deep-clone cache regression
        // show up in the allocation count.
        let row_count = 100usize;
        let col_count = 4usize;
        let make_column = || {
            DecodedColumn::Long(ColumnBuffer {
                values: Bytes::from(vec![0u8; row_count * 8]),
                validity: None,
            })
        };
        let decoded = DecodedBatch {
            request_id: 1,
            batch_seq: 0,
            schema_id: 0,
            row_count,
            columns: (0..col_count).map(|_| make_column()).collect(),
            flags: 0,
        };
        let schema = Arc::new(Schema::new());
        let dict = Arc::new(SymbolDict::new());
        let batch = OwnedBatch::new(decoded, schema, dict);

        // Warmup: populate the cache slot for every column.
        for idx in 0..col_count {
            let _ = batch.column(idx).unwrap();
        }

        // Now every `column(idx)` MUST hit the cache and allocate
        // nothing. 1000 × 4 = 4000 calls; a pre-cache regression
        // (or a cache that re-allocates the ColumnView wrapper)
        // would show up as 4000 allocations here.
        alloc_counter::start_counting();
        for _ in 0..1000 {
            for idx in 0..col_count {
                let view = batch.column(idx).unwrap();
                // `black_box` so the optimiser cannot elide the
                // lookup even though we discard the value.
                std::hint::black_box(view);
            }
        }
        let allocs = alloc_counter::stop_counting();
        assert_eq!(
            allocs, 0,
            "warmed OwnedBatch::column must be allocation-free; \
             observed {} allocs over 4000 calls",
            allocs,
        );
    }

    /// Companion to the zero-alloc test: confirms the cache returns
    /// a `ColumnView` whose data matches the underlying decoded
    /// column on consecutive calls. A broken lifetime launder in
    /// `OwnedBatch::column` (e.g. transmuting a temporary view that
    /// borrows from a dropped stack frame) would surface here as
    /// undefined behaviour — at minimum a debug-assertion failure,
    /// often a crash under MIRI.
    #[test]
    fn owned_batch_column_cache_returns_consistent_view() {
        use crate::egress::decoder::{ColumnBuffer, DecodedBatch, DecodedColumn};
        use crate::egress::schema::Schema;

        let row_count = 8usize;
        // Distinct sentinel byte per row so a corrupted view is loud.
        let mut values = Vec::with_capacity(row_count * 8);
        for i in 0..row_count {
            values.extend_from_slice(&(i as i64 * 7 + 3).to_le_bytes());
        }
        let decoded = DecodedBatch {
            request_id: 1,
            batch_seq: 0,
            schema_id: 0,
            row_count,
            columns: vec![DecodedColumn::Long(ColumnBuffer {
                values: Bytes::from(values),
                validity: None,
            })],
            flags: 0,
        };
        let batch = OwnedBatch::new(
            decoded,
            Arc::new(Schema::new()),
            Arc::new(SymbolDict::new()),
        );

        // First call: populates cache. Second + third: cache hits.
        for call in 0..3 {
            let view = batch.column(0).expect("column 0 must exist");
            let col = match view {
                ColumnView::Long(c) => c,
                other => panic!("expected Long, got {:?} on call {}", other.kind(), call),
            };
            for row in 0..row_count {
                let want = row as i64 * 7 + 3;
                assert_eq!(
                    col.value(row),
                    want,
                    "row {} corrupted on call {}",
                    row,
                    call,
                );
            }
        }
    }

    /// Regression for H8: the atomic allocator must skip zero and
    /// negatives on wrap (same invariant as the `&mut i64`
    /// variant), and must hand out strictly monotone positive ids
    /// in the steady state. Both properties are what makes the
    /// shared user / worker counter safe — without monotonicity,
    /// a worker-side failover replay could collide with a
    /// subsequent user-side `execute()`; without the wrap skip,
    /// the `NO_PENDING_CANCEL = -1` sentinel could collide with a
    /// real rid.
    #[test]
    fn alloc_request_id_atomic_skips_zero_and_negatives_on_wrap() {
        let next = AtomicI64::new(1);
        for expected in 1..=3i64 {
            assert_eq!(alloc_request_id_atomic(&next), expected);
        }
        // Pre-load to `i64::MAX` so `checked_add(1)` returns `None`
        // and the wrap branch is exercised. Must hand out
        // `i64::MAX` then reset to 1.
        next.store(i64::MAX, Ordering::Release);
        assert_eq!(alloc_request_id_atomic(&next), i64::MAX);
        assert_eq!(
            next.load(Ordering::Acquire),
            1,
            "wrap must reset to 1, never 0 or negative"
        );
        assert_eq!(alloc_request_id_atomic(&next), 1);
    }

    /// Regression for concurrent-allocation soundness:
    /// `alloc_request_id_atomic` MUST hand out unique ids under
    /// concurrent contention from multiple threads — the CAS-loop
    /// is the only thing standing between a user-thread `execute()`
    /// and a worker-thread `failover_and_replay` re-allocation.
    ///
    /// **Why CAS, not `fetch_add`:** the allocator atomically
    /// combines an increment with a "skip 0 and negatives on wrap"
    /// clamp. A naive `fetch_add` would advance to `i64::MIN` then
    /// `0` on overflow; even with a follow-up `.max(1)` clamp on
    /// the consumer side, two concurrent allocators near the wrap
    /// could both observe a pre-clamp value and both end up
    /// handing out `1` — colliding on a fresh post-wrap id. The
    /// CAS variant resolves the increment-and-clamp as a single
    /// atomic transition, so the two threads see strictly
    /// different post-clamp values.
    ///
    /// Wrap collision itself is unavoidable on ANY fixed-width
    /// counter — this test does NOT claim to verify behaviour
    /// across the `i64::MAX` boundary. Counter starts at `1` and
    /// 8 × 100k = 800k allocations stay deep in the non-wrapping
    /// window. The companion test
    /// [`alloc_request_id_atomic_skips_zero_and_negatives_on_wrap`]
    /// pins the wrap-skip behaviour separately.
    ///
    /// 8 threads × 100k allocations against a shared counter, all
    /// ids collected into a `HashSet`, assert `len() == 800_000`.
    /// Completes in well under a second on a modern machine.
    #[test]
    fn alloc_request_id_atomic_no_collisions_under_contention() {
        use std::collections::HashSet;
        const THREADS: usize = 8;
        const PER_THREAD: usize = 100_000;
        let counter = Arc::new(AtomicI64::new(1));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    let mut ids = Vec::with_capacity(PER_THREAD);
                    for _ in 0..PER_THREAD {
                        ids.push(alloc_request_id_atomic(&counter));
                    }
                    ids
                })
            })
            .collect();
        let mut all = HashSet::with_capacity(THREADS * PER_THREAD);
        for h in handles {
            for id in h.join().unwrap() {
                assert!(
                    id > 0,
                    "allocator must only hand out positive ids; observed {id}",
                );
                let inserted = all.insert(id);
                assert!(inserted, "collision on id {id}");
            }
        }
        assert_eq!(
            all.len(),
            THREADS * PER_THREAD,
            "{} threads × {} allocations must produce {} unique ids",
            THREADS,
            PER_THREAD,
            THREADS * PER_THREAD,
        );
    }

    /// Regression: `OwnedBatch::column`
    /// MUST surface OOB column indices as `InvalidApiCall` with a
    /// diagnostic naming both the requested index and the actual
    /// column count. The C-FFI per-row getters all delegate to this
    /// (`b.column(col_idx)` in every `_batch_get_*`), so without
    /// this pin a regression would surface only as a corrupted
    /// error envelope at the FFI boundary that no FFI test
    /// currently exercises.
    #[test]
    fn owned_batch_column_oob_returns_invalid_api_call() {
        use crate::egress::decoder::{ColumnBuffer, DecodedBatch, DecodedColumn};
        use crate::egress::schema::Schema;
        let decoded = DecodedBatch {
            request_id: 1,
            batch_seq: 0,
            schema_id: 0,
            row_count: 4,
            columns: vec![DecodedColumn::Long(ColumnBuffer {
                values: Bytes::from(vec![0u8; 32]),
                validity: None,
            })],
            flags: 0,
        };
        let batch = OwnedBatch::new(
            decoded,
            Arc::new(Schema::new()),
            Arc::new(SymbolDict::new()),
        );
        match batch.column(99) {
            Ok(_) => panic!("OOB column index must not succeed"),
            Err(e) => {
                assert!(
                    matches!(e.code(), ErrorCode::InvalidApiCall),
                    "OOB must surface as InvalidApiCall; got {:?}",
                    e.code(),
                );
                let msg = e.msg();
                assert!(
                    msg.contains("99"),
                    "diagnostic must name the OOB index; got {msg:?}",
                );
                assert!(
                    msg.contains("column_count=1") || msg.contains("(column_count=1)"),
                    "diagnostic must name the actual column_count; got {msg:?}",
                );
            }
        }
        // In-range still works (sanity).
        assert!(batch.column(0).is_ok(), "in-range column must succeed");
    }

    /// `patch_request_id` mutates the 8-byte span at
    /// [`REQUEST_ID_OFFSET`..+8] in little-endian, preserving every
    /// other byte exactly. Without this guarantee, the failover-replay
    /// path would silently corrupt either the message kind byte (byte
    /// 0) or the rest of the encoded payload (varints / binds) on
    /// every reconnect.
    #[test]
    fn patch_request_id_overwrites_only_the_id_span() {
        let mut buf = vec![0xCDu8; REQUEST_ID_OFFSET + 8 + 16];
        buf[0] = MsgKind::QueryRequest.as_u8();
        // Sentinel value at the id span so we can confirm it gets overwritten.
        buf[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]
            .copy_from_slice(&0x1122_3344_5566_7788i64.to_le_bytes());
        let patched = patch_request_id(Bytes::from(buf.clone()), 0x0102_0304_0506_0708);
        assert_eq!(patched[0], MsgKind::QueryRequest.as_u8());
        assert_eq!(
            i64::from_le_bytes(
                patched[REQUEST_ID_OFFSET..REQUEST_ID_OFFSET + 8]
                    .try_into()
                    .unwrap()
            ),
            0x0102_0304_0506_0708
        );
        // Bytes outside the id span are untouched. The QUERY_REQUEST
        // layout places the request_id immediately after the 1-byte
        // MsgKind, so `REQUEST_ID_OFFSET == 1` today and the
        // "[1..REQUEST_ID_OFFSET)" prefix is currently empty — guard
        // against the layout shifting (a future revision could insert
        // a version byte etc.) without clippy nagging about an empty
        // loop.
        //
        // Pin the current offset value at compile time. If a
        // future protocol revision shifts
        // `REQUEST_ID_OFFSET` away from `1`, this `const _` assert
        // fires at build time — that's the signal to revisit the
        // prefix-preservation logic (the loop below would then
        // actually run, and the `#[allow]` becomes load-bearing
        // instead of cosmetic).
        const _: () = assert!(
            REQUEST_ID_OFFSET == 1,
            "QUERY_REQUEST layout invariant broke: REQUEST_ID_OFFSET is no longer 1; \
             the [1..REQUEST_ID_OFFSET) loop below now runs and the prefix-preservation \
             logic needs revisiting."
        );
        #[allow(clippy::reversed_empty_ranges)]
        for i in 1..REQUEST_ID_OFFSET {
            assert_eq!(patched[i], 0xCD, "byte {} mutated outside id span", i);
        }
        for i in REQUEST_ID_OFFSET + 8..patched.len() {
            assert_eq!(patched[i], 0xCD, "byte {} mutated outside id span", i);
        }
    }

    /// The `NO_PENDING_CANCEL` sentinel must be negative so it cannot
    /// collide with a real `request_id` (the allocator skips zero and
    /// negatives, so positive values are the only legal request_ids).
    #[test]
    fn no_pending_cancel_sentinel_is_negative() {
        const { assert!(NO_PENDING_CANCEL < 0) };
    }

    /// Regression: `publish_with_shutdown` MUST wake from a blocked
    /// `send` on a full channel within ~one poll tick of `shutdown`
    /// being flipped. Before this was wrapped, `close()` could
    /// deadlock the worker join in the FFI close-while-cursor-alive
    /// path — the worker held its own `event_tx` clone and the
    /// cursor still owned the `Receiver`, so dropping just the
    /// user-side template did not disconnect the channel.
    #[test]
    fn publish_with_shutdown_wakes_blocked_send() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<u32>(1);
        // Fill the single-slot channel so the next send blocks.
        tx.send(0).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let tx_thread = tx.clone();
        let shutdown_thread = Arc::clone(&shutdown);
        // Spawn a publisher that will block on the full channel and
        // measure how long it takes to bail after `shutdown` flips.
        let started = std::time::Instant::now();
        let handle = thread::spawn(move || {
            let ok = publish_with_shutdown(
                &tx_thread,
                &shutdown_thread,
                Duration::from_millis(20),
                1u32,
            );
            (ok, started.elapsed())
        });
        // Give the publisher a beat to enter the blocked send, then
        // signal shutdown.
        thread::sleep(Duration::from_millis(50));
        shutdown.store(true, Ordering::Release);
        let (ok, elapsed) = handle.join().unwrap();
        assert!(!ok, "publish must return false when shutdown is signalled");
        assert!(
            elapsed < Duration::from_millis(500),
            "publish must bail within a few poll ticks; took {:?}",
            elapsed
        );
        // Receiver still has the prefilled value; the would-be publish
        // never landed.
        assert_eq!(rx.try_recv().unwrap(), 0);
        assert!(rx.try_recv().is_err());
    }

    /// Disconnected-receiver path of the same helper: returns `false`
    /// promptly without waiting on the poll tick.
    #[test]
    fn publish_with_shutdown_returns_false_on_receiver_drop() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<u32>(1);
        drop(rx);
        let shutdown = AtomicBool::new(false);
        let ok = publish_with_shutdown(&tx, &shutdown, Duration::from_secs(60), 7);
        assert!(!ok, "publish must return false when receiver is gone");
    }

    /// Regression: `publish_with_shutdown`
    /// MUST wake from a blocked `try_send` within ~one poll tick after
    /// the receiver drains a slot — NOT one full tick of waste sitting
    /// in `thread::sleep` while the channel has free space. With the
    /// pre-fix shared 100ms tick this method capped throughput under
    /// any sustained backpressure at 4 slots / 100 ms = 40 batches/sec.
    /// With the dedicated [`PUBLISH_POLL_TICK`] (1 ms) the wake-up
    /// latency is ~100× better.
    ///
    /// This test exercises the helper with the SAME 1ms tick the
    /// production `WorkerState::publish` passes. Pre-fix the same
    /// call shape (with `READ_POLL_TICK = 100ms`) would have produced
    /// an `elapsed` of ~120ms; post-fix it should be ~10-30ms.
    #[test]
    fn publish_with_shutdown_wakes_within_poll_tick_after_drain() {
        let (tx, rx) = std::sync::mpsc::sync_channel::<u32>(1);
        // Fill the single-slot channel so the next publish blocks.
        tx.send(0).unwrap();
        let shutdown = Arc::new(AtomicBool::new(false));
        let tx_thread = tx.clone();
        let shutdown_thread = Arc::clone(&shutdown);
        let started = std::time::Instant::now();
        let handle = thread::spawn(move || {
            // Pass the production publish tick exactly.
            let ok = publish_with_shutdown(&tx_thread, &shutdown_thread, PUBLISH_POLL_TICK, 42u32);
            (ok, started.elapsed())
        });
        // Give the publisher a beat to enter the blocked `try_send` /
        // `sleep` loop, then drain a slot so it can wake and publish.
        thread::sleep(Duration::from_millis(20));
        assert_eq!(rx.recv().unwrap(), 0);
        let (ok, elapsed) = handle.join().unwrap();
        assert!(ok, "publish must succeed after receiver drained a slot");
        // Receiver got the publisher's value.
        assert_eq!(rx.recv().unwrap(), 42);
        // Pre-fix: ~120ms minimum (initial sleep + 100ms tick before next try_send).
        // Post-fix: ~20-30ms (initial sleep + 1ms tick before next try_send).
        // 80ms threshold is comfortably above the post-fix expectation and
        // well below the pre-fix bound, so a regression would fail loudly.
        assert!(
            elapsed < Duration::from_millis(80),
            "publisher took {:?} to wake after drain; expected < 80ms under \
             PUBLISH_POLL_TICK = {:?} (pre-M1 shared 100ms tick would have \
             produced ~120ms)",
            elapsed,
            PUBLISH_POLL_TICK,
        );
    }

    /// Regression: `PipelinedCursor::drop`
    /// MUST bound its drain wait via [`CANCEL_DRAIN_BUDGET`] so a
    /// stuck server (compute thread wedged, one-way-alive socket
    /// where writes succeed but no reads arrive) cannot block the
    /// dropping thread indefinitely. The pre-fix `rx.recv()` was
    /// unbounded — and the FFI close-while-cursor-alive path
    /// actively *prevents* external rescue (leak-on-active branch
    /// in `_close`), so the bound MUST come from inside Drop itself.
    ///
    /// This test exercises the helper directly with a 50ms budget
    /// against a channel that never receives a terminal; expects
    /// `true` (timed out) within ~one budget plus epsilon.
    #[test]
    fn drain_to_terminal_bounds_wait_on_silent_worker() {
        let (tx, rx) = sync_channel::<IoEvent>(1);
        let started = std::time::Instant::now();
        let timed_out = drain_to_terminal(&rx, Duration::from_millis(50));
        let elapsed = started.elapsed();
        assert!(
            timed_out,
            "expected drain to time out when worker never publishes"
        );
        assert!(
            elapsed >= Duration::from_millis(50),
            "drain returned before budget expired: {:?}",
            elapsed,
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "drain blocked far past budget: {:?}",
            elapsed,
        );
        // Suppress unused-tx warning; the channel stays open
        // throughout the drain so we exercise the timeout path
        // (not the disconnect path tested separately below).
        drop(tx);
    }

    /// Companion to the regression above: when a terminal IS
    /// available, the helper returns `false` (not timed out) within
    /// microseconds, well under any production budget.
    #[test]
    fn drain_to_terminal_returns_promptly_on_terminal_event() {
        let (tx, rx) = sync_channel::<IoEvent>(1);
        tx.send(IoEvent::End {
            request_id: 1,
            final_seq: 0,
            total_rows: 0,
        })
        .unwrap();
        let started = std::time::Instant::now();
        let timed_out = drain_to_terminal(&rx, Duration::from_secs(60));
        let elapsed = started.elapsed();
        assert!(
            !timed_out,
            "expected clean drain when a terminal is already buffered"
        );
        assert!(
            elapsed < Duration::from_millis(100),
            "terminal observation took {:?}, expected sub-millisecond",
            elapsed,
        );
    }

    /// Disconnected-channel path of the same helper: returns `false`
    /// (treated as "drained — nothing more is coming") within
    /// microseconds, NOT a timeout. The Drop path relies on this
    /// distinction: a disconnected channel means the worker has
    /// exited cleanly, so there's no need to nuke the event_rx;
    /// the happy-path return-to-worker still runs.
    #[test]
    fn drain_to_terminal_returns_promptly_on_disconnect() {
        let (tx, rx) = sync_channel::<IoEvent>(1);
        drop(tx);
        let started = std::time::Instant::now();
        let timed_out = drain_to_terminal(&rx, Duration::from_secs(60));
        let elapsed = started.elapsed();
        assert!(
            !timed_out,
            "expected disconnected channel to be treated as drained"
        );
        assert!(
            elapsed < Duration::from_millis(100),
            "disconnect observation took {:?}, expected sub-millisecond",
            elapsed,
        );
    }

    /// Regression for H2: once `take_event` has seen a channel
    /// disconnect (worker thread exited without publishing a
    /// terminal), the cursor MUST flip its `done` flag in the same
    /// step so the next call returns `Err(InvalidApiCall)` as the
    /// docstring promises. Pre-fix the second call kept hitting the
    /// channel and returned an identical `SocketError`, so callers
    /// looping on `take_event` until `InvalidApiCall` would spin
    /// forever on the disconnected channel.
    #[test]
    fn take_event_marks_terminal_on_channel_disconnect() {
        // Build a synthetic PipelinedReader / PipelinedCursor pair
        // backed by an mpsc channel we control. Spawning a no-op
        // worker thread keeps `WorkerHandle::join` valid for the
        // reader's eventual Drop without exercising the live worker.
        let (cmd_tx, _cmd_rx) = sync_channel::<IoCommand>(1);
        let (event_tx, event_rx) = sync_channel::<IoEvent>(1);
        let join = thread::spawn(|| {});
        let mut reader = PipelinedReader {
            worker: Some(WorkerHandle {
                join,
                cmd_tx,
                event_rx: None,
            }),
            stats: Arc::new(ReaderStats::default()),
            cancel_slot: Arc::new(AtomicI64::new(NO_PENDING_CANCEL)),
            shutdown: Arc::new(AtomicBool::new(false)),
            current_addr_idx: Arc::new(AtomicUsize::new(0)),
            cfg: test_cfg(),
            server_version: Arc::new(AtomicU64::new(0)),
            cursor_active: true,
            next_request_id: Arc::new(AtomicI64::new(1)),
        };
        let mut cursor = PipelinedCursor {
            reader: &mut reader,
            request_id: 1,
            event_rx: Some(event_rx),
            done: false,
            cancelling: false,
            terminal: None,
            broken_state: false,
        };
        // Disconnect from the sending side so the cursor's `recv`
        // returns the Disconnected variant.
        drop(event_tx);

        // First call: transport-level diagnostic.
        match cursor.take_event() {
            Err(e) if matches!(e.code(), ErrorCode::SocketError) => {}
            other => panic!("expected SocketError on disconnect, got {other:?}"),
        }
        // Second call: the documented terminal short-circuit. Pre-fix
        // this returned another SocketError because `done` was never
        // flipped.
        match cursor.take_event() {
            Err(e) if matches!(e.code(), ErrorCode::InvalidApiCall) => {}
            other => panic!("expected InvalidApiCall after terminal, got {other:?}"),
        }
        // Same contract for the non-blocking and bounded variants
        // routed through the same helper.
        match cursor.try_take_event() {
            Err(e) if matches!(e.code(), ErrorCode::InvalidApiCall) => {}
            other => panic!("expected InvalidApiCall from try_take_event, got {other:?}"),
        }
        match cursor.take_event_timeout(Duration::from_millis(1)) {
            Err(e) if matches!(e.code(), ErrorCode::InvalidApiCall) => {}
            other => panic!("expected InvalidApiCall from take_event_timeout, got {other:?}"),
        }
    }

    /// Regression for M2: when `cmd_tx.send` fails because the
    /// worker has exited, `PipelinedQuery::execute` MUST put the
    /// `event_rx` it took back on `WorkerHandle::event_rx`. Pre-fix,
    /// the rx was dropped on the error path and the next call would
    /// surface `InvalidApiCall("event channel is closed")` instead
    /// of the real `SocketError("worker exited")` — misleading
    /// callers into thinking the channel was the failure when in
    /// fact the channel was just orphaned by the previous send
    /// failure.
    #[test]
    fn execute_restores_event_rx_when_worker_send_fails() {
        // Build a synthetic reader whose cmd channel's receiver is
        // already dropped, so any `cmd_tx.send(...)` returns
        // Disconnected immediately. Mirrors a worker thread that has
        // exited between the prior `_query_execute` and this one.
        let (cmd_tx, cmd_rx) = sync_channel::<IoCommand>(1);
        drop(cmd_rx); // simulate dead worker — sends will fail
        let (_event_tx, event_rx) = sync_channel::<IoEvent>(4);
        let join = thread::spawn(|| {});
        let mut reader = PipelinedReader {
            worker: Some(WorkerHandle {
                join,
                cmd_tx,
                // The rx the user-side handle holds before any
                // `execute()` ran, exactly as `launch()` would have
                // left it.
                event_rx: Some(event_rx),
            }),
            stats: Arc::new(ReaderStats::default()),
            cancel_slot: Arc::new(AtomicI64::new(NO_PENDING_CANCEL)),
            shutdown: Arc::new(AtomicBool::new(false)),
            current_addr_idx: Arc::new(AtomicUsize::new(0)),
            cfg: test_cfg(),
            server_version: Arc::new(AtomicU64::new(0)),
            cursor_active: false,
            next_request_id: Arc::new(AtomicI64::new(1)),
        };

        // First execute: send fails (worker is dead). Must surface
        // SocketError AND restore the event_rx.
        match reader.prepare("SELECT 1").execute() {
            Ok(_) => panic!("execute must fail when worker is dead"),
            Err(e) => assert!(
                matches!(e.code(), ErrorCode::SocketError),
                "first execute should report worker-exit as SocketError, got code={:?} msg={:?}",
                e.code(),
                e.msg(),
            ),
        }
        assert!(
            reader.worker.as_ref().unwrap().event_rx.is_some(),
            "event_rx must be restored on cmd_tx.send failure (M2)",
        );

        // Second execute: also fails for the SAME reason (worker is
        // still dead). Pre-fix, the rx was orphaned by the first
        // failure and this would have surfaced
        // InvalidApiCall("event channel is closed"), hiding the real
        // cause.
        match reader.prepare("SELECT 2").execute() {
            Ok(_) => panic!("execute must keep failing while the worker is dead"),
            Err(e) => assert!(
                matches!(e.code(), ErrorCode::SocketError),
                "second execute must keep reporting SocketError, got code={:?} msg={:?}",
                e.code(),
                e.msg(),
            ),
        }

        // Tear-down: clear the worker handle without dropping the
        // PipelinedReader's `Drop` path, which would otherwise call
        // `close()` and try to `join` on the (already-finished)
        // no-op thread, harmless but noisy.
        reader.worker = None;
    }

    /// Inline synthetic-cursor scaffolding for the cancel-wind-down
    /// regression tests below. Mirrors the fixture used by
    /// `take_event_marks_terminal_on_channel_disconnect`; pasted
    /// inline (vs. extracted to a helper) because `PipelinedCursor`
    /// borrows from `PipelinedReader` and the borrow's lifetime
    /// cannot cross a function boundary cleanly.
    macro_rules! cancel_test_fixture {
        ($reader:ident, $cursor:ident, $event_tx:ident) => {
            let (cmd_tx, _cmd_rx) = sync_channel::<IoCommand>(1);
            let ($event_tx, event_rx) = sync_channel::<IoEvent>(4);
            let join = thread::spawn(|| {});
            let mut $reader = PipelinedReader {
                worker: Some(WorkerHandle {
                    join,
                    cmd_tx,
                    event_rx: None,
                }),
                stats: Arc::new(ReaderStats::default()),
                cancel_slot: Arc::new(AtomicI64::new(NO_PENDING_CANCEL)),
                shutdown: Arc::new(AtomicBool::new(false)),
                current_addr_idx: Arc::new(AtomicUsize::new(0)),
                cfg: test_cfg(),
                server_version: Arc::new(AtomicU64::new(0)),
                cursor_active: true,
                next_request_id: Arc::new(AtomicI64::new(1)),
            };
            let mut $cursor = PipelinedCursor {
                reader: &mut $reader,
                request_id: 1,
                event_rx: Some(event_rx),
                done: false,
                cancelling: false,
                terminal: None,
                broken_state: false,
            };
        };
    }

    /// Regression: `PipelinedCursor::cancel`
    /// MUST return `Ok(())` when the cursor winds down via a
    /// transport `SocketError` (the server closed the socket in
    /// response to our CANCEL frame instead of sending a clean
    /// terminal — semantically the same outcome as a clean cancel).
    /// Pre-fix the user got `Err(SocketError)` from a successful
    /// cancel and could not distinguish it from an unrelated
    /// transport failure.
    #[test]
    fn cancel_returns_ok_on_socket_error_from_worker() {
        cancel_test_fixture!(reader, cursor, event_tx);
        // Worker publishes a SocketError in response to the cancel
        // (simulating: cancel frame went out, server closed the
        // socket, worker's next read returned `SocketError`, worker
        // surfaced it as `IoEvent::Error`).
        event_tx
            .send(IoEvent::Error(fmt!(
                SocketError,
                "connection reset by peer"
            )))
            .unwrap();
        match cursor.cancel() {
            Ok(()) => {}
            Err(e) => panic!(
                "cancel must return Ok on SocketError wind-down; got Err(code={:?}, msg={:?})",
                e.code(),
                e.msg()
            ),
        }
        // Tear-down per the convention used by the adjacent tests:
        // clear the worker handle so `PipelinedReader::Drop` doesn't
        // try to join the synthetic no-op thread.
        drop(cursor);
        reader.worker = None;
    }

    /// Companion to the SocketError test: `cancel` MUST also return
    /// `Ok(())` when the worker thread itself exited mid-drain
    /// (`finalize_on_channel_disconnect` returns
    /// `Err(InvalidApiCall("I/O thread terminated without
    /// publishing a final event"))`). The user asked to cancel; the
    /// cursor is no longer running; that's success.
    #[test]
    fn cancel_returns_ok_on_invalid_api_call_from_worker_exit() {
        cancel_test_fixture!(reader, cursor, event_tx);
        // Disconnect the sending side without publishing a terminal —
        // simulates the worker panicking or exiting after the cancel
        // was set. `take_event` then routes through
        // `finalize_on_channel_disconnect` and returns InvalidApiCall.
        drop(event_tx);
        match cursor.cancel() {
            Ok(()) => {}
            Err(e) => panic!(
                "cancel must return Ok on InvalidApiCall wind-down; got Err(code={:?}, msg={:?})",
                e.code(),
                e.msg()
            ),
        }
        drop(cursor);
        reader.worker = None;
    }

    /// Negative: `cancel` MUST still propagate `Err(_)` for codes
    /// that don't indicate "cancellation wound the cursor down" —
    /// e.g. a `ProtocolError` from a corrupted frame is a real
    /// upstream bug the user wants to see, NOT silently swallowed
    /// into Ok by the cancel path's permissiveness. Without this
    /// pin a future widening of the cancel-success classification
    /// (e.g. to cover all `Err(_)`) would turn the cancel into a
    /// silent success on any failure mode.
    #[test]
    fn cancel_propagates_protocol_error() {
        cancel_test_fixture!(reader, cursor, event_tx);
        event_tx
            .send(IoEvent::Error(fmt!(ProtocolError, "decoder saw garbage")))
            .unwrap();
        match cursor.cancel() {
            Err(e) if matches!(e.code(), ErrorCode::ProtocolError) => {}
            other => panic!(
                "cancel must propagate ProtocolError; got {:?}",
                match other {
                    Ok(()) => "Ok(())",
                    Err(_) => "Err(non-ProtocolError)",
                },
            ),
        }
        drop(cursor);
        reader.worker = None;
    }

    /// Regression: `cancel()` MUST bound its drain wait via
    /// [`CANCEL_DRAIN_BUDGET`] so a wedged server (worker reads
    /// returning `Ok(None)` forever) cannot deadlock the
    /// user-coordination thread that called `cancel()`. Pre-fix
    /// the loop called `take_event()` (unbounded `rx.recv()`) and
    /// would hang forever on a silent worker. This test exercises
    /// the private `cancel_with_budget` helper with a 50ms budget
    /// against an event channel that never publishes a terminal;
    /// expects timeout-error return within ~one budget + epsilon,
    /// the cursor marked terminal (`done = true`), and the event
    /// receiver dropped (so a subsequent `Drop` skips its own
    /// drain and the worker's next publish unblocks via
    /// `Disconnected`).
    #[test]
    fn cancel_returns_timeout_err_when_worker_never_publishes() {
        cancel_test_fixture!(reader, cursor, event_tx);
        let started = std::time::Instant::now();
        let result = cursor.cancel_with_budget(Duration::from_millis(50));
        let elapsed = started.elapsed();
        match result {
            Err(e) if matches!(e.code(), ErrorCode::SocketError) => {
                let msg = e.msg();
                assert!(
                    msg.contains("worker did not publish a terminal frame"),
                    "expected wedged-worker timeout diagnostic; got {msg:?}",
                );
            }
            other => panic!(
                "expected Err(SocketError) on cancel timeout; got {:?}",
                other
                    .map(|()| "Ok(())")
                    .map_err(|e| (e.code(), e.msg().to_string())),
            ),
        }
        assert!(
            elapsed >= Duration::from_millis(50),
            "cancel returned before budget expired: {elapsed:?}",
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "cancel blocked far past budget: {elapsed:?}",
        );
        assert!(
            cursor.terminal().is_none(),
            "terminal() should still be None — no terminal event was observed",
        );
        // Cursor MUST be marked `done` so subsequent `take_event`
        // short-circuits and `Drop` skips its drain attempt.
        match cursor.take_event() {
            Err(e) if matches!(e.code(), ErrorCode::InvalidApiCall) => {}
            other => panic!(
                "expected InvalidApiCall on take_event after cancel timeout (done flag must be set); \
                 got {other:?}"
            ),
        }
        // Suppress unused-tx warning; the channel stayed open
        // throughout the cancel to force the timeout path.
        drop(event_tx);
        drop(cursor);
        reader.worker = None;
    }

    /// Regression: a `PipelinedCursor` MUST handle an
    /// `IoEvent::FailoverReset`
    /// followed by more batches cleanly — the user-thread `dispatch`
    /// path updates `request_id` from the event and returns
    /// `Ok(Event::FailoverReset(...))`. Pre-fix, the worker-side
    /// `would_silently_duplicate` gate would have terminated the
    /// cursor with `FailoverWouldDuplicate` before any
    /// `IoEvent::FailoverReset` could be published — but that gate
    /// only test-covered the user-thread `dispatch` side here, not
    /// the worker-side gate. The actual bug fix removes the gate
    /// from `WorkerState::drive_query`; the worker change is
    /// integration-tested via the live-server / mock-server harness.
    /// This test pins the user-thread side: when an
    /// `IoEvent::FailoverReset` IS published, the cursor's
    /// `request_id` rotates and the cursor continues (not done,
    /// not errored).
    #[test]
    fn cursor_handles_failover_reset_then_continues() {
        cancel_test_fixture!(reader, cursor, event_tx);
        // Publish a FailoverReset event with a known new rid, then a
        // terminal so the test concludes cleanly without panicking
        // the test runtime via a wedged cursor.
        let new_rid = 4242i64;
        event_tx
            .send(IoEvent::FailoverReset(FailoverEvent {
                failed_addr: crate::egress::Endpoint::new("h", 1),
                new_addr: crate::egress::Endpoint::new("h", 2),
                new_server_info: None,
                failed_request_id: 1,
                new_request_id: new_rid,
                attempts: 1,
                trigger: fmt!(SocketError, "simulated mid-query failure"),
                elapsed: Duration::from_millis(0),
            }))
            .unwrap();
        event_tx
            .send(IoEvent::End {
                request_id: new_rid,
                final_seq: 0,
                total_rows: 0,
            })
            .unwrap();

        // First take: FailoverReset → cursor.request_id rotates,
        // cursor is NOT done, no error.
        match cursor.take_event() {
            Ok(Event::FailoverReset(ev)) => {
                assert_eq!(ev.new_request_id, new_rid, "event must carry new rid");
                // Pin the `failed_request_id` field added by this
                // PR: it MUST carry the pre-failover rid so users
                // can correlate `(failed, new)` pairs across the
                // failover boundary. Without this assertion the
                // field is set in production code but no test
                // would observe it.
                assert_eq!(
                    ev.failed_request_id, 1,
                    "event must carry the pre-failover rid",
                );
            }
            other => panic!("expected FailoverReset, got {other:?}"),
        }
        assert_eq!(
            cursor.request_id(),
            new_rid,
            "cursor.request_id() must update to the new rid after consuming FailoverReset"
        );
        assert!(
            cursor.terminal().is_none(),
            "FailoverReset must not mark the cursor terminal",
        );

        // Second take: End → cursor is done.
        match cursor.take_event() {
            Ok(Event::End { request_id, .. }) => {
                assert_eq!(request_id, new_rid);
            }
            other => panic!("expected End, got {other:?}"),
        }
        assert!(
            cursor.terminal().is_some(),
            "End must mark the cursor terminal"
        );

        drop(cursor);
        reader.worker = None;
    }

    /// Regression for M6: the worker's panic-catching diagnostic
    /// formatter must surface the most common payload types
    /// (`&'static str` from `panic!("…")` with a literal, `String`
    /// from formatted panics) so the `InvalidApiCall` error the
    /// user sees from `take_event*` names the real cause. Without
    /// this, the diagnostic would degrade to a generic placeholder
    /// even when Rust handed us a perfectly serialisable message.
    #[test]
    fn panic_payload_to_string_extracts_common_payload_types() {
        // `&'static str` payload — from `panic!("literal")`.
        let str_payload =
            std::panic::catch_unwind(|| panic!("literal payload")).expect_err("panic must Err");
        assert_eq!(panic_payload_to_string(&str_payload), "literal payload");

        // `String` payload — from `panic!("{}", …)` formatting.
        let string_payload = std::panic::catch_unwind(|| {
            panic!("formatted {}/{}", 42, "stuff");
        })
        .expect_err("panic must Err");
        assert_eq!(
            panic_payload_to_string(&string_payload),
            "formatted 42/stuff",
        );

        // Unknown payload type — fall through to a placeholder
        // rather than misformat a custom panic type.
        let unknown_payload = std::panic::catch_unwind(|| {
            std::panic::panic_any(123u32);
        })
        .expect_err("panic must Err");
        assert_eq!(
            panic_payload_to_string(&unknown_payload),
            "<non-string panic payload>",
        );
    }

    /// Companion to the doc rewrite on
    /// [`PipelinedFailoverResetCallback`]: a `Box<dyn FnMut + Send>`
    /// that panics MUST be safely catchable via `catch_unwind` so
    /// the worker can surface an `InvalidApiCall` instead of dying
    /// silently. Pins the shape used at the `failover_and_replay`
    /// call site so a future signature refactor that breaks
    /// `AssertUnwindSafe` compatibility fails this test before it
    /// silently regresses the diagnostic path.
    #[test]
    fn failover_reset_callback_panic_is_catchable() {
        let event = FailoverEvent {
            failed_addr: crate::egress::Endpoint::new("h", 1),
            new_addr: crate::egress::Endpoint::new("h", 1),
            new_server_info: None,
            failed_request_id: 7,
            new_request_id: 8,
            attempts: 1,
            trigger: fmt!(SocketError, "trigger"),
            elapsed: Duration::from_millis(0),
        };
        let mut cb: PipelinedFailoverResetCallback = Box::new(|_ev: &FailoverEvent| {
            panic!("callback exploded");
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| cb(&event)));
        let payload = result.expect_err("callback panic must Err");
        assert_eq!(panic_payload_to_string(&payload), "callback exploded");
    }

    /// Regression: the post-walk abort
    /// poll in `failover_and_replay` MUST observe a cursor cancel
    /// signalled while the worker was inside an uninterruptible
    /// `walk_via_tracker`. Without that poll, a fast endpoint accept
    /// after the user-thread cursor's broken-state Drop returned
    /// would let the worker invoke the user-installed
    /// `on_failover_reset` callback — and on the FFI surface that
    /// callback's `user_data` is a `unique_ptr<failover_callback>`
    /// the C++ destructor has already freed (UAF).
    ///
    /// This unit-tests the predicate the post-walk site relies on
    /// (the same predicate the inner backoff `abort_check` uses): a
    /// non-`NO_PENDING_CANCEL` `cancel_slot` MUST translate to
    /// `Err(Cancelled)`, and a set `shutdown` MUST translate to
    /// `Err(InvalidApiCall)`. A future refactor that loosens the
    /// predicate (e.g. checks only `shutdown`, or only fires on a
    /// value matching the current request_id) would break this test
    /// before silently re-introducing the UAF.
    #[test]
    fn check_user_abort_during_failover_translates_signals() {
        let shutdown = AtomicBool::new(false);
        let cancel_slot = AtomicI64::new(NO_PENDING_CANCEL);

        // Neither signal set — no abort.
        assert!(
            check_user_abort_during_failover(&shutdown, &cancel_slot, "walk").is_none(),
            "no signals set must yield None",
        );

        // Cancel signalled — must yield `Cancelled`.
        cancel_slot.store(42, Ordering::Release);
        let err = check_user_abort_during_failover(&shutdown, &cancel_slot, "walk")
            .expect("cancel_slot set must yield Some");
        assert_eq!(err.code(), ErrorCode::Cancelled);
        assert!(
            err.msg().contains("walk"),
            "phase string must appear in the diagnostic; got: {}",
            err.msg(),
        );

        // Reset cancel; signal shutdown — must yield `InvalidApiCall`
        // (and shutdown takes precedence over cancel if both are
        // set, matching the inner closure's `if / else if` order).
        cancel_slot.store(NO_PENDING_CANCEL, Ordering::Release);
        shutdown.store(true, Ordering::Release);
        let err = check_user_abort_during_failover(&shutdown, &cancel_slot, "backoff")
            .expect("shutdown set must yield Some");
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg().contains("backoff"),
            "phase string must appear in the diagnostic; got: {}",
            err.msg(),
        );

        // Both signals set — shutdown wins (consistency with the
        // backoff abort_check ordering; both arms are equally
        // user-initiated, so the discriminating reason matters less
        // than the deterministic choice).
        cancel_slot.store(7, Ordering::Release);
        let err = check_user_abort_during_failover(&shutdown, &cancel_slot, "walk")
            .expect("both set must yield Some");
        assert_eq!(
            err.code(),
            ErrorCode::InvalidApiCall,
            "shutdown precedence: both signals set must still yield InvalidApiCall, not Cancelled",
        );
    }

    /// Smoke test for the local `eprintln_lossy` shim. The canonical
    /// implementation lives at the `questdb-rs` crate root; this
    /// module's `eprintln_lossy` is a thin alias. The test confirms
    /// the alias accepts `format_args!` and returns `()` without
    /// panicking — it does NOT (and cannot from outside the
    /// platform's stderr-write internals) verify the "swallows
    /// stderr write failures" property; that is covered by the
    /// canonical function's own docstring + manual review.
    #[test]
    fn eprintln_lossy_accepts_format_args() {
        eprintln_lossy(format_args!(
            "smoke test for eprintln_lossy alias (val={})",
            42
        ));
    }
}
