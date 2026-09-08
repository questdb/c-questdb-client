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

//! Owning counterparts to [`ReaderQuery`] and [`Cursor`].
//!
//! [`Cursor<'r>`] borrows `&'r mut Reader`, which is the right shape for
//! ordinary Rust code and the wrong shape for anything that must *own* its
//! result stream: a C ABI has nowhere to put a lifetime, and ADBC's
//! `Statement::execute` must return `Box<dyn RecordBatchReader + Send +
//! 'static>`. Without an owning handle those consumers reach for a
//! self-referential struct built out of `transmute` and `ManuallyDrop` —
//! a construction whose failure mode is undefined behaviour rather than a
//! test failure.
//!
//! [`OwnedCursor`] removes the need. It holds the connection instead of
//! borrowing it, so it is a plain `'static` value that can be moved into a
//! struct, boxed as a trait object, or handed across FFI.
//!
//! **There is no second protocol implementation here.** Both handles drive
//! the same crate-internal `CursorState`: submission goes through
//! `CursorState::submit`, advancing goes through
//! `CursorState::next_batch_step`, and teardown goes through
//! `CursorState::drop_cleanup` — the identical body `Drop for Cursor`
//! runs. This module is ownership plumbing and nothing else.
//!
//! [`ReaderQuery`]: crate::egress::ReaderQuery
//! [`Cursor`]: crate::egress::Cursor
//! [`Cursor<'r>`]: crate::egress::Cursor

// `Borrow` is not imported: it is a supertrait of `BorrowMut`, so
// `.borrow()` resolves through the `O: BorrowMut<Reader>` bound.
use std::borrow::BorrowMut;
use std::net::Ipv4Addr;

use crate::egress::column::ColumnView;
use crate::egress::query_request::{QueryRequest, QueryRequestBuilder};
use crate::egress::reader::{
    CursorState, FailoverProgressEvent, FailoverResetEvent, NextOutcome, Reader, Terminal,
};
use crate::egress::schema::Schema;
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::{Bind, Endpoint, ServerInfo, SimpleNullKind};
use crate::error::{Result, fmt};

/// Owning counterpart of `reader::FailoverResetCallback<'r>`. `'static`
/// rather than `'r`: an [`OwnedQuery`] borrows nothing, so a callback that
/// borrowed from the caller's stack would reintroduce exactly the lifetime
/// an owning handle exists to avoid. FFI trampolines and `move` closures
/// over owned state both satisfy it.
type OwnedResetCallback = Box<dyn FnMut(&FailoverResetEvent) + Send + 'static>;

/// Owning counterpart of `reader::FailoverProgressCallback<'r>`. See
/// [`OwnedResetCallback`] for why this is `'static`.
type OwnedProgressCallback = Box<dyn FnMut(&FailoverProgressEvent) + Send + 'static>;

/// `CursorState`'s hook parameter shape, restated here because the aliases
/// in `reader` are module-private. Erasing `Send` is deliberate and matches
/// `Cursor::split`: the bound is enforced where the callback is *stored*,
/// not where it is called.
type ResetHook<'cb> = dyn FnMut(&FailoverResetEvent) + 'cb;
type ProgressHook<'cb> = dyn FnMut(&FailoverProgressEvent) + 'cb;

#[cfg(feature = "arrow-egress")]
use crate::egress::arrow::{external_arrow_error, has_tentative_array};

/// A query being built against an owned connection.
///
/// The owning counterpart of [`ReaderQuery`](crate::egress::ReaderQuery).
/// Generic over the owner `O` so a caller holding a bare [`Reader`] and a
/// caller holding a pooled `OwnedReader` get the same API — `Reader`
/// satisfies `BorrowMut<Reader>` through the standard library's reflexive
/// blanket impl.
#[must_use = "OwnedQuery does nothing until you call .execute(); dropping it discards \
              the prepared SQL and any binds without sending a QUERY_REQUEST, and \
              returns the owned connection"]
pub struct OwnedQuery<O: BorrowMut<Reader>> {
    owner: O,
    builder: QueryRequestBuilder,
    /// Request a query-scoped SYMBOL dict reset; translated to a
    /// `query_flags` trailer by `CursorState::submit` iff the server
    /// advertised `CAP_QUERY_FLAGS`. Same semantics as
    /// [`ReaderQuery::reset_symbol_dict`](crate::egress::ReaderQuery::reset_symbol_dict).
    reset_symbol_dict: bool,
    /// Mirrors `ReaderQuery::on_failover_reset`, `'static` instead of `'r`.
    on_failover_reset: Option<OwnedResetCallback>,
    /// Mirrors `ReaderQuery::on_failover_progress`, `'static` instead of `'r`.
    on_failover_progress: Option<OwnedProgressCallback>,
}

/// Forward one typed bind to the shared [`QueryRequestBuilder`], the same
/// single implementation `ReaderQuery`'s `bind_method!` forwards to. These
/// exist rather than leaving callers to build [`Bind`] values by hand
/// because some of them are *not* plain wrappers — `bind_uuid` reverses the
/// caller's canonical RFC-4122 bytes into QWP wire order, and a caller
/// reaching for `Bind::Uuid` directly would silently emit a byte-swapped
/// UUID.
macro_rules! owned_bind_method {
    ($(#[$meta:meta])* $name:ident, $($arg:ident : $ty:ty),*) => {
        $(#[$meta])*
        pub fn $name(mut self, $($arg : $ty),*) -> Self {
            self.builder = self.builder.$name($($arg),*);
            self
        }
    };
}

/// [`OwnedQuery`] over a reader checked out of a
/// [`QuestDb`](crate::QuestDb) pool.
#[cfg(feature = "sync-sender-qwp-ws")]
pub type PooledQuery = OwnedQuery<crate::OwnedReader>;

/// [`OwnedCursor`] over a reader checked out of a
/// [`QuestDb`](crate::QuestDb) pool. This is the `'static`, `Send` result
/// stream an FFI or ADBC consumer hands out.
#[cfg(feature = "sync-sender-qwp-ws")]
pub type PooledCursor = OwnedCursor<crate::OwnedReader>;

impl<O: BorrowMut<Reader>> OwnedQuery<O> {
    /// Begin a query that will own `owner` for the life of its cursor.
    pub(crate) fn new<S: Into<String>>(owner: O, sql: S) -> Self {
        Self {
            owner,
            builder: QueryRequest::builder(sql),
            reset_symbol_dict: false,
            on_failover_reset: None,
            on_failover_progress: None,
        }
    }

    /// Append one bind value, in placeholder order.
    pub fn bind(mut self, value: Bind) -> Self {
        self.builder = self.builder.bind(value);
        self
    }

    owned_bind_method!(bind_null, kind: SimpleNullKind);
    owned_bind_method!(bind_bool, v: bool);
    owned_bind_method!(bind_i8, v: i8);
    owned_bind_method!(bind_i16, v: i16);
    owned_bind_method!(bind_i32, v: i32);
    owned_bind_method!(bind_i64, v: i64);
    owned_bind_method!(bind_f32, v: f32);
    owned_bind_method!(bind_f64, v: f64);
    owned_bind_method!(bind_timestamp_micros, v: i64);
    owned_bind_method!(bind_timestamp_nanos, v: i64);
    owned_bind_method!(bind_date_millis, v: i64);
    owned_bind_method!(
        /// Bind a UUID as 16 bytes in canonical RFC-4122 big-endian order,
        /// which is what `uuid::Uuid::as_bytes()` returns.
        bind_uuid,
        v: [u8; 16]
    );
    owned_bind_method!(
        /// Bind a LONG256 as 32 raw little-endian bytes: four 64-bit limbs,
        /// least-significant limb first.
        bind_long256,
        v: [u8; 32]
    );
    owned_bind_method!(bind_char, v: u16);
    owned_bind_method!(bind_ipv4, v: Ipv4Addr);
    owned_bind_method!(bind_decimal64, value: i64, scale: i8);
    owned_bind_method!(bind_decimal128, value: i128, scale: i8);
    owned_bind_method!(bind_decimal256, bytes: [u8; 32], scale: i8);
    owned_bind_method!(bind_geohash, value: u64, precision_bits: u8);
    owned_bind_method!(bind_null_varchar,);
    owned_bind_method!(bind_null_binary,);
    owned_bind_method!(bind_null_decimal64, scale: i8);
    owned_bind_method!(bind_null_decimal128, scale: i8);
    owned_bind_method!(bind_null_decimal256, scale: i8);
    owned_bind_method!(bind_null_geohash, precision_bits: u8);

    /// Bind a UTF-8 VARCHAR. The bytes are copied.
    pub fn bind_varchar<S: Into<String>>(mut self, v: S) -> Self {
        self.builder = self.builder.bind_varchar(v);
        self
    }

    /// Bind a BINARY value. The bytes are copied.
    pub fn bind_binary<B: Into<Vec<u8>>>(mut self, v: B) -> Self {
        self.builder = self.builder.bind_binary(v);
        self
    }

    /// Install a failover-reset callback — the owning counterpart of
    /// [`ReaderQuery::on_failover_reset`], with the identical contract
    /// (installing it is the caller's opt-in to handling replay after rows
    /// have already been delivered; without it a post-delivery transport
    /// failure surfaces [`FailoverWouldDuplicate`] instead of silently
    /// replaying). Calling it twice replaces the previous closure.
    ///
    /// The `'static` bound is the only difference from the borrowing
    /// handle: an [`OwnedCursor`] outlives every stack frame, so a callback
    /// borrowing from one would be unsound. Capture by `move`.
    ///
    /// [`ReaderQuery::on_failover_reset`]: crate::egress::ReaderQuery::on_failover_reset
    /// [`FailoverWouldDuplicate`]: crate::ErrorCode::FailoverWouldDuplicate
    pub fn on_failover_reset<F>(mut self, callback: F) -> Self
    where
        F: FnMut(&FailoverResetEvent) + Send + 'static,
    {
        self.on_failover_reset = Some(Box::new(callback));
        self
    }

    /// Install a failover-progress callback — the owning counterpart of
    /// [`ReaderQuery::on_failover_progress`], with the identical contract:
    /// observational only, and it does **not** authorize replay after
    /// delivery. Calling it twice replaces the previous closure. See
    /// [`Self::on_failover_reset`] for why the bound is `'static`.
    ///
    /// [`ReaderQuery::on_failover_progress`]: crate::egress::ReaderQuery::on_failover_progress
    pub fn on_failover_progress<F>(mut self, callback: F) -> Self
    where
        F: FnMut(&FailoverProgressEvent) + Send + 'static,
    {
        self.on_failover_progress = Some(Box::new(callback));
        self
    }

    /// Override the `initial_credit` (bytes; `0` = unbounded).
    pub fn initial_credit(mut self, credit: u64) -> Self {
        self.builder = self.builder.initial_credit(credit);
        self
    }

    /// Request a query-scoped SYMBOL dict: the server resets the connection
    /// dict before streaming this query so it never inherits symbols from
    /// earlier queries on the same connection. Silently no-op against a
    /// server that does not advertise `CAP_QUERY_FLAGS`.
    pub fn reset_symbol_dict(mut self, reset: bool) -> Self {
        self.reset_symbol_dict = reset;
        self
    }

    /// Hand the connection back without submitting anything.
    pub fn into_owner(self) -> O {
        self.owner
    }

    /// Send the `QUERY_REQUEST`, moving the connection into the returned
    /// cursor.
    ///
    /// On failure the connection is *not* returned to the caller: the
    /// `OwnedQuery` is consumed, so `owner` drops here — which for a pooled
    /// reader releases the slot, and for a bare `Reader` closes it. Take a
    /// clone of anything you need from the connection before calling, or
    /// use [`Self::try_execute`] to get the connection back.
    pub fn execute(self) -> Result<OwnedCursor<O>> {
        self.try_execute().map_err(|(err, _owner)| err)
    }

    /// [`Self::execute`], but hands the connection back on failure instead
    /// of dropping it.
    ///
    /// A failed submit does not necessarily kill the connection — a
    /// rejected bind or an encode error never reaches the wire — so a
    /// caller that manages the connection's lifetime itself (a C ABI handle
    /// the user still holds, a pool slot with its own return path) must be
    /// able to keep it. `execute()` discarding the owner is the right
    /// default for the fluent path, but it is a policy, not a constraint,
    /// and it cannot be the only option.
    ///
    /// Whether the returned connection is still *usable* depends on the
    /// error: check [`Reader::transport_torn_down`] before reusing it.
    #[allow(clippy::result_large_err)]
    pub fn try_execute(self) -> std::result::Result<OwnedCursor<O>, (crate::Error, O)> {
        let OwnedQuery {
            mut owner,
            builder,
            reset_symbol_dict,
            on_failover_reset,
            on_failover_progress,
        } = self;
        let state = match CursorState::submit(owner.borrow_mut(), builder, reset_symbol_dict) {
            Ok(state) => state,
            Err(err) => return Err((err, owner)),
        };
        Ok(OwnedCursor {
            owner: Some(owner),
            state,
            on_failover_reset,
            on_failover_progress,
        })
    }
}

/// A result stream that owns its connection.
///
/// The owning counterpart of [`Cursor`](crate::egress::Cursor). Because it
/// owns the connection rather than borrowing it, it can be moved into a
/// struct, boxed as a trait object, or returned across an FFI boundary —
/// none of which a lifetime-bound cursor permits. It is `Send` whenever `O`
/// is, so `OwnedCursor<OwnedReader>` ([`PooledCursor`]) satisfies the
/// `Send + 'static` bound an ADBC `RecordBatchReader` must meet.
///
/// Dropping mid-stream runs exactly the teardown
/// [`Cursor`](crate::egress::Cursor) runs — best-effort `CANCEL` then close
/// — so an abandoned query never leaves frames in flight for the next user
/// of the connection. For a pooled owner that torn-down transport is what
/// makes the pool retire the reader instead of recycling it.
#[must_use = "OwnedCursor must be drained via next_batch(); dropping it mid-stream \
              sends a best-effort CANCEL and closes the WebSocket, retiring the \
              connection it owns"]
pub struct OwnedCursor<O: BorrowMut<Reader>> {
    /// `Some` for the whole normal life of the cursor; `None` only after
    /// [`Self::into_owner`] has moved the connection out. An `Option` (not
    /// a bare `O`) because `OwnedCursor` implements [`Drop`], and a type
    /// with a `Drop` impl cannot be destructured to move a field out. The
    /// alternative — `ManuallyDrop` plus a `read` — is exactly the
    /// unsafe-code pattern this type exists to spare its callers.
    owner: Option<O>,
    state: CursorState,
    /// Moved across from the [`OwnedQuery`] at `execute()`, exactly as
    /// `Cursor` moves its `'r`-bound pair across from `ReaderQuery`.
    on_failover_reset: Option<OwnedResetCallback>,
    on_failover_progress: Option<OwnedProgressCallback>,
}

/// The owned connection, reached through a borrow of just the `owner`
/// field so the caller can hold `&mut self.state` at the same time —
/// `self.reader()` as an inherent method would borrow the whole cursor and
/// none of the forwarders below would compile.
///
/// The `expect` is unreachable: `owner` is only vacated by
/// [`OwnedCursor::into_owner`], which consumes `self`.
fn reader_of<O: BorrowMut<Reader>>(owner: &mut Option<O>) -> &mut Reader {
    owner
        .as_mut()
        .expect("OwnedCursor used after into_owner")
        .borrow_mut()
}

impl<O: BorrowMut<Reader>> OwnedCursor<O> {
    /// Disjoint reborrow of the four fields, with the callbacks erased to
    /// `&mut dyn FnMut` for [`CursorState`]. The verbatim shape of
    /// `Cursor::split`, and load-bearing for the same reason: the compiler
    /// sees a whole-`self` borrow at `self.state.f(reader_of(&mut
    /// self.owner), ..)` once the callee also wants `&mut self.on_*`.
    #[allow(clippy::type_complexity)]
    fn split(
        &mut self,
    ) -> (
        &mut Reader,
        &mut CursorState,
        Option<&mut ResetHook<'_>>,
        Option<&mut ProgressHook<'_>>,
    ) {
        let OwnedCursor {
            owner,
            state,
            on_failover_reset,
            on_failover_progress,
        } = self;
        (
            reader_of(owner),
            state,
            on_failover_reset
                .as_mut()
                .map(|cb| cb as &mut ResetHook<'_>),
            on_failover_progress
                .as_mut()
                .map(|cb| cb as &mut ProgressHook<'_>),
        )
    }

    /// Shared read-only view of the owned connection. `BorrowMut<Reader>`
    /// implies `Borrow<Reader>`, so the `&self` accessors need no `&mut`.
    fn reader_ref(&self) -> &Reader {
        self.owner
            .as_ref()
            .expect("OwnedCursor used after into_owner")
            .borrow()
    }

    /// Advance the stream by one batch. `Ok(true)` when a batch has been
    /// decoded, `Ok(false)` at end of stream (after which
    /// [`Self::terminal`] is `Some` on the success paths). A `QUERY_ERROR`,
    /// an exhausted failover budget, or a decode failure surfaces as `Err`
    /// — and is re-raised on every subsequent call, so a retry loop cannot
    /// mistake a failed stream for a clean one.
    ///
    /// Mid-query failover behaves exactly as on [`Cursor::next_batch`]:
    /// transparent before the first batch, and after one has been yielded
    /// only if [`OwnedQuery::on_failover_reset`] was installed —
    /// otherwise
    /// [`FailoverWouldDuplicate`](crate::ErrorCode::FailoverWouldDuplicate)
    /// rather than a silent replay from `batch_seq=0`.
    ///
    /// [`Cursor::next_batch`]: crate::egress::Cursor::next_batch
    pub fn next_batch(&mut self) -> Result<bool> {
        let (reader, state, on_reset, on_progress) = self.split();
        match state.next_batch_step(reader, on_reset, on_progress)? {
            NextOutcome::HaveBatch => Ok(true),
            NextOutcome::Done => Ok(false),
        }
    }

    /// `Some` after a `RESULT_END` or `EXEC_DONE` has been observed.
    pub fn terminal(&self) -> Option<&Terminal> {
        self.state.terminal()
    }

    /// The `request_id` this cursor's query was submitted under. Changes
    /// after a mid-query failover replay.
    pub fn request_id(&self) -> i64 {
        self.state.request_id()
    }

    /// Whether the owned connection is still usable for another query.
    /// `false` while the stream is live and after a teardown.
    pub fn connection_reusable(&self) -> bool {
        self.state.connection_reusable(self.reader_ref())
    }

    /// Connection-level total of CREDIT bytes granted on this connection.
    pub fn credit_granted_total(&self) -> u64 {
        self.state.credit_granted_total(self.reader_ref())
    }

    /// Number of successful mid-query failover reconnects since
    /// `execute()`.
    pub fn failover_resets(&self) -> u32 {
        self.state.failover_resets()
    }

    /// Number of transparent same-connection re-issues after the server's
    /// transient stale-cached-plan error. `0` on the happy path.
    pub fn stale_plan_retries(&self) -> u32 {
        self.state.stale_plan_retries()
    }

    /// The endpoint the owned connection is currently bound to. Reflects
    /// the new endpoint after a mid-query failover.
    pub fn current_addr(&self) -> &Endpoint {
        self.state.current_addr(self.reader_ref())
    }

    /// Negotiated QWP version of the owned connection.
    pub fn server_version(&self) -> Result<u8> {
        self.state.server_version(self.reader_ref())
    }

    /// `SERVER_INFO` of the currently connected endpoint.
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.state.server_info(self.reader_ref())
    }

    /// Send a `CANCEL` frame and drain until the server's terminal.
    pub fn cancel(&mut self) -> Result<()> {
        let (reader, state, on_reset, on_progress) = self.split();
        state.cancel(reader, on_reset, on_progress)
    }

    /// Grant the server `additional_bytes` of read budget on this request.
    pub fn add_credit(&mut self, additional_bytes: u64) -> Result<()> {
        let (reader, state, on_reset, on_progress) = self.split();
        state.add_credit(reader, additional_bytes, on_reset, on_progress)
    }

    /// Hand the connection back, discarding any unread remainder of the
    /// stream.
    ///
    /// Runs the same teardown as `Drop`, so an *undrained* stream returns a
    /// connection whose transport has been closed — a pooled owner will
    /// then be retired rather than recycled. Drain to `Ok(false)` first if
    /// you want the connection back alive.
    pub fn into_owner(mut self) -> O {
        let mut owner = self
            .owner
            .take()
            .expect("OwnedCursor::into_owner called twice");
        self.state.drop_cleanup(owner.borrow_mut());
        // `self` still drops here; its `owner` is now `None`, so the `Drop`
        // impl below is a no-op and the cleanup is not run twice.
        owner
    }

    /// Rows in the current batch, or `0` before the first `next_batch`.
    pub fn batch_row_count(&self) -> usize {
        self.state.last_batch().map_or(0, |b| b.row_count)
    }

    /// Columns in the current batch, or `0` before the first `next_batch`.
    pub fn batch_column_count(&self) -> usize {
        self.state.last_batch().map_or(0, |b| b.columns.len())
    }

    /// Schema of the current query, or `None` before the first `next_batch`.
    pub fn batch_schema(&self) -> Option<&Schema> {
        self.reader_ref().query_schema()
    }

    /// Sequence number of the current batch, or `None` before the first
    /// `next_batch`.
    pub fn batch_seq(&self) -> Option<u64> {
        self.state.last_batch().map(|b| b.batch_seq)
    }

    /// `request_id` echoed on the current batch, or `None` before the first
    /// `next_batch`. Differs from [`Self::request_id`] only in the window
    /// after a mid-query failover has re-issued the query but before the
    /// replayed batch has been decoded.
    pub fn batch_request_id(&self) -> Option<i64> {
        self.state.last_batch().map(|b| b.request_id)
    }

    /// Per-batch wire flags (`FLAG_GORILLA` / `FLAG_DELTA_SYMBOL_DICT` /
    /// `FLAG_ZSTD`) from the current batch's frame header, or `None` before
    /// the first `next_batch`.
    pub fn batch_flags(&self) -> Option<u8> {
        self.state.last_batch().map(|b| b.flags)
    }

    /// Connection-scoped symbol dictionary the current batch's SYMBOL
    /// columns index into. The owning replacement for
    /// [`BatchView::dict`](crate::egress::BatchView::dict); unlike the
    /// per-batch accessors it is always available, because the dictionary
    /// is a property of the connection rather than of a decoded batch.
    pub fn symbol_dict(&self) -> &SymbolDict {
        self.reader_ref().symbol_dict()
    }

    /// A view of one column of the current batch.
    ///
    /// This is the owning replacement for going through [`BatchView`]: the
    /// returned view borrows `&self`, so no second handle spanning the
    /// cursor and the reader has to exist — `decoded` comes from
    /// `self.state`, `dict` from `self.owner`'s `Reader`, both reachable
    /// through the same `&self`.
    ///
    /// [`BatchView`]: crate::egress::BatchView
    pub fn batch_column(&self, idx: usize) -> Result<ColumnView<'_>> {
        let decoded = self
            .state
            .last_batch()
            .ok_or_else(|| fmt!(InvalidApiCall, "no current batch; call next_batch() first"))?;
        decoded.column_view(idx, self.reader_ref().symbol_dict())
    }
}

impl<O: BorrowMut<Reader>> Drop for OwnedCursor<O> {
    fn drop(&mut self) {
        // The verbatim body of `Drop for Cursor`, reached through the same
        // `CursorState` method rather than copied.
        if let Some(owner) = self.owner.as_mut() {
            self.state.drop_cleanup(owner.borrow_mut());
        }
    }
}

#[cfg(feature = "arrow-egress")]
impl<O: BorrowMut<Reader>> OwnedCursor<O> {
    /// Next batch as an Arrow [`RecordBatch`](arrow::array::RecordBatch).
    /// `Ok(None)` on stream end; replays terminal errors like
    /// [`Self::next_batch`]. No drift check — build an [`OwnedArrowReader`]
    /// via [`Self::into_arrow_reader`] for that.
    ///
    /// The owning counterpart of
    /// [`Cursor::next_arrow_batch`](crate::egress::Cursor::next_arrow_batch).
    pub fn next_arrow_batch(&mut self) -> Result<Option<arrow::array::RecordBatch>> {
        self.next_arrow_batch_inner(None, false)
    }

    /// Next batch as an Arrow `RecordBatch`, with explicit control over the
    /// two knobs [`Self::next_arrow_batch`] fixes: `expected_schema` (drift
    /// check against a schema pinned by the caller) and `compact` (emit
    /// SYMBOL columns with only the referenced values and batch-local
    /// codes).
    ///
    /// The owning counterpart of
    /// [`Cursor::next_arrow_batch_inner`](crate::egress::Cursor::next_arrow_batch_inner),
    /// and — like it — the entry point a consumer that pins its own schema
    /// (an FFI shim, an ADBC statement) needs; the convenience wrappers
    /// cannot express it.
    pub fn next_arrow_batch_inner(
        &mut self,
        expected_schema: Option<&arrow::datatypes::SchemaRef>,
        compact: bool,
    ) -> Result<Option<arrow::array::RecordBatch>> {
        let (reader, state, on_reset, on_progress) = self.split();
        state.next_arrow_batch_inner(reader, expected_schema, compact, on_reset, on_progress)
    }

    /// Shared by [`Self::next_arrow_batch`] and [`OwnedArrowReader`]'s
    /// `Iterator` impl — `expected_schema` is `Some` only from the latter,
    /// which pins a schema at construction and wants every later batch
    /// checked against it, except for the first frame after a failover
    /// replay, which it passes `None` and validates itself. Forwards
    /// straight to
    /// `CursorState::next_arrow_batch_inner`, the same method the borrowing
    /// path's `Cursor::next_arrow_batch_inner` calls: no protocol logic is
    /// duplicated here.
    ///
    /// `compact` (symbol-dictionary compaction) is hardcoded `false`, same
    /// as every other streaming entry point (`Cursor::next_arrow_batch`,
    /// `CursorRecordBatchReader`) — only the materialise-whole adapters opt
    /// into it.
    fn next_arrow_batch_checked(
        &mut self,
        expected_schema: Option<&arrow::datatypes::SchemaRef>,
    ) -> Result<Option<arrow::array::RecordBatch>> {
        self.next_arrow_batch_inner(expected_schema, false)
    }

    /// Consume this cursor as an owned Arrow
    /// [`RecordBatchReader`](arrow::array::RecordBatchReader).
    ///
    /// The owning counterpart of
    /// [`Cursor::as_arrow_reader`](crate::egress::Cursor::as_arrow_reader).
    /// Blocks until the first batch arrives, because `RecordBatchReader`
    /// requires a schema before iteration; the result's latency is
    /// therefore data-dependent. A statement that yields no batch at all
    /// (DDL) gives an empty schema and an immediately-exhausted stream —
    /// that is the documented shape of a schema-less result, not an error.
    ///
    /// Mid-stream schema drift on a later batch poisons the reader exactly
    /// like
    /// [`CursorRecordBatchReader`](crate::egress::arrow::CursorRecordBatchReader)
    /// does, including its tentative-array special case (see that type's
    /// docs for why `schemas_equal` alone can't catch a tentative→firm
    /// ndim upgrade) and its post-failover replay/re-pin dance with
    /// `resets_at_pin`.
    ///
    /// That last part is reachable only for a caller that installs
    /// [`OwnedQuery::on_failover_reset`] and then wraps the cursor here:
    /// without the callback, `CursorState`'s silent-duplicate guard turns a
    /// post-first-batch failover into `FailoverWouldDuplicate` and the
    /// stream never replays. With the callback the caller has authorised
    /// replay, and a replayed stream restarts at `batch_seq=0`, so this
    /// reader **re-delivers batches it has already yielded** — that is what
    /// installing the callback opts into, and the callback is where a
    /// consumer learns to discard what it accumulated. What the re-pin
    /// dance adds is the part a
    /// [`RecordBatchReader`](arrow::array::RecordBatchReader) cannot
    /// negotiate: the first replayed frame is passed to the decoder without
    /// an internal drift check (a new endpoint's batch 0 legitimately
    /// re-sends its schema and dictionary state), then required to match
    /// the schema already handed out, because a `RecordBatchReader`'s
    /// schema is fixed for its lifetime. Without it, every replay would
    /// surface as spurious
    /// [`SchemaDrift`](crate::ErrorCode::SchemaDrift); with it, only a
    /// genuinely different post-failover schema does. Use
    /// [`Self::next_arrow_batch_inner`] directly if you need to observe the
    /// reset and de-duplicate yourself.
    pub fn into_arrow_reader(mut self) -> Result<OwnedArrowReader<O>> {
        let first = self.next_arrow_batch_checked(None)?;
        let schema = match &first {
            Some(b) => b.schema(),
            None => std::sync::Arc::new(arrow::datatypes::Schema::empty()),
        };
        let resets_at_pin = self.failover_resets();
        Ok(OwnedArrowReader {
            cursor: self,
            schema,
            pending: first,
            poisoned: false,
            resets_at_pin,
        })
    }
}

/// An owned Arrow [`RecordBatchReader`](arrow::array::RecordBatchReader).
///
/// The owning counterpart of
/// [`CursorRecordBatchReader`](crate::egress::arrow::CursorRecordBatchReader):
/// built from [`OwnedCursor::into_arrow_reader`] rather than borrowing a
/// [`Cursor`](crate::egress::Cursor), so it carries no lifetime and can be
/// boxed as `Box<dyn RecordBatchReader + Send + 'static>` — the exact shape
/// ADBC's `Statement::execute` must return. It is `Send` whenever `O` is,
/// same as [`OwnedCursor`].
///
/// `OwnedArrowReader` owns the `OwnedCursor` it was built from, which owns
/// the connection, so the ordinary `Drop` glue tears everything down in the
/// right order — abandoning the stream mid-iteration runs the same
/// best-effort `CANCEL` + close as dropping an `OwnedCursor` directly.
/// There is no `unsafe`, `transmute`, or `ManuallyDrop` anywhere in this
/// module: that is the entire point of the owning handles.
#[cfg(feature = "arrow-egress")]
#[must_use = "OwnedArrowReader does nothing until iterated; dropping it mid-stream sends \
              a best-effort CANCEL and closes the WebSocket, retiring the connection it owns"]
pub struct OwnedArrowReader<O: BorrowMut<Reader>> {
    cursor: OwnedCursor<O>,
    schema: arrow::datatypes::SchemaRef,
    pending: Option<arrow::array::RecordBatch>,
    poisoned: bool,
    /// [`OwnedCursor::failover_resets`] at the point `schema` was pinned.
    /// Mirrors `CursorRecordBatchReader::resets_at_pin`; see
    /// [`OwnedCursor::into_arrow_reader`] for when it moves and why the
    /// replayed frame still has to match the pinned schema.
    resets_at_pin: u32,
}

#[cfg(feature = "arrow-egress")]
impl<O: BorrowMut<Reader>> OwnedArrowReader<O> {
    /// Snapshotted schema. Same as the
    /// [`RecordBatchReader::schema`](arrow::array::RecordBatchReader::schema)
    /// trait method, exposed for callers without the trait imported.
    pub fn schema(&self) -> arrow::datatypes::SchemaRef {
        self.schema.clone()
    }
}

#[cfg(feature = "arrow-egress")]
impl<O: BorrowMut<Reader>> Iterator for OwnedArrowReader<O> {
    type Item = std::result::Result<arrow::array::RecordBatch, arrow::error::ArrowError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.poisoned {
            return None;
        }
        if let Some(rb) = self.pending.take() {
            return Some(Ok(rb));
        }
        // A transparent mid-query failover (only possible when the caller
        // installed `on_failover_reset`) re-reads the result from
        // `batch_seq 0` on a new endpoint. Pass `None` (no drift check) for
        // that first replayed frame so the new node's batch 0 isn't rejected,
        // then require it to match the pinned schema: a RecordBatchReader's
        // schema must be stable for its lifetime, so a genuinely different
        // post-failover schema is surfaced as drift, not silently swapped in.
        let drift_check = if self.cursor.failover_resets() == self.resets_at_pin {
            Some(&self.schema)
        } else {
            None
        };
        match self.cursor.next_arrow_batch_checked(drift_check) {
            Ok(Some(rb)) => {
                if self.cursor.failover_resets() != self.resets_at_pin {
                    if rb.schema() != self.schema {
                        self.poisoned = true;
                        return Some(Err(external_arrow_error(fmt!(
                            SchemaDrift,
                            "post-failover replay returned a different schema; \
                             a RecordBatchReader schema must be stable for the \
                             reader's lifetime; use \
                             OwnedCursor::next_arrow_batch_inner to handle \
                             drift explicitly"
                        ))));
                    }
                    self.resets_at_pin = self.cursor.failover_resets();
                } else if has_tentative_array(&self.schema) && rb.schema() != self.schema {
                    // Same representability gap `CursorRecordBatchReader`
                    // guards against: `schemas_equal` (which backs the
                    // `expected_schema` drift check just above) deliberately
                    // treats a tentative ndim metadata field as matching any
                    // concrete dimension, so a tentative→firm upgrade sails
                    // past that check even though the actual
                    // `arrow::datatypes::Schema` now differs from the one
                    // already handed out as this reader's fixed schema.
                    self.poisoned = true;
                    return Some(Err(external_arrow_error(fmt!(
                        SchemaDrift,
                        "tentative→firm ndim upgrade is not representable in \
                         RecordBatchReader (schema must be stable for the \
                         reader's lifetime); use OwnedCursor::next_arrow_batch \
                         to handle drift explicitly"
                    ))));
                }
                Some(Ok(rb))
            }
            Ok(None) => {
                self.poisoned = true;
                None
            }
            Err(e) => {
                self.poisoned = true;
                Some(Err(external_arrow_error(e)))
            }
        }
    }
}

#[cfg(feature = "arrow-egress")]
impl<O: BorrowMut<Reader>> arrow::array::RecordBatchReader for OwnedArrowReader<O> {
    fn schema(&self) -> arrow::datatypes::SchemaRef {
        self.schema.clone()
    }
}

// `Send` holds whenever `O` does: `OwnedArrowReader` adds only a
// `SchemaRef` (`Arc`, `Send + Sync`), an `Option<RecordBatch>` (`Send`
// when its arrays are, which QuestDB's Arrow arrays are), a `bool` and a
// `u32` on top of the `OwnedCursor` it wraps — no interior mutability, no raw
// pointers. Checked here for the pool-backed `OwnedReader` shape ADBC
// actually uses (only available when `sync-sender-qwp-ws` is also on); a
// second copy against `PooledCursor` lives in `tests/egress_owned_arrow.rs`
// so the assertion is exercised from outside the crate too.
#[cfg(all(feature = "arrow-egress", feature = "sync-sender-qwp-ws"))]
const _: fn() = || {
    fn assert_send<T: Send>() {}
    assert_send::<OwnedCursor<crate::OwnedReader>>();
    assert_send::<OwnedArrowReader<crate::OwnedReader>>();
};

impl Reader {
    /// Begin a query that takes ownership of this connection.
    ///
    /// The owning counterpart of [`Reader::prepare`]: instead of borrowing
    /// the reader for the cursor's lifetime, the cursor *is* the reader's
    /// new home. Get it back with
    /// [`OwnedCursor::into_owner`] once the stream has been drained.
    pub fn into_query<S: Into<String>>(self, sql: S) -> OwnedQuery<Reader> {
        OwnedQuery::new(self, sql)
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
impl crate::OwnedReader {
    /// Begin a query on this pooled connection.
    ///
    /// The resulting [`PooledCursor`] owns the pool slot, so it — not the
    /// caller — decides when the reader goes back. Draining the stream and
    /// calling [`OwnedCursor::into_owner`] returns a live, reusable
    /// connection; dropping mid-stream retires it.
    pub fn query<S: Into<String>>(self, sql: S) -> PooledQuery {
        OwnedQuery::new(self, sql)
    }
}
