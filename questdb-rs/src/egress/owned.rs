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

use crate::egress::column::ColumnView;
use crate::egress::query_request::{QueryRequest, QueryRequestBuilder};
use crate::egress::reader::{CursorState, NextOutcome, Reader, Terminal};
use crate::egress::schema::Schema;
use crate::egress::{Bind, Endpoint, ServerInfo};
use crate::error::{Result, fmt};

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
        }
    }

    /// Append one bind value, in placeholder order.
    pub fn bind(mut self, value: Bind) -> Self {
        self.builder = self.builder.bind(value);
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
    /// clone of anything you need from the connection before calling.
    pub fn execute(mut self) -> Result<OwnedCursor<O>> {
        let state = CursorState::submit(
            self.owner.borrow_mut(),
            self.builder,
            self.reset_symbol_dict,
        )?;
        Ok(OwnedCursor {
            owner: Some(self.owner),
            state,
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
    /// Mid-query failover behaves as on [`Cursor::next_batch`]: because no
    /// reset callback can be installed on this handle yet, a transport
    /// failure *after* a batch has been yielded surfaces
    /// [`FailoverWouldDuplicate`](crate::ErrorCode::FailoverWouldDuplicate)
    /// rather than silently replaying from `batch_seq=0`. Failover before
    /// the first batch stays transparent.
    ///
    /// [`Cursor::next_batch`]: crate::egress::Cursor::next_batch
    pub fn next_batch(&mut self) -> Result<bool> {
        // Disjoint field borrows: `&mut self.owner` for the argument,
        // `&mut self.state` for the receiver.
        let reader = reader_of(&mut self.owner);
        match self.state.next_batch_step(reader, None, None)? {
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
        let reader = reader_of(&mut self.owner);
        self.state.cancel(reader, None, None)
    }

    /// Grant the server `additional_bytes` of read budget on this request.
    pub fn add_credit(&mut self, additional_bytes: u64) -> Result<()> {
        let reader = reader_of(&mut self.owner);
        self.state.add_credit(reader, additional_bytes, None, None)
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
