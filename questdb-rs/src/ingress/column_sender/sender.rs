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

//! Borrowed-handle types for the column-major sender.

use std::fmt::{self, Debug, Formatter};
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::ingress::AckLevel;
use crate::ingress::QwpWsSenderError;
use crate::ingress::buffer::{SymbolGlobalDict, SymbolGlobalDictMark};
use crate::ingress::sender::qwp_ws::{
    SyncQwpWsHandlerState, publish_qwp_ws_payload_background, qwp_ws_acked_fsn_background,
    qwp_ws_begin_close_background, qwp_ws_check_error_background,
    qwp_ws_drain_to_deadline_background, qwp_ws_is_terminal_background, qwp_ws_ok_fsn_background,
    qwp_ws_poll_sender_error_in_range_background, qwp_ws_published_fsn_background,
};
use crate::ingress::sender::qwp_ws_sfa_symbol_dict::{
    PersistedSymbolDict, PersistedSymbolDictMark,
};
#[cfg(feature = "arrow-ingress")]
use crate::ingress::{ColumnName, TableName};
use crate::{Result, error};

#[cfg(feature = "arrow-ingress")]
use super::arrow_batch::{self, ArrowColumnOverride};
use super::chunk::Chunk;
use super::conn::{ColumnConn, PublishError};
use super::encoder;

#[cfg(feature = "arrow-ingress")]
use arrow::array::RecordBatch;

fn classify_flush_error(err: crate::Error) -> crate::Error {
    if err.code() == ErrorCode::SocketError {
        return crate::Error::new(ErrorCode::FailoverRetry, err.msg().to_owned());
    }
    err
}

/// Outcome of publishing a single frame on the direct backend.
enum FrameOutcome {
    Published,
    /// The encoded frame exceeded the negotiated cap before any byte reached
    /// the wire, so the caller may split the row range and retry. Carries the
    /// detailed size error so the split floor can surface exact byte counts.
    TooLarge(crate::Error),
    /// The deferred window is full before any byte reached the wire. The
    /// top-level flush surfaces this as the explicit "call sync()" contract;
    /// a split consumes it internally (commit the published prefix, drain,
    /// retry the range) since its extra frames are an implementation detail
    /// the caller cannot account for.
    NoSlot(crate::Error),
}

/// Outcome of appending a single frame on the store-and-forward backend.
#[derive(Debug)]
enum SfaOutcome {
    Published(u64),
    /// The encoded frame exceeded the negotiated cap before it was queued, so
    /// the caller may split the row range and retry. Carries the detailed size
    /// error so the split floor can surface exact byte counts.
    TooLarge(crate::Error),
}

/// The immutable inputs to an Arrow-batch flush, bundled so the recursive split
/// helpers don't thread five arguments through every call. `batch.slice(...)`
/// (zero-copy) produces the sub-range views.
#[cfg(feature = "arrow-ingress")]
struct ArrowFrameSpec<'a> {
    table: TableName<'a>,
    batch: &'a RecordBatch,
    ts_col_idx: Option<usize>,
    server_stamp: bool,
    overrides: &'a [ArrowColumnOverride<'a>],
}

/// Split point for an oversize `row_count`: the largest multiple of 8 not
/// exceeding `row_count / 2` (at least 8). `None` once the block is at the
/// 8-row floor, which cannot be split further because bit-packed `Bool`
/// columns and validity bitmaps are only byte-addressable.
fn split_mid(row_count: usize) -> Option<usize> {
    if row_count <= 8 {
        return None;
    }
    let mid = (row_count / 2) & !7;
    Some(if mid == 0 { 8 } else { mid })
}

/// Whether a flush also waits for a server completion boundary at the
/// requested [`AckLevel`] before returning (an "ACKing flush"), or returns as
/// soon as the frame is published ("publish-only").
#[derive(Clone, Copy, Debug)]
pub(crate) enum WaitForAck {
    No,
    Yes(AckLevel),
}

/// Delivery certainty of the **current input** when an ACKing flush fails.
///
/// Drives the C FFI Arrow re-export decision (see
/// `doc/COLUMN_SENDER_ACK_BOUNDARY_FLUSH.md` §7.5): `NotDelivered` may
/// re-export the caller's batch for retry; `DeliveryUnknown` must not. The
/// distinction is delivery certainty of the current input, *not* the error
/// code — a direct-mode `write_all`/`flush` error or a post-publish ACK-wait
/// failure is `DeliveryUnknown` even though it reports `FailoverRetry`.
#[derive(Debug)]
#[doc(hidden)]
#[non_exhaustive]
pub enum FlushFailure {
    /// Provably not transmitted (ACK/durable validation, encode, size check,
    /// or a transport error before any byte was written). Manual chunks remain
    /// untouched; Arrow input may be re-exported for retry.
    NotDelivered(crate::Error),
    /// May have reached the server: the write succeeded, partially succeeded,
    /// or the post-write ACK wait failed. The current input must not be
    /// re-exported (Arrow) or blindly replayed (manual chunk).
    ///
    /// Manual-chunk state depends on the sub-case, per the publish-only
    /// clearing rule (`doc/COLUMN_SENDER_ACK_BOUNDARY_FLUSH.md` §7.4): the
    /// chunk is cleared once publication succeeds (so an ACKing flush whose
    /// later ACK wait fails leaves it cleared), but a *partial write*
    /// (`PublishError::DuringWrite`) returns before the chunk is cleared and so
    /// leaves it populated. Either way delivery is uncertain — chunk state is
    /// not a "safe to retry" signal here. [`FlushFailure::into_error`] tags the
    /// wrapped error [`in_doubt`](crate::Error::in_doubt) so publish-only
    /// callers can detect this without inspecting the error code.
    DeliveryUnknown(crate::Error),
}

impl FlushFailure {
    /// The underlying error, collapsing the delivery classification into a
    /// plain [`crate::Error`]. Used by the public `Result<()>`-returning API,
    /// which never re-exports. The `DeliveryUnknown` arm tags the error
    /// [`in_doubt`](crate::Error::in_doubt) so publish-only callers retain the
    /// delivery-unknown signal that the enum carried.
    #[doc(hidden)]
    pub fn into_error(self) -> crate::Error {
        match self {
            FlushFailure::NotDelivered(e) => e,
            FlushFailure::DeliveryUnknown(e) => e.with_in_doubt(true),
        }
    }

    /// `true` when the current input was provably not transmitted.
    #[doc(hidden)]
    #[must_use]
    pub fn is_not_delivered(&self) -> bool {
        matches!(self, FlushFailure::NotDelivered(_))
    }
}

/// Direct-backend `NotDelivered`: map a socket error to `FailoverRetry`, the
/// same way publish-only [`classify_flush_error`] does.
fn direct_not_delivered(e: crate::Error) -> FlushFailure {
    FlushFailure::NotDelivered(classify_flush_error(e))
}

/// Direct-backend `DeliveryUnknown`: same `FailoverRetry` mapping, but the
/// current input may already be on the wire.
fn direct_delivery_unknown(e: crate::Error) -> FlushFailure {
    FlushFailure::DeliveryUnknown(classify_flush_error(e))
}

/// Downgrade a split sub-range failure once an earlier sub-range has already
/// committed (direct) or been enqueued (store-and-forward): the chunk is now
/// partially on the server, so it is no longer safe to blind-retry the whole
/// chunk. `NotDelivered` (safe to re-export) becomes `DeliveryUnknown` (in
/// doubt, must not re-export); `DeliveryUnknown` is left unchanged so we never
/// mask an in-doubt failure as retryable.
fn deny_retry_after_partial(f: FlushFailure) -> FlushFailure {
    match f {
        FlushFailure::NotDelivered(e) => FlushFailure::DeliveryUnknown(e),
        other => other,
    }
}

pub struct ColumnSender {
    backend: ColumnSenderBackend,
}

// Both variants are large (the direct backend owns a live connection; the
// store-and-forward backend embeds the whole background handler state -- queue
// producer, recovered dictionary, persisted side-file), so both are boxed to
// keep `ColumnSender` itself pointer-sized as it is moved in and out of the pool.
enum ColumnSenderBackend {
    Direct(Box<DirectColumnBackend>),
    StoreAndForward(Box<SfaColumnBackend>),
}

struct DirectColumnBackend {
    conn: ColumnConn,
    symbol_dict: SymbolGlobalDict,
    scratch: encoder::EncodeScratch,
    first_frame_sent: bool,
}

struct SfaColumnBackend {
    /// The slot's persisted symbol dictionary (file mode) for write-ahead: the
    /// symbols each frame introduces are appended here before the frame is
    /// published, and rolled back in lockstep with `symbol_dict` when an append
    /// fails, so recovery / orphan-drain can rebuild the exact dictionary the
    /// stored delta frames reference. `None` in memory mode / on open failure.
    ///
    /// Declared *before* `state` so Rust drops it first (fields drop in
    /// declaration order): the `.symbol-dict` write handle is closed before
    /// `state`'s runner is joined and its slot lock -- the cross-process guard on
    /// this slot -- is released, so the OS file handle never outlives the lock that
    /// guards it. Mirrors the row path, where the encoder owning this handle is
    /// declared ahead of the runner.
    persisted_symbol_dict: Option<PersistedSymbolDict>,
    state: SyncQwpWsHandlerState,
    symbol_dict: SymbolGlobalDict,
    /// When true, SFA frames carry only the symbol ids new since the previous
    /// frame (a delta), and the background driver re-registers the whole
    /// dictionary via a catch-up frame on reconnect. When false, every frame
    /// re-ships the full dictionary from id 0 (self-sufficient). Determined by
    /// the store's mode (memory always; file iff the persisted dict opened);
    /// see [`ColumnSender::new_store_and_forward`].
    delta_dict_enabled: bool,
    scratch: encoder::EncodeScratch,
    payload: Vec<u8>,
    max_buf_size: usize,
    request_durable_ack: bool,
    /// No-progress deadline for the `sync` poll loop. Mirrors the direct
    /// backend's socket `request_timeout`: it bounds how long `sync` waits
    /// *without the ack/durable watermark advancing*, so a silent-but-alive
    /// peer (back-pressured WAL, stuck commit) cannot block the caller
    /// forever. A legitimately slow-but-progressing sync keeps resetting it.
    /// `Duration::ZERO` disables the deadline (unbounded, legacy behaviour).
    sync_timeout: Duration,
    last_ok_sync_boundary: Option<u64>,
    last_durable_sync_boundary: Option<u64>,
    drop_on_return: bool,
}

impl Debug for ColumnSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.backend {
            ColumnSenderBackend::Direct(direct) => f
                .debug_struct("ColumnSender")
                .field("mode", &"direct")
                .field("must_close", &direct.conn.must_close())
                .field("in_flight", &direct.conn.in_flight())
                .finish(),
            ColumnSenderBackend::StoreAndForward(sfa) => f
                .debug_struct("ColumnSender")
                .field("mode", &"store_and_forward")
                .field(
                    "must_close",
                    &(sfa.drop_on_return || qwp_ws_is_terminal_background(&sfa.state)),
                )
                .field("in_flight", &0u32)
                .finish(),
        }
    }
}

impl ColumnSender {
    pub(crate) fn new(
        conn: ColumnConn,
        symbol_dict: SymbolGlobalDict,
        scratch: encoder::EncodeScratch,
        first_frame_sent: bool,
    ) -> Self {
        Self::new_direct(conn, symbol_dict, scratch, first_frame_sent)
    }

    pub(crate) fn new_direct(
        conn: ColumnConn,
        symbol_dict: SymbolGlobalDict,
        scratch: encoder::EncodeScratch,
        first_frame_sent: bool,
    ) -> Self {
        Self {
            backend: ColumnSenderBackend::Direct(Box::new(DirectColumnBackend {
                conn,
                symbol_dict,
                scratch,
                first_frame_sent,
            })),
        }
    }

    pub(crate) fn new_store_and_forward(
        mut state: SyncQwpWsHandlerState,
        max_buf_size: usize,
        request_durable_ack: bool,
        sync_timeout: Duration,
    ) -> Result<Self> {
        // The background driver enables its catch-up mirror on exactly the same
        // condition as this foreground (memory mode always; file mode iff the
        // side-file opened), so the two stay in lockstep: both emit delta, or both
        // stay full-dict. In file mode, seed the dictionary from the recovered
        // entries (so new symbols continue above the recovered ids) and claim the
        // side-file for write-ahead -- the row encoder in this state is dormant for
        // a column sender, so connect_sfa_background left the side-file for us.
        let delta_dict_enabled = state.delta_dict_enabled;
        let mut symbol_dict = SymbolGlobalDict::new();
        if delta_dict_enabled {
            // Take the recovered entries so the (potentially large) buffer is freed
            // after seeding rather than living dead in `state` -- which the backend
            // holds for its whole life -- for the connection's duration.
            let recovered = std::mem::take(&mut state.recovered_dict_entries);
            symbol_dict.seed(&recovered, state.recovered_dict_count)?;
        }
        let persisted_symbol_dict = state.persisted_symbol_dict.take();
        // The row encoder in `state` is dormant for a column sender (we use our own
        // `symbol_dict` above and never touch it); release the recovered dictionary
        // seeded into it at connect so it is not carried dead for the connection's
        // life -- matching the `recovered_dict_entries` take above.
        state.release_dormant_encoder_dict();
        Ok(Self {
            backend: ColumnSenderBackend::StoreAndForward(Box::new(SfaColumnBackend {
                state,
                symbol_dict,
                delta_dict_enabled,
                persisted_symbol_dict,
                scratch: encoder::EncodeScratch::new(),
                payload: Vec::new(),
                max_buf_size,
                request_durable_ack,
                sync_timeout,
                last_ok_sync_boundary: None,
                last_durable_sync_boundary: None,
                drop_on_return: false,
            })),
        })
    }

    pub(crate) fn is_store_and_forward(&self) -> bool {
        matches!(self.backend, ColumnSenderBackend::StoreAndForward(_))
    }

    #[must_use]
    pub fn must_close(&self) -> bool {
        match &self.backend {
            ColumnSenderBackend::Direct(direct) => direct.conn.must_close(),
            ColumnSenderBackend::StoreAndForward(sfa) => {
                sfa.drop_on_return || qwp_ws_is_terminal_background(&sfa.state)
            }
        }
    }

    pub fn mark_must_close(&mut self) {
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => direct.conn.mark_must_close(),
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.drop_on_return = true,
        }
    }

    pub(crate) fn in_flight(&self) -> u32 {
        match &self.backend {
            ColumnSenderBackend::Direct(direct) => direct.conn.in_flight(),
            ColumnSenderBackend::StoreAndForward(_) => 0,
        }
    }

    /// Non-blocking: `true` once the store-and-forward backend has no
    /// undelivered frames — every published frame has reached the pool's ack
    /// watermark (durable when `durable`, otherwise the OK watermark) — so the
    /// connection can be retired without losing data. A terminal backend
    /// reports `true`: its queued frames are already unrecoverable. Always
    /// `true` for the direct backend, which owns no background queue.
    ///
    /// The pool reaper uses this to avoid evicting an idle connection whose
    /// background runner is still flushing.
    pub(crate) fn sfa_fully_delivered(&self, durable: bool) -> bool {
        let ColumnSenderBackend::StoreAndForward(sfa) = &self.backend else {
            return true;
        };
        if qwp_ws_is_terminal_background(&sfa.state) {
            return true;
        }
        let Ok(Some(published)) = qwp_ws_published_fsn_background(&sfa.state) else {
            // Nothing published yet, or a terminal/poisoned read: no
            // recoverable frames are queued.
            return true;
        };
        let watermark = if durable {
            qwp_ws_acked_fsn_background(&sfa.state)
        } else {
            qwp_ws_ok_fsn_background(&sfa.state)
        };
        matches!(watermark, Ok(Some(w)) if w >= published)
    }

    /// Non-blocking: stop accepting new store-and-forward publications and wake
    /// the background runner to flush what is queued. Pairs with
    /// [`Self::drain_to_deadline`]. No-op for the direct backend.
    pub(crate) fn begin_close(&self) {
        if let ColumnSenderBackend::StoreAndForward(sfa) = &self.backend {
            qwp_ws_begin_close_background(&sfa.state);
        }
    }

    /// Block until the store-and-forward queue has delivered every published
    /// frame, or `deadline` elapses. `Ok(())` means fully drained (or nothing
    /// was queued); `Err` means the drain timed out or the transport went
    /// terminal with frames still undelivered. No-op `Ok(())` for the direct
    /// backend, whose deferred frames are handled by `commit_in_flight_on_drop`.
    pub(crate) fn drain_to_deadline(&mut self, deadline: Option<Instant>) -> crate::Result<()> {
        match &mut self.backend {
            ColumnSenderBackend::Direct(_) => Ok(()),
            ColumnSenderBackend::StoreAndForward(sfa) => {
                qwp_ws_drain_to_deadline_background(&mut sfa.state, deadline)
            }
        }
    }

    pub(crate) fn transport_dead(&self) -> bool {
        match &self.backend {
            ColumnSenderBackend::Direct(direct) => direct.conn.transport_dead(),
            ColumnSenderBackend::StoreAndForward(_) => false,
        }
    }

    pub(crate) fn endpoint_idx(&self) -> Option<usize> {
        match &self.backend {
            ColumnSenderBackend::Direct(direct) => Some(direct.conn.endpoint_idx()),
            ColumnSenderBackend::StoreAndForward(_) => None,
        }
    }

    /// Encode and publish `chunk` as a QWP/WebSocket frame **without** waiting
    /// for a server completion boundary. Call [`Self::sync`] (or use
    /// [`Self::flush_and_wait`]) to wait for the requested [`AckLevel`].
    ///
    /// Frames published by `flush` are not committed until the next
    /// [`Self::sync`] / [`Self::flush_and_wait`] completes: that ACK boundary is
    /// the only durability and replay checkpoint. If a later flush or sync fails
    /// and you reborrow onto a fresh connection, re-drive the source from the
    /// last successful `sync`, not just the failing `chunk` — every frame
    /// published since that checkpoint is discarded with the dead connection.
    ///
    /// On success `chunk` is cleared. On failure `chunk` is left untouched and
    /// the data is **not** guaranteed undelivered: a transport error that fails
    /// mid-frame may already have put bytes on the wire. Such a failure reports
    /// [`ErrorCode::FailoverRetry`] but tags the error
    /// [`in_doubt`](crate::Error::in_doubt) — inspect it before re-flushing the
    /// retained `chunk` on a fresh connection, since replay can duplicate rows.
    pub fn flush(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => direct.flush_inner(chunk, WaitForAck::No),
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.flush_chunk(chunk, WaitForAck::No),
        }
        .map_err(FlushFailure::into_error)
    }

    /// Store-and-forward only: encode and publish `chunk` into the local SFA
    /// queue and return the last published frame sequence number. If a chunk is
    /// split into multiple frames, the returned FSN is the final frame boundary;
    /// cumulative ACK coverage of that boundary covers the whole chunk.
    pub fn flush_and_get_fsn(&mut self, chunk: &mut Chunk<'_>) -> Result<Option<u64>> {
        match &mut self.backend {
            ColumnSenderBackend::StoreAndForward(sfa) => sfa
                .flush_chunk_and_get_fsn(chunk)
                .map(Some)
                .map_err(FlushFailure::into_error),
            ColumnSenderBackend::Direct(_) => Err(error::fmt!(
                InvalidApiCall,
                "flush_and_get_fsn is store-and-forward only; direct column senders do not expose FSNs."
            )),
        }
    }

    /// Publish `chunk` as a completion boundary, then wait until every frame
    /// published before or by this call on this borrowed sender reaches
    /// `ack_level` (see `doc/COLUMN_SENDER_ACK_BOUNDARY_FLUSH.md`).
    ///
    /// The boundary is cumulative: a successful return means all prior no-wait
    /// flushes plus this one are acknowledged at `ack_level`. An empty `chunk`
    /// behaves exactly like [`Self::sync`] (it encodes a header-only frame).
    ///
    /// `AckLevel::Durable` requires the pool to be opened with
    /// `request_durable_ack=on`; otherwise the call is rejected up front
    /// (`InvalidApiCall`) before `chunk` is touched.
    ///
    /// Failure contract: the ACK level is validated, then the frame is
    /// published, then the wait runs. If publication itself fails the `chunk`
    /// is untouched and retryable. Once publication succeeds `chunk` is cleared
    /// even if the later ACK wait fails — at which point delivery of the just
    /// published frame is **unknown** (it may be committed, rejected, or in
    /// flight) and the borrow should be dropped/reborrowed per the error class.
    /// There is no internal failover retry; replay is the caller's
    /// responsibility.
    pub fn flush_and_wait(&mut self, chunk: &mut Chunk<'_>, ack_level: AckLevel) -> Result<()> {
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => {
                direct.flush_inner(chunk, WaitForAck::Yes(ack_level))
            }
            ColumnSenderBackend::StoreAndForward(sfa) => {
                sfa.flush_chunk(chunk, WaitForAck::Yes(ack_level))
            }
        }
        .map_err(FlushFailure::into_error)
    }

    /// Encode and publish an Arrow [`RecordBatch`] **without** a per-row
    /// designated timestamp, explicitly delegating timestamp assignment to the
    /// server (each row is stamped on arrival).
    ///
    /// This is the opt-in counterpart to [`Self::flush_arrow_batch_at_column`].
    /// If your batch carries a real event-time column, prefer
    /// `flush_arrow_batch_at_column` — reaching for this method instead would
    /// discard that column's role as the designated timestamp and silently
    /// substitute server arrival time, producing wrong partitions/order.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        self.flush_arrow_batch_dispatch(table, batch, None, true, overrides, WaitForAck::No)
            .map_err(FlushFailure::into_error)
    }

    /// Store-and-forward only: Arrow counterpart of [`Self::flush_and_get_fsn`]
    /// for server-stamped batches.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now_and_get_fsn<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<Option<u64>>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        self.flush_arrow_batch_dispatch_get_fsn(table, batch, None, true, overrides)
            .map_err(FlushFailure::into_error)
    }

    /// ACKing counterpart of [`Self::flush_arrow_batch_at_now`]:
    /// publish `batch` as a boundary, then wait for `ack_level`. The same
    /// boundary/durable/failure contract as [`Self::flush_and_wait`] applies.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now_and_wait<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> Result<()>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        self.flush_arrow_batch_dispatch(
            table,
            batch,
            None,
            true,
            overrides,
            WaitForAck::Yes(ack_level),
        )
        .map_err(FlushFailure::into_error)
    }

    /// Encode and publish an Arrow [`RecordBatch`], sourcing the per-row
    /// designated timestamp from the named `Timestamp(_)` column of the batch.
    ///
    /// Use [`Self::flush_arrow_batch_at_now`] to instead let the server
    /// stamp each row on arrival.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        let ts_col_idx = arrow_batch::resolve_ts_column(batch, ts_column)?;
        self.flush_arrow_batch_dispatch(
            table,
            batch,
            Some(ts_col_idx),
            false,
            overrides,
            WaitForAck::No,
        )
        .map_err(FlushFailure::into_error)
    }

    /// Store-and-forward only: Arrow counterpart of [`Self::flush_and_get_fsn`]
    /// for batches whose designated timestamp is sourced from `ts_column`.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column_and_get_fsn<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<Option<u64>>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        let ts_col_idx = arrow_batch::resolve_ts_column(batch, ts_column)?;
        self.flush_arrow_batch_dispatch_get_fsn(table, batch, Some(ts_col_idx), false, overrides)
            .map_err(FlushFailure::into_error)
    }

    /// ACKing counterpart of [`Self::flush_arrow_batch_at_column`]: publish
    /// `batch` as a boundary, then wait for `ack_level`. The same
    /// boundary/durable/failure contract as [`Self::flush_and_wait`] applies.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column_and_wait<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> Result<()>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        let ts_col_idx = arrow_batch::resolve_ts_column(batch, ts_column)?;
        self.flush_arrow_batch_dispatch(
            table,
            batch,
            Some(ts_col_idx),
            false,
            overrides,
            WaitForAck::Yes(ack_level),
        )
        .map_err(FlushFailure::into_error)
    }

    /// Backend dispatch shared by every Arrow flush variant.
    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch_dispatch(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        server_stamp: bool,
        overrides: &[ArrowColumnOverride<'_>],
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => direct.flush_arrow_batch_inner(
                table,
                batch,
                ts_col_idx,
                server_stamp,
                overrides,
                wait,
            ),
            ColumnSenderBackend::StoreAndForward(sfa) => {
                sfa.flush_arrow_batch(table, batch, ts_col_idx, server_stamp, overrides, wait)
            }
        }
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch_dispatch_get_fsn(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        server_stamp: bool,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> std::result::Result<Option<u64>, FlushFailure> {
        match &mut self.backend {
            ColumnSenderBackend::StoreAndForward(sfa) => sfa
                .flush_arrow_batch_and_get_fsn(table, batch, ts_col_idx, server_stamp, overrides)
                .map(Some),
            ColumnSenderBackend::Direct(_) => Err(FlushFailure::NotDelivered(error::fmt!(
                InvalidApiCall,
                "flush_arrow_batch_*_and_get_fsn is store-and-forward only; direct column senders do not expose FSNs."
            ))),
        }
    }

    /// Preflight ACK-level validation for the C FFI ACKing-flush entry points.
    /// Run before the Arrow C Data Interface import consumes `array->release`
    /// (and before chunk encode), so a rejected `AckLevel::Durable` leaves
    /// caller-owned input untouched. Dispatches per backend.
    #[doc(hidden)]
    pub fn validate_ack_level(&self, ack_level: AckLevel) -> Result<()> {
        match &self.backend {
            ColumnSenderBackend::Direct(direct) => direct.conn.validate_ack_level(ack_level),
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.validate_ack_level(ack_level),
        }
    }

    /// FFI-only ACKing Arrow flush (server-stamped) that surfaces the
    /// [`FlushFailure`] delivery classification so the C layer can decide
    /// whether to re-export the caller's `ArrowArray`.
    #[doc(hidden)]
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now_and_wait_ffi(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure> {
        self.flush_arrow_batch_dispatch(
            table,
            batch,
            None,
            true,
            overrides,
            WaitForAck::Yes(ack_level),
        )
    }

    /// FFI-only ACKing Arrow flush (column-stamped) that surfaces the
    /// [`FlushFailure`] delivery classification. A failure to resolve
    /// `ts_column` is `NotDelivered` (nothing was published).
    #[doc(hidden)]
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_column_and_wait_ffi(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_column: ColumnName<'_>,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure> {
        let ts_col_idx =
            arrow_batch::resolve_ts_column(batch, ts_column).map_err(FlushFailure::NotDelivered)?;
        self.flush_arrow_batch_dispatch(
            table,
            batch,
            Some(ts_col_idx),
            false,
            overrides,
            WaitForAck::Yes(ack_level),
        )
    }

    pub fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => direct.sync(ack_level),
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.sync(ack_level),
        }
    }

    /// Store-and-forward only: wait up to `timeout` for every frame published
    /// so far to reach `ack_level`. `timeout` is a no-progress deadline — it
    /// fires only if the ack watermark fails to advance for that long;
    /// `Duration::ZERO` waits indefinitely. On expiry it returns a
    /// [`ErrorCode::FailoverRetry`](crate::ErrorCode::FailoverRetry)
    /// error and the queued frames are retained for replay.
    pub fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()> {
        match &mut self.backend {
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.wait(ack_level, timeout),
            ColumnSenderBackend::Direct(_) => Err(error::fmt!(
                InvalidApiCall,
                "wait(timeout) is store-and-forward only; the direct sender uses commit()."
            )),
        }
    }

    /// Store-and-forward only: return the highest frame sequence number
    /// published locally by this sender, or `None` if no frame has been
    /// published.
    pub fn published_fsn(&self) -> Result<Option<u64>> {
        match &self.backend {
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.published_fsn(),
            ColumnSenderBackend::Direct(_) => Err(error::fmt!(
                InvalidApiCall,
                "published_fsn is store-and-forward only; direct column senders do not expose FSNs."
            )),
        }
    }

    /// Store-and-forward only: return the highest frame sequence number
    /// completed by server ACK or server-side reject-and-continue, or `None`
    /// if no frame has completed.
    pub fn acked_fsn(&self) -> Result<Option<u64>> {
        match &self.backend {
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.acked_fsn(),
            ColumnSenderBackend::Direct(_) => Err(error::fmt!(
                InvalidApiCall,
                "acked_fsn is store-and-forward only; direct column senders do not expose FSNs."
            )),
        }
    }
}

impl DirectColumnBackend {
    fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        // An ACKing flush of an empty chunk *is* `sync`: it publishes a
        // non-deferred header-only commit frame, then drains to the ack level
        // (`sync_all_acks`). `sync` is not a data flush, so it must leave the
        // deferral state untouched — the next data flush still chooses defer
        // from `first_frame_sent` exactly as before.
        let first_frame_sent = self.first_frame_sent;
        let mut commit_chunk = Chunk::new("");
        let result = self.flush_inner(&mut commit_chunk, WaitForAck::Yes(ack_level));
        self.first_frame_sent = first_frame_sent;
        result.map_err(FlushFailure::into_error)
    }

    fn flush_inner(
        &mut self,
        chunk: &mut Chunk<'_>,
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        // ACK validation is a preflight: a bad / durable-without-opt-in level
        // is rejected before any encode or write touches caller-owned state.
        // An ACKing flush publishes its data-bearing frame non-deferred and
        // then drains in-flight to zero, so it neither defers nor needs the
        // reserved commit slot.
        let defer_commit = match wait {
            WaitForAck::No => self.first_frame_sent,
            WaitForAck::Yes(level) => {
                self.conn
                    .validate_ack_level(level)
                    .map_err(direct_not_delivered)?;
                false
            }
        };

        self.conn.try_drain_acks().map_err(direct_not_delivered)?;

        // Whole-chunk fast path: no slicing, no extra allocation. Only when a
        // single frame would exceed the negotiated cap do we fall back to
        // splitting the row range into multiple frames, all but the last
        // deferred so the chunk still commits atomically at one boundary.
        match self.publish_frame(chunk, None, defer_commit)? {
            FrameOutcome::Published => {}
            FrameOutcome::NoSlot(err) => return Err(FlushFailure::NotDelivered(err)),
            FrameOutcome::TooLarge(err) => {
                let row_count = chunk.row_count();
                match split_mid(row_count) {
                    Some(mid) => {
                        // Splitting publishes deferred prefix frames as it goes.
                        // If a later sub-range hits the floor, those frames sit
                        // on the wire uncommitted; tear the connection down so
                        // the drop-time best-effort commit discards them instead
                        // of committing a partial chunk under a later boundary.
                        let mut committed = false;
                        let mut result = self.publish_split(chunk, 0, mid, true, &mut committed);
                        if result.is_ok() {
                            result = self.publish_split(
                                chunk,
                                mid,
                                row_count - mid,
                                defer_commit,
                                &mut committed,
                            );
                        }
                        if let Err(e) = result {
                            self.conn.mark_must_close();
                            // A mid-split sync may already have committed a
                            // prefix. The deferred remainder is discarded on
                            // drop, but a committed prefix is real, so downgrade
                            // a "safe to retry" failure to in-doubt to avoid
                            // duplicating it.
                            return Err(if committed {
                                deny_retry_after_partial(e)
                            } else {
                                e
                            });
                        }
                    }
                    None => return Err(direct_not_delivered(err)),
                }
            }
        }

        // Once published, the chunk is no longer needed for completion/replay
        // (rule holds even if the later ACK wait fails).
        chunk.clear();

        if let WaitForAck::Yes(level) = wait {
            self.conn
                .sync_all_acks(level)
                .map_err(direct_delivery_unknown)?;
        }
        Ok(())
    }

    /// Publish one frame. `range` is `None` for the whole chunk (the hot path,
    /// no slice allocation) or `Some((offset, count))` for a sub-range while
    /// splitting. Returns [`FrameOutcome::TooLarge`] (nothing on the wire, dict
    /// rolled back) when the frame exceeds the cap so the caller can split;
    /// every other failure is a terminal [`FlushFailure`].
    fn publish_frame(
        &mut self,
        chunk: &Chunk<'_>,
        range: Option<(usize, usize)>,
        defer_commit: bool,
    ) -> std::result::Result<FrameOutcome, FlushFailure> {
        if defer_commit && !self.conn.has_sync_commit_slot() {
            return Ok(FrameOutcome::NoSlot(error::fmt!(
                InvalidApiCall,
                "column sender deferred flush capacity exhausted; call sync() \
                 before flushing more chunks."
            )));
        }

        if self.conn.at_in_flight_cap() {
            self.conn
                .drain_one_ack_blocking()
                .map_err(direct_not_delivered)?;
        }

        let dict_mark = self.symbol_dict.mark();
        let result = self.conn.publish_qwp(|out| match range {
            None => encoder::encode_chunk_into(
                out,
                chunk,
                &mut self.symbol_dict,
                &mut self.scratch,
                defer_commit,
            ),
            Some((offset, count)) => {
                let view = unsafe { chunk.slice_rows(offset, count) };
                encoder::encode_chunk_into(
                    out,
                    &view,
                    &mut self.symbol_dict,
                    &mut self.scratch,
                    defer_commit,
                )
            }
        });

        match result {
            Ok(published) => {
                self.conn.push_pending(published.fsn);
                self.first_frame_sent = true;
                Ok(FrameOutcome::Published)
            }
            Err(PublishError::BeforeWrite(e)) if e.code() == ErrorCode::BatchTooLarge => {
                self.symbol_dict.rollback(dict_mark);
                Ok(FrameOutcome::TooLarge(e))
            }
            Err(PublishError::BeforeWrite(e)) => {
                if e.code() != ErrorCode::SocketError {
                    self.symbol_dict.rollback(dict_mark);
                }
                Err(direct_not_delivered(e))
            }
            // Bytes may be on the wire: do not roll back the dict, and report
            // delivery as unknown.
            Err(PublishError::DuringWrite(e)) => Err(direct_delivery_unknown(e)),
        }
    }

    /// Publish rows `[row_offset, row_offset + row_count)`, recursively halving
    /// the range whenever a frame is still too large. The prefix half is always
    /// deferred; the tail half inherits `defer_commit` so the original commit
    /// boundary lands on the very last frame.
    fn publish_split(
        &mut self,
        chunk: &Chunk<'_>,
        row_offset: usize,
        row_count: usize,
        defer_commit: bool,
        committed: &mut bool,
    ) -> std::result::Result<(), FlushFailure> {
        let outcome =
            match self.publish_frame(chunk, Some((row_offset, row_count)), defer_commit)? {
                FrameOutcome::NoSlot(_) => {
                    // The deferred window filled mid-split. The extra frames are
                    // an internal detail the caller cannot budget for, so commit
                    // the published prefix to drain the window and retry this
                    // range — rows are split whole, so the early-committed prefix
                    // rows are complete.
                    self.sync(AckLevel::Ok)
                        .map_err(FlushFailure::DeliveryUnknown)?;
                    // The prefix is now committed on the server: a later failure
                    // anywhere in this split must not report the whole chunk as
                    // safe to blind-retry (it would duplicate this prefix).
                    *committed = true;
                    self.publish_frame(chunk, Some((row_offset, row_count)), defer_commit)?
                }
                outcome => outcome,
            };
        match outcome {
            FrameOutcome::Published => Ok(()),
            FrameOutcome::NoSlot(err) => Err(FlushFailure::NotDelivered(err)),
            FrameOutcome::TooLarge(err) => match split_mid(row_count) {
                Some(mid) => {
                    self.publish_split(chunk, row_offset, mid, true, committed)?;
                    self.publish_split(
                        chunk,
                        row_offset + mid,
                        row_count - mid,
                        defer_commit,
                        committed,
                    )
                }
                None => Err(direct_not_delivered(err)),
            },
        }
    }

    #[cfg(feature = "arrow-ingress")]
    #[allow(clippy::too_many_arguments)]
    fn flush_arrow_batch_inner(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        server_stamp: bool,
        overrides: &[ArrowColumnOverride<'_>],
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        let defer_commit = match wait {
            WaitForAck::No => self.first_frame_sent,
            WaitForAck::Yes(level) => {
                self.conn
                    .validate_ack_level(level)
                    .map_err(direct_not_delivered)?;
                false
            }
        };

        self.conn.try_drain_acks().map_err(direct_not_delivered)?;

        let spec = ArrowFrameSpec {
            table,
            batch,
            ts_col_idx,
            server_stamp,
            overrides,
        };
        // Whole-batch fast path; split the row range only when a single frame
        // exceeds the cap, all but the last deferred so the batch still commits
        // at one boundary.
        match self.publish_arrow_frame(&spec, None, defer_commit)? {
            FrameOutcome::Published => {}
            FrameOutcome::NoSlot(err) => return Err(FlushFailure::NotDelivered(err)),
            FrameOutcome::TooLarge(err) => {
                let row_count = batch.num_rows();
                match split_mid(row_count) {
                    Some(mid) => {
                        let mut committed = false;
                        let mut result =
                            self.publish_arrow_split(&spec, 0, mid, true, &mut committed);
                        if result.is_ok() {
                            result = self.publish_arrow_split(
                                &spec,
                                mid,
                                row_count - mid,
                                defer_commit,
                                &mut committed,
                            );
                        }
                        if let Err(e) = result {
                            self.conn.mark_must_close();
                            // See `flush_inner`: a mid-split sync may have
                            // committed a prefix, so a blind retry would
                            // duplicate it.
                            return Err(if committed {
                                deny_retry_after_partial(e)
                            } else {
                                e
                            });
                        }
                    }
                    None => return Err(direct_not_delivered(err)),
                }
            }
        }

        if let WaitForAck::Yes(level) = wait {
            self.conn
                .sync_all_acks(level)
                .map_err(direct_delivery_unknown)?;
        }
        Ok(())
    }

    /// Arrow counterpart of [`Self::publish_frame`]: `range` is `None` for the
    /// whole batch or `Some((offset, count))` for a zero-copy `batch.slice`
    /// sub-range while splitting.
    #[cfg(feature = "arrow-ingress")]
    fn publish_arrow_frame(
        &mut self,
        spec: &ArrowFrameSpec<'_>,
        range: Option<(usize, usize)>,
        defer_commit: bool,
    ) -> std::result::Result<FrameOutcome, FlushFailure> {
        if defer_commit && !self.conn.has_sync_commit_slot() {
            return Ok(FrameOutcome::NoSlot(error::fmt!(
                InvalidApiCall,
                "column sender deferred flush capacity exhausted; call sync() \
                 before flushing more arrow batches."
            )));
        }

        if self.conn.at_in_flight_cap() {
            self.conn
                .drain_one_ack_blocking()
                .map_err(direct_not_delivered)?;
        }

        let dict_mark = self.symbol_dict.mark();
        let sliced;
        let batch = match range {
            None => spec.batch,
            Some((offset, count)) => {
                sliced = spec.batch.slice(offset, count);
                &sliced
            }
        };
        let result = self.conn.publish_qwp(|out| {
            arrow_batch::encode_arrow_batch_into(
                out,
                spec.table,
                batch,
                spec.ts_col_idx,
                spec.server_stamp,
                spec.overrides,
                &mut self.symbol_dict,
                defer_commit,
            )
        });

        match result {
            Ok(published) => {
                self.conn.push_pending(published.fsn);
                self.first_frame_sent = true;
                Ok(FrameOutcome::Published)
            }
            Err(PublishError::BeforeWrite(e)) if e.code() == ErrorCode::BatchTooLarge => {
                self.symbol_dict.rollback(dict_mark);
                Ok(FrameOutcome::TooLarge(e))
            }
            Err(PublishError::BeforeWrite(e)) => {
                if e.code() != ErrorCode::SocketError {
                    self.symbol_dict.rollback(dict_mark);
                }
                Err(direct_not_delivered(e))
            }
            Err(PublishError::DuringWrite(e)) => Err(direct_delivery_unknown(e)),
        }
    }

    /// Arrow counterpart of [`Self::publish_split`].
    #[cfg(feature = "arrow-ingress")]
    fn publish_arrow_split(
        &mut self,
        spec: &ArrowFrameSpec<'_>,
        row_offset: usize,
        row_count: usize,
        defer_commit: bool,
        committed: &mut bool,
    ) -> std::result::Result<(), FlushFailure> {
        let outcome =
            match self.publish_arrow_frame(spec, Some((row_offset, row_count)), defer_commit)? {
                FrameOutcome::NoSlot(_) => {
                    // Same mid-split drain as `publish_split`: commit the
                    // published prefix and retry this range.
                    self.sync(AckLevel::Ok)
                        .map_err(FlushFailure::DeliveryUnknown)?;
                    // Prefix committed on the server: see `publish_split`.
                    *committed = true;
                    self.publish_arrow_frame(spec, Some((row_offset, row_count)), defer_commit)?
                }
                outcome => outcome,
            };
        match outcome {
            FrameOutcome::Published => Ok(()),
            FrameOutcome::NoSlot(err) => Err(FlushFailure::NotDelivered(err)),
            FrameOutcome::TooLarge(err) => match split_mid(row_count) {
                Some(mid) => {
                    self.publish_arrow_split(spec, row_offset, mid, true, committed)?;
                    self.publish_arrow_split(
                        spec,
                        row_offset + mid,
                        row_count - mid,
                        defer_commit,
                        committed,
                    )
                }
                None => Err(direct_not_delivered(err)),
            },
        }
    }
}

impl SfaColumnBackend {
    /// Lifted out of [`Self::sync`] so an ACKing flush can reject a
    /// durable-without-opt-in request *before* encode mutates the symbol dict
    /// or the Arrow import consumes the caller's array.
    fn validate_ack_level(&self, ack_level: AckLevel) -> Result<()> {
        if ack_level == AckLevel::Durable && !self.request_durable_ack {
            return Err(error::fmt!(
                InvalidApiCall,
                "AckLevel::Durable requires the pool to be opened with \
                 `request_durable_ack=on` in the connect string."
            ));
        }
        Ok(())
    }

    fn flush_chunk(
        &mut self,
        chunk: &mut Chunk<'_>,
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        self.flush_chunk_boundary(chunk, wait).map(|_| ())
    }

    fn flush_chunk_and_get_fsn(
        &mut self,
        chunk: &mut Chunk<'_>,
    ) -> std::result::Result<u64, FlushFailure> {
        self.flush_chunk_boundary(chunk, WaitForAck::No)
    }

    fn flush_chunk_boundary(
        &mut self,
        chunk: &mut Chunk<'_>,
        wait: WaitForAck,
    ) -> std::result::Result<u64, FlushFailure> {
        // Preflight: durable opt-in is validated before encode/append, so a
        // rejected level leaves the chunk and queue untouched.
        if let WaitForAck::Yes(level) = wait {
            self.validate_ack_level(level)
                .map_err(FlushFailure::NotDelivered)?;
        }
        if let Err(e) = qwp_ws_check_error_background(&self.state) {
            return Err(FlushFailure::NotDelivered(e));
        }
        let max_buf_size = self.effective_max_buf_size();
        // Whole-chunk fast path; only split when a single frame exceeds the cap.
        // Each split frame commits on its own (never deferred) — the
        // store-and-forward queue is frame-granular and at-least-once, so deferred
        // (uncommitted) frames could be lost on a reconnect that trims them after
        // their ack but before the commit. The boundary to wait for is the last
        // frame's FSN; its cumulative ack covers the prefix. (In delta mode the
        // frames are not individually self-sufficient; the driver re-registers the
        // dictionary via a catch-up frame on reconnect.)
        let boundary = match self.publish_chunk_sfa(chunk, None, max_buf_size)? {
            SfaOutcome::Published(fsn) => fsn,
            SfaOutcome::TooLarge(err) => {
                let row_count = chunk.row_count();
                match split_mid(row_count) {
                    Some(mid) => {
                        self.publish_split_sfa(chunk, 0, mid, max_buf_size)?;
                        // The prefix is now durably queued (at-least-once); a
                        // failure on the remainder leaves it enqueued, so the
                        // chunk must not be reported as safe to blind-retry.
                        self.publish_split_sfa(chunk, mid, row_count - mid, max_buf_size)
                            .map_err(deny_retry_after_partial)?
                    }
                    None => return Err(FlushFailure::NotDelivered(err)),
                }
            }
        };
        chunk.clear();
        if let WaitForAck::Yes(level) = wait {
            // The frame is in the local queue; a wait failure is delivery-unknown.
            self.wait_for_boundary(level, boundary, self.sync_timeout)
                .map_err(FlushFailure::DeliveryUnknown)?;
        }
        Ok(boundary)
    }

    /// Rolls the in-memory dictionary and its persisted side-file back to the
    /// marks taken at the top of a frame's publish, discarding any symbols that
    /// frame introduced. Keeps the side-file an exact mirror of the in-memory
    /// dictionary, so an id the next frame reuses never maps to an abandoned
    /// symbol on recovery. If the side-file truncate fails (a failing disk),
    /// [`PersistedSymbolDict::rollback`] poisons the on-disk file so recovery
    /// starts fresh (the torn-dict guard then fails loudly) instead of silently
    /// aliasing the reused id; drop the handle so this slot stops persisting.
    ///
    /// Dropping the handle also disables delta encoding for subsequent frames: with
    /// no side-file to write symbols ahead to, a delta frame appended from here on
    /// would be unrecoverable after a restart (its base ids are gone from the
    /// poisoned side-file). Falling back to dense (self-sufficient) frames keeps
    /// everything ingested from here on crash-recoverable without the side-file.
    ///
    /// The background driver's send mirror lives on the I/O thread and cannot be
    /// reached from here, so it stays enabled while the foreground goes dense. That is
    /// safe: the dense frames base at id 0 and re-ship the whole dictionary, which the
    /// torn-dict guard accepts as an idempotent overlap of the mirrored prefix (see
    /// `guard_dict_not_torn` in `qwp_ws_driver`) and `accumulate` keeps in lockstep.
    ///
    /// Takes the symbol fields by disjoint borrow (not `&mut self`) so
    /// [`Self::encode_persist_publish_chunk`] can roll back while the transport
    /// `state` is separately borrowed by its publish closure. Mirrors the row path's
    /// `QwpWsReplayEncoder::rollback_frame`.
    fn rollback_symbol_frame(
        symbol_dict: &mut SymbolGlobalDict,
        persisted_symbol_dict: &mut Option<PersistedSymbolDict>,
        delta_dict_enabled: &mut bool,
        dict_mark: SymbolGlobalDictMark,
        pd_mark: Option<PersistedSymbolDictMark>,
    ) {
        symbol_dict.rollback(dict_mark);
        if let Some(mark) = pd_mark {
            let truncate_failed = persisted_symbol_dict
                .as_mut()
                .is_some_and(|pd| pd.rollback(mark).is_err());
            if truncate_failed {
                *persisted_symbol_dict = None;
                *delta_dict_enabled = false;
            }
        }
    }

    /// `&mut self` wrapper over [`Self::rollback_symbol_frame`] for the Arrow
    /// publish path, which is not structured around a publish closure.
    #[cfg(feature = "arrow-ingress")]
    fn rollback_frame(
        &mut self,
        dict_mark: SymbolGlobalDictMark,
        pd_mark: Option<PersistedSymbolDictMark>,
    ) {
        Self::rollback_symbol_frame(
            &mut self.symbol_dict,
            &mut self.persisted_symbol_dict,
            &mut self.delta_dict_enabled,
            dict_mark,
            pd_mark,
        );
    }

    /// Write-ahead: appends the symbols `[from_id, next_id)` this frame introduced
    /// to the persisted side-file before the frame is published, so a recovered /
    /// orphan-drained slot can rebuild the dictionary its (non-self-sufficient)
    /// delta frame references. No-op in memory mode (no side-file). Takes the symbol
    /// fields by disjoint borrow so it composes with the transport-free
    /// [`Self::encode_persist_publish_chunk`].
    fn persist_new_symbols_into(
        symbol_dict: &SymbolGlobalDict,
        persisted_symbol_dict: &mut Option<PersistedSymbolDict>,
        from_id: u64,
    ) -> crate::Result<()> {
        let Some(pd) = persisted_symbol_dict.as_mut() else {
            return Ok(());
        };
        // Gather the frame's new symbols, then write them ahead in one batched
        // write_all rather than one alloc + one write() syscall per symbol.
        let mut new_symbols: Vec<&[u8]> = Vec::new();
        for id in from_id..symbol_dict.next_id() {
            let bytes = symbol_dict.entry(id).ok_or_else(|| {
                error::fmt!(
                    SocketError,
                    "internal: missing symbol id {} for persistence",
                    id
                )
            })?;
            new_symbols.push(bytes);
        }
        pd.append_symbols(&new_symbols)
            .map_err(|e| error::fmt!(SocketError, "could not persist symbols: {}", e))?;
        Ok(())
    }

    /// `&mut self` wrapper over [`Self::persist_new_symbols_into`] for the Arrow
    /// publish path.
    #[cfg(feature = "arrow-ingress")]
    fn persist_new_symbols(&mut self, from_id: u64) -> crate::Result<()> {
        Self::persist_new_symbols_into(&self.symbol_dict, &mut self.persisted_symbol_dict, from_id)
    }

    /// Transport-free core of [`Self::publish_chunk_sfa`]: mark the dictionary and
    /// side-file, encode `target`, size-check it, write-ahead its new symbols, then
    /// hand the payload to `publish`. On **any** failure (encode / size / persist /
    /// publish) the dictionary and side-file are rolled back together via
    /// [`Self::rollback_symbol_frame`], so the aborted frame's symbol ids are freed
    /// and reused by the next frame instead of running one step ahead of the
    /// driver's send mirror (which only advances on a successful send) and tripping
    /// the torn-dict guard.
    ///
    /// The symbol fields are passed as disjoint borrows rather than `&mut self` so
    /// the caller can lend the transport `state` to the `publish` closure without a
    /// borrow conflict; that separation is also what makes this write-ahead/rollback
    /// lockstep unit-testable with a synthetic `publish` (see the tests), mirroring
    /// the row path's `QwpWsReplayEncoder::encode_and_publish`.
    #[allow(clippy::too_many_arguments)]
    fn encode_persist_publish_chunk(
        payload: &mut Vec<u8>,
        scratch: &mut encoder::EncodeScratch,
        symbol_dict: &mut SymbolGlobalDict,
        persisted_symbol_dict: &mut Option<PersistedSymbolDict>,
        delta_dict_enabled: &mut bool,
        target: &Chunk<'_>,
        max_buf_size: usize,
        publish: impl FnOnce(&[u8]) -> std::result::Result<u64, FlushFailure>,
    ) -> std::result::Result<SfaOutcome, FlushFailure> {
        payload.clear();
        let dict_mark = symbol_dict.mark();
        let dict_len_before = symbol_dict.next_id();
        let pd_mark = persisted_symbol_dict.as_ref().map(|pd| pd.mark());
        // Delta mode ships only the ids new since the previous frame; the driver
        // re-registers the full dictionary on reconnect. Dense mode re-ships the
        // whole dictionary from id 0 so every stored frame is self-sufficient. Both
        // commit on their own (never deferred): the SFA queue is frame-granular and
        // at-least-once.
        let encoded = if *delta_dict_enabled {
            encoder::encode_chunk_into(payload, target, symbol_dict, scratch, false)
        } else {
            encoder::encode_chunk_replay_into(payload, target, symbol_dict, scratch)
        };
        if let Err(e) = encoded {
            Self::rollback_symbol_frame(
                symbol_dict,
                persisted_symbol_dict,
                delta_dict_enabled,
                dict_mark,
                pd_mark,
            );
            return Err(FlushFailure::NotDelivered(e));
        }
        if payload.len() > max_buf_size {
            Self::rollback_symbol_frame(
                symbol_dict,
                persisted_symbol_dict,
                delta_dict_enabled,
                dict_mark,
                pd_mark,
            );
            return Ok(SfaOutcome::TooLarge(error::fmt!(
                BatchTooLarge,
                "QWP frame ({} bytes) exceeds max_buf_size ({} bytes)",
                payload.len(),
                max_buf_size
            )));
        }
        // Write-ahead the frame's new symbols before publishing (file mode); on any
        // failure roll the dictionary and side-file back together so the next frame
        // reuses the freed ids without desyncing recovery.
        if let Err(e) =
            Self::persist_new_symbols_into(symbol_dict, persisted_symbol_dict, dict_len_before)
        {
            Self::rollback_symbol_frame(
                symbol_dict,
                persisted_symbol_dict,
                delta_dict_enabled,
                dict_mark,
                pd_mark,
            );
            return Err(FlushFailure::NotDelivered(e));
        }
        // Local append is atomic: a failed append did not accept the frame
        // (`NotDelivered`); the returned FSN is the boundary to wait for.
        match publish(payload) {
            Ok(fsn) => Ok(SfaOutcome::Published(fsn)),
            Err(e) => {
                Self::rollback_symbol_frame(
                    symbol_dict,
                    persisted_symbol_dict,
                    delta_dict_enabled,
                    dict_mark,
                    pd_mark,
                );
                Err(e)
            }
        }
    }

    /// Encode `range` (`None` = whole chunk, no slice allocation) as a replay
    /// frame, check it against the cap, and append it to the queue. Returns
    /// [`SfaOutcome::TooLarge`] (nothing queued, dict rolled back) when the frame
    /// exceeds the cap so the caller can split. The write-ahead/rollback lockstep
    /// lives in the transport-free [`Self::encode_persist_publish_chunk`]; this
    /// wrapper only resolves the row range and lends it the real background publish.
    fn publish_chunk_sfa(
        &mut self,
        chunk: &Chunk<'_>,
        range: Option<(usize, usize)>,
        max_buf_size: usize,
    ) -> std::result::Result<SfaOutcome, FlushFailure> {
        let view;
        let target = match range {
            None => chunk,
            Some((offset, count)) => {
                view = unsafe { chunk.slice_rows(offset, count) };
                &view
            }
        };
        let Self {
            state,
            symbol_dict,
            persisted_symbol_dict,
            delta_dict_enabled,
            scratch,
            payload,
            ..
        } = self;
        Self::encode_persist_publish_chunk(
            payload,
            scratch,
            symbol_dict,
            persisted_symbol_dict,
            delta_dict_enabled,
            target,
            max_buf_size,
            |encoded| {
                publish_qwp_ws_payload_background(state, encoded, max_buf_size)
                    .map_err(FlushFailure::NotDelivered)
            },
        )
    }

    /// Append rows `[row_offset, row_offset + row_count)`, halving the range
    /// whenever a frame is still too large. Returns the last frame's FSN.
    fn publish_split_sfa(
        &mut self,
        chunk: &Chunk<'_>,
        row_offset: usize,
        row_count: usize,
        max_buf_size: usize,
    ) -> std::result::Result<u64, FlushFailure> {
        match self.publish_chunk_sfa(chunk, Some((row_offset, row_count)), max_buf_size)? {
            SfaOutcome::Published(fsn) => Ok(fsn),
            SfaOutcome::TooLarge(err) => match split_mid(row_count) {
                Some(mid) => {
                    self.publish_split_sfa(chunk, row_offset, mid, max_buf_size)?;
                    self.publish_split_sfa(chunk, row_offset + mid, row_count - mid, max_buf_size)
                        .map_err(deny_retry_after_partial)
                }
                None => Err(FlushFailure::NotDelivered(err)),
            },
        }
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        server_stamp: bool,
        overrides: &[ArrowColumnOverride<'_>],
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        self.flush_arrow_batch_boundary(table, batch, ts_col_idx, server_stamp, overrides, wait)
            .map(|_| ())
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch_and_get_fsn(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        server_stamp: bool,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> std::result::Result<u64, FlushFailure> {
        self.flush_arrow_batch_boundary(
            table,
            batch,
            ts_col_idx,
            server_stamp,
            overrides,
            WaitForAck::No,
        )
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch_boundary(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        server_stamp: bool,
        overrides: &[ArrowColumnOverride<'_>],
        wait: WaitForAck,
    ) -> std::result::Result<u64, FlushFailure> {
        if let WaitForAck::Yes(level) = wait {
            self.validate_ack_level(level)
                .map_err(FlushFailure::NotDelivered)?;
        }
        if let Err(e) = qwp_ws_check_error_background(&self.state) {
            return Err(FlushFailure::NotDelivered(e));
        }
        let max_buf_size = self.effective_max_buf_size();
        let spec = ArrowFrameSpec {
            table,
            batch,
            ts_col_idx,
            server_stamp,
            overrides,
        };
        // Whole-batch fast path; split into self-sufficient frames only when one
        // exceeds the cap (see the rationale on `flush_chunk`).
        let boundary = match self.publish_arrow_sfa(&spec, None, max_buf_size)? {
            SfaOutcome::Published(fsn) => fsn,
            SfaOutcome::TooLarge(err) => {
                let row_count = batch.num_rows();
                match split_mid(row_count) {
                    Some(mid) => {
                        self.publish_arrow_split_sfa(&spec, 0, mid, max_buf_size)?;
                        // Prefix is durably queued; see `flush_chunk_boundary`.
                        self.publish_arrow_split_sfa(&spec, mid, row_count - mid, max_buf_size)
                            .map_err(deny_retry_after_partial)?
                    }
                    None => return Err(FlushFailure::NotDelivered(err)),
                }
            }
        };
        if let WaitForAck::Yes(level) = wait {
            self.wait_for_boundary(level, boundary, self.sync_timeout)
                .map_err(FlushFailure::DeliveryUnknown)?;
        }
        Ok(boundary)
    }

    /// Arrow counterpart of [`Self::publish_chunk_sfa`].
    #[cfg(feature = "arrow-ingress")]
    fn publish_arrow_sfa(
        &mut self,
        spec: &ArrowFrameSpec<'_>,
        range: Option<(usize, usize)>,
        max_buf_size: usize,
    ) -> std::result::Result<SfaOutcome, FlushFailure> {
        self.payload.clear();
        let dict_mark = self.symbol_dict.mark();
        let dict_len_before = self.symbol_dict.next_id();
        let pd_mark = self.persisted_symbol_dict.as_ref().map(|pd| pd.mark());
        let sliced;
        let batch = match range {
            None => spec.batch,
            Some((offset, count)) => {
                sliced = spec.batch.slice(offset, count);
                &sliced
            }
        };
        let encoded = if self.delta_dict_enabled {
            arrow_batch::encode_arrow_batch_into(
                &mut self.payload,
                spec.table,
                batch,
                spec.ts_col_idx,
                spec.server_stamp,
                spec.overrides,
                &mut self.symbol_dict,
                false,
            )
        } else {
            arrow_batch::encode_arrow_batch_replay_into(
                &mut self.payload,
                spec.table,
                batch,
                spec.ts_col_idx,
                spec.server_stamp,
                spec.overrides,
                &mut self.symbol_dict,
            )
        };
        if let Err(e) = encoded {
            self.rollback_frame(dict_mark, pd_mark);
            return Err(FlushFailure::NotDelivered(e));
        }
        if self.payload.len() > max_buf_size {
            self.rollback_frame(dict_mark, pd_mark);
            return Ok(SfaOutcome::TooLarge(error::fmt!(
                BatchTooLarge,
                "QWP frame ({} bytes) exceeds max_buf_size ({} bytes)",
                self.payload.len(),
                max_buf_size
            )));
        }
        // Write-ahead the frame's new symbols before publishing (file mode); see
        // publish_chunk_sfa.
        if let Err(e) = self.persist_new_symbols(dict_len_before) {
            self.rollback_frame(dict_mark, pd_mark);
            return Err(FlushFailure::NotDelivered(e));
        }
        match publish_qwp_ws_payload_background(&mut self.state, &self.payload, max_buf_size) {
            Ok(fsn) => Ok(SfaOutcome::Published(fsn)),
            Err(e) => {
                self.rollback_frame(dict_mark, pd_mark);
                Err(FlushFailure::NotDelivered(e))
            }
        }
    }

    /// Arrow counterpart of [`Self::publish_split_sfa`]. Returns the last
    /// frame's FSN.
    #[cfg(feature = "arrow-ingress")]
    fn publish_arrow_split_sfa(
        &mut self,
        spec: &ArrowFrameSpec<'_>,
        row_offset: usize,
        row_count: usize,
        max_buf_size: usize,
    ) -> std::result::Result<u64, FlushFailure> {
        match self.publish_arrow_sfa(spec, Some((row_offset, row_count)), max_buf_size)? {
            SfaOutcome::Published(fsn) => Ok(fsn),
            SfaOutcome::TooLarge(err) => match split_mid(row_count) {
                Some(mid) => {
                    self.publish_arrow_split_sfa(spec, row_offset, mid, max_buf_size)?;
                    self.publish_arrow_split_sfa(
                        spec,
                        row_offset + mid,
                        row_count - mid,
                        max_buf_size,
                    )
                    .map_err(deny_retry_after_partial)
                }
                None => Err(FlushFailure::NotDelivered(err)),
            },
        }
    }

    fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        self.wait(ack_level, self.sync_timeout)
    }

    fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()> {
        self.validate_ack_level(ack_level)?;
        let Some(boundary) = qwp_ws_published_fsn_background(&self.state)? else {
            return Ok(());
        };
        self.wait_for_boundary(ack_level, boundary, timeout)
    }

    fn published_fsn(&self) -> Result<Option<u64>> {
        qwp_ws_published_fsn_background(&self.state)
    }

    fn acked_fsn(&self) -> Result<Option<u64>> {
        qwp_ws_acked_fsn_background(&self.state)
    }

    /// Block until the OK/durable watermark reaches `boundary`, then record it
    /// as the satisfied watermark (so a trailing `sync(level)`/`flush_and_wait`
    /// on the same boundary short-circuits). Short-circuits immediately when the
    /// cached watermark already covers `boundary`.
    fn wait_for_boundary(
        &mut self,
        ack_level: AckLevel,
        boundary: u64,
        timeout: Duration,
    ) -> Result<()> {
        let last_boundary = match ack_level {
            AckLevel::Ok => self.last_ok_sync_boundary,
            AckLevel::Durable => self.last_durable_sync_boundary,
        };
        if last_boundary.is_some_and(|last| last >= boundary) {
            return Ok(());
        }
        let from_fsn = last_boundary.map_or(0, |last| last.saturating_add(1));

        // No-progress deadline: reset every time the ack/durable watermark
        // advances, so this only fires when the peer stays alive yet silent
        // (never advancing toward `boundary`) for `sync_timeout`. This mirrors
        // the direct backend, whose blocking read re-arms `request_timeout` on
        // every received frame and surfaces a timeout when none arrive.
        let mut deadline_anchor = Instant::now();
        let mut last_completed: Option<u64> = None;

        loop {
            if let Some(sender_error) =
                qwp_ws_poll_sender_error_in_range_background(&self.state, from_fsn, boundary)?
            {
                return Err(sfa_sender_error(sender_error));
            }

            let completed = match ack_level {
                AckLevel::Ok => qwp_ws_ok_fsn_background(&self.state)?,
                AckLevel::Durable => qwp_ws_acked_fsn_background(&self.state)?,
            };
            if completed.is_some_and(|fsn| fsn >= boundary) {
                match ack_level {
                    AckLevel::Ok => self.last_ok_sync_boundary = Some(boundary),
                    AckLevel::Durable => self.last_durable_sync_boundary = Some(boundary),
                }
                return Ok(());
            }
            if completed != last_completed {
                last_completed = completed;
                deadline_anchor = Instant::now();
            }

            qwp_ws_check_error_background(&self.state)?;

            if !timeout.is_zero() && deadline_anchor.elapsed() >= timeout {
                return Err(sfa_sync_timeout(timeout, ack_level, boundary, completed));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn effective_max_buf_size(&self) -> usize {
        let server_max = self.state.server_max_batch_size.load(Ordering::Acquire);
        if server_max == 0 {
            self.max_buf_size
        } else {
            self.max_buf_size.min(server_max)
        }
    }
}

/// The store-and-forward `wait` poll loop made no progress toward `boundary`
/// for `sync_timeout`. The connection is alive but the server is not advancing
/// the ack/durable watermark (e.g. back-pressured WAL or a stuck commit).
///
/// Classified `FailoverRetry`, but — unlike the direct backend's
/// transport-timeout path, which drops the connection and discards its
/// uncommitted frames — the local SFA queue still holds every unacked frame
/// and the background runner keeps delivering them across reborrows and
/// reconnects. Re-flushing the same data would therefore duplicate it. The
/// correct recovery is to retry `wait()` (idempotent — it only re-observes
/// the watermark) until the runner catches up, or to close/drain the pool.
/// Delivery has *not* failed; the watermark simply has not reached `boundary`
/// yet.
fn sfa_sync_timeout(
    sync_timeout: Duration,
    ack_level: AckLevel,
    boundary: u64,
    completed: Option<u64>,
) -> crate::Error {
    let level = match ack_level {
        AckLevel::Ok => "ok",
        AckLevel::Durable => "durable",
    };
    let progress = match completed {
        Some(fsn) => format!("reached FSN {}", fsn),
        None => "reached no frame".to_string(),
    };
    crate::Error::new(
        ErrorCode::FailoverRetry,
        format!(
            "QWP/WebSocket store-and-forward wait({}) timed out after {:?} \
             with no ack progress (target FSN {}, {}); the connection is alive \
             but the server is not advancing the watermark. The frames remain \
             queued and the background runner keeps delivering them: retry \
             wait() to keep awaiting the ack, or close the pool to drain. Do \
             not re-flush the same data, which is already accepted and would \
             be delivered twice.",
            level, sync_timeout, boundary, progress
        ),
    )
}

fn sfa_sender_error(sender_error: QwpWsSenderError) -> crate::Error {
    let message = sender_error
        .message
        .as_deref()
        .unwrap_or("server rejected frame");
    crate::Error::new(
        ErrorCode::ServerRejection,
        format!(
            "QWP/WebSocket server rejected store-and-forward frame range [{}, {}]: {}",
            sender_error.from_fsn, sender_error.to_fsn, message
        ),
    )
    .with_qwp_ws_rejection(sender_error)
}

#[cfg(test)]
mod tests {
    use super::split_mid;

    #[test]
    fn split_mid_floors_at_eight_rows() {
        assert_eq!(split_mid(0), None);
        assert_eq!(split_mid(1), None);
        assert_eq!(split_mid(8), None);
    }

    #[test]
    fn split_mid_returns_eight_aligned_point_below_count() {
        for count in [9usize, 12, 15, 16, 17, 100, 10_000, 16_384] {
            let mid = split_mid(count).unwrap();
            assert_eq!(
                mid % 8,
                0,
                "split point must be 8-aligned for count {count}"
            );
            assert!(mid >= 8, "split point must be at least 8 for count {count}");
            assert!(
                mid < count,
                "split point must make progress for count {count}"
            );
        }
    }

    #[test]
    fn deny_retry_after_partial_downgrades_not_delivered_and_never_upgrades() {
        use super::{FlushFailure, deny_retry_after_partial};
        use crate::{Error, ErrorCode};

        // Once a split has put a prefix on the server, a "safe to retry"
        // (`NotDelivered`) failure on the remainder must become in-doubt
        // (`DeliveryUnknown`) so the caller does not blind-retry and duplicate
        // the committed / enqueued prefix.
        let nd = FlushFailure::NotDelivered(Error::new(ErrorCode::SocketError, "boom"));
        assert!(nd.is_not_delivered());
        let downgraded = deny_retry_after_partial(nd);
        assert!(!downgraded.is_not_delivered());
        assert!(
            downgraded.into_error().in_doubt(),
            "downgraded failure must be flagged in-doubt"
        );

        // The reverse must never happen: an already in-doubt failure stays in
        // doubt — upgrading it back to retryable could cause data loss.
        let du = FlushFailure::DeliveryUnknown(Error::new(ErrorCode::SocketError, "boom"));
        let still = deny_retry_after_partial(du);
        assert!(!still.is_not_delivered());
        assert!(still.into_error().in_doubt());
    }

    // Builds a one-row chunk whose single symbol column references the sole
    // dictionary entry `sym`, so each successive frame interns exactly one new
    // symbol into the connection-scoped global dictionary.
    #[cfg(test)]
    fn one_symbol_chunk<'a>(
        codes: &'a [i32],
        offsets: &'a [i32],
        ts: &'a [i64],
        sym: &'a [u8],
    ) -> super::Chunk<'a> {
        let mut chunk = super::Chunk::new("trades");
        chunk.symbol_i32("sym", codes, offsets, sym, None).unwrap();
        chunk.at_nanos(ts).unwrap();
        chunk
    }

    #[test]
    fn column_sfa_write_ahead_rolls_back_dict_and_side_file_when_publish_fails() {
        // The *column* SFA path's write-ahead + rollback lockstep (the primary
        // QWP/WS store-and-forward path; the row encoder is dormant for it). A
        // transient, recoverable publish failure must roll BOTH the in-memory
        // dictionary and the persisted side-file back together, so the aborted
        // frame's symbol id is reused by the next frame -- never left one step ahead
        // of the driver's send mirror (which only advances on a successful send),
        // which would trip the torn-dict guard and strand the whole queue. The
        // column twin of the row path's
        // `encode_and_publish_rolls_back_dict_when_publish_fails` (qwp_ws_publisher),
        // additionally asserting the *side-file* rolls back in lockstep and mirrors
        // the live dictionary on reopen.
        use super::{FlushFailure, SfaColumnBackend, SfaOutcome};
        use crate::ErrorCode;
        use crate::error;
        use crate::ingress::buffer::SymbolGlobalDict;
        use crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

        let dir = tempfile::tempdir().unwrap();
        let mut dict = SymbolGlobalDict::new();
        let mut pd = Some(PersistedSymbolDict::open(dir.path()).unwrap());
        let mut delta = true;
        let mut scratch = super::encoder::EncodeScratch::new();
        let mut payload = Vec::new();
        let codes = [0i32];
        let offsets = [0i32, 2];

        // Frame 1: "S0" -> id 0, published OK; lands in dict + side-file.
        let chunk = one_symbol_chunk(&codes, &offsets, &[1i64], b"S0");
        let out = SfaColumnBackend::encode_persist_publish_chunk(
            &mut payload,
            &mut scratch,
            &mut dict,
            &mut pd,
            &mut delta,
            &chunk,
            usize::MAX,
            |_| Ok(1),
        )
        .unwrap();
        assert!(matches!(out, SfaOutcome::Published(1)));
        assert_eq!(dict.next_id(), 1);
        assert_eq!(dict.entry(0), Some(&b"S0"[..]));
        assert_eq!(pd.as_ref().unwrap().size(), 1);

        // Frame 2: "S1" would be id 1, but the publish fails -> the dict AND the
        // side-file must roll back so "S1" leaves no trace.
        let chunk = one_symbol_chunk(&codes, &offsets, &[2i64], b"S1");
        let err = SfaColumnBackend::encode_persist_publish_chunk(
            &mut payload,
            &mut scratch,
            &mut dict,
            &mut pd,
            &mut delta,
            &chunk,
            usize::MAX,
            |_| {
                Err(FlushFailure::NotDelivered(error::fmt!(
                    SocketError,
                    "simulated back-pressure"
                )))
            },
        )
        .unwrap_err();
        assert!(err.is_not_delivered());
        assert_eq!(err.into_error().code(), ErrorCode::SocketError);
        assert_eq!(
            dict.next_id(),
            1,
            "a failed publish must roll the dict back so ids are reused, not skipped"
        );
        assert_eq!(
            pd.as_ref().unwrap().size(),
            1,
            "the side-file must roll back in lockstep with the dict"
        );
        assert!(delta, "a clean rollback must leave delta enabled");

        // Frame 3: "S2" must REUSE the freed id 1 in both dict and side-file.
        let chunk = one_symbol_chunk(&codes, &offsets, &[3i64], b"S2");
        let out = SfaColumnBackend::encode_persist_publish_chunk(
            &mut payload,
            &mut scratch,
            &mut dict,
            &mut pd,
            &mut delta,
            &chunk,
            usize::MAX,
            |_| Ok(2),
        )
        .unwrap();
        assert!(matches!(out, SfaOutcome::Published(2)));
        assert_eq!(dict.next_id(), 2);
        assert_eq!(
            dict.entry(1),
            Some(&b"S2"[..]),
            "S2 reuses the id S1 vacated"
        );

        // Reopen the side-file: it must mirror the live dictionary exactly
        // [S0, S2], with no trace of the rolled-back S1.
        drop(pd.take());
        let reopened = PersistedSymbolDict::open(dir.path()).unwrap();
        assert_eq!(
            reopened.read_loaded_symbols(),
            vec![b"S0".to_vec(), b"S2".to_vec()]
        );
    }

    #[test]
    fn column_sfa_side_file_rollback_failure_drops_handle_and_disables_delta() {
        // When the slot's persisted side-file cannot be rolled back (a failing
        // disk), the write-ahead path must drop the side-file handle AND disable
        // delta so subsequent frames fall back to dense (self-sufficient) encoding
        // -- a delta frame the poisoned/desynced side-file can no longer rebuild on
        // recovery would strand the queued data at the send loop's torn-dict guard.
        // Injected via the side-file's fail-next-append-cleanup hook (poisons the
        // handle so the write-ahead append fails and the ensuing rollback fails
        // too), exercising `rollback_symbol_frame`'s truncate-failed branch on the
        // column path. The column twin of the row path's
        // `file_mode_side_file_rollback_failure_drops_handle_and_disables_delta`.
        use super::SfaColumnBackend;
        use crate::ErrorCode;
        use crate::ingress::buffer::SymbolGlobalDict;
        use crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

        let dir = tempfile::tempdir().unwrap();
        let mut pd_handle = PersistedSymbolDict::open(dir.path()).unwrap();
        pd_handle.arm_fail_next_append_cleanup();
        let mut dict = SymbolGlobalDict::new();
        let mut pd = Some(pd_handle);
        let mut delta = true;
        let mut scratch = super::encoder::EncodeScratch::new();
        let mut payload = Vec::new();
        let codes = [0i32];
        let offsets = [0i32, 5];

        // The frame interns a new symbol, so write-ahead appends it -- which the
        // armed hook fails, poisoning the side-file so the ensuing rollback fails
        // too. The `Ok`-returning publish closure is never reached.
        let chunk = one_symbol_chunk(&codes, &offsets, &[1i64], b"alpha");
        let err = SfaColumnBackend::encode_persist_publish_chunk(
            &mut payload,
            &mut scratch,
            &mut dict,
            &mut pd,
            &mut delta,
            &chunk,
            usize::MAX,
            |_| Ok(1),
        )
        .unwrap_err();
        assert!(err.is_not_delivered());
        let e = err.into_error();
        assert_eq!(e.code(), ErrorCode::SocketError);
        assert!(e.msg().contains("persist"), "{e}");

        assert!(
            pd.is_none(),
            "a failed side-file rollback must drop the handle"
        );
        assert!(
            !delta,
            "dropping the side-file must disable delta so frames go dense"
        );
    }
}
