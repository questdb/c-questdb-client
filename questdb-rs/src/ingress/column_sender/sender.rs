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
use crate::ingress::buffer::{Buffer, QwpWsColumnarBuffer, QwpWsEncodeScratch, SymbolGlobalDict};
use crate::ingress::sender::qwp_ws::{
    SyncQwpWsHandlerState, publish_qwp_ws_payload_background, qwp_ws_acked_fsn_background,
    qwp_ws_begin_close_background, qwp_ws_check_error_background,
    qwp_ws_drain_to_deadline_background, qwp_ws_is_terminal_background, qwp_ws_ok_fsn_background,
    qwp_ws_poll_sender_error_in_range_background, qwp_ws_published_fsn_background,
};
use crate::ingress::sender::qwp_ws_sfa_publisher::{SfaForegroundPublisher, SfaPublishOutcome};
#[cfg(feature = "arrow-ingress")]
use crate::ingress::{ColumnName, TableName};
use crate::{Result, error};

#[cfg(feature = "arrow-ingress")]
use super::arrow_batch::{self, ArrowColumnOverride, ArrowTsSource};
use super::chunk::Chunk;
use super::conn::{ColumnConn, PublishError};
use super::encoder;
use super::qwp_frame_size_error;

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

/// The immutable inputs to an Arrow-batch flush, bundled so the recursive split
/// helpers don't thread five arguments through every call. `batch.slice(...)`
/// (zero-copy) produces the sub-range views.
#[cfg(feature = "arrow-ingress")]
struct ArrowFrameSpec<'a> {
    table: TableName<'a>,
    batch: &'a RecordBatch,
    ts: ArrowTsSource,
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
/// Drives the C FFI Arrow re-export decision: `NotDelivered` may re-export the
/// caller's batch for retry; `DeliveryUnknown` must not. The
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
    /// Manual-chunk state depends on the sub-case: the chunk is cleared once
    /// publication succeeds (so an ACKing flush whose
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

pub struct PooledSenderCore {
    backend: Box<SfaBackend>,
}

/// Hidden direct sender used by whole-source DataFrame ingestion. It is a
/// distinct type from [`PooledSenderCore`] so store-and-forward-only methods
/// (Buffer publication, FSNs, and timed waits) cannot be called on it.
#[doc(hidden)]
pub struct DirectSenderCore {
    backend: Box<DirectColumnBackend>,
}

struct DirectColumnBackend {
    conn: ColumnConn,
    symbol_dict: SymbolGlobalDict,
    scratch: encoder::EncodeScratch,
    first_frame_sent: bool,
    /// A mid-split internal `sync` committed a prefix server-side since the
    /// last successful commit+ack boundary (a caller `sync` or a waited
    /// flush). While set, a failed `sync` classifies as delivery-unknown
    /// even at "provably not delivered" sites: a blind whole-operation
    /// resend would duplicate that prefix.
    commit_since_sync: bool,
}

struct SfaBackend {
    /// Owns the retained payload and the one in-memory/persisted symbol namespace
    /// shared by every pooled encoder. Declared before `state` so its side-file
    /// handle closes before the runner releases the slot lock.
    foreground: SfaForegroundPublisher,
    state: SyncQwpWsHandlerState,
    buffer_scratch: QwpWsEncodeScratch,
    scratch: encoder::EncodeScratch,
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

impl Debug for PooledSenderCore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("PooledSenderCore")
            .field(
                "must_close",
                &(self.backend.drop_on_return
                    || qwp_ws_is_terminal_background(&self.backend.state)),
            )
            .finish()
    }
}

impl Debug for DirectSenderCore {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirectSenderCore")
            .field("must_close", &self.backend.conn.must_close())
            .field("in_flight", &self.backend.conn.in_flight())
            .finish()
    }
}

impl PooledSenderCore {
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
        // side-file for write-ahead -- the standalone replay encoder in this state
        // is dormant for the pooled core, so connect_sfa_background left the
        // side-file for us.
        let delta_dict_enabled = state.delta_dict_enabled;
        let persisted_symbol_dict = state.persisted_symbol_dict.take();
        let mut foreground = SfaForegroundPublisher::new(delta_dict_enabled, persisted_symbol_dict);
        if delta_dict_enabled {
            // Take the recovered entries so the (potentially large) buffer is freed
            // after seeding rather than living dead in `state` -- which the backend
            // holds for its whole life -- for the connection's duration.
            let recovered = std::mem::take(&mut state.recovered_dict_entries);
            foreground.seed(&recovered, state.recovered_dict_count)?;
        }
        // The standalone replay encoder in `state` is dormant for the pooled core
        // (the foreground above owns the live dictionary); release the recovered
        // dictionary seeded into it at connect so it is not carried dead for the
        // connection's life -- matching the `recovered_dict_entries` take above.
        state.release_dormant_encoder_dict();
        Ok(Self {
            backend: Box::new(SfaBackend {
                foreground,
                state,
                buffer_scratch: QwpWsEncodeScratch::new(),
                scratch: encoder::EncodeScratch::new(),
                max_buf_size,
                request_durable_ack,
                sync_timeout,
                last_ok_sync_boundary: None,
                last_durable_sync_boundary: None,
                drop_on_return: false,
            }),
        })
    }

    #[must_use]
    pub fn must_close(&self) -> bool {
        self.backend.drop_on_return || qwp_ws_is_terminal_background(&self.backend.state)
    }

    pub fn mark_must_close(&mut self) {
        self.backend.drop_on_return = true;
    }

    /// Non-blocking: `true` once the store-and-forward backend has no
    /// undelivered frames — every published frame has reached the pool's ack
    /// watermark (durable when `durable`, otherwise the OK watermark) — so the
    /// connection can be retired without losing data. A terminal backend
    /// reports `true`: its queued frames are already unrecoverable.
    ///
    /// The pool reaper uses this to avoid evicting an idle connection whose
    /// background runner is still flushing.
    pub(crate) fn sfa_fully_delivered(&self, durable: bool) -> bool {
        let sfa = &self.backend;
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
    /// [`Self::drain_to_deadline`].
    pub(crate) fn begin_close(&self) {
        qwp_ws_begin_close_background(&self.backend.state);
    }

    /// Block until the store-and-forward queue has delivered every published
    /// frame, or `deadline` elapses. `Ok(())` means fully drained (or nothing
    /// was queued); `Err` means the drain timed out or the transport went
    /// terminal with frames still undelivered.
    pub(crate) fn drain_to_deadline(&mut self, deadline: Option<Instant>) -> crate::Result<()> {
        qwp_ws_drain_to_deadline_background(&mut self.backend.state, deadline)
    }

    /// Encode and publish `chunk` into the store-and-forward queue without
    /// waiting for a server completion boundary.
    pub fn flush(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        self.backend
            .flush_chunk(chunk, WaitForAck::No)
            .map_err(FlushFailure::into_error)
    }

    /// Encode and publish a QWP/WebSocket row [`Buffer`] into the local
    /// store-and-forward queue. The buffer is cleared only after local
    /// publication succeeds.
    pub fn flush_buffer(&mut self, buffer: &mut Buffer) -> Result<()> {
        self.flush_buffer_and_get_fsn(buffer).map(|_| ())
    }

    /// Encode and publish a QWP/WebSocket row [`Buffer`] without clearing it.
    pub fn flush_buffer_and_keep(&mut self, buffer: &Buffer) -> Result<()> {
        self.flush_buffer_and_keep_and_get_fsn(buffer).map(|_| ())
    }

    /// Publish a QWP/WebSocket row [`Buffer`], clear it after local acceptance,
    /// and return the frame sequence number. Empty buffers publish no frame and
    /// return `None`.
    pub fn flush_buffer_and_get_fsn(&mut self, buffer: &mut Buffer) -> Result<Option<u64>> {
        let fsn = self.publish_buffer(buffer, None)?;
        buffer.clear();
        Ok(fsn)
    }

    /// Publish a QWP/WebSocket row [`Buffer`] without clearing it and return the
    /// frame sequence number. Empty buffers publish no frame and return `None`.
    pub fn flush_buffer_and_keep_and_get_fsn(&mut self, buffer: &Buffer) -> Result<Option<u64>> {
        self.publish_buffer(buffer, None)
    }

    /// Publish a QWP/WebSocket row [`Buffer`] as a completion boundary, clear
    /// it after local acceptance, and wait for every prior publication to reach
    /// `ack_level`. A wait failure after publication still leaves the buffer
    /// cleared because replay is owned by the store-and-forward queue.
    pub fn flush_buffer_and_wait(
        &mut self,
        buffer: &mut Buffer,
        ack_level: AckLevel,
    ) -> Result<()> {
        let boundary = self.publish_buffer(buffer, Some(ack_level))?;
        buffer.clear();

        let sfa = &mut self.backend;
        match boundary {
            Some(fsn) => sfa
                .wait_for_boundary(ack_level, fsn, sfa.sync_timeout)
                .map_err(FlushFailure::DeliveryUnknown)
                .map_err(FlushFailure::into_error),
            None => sfa.wait(ack_level, sfa.sync_timeout),
        }
    }

    fn publish_buffer(
        &mut self,
        buffer: &Buffer,
        ack_level: Option<AckLevel>,
    ) -> Result<Option<u64>> {
        let qwp = buffer.as_qwp_ws().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "Pooled QWP ingestion requires a QWP/WebSocket buffer created by `QuestDb::new_buffer()`."
            )
        })?;
        self.backend
            .publish_buffer(qwp, ack_level)
            .map_err(FlushFailure::into_error)
    }

    /// Store-and-forward only: encode and publish `chunk` into the local SFA
    /// queue and return the last published frame sequence number. If a chunk is
    /// split into multiple frames, the returned FSN is the final frame boundary;
    /// cumulative ACK coverage of that boundary covers the whole chunk.
    pub fn flush_and_get_fsn(&mut self, chunk: &mut Chunk<'_>) -> Result<Option<u64>> {
        self.backend
            .flush_chunk_and_get_fsn(chunk)
            .map(Some)
            .map_err(FlushFailure::into_error)
    }

    /// Publish `chunk` as a completion boundary, then wait until every frame
    /// published before or by this call on this borrowed sender reaches
    /// `ack_level`.
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
        self.backend
            .flush_chunk(chunk, WaitForAck::Yes(ack_level))
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
        self.flush_arrow_batch_dispatch(
            table,
            batch,
            ArrowTsSource::ServerNow,
            overrides,
            WaitForAck::No,
        )
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
        self.flush_arrow_batch_dispatch_get_fsn(table, batch, ArrowTsSource::ServerNow, overrides)
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
            ArrowTsSource::ServerNow,
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
            ArrowTsSource::Column(ts_col_idx),
            overrides,
            WaitForAck::No,
        )
        .map_err(FlushFailure::into_error)
    }

    /// Encode and publish an Arrow [`RecordBatch`] with one scalar
    /// nanosecond-precision Unix epoch timestamp as every row's designated
    /// timestamp, encoded as a repeated constant. Unlike
    /// [`Self::flush_arrow_batch_at_now`] the value is fixed at the caller,
    /// so resubmission is idempotent under `DEDUP UPSERT KEYS`. Rejects
    /// negative (pre-epoch) values.
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_scalar_nanos<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        nanos: i64,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        self.flush_arrow_batch_dispatch(
            table,
            batch,
            ArrowTsSource::ScalarNanos(nanos),
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
        self.flush_arrow_batch_dispatch_get_fsn(
            table,
            batch,
            ArrowTsSource::Column(ts_col_idx),
            overrides,
        )
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
            ArrowTsSource::Column(ts_col_idx),
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
        ts: ArrowTsSource,
        overrides: &[ArrowColumnOverride<'_>],
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        self.backend
            .flush_arrow_batch(table, batch, ts, overrides, wait)
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch_dispatch_get_fsn(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts: ArrowTsSource,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> std::result::Result<Option<u64>, FlushFailure> {
        self.backend
            .flush_arrow_batch_and_get_fsn(table, batch, ts, overrides)
            .map(Some)
    }

    /// Preflight ACK-level validation for the C FFI ACKing-flush entry points.
    /// Run before the Arrow C Data Interface import consumes `array->release`
    /// (and before chunk encode), so a rejected `AckLevel::Durable` leaves
    /// caller-owned input untouched.
    #[doc(hidden)]
    pub fn validate_ack_level(&self, ack_level: AckLevel) -> Result<()> {
        self.backend.validate_ack_level(ack_level)
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
            ArrowTsSource::ServerNow,
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
            ArrowTsSource::Column(ts_col_idx),
            overrides,
            WaitForAck::Yes(ack_level),
        )
    }

    pub fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        self.backend.sync(ack_level)
    }

    /// Store-and-forward only: wait up to `timeout` for every frame published
    /// so far to reach `ack_level`. `timeout` is a no-progress deadline — it
    /// fires only if the ack watermark fails to advance for that long;
    /// `Duration::ZERO` waits indefinitely. On expiry it returns a
    /// [`ErrorCode::FailoverRetry`](crate::ErrorCode::FailoverRetry)
    /// error and the queued frames are retained for replay.
    pub fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()> {
        self.backend.wait(ack_level, timeout)
    }

    /// Store-and-forward only: return the highest frame sequence number
    /// published locally by this sender, or `None` if no frame has been
    /// published.
    pub fn published_fsn(&self) -> Result<Option<u64>> {
        self.backend.published_fsn()
    }

    /// Store-and-forward only: return the highest frame sequence number
    /// completed by server ACK or server-side reject-and-continue, or `None`
    /// if no frame has completed.
    pub fn acked_fsn(&self) -> Result<Option<u64>> {
        self.backend.acked_fsn()
    }
}

impl DirectSenderCore {
    pub(crate) fn new(
        conn: ColumnConn,
        symbol_dict: SymbolGlobalDict,
        scratch: encoder::EncodeScratch,
        first_frame_sent: bool,
    ) -> Self {
        Self {
            backend: Box::new(DirectColumnBackend {
                conn,
                symbol_dict,
                scratch,
                first_frame_sent,
                commit_since_sync: false,
            }),
        }
    }

    #[must_use]
    pub fn must_close(&self) -> bool {
        self.backend.conn.must_close()
    }

    pub fn mark_must_close(&mut self) {
        self.backend.conn.mark_must_close();
    }

    pub(crate) fn in_flight(&self) -> u32 {
        self.backend.conn.in_flight()
    }

    pub(crate) fn transport_dead(&self) -> bool {
        self.backend.conn.transport_dead()
    }

    pub(crate) fn endpoint_idx(&self) -> usize {
        self.backend.conn.endpoint_idx()
    }

    pub fn flush(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        self.backend
            .flush_inner(chunk, WaitForAck::No)
            .map_err(FlushFailure::into_error)
    }

    pub fn flush_and_wait(&mut self, chunk: &mut Chunk<'_>, ack_level: AckLevel) -> Result<()> {
        self.backend
            .flush_inner(chunk, WaitForAck::Yes(ack_level))
            .map_err(FlushFailure::into_error)
    }

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
        self.backend
            .flush_arrow_batch_inner(
                table,
                batch,
                ArrowTsSource::ServerNow,
                overrides,
                WaitForAck::No,
            )
            .map_err(FlushFailure::into_error)
    }

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
        self.backend
            .flush_arrow_batch_inner(
                table,
                batch,
                ArrowTsSource::Column(ts_col_idx),
                overrides,
                WaitForAck::No,
            )
            .map_err(FlushFailure::into_error)
    }

    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_scalar_nanos<'t, T>(
        &mut self,
        table: T,
        batch: &RecordBatch,
        nanos: i64,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<()>
    where
        T: TryInto<TableName<'t>>,
        crate::Error: From<T::Error>,
    {
        let table: TableName<'t> = table.try_into()?;
        self.backend
            .flush_arrow_batch_inner(
                table,
                batch,
                ArrowTsSource::ScalarNanos(nanos),
                overrides,
                WaitForAck::No,
            )
            .map_err(FlushFailure::into_error)
    }

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
        self.backend
            .flush_arrow_batch_inner(
                table,
                batch,
                ArrowTsSource::ServerNow,
                overrides,
                WaitForAck::Yes(ack_level),
            )
            .map_err(FlushFailure::into_error)
    }

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
        self.backend
            .flush_arrow_batch_inner(
                table,
                batch,
                ArrowTsSource::Column(ts_col_idx),
                overrides,
                WaitForAck::Yes(ack_level),
            )
            .map_err(FlushFailure::into_error)
    }

    #[doc(hidden)]
    pub fn validate_ack_level(&self, ack_level: AckLevel) -> Result<()> {
        self.backend.conn.validate_ack_level(ack_level)
    }

    #[doc(hidden)]
    #[cfg(feature = "arrow-ingress")]
    pub fn flush_arrow_batch_at_now_and_wait_ffi(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        overrides: &[ArrowColumnOverride<'_>],
        ack_level: AckLevel,
    ) -> std::result::Result<(), FlushFailure> {
        self.backend.flush_arrow_batch_inner(
            table,
            batch,
            ArrowTsSource::ServerNow,
            overrides,
            WaitForAck::Yes(ack_level),
        )
    }

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
        self.backend.flush_arrow_batch_inner(
            table,
            batch,
            ArrowTsSource::Column(ts_col_idx),
            overrides,
            WaitForAck::Yes(ack_level),
        )
    }

    pub fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        self.backend.sync(ack_level)
    }
}

impl DirectColumnBackend {
    fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        // An ACKing flush of an empty chunk *is* `sync`: it publishes a
        // non-deferred header-only commit frame, then drains to the ack level
        // (`sync_all_acks`). `sync` is not a data flush, so it must leave the
        // deferral state untouched — the next data flush still chooses defer
        // from `first_frame_sent` exactly as before.
        //
        // Pending deferred frames die uncommitted with the connection, so a
        // failure before this sync's commit frame could reach the wire is
        // genuinely not-delivered and a whole-operation resend is safe —
        // unless a mid-split internal sync already committed a prefix
        // (`commit_since_sync`): then the same sites must report
        // delivery-unknown or a blind resend would duplicate that prefix.
        let first_frame_sent = self.first_frame_sent;
        let mut commit_chunk = Chunk::new("");
        let mut result = self.flush_inner(&mut commit_chunk, WaitForAck::Yes(ack_level));
        self.first_frame_sent = first_frame_sent;
        if self.commit_since_sync {
            result = result.map_err(deny_retry_after_partial);
        }
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
            self.commit_since_sync = false;
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
                    self.commit_since_sync = true;
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
        ts: ArrowTsSource,
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
            ts,
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
            self.commit_since_sync = false;
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
                spec.ts,
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
                    self.commit_since_sync = true;
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

impl SfaBackend {
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

    fn publish_buffer(
        &mut self,
        buffer: &QwpWsColumnarBuffer,
        ack_level: Option<AckLevel>,
    ) -> std::result::Result<Option<u64>, FlushFailure> {
        if let Some(level) = ack_level {
            self.validate_ack_level(level)
                .map_err(FlushFailure::NotDelivered)?;
        }
        if let Err(err) = qwp_ws_check_error_background(&self.state) {
            return Err(FlushFailure::NotDelivered(err));
        }
        if buffer.is_empty() {
            return Ok(None);
        }

        let max_buf_size = self.effective_max_buf_size();
        let Self {
            foreground,
            state,
            buffer_scratch,
            ..
        } = self;
        match foreground
            .encode_persist_publish(
                max_buf_size,
                |payload, symbol_dict, delta_enabled| {
                    buffer.encode_ws_replay_message_with_defer(
                        payload,
                        buffer_scratch,
                        symbol_dict,
                        super::wire::QWP_VERSION_1,
                        false,
                        delta_enabled,
                    )
                },
                |payload| publish_qwp_ws_payload_background(state, payload, max_buf_size),
            )
            .map_err(FlushFailure::NotDelivered)?
        {
            SfaPublishOutcome::Published(fsn) => Ok(Some(fsn)),
            SfaPublishOutcome::TooLarge {
                encoded_len,
                max_buf_size,
            } => Err(FlushFailure::NotDelivered(qwp_frame_size_error(
                encoded_len,
                max_buf_size,
            ))),
        }
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
            SfaPublishOutcome::Published(fsn) => fsn,
            SfaPublishOutcome::TooLarge {
                encoded_len,
                max_buf_size,
            } => {
                let err = qwp_frame_size_error(encoded_len, max_buf_size);
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

    /// Encode `range` (`None` = whole chunk, no slice allocation) as a replay
    /// frame, check it against the cap, and append it to the queue. Returns
    /// [`SfaPublishOutcome::TooLarge`] (nothing queued, dict rolled back) when the
    /// frame exceeds the cap so the caller can split.
    fn publish_chunk_sfa(
        &mut self,
        chunk: &Chunk<'_>,
        range: Option<(usize, usize)>,
        max_buf_size: usize,
    ) -> std::result::Result<SfaPublishOutcome, FlushFailure> {
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
            foreground,
            scratch,
            ..
        } = self;
        foreground
            .encode_persist_publish(
                max_buf_size,
                |payload, symbol_dict, delta_enabled| {
                    if delta_enabled {
                        encoder::encode_chunk_into(payload, target, symbol_dict, scratch, false)
                    } else {
                        encoder::encode_chunk_replay_into(payload, target, symbol_dict, scratch)
                    }
                },
                |encoded| publish_qwp_ws_payload_background(state, encoded, max_buf_size),
            )
            .map_err(FlushFailure::NotDelivered)
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
            SfaPublishOutcome::Published(fsn) => Ok(fsn),
            SfaPublishOutcome::TooLarge {
                encoded_len,
                max_buf_size,
            } => match split_mid(row_count) {
                Some(mid) => {
                    self.publish_split_sfa(chunk, row_offset, mid, max_buf_size)?;
                    self.publish_split_sfa(chunk, row_offset + mid, row_count - mid, max_buf_size)
                        .map_err(deny_retry_after_partial)
                }
                None => Err(FlushFailure::NotDelivered(qwp_frame_size_error(
                    encoded_len,
                    max_buf_size,
                ))),
            },
        }
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts: ArrowTsSource,
        overrides: &[ArrowColumnOverride<'_>],
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        self.flush_arrow_batch_boundary(table, batch, ts, overrides, wait)
            .map(|_| ())
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch_and_get_fsn(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts: ArrowTsSource,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> std::result::Result<u64, FlushFailure> {
        self.flush_arrow_batch_boundary(table, batch, ts, overrides, WaitForAck::No)
    }

    #[cfg(feature = "arrow-ingress")]
    fn flush_arrow_batch_boundary(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts: ArrowTsSource,
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
            ts,
            overrides,
        };
        // Whole-batch fast path; split into self-sufficient frames only when one
        // exceeds the cap (see the rationale on `flush_chunk`).
        let boundary = match self.publish_arrow_sfa(&spec, None, max_buf_size)? {
            SfaPublishOutcome::Published(fsn) => fsn,
            SfaPublishOutcome::TooLarge {
                encoded_len,
                max_buf_size,
            } => {
                let err = qwp_frame_size_error(encoded_len, max_buf_size);
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
    ) -> std::result::Result<SfaPublishOutcome, FlushFailure> {
        let sliced;
        let batch = match range {
            None => spec.batch,
            Some((offset, count)) => {
                sliced = spec.batch.slice(offset, count);
                &sliced
            }
        };
        let Self {
            state, foreground, ..
        } = self;
        foreground
            .encode_persist_publish(
                max_buf_size,
                |payload, symbol_dict, delta_enabled| {
                    if delta_enabled {
                        arrow_batch::encode_arrow_batch_into(
                            payload,
                            spec.table,
                            batch,
                            spec.ts,
                            spec.overrides,
                            symbol_dict,
                            false,
                        )
                    } else {
                        arrow_batch::encode_arrow_batch_replay_into(
                            payload,
                            spec.table,
                            batch,
                            spec.ts,
                            spec.overrides,
                            symbol_dict,
                        )
                    }
                },
                |payload| publish_qwp_ws_payload_background(state, payload, max_buf_size),
            )
            .map_err(FlushFailure::NotDelivered)
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
            SfaPublishOutcome::Published(fsn) => Ok(fsn),
            SfaPublishOutcome::TooLarge {
                encoded_len,
                max_buf_size,
            } => match split_mid(row_count) {
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
                None => Err(FlushFailure::NotDelivered(qwp_frame_size_error(
                    encoded_len,
                    max_buf_size,
                ))),
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
}
