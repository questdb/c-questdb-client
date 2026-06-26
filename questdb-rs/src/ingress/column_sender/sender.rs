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
use crate::ingress::QwpWsSenderError;
use crate::ingress::buffer::SymbolGlobalDict;
use crate::ingress::sender::qwp_ws::{
    SyncQwpWsHandlerState, publish_qwp_ws_payload_background, qwp_ws_acked_fsn_background,
    qwp_ws_check_error_background, qwp_ws_is_terminal_background, qwp_ws_ok_fsn_background,
    qwp_ws_poll_sender_error_in_range_background, qwp_ws_published_fsn_background,
};
#[cfg(feature = "arrow")]
use crate::ingress::{ColumnName, TableName};
use crate::{Result, error};

#[cfg(feature = "arrow")]
use super::arrow_batch::{self, ArrowColumnOverride};
use super::chunk::Chunk;
use super::conn::{ColumnConn, PublishError};
use super::encoder;

#[cfg(feature = "arrow")]
use arrow_array::RecordBatch;

fn classify_flush_error(err: crate::Error) -> crate::Error {
    if err.code() == ErrorCode::SocketError {
        return crate::Error::new(ErrorCode::FailoverRetry, err.msg().to_owned());
    }
    err
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckLevel {
    #[default]
    Ok,
    Durable,
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

pub struct ColumnSender {
    backend: ColumnSenderBackend,
}

enum ColumnSenderBackend {
    Direct(DirectColumnBackend),
    StoreAndForward(SfaColumnBackend),
}

struct DirectColumnBackend {
    conn: ColumnConn,
    symbol_dict: SymbolGlobalDict,
    scratch: encoder::EncodeScratch,
    first_frame_sent: bool,
}

struct SfaColumnBackend {
    state: SyncQwpWsHandlerState,
    symbol_dict: SymbolGlobalDict,
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
            backend: ColumnSenderBackend::Direct(DirectColumnBackend {
                conn,
                symbol_dict,
                scratch,
                first_frame_sent,
            }),
        }
    }

    pub(crate) fn new_store_and_forward(
        state: SyncQwpWsHandlerState,
        max_buf_size: usize,
        request_durable_ack: bool,
        sync_timeout: Duration,
    ) -> Self {
        Self {
            backend: ColumnSenderBackend::StoreAndForward(SfaColumnBackend {
                state,
                symbol_dict: SymbolGlobalDict::new(),
                scratch: encoder::EncodeScratch::new(),
                payload: Vec::new(),
                max_buf_size,
                request_durable_ack,
                sync_timeout,
                last_ok_sync_boundary: None,
                last_durable_sync_boundary: None,
                drop_on_return: false,
            }),
        }
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

    /// Override the store-and-forward `sync` no-progress deadline. Tests use
    /// this to exercise the timeout without waiting for the production default
    /// (`request_timeout`, 30s). No-op on the direct backend.
    #[cfg(test)]
    pub(crate) fn set_sfa_sync_timeout_for_test(&mut self, timeout: Duration) {
        if let ColumnSenderBackend::StoreAndForward(sfa) = &mut self.backend {
            sfa.sync_timeout = timeout;
        }
    }

    pub(crate) fn in_flight(&self) -> u32 {
        match &self.backend {
            ColumnSenderBackend::Direct(direct) => direct.conn.in_flight(),
            ColumnSenderBackend::StoreAndForward(_) => 0,
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
    #[cfg(feature = "arrow")]
    pub fn flush_arrow_batch_server_stamped<'t, T>(
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

    /// ACKing counterpart of [`Self::flush_arrow_batch_server_stamped`]:
    /// publish `batch` as a boundary, then wait for `ack_level`. The same
    /// boundary/durable/failure contract as [`Self::flush_and_wait`] applies.
    #[cfg(feature = "arrow")]
    pub fn flush_arrow_batch_server_stamped_and_wait<'t, T>(
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
    /// Use [`Self::flush_arrow_batch_server_stamped`] to instead let the server
    /// stamp each row on arrival.
    #[cfg(feature = "arrow")]
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

    /// ACKing counterpart of [`Self::flush_arrow_batch_at_column`]: publish
    /// `batch` as a boundary, then wait for `ack_level`. The same
    /// boundary/durable/failure contract as [`Self::flush_and_wait`] applies.
    #[cfg(feature = "arrow")]
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
    #[cfg(feature = "arrow")]
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
    #[cfg(feature = "arrow")]
    pub fn flush_arrow_batch_server_stamped_and_wait_ffi(
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
    #[cfg(feature = "arrow")]
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

        if defer_commit && !self.conn.has_sync_commit_slot() {
            return Err(FlushFailure::NotDelivered(error::fmt!(
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
        let published = match self.conn.publish_qwp(|out| {
            encoder::encode_chunk_into(
                out,
                chunk,
                &mut self.symbol_dict,
                &mut self.scratch,
                defer_commit,
            )
        }) {
            Ok(p) => p,
            Err(PublishError::BeforeWrite(e)) => {
                if e.code() != ErrorCode::SocketError {
                    self.symbol_dict.rollback(dict_mark);
                }
                return Err(direct_not_delivered(e));
            }
            // Bytes may be on the wire: do not roll back the dict, and report
            // delivery as unknown.
            Err(PublishError::DuringWrite(e)) => return Err(direct_delivery_unknown(e)),
        };

        self.conn.push_pending(published.fsn);
        // Once published, the chunk is no longer needed for completion/replay
        // (rule holds even if the later ACK wait fails).
        chunk.clear();
        self.first_frame_sent = true;

        if let WaitForAck::Yes(level) = wait {
            self.conn
                .sync_all_acks(level)
                .map_err(direct_delivery_unknown)?;
        }
        Ok(())
    }

    #[cfg(feature = "arrow")]
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

        if defer_commit && !self.conn.has_sync_commit_slot() {
            return Err(FlushFailure::NotDelivered(error::fmt!(
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
        let published = match self.conn.publish_qwp(|out| {
            arrow_batch::encode_arrow_batch_into(
                out,
                table,
                batch,
                ts_col_idx,
                server_stamp,
                overrides,
                &mut self.symbol_dict,
                defer_commit,
            )
        }) {
            Ok(p) => p,
            Err(PublishError::BeforeWrite(e)) => {
                if e.code() != ErrorCode::SocketError {
                    self.symbol_dict.rollback(dict_mark);
                }
                return Err(direct_not_delivered(e));
            }
            Err(PublishError::DuringWrite(e)) => return Err(direct_delivery_unknown(e)),
        };

        self.conn.push_pending(published.fsn);
        self.first_frame_sent = true;

        if let WaitForAck::Yes(level) = wait {
            self.conn
                .sync_all_acks(level)
                .map_err(direct_delivery_unknown)?;
        }
        Ok(())
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
        // Preflight: durable opt-in is validated before encode/append, so a
        // rejected level leaves the chunk and queue untouched.
        if let WaitForAck::Yes(level) = wait {
            self.validate_ack_level(level)
                .map_err(FlushFailure::NotDelivered)?;
        }
        if let Err(e) = qwp_ws_check_error_background(&self.state) {
            return Err(FlushFailure::NotDelivered(e));
        }
        self.payload.clear();
        let dict_mark = self.symbol_dict.mark();
        if let Err(e) = encoder::encode_chunk_replay_into(
            &mut self.payload,
            chunk,
            &mut self.symbol_dict,
            &mut self.scratch,
        ) {
            self.symbol_dict.rollback(dict_mark);
            return Err(FlushFailure::NotDelivered(e));
        }
        let max_buf_size = self.effective_max_buf_size();
        // Local append is atomic: a failed append did not accept the frame
        // (`NotDelivered`); the returned FSN is the boundary to wait for.
        let boundary =
            match publish_qwp_ws_payload_background(&mut self.state, &self.payload, max_buf_size) {
                Ok(fsn) => fsn,
                Err(e) => {
                    self.symbol_dict.rollback(dict_mark);
                    return Err(FlushFailure::NotDelivered(e));
                }
            };
        chunk.clear();
        if let WaitForAck::Yes(level) = wait {
            // The frame is in the local queue; a wait failure is delivery-unknown.
            self.wait_for_boundary(level, boundary)
                .map_err(FlushFailure::DeliveryUnknown)?;
        }
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn flush_arrow_batch(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        server_stamp: bool,
        overrides: &[ArrowColumnOverride<'_>],
        wait: WaitForAck,
    ) -> std::result::Result<(), FlushFailure> {
        if let WaitForAck::Yes(level) = wait {
            self.validate_ack_level(level)
                .map_err(FlushFailure::NotDelivered)?;
        }
        if let Err(e) = qwp_ws_check_error_background(&self.state) {
            return Err(FlushFailure::NotDelivered(e));
        }
        self.payload.clear();
        let dict_mark = self.symbol_dict.mark();
        if let Err(e) = arrow_batch::encode_arrow_batch_replay_into(
            &mut self.payload,
            table,
            batch,
            ts_col_idx,
            server_stamp,
            overrides,
            &mut self.symbol_dict,
        ) {
            self.symbol_dict.rollback(dict_mark);
            return Err(FlushFailure::NotDelivered(e));
        }
        let max_buf_size = self.effective_max_buf_size();
        let boundary =
            match publish_qwp_ws_payload_background(&mut self.state, &self.payload, max_buf_size) {
                Ok(fsn) => fsn,
                Err(e) => {
                    self.symbol_dict.rollback(dict_mark);
                    return Err(FlushFailure::NotDelivered(e));
                }
            };
        if let WaitForAck::Yes(level) = wait {
            self.wait_for_boundary(level, boundary)
                .map_err(FlushFailure::DeliveryUnknown)?;
        }
        Ok(())
    }

    fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        self.validate_ack_level(ack_level)?;
        let Some(boundary) = qwp_ws_published_fsn_background(&self.state)? else {
            return Ok(());
        };
        self.wait_for_boundary(ack_level, boundary)
    }

    /// Block until the OK/durable watermark reaches `boundary`, then record it
    /// as the satisfied watermark (so a trailing `sync(level)`/`flush_and_wait`
    /// on the same boundary short-circuits). Short-circuits immediately when the
    /// cached watermark already covers `boundary`.
    fn wait_for_boundary(&mut self, ack_level: AckLevel, boundary: u64) -> Result<()> {
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

            if !self.sync_timeout.is_zero() && deadline_anchor.elapsed() >= self.sync_timeout {
                return Err(sfa_sync_timeout(
                    self.sync_timeout,
                    ack_level,
                    boundary,
                    completed,
                ));
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

/// The store-and-forward `sync` poll loop made no progress toward `boundary`
/// for `sync_timeout`. The connection is alive but the server is not advancing
/// the ack/durable watermark (e.g. back-pressured WAL or a stuck commit).
///
/// Classified `FailoverRetry` — the local SFA queue still holds every unacked
/// frame, so the caller can drop this borrow and re-borrow to replay, exactly
/// as on the direct backend's transport-timeout path. The sync has *not*
/// committed; the watermark simply has not reached `boundary` yet.
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
            "QWP/WebSocket store-and-forward sync({}) timed out after {:?} \
             with no ack progress (target FSN {}, {}); the connection is alive \
             but the server is not advancing the watermark. The queued frames \
             are retained; drop this sender and re-borrow to replay.",
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
