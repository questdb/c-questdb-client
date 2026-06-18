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
//!
//! A [`ColumnSender`] owns one pipelined QWP/WebSocket connection
//! ([`super::conn::ColumnConn`]) and a connection-scoped
//! [`SymbolGlobalDict`]: both travel back into the pool together when the
//! [`super::BorrowedSender`] is dropped.

use std::fmt::{self, Debug, Formatter};

use crate::ErrorCode;
use crate::ingress::buffer::SymbolGlobalDict;
#[cfg(feature = "arrow")]
use crate::ingress::{ColumnName, TableName};
use crate::{Result, error};

#[cfg(feature = "arrow")]
use super::arrow_batch::{self, ArrowColumnOverride};
use super::chunk::Chunk;
use super::conn::ColumnConn;
use super::encoder;

#[cfg(feature = "arrow")]
use arrow_array::RecordBatch;

/// Map a flush/sync failure onto the failover taxonomy.
///
/// Transport-level failures — connection reset, EOF, server-closed, framing
/// errors — surface from [`ColumnConn`] as [`ErrorCode::SocketError`] and are
/// **transient**: a fresh connection from the pool (which rotates to a live
/// endpoint) can re-drive the uncommitted tail. We re-tag these
/// [`ErrorCode::FailoverRetry`] so callers can tell "retry on a fresh conn"
/// from "give up".
///
/// Everything else stays terminal: `AuthError` / `ProtocolVersionError`
/// (credentials / negotiation), `ServerFlushError` and `ServerRejection`
/// (the server refused the *data*), and `InvalidApiCall` / schema rejections
/// (a re-drive would fail identically until the retry budget drains). This is
/// the finer split the failover design calls for over the row API's coarse
/// `reconnect_error_is_terminal`.
fn classify_flush_error(err: crate::Error) -> crate::Error {
    if err.code() == ErrorCode::SocketError {
        return crate::Error::new(ErrorCode::FailoverRetry, err.msg().to_owned());
    }
    err
}

/// Acknowledgement level for [`ColumnSender::sync`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckLevel {
    /// Wait for the server's WAL-commit ACK (spec status `0x00`). Always
    /// available.
    #[default]
    Ok,
    /// Wait for the server's object-store durability ACK (spec status
    /// `0x02`). Enterprise feature; requires `request_durable_ack=on` in
    /// the connect string.
    Durable,
}

/// One [`ColumnConn`] in the pool, wrapped in the column-sender API.
pub struct ColumnSender {
    pub(crate) conn: ColumnConn,
    pub(crate) symbol_dict: SymbolGlobalDict,
    pub(crate) scratch: encoder::EncodeScratch,
    /// The first frame is sent without `FLAG_DEFER_COMMIT` so the server
    /// commits it immediately. This lets the WAL segment roll and update
    /// `initialSymbolCount`, warming the server's `ClientSymbolCache` for
    /// all subsequent deferred frames. The flag is connection-scoped: it
    /// travels with the slot across borrow/return so a recycled warm
    /// connection does not re-send a redundant immediate-commit frame.
    pub(crate) first_frame_sent: bool,
}

impl Debug for ColumnSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ColumnSender")
            .field("must_close", &self.conn.must_close())
            .field("in_flight", &self.conn.in_flight())
            .finish()
    }
}

impl ColumnSender {
    pub(crate) fn new(
        conn: ColumnConn,
        symbol_dict: SymbolGlobalDict,
        scratch: encoder::EncodeScratch,
        first_frame_sent: bool,
    ) -> Self {
        Self {
            conn,
            symbol_dict,
            scratch,
            first_frame_sent,
        }
    }

    /// `true` once the underlying QWP/WS connection has latched into a
    /// permanently-unusable state. On return to the pool such senders
    /// are dropped rather than recycled.
    #[must_use]
    pub fn must_close(&self) -> bool {
        self.conn.must_close()
    }

    /// Force the connection into the terminal `must_close` state. The
    /// pool will drop this conn on return instead of recycling it.
    /// Intended for higher-level error recovery: when a mid-call flush
    /// fails after earlier flushes succeeded, the conn holds in-flight
    /// uncommitted frames; recycling it would let the next borrower's
    /// flush commit those frames alongside their own.
    pub fn mark_must_close(&mut self) {
        self.conn.mark_must_close();
    }

    /// Encode `chunk` into a QWP/WebSocket frame, write it to the
    /// socket, and return — **without** waiting for the server's ack.
    ///
    /// The first frame is sent as an immediate commit so the server can
    /// warm its symbol cache. Later frames are sent with
    /// `FLAG_DEFER_COMMIT`: the server appends rows to WAL but skips the
    /// commit. Call [`sync`](Self::sync) to trigger the commit for all
    /// accumulated rows.
    ///
    /// Ready acks are drained non-blocking before the write. Deferred
    /// flushes reserve one in-flight slot for the later
    /// commit-triggering sync frame; when that reserve would be consumed,
    /// this call returns [`ErrorCode::InvalidApiCall`](crate::ErrorCode::InvalidApiCall)
    /// and the caller must call [`sync`](Self::sync) before flushing more
    /// chunks.
    ///
    /// On success, `chunk` is cleared (its retained descriptor capacity
    /// is preserved) and the caller's buffers are released.
    ///
    /// On failure, the error is returned and `chunk` is left untouched.
    /// Transport and server failures latch the connection as terminal;
    /// validation and capacity failures leave it usable.
    ///
    /// `flush` does not wait for the server's per-frame ack, so a
    /// server-side rejection of an already-written frame surfaces only on
    /// a later `flush`/[`sync`](Self::sync) — not on this call. Call
    /// [`sync`](Self::sync) before dropping the sender to observe those
    /// acks; a sender dropped with frames still in flight discards the
    /// connection (and their acks) rather than reusing it.
    pub fn flush(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        let defer = self.first_frame_sent;
        self.flush_inner(chunk, defer)
            .map_err(classify_flush_error)?;
        self.first_frame_sent = true;
        Ok(())
    }

    /// Encode `batch` as a single QWP/WebSocket frame for `table` and
    /// publish it through this pooled connection in one pass — no
    /// intermediate buffer staging, no per-column copy. The
    /// per-row designated timestamp is omitted; the server stamps each
    /// row on arrival (matches [`Self::flush`] when called on a
    /// time-stamp-less chunk).
    ///
    /// Use [`Self::flush_arrow_batch_at_column`] to source the
    /// designated timestamp from a `Timestamp(_)` column in `batch`.
    ///
    /// The first frame is sent as an immediate commit so the server can
    /// warm its symbol cache; later frames are sent with
    /// `FLAG_DEFER_COMMIT`. Call [`Self::sync`] to trigger commit for
    /// all accumulated rows.
    ///
    /// `overrides` (use `&[]` for none) supplies per-column wire-type
    /// hints without requiring the caller to patch the Arrow `Field`
    /// metadata first.
    ///
    /// Every column in `batch` must satisfy `ArrayData::validate_full`
    /// (offsets monotonic and in bounds, dictionary keys in range, declared
    /// null counts accurate) — the invariant any array built through the safe
    /// `arrow` constructors already upholds. Arrays assembled via
    /// `ArrayData::build_unchecked` bypass that check and can drive
    /// out-of-range reads here; validate them before calling. The C ABI entry
    /// point validates on the caller's behalf since it cannot assume a trusted
    /// producer.
    ///
    /// `table` accepts anything convertible into a [`TableName`], so a bare
    /// `&str` works directly (validated here) as well as a pre-validated
    /// [`TableName`].
    #[cfg(feature = "arrow")]
    pub fn flush_arrow_batch<'t, T>(
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
        let defer = self.first_frame_sent;
        self.flush_arrow_batch_inner(table, batch, None, overrides, defer)
            .map_err(classify_flush_error)?;
        self.first_frame_sent = true;
        Ok(())
    }

    /// Variant of [`Self::flush_arrow_batch`] that sources the per-row
    /// designated timestamp from `ts_column`. The column must be a
    /// `Timestamp(Microsecond | Nanosecond | Millisecond, _)` with no
    /// null rows and no values before the Unix epoch; `Millisecond` is
    /// widened to µs on the wire. `overrides` (use `&[]` for none) has
    /// the same meaning as in [`Self::flush_arrow_batch`].
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
        let defer = self.first_frame_sent;
        self.flush_arrow_batch_inner(table, batch, Some(ts_col_idx), overrides, defer)
            .map_err(classify_flush_error)?;
        self.first_frame_sent = true;
        Ok(())
    }

    /// Block until all in-flight frames are acknowledged at the
    /// requested [`AckLevel`].
    ///
    /// Sends a commit-triggering frame (without `FLAG_DEFER_COMMIT`)
    /// so the server commits all rows accumulated from preceding
    /// deferred flushes, then drains all acks.
    ///
    /// `AckLevel::Ok` waits for every in-flight frame's WAL-commit ack.
    /// `AckLevel::Durable` additionally waits for the server's
    /// object-store durability watermarks to reach every frame's
    /// seq_txn (requires `request_durable_ack=on` at connect).
    pub fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        self.conn.validate_ack_level(ack_level)?;

        // Send a commit-triggering empty frame (no FLAG_DEFER_COMMIT).
        let mut commit_chunk = Chunk::new("");
        self.flush_inner(&mut commit_chunk, /* defer_commit = */ false)
            .map_err(classify_flush_error)?;
        self.conn
            .sync_all_acks(ack_level)
            .map_err(classify_flush_error)
    }

    fn flush_inner(&mut self, chunk: &mut Chunk<'_>, defer_commit: bool) -> Result<()> {
        self.conn.try_drain_acks()?;

        if defer_commit && !self.conn.has_sync_commit_slot() {
            return Err(error::fmt!(
                InvalidApiCall,
                "column sender deferred flush capacity exhausted; call sync() \
                 before flushing more chunks."
            ));
        }

        if self.conn.at_in_flight_cap() {
            self.conn.drain_one_ack_blocking()?;
        }

        let dict = &mut self.symbol_dict;
        let scratch = &mut self.scratch;
        let dict_mark = dict.mark();
        let published = match self
            .conn
            .publish_qwp(|out| encoder::encode_chunk_into(out, chunk, dict, scratch, defer_commit))
        {
            Ok(p) => p,
            Err(e) => {
                if e.code() != ErrorCode::SocketError {
                    dict.rollback(dict_mark);
                }
                return Err(e);
            }
        };

        self.conn.push_pending(published.fsn);
        chunk.clear();
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn flush_arrow_batch_inner(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        overrides: &[ArrowColumnOverride<'_>],
        defer_commit: bool,
    ) -> Result<()> {
        self.conn.try_drain_acks()?;

        if defer_commit && !self.conn.has_sync_commit_slot() {
            return Err(error::fmt!(
                InvalidApiCall,
                "column sender deferred flush capacity exhausted; call sync() \
                 before flushing more arrow batches."
            ));
        }

        if self.conn.at_in_flight_cap() {
            self.conn.drain_one_ack_blocking()?;
        }

        let dict_mark = self.symbol_dict.mark();
        let dict = &mut self.symbol_dict;
        let result = self.conn.publish_qwp(|out| {
            arrow_batch::encode_arrow_batch_into(
                out,
                table,
                batch,
                ts_col_idx,
                overrides,
                dict,
                defer_commit,
            )
        });
        let published = match result {
            Ok(p) => p,
            Err(err) => {
                if err.code() != ErrorCode::SocketError {
                    self.symbol_dict.rollback(dict_mark);
                }
                return Err(err);
            }
        };

        self.conn.push_pending(published.fsn);
        Ok(())
    }
}
