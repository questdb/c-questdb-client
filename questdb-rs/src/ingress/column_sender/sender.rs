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
//! ([`super::conn::ColumnConn`]), a connection-scoped
//! [`SchemaRegistry`](super::encoder::SchemaRegistry), and a
//! connection-scoped [`SymbolGlobalDict`]: all three travel back into the
//! pool together when the [`super::BorrowedSender`] is dropped.

use std::fmt::{self, Debug, Formatter};

#[cfg(feature = "arrow")]
use crate::ErrorCode;
use crate::ingress::buffer::SymbolGlobalDict;
#[cfg(feature = "arrow")]
use crate::ingress::{ColumnName, TableName};
use crate::{Result, error};

#[cfg(feature = "arrow")]
use super::arrow_batch;
use super::chunk::Chunk;
use super::conn::ColumnConn;
use super::encoder::{self, SchemaRegistry};

#[cfg(feature = "arrow")]
use arrow_array::RecordBatch;

/// Acknowledgement level for [`ColumnSender::sync`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
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
    pub(crate) schema_registry: SchemaRegistry,
    pub(crate) symbol_dict: SymbolGlobalDict,
    pub(crate) scratch: encoder::EncodeScratch,
    /// The first frame is sent without `FLAG_DEFER_COMMIT` so the server
    /// commits it immediately. This lets the WAL segment roll and update
    /// `initialSymbolCount`, warming the server's `ClientSymbolCache` for
    /// all subsequent deferred frames.
    first_frame_sent: bool,
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
        schema_registry: SchemaRegistry,
        symbol_dict: SymbolGlobalDict,
        scratch: encoder::EncodeScratch,
    ) -> Self {
        Self {
            conn,
            schema_registry,
            symbol_dict,
            scratch,
            first_frame_sent: false,
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
    pub fn flush(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        let defer = self.first_frame_sent;
        self.flush_inner(chunk, defer)?;
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
    #[cfg(feature = "arrow")]
    pub fn flush_arrow_batch(&mut self, table: TableName<'_>, batch: &RecordBatch) -> Result<()> {
        let defer = self.first_frame_sent;
        self.flush_arrow_batch_inner(table, batch, None, defer)?;
        self.first_frame_sent = true;
        Ok(())
    }

    /// Variant of [`Self::flush_arrow_batch`] that sources the per-row
    /// designated timestamp from `ts_column`. The column must be a
    /// `Timestamp(Microsecond | Nanosecond | Millisecond, _)` with no
    /// null rows and no values before the Unix epoch; `Millisecond` is
    /// widened to µs on the wire.
    #[cfg(feature = "arrow")]
    pub fn flush_arrow_batch_at_column(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_column: ColumnName<'_>,
    ) -> Result<()> {
        let ts_col_idx = arrow_batch::resolve_ts_column(batch, ts_column)?;
        let defer = self.first_frame_sent;
        self.flush_arrow_batch_inner(table, batch, Some(ts_col_idx), defer)?;
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
        self.flush_inner(&mut commit_chunk, /* defer_commit = */ false)?;
        self.conn.sync_all_acks(ack_level)
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

        let schema = &mut self.schema_registry;
        let dict = &mut self.symbol_dict;
        let scratch = &mut self.scratch;
        let dict_mark = dict.mark();
        let published = match self.conn.publish_qwp(|out| {
            encoder::encode_chunk_into(out, chunk, schema, dict, scratch, defer_commit)
        }) {
            Ok(p) => p,
            Err(e) => {
                dict.rollback(dict_mark);
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
        let schema = &mut self.schema_registry;
        let dict = &mut self.symbol_dict;
        let result = self.conn.publish_qwp(|out| {
            arrow_batch::encode_arrow_batch_into(
                out,
                table,
                batch,
                ts_col_idx,
                schema,
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
