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

use crate::ErrorCode;
use crate::ingress::buffer::{Buffer, QwpWsColumnarBuffer, QwpWsEncodeScratch, SymbolGlobalDict};
use crate::{Result, error};

use super::chunk::Chunk;
use super::conn::ColumnConn;
use super::encoder::{self, SchemaRegistry};
use super::wire::QWP_VERSION_1;

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
    buffer_scratch: QwpWsEncodeScratch,
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
    ) -> Self {
        Self {
            conn,
            schema_registry,
            symbol_dict,
            buffer_scratch: QwpWsEncodeScratch::new(),
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

    /// Publish a QWP/WebSocket [`Buffer`] through this pooled connection.
    ///
    /// This exists for FFI callers that build a Rust `Buffer` through the
    /// public Arrow batch path and need the same pooled connection,
    /// deferred-commit, and closing-sync behavior as [`flush`](Self::flush).
    /// On success, `buffer` is cleared.
    pub fn flush_buffer(&mut self, buffer: &mut Buffer) -> Result<()> {
        let qwp = buffer.as_qwp_ws().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "column sender pooled flush requires a QWP/WebSocket buffer"
            )
        })?;
        qwp.check_can_flush()?;
        if qwp.is_empty() {
            buffer.clear();
            return Ok(());
        }

        let defer = self.first_frame_sent;
        self.flush_buffer_inner(qwp, defer)?;
        self.first_frame_sent = true;
        buffer.clear();
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
        let published = self.conn.publish_qwp(|out| {
            encoder::encode_chunk_into(out, chunk, schema, dict, defer_commit)
        })?;

        self.conn.push_pending(published.fsn);
        chunk.clear();
        Ok(())
    }

    fn flush_buffer_inner(
        &mut self,
        buffer: &QwpWsColumnarBuffer,
        defer_commit: bool,
    ) -> Result<()> {
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

        let dict_mark = self.symbol_dict.mark();
        let scratch = &mut self.buffer_scratch;
        let symbol_dict = &mut self.symbol_dict;
        let result = self.conn.publish_qwp(|out| {
            buffer.encode_ws_replay_message_with_defer(
                scratch,
                symbol_dict,
                QWP_VERSION_1,
                defer_commit,
            )?;
            out.extend_from_slice(&scratch.message);
            Ok(())
        });
        let published = match result {
            Ok(published) => published,
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
