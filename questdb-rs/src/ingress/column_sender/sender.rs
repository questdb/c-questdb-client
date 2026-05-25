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

use crate::Result;
use crate::ingress::buffer::SymbolGlobalDict;

use super::chunk::Chunk;
use super::conn::ColumnConn;
use super::encoder::{self, SchemaRegistry};

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

    /// Encode `chunk` into a QWP/WebSocket frame, write it to the
    /// socket, and return — **without** waiting for the server's ack.
    ///
    /// The frame is sent with `FLAG_DEFER_COMMIT`: the server appends
    /// rows to WAL but skips the commit. Call [`sync`](Self::sync) to
    /// trigger the commit for all accumulated rows.
    ///
    /// Ready acks are drained non-blocking before the write. If the
    /// in-flight count has reached the protocol cap (128), this call
    /// blocks until at least one ack frees a slot.
    ///
    /// On success, `chunk` is cleared (its retained descriptor capacity
    /// is preserved) and the caller's buffers are released.
    ///
    /// On failure, the connection is latched as terminal and the error
    /// is returned. `chunk` is left untouched.
    pub fn flush(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        let defer = self.first_frame_sent;
        self.flush_inner(chunk, defer)?;
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
        // Send a commit-triggering empty frame (no FLAG_DEFER_COMMIT).
        let mut commit_chunk = Chunk::new("");
        self.flush_inner(&mut commit_chunk, /* defer_commit = */ false)?;
        self.conn.sync_all_acks(ack_level)
    }

    fn flush_inner(&mut self, chunk: &mut Chunk<'_>, defer_commit: bool) -> Result<()> {
        self.conn.try_drain_acks()?;

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
}
