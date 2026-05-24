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
//! A [`ColumnSender`] is one borrowed pool slot. It owns the underlying
//! [`crate::ingress::Sender`], the connection-scoped [`SchemaRegistry`],
//! and the connection-scoped [`SymbolGlobalDict`]: all three travel back
//! into the pool together when the [`super::BorrowedSender`] is dropped.

use std::fmt::{self, Debug, Formatter};
use std::time::Duration;

use crate::ingress::Sender;
use crate::ingress::buffer::SymbolGlobalDict;
use crate::{Result, error};

use super::chunk::Chunk;
use super::encoder::{self, SchemaRegistry};

/// Acknowledgement level a [`ColumnSender::flush`] call waits for.
///
/// See `doc/COLUMN_SENDER_PLAN.md` §4 for the rationale and the QWP/WS spec
/// for the status-byte values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AckLevel {
    /// Wait for the server's WAL-commit ACK (spec status `0x00`). Always
    /// available.
    #[default]
    Ok,
    /// Wait for the server's object-store durability ACK (spec status
    /// `0x02`). Enterprise feature; requires `request_durable_ack=on` in the
    /// connect string. Flush returns `InvalidApiCall` otherwise.
    Durable,
}

/// One [`crate::ingress::Sender`] in the pool, wrapped in the column-sender
/// type system.
///
/// The user reaches this via [`super::BorrowedSender`].
pub struct ColumnSender {
    pub(crate) sender: Sender,
    pub(crate) schema_registry: SchemaRegistry,
    pub(crate) symbol_dict: SymbolGlobalDict,
    /// Latched from the connect string at [`super::QuestDb::connect`]; a
    /// [`AckLevel::Durable`] flush is only honoured when this is `true`.
    durable_ack_opt_in: bool,
}

impl Debug for ColumnSender {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ColumnSender")
            .field("sender", &self.sender)
            .field("durable_ack_opt_in", &self.durable_ack_opt_in)
            .finish()
    }
}

impl ColumnSender {
    pub(crate) fn new(
        sender: Sender,
        schema_registry: SchemaRegistry,
        symbol_dict: SymbolGlobalDict,
        durable_ack_opt_in: bool,
    ) -> Self {
        Self {
            sender,
            schema_registry,
            symbol_dict,
            durable_ack_opt_in,
        }
    }

    /// `true` once the underlying QWP/WS connection has latched into a
    /// permanently-unusable state. On return to the pool such senders
    /// are dropped rather than recycled.
    #[must_use]
    pub fn must_close(&self) -> bool {
        self.sender.must_close()
    }

    /// Encode `chunk` into a QWP/WebSocket frame, publish it, and block
    /// until the server acknowledges at the requested [`AckLevel`].
    ///
    /// On success, `chunk` is cleared (its retained capacity is preserved).
    /// On failure, `chunk` is left untouched so the caller can inspect or
    /// recover its contents before dropping it.
    ///
    /// At most one frame is in flight per sender at a time — that is what
    /// makes this call synchronous. For parallel ingest, borrow multiple
    /// senders from the [`super::QuestDb`] pool, one per worker thread.
    ///
    /// `AckLevel::Durable` requires the pool to have been opened with
    /// `request_durable_ack=on`; otherwise this returns `InvalidApiCall`.
    pub fn flush(&mut self, chunk: &mut Chunk, ack_level: AckLevel) -> Result<()> {
        if ack_level == AckLevel::Durable && !self.durable_ack_opt_in {
            return Err(error::fmt!(
                InvalidApiCall,
                "AckLevel::Durable requires the pool to be opened with \
                 `request_durable_ack=on` in the connect string."
            ));
        }

        let payload =
            encoder::encode_chunk(chunk, &mut self.schema_registry, &mut self.symbol_dict)?;
        let fsn = self.sender.qwp_ws_publish_raw(&payload)?;
        self.await_ack(fsn)?;
        chunk.clear();
        Ok(())
    }

    /// Wait until the underlying connection's cumulative ack watermark
    /// reaches `fsn`, or until the connection latches into `must_close`.
    fn await_ack(&mut self, fsn: u64) -> Result<()> {
        // Poll in 50 ms slices so a connection that latches into
        // `must_close` mid-wait is surfaced promptly rather than blocking
        // forever on the underlying ack watermark.
        const POLL: Duration = Duration::from_millis(50);
        loop {
            if self.sender.await_acked_fsn(fsn, POLL)? {
                return Ok(());
            }
            if self.sender.must_close() {
                return Err(error::fmt!(
                    SocketError,
                    "QWP/WebSocket connection entered a terminal state before \
                     the published frame was acknowledged."
                ));
            }
        }
    }
}
