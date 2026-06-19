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
use std::time::Duration;

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
use super::conn::ColumnConn;
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
    ) -> Self {
        Self {
            backend: ColumnSenderBackend::StoreAndForward(SfaColumnBackend {
                state,
                symbol_dict: SymbolGlobalDict::new(),
                scratch: encoder::EncodeScratch::new(),
                payload: Vec::new(),
                max_buf_size,
                request_durable_ack,
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

    pub fn flush(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => {
                let defer = direct.first_frame_sent;
                direct
                    .flush_inner(chunk, defer)
                    .map_err(classify_flush_error)?;
                direct.first_frame_sent = true;
                Ok(())
            }
            ColumnSenderBackend::StoreAndForward(sfa) => sfa.flush_chunk(chunk),
        }
    }

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
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => {
                let defer = direct.first_frame_sent;
                direct
                    .flush_arrow_batch_inner(table, batch, None, overrides, defer)
                    .map_err(classify_flush_error)?;
                direct.first_frame_sent = true;
                Ok(())
            }
            ColumnSenderBackend::StoreAndForward(sfa) => {
                sfa.flush_arrow_batch(table, batch, None, overrides)
            }
        }
    }

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
        match &mut self.backend {
            ColumnSenderBackend::Direct(direct) => {
                let defer = direct.first_frame_sent;
                direct
                    .flush_arrow_batch_inner(table, batch, Some(ts_col_idx), overrides, defer)
                    .map_err(classify_flush_error)?;
                direct.first_frame_sent = true;
                Ok(())
            }
            ColumnSenderBackend::StoreAndForward(sfa) => {
                sfa.flush_arrow_batch(table, batch, Some(ts_col_idx), overrides)
            }
        }
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
        self.conn.validate_ack_level(ack_level)?;
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
            Err(e) => {
                if e.code() != ErrorCode::SocketError {
                    self.symbol_dict.rollback(dict_mark);
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
        let published = match self.conn.publish_qwp(|out| {
            arrow_batch::encode_arrow_batch_into(
                out,
                table,
                batch,
                ts_col_idx,
                overrides,
                &mut self.symbol_dict,
                defer_commit,
            )
        }) {
            Ok(p) => p,
            Err(e) => {
                if e.code() != ErrorCode::SocketError {
                    self.symbol_dict.rollback(dict_mark);
                }
                return Err(e);
            }
        };

        self.conn.push_pending(published.fsn);
        Ok(())
    }
}

impl SfaColumnBackend {
    fn flush_chunk(&mut self, chunk: &mut Chunk<'_>) -> Result<()> {
        qwp_ws_check_error_background(&self.state)?;
        self.payload.clear();
        let dict_mark = self.symbol_dict.mark();
        if let Err(e) = encoder::encode_chunk_replay_into(
            &mut self.payload,
            chunk,
            &mut self.symbol_dict,
            &mut self.scratch,
        ) {
            self.symbol_dict.rollback(dict_mark);
            return Err(e);
        }
        let max_buf_size = self.effective_max_buf_size();
        if let Err(e) =
            publish_qwp_ws_payload_background(&mut self.state, &self.payload, max_buf_size)
        {
            self.symbol_dict.rollback(dict_mark);
            return Err(e);
        }
        chunk.clear();
        Ok(())
    }

    #[cfg(feature = "arrow")]
    fn flush_arrow_batch(
        &mut self,
        table: TableName<'_>,
        batch: &RecordBatch,
        ts_col_idx: Option<usize>,
        overrides: &[ArrowColumnOverride<'_>],
    ) -> Result<()> {
        qwp_ws_check_error_background(&self.state)?;
        self.payload.clear();
        let dict_mark = self.symbol_dict.mark();
        if let Err(e) = arrow_batch::encode_arrow_batch_replay_into(
            &mut self.payload,
            table,
            batch,
            ts_col_idx,
            overrides,
            &mut self.symbol_dict,
        ) {
            self.symbol_dict.rollback(dict_mark);
            return Err(e);
        }
        let max_buf_size = self.effective_max_buf_size();
        if let Err(e) =
            publish_qwp_ws_payload_background(&mut self.state, &self.payload, max_buf_size)
        {
            self.symbol_dict.rollback(dict_mark);
            return Err(e);
        }
        Ok(())
    }

    fn sync(&mut self, ack_level: AckLevel) -> Result<()> {
        if ack_level == AckLevel::Durable && !self.request_durable_ack {
            return Err(error::fmt!(
                InvalidApiCall,
                "AckLevel::Durable requires the pool to be opened with \
                 `request_durable_ack=on` in the connect string."
            ));
        }

        let Some(boundary) = qwp_ws_published_fsn_background(&self.state)? else {
            return Ok(());
        };
        let last_boundary = match ack_level {
            AckLevel::Ok => self.last_ok_sync_boundary,
            AckLevel::Durable => self.last_durable_sync_boundary,
        };
        if last_boundary.is_some_and(|last| last >= boundary) {
            return Ok(());
        }
        let from_fsn = last_boundary.map_or(0, |last| last.saturating_add(1));

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

            qwp_ws_check_error_background(&self.state)?;
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
