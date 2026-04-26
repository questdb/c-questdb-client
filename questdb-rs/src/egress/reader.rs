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

//! `Reader` (per-connection) + `Cursor` (per-query) public API.
//!
//! Phase 1: a single in-flight query per connection (runtime-checked, not
//! type-encoded). Drop sends a best-effort WS close. Cancellation issues a
//! CANCEL frame and drains until the terminal frame.

#![cfg(feature = "sync-reader-ws")]

use std::net::Ipv4Addr;

use crate::egress::binds::Bind;
use crate::egress::column::ColumnView;
use crate::egress::column_kind::ColumnKind;
use crate::egress::config::ReaderConfig;
use crate::egress::decoder::DecodedBatch;
use crate::egress::error::{Result, fmt};
use crate::egress::query_request::{QueryRequest, QueryRequestBuilder};
use crate::egress::schema::{Schema, SchemaRegistry};
use crate::egress::server_event::{ServerEvent, decode_frame};
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::transport::WsTransport;
use crate::egress::wire::msg_kind::MsgKind;

// ---------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------

/// Per-connection reader. Owns the WebSocket transport and the
/// connection-scoped symbol dictionary + schema registry.
pub struct Reader {
    transport: WsTransport,
    dict: SymbolDict,
    registry: SchemaRegistry,
    next_request_id: i64,
    cursor_active: bool,
}

impl Reader {
    /// Open a new connection from a connect string.
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        let cfg = ReaderConfig::from_conf(conf)?;
        Self::from_config(&cfg)
    }

    /// Open a new connection using an already-built [`ReaderConfig`].
    pub fn from_config(cfg: &ReaderConfig) -> Result<Self> {
        let transport = WsTransport::connect(cfg)?;
        Ok(Reader {
            transport,
            dict: SymbolDict::new(),
            registry: SchemaRegistry::new(),
            next_request_id: 1,
            cursor_active: false,
        })
    }

    /// Negotiated QWP version this connection is using.
    pub fn server_version(&self) -> u8 {
        self.transport.server_version()
    }

    /// Connection-scoped symbol dictionary.
    pub fn symbol_dict(&self) -> &SymbolDict {
        &self.dict
    }

    /// Connection-scoped schema registry.
    pub fn schema_registry(&self) -> &SchemaRegistry {
        &self.registry
    }

    /// Begin building a query. The returned `ReaderQuery` exclusively
    /// borrows the reader; only one in-flight cursor at a time (Phase 1).
    pub fn query<S: Into<String>>(&mut self, sql: S) -> ReaderQuery<'_> {
        ReaderQuery {
            reader: self,
            builder: QueryRequest::builder(sql),
            error: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Query builder
// ---------------------------------------------------------------------------

/// Borrows a `Reader` exclusively while the query is being constructed and
/// (eventually) the cursor is live.
pub struct ReaderQuery<'r> {
    reader: &'r mut Reader,
    builder: QueryRequestBuilder,
    /// First fatal error (if any) deferred until `execute`, so the fluent
    /// chain stays clean.
    error: Option<crate::egress::Error>,
}

macro_rules! bind_method {
    ($name:ident, $($arg:ident : $ty:ty),*) => {
        pub fn $name(mut self, $($arg : $ty),*) -> Self {
            // Manually re-assign because QueryRequestBuilder consumes self.
            self.builder = self.builder.$name($($arg),*);
            self
        }
    };
}

impl<'r> ReaderQuery<'r> {
    /// Override the `initial_credit` (bytes; `0` = unbounded).
    pub fn initial_credit(mut self, credit: u64) -> Self {
        self.builder = self.builder.initial_credit(credit);
        self
    }

    /// Append a typed bind parameter.
    pub fn bind(mut self, value: Bind) -> Self {
        self.builder = self.builder.bind(value);
        self
    }

    bind_method!(bind_null, kind: ColumnKind);
    bind_method!(bind_bool, v: bool);
    bind_method!(bind_i8, v: i8);
    bind_method!(bind_i16, v: i16);
    bind_method!(bind_i32, v: i32);
    bind_method!(bind_i64, v: i64);
    bind_method!(bind_f32, v: f32);
    bind_method!(bind_f64, v: f64);
    bind_method!(bind_timestamp_micros, v: i64);
    bind_method!(bind_timestamp_nanos, v: i64);
    bind_method!(bind_date_millis, v: i64);
    bind_method!(bind_uuid_bytes, v: [u8; 16]);
    bind_method!(bind_long256, v: [u8; 32]);
    bind_method!(bind_char, v: u16);
    bind_method!(bind_ipv4, v: Ipv4Addr);

    pub fn bind_varchar<S: Into<String>>(mut self, v: S) -> Self {
        self.builder = self.builder.bind_varchar(v);
        self
    }

    pub fn bind_decimal64(mut self, value: i64, scale: i8) -> Self {
        self.builder = self.builder.bind_decimal64(value, scale);
        self
    }

    pub fn bind_decimal128(mut self, value: i128, scale: i8) -> Self {
        self.builder = self.builder.bind_decimal128(value, scale);
        self
    }

    pub fn bind_decimal256(mut self, bytes: [u8; 32], scale: i8) -> Self {
        self.builder = self.builder.bind_decimal256(bytes, scale);
        self
    }

    pub fn bind_geohash(mut self, value: u64, precision_bits: u8) -> Self {
        self.builder = self.builder.bind_geohash(value, precision_bits);
        self
    }

    pub fn bind_binary<B: Into<Vec<u8>>>(mut self, v: B) -> Self {
        self.builder = self.builder.bind_binary(v);
        self
    }

    pub fn bind_null_varchar(mut self) -> Self {
        self.builder = self.builder.bind_null_varchar();
        self
    }

    pub fn bind_null_binary(mut self) -> Self {
        self.builder = self.builder.bind_null_binary();
        self
    }

    pub fn bind_null_decimal64(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal64(scale);
        self
    }

    pub fn bind_null_decimal128(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal128(scale);
        self
    }

    pub fn bind_null_decimal256(mut self, scale: i8) -> Self {
        self.builder = self.builder.bind_null_decimal256(scale);
        self
    }

    pub fn bind_null_geohash(mut self, precision_bits: u8) -> Self {
        self.builder = self.builder.bind_null_geohash(precision_bits);
        self
    }

    /// Send the QUERY_REQUEST and return a streaming `Cursor`.
    pub fn execute(self) -> Result<Cursor<'r>> {
        if let Some(e) = self.error {
            return Err(e);
        }
        if self.reader.cursor_active {
            return Err(fmt!(
                InvalidApiCall,
                "another cursor is already in flight on this connection (Phase 1 single-in-flight)"
            ));
        }
        let request_id = self.reader.next_request_id;
        self.reader.next_request_id = self.reader.next_request_id.wrapping_add(1);

        let req = self.builder.request_id(request_id).build()?;
        let mut buf = Vec::with_capacity(64);
        req.encode(&mut buf)?;
        self.reader.transport.write_message(&buf)?;

        self.reader.cursor_active = true;
        Ok(Cursor {
            reader: self.reader,
            request_id,
            last_batch: None,
            terminal: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Cursor + BatchView
// ---------------------------------------------------------------------------

/// Reason the stream ended. Surfaced via [`Cursor::terminal`] once
/// `next_batch` returns `None`.
#[derive(Debug, Clone)]
pub enum Terminal {
    /// `RESULT_END` (`0x12`).
    End { final_seq: u64, total_rows: u64 },
    /// `EXEC_DONE` (`0x16`) — non-SELECT acknowledgement.
    ExecDone { op_type: u8, rows_affected: u64 },
}

/// Streaming cursor over `RESULT_BATCH` frames.
///
/// `next_batch` advances the stream by one batch, returning `None` once a
/// terminal frame arrives (which is then accessible via [`Cursor::terminal`]).
/// `cancel` sends a `CANCEL` frame and drains until the server's terminal.
pub struct Cursor<'r> {
    reader: &'r mut Reader,
    request_id: i64,
    last_batch: Option<DecodedBatch>,
    terminal: Option<Terminal>,
}

impl<'r> Cursor<'r> {
    pub fn request_id(&self) -> i64 {
        self.request_id
    }

    /// `Some` after a `RESULT_END` or `EXEC_DONE` has been observed.
    pub fn terminal(&self) -> Option<&Terminal> {
        self.terminal.as_ref()
    }

    /// Advance the cursor by one batch. Returns `Ok(None)` when the stream
    /// has terminated (success). `QUERY_ERROR` becomes `Err`.
    pub fn next_batch(&mut self) -> Result<Option<BatchView<'_>>> {
        if self.terminal.is_some() {
            return Ok(None);
        }
        loop {
            let (header, payload) = self.reader.transport.read_frame()?;
            let event =
                decode_frame(header, &payload, &mut self.reader.dict, &mut self.reader.registry)?;
            match event {
                ServerEvent::Batch(b) => {
                    if b.request_id != self.request_id {
                        return Err(fmt!(
                            ProtocolError,
                            "RESULT_BATCH request_id {} != cursor {}",
                            b.request_id,
                            self.request_id
                        ));
                    }
                    self.last_batch = Some(b);
                    let last = self.last_batch.as_ref().unwrap();
                    let schema = self.reader.registry.get(last.schema_id).ok_or_else(|| {
                        fmt!(
                            ProtocolError,
                            "RESULT_BATCH references schema {} not in registry",
                            last.schema_id
                        )
                    })?;
                    return Ok(Some(BatchView {
                        decoded: last,
                        dict: &self.reader.dict,
                        schema,
                    }));
                }
                ServerEvent::End { request_id, final_seq, total_rows } => {
                    self.check_rid(request_id, "RESULT_END")?;
                    self.terminal = Some(Terminal::End { final_seq, total_rows });
                    self.reader.cursor_active = false;
                    return Ok(None);
                }
                ServerEvent::ExecDone { request_id, op_type, rows_affected } => {
                    self.check_rid(request_id, "EXEC_DONE")?;
                    self.terminal = Some(Terminal::ExecDone { op_type, rows_affected });
                    self.reader.cursor_active = false;
                    return Ok(None);
                }
                ServerEvent::Error { request_id, status, message } => {
                    self.check_rid(request_id, "QUERY_ERROR")?;
                    self.reader.cursor_active = false;
                    return Err(map_server_status(status, message));
                }
                ServerEvent::CacheReset { .. } | ServerEvent::ServerInfo(_) => {
                    // State already mutated by decode_frame; keep reading.
                    continue;
                }
            }
        }
    }

    /// Send a CANCEL frame and drain until the server emits a terminal
    /// frame for this request.
    pub fn cancel(&mut self) -> Result<()> {
        if self.terminal.is_some() {
            return Ok(());
        }
        let mut payload = Vec::with_capacity(9);
        payload.push(MsgKind::Cancel.as_u8());
        payload.extend_from_slice(&self.request_id.to_le_bytes());
        self.reader.transport.write_message(&payload)?;

        // Drain until terminal — swallow batches between CANCEL and the
        // server's terminal acknowledgement.
        while self.terminal.is_none() {
            match self.next_batch() {
                Ok(Some(_)) => {} // discarded
                Ok(None) => break,
                Err(e) => {
                    if matches!(
                        e.code(),
                        crate::egress::ErrorCode::Cancelled
                    ) {
                        break;
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn check_rid(&self, got: i64, what: &str) -> Result<()> {
        if got != self.request_id {
            return Err(fmt!(
                ProtocolError,
                "{} request_id {} != cursor {}",
                what,
                got,
                self.request_id
            ));
        }
        Ok(())
    }
}

impl Drop for Cursor<'_> {
    fn drop(&mut self) {
        // Fire-and-forget per the project policy. The transport's own Drop
        // closes the WS; that releases any server-side resources tied to
        // this request_id.
        self.reader.cursor_active = false;
    }
}

/// Borrowed view over the most recently decoded batch.
pub struct BatchView<'c> {
    decoded: &'c DecodedBatch,
    dict: &'c SymbolDict,
    schema: &'c Schema,
}

impl<'c> BatchView<'c> {
    pub fn request_id(&self) -> i64 {
        self.decoded.request_id
    }

    pub fn batch_seq(&self) -> u64 {
        self.decoded.batch_seq
    }

    pub fn schema(&self) -> &'c Schema {
        self.schema
    }

    pub fn row_count(&self) -> usize {
        self.decoded.row_count
    }

    pub fn column_count(&self) -> usize {
        self.decoded.columns.len()
    }

    /// Project a single column to a typed view.
    pub fn column(&self, idx: usize) -> Result<ColumnView<'_>> {
        self.decoded.column_view(idx, self.dict)
    }
}

fn map_server_status(
    status: crate::egress::wire::msg_kind::StatusCode,
    message: String,
) -> crate::egress::Error {
    use crate::egress::ErrorCode as C;
    use crate::egress::wire::msg_kind::StatusCode as S;
    let code = match status {
        S::SchemaMismatch => C::ServerSchemaMismatch,
        S::ParseError => C::ServerParseError,
        S::InternalError => C::ServerInternalError,
        S::SecurityError => C::ServerSecurityError,
        S::Cancelled => C::Cancelled,
        S::LimitExceeded => C::ServerLimitExceeded,
    };
    crate::egress::Error::new(code, message)
}
