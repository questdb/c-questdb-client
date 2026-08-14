/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2026 QuestDB
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

//! Experimental transport-neutral QWP v1 codec for browser WebAssembly.
//!
//! This module deliberately stops at the WebSocket *message* boundary. Pass
//! bytes returned by [`QwpBrowserEncoder::encode`] directly to the browser's
//! `WebSocket.send()` API. Do not add RFC 6455 framing or masking: the browser
//! owns both, along with DNS, TCP, TLS, ping/pong, and the HTTP upgrade.

use crate::egress::column::ColumnView;
use crate::egress::decoder::ZstdScratch;
use crate::egress::query_request::QueryRequest;
use crate::egress::schema::Schema;
use crate::egress::server_event::{ServerEvent, decode_frame};
use crate::egress::symbol_dict::SymbolDict;
use crate::egress::wire::header::{FrameHeader, HEADER_LEN};
use crate::error;
use crate::ingress::qwp_ws_core::qwp_ws_codec::{
    PipelinedResponse, parse_pipelined_response_with_table_handler,
};
use crate::ingress::qwp_ws_core::qwp_ws_driver::{
    DriveOutcome, DriverError, QwpWsCoreHarness, QwpWsCoreTransport, ReconnectPolicy,
    ReconnectReason, TransportFailure, TransportPoll, TransportResponse, TransportSendResult,
    decode_transport_response,
};
use crate::ingress::qwp_ws_core::qwp_ws_queue::OutboundFrameView;
use crate::ingress::qwp_ws_core::qwp_ws_sfa_queue::{SfaFrameQueue, SfaMemoryQueueOptions};
use crate::ingress::{Buffer, QwpWsEncodeScratch, SymbolGlobalDict};
use bytes::Bytes;
use serde::Serialize;
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::time::Duration;

const QWP_VERSION_1: u8 = 1;
#[cfg(test)]
const STATUS_OK: u8 = 0x00;

/// A transport-neutral encoder for QWP v1 WebSocket message payloads.
///
/// The encoder retains the connection symbol dictionary between calls. Its
/// current dense encoding makes every returned message self-contained, which
/// keeps reconnect handling simple for the prototype.
pub struct QwpBrowserEncoder {
    payload: Vec<u8>,
    scratch: QwpWsEncodeScratch,
    global_dict: SymbolGlobalDict,
}

impl QwpBrowserEncoder {
    /// Construct an empty QWP v1 encoder.
    pub fn new() -> Self {
        Self {
            payload: Vec::with_capacity(16 * 1024),
            scratch: QwpWsEncodeScratch::new(),
            global_dict: SymbolGlobalDict::new(),
        }
    }

    /// Encode `buffer` as one binary QWP WebSocket message.
    ///
    /// The returned bytes are a QWP payload, not an RFC 6455 frame. They can be
    /// passed directly to JavaScript as a `Uint8Array` and then to
    /// `WebSocket.send()`.
    pub fn encode<'a>(&'a mut self, buffer: &Buffer) -> crate::Result<&'a [u8]> {
        let qwp = buffer.as_qwp_ws().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QwpBrowserEncoder requires a Buffer created by Buffer::new_qwp_ws()"
            )
        })?;
        if qwp.is_empty() {
            return Err(error::fmt!(
                InvalidApiCall,
                "Cannot encode an empty QWP/WebSocket buffer"
            ));
        }

        let dict_mark = self.global_dict.mark();
        if let Err(err) = qwp.encode_ws_replay_message_with_defer(
            &mut self.payload,
            &mut self.scratch,
            &mut self.global_dict,
            QWP_VERSION_1,
            false,
            false,
        ) {
            self.global_dict.rollback(dict_mark);
            return Err(err);
        }
        Ok(&self.payload)
    }

    /// Forget connection-scoped state after retiring a browser WebSocket.
    pub fn reset_connection(&mut self) {
        self.payload.clear();
        self.scratch = QwpWsEncodeScratch::new();
        self.global_dict = SymbolGlobalDict::new();
    }
}

impl Default for QwpBrowserEncoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Browser-facing reliable QWP ingress state.
///
/// This is the existing Rust sender driver backed by its in-memory SFA queue.
/// JavaScript supplies WebSocket open/message/close events and drains complete
/// QWP message payloads. Published frames remain queued until a server ACK
/// advances the driver's completion watermark; reconnect rewinds to the oldest
/// unresolved frame.
pub struct QwpBrowserSender {
    encoder: QwpBrowserEncoder,
    driver: QwpWsCoreHarness<SfaFrameQueue, BrowserTransport>,
}

#[derive(Debug, Default)]
struct BrowserTransport {
    connected: bool,
    reconnect_requested: bool,
    responses: VecDeque<TransportResponse>,
    outbound: VecDeque<Vec<u8>>,
}

impl QwpWsCoreTransport for BrowserTransport {
    fn try_poll_response(&mut self) -> Result<TransportPoll, TransportFailure> {
        Ok(self
            .responses
            .pop_front()
            .map_or(TransportPoll::Idle, TransportPoll::Response))
    }

    fn send_frame(
        &mut self,
        frame: OutboundFrameView<'_>,
    ) -> Result<TransportSendResult, TransportFailure> {
        if !self.connected {
            return Err(TransportFailure::Disconnect(error::fmt!(
                SocketError,
                "browser WebSocket is not open"
            )));
        }
        // WebSocket.send() copies this message after JavaScript drains it. The
        // SFA queue remains the authoritative retained copy until ACK.
        self.outbound.push_back(frame.payload.to_vec());
        Ok(TransportSendResult::NoResponse)
    }

    fn restart_connection(&mut self, _reason: ReconnectReason) -> Result<(), DriverError> {
        self.connected = false;
        self.reconnect_requested = true;
        self.responses.clear();
        self.outbound.clear();
        Ok(())
    }
}

impl QwpBrowserSender {
    /// Create a reliable browser sender with a bounded in-memory replay queue.
    pub fn new(max_queue_bytes: usize) -> crate::Result<Self> {
        if max_queue_bytes == 0 {
            return Err(error::fmt!(
                InvalidApiCall,
                "browser QWP replay queue capacity must be greater than zero"
            ));
        }
        // Segments are a queue implementation detail. Keep them small enough
        // for browser memory while allowing a full 16 MiB QWP message.
        let segment_size_bytes = (16 * 1024 * 1024 + 4096) as u64;
        let queue = SfaFrameQueue::open_memory(SfaMemoryQueueOptions {
            segment_size_bytes,
            max_bytes: max_queue_bytes.max(segment_size_bytes as usize * 2),
        })
        .map_err(DriverError::from)
        .map_err(browser_driver_error)?;
        let driver = QwpWsCoreHarness::from_queue_with_reconnect_policy(
            queue,
            BrowserTransport::default(),
            ReconnectPolicy::bounded(Duration::MAX, Duration::ZERO, Duration::ZERO),
            false,
        );
        Ok(Self {
            encoder: QwpBrowserEncoder::new(),
            driver,
        })
    }

    /// Encode and publish a buffer into the retained replay queue.
    pub fn publish(&mut self, buffer: &Buffer) -> crate::Result<u64> {
        let payload = self.encoder.encode(buffer)?;
        self.driver
            .try_submit(payload)
            .map(|receipt| receipt.fsn)
            .map_err(browser_driver_error)
    }

    /// Notify the driver that JavaScript has an open WebSocket.
    pub fn connection_opened(&mut self) {
        let transport = self.driver.transport_mut();
        transport.connected = true;
        transport.reconnect_requested = false;
    }

    /// Notify the driver that the socket is no longer usable. The replay
    /// cursor immediately rewinds to the oldest unacknowledged publication.
    pub fn connection_closed(&mut self) {
        let transport = self.driver.transport_mut();
        let was_connected = transport.connected;
        transport.connected = false;
        transport.responses.clear();
        transport.outbound.clear();
        if was_connected {
            let _ = self.driver.finish_browser_reconnect();
        }
    }

    /// Return the next complete QWP message for `WebSocket.send()`.
    pub fn next_payload(&mut self) -> crate::Result<Option<Vec<u8>>> {
        if !self.driver.transport_mut().connected {
            return Ok(None);
        }
        let outcome = self
            .driver
            .drive_send_once()
            .map_err(browser_driver_error)?;
        if matches!(outcome, DriveOutcome::Terminal) {
            return Err(error::fmt!(SocketError, "browser QWP sender is terminal"));
        }
        Ok(self.driver.transport_mut().outbound.pop_front())
    }

    /// Apply a complete QWP response payload through the native ACK/rejection
    /// decoder and delivery driver.
    pub fn handle_response(&mut self, payload: &[u8]) -> crate::Result<()> {
        match decode_transport_response(payload).map_err(browser_transport_failure)? {
            Some(response) => self.driver.transport_mut().responses.push_back(response),
            None => return Ok(()),
        }
        let _ = self
            .driver
            .drive_receive_once()
            .map_err(browser_driver_error)?;
        Ok(())
    }

    /// True when the Rust driver classified a response as retriable and asks
    /// JavaScript to rotate to another browser WebSocket endpoint.
    pub fn reconnect_requested(&mut self) -> bool {
        self.driver.transport_mut().reconnect_requested
    }

    pub fn published_fsn(&self) -> Option<u64> {
        self.driver.published_fsn()
    }

    pub fn acked_fsn(&self) -> Option<u64> {
        self.driver.acked_fsn()
    }
}

fn browser_transport_failure(failure: TransportFailure) -> crate::Error {
    match failure {
        TransportFailure::Disconnect(err)
        | TransportFailure::ServerClose(err)
        | TransportFailure::Retryable(err)
        | TransportFailure::Terminal(err) => err,
        TransportFailure::ProtocolViolation { close_code, reason } => error::fmt!(
            SocketError,
            "QWP/WebSocket protocol violation [close_code={close_code:?}]: {reason}"
        ),
    }
}

fn browser_driver_error(err: DriverError) -> crate::Error {
    match err {
        DriverError::Transport(err) | DriverError::Storage(err) => err,
        DriverError::Queue(err) => error::fmt!(
            InvalidApiCall,
            "browser QWP replay queue rejected publication: {err:?}"
        ),
        DriverError::SubmitTimedOut { backpressure } => error::fmt!(
            SocketError,
            "browser QWP replay queue is full: {backpressure:?}"
        ),
        DriverError::Terminal => error::fmt!(SocketError, "browser QWP sender is terminal"),
        DriverError::Closing => error::fmt!(InvalidApiCall, "browser QWP sender is closing"),
        DriverError::UnknownReceipt { fsn } => {
            error::fmt!(InvalidApiCall, "browser QWP receipt is unknown [fsn={fsn}]")
        }
    }
}

/// Transport-neutral state for one browser-owned QWP egress WebSocket.
///
/// JavaScript sends [`encode_query`](Self::encode_query)'s bytes as one
/// binary WebSocket message and passes every complete binary response message
/// to [`decode_frame_json`](Self::decode_frame_json). The codec retains the
/// connection-scoped symbol dictionary and the current query schema between
/// calls, matching the native [`crate::egress::Reader`] decoder.
pub struct QwpBrowserQueryCodec {
    next_request_id: i64,
    active_request_id: Option<i64>,
    dict: SymbolDict,
    query_schema: Option<Schema>,
    zstd_scratch: ZstdScratch,
    encoded_request: Vec<u8>,
}

impl QwpBrowserQueryCodec {
    pub fn new() -> Self {
        Self {
            next_request_id: 0,
            active_request_id: None,
            dict: SymbolDict::new(),
            query_schema: None,
            zstd_scratch: ZstdScratch::new(),
            encoded_request: Vec::with_capacity(256),
        }
    }

    /// Encode a SQL statement as a bare QWP `QUERY_REQUEST` payload.
    ///
    /// The browser must send the returned bytes directly as one binary
    /// WebSocket message. This prototype deliberately requests unbounded
    /// credit and supports one in-flight query per connection, like the
    /// native Reader API.
    pub fn encode_query<'a>(&'a mut self, sql: &str) -> crate::Result<&'a [u8]> {
        if self.active_request_id.is_some() {
            return Err(error::fmt!(
                InvalidApiCall,
                "another QWP query is already in flight on this browser connection"
            ));
        }
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| error::fmt!(InvalidApiCall, "QWP browser request id space exhausted"))?;
        let request = QueryRequest::builder(sql)
            .request_id(request_id)
            .initial_credit(0)
            .build()?;
        self.encoded_request.clear();
        request.encode(&mut self.encoded_request)?;
        self.query_schema = None;
        self.active_request_id = Some(request_id);
        Ok(&self.encoded_request)
    }

    /// Decode one complete server-to-client QWP frame to JSON for JavaScript.
    ///
    /// Result cells are strings (or `null`) so 64/128/256-bit values cross the
    /// JavaScript boundary without precision loss. The `type` field on each
    /// column preserves the QWP type.
    pub fn decode_frame_json(&mut self, frame: &[u8]) -> crate::Result<String> {
        if frame.len() < HEADER_LEN {
            return Err(error::fmt!(
                ProtocolError,
                "QWP browser egress frame truncated: got {} bytes, need at least {}",
                frame.len(),
                HEADER_LEN
            ));
        }
        let header = FrameHeader::parse(frame)?;
        let expected_len = HEADER_LEN
            .checked_add(header.payload_length as usize)
            .ok_or_else(|| error::fmt!(ProtocolError, "QWP frame length overflow"))?;
        if frame.len() != expected_len {
            return Err(error::fmt!(
                ProtocolError,
                "QWP frame length mismatch: got {} bytes, header declares {}",
                frame.len(),
                expected_len
            ));
        }
        let payload = Bytes::copy_from_slice(&frame[HEADER_LEN..]);
        let event = decode_frame(
            header,
            &payload,
            &mut self.dict,
            &mut self.query_schema,
            &mut self.zstd_scratch,
        )?;
        let browser_event = self.browser_event(event)?;
        serde_json::to_string(&browser_event)
            .map_err(|err| error::fmt!(ProtocolError, "could not serialize QWP result: {}", err))
    }

    /// Forget state after the JavaScript owner closes or loses the WebSocket.
    pub fn reset_connection(&mut self) {
        self.next_request_id = 0;
        self.active_request_id = None;
        self.dict.reset();
        self.query_schema = None;
        self.zstd_scratch = ZstdScratch::new();
        self.encoded_request.clear();
    }

    fn browser_event(&mut self, event: ServerEvent) -> crate::Result<BrowserQueryEvent> {
        match event {
            ServerEvent::Batch(batch) => {
                self.check_request_id(batch.request_id, "RESULT_BATCH")?;
                let schema = self.query_schema.as_ref().ok_or_else(|| {
                    error::fmt!(ProtocolError, "RESULT_BATCH decoded without a schema")
                })?;
                let columns = schema
                    .columns()
                    .iter()
                    .map(|column| BrowserQueryColumn {
                        name: column.name.clone(),
                        kind: column.kind.name(),
                    })
                    .collect();
                let mut rows = Vec::with_capacity(batch.row_count);
                for row_index in 0..batch.row_count {
                    let mut row = Vec::with_capacity(batch.columns.len());
                    for column_index in 0..batch.columns.len() {
                        let column = batch.column_view(column_index, &self.dict)?;
                        row.push(format_cell(column, row_index));
                    }
                    rows.push(row);
                }
                Ok(BrowserQueryEvent::Batch {
                    request_id: batch.request_id,
                    batch_seq: batch.batch_seq,
                    flags: batch.flags,
                    columns,
                    rows,
                })
            }
            ServerEvent::End {
                request_id,
                final_seq,
                total_rows,
            } => {
                self.check_request_id(request_id, "RESULT_END")?;
                self.active_request_id = None;
                Ok(BrowserQueryEvent::End {
                    request_id,
                    final_seq,
                    total_rows,
                })
            }
            ServerEvent::ExecDone {
                request_id,
                op_type,
                rows_affected,
            } => {
                self.check_request_id(request_id, "EXEC_DONE")?;
                self.active_request_id = None;
                Ok(BrowserQueryEvent::ExecDone {
                    request_id,
                    op_type,
                    rows_affected,
                })
            }
            ServerEvent::Error {
                request_id,
                status,
                message,
            } => {
                self.check_request_id(request_id, "QUERY_ERROR")?;
                self.active_request_id = None;
                Ok(BrowserQueryEvent::Error {
                    request_id,
                    status: status.as_u8(),
                    message,
                })
            }
            ServerEvent::CacheReset { .. } => Ok(BrowserQueryEvent::CacheReset),
            ServerEvent::ServerInfo(info) => Ok(BrowserQueryEvent::ServerInfo {
                role: info.role.as_str(),
                epoch: info.epoch,
                capabilities: info.capabilities,
                cluster_id: info.cluster_id,
                node_id: info.node_id,
                zone_id: info.zone_id,
            }),
        }
    }

    fn check_request_id(&self, actual: i64, message: &str) -> crate::Result<()> {
        match self.active_request_id {
            Some(expected) if actual == expected => Ok(()),
            Some(expected) => Err(error::fmt!(
                ProtocolError,
                "{} request_id {} != active browser query {}",
                message,
                actual,
                expected
            )),
            None => Err(error::fmt!(
                ProtocolError,
                "{} arrived without an active browser query",
                message
            )),
        }
    }
}

impl Default for QwpBrowserQueryCodec {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum BrowserQueryEvent {
    Batch {
        request_id: i64,
        batch_seq: u64,
        flags: u8,
        columns: Vec<BrowserQueryColumn>,
        rows: Vec<Vec<Option<String>>>,
    },
    End {
        request_id: i64,
        final_seq: u64,
        total_rows: u64,
    },
    ExecDone {
        request_id: i64,
        op_type: u8,
        rows_affected: u64,
    },
    Error {
        request_id: i64,
        status: u8,
        message: String,
    },
    CacheReset,
    ServerInfo {
        role: String,
        epoch: u64,
        capabilities: u32,
        cluster_id: String,
        node_id: String,
        zone_id: Option<String>,
    },
}

#[derive(Serialize)]
struct BrowserQueryColumn {
    name: String,
    #[serde(rename = "type")]
    kind: &'static str,
}

fn format_cell(column: ColumnView<'_>, row: usize) -> Option<String> {
    if column.is_null(row) {
        return None;
    }
    Some(match column {
        ColumnView::Boolean(c) => (c.value(row) != 0).to_string(),
        ColumnView::Byte(c) => c.value(row).to_string(),
        ColumnView::Short(c) => c.value(row).to_string(),
        ColumnView::Int(c) => c.value(row).to_string(),
        ColumnView::Long(c) => c.value(row).to_string(),
        ColumnView::Float(c) => c.value(row).to_string(),
        ColumnView::Double(c) => c.value(row).to_string(),
        ColumnView::Symbol(c) => c.resolve(row).unwrap_or("<unknown symbol>").to_owned(),
        ColumnView::Timestamp(c) => c.value(row).to_string(),
        ColumnView::Date(c) => c.value(row).to_string(),
        ColumnView::Uuid(c) => format_uuid(c.value(row)),
        ColumnView::Long256(c) => format_hex_le(c.value(row)),
        ColumnView::TimestampNanos(c) => c.value(row).to_string(),
        ColumnView::Decimal64(c) => format_decimal(&c.value(row).to_string(), c.scale()),
        ColumnView::Char(c) => char::from_u32(c.value(row) as u32)
            .map(|value| value.to_string())
            .unwrap_or_else(|| format!("U+{:04X}", c.value(row))),
        ColumnView::Ipv4(c) => Ipv4Addr::from(c.value(row)).to_string(),
        ColumnView::Varchar(c) => c.value(row).unwrap_or_default().to_owned(),
        ColumnView::Binary(c) => format_hex(c.value(row).unwrap_or_default()),
        ColumnView::Geohash(c) => format!("{}/{}b", c.value(row), c.precision_bits()),
        ColumnView::Decimal128(c) => format_decimal(&c.value(row).to_string(), c.scale()),
        ColumnView::Decimal256(c) => {
            format!("{} (scale {})", format_hex_le(c.value(row)), c.scale())
        }
        ColumnView::DoubleArray(c) => {
            let values = (0..c.element_count(row))
                .map(|index| c.element(row, index).unwrap().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("shape={:?} [{}]", c.shape(row).unwrap_or_default(), values)
        }
        ColumnView::LongArray(c) => {
            let values = (0..c.element_count(row))
                .map(|index| c.element(row, index).unwrap().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            format!("shape={:?} [{}]", c.shape(row).unwrap_or_default(), values)
        }
    })
}

fn format_decimal(mantissa: &str, scale: i8) -> String {
    if scale <= 0 {
        return format!(
            "{}{}",
            mantissa,
            "0".repeat(usize::from(scale.unsigned_abs()))
        );
    }
    let negative = mantissa.starts_with('-');
    let digits = mantissa.strip_prefix('-').unwrap_or(mantissa);
    let scale = scale as usize;
    let value = if digits.len() > scale {
        let split = digits.len() - scale;
        format!("{}.{}", &digits[..split], &digits[split..])
    } else {
        format!("0.{}{}", "0".repeat(scale - digits.len()), digits)
    };
    if negative { format!("-{value}") } else { value }
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        format_hex(&bytes[0..4]),
        format_hex(&bytes[4..6]),
        format_hex(&bytes[6..8]),
        format_hex(&bytes[8..10]),
        format_hex(&bytes[10..16])
    )
}

fn format_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn format_hex_le(bytes: &[u8]) -> String {
    let mut reversed = bytes.to_vec();
    reversed.reverse();
    format!("0x{}", format_hex(&reversed))
}

/// Per-table commit watermark carried by a successful QWP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QwpBrowserTableTxn {
    /// Table name supplied by the server.
    pub table: String,
    /// Server-side sequencer transaction watermark.
    pub seq_txn: i64,
}

/// A decoded QWP server WebSocket message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QwpBrowserResponse {
    /// The server accepted every message through `sequence`.
    Ok {
        /// Cumulative zero-based wire sequence.
        sequence: u64,
        /// Per-table commit watermarks.
        tables: Vec<QwpBrowserTableTxn>,
    },
    /// The server durably committed the listed table watermarks.
    DurableAck {
        /// Per-table durable commit watermarks.
        tables: Vec<QwpBrowserTableTxn>,
    },
    /// The server rejected a message.
    Error {
        /// QWP status byte.
        status: u8,
        /// Wire sequence associated with the rejection.
        sequence: u64,
        /// UTF-8 server diagnostic.
        message: String,
    },
}

/// Decode one complete binary QWP response message delivered by a browser
/// WebSocket `message` event.
pub fn decode_response(payload: &[u8]) -> crate::Result<QwpBrowserResponse> {
    let mut tables = Vec::new();
    let mut on_table = |_, table: &str, seq_txn| {
        tables.push(QwpBrowserTableTxn {
            table: table.to_owned(),
            seq_txn,
        });
        Ok(())
    };
    match parse_pipelined_response_with_table_handler(payload, Some(&mut on_table))? {
        PipelinedResponse::Ok { sequence } => Ok(QwpBrowserResponse::Ok { sequence, tables }),
        PipelinedResponse::DurableAck => Ok(QwpBrowserResponse::DurableAck { tables }),
        PipelinedResponse::Error(error) => Ok(QwpBrowserResponse::Error {
            status: error.status,
            sequence: error.sequence,
            message: error.message,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingress::TimestampMicros;

    #[test]
    fn encoder_emits_self_contained_qwp_v1_message() {
        let mut buffer = Buffer::new_qwp_ws();
        buffer
            .table("wasm_prototype")
            .unwrap()
            .symbol("symbol", "ETH-USD")
            .unwrap()
            .column_f64("price", 4242.5)
            .unwrap()
            .column_i64("quantity", 7)
            .unwrap()
            .at(TimestampMicros::new(1_700_000_000_000_000))
            .unwrap();

        let payload = QwpBrowserEncoder::new().encode(&buffer).unwrap().to_vec();
        assert_eq!(&payload[..4], b"QWP1");
        assert_eq!(payload[4], QWP_VERSION_1);
        assert_eq!(u16::from_le_bytes(payload[6..8].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(payload[8..12].try_into().unwrap()) as usize,
            payload.len() - 12
        );
    }

    #[test]
    fn reliable_sender_replays_unacknowledged_frame_after_reconnect() {
        let mut buffer = Buffer::new_qwp_ws();
        buffer.table("wasm_replay").unwrap();
        buffer.column_i64("value", 42).unwrap();
        buffer.at_now().unwrap();

        let mut sender = QwpBrowserSender::new(40 * 1024 * 1024).unwrap();
        assert_eq!(sender.publish(&buffer).unwrap(), 0);
        sender.connection_opened();
        let first = sender.next_payload().unwrap().unwrap();
        assert!(sender.next_payload().unwrap().is_none());

        sender.connection_closed();
        sender.connection_opened();
        let replay = sender.next_payload().unwrap().unwrap();
        assert_eq!(replay, first);

        let mut ack = vec![STATUS_OK];
        ack.extend_from_slice(&0u64.to_le_bytes());
        ack.extend_from_slice(&0u16.to_le_bytes());
        sender.handle_response(&ack).unwrap();
        assert_eq!(sender.acked_fsn(), Some(0));
        assert!(sender.next_payload().unwrap().is_none());
    }

    #[test]
    fn decoder_parses_ok_response_and_table_watermarks() {
        let mut payload = vec![STATUS_OK];
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&4u16.to_le_bytes());
        payload.extend_from_slice(b"test");
        payload.extend_from_slice(&42i64.to_le_bytes());

        assert_eq!(
            decode_response(&payload).unwrap(),
            QwpBrowserResponse::Ok {
                sequence: 7,
                tables: vec![QwpBrowserTableTxn {
                    table: "test".to_owned(),
                    seq_txn: 42,
                }],
            }
        );
    }

    #[test]
    fn decoder_rejects_trailing_error_bytes() {
        let mut payload = vec![0x05];
        payload.extend_from_slice(&3u64.to_le_bytes());
        payload.extend_from_slice(&3u16.to_le_bytes());
        payload.extend_from_slice(b"bad!");

        let err = decode_response(&payload).unwrap_err();
        assert!(err.msg().contains("trailing bytes"), "{err}");
    }
}
