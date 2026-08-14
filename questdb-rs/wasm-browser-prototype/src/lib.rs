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

use questdb::ingress::{Buffer, TimestampMicros};
use questdb::qwp_browser::{
    QwpBrowserQueryCodec, QwpBrowserResponse, QwpBrowserSender, decode_response,
};
use wasm_bindgen::prelude::*;

/// Minimal row-oriented QWP v1 batch builder exposed to browser JavaScript.
///
/// JavaScript owns the `WebSocket`, while Rust owns publication, ACK and replay
/// state. Drain [`QwpBrowserClient::next_payload`] into `WebSocket.send()`.
#[wasm_bindgen]
pub struct QwpBrowserClient {
    buffer: Buffer,
    sender: QwpBrowserSender,
}

#[wasm_bindgen]
impl QwpBrowserClient {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<Self, JsValue> {
        Ok(Self {
            buffer: Buffer::new_qwp_ws(),
            sender: QwpBrowserSender::new(64 * 1024 * 1024).map_err(js_error)?,
        })
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn reset_connection(&mut self) {
        self.sender.connection_closed();
    }

    pub fn connection_opened(&mut self) {
        self.sender.connection_opened();
    }

    pub fn table(&mut self, name: &str) -> Result<(), JsValue> {
        self.buffer.table(name).map(drop).map_err(js_error)
    }

    pub fn symbol(&mut self, name: &str, value: &str) -> Result<(), JsValue> {
        self.buffer.symbol(name, value).map(drop).map_err(js_error)
    }

    pub fn column_bool(&mut self, name: &str, value: bool) -> Result<(), JsValue> {
        self.buffer
            .column_bool(name, value)
            .map(drop)
            .map_err(js_error)
    }

    /// JavaScript passes `i64` values as `BigInt` through wasm-bindgen.
    pub fn column_i64(&mut self, name: &str, value: i64) -> Result<(), JsValue> {
        self.buffer
            .column_i64(name, value)
            .map(drop)
            .map_err(js_error)
    }

    pub fn column_f64(&mut self, name: &str, value: f64) -> Result<(), JsValue> {
        self.buffer
            .column_f64(name, value)
            .map(drop)
            .map_err(js_error)
    }

    pub fn column_str(&mut self, name: &str, value: &str) -> Result<(), JsValue> {
        self.buffer
            .column_str(name, value)
            .map(drop)
            .map_err(js_error)
    }

    /// Finish the current row at an exact microsecond Unix timestamp.
    ///
    /// This is an `i64`, so JavaScript must pass a `BigInt`.
    pub fn at_micros(&mut self, micros: i64) -> Result<(), JsValue> {
        self.buffer
            .at(TimestampMicros::new(micros))
            .map_err(js_error)
    }

    /// Finish the current row without a designated timestamp.
    pub fn at_now(&mut self) -> Result<(), JsValue> {
        self.buffer.at_now().map_err(js_error)
    }

    /// Publish the completed rows into Rust's retained replay queue.
    pub fn publish(&mut self) -> Result<u64, JsValue> {
        self.sender.publish(&self.buffer).map_err(js_error)
    }

    /// Return the next queued QWP message, or `undefined` when idle/offline.
    pub fn next_payload(&mut self) -> Result<Option<Vec<u8>>, JsValue> {
        self.sender.next_payload().map_err(js_error)
    }

    /// Apply one complete QWP response to the shared Rust ACK/replay driver.
    pub fn handle_response(&mut self, payload: &[u8]) -> Result<(), JsValue> {
        self.sender.handle_response(payload).map_err(js_error)
    }

    pub fn reconnect_requested(&mut self) -> bool {
        self.sender.reconnect_requested()
    }

    pub fn published_fsn(&self) -> Option<u64> {
        self.sender.published_fsn()
    }

    pub fn acked_fsn(&self) -> Option<u64> {
        self.sender.acked_fsn()
    }

    /// Decode a complete QWP response delivered by a WebSocket `message`
    /// event into a compact diagnostic string for the prototype UI.
    pub fn describe_response(&self, payload: &[u8]) -> Result<String, JsValue> {
        decode_response(payload)
            .map(describe_response)
            .map_err(js_error)
    }
}

impl Default for QwpBrowserClient {
    fn default() -> Self {
        Self::new().expect("default browser QWP replay queue")
    }
}

/// QWP egress query encoder and streaming result decoder.
///
/// JavaScript owns a second WebSocket connected to `/read/v1`. The Rust state
/// retained here is the same schema + symbol-dictionary state used by the
/// native egress Reader.
#[wasm_bindgen]
pub struct QwpBrowserQuery {
    codec: QwpBrowserQueryCodec,
}

#[wasm_bindgen]
impl QwpBrowserQuery {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            codec: QwpBrowserQueryCodec::new(),
        }
    }

    /// Encode SQL as a bare QWP QUERY_REQUEST WebSocket payload.
    pub fn encode_query(&mut self, sql: &str) -> Result<Vec<u8>, JsValue> {
        self.codec
            .encode_query(sql)
            .map(<[u8]>::to_vec)
            .map_err(js_error)
    }

    /// Decode one complete QWP server frame into a JSON event.
    pub fn decode_frame(&mut self, payload: &[u8]) -> Result<String, JsValue> {
        self.codec.decode_frame_json(payload).map_err(js_error)
    }

    pub fn reset_connection(&mut self) {
        self.codec.reset_connection();
    }
}

impl Default for QwpBrowserQuery {
    fn default() -> Self {
        Self::new()
    }
}

fn js_error(err: questdb::Error) -> JsValue {
    JsValue::from_str(&err.to_string())
}

fn describe_response(response: QwpBrowserResponse) -> String {
    match response {
        QwpBrowserResponse::Ok { sequence, tables } => {
            format!("OK sequence={sequence} tables={}", describe_tables(&tables))
        }
        QwpBrowserResponse::DurableAck { tables } => {
            format!("DURABLE_ACK tables={}", describe_tables(&tables))
        }
        QwpBrowserResponse::Error {
            status,
            sequence,
            message,
        } => format!("ERROR status=0x{status:02x} sequence={sequence}: {message}"),
    }
}

fn describe_tables(tables: &[questdb::qwp_browser::QwpBrowserTableTxn]) -> String {
    if tables.is_empty() {
        return "[]".to_owned();
    }
    let mut out = String::from("[");
    for (index, table) in tables.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&table.table);
        out.push(':');
        out.push_str(&table.seq_txn.to_string());
    }
    out.push(']');
    out
}
