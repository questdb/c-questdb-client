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

use crate::error::{self, Result};
#[cfg(feature = "_sync-sender")]
use crate::ingress::SenderBuilder;
use crate::ingress::{Buffer, Protocol, ProtocolVersion};
use std::fmt::{Debug, Formatter};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::time::{Duration, Instant};

#[cfg(feature = "sync-sender-qwp-udp")]
mod qwp_udp;

#[cfg(feature = "sync-sender-qwp-udp")]
pub(crate) use qwp_udp::*;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_codec;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_driver;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_ownership;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_publisher;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_queue;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_sfa_segment;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_sfa_queue;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_sfa_slot;

#[cfg(feature = "_sender-qwp-ws")]
pub use qwp_ws_ownership::*;

#[cfg(all(test, feature = "sync-sender-qwp-ws"))]
pub(crate) mod qwp_ws_test_support {
    pub(crate) use super::qwp_ws_driver::{
        BlockingQwpWsTransport, CloseOutcome, DeliveryOutcome, ManualDriverPrototype,
    };
    pub(crate) use super::qwp_ws_publisher::QwpWsPublicationDriver;
    pub(crate) use super::qwp_ws_queue::{VolatileFrameQueue, VolatileQueueOptions};
    pub(crate) use super::qwp_ws_sfa_slot::{SfaSlotOptions, SfaSlotQueue};

    pub(crate) fn connect_blocking_transport(
        host: impl Into<String>,
        port: impl Into<String>,
        auth_header: Option<String>,
    ) -> crate::Result<BlockingQwpWsTransport> {
        BlockingQwpWsTransport::connect(
            host,
            port,
            false,
            None,
            crate::ingress::conf::QwpWsConfig::default(),
            auth_header,
        )
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
mod qwp_ws;

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) use qwp_ws::*;

#[cfg(feature = "sync-sender-tcp")]
mod tcp;

#[cfg(feature = "sync-sender-tcp")]
pub(crate) use tcp::*;

#[cfg(feature = "sync-sender-tcp")]
use std::io::Write;

#[cfg(feature = "sync-sender-tcp")]
use crate::ingress::map_io_to_socket_err;

#[cfg(feature = "sync-sender-http")]
mod http;

#[cfg(feature = "sync-sender-http")]
pub(crate) use http::*;

#[allow(clippy::enum_variant_names)]
pub(crate) enum SyncProtocolHandler {
    #[cfg(feature = "sync-sender-qwp-udp")]
    SyncQwpUdp(SyncQwpUdpHandlerState),

    #[cfg(feature = "sync-sender-qwp-ws")]
    SyncQwpWs(Box<SyncQwpWsHandlerState>),

    #[cfg(feature = "sync-sender-qwp-ws")]
    ManualQwpWs(Box<ManualQwpWsHandlerState>),

    #[cfg(feature = "sync-sender-tcp")]
    SyncTcp(SyncConnection),

    #[cfg(feature = "sync-sender-http")]
    SyncHttp(SyncHttpHandlerState),
}

/// Connects to a QuestDB instance and inserts data via the configured
/// ingestion protocol.
///
/// * To construct an instance, use [`Sender::from_conf`] or the [`SenderBuilder`].
/// * To prepare messages, use [`Buffer`] objects.
/// * To send messages, call the [`flush`](Sender::flush) method.
pub struct Sender {
    descr: String,
    handler: SyncProtocolHandler,
    connected: bool,
    max_buf_size: usize,
    protocol: Protocol,
    protocol_version: ProtocolVersion,
    max_name_len: usize,
}

impl Debug for Sender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(self.descr.as_str())
    }
}

impl Sender {
    pub(crate) fn new(
        descr: String,
        handler: SyncProtocolHandler,
        max_buf_size: usize,
        protocol: Protocol,
        protocol_version: ProtocolVersion,
        max_name_len: usize,
    ) -> Self {
        Self {
            descr,
            handler,
            connected: true,
            max_buf_size,
            protocol,
            protocol_version,
            max_name_len,
        }
    }

    /// Create a new `Sender` instance from the given configuration string.
    ///
    /// The format of the string is: `"http::addr=host:port;key=value;...;"`.
    ///
    /// Instead of `"http"`, you can also specify `"https"`, `"tcp"`, `"tcps"`,
    /// and `"qwpudp"`.
    ///
    /// We recommend HTTP for most cases because it provides more features, like
    /// reporting errors to the client and supporting transaction control. TCP can
    /// sometimes be faster in higher-latency networks, but misses a number of
    /// features.
    ///
    /// Keys in the config string correspond to same-named methods on `SenderBuilder`.
    ///
    /// For the full list of keys and values, see the docs on [`SenderBuilder`].
    ///
    /// You can also load the configuration from an environment variable.
    /// See [`Sender::from_env`].
    ///
    /// In the case of TCP, this synchronously establishes the TCP connection, and
    /// returns once the connection is fully established. If the connection
    /// requires authentication or TLS, these will also be completed before
    /// returning.
    #[cfg(feature = "_sync-sender")]
    pub fn from_conf<T: AsRef<str>>(conf: T) -> Result<Self> {
        SenderBuilder::from_conf(conf)?.build()
    }

    /// Create a new `Sender` from the configuration stored in the `QDB_CLIENT_CONF`
    /// environment variable. The format is the same as that accepted by
    /// [`Sender::from_conf`].
    ///
    /// In the case of TCP, this synchronously establishes the TCP connection, and
    /// returns once the connection is fully established. If the connection
    /// requires authentication or TLS, these will also be completed before
    /// returning.
    #[cfg(feature = "_sync-sender")]
    pub fn from_env() -> Result<Self> {
        SenderBuilder::from_env()?.build()
    }

    /// Creates a new [`Buffer`] using the sender's protocol settings
    pub fn new_buffer(&self) -> Buffer {
        #[cfg(feature = "sync-sender-qwp-udp")]
        if matches!(&self.handler, SyncProtocolHandler::SyncQwpUdp(_)) {
            return Buffer::qwp_with_max_name_len(self.max_name_len);
        }

        #[cfg(feature = "sync-sender-qwp-ws")]
        if matches!(
            &self.handler,
            SyncProtocolHandler::SyncQwpWs(_) | SyncProtocolHandler::ManualQwpWs(_)
        ) {
            return Buffer::qwp_with_max_name_len(self.max_name_len);
        }

        Buffer::with_max_name_len(self.protocol_version, self.max_name_len)
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn flush_qwp_ws_buffer(&mut self, buf: &Buffer, transactional: bool) -> Result<Option<u64>> {
        if !matches!(
            &self.handler,
            SyncProtocolHandler::SyncQwpWs(_) | SyncProtocolHandler::ManualQwpWs(_)
        ) {
            return Err(error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket FSN methods are only supported for QWP/WebSocket senders."
            ));
        }
        match &self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_check_error_background(state)?,
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_check_error_manual(state)?,
            _ => unreachable!("QWP/WebSocket handler was checked above"),
        }

        let qwp = buf.as_qwp().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket sender requires a QWP buffer created by `Sender::new_buffer()`."
            )
        })?;
        qwp.check_can_flush()?;
        if qwp.is_empty() {
            return Ok(None);
        }
        if qwp.len() > self.max_buf_size {
            return Err(error::fmt!(
                InvalidApiCall,
                "Could not flush buffer: QWP buffer size hint of {} exceeds maximum configured allowed size of {} bytes.",
                qwp.len(),
                self.max_buf_size
            ));
        }
        if transactional {
            return Err(error::fmt!(
                InvalidApiCall,
                "Transactional flushes are not supported for QWP/WebSocket."
            ));
        }

        let result = match &mut self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => flush_qwp_ws(state, qwp),
            SyncProtocolHandler::ManualQwpWs(state) => flush_qwp_ws_manual(state, qwp),
            _ => unreachable!("QWP/WebSocket handler was checked above"),
        };
        if result
            .as_ref()
            .is_err_and(|err| matches!(err.code(), crate::ErrorCode::SocketError))
        {
            self.connected = false;
        }
        result
    }

    #[allow(unused_variables)]
    fn flush_impl(&mut self, buf: &Buffer, transactional: bool) -> Result<()> {
        #[cfg(feature = "sync-sender-qwp-udp")]
        #[allow(irrefutable_let_patterns)]
        if let SyncProtocolHandler::SyncQwpUdp(ref mut state) = self.handler {
            let qwp = buf.as_qwp().ok_or_else(|| {
                error::fmt!(
                    InvalidApiCall,
                    "QWP/UDP sender requires a QWP buffer created by `Sender::new_buffer()`."
                )
            })?;
            qwp.check_can_flush()?;
            if qwp.is_empty() {
                return Ok(());
            }
            if qwp.len() > self.max_buf_size {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "Could not flush buffer: QWP buffer size hint of {} exceeds maximum configured allowed size of {} bytes.",
                    qwp.len(),
                    self.max_buf_size
                ));
            }
            if transactional {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "Transactional flushes are not supported for QWP/UDP."
                ));
            }
            return flush_qwp_udp(state, qwp);
        }

        #[cfg(feature = "sync-sender-qwp-ws")]
        if matches!(
            &self.handler,
            SyncProtocolHandler::SyncQwpWs(_) | SyncProtocolHandler::ManualQwpWs(_)
        ) {
            return self.flush_qwp_ws_buffer(buf, transactional).map(|_| ());
        }

        if !self.connected {
            return Err(error::fmt!(
                SocketError,
                "Could not flush buffer: not connected to database."
            ));
        }
        let ilp = buf.as_ilp().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "ILP sender requires an ILP buffer. QWP buffers must be flushed with a QWP/UDP sender."
            )
        })?;
        ilp.check_can_flush()?;

        let bytes = ilp.as_bytes();
        if bytes.is_empty() {
            return Ok(());
        }

        if ilp.len() > self.max_buf_size {
            return Err(error::fmt!(
                InvalidApiCall,
                "Could not flush buffer: Buffer size of {} exceeds maximum configured allowed size of {} bytes.",
                ilp.len(),
                self.max_buf_size
            ));
        }

        self.check_protocol_version(ilp.protocol_version())?;
        match self.handler {
            #[cfg(feature = "sync-sender-tcp")]
            SyncProtocolHandler::SyncTcp(ref mut conn) => {
                if transactional {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "Transactional flushes are not supported for ILP over TCP."
                    ));
                }
                conn.write_all(bytes).map_err(|io_err| {
                    self.connected = false;
                    map_io_to_socket_err("Could not flush buffer: ", io_err)
                })?;
                conn.flush().map_err(|io_err| {
                    self.connected = false;
                    map_io_to_socket_err("Could not flush to network: ", io_err)
                })?;
                Ok(())
            }
            #[cfg(feature = "sync-sender-http")]
            SyncProtocolHandler::SyncHttp(ref state) => {
                if transactional && !ilp.transactional() {
                    return Err(error::fmt!(
                        InvalidApiCall,
                        "Buffer contains lines for multiple tables. \
                        Transactional flushes are only supported for buffers containing lines for a single table."
                    ));
                }
                let request_min_throughput = *state.config.request_min_throughput;
                let extra_time = if request_min_throughput > 0 {
                    (bytes.len() as f64) / (request_min_throughput as f64)
                } else {
                    0.0f64
                };

                match http_send_with_retries(
                    state,
                    bytes,
                    *state.config.request_timeout + std::time::Duration::from_secs_f64(extra_time),
                    *state.config.retry_timeout,
                ) {
                    Ok(res) => {
                        if res.status().is_client_error() || res.status().is_server_error() {
                            Err(parse_http_error(res.status().as_u16(), res))
                        } else {
                            res.into_body();
                            Ok(())
                        }
                    }
                    Err(err) => Err(crate::error::Error::from_ureq_error(err, &state.url)),
                }
            }
            #[cfg(feature = "sync-sender-qwp-udp")]
            SyncProtocolHandler::SyncQwpUdp(_) => Err(error::fmt!(
                InvalidApiCall,
                "internal error: QWP/UDP handler in ILP flush path"
            )),
            #[cfg(feature = "sync-sender-qwp-ws")]
            SyncProtocolHandler::SyncQwpWs(_) => Err(error::fmt!(
                InvalidApiCall,
                "internal error: QWP/WebSocket handler in ILP flush path"
            )),
            #[cfg(feature = "sync-sender-qwp-ws")]
            SyncProtocolHandler::ManualQwpWs(_) => Err(error::fmt!(
                InvalidApiCall,
                "internal error: manual QWP/WebSocket handler in ILP flush path"
            )),
        }
    }

    /// Send the batch of rows in the buffer to the QuestDB server, and, if the
    /// `transactional` parameter is true, ensure the flush will be transactional.
    ///
    /// A flush is transactional iff all the rows belong to the same table. This allows
    /// QuestDB to treat the flush as a single database transaction, because it doesn't
    /// support transactions spanning multiple tables. Additionally, only ILP-over-HTTP
    /// supports transactional flushes; QWP/UDP is a best-effort datagram transport and
    /// has no flush-level atomicity guarantee.
    ///
    /// If the flush wouldn't be transactional, this function returns an error and
    /// doesn't flush any data.
    ///
    /// The function sends an HTTP request and waits for the response. If the server
    /// responds with an error, it returns a descriptive error. In the case of a network
    /// error, it retries until it has exhausted the retry time budget.
    ///
    /// All the data stays in the buffer. Clear the buffer before starting a new batch.
    #[cfg(feature = "sync-sender-http")]
    pub fn flush_and_keep_with_flags(&mut self, buf: &Buffer, transactional: bool) -> Result<()> {
        self.flush_impl(buf, transactional)
    }

    /// Send the given buffer of rows to the QuestDB server.
    ///
    /// All the data stays in the buffer. Clear the buffer before starting a new batch.
    ///
    /// To send and clear in one step, call [Sender::flush] instead.
    pub fn flush_and_keep(&mut self, buf: &Buffer) -> Result<()> {
        self.flush_impl(buf, false)
    }

    /// Send the given buffer of rows to the QuestDB server, clearing the buffer.
    ///
    /// After this function returns, the buffer is empty and ready for the next batch.
    /// If you want to preserve the buffer contents, call [Sender::flush_and_keep]. If
    /// you want to ensure the flush is transactional, call
    /// [Sender::flush_and_keep_with_flags].
    ///
    /// With ILP-over-HTTP, this function sends an HTTP request and waits for the
    /// response. If the server responds with an error, it returns a descriptive error.
    /// In the case of a network error, it retries until it has exhausted the retry time
    /// budget.
    ///
    /// With ILP-over-TCP, the function blocks only until the buffer is flushed to the
    /// underlying OS-level network socket, without waiting to actually send it to the
    /// server. In the case of an error, the server will quietly disconnect: consult the
    /// server logs for error messages.
    ///
    /// With QWP-over-UDP, the function sends one or more UDP datagrams and returns
    /// local socket errors only. A successful return does not guarantee delivery, and
    /// when a flush spans multiple datagrams there is no all-or-nothing guarantee for
    /// the logical batch.
    ///
    /// With QWP-over-WebSocket, the function publishes the rows into local
    /// memory or Store-and-Forward storage and returns without waiting for the
    /// submitted frame's server ACK. It may still wait for local capacity. In
    /// the default background progress mode, a sender-owned runner sends,
    /// receives ACKs, reconnects, and replays as needed. In manual progress
    /// mode, the caller must use `Sender::drive_once` or
    /// `Sender::await_acked_fsn` to advance WebSocket progress. Server or
    /// transport failures observed later are reported by subsequent sender
    /// calls.
    ///
    /// HTTP should be the first choice, but use TCP if you need to continuously send
    /// data to the server at a high rate.
    ///
    /// To improve the HTTP performance, send larger buffers (with more rows), and
    /// consider parallelizing writes using multiple senders from multiple threads.
    pub fn flush(&mut self, buf: &mut Buffer) -> crate::Result<()> {
        self.flush_impl(buf, false)?;
        buf.clear();
        Ok(())
    }

    /// Publish the QWP/WebSocket buffer and return the highest published frame
    /// sequence number.
    ///
    /// This is QWP/WebSocket-specific. It has the same local-publication
    /// semantics as [`Sender::flush`]: it returns after the frame is accepted
    /// by the local replay queue, before the server necessarily ACKs it. Empty
    /// buffers return `Ok(None)`.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn flush_and_get_fsn(&mut self, buf: &mut Buffer) -> Result<Option<u64>> {
        let fsn = self.flush_and_keep_and_get_fsn(buf)?;
        buf.clear();
        Ok(fsn)
    }

    /// Publish the QWP/WebSocket buffer without clearing it and return the
    /// highest published frame sequence number.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn flush_and_keep_and_get_fsn(&mut self, buf: &Buffer) -> Result<Option<u64>> {
        self.flush_qwp_ws_buffer(buf, false)
    }

    /// Return the highest frame sequence number published locally by this
    /// QWP/WebSocket sender, or `None` if no frame has been published.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn published_fsn(&self) -> Result<Option<u64>> {
        match &self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_published_fsn_background(state),
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_published_fsn_manual(state),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "published_fsn is only supported for QWP/WebSocket senders."
            )),
        }
    }

    /// Return the highest frame sequence number completed by server ACK or
    /// server-side reject-and-continue, or `None` if no frame has completed.
    /// In QWP/WebSocket durable ACK mode, ordinary OK frames only release send
    /// window pressure; this watermark advances after durable ACK coverage.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn acked_fsn(&self) -> Result<Option<u64>> {
        match &self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_acked_fsn_background(state),
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_acked_fsn_manual(state),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "acked_fsn is only supported for QWP/WebSocket senders."
            )),
        }
    }

    /// Wait until the QWP/WebSocket cumulative completion watermark reaches
    /// `fsn`.
    ///
    /// The watermark advances on server ACKs and server-side
    /// reject-and-continue responses. In QWP/WebSocket durable ACK mode,
    /// ordinary OK frames only release send window pressure; this waits for
    /// durable ACK coverage. Returns `Ok(true)` if the watermark is reached
    /// before `timeout`, and `Ok(false)` on timeout. In manual progress mode
    /// this method also drives WebSocket progress while waiting.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn await_acked_fsn(&mut self, fsn: u64, timeout: Duration) -> Result<bool> {
        if !matches!(
            &self.handler,
            SyncProtocolHandler::SyncQwpWs(_) | SyncProtocolHandler::ManualQwpWs(_)
        ) {
            return Err(error::fmt!(
                InvalidApiCall,
                "await_acked_fsn is only supported for QWP/WebSocket senders."
            ));
        }

        let deadline = Instant::now().checked_add(timeout);
        loop {
            if self.acked_fsn()?.is_some_and(|acked| acked >= fsn) {
                return Ok(true);
            }
            if qwp_ws_deadline_expired(deadline) {
                return Ok(false);
            }

            match &mut self.handler {
                SyncProtocolHandler::ManualQwpWs(state) => {
                    if !qwp_ws_drive_once(state)? {
                        qwp_ws_sleep_until(deadline);
                    }
                }
                SyncProtocolHandler::SyncQwpWs(_) => qwp_ws_sleep_until(deadline),
                _ => unreachable!("QWP/WebSocket handler was checked above"),
            }
        }
    }

    /// Poll the next structured QWP/WebSocket server error observed by this
    /// sender.
    ///
    /// This reports QWP server non-OK responses and terminal WebSocket
    /// protocol violations. It remains usable after the sender has halted so
    /// callers can inspect the error that made it terminal.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn poll_qwp_ws_error(&mut self) -> Result<Option<QwpWsSenderError>> {
        match &mut self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_poll_sender_error_background(state),
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_poll_sender_error_manual(state),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "poll_qwp_ws_error is only supported for QWP/WebSocket senders."
            )),
        }
    }

    /// Return the structured QWP/WebSocket diagnostic that halted this sender,
    /// if terminalization was caused by a QWP/WebSocket server or protocol
    /// error.
    ///
    /// Unlike [`Sender::poll_qwp_ws_error`], this does not consume the diagnostic.
    #[cfg(feature = "sync-sender-qwp-ws")]
    #[doc(hidden)]
    pub fn qwp_ws_terminal_error(&self) -> Result<Option<QwpWsSenderError>> {
        match &self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_terminal_sender_error_background(state),
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_terminal_sender_error_manual(state),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "qwp_ws_terminal_error is only supported for QWP/WebSocket senders."
            )),
        }
    }

    /// Return how many QWP/WebSocket structured server errors were dropped
    /// because the sender's bounded diagnostic ring was full.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn qwp_ws_errors_dropped(&self) -> Result<u64> {
        match &self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_sender_errors_dropped_background(state),
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_sender_errors_dropped_manual(state),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "qwp_ws_errors_dropped is only supported for QWP/WebSocket senders."
            )),
        }
    }

    /// Drive one QWP/WebSocket progress step when the sender was built with
    /// [`QwpWsProgress::Manual`].
    ///
    /// This sends at most one queued frame or polls one ready response. It
    /// returns `Ok(false)` when no progress is immediately available.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn drive_once(&mut self) -> Result<bool> {
        match &mut self.handler {
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_drive_once(state),
            SyncProtocolHandler::SyncQwpWs(_) => Err(error::fmt!(
                InvalidApiCall,
                "drive_once is only supported when qwp_ws_progress is manual."
            )),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "drive_once is only supported for QWP/WebSocket senders."
            )),
        }
    }

    /// Stop accepting new QWP/WebSocket publications and wait for all already
    /// published frames to complete.
    ///
    /// This uses the current built-in close-drain timeout. The Java-compatible
    /// `close_flush_timeout_millis` config key is still rejected until Rust
    /// exposes configurable close-drain timeout semantics.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn close_drain(&mut self) -> Result<()> {
        let result = match &mut self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_close_drain_background(state),
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_close_drain_manual(state),
            _ => Err(error::fmt!(
                InvalidApiCall,
                "close_drain is only supported for QWP/WebSocket senders."
            )),
        };
        if result
            .as_ref()
            .is_err_and(|err| matches!(err.code(), crate::ErrorCode::SocketError))
        {
            self.connected = false;
        }
        result
    }

    /// Tell whether the sender is no longer usable and must be dropped.
    ///
    /// This happens when there was an earlier failure.
    ///
    /// This method is specific to ILP-over-TCP and is not relevant for ILP-over-HTTP.
    pub fn must_close(&self) -> bool {
        !self.connected
    }

    /// Returns the sender's configured transport protocol.
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Returns the sender's protocol version.
    ///
    /// The returned value may be explicitly configured, auto-detected, or a
    /// transport-defined default. Interpret it together with [`Sender::protocol`]
    /// and [`ProtocolVersion`]. For QWP/UDP this reports the QWP datagram
    /// version, currently represented as [`ProtocolVersion::V1`]; it is not an
    /// ILP feature version.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Return the sender's maxinum name length of any column or table name.
    /// This is either set explicitly when constructing the sender,
    /// or the default value of 127.
    /// When unset and using protocol version 2 over HTTP, the value is read
    /// from the server from the `cairo.max.file.name.length` setting in
    /// `server.conf` which defaults to 127.
    pub fn max_name_len(&self) -> usize {
        self.max_name_len
    }

    #[inline(always)]
    fn check_protocol_version(&self, version: ProtocolVersion) -> Result<()> {
        if self.protocol_version != version {
            return Err(error::fmt!(
                ProtocolVersionError,
                "Attempting to send with protocol version {} \
                but the sender is configured to use protocol version {}",
                version,
                self.protocol_version
            ));
        }
        Ok(())
    }
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn qwp_ws_deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|deadline| Instant::now() >= deadline)
}

#[cfg(feature = "sync-sender-qwp-ws")]
fn qwp_ws_sleep_until(deadline: Option<Instant>) {
    const PARK: Duration = Duration::from_micros(50);
    if qwp_ws_deadline_expired(deadline) {
        return;
    }
    let sleep_for = deadline
        .map(|deadline| deadline.saturating_duration_since(Instant::now()).min(PARK))
        .unwrap_or(PARK);
    if !sleep_for.is_zero() {
        std::thread::sleep(sleep_for);
    }
}
