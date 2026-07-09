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

// `SyncProtocolHandler` is cfg-pruned: with only `sync-sender-qwp-ws`
// enabled, the enum has just the two `*QwpWs` variants and a number
// of `_ =>` fallbacks here become unreachable. Suppress only in that
// exact configuration so a regression in the multi-handler builds
// still surfaces.
#![cfg_attr(
    not(any(
        feature = "sync-sender-tcp",
        feature = "sync-sender-http",
        feature = "sync-sender-qwp-udp"
    )),
    allow(unreachable_patterns)
)]

use crate::error::{self, Result};
#[cfg(feature = "sync-sender-qwp-ws")]
use crate::ingress::AckLevel;
#[cfg(feature = "_sync-sender")]
use crate::ingress::SenderBuilder;
use crate::ingress::{Buffer, Protocol, ProtocolVersion};
use std::fmt::{Debug, Formatter};
#[cfg(feature = "sync-sender-qwp-ws")]
use std::sync::atomic::{AtomicUsize, Ordering};
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

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) use qwp_ws_driver::{
    ReconnectPolicy, ReconnectReason, reconnect_backoff_step, reconnect_error_is_terminal,
};

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_ownership;

#[cfg(feature = "_sender-qwp-ws")]
mod qwp_ws_orphan;
#[cfg(all(test, feature = "_sender-qwp-ws"))]
pub(crate) use qwp_ws_orphan::has_any_sfa_file;
#[cfg(feature = "_sender-qwp-ws")]
pub(crate) use qwp_ws_orphan::is_candidate_orphan;

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
pub(crate) use qwp_ws_ownership::QwpWsRoleReject;
#[cfg(feature = "_sender-qwp-ws")]
pub use qwp_ws_ownership::*;

#[cfg(feature = "sync-sender-qwp-ws")]
pub(crate) mod qwp_ws;

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

#[cfg(feature = "sync-sender-qwp-ws")]
fn effective_qwp_ws_max_buf_size(configured: usize, server_max: &AtomicUsize) -> usize {
    let server = server_max.load(Ordering::Relaxed);
    if server > 0 {
        configured.min(server)
    } else {
        configured
    }
}

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
    init_buf_size: usize,
    max_buf_size: usize,
    protocol: Protocol,
    protocol_version: ProtocolVersion,
    max_name_len: usize,
    #[cfg(feature = "_sender-qwp-ws")]
    qwp_ws_error_handler: QwpWsErrorHandler,
}

impl Debug for Sender {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        f.write_str(self.descr.as_str())
    }
}

impl Sender {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        descr: String,
        handler: SyncProtocolHandler,
        init_buf_size: usize,
        max_buf_size: usize,
        protocol: Protocol,
        protocol_version: ProtocolVersion,
        max_name_len: usize,
        #[cfg(feature = "_sender-qwp-ws")] qwp_ws_error_handler: QwpWsErrorHandler,
    ) -> Self {
        Self {
            descr,
            handler,
            connected: true,
            init_buf_size,
            max_buf_size,
            protocol,
            protocol_version,
            max_name_len,
            #[cfg(feature = "_sender-qwp-ws")]
            qwp_ws_error_handler,
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
            return Buffer::qwp_ws_with_max_name_len(self.max_name_len);
        }

        Buffer::with_init_capacity_and_max_name_len(
            self.protocol_version,
            self.init_buf_size,
            self.max_name_len,
        )
    }

    #[cfg(feature = "sync-sender-qwp-ws")]
    fn drain_qwp_ws_error_notifications(&mut self) -> Result<()> {
        loop {
            let error = match &mut self.handler {
                SyncProtocolHandler::SyncQwpWs(state) => {
                    qwp_ws_poll_sender_error_notification_background(state)?
                }
                SyncProtocolHandler::ManualQwpWs(state) => {
                    qwp_ws_poll_sender_error_notification_manual(state)?
                }
                _ => return Ok(()),
            };
            let Some(error) = error else {
                return Ok(());
            };
            self.qwp_ws_error_handler.handle(&error);
        }
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
            SyncProtocolHandler::SyncQwpWs(state) => {
                if let Err(err) = qwp_ws_check_error_background(state) {
                    let _ = self.drain_qwp_ws_error_notifications();
                    return Err(err);
                }
            }
            SyncProtocolHandler::ManualQwpWs(state) => {
                if let Err(err) = qwp_ws_check_error_manual(state) {
                    let _ = self.drain_qwp_ws_error_notifications();
                    return Err(err);
                }
            }
            _ => unreachable!("QWP/WebSocket handler was checked above"),
        }
        self.drain_qwp_ws_error_notifications()?;

        let qwp = buf.as_qwp_ws().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket sender requires a QWP/WebSocket buffer created by `Sender::new_buffer()`."
            )
        })?;
        qwp.check_can_flush()?;
        if qwp.is_empty() {
            return Ok(None);
        }
        if transactional {
            return Err(error::fmt!(
                InvalidApiCall,
                "Transactional flushes are not supported for QWP/WebSocket."
            ));
        }

        let result = match &mut self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => {
                let max =
                    effective_qwp_ws_max_buf_size(self.max_buf_size, &state.server_max_batch_size);
                flush_qwp_ws(state, qwp, max)
            }
            SyncProtocolHandler::ManualQwpWs(state) => {
                let max =
                    effective_qwp_ws_max_buf_size(self.max_buf_size, &state.server_max_batch_size);
                flush_qwp_ws_manual(state, qwp, max)
            }
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
                    *state.config.retry_max_backoff,
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
    /// `Sender::wait` to advance WebSocket progress. Server or
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
    ///
    /// Use this when you need non-blocking/pipelined progress tracking on this
    /// sender stream: keep the returned FSN and compare it with
    /// [`Self::acked_fsn`]. Use [`Self::wait`] instead when you only need a
    /// blocking barrier for everything published so far.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn flush_and_get_fsn(&mut self, buf: &mut Buffer) -> Result<Option<u64>> {
        let fsn = self.flush_and_keep_and_get_fsn(buf)?;
        buf.clear();
        Ok(fsn)
    }

    /// Publish the QWP/WebSocket buffer without clearing it and return the
    /// highest published frame sequence number.
    ///
    /// The returned FSN has the same local-publication semantics as
    /// [`Self::flush_and_get_fsn`].
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn flush_and_keep_and_get_fsn(&mut self, buf: &Buffer) -> Result<Option<u64>> {
        self.flush_qwp_ws_buffer(buf, false)
    }

    /// Return the highest frame sequence number published locally by this
    /// QWP/WebSocket sender, or `None` if no frame has been published.
    ///
    /// This is a sender-stream watermark, not a process-global receipt.
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
    ///
    /// After [`Self::flush_and_get_fsn`] returns `Some(fsn)`, that publication
    /// boundary has completed once this method returns a value greater than or
    /// equal to `fsn`. Use [`Self::wait`] when you need an explicit
    /// [`AckLevel::Ok`] or [`AckLevel::Durable`] barrier.
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

    /// Wait until every QWP/WebSocket frame published so far on this sender
    /// reaches `ack_level`, or until the wait makes no progress for `timeout`.
    ///
    /// This is the row-major counterpart to the column-major
    /// [`crate::BorrowedColumnSender::wait`]: it takes the cumulative publication
    /// boundary ([`Self::published_fsn`]) and blocks until the requested
    /// completion watermark covers it.
    ///
    /// * [`AckLevel::Ok`] waits for the server to accept every published
    ///   frame.
    /// * [`AckLevel::Durable`] waits for durable-ACK coverage. It requires the
    ///   sender to be opened with `request_durable_ack=on`; otherwise the call
    ///   is rejected before checking whether any frame has been published.
    ///
    /// `timeout` is a **no-progress** deadline: it fires only if the ack
    /// watermark fails to advance for that long, so a steadily-progressing
    /// large batch keeps waiting. `Duration::ZERO` waits indefinitely. On
    /// expiry it returns an
    /// [`ErrorCode::FailoverRetry`](crate::error::ErrorCode::FailoverRetry)
    /// error and the published frames are retained for replay.
    ///
    /// A terminal server rejection of a frame in the pending range, or a
    /// terminal transport/protocol failure, is returned as an error. Retriable
    /// server rejections reconnect and replay until the frame is acknowledged or
    /// the sender is stopped. When nothing has been published yet, a valid wait
    /// returns immediately. QWP/WebSocket only; other
    /// protocols return `InvalidApiCall`. In manual progress mode this also
    /// drives WebSocket progress while waiting.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn wait(&mut self, ack_level: AckLevel, timeout: Duration) -> Result<()> {
        if !matches!(
            &self.handler,
            SyncProtocolHandler::SyncQwpWs(_) | SyncProtocolHandler::ManualQwpWs(_)
        ) {
            return Err(error::fmt!(
                InvalidApiCall,
                "wait is only supported for QWP/WebSocket senders."
            ));
        }

        if ack_level == AckLevel::Durable {
            let request_durable_ack = match &self.handler {
                SyncProtocolHandler::SyncQwpWs(state) => state.request_durable_ack,
                SyncProtocolHandler::ManualQwpWs(state) => state.request_durable_ack,
                _ => unreachable!("QWP/WebSocket handler was checked above"),
            };
            if !request_durable_ack {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "AckLevel::Durable requires the pool to be opened with \
                     `request_durable_ack=on` in the connect string."
                ));
            }
        }

        let Some(boundary) = self.published_fsn()? else {
            return Ok(());
        };

        // No-progress deadline: reset whenever the completion watermark
        // advances, so it only fires when the peer stays alive yet silent.
        let mut deadline_anchor = Instant::now();
        let mut last_completed: Option<u64> = None;

        loop {
            let completed = self.qwp_ws_completed_fsn(ack_level)?;
            if completed.is_some_and(|fsn| fsn >= boundary) {
                return Ok(());
            }
            if completed != last_completed {
                last_completed = completed;
                deadline_anchor = Instant::now();
            }
            if !timeout.is_zero() && deadline_anchor.elapsed() >= timeout {
                return Err(qwp_ws_wait_timeout(ack_level, timeout, boundary, completed));
            }

            match &mut self.handler {
                SyncProtocolHandler::ManualQwpWs(state) => {
                    if !qwp_ws_drive_once(state)? {
                        qwp_ws_sleep_until(None);
                    }
                }
                SyncProtocolHandler::SyncQwpWs(_) => qwp_ws_sleep_until(None),
                _ => unreachable!("QWP/WebSocket handler was checked above"),
            }
        }
    }

    /// Completion watermark for `ack_level` across both QWP/WebSocket progress
    /// modes. `Ok` tracks server acceptance; `Durable` tracks durable-ACK
    /// coverage. Terminal failures surface here as an `Err`.
    #[cfg(feature = "sync-sender-qwp-ws")]
    fn qwp_ws_completed_fsn(&self, ack_level: AckLevel) -> Result<Option<u64>> {
        match (&self.handler, ack_level) {
            (SyncProtocolHandler::SyncQwpWs(state), AckLevel::Ok) => {
                qwp_ws_ok_fsn_background(state)
            }
            (SyncProtocolHandler::SyncQwpWs(state), AckLevel::Durable) => {
                qwp_ws_acked_fsn_background(state)
            }
            (SyncProtocolHandler::ManualQwpWs(state), AckLevel::Ok) => qwp_ws_ok_fsn_manual(state),
            (SyncProtocolHandler::ManualQwpWs(state), AckLevel::Durable) => {
                qwp_ws_acked_fsn_manual(state)
            }
            _ => Err(error::fmt!(
                InvalidApiCall,
                "wait is only supported for QWP/WebSocket senders."
            )),
        }
    }

    /// Poll the next structured QWP/WebSocket server error observed by this
    /// sender.
    ///
    /// This reports QWP server non-OK responses and WebSocket protocol
    /// violations. It remains usable after the sender has halted so
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

    /// Return how many QWP/WebSocket structured diagnostics were dropped
    /// because the sender's unified bounded diagnostic log was full.
    ///
    /// The same log feeds [`Sender::poll_qwp_ws_error`] and
    /// `QwpWsErrorHandler` notification delivery through independent cursors.
    /// A diagnostic is retained until both cursors have consumed it, so a
    /// lagging cursor can cause later diagnostics to overwrite unread entries
    /// and increment this count.
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

    /// Snapshot the QWP/WebSocket sender's lifetime totals.
    ///
    /// Mirrors the `getTotal*` counters on Java's `QwpWebSocketSender` so the
    /// QuestDB Enterprise e2e harness (questdb-ent/e2e) can read identical
    /// signals across language bindings. See [`QwpWsTotals`] for the field
    /// list. Returns `InvalidApiCall` for non-QWP/WebSocket senders.
    #[cfg(feature = "sync-sender-qwp-ws")]
    pub fn qwp_ws_totals(&self) -> Result<QwpWsTotals> {
        let counters = match &self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => qwp_ws_counters_background(state)?,
            SyncProtocolHandler::ManualQwpWs(state) => qwp_ws_counters_manual(state)?,
            _ => {
                return Err(error::fmt!(
                    InvalidApiCall,
                    "qwp_ws_totals is only supported for QWP/WebSocket senders."
                ));
            }
        };
        Ok(counters.into())
    }

    /// Drive one QWP/WebSocket progress step when the sender was built with
    /// [`QwpWsProgress::Manual`].
    ///
    /// One call performs, in order:
    /// - send at most one queued frame;
    /// - drain all ready response frames from the transport (acks, durable
    ///   acks, rejects), applying their effects on local store state;
    /// - perform at most one bounded storage-maintenance step (provision a
    ///   missing hot spare or trim one fully-acked sealed segment) when
    ///   Store-and-Forward is configured;
    /// - send a durable-ACK keepalive only if nothing above produced
    ///   progress and one is due.
    ///
    /// Returns `Ok(true)` if any of those steps produced progress and
    /// `Ok(false)` when the call was idle. Manual schedulers should keep
    /// calling `drive_once` until it returns `false` before parking, since the
    /// receive drain and storage maintenance are paced one unit per call:
    /// hot-spare provisioning and segment trim each take their own call, so a
    /// large ACK can free segment-cap headroom over several `drive_once`
    /// turns.
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
    /// The wait is bounded by the QWP/WebSocket `close_flush_timeout_millis`
    /// setting. Its default is 5000 ms, matching the Java sender. Values less
    /// than or equal to zero skip the wait.
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
        let drain_result = if matches!(
            &self.handler,
            SyncProtocolHandler::SyncQwpWs(_) | SyncProtocolHandler::ManualQwpWs(_)
        ) {
            self.drain_qwp_ws_error_notifications()
        } else {
            Ok(())
        };
        if result
            .as_ref()
            .is_err_and(|err| matches!(err.code(), crate::ErrorCode::SocketError))
        {
            self.connected = false;
        }
        result.and(drain_result)
    }

    /// Tell whether the sender is no longer usable and must be dropped.
    ///
    /// Returns `true` after an unrecoverable failure. For ILP-over-TCP this
    /// is any socket error. For QWP/WebSocket this also covers a server
    /// rejection or protocol violation that latches the publication
    /// lifecycle to its terminal state. ILP-over-HTTP and QWP/UDP never
    /// transition into a permanently-unusable state and always return
    /// `false`.
    ///
    /// In QWP/WebSocket manual progress mode the answer only refreshes when
    /// the user drives the sender (`drive_once` / `flush`), since no
    /// background thread is observing the transport.
    #[must_use]
    pub fn must_close(&self) -> bool {
        if !self.connected {
            return true;
        }
        #[cfg(feature = "sync-sender-qwp-ws")]
        match &self.handler {
            SyncProtocolHandler::SyncQwpWs(state) => return qwp_ws_is_terminal_background(state),
            SyncProtocolHandler::ManualQwpWs(state) => return qwp_ws_is_terminal_manual(state),
            _ => {}
        }
        false
    }

    /// Non-blocking: `true` once a background QWP/WebSocket
    /// store-and-forward sender has no undelivered published frames, so a
    /// parked pooled row sender can be retired without losing queued data.
    /// Non-QWP/WebSocket handlers and terminal background handlers report
    /// `true`.
    pub(crate) fn sfa_fully_delivered(&self, durable: bool) -> bool {
        #[cfg(feature = "sync-sender-qwp-ws")]
        {
            let SyncProtocolHandler::SyncQwpWs(state) = &self.handler else {
                return true;
            };
            if qwp_ws_is_terminal_background(state) {
                return true;
            }
            let Ok(Some(published)) = qwp_ws_published_fsn_background(state) else {
                return true;
            };
            let watermark = if durable {
                qwp_ws_acked_fsn_background(state)
            } else {
                qwp_ws_ok_fsn_background(state)
            };
            matches!(watermark, Ok(Some(w)) if w >= published)
        }
        #[cfg(not(feature = "sync-sender-qwp-ws"))]
        {
            let _ = durable;
            true
        }
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

/// Error for a [`Sender::wait`] that made no ack progress within its
/// no-progress `timeout`. Classified [`ErrorCode::FailoverRetry`]: the
/// published frames are retained and the background runner keeps delivering
/// them, so recover by retrying `wait()` until it returns `Ok` — not by
/// re-flushing, which would duplicate the rows. Mirrors the column-major
/// store-and-forward wait.
#[cfg(feature = "sync-sender-qwp-ws")]
fn qwp_ws_wait_timeout(
    ack_level: AckLevel,
    timeout: Duration,
    boundary: u64,
    completed: Option<u64>,
) -> crate::Error {
    let level = match ack_level {
        AckLevel::Ok => "ok",
        AckLevel::Durable => "durable",
    };
    let progress = match completed {
        Some(fsn) => format!("reached FSN {fsn}"),
        None => "reached no frame".to_string(),
    };
    error::Error::new(
        error::ErrorCode::FailoverRetry,
        format!(
            "QWP/WebSocket wait({level}) timed out after {timeout:?} with no ack \
             progress (target FSN {boundary}, {progress}); the connection is alive \
             but the server is not advancing the watermark. The published frames \
             remain queued and the background runner keeps delivering them: retry \
             wait() to keep awaiting the ack, or close the pool to drain. Do not \
             re-flush the same data, which is already accepted and would be \
             delivered twice."
        ),
    )
}
