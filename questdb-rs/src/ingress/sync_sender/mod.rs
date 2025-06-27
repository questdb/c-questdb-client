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
use crate::ingress::{Buffer, ProtocolVersion, SenderBuilder};
use std::fmt::{Debug, Formatter};

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

pub(crate) enum SyncProtocolHandler {
    #[cfg(feature = "sync-sender-tcp")]
    SyncTcp(SyncConnection),

    #[cfg(feature = "sync-sender-http")]
    SyncHttp(SyncHttpHandlerState),
}

/// Connects to a QuestDB instance and inserts data via the ILP protocol.
///
/// * To construct an instance, use [`Sender::from_conf`] or the [`SenderBuilder`].
/// * To prepare messages, use [`Buffer`] objects.
/// * To send messages, call the [`flush`](Sender::flush) method.
pub struct Sender {
    descr: String,
    handler: SyncProtocolHandler,
    connected: bool,
    max_buf_size: usize,
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
        protocol_version: ProtocolVersion,
        max_name_len: usize,
    ) -> Self {
        Self {
            descr,
            handler,
            connected: true,
            max_buf_size,
            protocol_version,
            max_name_len,
        }
    }

    /// Create a new `Sender` instance from the given configuration string.
    ///
    /// The format of the string is: `"http::addr=host:port;key=value;...;"`.
    ///
    /// Instead of `"http"`, you can also specify `"https"`, `"tcp"`, and `"tcps"`.
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
    pub fn from_env() -> Result<Self> {
        SenderBuilder::from_env()?.build()
    }

    /// Creates a new [`Buffer`] using the sender's protocol settings
    pub fn new_buffer(&self) -> Buffer {
        Buffer::with_max_name_len(self.protocol_version, self.max_name_len)
    }

    #[allow(unused_variables)]
    fn flush_impl(&mut self, buf: &Buffer, transactional: bool) -> Result<()> {
        if !self.connected {
            return Err(error::fmt!(
                SocketError,
                "Could not flush buffer: not connected to database."
            ));
        }
        buf.check_can_flush()?;

        if buf.len() > self.max_buf_size {
            return Err(error::fmt!(
                InvalidApiCall,
                "Could not flush buffer: Buffer size of {} exceeds maximum configured allowed size of {} bytes.",
                buf.len(),
                self.max_buf_size
            ));
        }

        self.check_protocol_version(buf.version)?;

        let bytes = buf.as_bytes();
        if bytes.is_empty() {
            return Ok(());
        }
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
                Ok(())
            }
            #[cfg(feature = "sync-sender-http")]
            SyncProtocolHandler::SyncHttp(ref state) => {
                if transactional && !buf.transactional() {
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
        }
    }

    /// Send the batch of rows in the buffer to the QuestDB server, and, if the
    /// `transactional` parameter is true, ensure the flush will be transactional.
    ///
    /// A flush is transactional iff all the rows belong to the same table. This allows
    /// QuestDB to treat the flush as a single database transaction, because it doesn't
    /// support transactions spanning multiple tables. Additionally, only ILP-over-HTTP
    /// supports transactional flushes.
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

    /// Tell whether the sender is no longer usable and must be dropped.
    ///
    /// This happens when there was an earlier failure.
    ///
    /// This method is specific to ILP-over-TCP and is not relevant for ILP-over-HTTP.
    pub fn must_close(&self) -> bool {
        !self.connected
    }

    /// Returns the sender's protocol version
    ///
    /// - Explicitly set version, or
    /// - Auto-detected for HTTP transport, or [`ProtocolVersion::V1`] for TCP transport.
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
