use crate::error::{self, Result};
use crate::ingress::{Buffer, ProtocolVersion, SenderBuilder};
use std::fmt::{Debug, Formatter};

#[cfg(feature = "sync-sender-tcp")]
use rustls::{ClientConnection, StreamOwned};

#[cfg(feature = "sync-sender-tcp")]
use crate::ingress::{map_io_to_socket_err, parse_key_pair};

#[cfg(feature = "sync-sender-tcp")]
use std::io::{self, BufReader, Write as IoWrite};

#[cfg(feature = "sync-sender-tcp")]
use socket2::Socket;

#[cfg(feature = "sync-sender-tcp")]
use std::io::BufRead;

#[cfg(all(feature = "sync-sender-tcp", feature = "aws-lc-crypto"))]
use aws_lc_rs::rand::SystemRandom;

#[cfg(all(feature = "sync-sender-tcp", feature = "ring-crypto"))]
use ring::rand::SystemRandom;

#[cfg(feature = "sync-sender-http")]
mod http;

#[cfg(feature = "sync-sender-http")]
pub(crate) use http::*;

#[cfg(feature = "sync-sender-tcp")]
pub(crate) enum SyncConnection {
    Direct(Socket),
    Tls(Box<StreamOwned<ClientConnection, Socket>>),
}

#[cfg(feature = "sync-sender-tcp")]
impl SyncConnection {
    fn send_key_id(&mut self, key_id: &str) -> Result<()> {
        writeln!(self, "{}", key_id)
            .map_err(|io_err| map_io_to_socket_err("Failed to send key_id: ", io_err))?;
        Ok(())
    }

    fn read_challenge(&mut self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        let mut reader = BufReader::new(self);
        reader.read_until(b'\n', &mut buf).map_err(|io_err| {
            map_io_to_socket_err(
                "Failed to read authentication challenge (timed out?): ",
                io_err,
            )
        })?;
        if buf.last().copied().unwrap_or(b'\0') != b'\n' {
            return Err(if buf.is_empty() {
                error::fmt!(
                    AuthError,
                    concat!(
                        "Did not receive auth challenge. ",
                        "Is the database configured to require ",
                        "authentication?"
                    )
                )
            } else {
                error::fmt!(AuthError, "Received incomplete auth challenge: {:?}", buf)
            });
        }
        buf.pop(); // b'\n'
        Ok(buf)
    }

    pub(crate) fn authenticate(
        &mut self,
        auth: &crate::ingress::conf::EcdsaAuthParams,
    ) -> Result<()> {
        use base64ct::{Base64, Encoding};

        if auth.key_id.contains('\n') {
            return Err(error::fmt!(
                AuthError,
                "Bad key id {:?}: Should not contain new-line char.",
                auth.key_id
            ));
        }
        let key_pair = parse_key_pair(auth)?;
        self.send_key_id(auth.key_id.as_str())?;
        let challenge = self.read_challenge()?;
        let rng = SystemRandom::new();
        let signature = key_pair
            .sign(&rng, &challenge[..])
            .map_err(|unspecified_err| {
                error::fmt!(AuthError, "Failed to sign challenge: {}", unspecified_err)
            })?;
        let mut encoded_sig = Base64::encode_string(signature.as_ref());
        encoded_sig.push('\n');
        let buf = encoded_sig.as_bytes();
        if let Err(io_err) = self.write_all(buf) {
            return Err(map_io_to_socket_err(
                "Could not send signed challenge: ",
                io_err,
            ));
        }
        Ok(())
    }
}

pub(crate) enum SyncProtocolHandler {
    #[cfg(feature = "sync-sender-tcp")]
    SyncTcp(SyncConnection),

    #[cfg(feature = "sync-sender-http")]
    SyncHttp(SyncHttpHandlerState),
}

#[cfg(feature = "sync-sender-tcp")]
impl io::Read for SyncConnection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.read(buf),
            Self::Tls(stream) => stream.read(buf),
        }
    }
}

#[cfg(feature = "sync-sender-tcp")]
impl IoWrite for SyncConnection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Direct(sock) => sock.write(buf),
            Self::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Direct(sock) => sock.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
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
    pub fn from_conf<T: AsRef<str>>(conf: T) -> crate::Result<Self> {
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
    pub fn from_env() -> crate::Result<Self> {
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
    pub fn flush_and_keep_with_flags(
        &mut self,
        buf: &Buffer,
        transactional: bool,
    ) -> crate::Result<()> {
        self.flush_impl(buf, transactional)
    }

    /// Send the given buffer of rows to the QuestDB server.
    ///
    /// All the data stays in the buffer. Clear the buffer before starting a new batch.
    ///
    /// To send and clear in one step, call [Sender::flush] instead.
    pub fn flush_and_keep(&mut self, buf: &Buffer) -> crate::Result<()> {
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
    fn check_protocol_version(&self, version: ProtocolVersion) -> crate::Result<()> {
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
