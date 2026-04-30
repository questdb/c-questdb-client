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

//! Sync QWP/WebSocket (RFC 6455) sender. Hand-rolled HTTP/1.1 upgrade and binary
//! framing — no external WebSocket dependency. See QWP_SPECIFICATION §2 (transport),
//! §3 (version negotiation) and §13 (response format).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::error;
use crate::ingress::SyncProtocolHandler;
use crate::ingress::buffer::QwpBuffer;
use crate::ingress::conf::{QwpWsConfig, SfDurability};
use crate::ingress::tls::{TlsSettings, configure_tls};

use super::qwp_ws_codec::{
    self as codec, MAX_INBOUND_FRAME_BYTES, WS_OPCODE_BINARY, WS_OPCODE_CLOSE,
    WS_OPCODE_CONTINUATION, WS_OPCODE_PING, WS_OPCODE_PONG, WS_OPCODE_TEXT,
};
use super::qwp_ws_driver::{
    BlockingQwpWsTransport, DeliveryOutcome, DriverError, ManualDriverPrototype, ManualDriverQueue,
    ReconnectPolicy, reconnect_error_is_terminal,
};
use super::qwp_ws_publisher::{QwpWsPublicationDriver, QwpWsPublicationError};
use super::qwp_ws_queue::{
    OutboundFrame, QwpReceipt, QwpReceiptStatus, SentFrame, VolatileFrameQueue,
    VolatileQueueOptions,
};
use super::qwp_ws_sfa_slot::{SfaSlotOptions, SfaSlotQueue};

// ---------- transport ----------

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

pub(crate) enum WsStream {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl WsStream {
    fn set_timeouts(&self, read: Option<Duration>, write: Option<Duration>) -> std::io::Result<()> {
        let sock = match self {
            WsStream::Plain(s) => s,
            WsStream::Tls(s) => s.get_ref(),
        };
        sock.set_read_timeout(read)?;
        sock.set_write_timeout(write)?;
        Ok(())
    }
}

impl Read for WsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.read(buf),
            WsStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for WsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WsStream::Plain(s) => s.write(buf),
            WsStream::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WsStream::Plain(s) => s.flush(),
            WsStream::Tls(s) => s.flush(),
        }
    }
}

// ---------- handler state ----------

pub(crate) type SyncQwpWsPublisher =
    QwpWsPublicationDriver<ConfiguredQwpWsQueue, BlockingQwpWsTransport>;

pub(crate) struct SyncQwpWsHandlerState {
    pub(crate) publisher: SyncQwpWsPublisher,
    pub(crate) max_flush_drive_steps: usize,
}

pub(crate) enum ConfiguredQwpWsQueue {
    Memory(VolatileFrameQueue),
    StoreAndForward(SfaSlotQueue),
}

impl ConfiguredQwpWsQueue {
    fn open(qwp_ws: &QwpWsConfig) -> crate::Result<Self> {
        if *qwp_ws.sf_durability != SfDurability::Memory {
            let durability = qwp_ws.sf_durability.as_conf_value();
            return Err(error::fmt!(
                ConfigError,
                "sf_durability={durability} is not yet supported (deferred follow-up; use sf_durability=memory)"
            ));
        }

        let max_bytes = usize_from_config("sf_max_total_bytes", qwp_ws.sf_max_total_bytes())?;
        let max_frames = configured_max_frames(qwp_ws)?;
        let max_in_flight = *qwp_ws.max_in_flight;

        if let Some(sf_dir) = qwp_ws.sf_dir.as_ref() {
            return Ok(Self::StoreAndForward(
                SfaSlotQueue::open(SfaSlotOptions {
                    sf_dir: sf_dir.clone(),
                    sender_id: qwp_ws.sender_id.to_string(),
                    segment_size_bytes: *qwp_ws.sf_max_bytes,
                    max_frames,
                    max_bytes,
                    max_in_flight,
                })
                .map_err(|err| {
                    error::fmt!(
                        SocketError,
                        "Could not open QWP/WebSocket Store-and-Forward queue: {:?}",
                        err
                    )
                })?,
            ));
        }

        Ok(Self::Memory(
            VolatileFrameQueue::new(VolatileQueueOptions {
                max_frames,
                max_bytes,
                max_in_flight,
            })
            .map_err(|err| {
                error::fmt!(
                    ConfigError,
                    "Invalid QWP/WebSocket memory queue configuration: {:?}",
                    err
                )
            })?,
        ))
    }
}

fn configured_max_frames(qwp_ws: &QwpWsConfig) -> crate::Result<usize> {
    let max_total_bytes = qwp_ws.sf_max_total_bytes();
    let segment_bytes = (*qwp_ws.sf_max_bytes).max(1);
    let frames_by_bytes = max_total_bytes.div_ceil(segment_bytes).max(1);
    let frames = frames_by_bytes.max(*qwp_ws.max_in_flight as u64);
    usize_from_config("computed QWP/WebSocket max_frames", frames)
}

fn usize_from_config(name: &str, value: u64) -> crate::Result<usize> {
    usize::try_from(value).map_err(|_| {
        error::fmt!(
            ConfigError,
            "{name} value is too large for this platform [value={value}]"
        )
    })
}

impl ManualDriverQueue for ConfiguredQwpWsQueue {
    fn try_submit(&mut self, payload: &[u8]) -> Result<QwpReceipt, DriverError> {
        match self {
            Self::Memory(queue) => Ok(queue.try_submit(payload)?),
            Self::StoreAndForward(queue) => queue.try_submit(payload),
        }
    }

    fn next_outbound_frame(&self) -> Result<OutboundFrame<'_>, DriverError> {
        match self {
            Self::Memory(queue) => Ok(queue.next_outbound_frame()?),
            Self::StoreAndForward(queue) => queue.next_outbound_frame(),
        }
    }

    fn commit_sent(&mut self, frame: SentFrame) -> Result<(), DriverError> {
        match self {
            Self::Memory(queue) => Ok(queue.commit_sent(frame)?),
            Self::StoreAndForward(queue) => queue.commit_sent(frame),
        }
    }

    fn ack_wire(&mut self, wire_seq: u64) -> Result<(), DriverError> {
        match self {
            Self::Memory(queue) => Ok(queue.ack_wire(wire_seq)?),
            Self::StoreAndForward(queue) => queue.ack_wire(wire_seq),
        }
    }

    fn reject_wire(&mut self, wire_seq: u64) -> Result<QwpReceipt, DriverError> {
        match self {
            Self::Memory(queue) => Ok(queue.reject_wire(wire_seq)?),
            Self::StoreAndForward(queue) => queue.reject_wire(wire_seq),
        }
    }

    fn close(&mut self) -> Result<(), DriverError> {
        match self {
            Self::Memory(queue) => queue.close(),
            Self::StoreAndForward(queue) => Ok(queue.close()?),
        }
    }

    fn restart_connection(&mut self) {
        match self {
            Self::Memory(queue) => queue.restart_connection(),
            Self::StoreAndForward(queue) => queue.restart_connection(),
        }
    }

    fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus {
        match self {
            Self::Memory(queue) => queue.receipt_status(receipt),
            Self::StoreAndForward(queue) => queue.receipt_status(receipt),
        }
    }

    fn published_fsn(&self) -> Option<u64> {
        match self {
            Self::Memory(queue) => queue.published_fsn(),
            Self::StoreAndForward(queue) => queue.published_fsn(),
        }
    }

    fn completed_fsn(&self) -> Option<u64> {
        match self {
            Self::Memory(queue) => queue.completed_fsn(),
            Self::StoreAndForward(queue) => queue.completed_fsn(),
        }
    }

    fn fsn_for_wire_seq(&self, wire_seq: u64) -> Result<u64, DriverError> {
        match self {
            Self::Memory(queue) => queue.fsn_for_wire_seq(wire_seq),
            Self::StoreAndForward(queue) => queue.fsn_for_wire_seq(wire_seq),
        }
    }
}

// ---------- minimal SHA-1 for Sec-WebSocket-Accept ----------

// ---------- frame I/O ----------

fn random_mask() -> [u8; 4] {
    let mut mask = [0u8; 4];
    rand::rng().fill_bytes(&mut mask);
    mask
}

/// Write a single binary frame (FIN=1, opcode=0x2). Mask-bit set as required for
/// client → server frames. `out` is a scratch buffer; the frame is then written
/// to `stream` in one or more `write_all` calls.
pub(crate) fn write_binary_frame<W: Write>(
    stream: &mut W,
    out: &mut Vec<u8>,
    payload: &[u8],
) -> std::io::Result<()> {
    codec::write_frame_to_buf(out, true, WS_OPCODE_BINARY, payload, random_mask());
    stream.write_all(out)
}

/// Read one full WebSocket message into `out`. Reassembles fragmented frames.
/// Replies to PING with PONG and treats CLOSE as an error. Returns the opcode
/// of the first data frame (text/binary).
pub(crate) fn read_message<S: Read + Write>(
    stream: &mut S,
    scratch: &mut Vec<u8>,
    out: &mut Vec<u8>,
) -> crate::Result<u8> {
    out.clear();
    let mut first_opcode: Option<u8> = None;
    loop {
        let (fin, opcode, payload) = read_frame(stream)?;
        match opcode {
            WS_OPCODE_PING => {
                codec::write_frame_to_buf(scratch, true, WS_OPCODE_PONG, &payload, random_mask());
                stream.write_all(scratch).map_err(|io| {
                    error::fmt!(SocketError, "Could not send WebSocket PONG: {}", io)
                })?;
                continue;
            }
            WS_OPCODE_PONG => continue,
            WS_OPCODE_CLOSE => {
                let reason = codec::ws_close_reason(&payload);
                return Err(error::fmt!(
                    SocketError,
                    "WebSocket connection closed by server{}",
                    reason
                ));
            }
            WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
                if first_opcode.is_some() {
                    return Err(error::fmt!(
                        SocketError,
                        "Unexpected new data frame mid-message"
                    ));
                }
                first_opcode = Some(opcode);
                out.extend_from_slice(&payload);
            }
            WS_OPCODE_CONTINUATION => {
                if first_opcode.is_none() {
                    return Err(error::fmt!(
                        SocketError,
                        "Continuation frame without prior data frame"
                    ));
                }
                out.extend_from_slice(&payload);
            }
            other => {
                return Err(error::fmt!(
                    SocketError,
                    "Unknown WebSocket opcode: 0x{:x}",
                    other
                ));
            }
        }
        if fin {
            return Ok(first_opcode.unwrap());
        }
    }
}

fn read_frame<R: Read>(stream: &mut R) -> crate::Result<(bool, u8, Vec<u8>)> {
    let mut hdr = [0u8; 2];
    read_exact_io(stream, &mut hdr, "WebSocket frame header")?;
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    if masked {
        return Err(error::fmt!(
            SocketError,
            "WebSocket server frame must not be masked"
        ));
    }
    let len_short = hdr[1] & 0x7F;
    let payload_len: u64 = match len_short {
        126 => {
            let mut b = [0u8; 2];
            read_exact_io(stream, &mut b, "WebSocket frame length")?;
            u16::from_be_bytes(b) as u64
        }
        127 => {
            let mut b = [0u8; 8];
            read_exact_io(stream, &mut b, "WebSocket frame length")?;
            u64::from_be_bytes(b)
        }
        n => n as u64,
    };

    if payload_len > MAX_INBOUND_FRAME_BYTES {
        return Err(error::fmt!(
            SocketError,
            "WebSocket frame too large: {} bytes",
            payload_len
        ));
    }

    let mut payload = vec![0u8; payload_len as usize];
    if !payload.is_empty() {
        read_exact_io(stream, &mut payload, "WebSocket frame payload")?;
    }
    Ok((fin, opcode, payload))
}

fn read_exact_io<R: Read>(stream: &mut R, buf: &mut [u8], what: &str) -> crate::Result<()> {
    stream
        .read_exact(buf)
        .map_err(|io| error::fmt!(SocketError, "Could not read {}: {}", what, io))
}

// ---------- HTTP/1.1 upgrade ----------

#[allow(clippy::too_many_arguments)]
pub(crate) fn perform_upgrade<S: Read + Write>(
    stream: &mut S,
    host_header: &str,
    auth_header: Option<&str>,
    max_version: u32,
    client_id: Option<&str>,
    request_durable_ack: bool,
) -> crate::Result<u8> {
    // RFC 6455 only requires a 16-byte random nonce that the client base64-
    // encodes. It is not a security boundary.
    let mut key_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut key_bytes);
    let key_b64 = codec::b64_encode(&key_bytes);

    let req = codec::build_upgrade_request(
        host_header,
        &key_b64,
        auth_header,
        max_version,
        client_id,
        request_durable_ack,
    );

    stream.write_all(req.as_bytes()).map_err(|io| {
        error::fmt!(
            SocketError,
            "Could not send WebSocket upgrade request: {}",
            io
        )
    })?;

    let header_block = read_http_header_block(stream)?;
    let parsed = codec::parse_http_header_block(&header_block)?;
    let expected_accept = codec::compute_accept(&key_b64);
    codec::validate_upgrade_response(&parsed, &expected_accept)
}

fn read_http_header_block<R: Read>(stream: &mut R) -> crate::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|io| error::fmt!(SocketError, "Could not read upgrade response: {}", io))?;
        if n == 0 {
            return Err(error::fmt!(
                SocketError,
                "Connection closed before WebSocket upgrade completed"
            ));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = codec::find_subsequence(&buf, b"\r\n\r\n") {
            buf.truncate(pos);
            return Ok(buf);
        }
        if buf.len() > 8192 {
            return Err(error::fmt!(
                SocketError,
                "WebSocket upgrade response exceeds 8 KiB header limit"
            ));
        }
    }
}

// ---------- connect ----------

/// Establish a fresh QWP/WebSocket connection: TCP → optional TLS → HTTP
/// upgrade. Returns the connected stream and the version the server picked.
pub(crate) fn establish_connection(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<&str>,
) -> crate::Result<(WsStream, u8)> {
    use std::net::ToSocketAddrs;

    let connect_timeout = *qwp_ws.connect_timeout;
    let request_timeout = *qwp_ws.request_timeout;

    let addr = (
        host,
        port.parse::<u16>()
            .map_err(|_| error::fmt!(ConfigError, "Invalid port: {:?}", port))?,
    )
        .to_socket_addrs()
        .map_err(|io| {
            error::fmt!(
                CouldNotResolveAddr,
                "Could not resolve {}:{}: {}",
                host,
                port,
                io
            )
        })?
        .next()
        .ok_or_else(|| {
            error::fmt!(
                CouldNotResolveAddr,
                "No address found for {}:{}",
                host,
                port
            )
        })?;

    let tcp = TcpStream::connect_timeout(&addr, connect_timeout)
        .map_err(|io| error::fmt!(SocketError, "Could not connect to {}: {}", addr, io))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(request_timeout)).ok();
    tcp.set_write_timeout(Some(request_timeout)).ok();

    let mut stream = if use_tls {
        let tls = tls_settings.ok_or_else(|| {
            error::fmt!(ConfigError, "TLS settings missing for QWP/WebSocket Secure")
        })?;
        let cfg: Arc<rustls::ClientConfig> = configure_tls(tls)?;
        let server_name = host
            .to_string()
            .try_into()
            .map_err(|e| error::fmt!(TlsError, "Invalid TLS server name {:?}: {}", host, e))?;
        let conn = rustls::ClientConnection::new(cfg, server_name)
            .map_err(|e| error::fmt!(TlsError, "TLS handshake setup failed: {}", e))?;
        WsStream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        WsStream::Plain(tcp)
    };

    let host_header = if (use_tls && port == "443") || (!use_tls && port == "80") {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let max_version = *qwp_ws.max_protocol_version;
    let client_id = qwp_ws.client_id.as_deref();
    let request_durable_ack = *qwp_ws.request_durable_ack;

    let negotiated_version = perform_upgrade(
        &mut stream,
        &host_header,
        auth_header,
        max_version,
        client_id,
        request_durable_ack,
    )?;

    stream
        .set_timeouts(Some(request_timeout), Some(request_timeout))
        .ok();

    Ok((stream, negotiated_version))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn connect_qwp_ws(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<SyncProtocolHandler> {
    let publisher = open_qwp_ws_publisher(host, port, use_tls, tls_settings, qwp_ws, auth_header)?;

    Ok(SyncProtocolHandler::SyncQwpWs(Box::new(
        SyncQwpWsHandlerState {
            publisher,
            max_flush_drive_steps: max_flush_drive_steps(qwp_ws),
        },
    )))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn open_qwp_ws_publisher(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<SyncQwpWsPublisher> {
    let queue = ConfiguredQwpWsQueue::open(qwp_ws)?;
    let transport =
        connect_blocking_transport(host, port, use_tls, tls_settings, qwp_ws, auth_header)?;
    let negotiated_version = transport.negotiated_version();
    let driver = ManualDriverPrototype::from_queue_with_reconnect_policy(
        queue,
        transport,
        ReconnectPolicy::bounded(
            *qwp_ws.reconnect_max_duration,
            *qwp_ws.reconnect_initial_backoff,
            *qwp_ws.reconnect_max_backoff,
        ),
    );

    Ok(QwpWsPublicationDriver::new(driver, negotiated_version))
}

fn connect_blocking_transport(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<BlockingQwpWsTransport> {
    if *qwp_ws.initial_connect_retry {
        connect_blocking_transport_with_retry(
            host,
            port,
            use_tls,
            tls_settings,
            qwp_ws,
            auth_header,
        )
    } else {
        BlockingQwpWsTransport::connect(
            host,
            port,
            use_tls,
            tls_settings,
            qwp_ws.clone(),
            auth_header,
        )
    }
}

fn connect_blocking_transport_with_retry(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
) -> crate::Result<BlockingQwpWsTransport> {
    let deadline = Instant::now().checked_add(*qwp_ws.reconnect_max_duration);
    let mut attempts = 0usize;
    let mut backoff = *qwp_ws.reconnect_initial_backoff;
    let mut last_error = None;

    while deadline.map_or(true, |deadline| Instant::now() < deadline) {
        attempts += 1;
        match BlockingQwpWsTransport::connect(
            host,
            port,
            use_tls,
            tls_settings.clone(),
            qwp_ws.clone(),
            auth_header.clone(),
        ) {
            Ok(transport) => return Ok(transport),
            Err(err) if reconnect_error_is_terminal(&err) => return Err(err),
            Err(err) => last_error = Some(err),
        }

        let Some(deadline) = deadline else {
            thread::sleep(backoff);
            backoff = double_duration(backoff).min(*qwp_ws.reconnect_max_backoff);
            continue;
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        thread::sleep(backoff.min(remaining));
        backoff = double_duration(backoff).min(*qwp_ws.reconnect_max_backoff);
    }

    Err(last_error.unwrap_or_else(|| {
        error::fmt!(
            SocketError,
            "QWP/WebSocket initial connect retry budget exhausted after {attempts} attempts"
        )
    }))
}

// ---------- send / receive ----------

/// Public flush entry point: publish through the replay queue, drive the
/// transport, and wait synchronously for the submitted frame's outcome.
pub(crate) fn flush_qwp_ws(
    state: &mut SyncQwpWsHandlerState,
    buffer: &QwpBuffer,
) -> crate::Result<()> {
    let receipt = state
        .publisher
        .submit_qwp_with_drive_limit(buffer, state.max_flush_drive_steps)
        .map_err(publication_error_to_error)?;

    let outcome = state
        .publisher
        .wait_steps(receipt, state.max_flush_drive_steps)
        .map_err(|err| driver_error_to_error(&state.publisher, err))?;

    match outcome {
        DeliveryOutcome::Acked => Ok(()),
        DeliveryOutcome::Rejected => Err(state
            .publisher
            .last_server_error()
            .map(|err| err.error.clone())
            .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket frame was rejected"))),
        DeliveryOutcome::Terminal => Err(state
            .publisher
            .terminal_error()
            .cloned()
            .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket sender is terminal"))),
        DeliveryOutcome::Timeout => Err(error::fmt!(
            SocketError,
            "QWP/WebSocket flush timed out before the server acknowledged the frame"
        )),
    }
}

pub(crate) fn max_flush_drive_steps(qwp_ws: &QwpWsConfig) -> usize {
    (*qwp_ws.max_in_flight).saturating_add(4).max(16)
}

fn double_duration(duration: Duration) -> Duration {
    duration.checked_mul(2).unwrap_or(Duration::MAX)
}

pub(crate) fn publication_error_to_error(err: QwpWsPublicationError) -> crate::Error {
    match err {
        QwpWsPublicationError::Encode(err) => err,
        QwpWsPublicationError::Driver(err) => driver_error_to_error_without_state(err),
    }
}

pub(crate) fn driver_error_to_error(
    publisher: &SyncQwpWsPublisher,
    err: DriverError,
) -> crate::Error {
    match err {
        DriverError::Terminal => publisher
            .terminal_error()
            .cloned()
            .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WebSocket sender is terminal")),
        err => driver_error_to_error_without_state(err),
    }
}

fn driver_error_to_error_without_state(err: DriverError) -> crate::Error {
    match err {
        DriverError::Transport(err) | DriverError::Storage(err) => err,
        DriverError::Queue(err) => error::fmt!(
            InvalidApiCall,
            "QWP/WebSocket queue rejected publication: {:?}",
            err
        ),
        DriverError::SubmitTimedOut => error::fmt!(
            SocketError,
            "QWP/WebSocket flush timed out waiting for local queue capacity"
        ),
        DriverError::Terminal => error::fmt!(SocketError, "QWP/WebSocket sender is terminal"),
        DriverError::Closing => error::fmt!(InvalidApiCall, "QWP/WebSocket sender is closing"),
        DriverError::UnknownReceipt { fsn } => error::fmt!(
            InvalidApiCall,
            "QWP/WebSocket receipt is unknown [fsn={fsn}]"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_short_payload_is_masked() {
        let mut out = Vec::new();
        let payload = b"hello";
        codec::write_frame_to_buf(&mut out, true, WS_OPCODE_BINARY, payload, [0; 4]);
        assert_eq!(out[0], 0x82); // FIN | binary
        assert_eq!(out[1] & 0x80, 0x80); // masked
        assert_eq!(out[1] & 0x7F, 5); // length
    }

    #[test]
    fn masked_server_frame_is_protocol_error() {
        let mut masked_frame = Vec::new();
        codec::write_frame_to_buf(&mut masked_frame, true, WS_OPCODE_BINARY, b"hello", [0; 4]);
        let err = read_message(
            &mut std::io::Cursor::new(masked_frame),
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap_err();

        assert_eq!(err.code(), crate::ErrorCode::SocketError);
        assert!(
            err.msg().contains("must not be masked"),
            "got: {}",
            err.msg()
        );
    }
}
