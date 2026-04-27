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

//! Async, pipelined QWP/WebSocket transport with optional auto-reconnect.
//!
//! ## Concurrency model
//!
//! * The connected stream is split into a read half and a write half so they
//!   advance independently.
//! * A **writer task** drains an unbounded mpsc of pre-built frames and writes
//!   them to the wire. The mpsc preserves submission order.
//! * A **reader task** parses inbound frames, replies to PING via the writer
//!   task, and dispatches OK / error responses to the matching in-flight
//!   request via a `oneshot` channel keyed by sequence number.
//! * `flush(&self, ...)` may be called concurrently by many tasks. Each call
//!   acquires an `Arc<Semaphore>` permit (the in-flight window), then under
//!   the encoder lock: assigns the next sequence, encodes the message,
//!   builds the masked frame, registers a `oneshot`, and pushes the frame to
//!   the writer's mpsc. Doing all five steps under one lock makes the
//!   assigned sequence match wire order.
//!
//! ## Failover (`failover=true`, the default)
//!
//! * Connection state lives in `Inner.state`: `Healthy { write_tx }`,
//!   `Reconnecting`, or `Failed`.
//! * When the reader or writer task hits an I/O error, it CAS-transitions the
//!   state from `Healthy` → `Reconnecting` (only one wins) and spawns a
//!   reconnect task.
//! * The reconnect task runs the same bounded backoff loop the sync sender
//!   uses, then on success: spawns fresh reader/writer tasks, resets the
//!   encoder's connection-scoped state (symbol dict / schema registry /
//!   sequence counter), and **replays every in-flight buffer in submission
//!   order** under new sequence numbers. Each replayed message keeps its
//!   original `oneshot` so the awaiting `flush()` future eventually resolves
//!   normally.
//! * `flush()` calls that arrive while reconnecting park on `state_changed`
//!   until the connection is back up.
//! * If reconnect exhausts its budget, the state transitions to `Failed`,
//!   every in-flight oneshot completes with the latched error, and any
//!   future `flush()` returns that error directly.
//!
//! ## At-least-once on failover
//!
//! A message that the server fully committed before the socket died may be
//! replayed and inserted again. QWP doesn't have client-supplied idempotency
//! keys; this matches the Java reference client's semantics. Set
//! `failover=false` if exactly-once is required (the user must then handle
//! reconnect by rebuilding the sender themselves).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, Notify, Semaphore, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::Error;
use crate::error;
use crate::ingress::buffer::{QwpWsEncodeScratch, SchemaRegistry, SymbolGlobalDict};
use crate::ingress::conf::QwpWsConfig;
use crate::ingress::tls::{TlsSettings, configure_tls};
use crate::ingress::{Buffer, FailoverCallback};

use super::qwp_ws_codec::{
    self as codec, MAX_INBOUND_FRAME_BYTES, PipelinedResponse, WS_OPCODE_BINARY, WS_OPCODE_CLOSE,
    WS_OPCODE_CONTINUATION, WS_OPCODE_PING, WS_OPCODE_PONG, WS_OPCODE_TEXT,
};

// ---------- transport halves ----------

type TlsStream = tokio_rustls::client::TlsStream<TcpStream>;

enum ReadHalfKind {
    Plain(ReadHalf<TcpStream>),
    Tls(ReadHalf<TlsStream>),
}

enum WriteHalfKind {
    Plain(WriteHalf<TcpStream>),
    Tls(WriteHalf<TlsStream>),
}

enum FullStream {
    Plain(TcpStream),
    Tls(Box<TlsStream>),
}

impl FullStream {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            FullStream::Plain(s) => s.write_all(buf).await,
            FullStream::Tls(s) => s.write_all(buf).await,
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            FullStream::Plain(s) => s.read(buf).await,
            FullStream::Tls(s) => s.read(buf).await,
        }
    }
    fn split(self) -> (ReadHalfKind, WriteHalfKind) {
        match self {
            FullStream::Plain(s) => {
                let (r, w) = tokio::io::split(s);
                (ReadHalfKind::Plain(r), WriteHalfKind::Plain(w))
            }
            FullStream::Tls(s) => {
                let (r, w) = tokio::io::split(*s);
                (ReadHalfKind::Tls(r), WriteHalfKind::Tls(w))
            }
        }
    }
}

impl ReadHalfKind {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            ReadHalfKind::Plain(r) => r.read_exact(buf).await.map(|_| ()),
            ReadHalfKind::Tls(r) => r.read_exact(buf).await.map(|_| ()),
        }
    }
}

impl WriteHalfKind {
    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            WriteHalfKind::Plain(w) => w.write_all(buf).await,
            WriteHalfKind::Tls(w) => w.write_all(buf).await,
        }
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WriteHalfKind::Plain(w) => w.flush().await,
            WriteHalfKind::Tls(w) => w.flush().await,
        }
    }
}

// ---------- public AsyncSender ----------

/// Pipelined async QWP/WebSocket sender with optional auto-reconnect.
///
/// `flush(&self, ...)` may be called concurrently from many tasks (typically
/// via `Arc<AsyncSender>`). Up to `max_in_flight` messages can be outstanding
/// at once; further calls park until the window opens.
pub struct AsyncSender {
    inner: Arc<Inner>,
}

struct Inner {
    encoder: AsyncMutex<Encoder>,
    in_flight: StdMutex<BTreeMap<u64, InFlight>>,
    in_flight_sem: Arc<Semaphore>,

    /// Live connection state. The supervisor (reconnect task) and the
    /// reader/writer tasks all CAS through this.
    state: StdMutex<ConnState>,

    /// Notifies anyone awaiting a state transition.
    state_changed: Notify,

    /// Sticky terminal error. Once set, every flush returns this directly.
    error_state: StdMutex<Option<Error>>,

    /// Inputs for re-establishing the connection on failover.
    reconnect: ReconnectParams,

    /// Whether a transport error triggers reconnect+replay (default) or
    /// latches the sender as terminally failed.
    failover: bool,

    on_failover_reset: Option<FailoverCallback>,

    max_buf_size: usize,
    request_timeout: Duration,
    /// Negotiated version on the most-recent successful connection.
    /// Wrapped in `StdMutex` because reconnects update it.
    negotiated_version: StdMutex<u8>,
}

enum ConnState {
    Healthy {
        write_tx: mpsc::UnboundedSender<Vec<u8>>,
    },
    Reconnecting,
    Failed,
}

struct Encoder {
    global_dict: SymbolGlobalDict,
    schema_registry: SchemaRegistry,
    scratch: QwpWsEncodeScratch,
    next_sequence: u64,
}

struct InFlight {
    tx: oneshot::Sender<Result<(), Error>>,
    buffer: Buffer,
}

#[derive(Clone)]
struct ReconnectParams {
    host: String,
    port: String,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    auth_header: Option<String>,
    qwp_ws: QwpWsConfig,
}

impl std::fmt::Debug for AsyncSender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncSender")
            .field("negotiated_version", &*self.inner.negotiated_version.lock().unwrap())
            .finish()
    }
}

impl AsyncSender {
    /// Create a new QWP buffer for use with this sender.
    pub fn new_buffer(&self) -> Buffer {
        Buffer::qwp_with_max_name_len(127)
    }

    /// Most-recently negotiated QWP protocol version.
    pub fn protocol_version(&self) -> u8 {
        *self.inner.negotiated_version.lock().unwrap()
    }

    /// Send the buffer's rows to the server, then clear the buffer.
    pub async fn flush(&self, buf: &mut Buffer) -> crate::Result<()> {
        self.flush_impl(buf).await?;
        buf.clear();
        Ok(())
    }

    /// Send the buffer's rows but leave it intact for a possible resend.
    pub async fn flush_and_keep(&self, buf: &Buffer) -> crate::Result<()> {
        self.flush_impl(buf).await
    }

    async fn flush_impl(&self, buf: &Buffer) -> crate::Result<()> {
        let qwp = buf.as_qwp().ok_or_else(|| {
            error::fmt!(
                InvalidApiCall,
                "QWP/WebSocket sender requires a QWP buffer created by `AsyncSender::new_buffer()`."
            )
        })?;
        qwp.check_can_flush()?;
        if qwp.is_empty() {
            return Ok(());
        }
        if qwp.len() > self.inner.max_buf_size {
            return Err(error::fmt!(
                InvalidApiCall,
                "Could not flush buffer: QWP buffer size hint of {} exceeds maximum configured allowed size of {} bytes.",
                qwp.len(),
                self.inner.max_buf_size
            ));
        }

        if let Some(err) = self.inner.snapshot_error() {
            return Err(err);
        }

        let permit = self
            .inner
            .in_flight_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| {
                self.inner.snapshot_error().unwrap_or_else(|| {
                    error::fmt!(SocketError, "QWP/WS sender closed")
                })
            })?;

        // Try to register the message until we catch the connection in a
        // Healthy state. While Reconnecting we park; on Failed we bail.
        let rx = loop {
            if let Some(err) = self.inner.snapshot_error() {
                return Err(err);
            }

            let notified = self.inner.state_changed.notified();
            tokio::pin!(notified);

            let mut enc_guard = self.inner.encoder.lock().await;

            let write_tx = {
                let state = self.inner.state.lock().unwrap();
                match &*state {
                    ConnState::Failed => {
                        return Err(self.inner.snapshot_error().unwrap_or_else(|| {
                            error::fmt!(SocketError, "QWP/WS connection closed")
                        }));
                    }
                    ConnState::Reconnecting => None,
                    ConnState::Healthy { write_tx } => Some(write_tx.clone()),
                }
            };

            let Some(write_tx) = write_tx else {
                drop(enc_guard);
                notified.await;
                continue;
            };

            // We hold the encoder lock; the reconnect supervisor takes the
            // same lock during replay, so register+submit here is atomic
            // relative to drain+replay.
            let enc = &mut *enc_guard;
            let version = *self.inner.negotiated_version.lock().unwrap();
            enc.next_sequence = enc.next_sequence.wrapping_add(1);
            let seq = enc.next_sequence;

            enc.scratch.message.clear();
            qwp.encode_ws_message(
                &mut enc.scratch,
                &mut enc.global_dict,
                &mut enc.schema_registry,
                version,
            )?;

            let mut frame = Vec::with_capacity(enc.scratch.message.len() + 14);
            codec::write_frame_to_buf(
                &mut frame,
                true,
                WS_OPCODE_BINARY,
                &enc.scratch.message,
                random_mask(),
            );

            let (tx, rx) = oneshot::channel();
            self.inner.in_flight.lock().unwrap().insert(
                seq,
                InFlight {
                    tx,
                    buffer: buf.clone(),
                },
            );

            // If `send` fails the writer task is gone. The entry is in the
            // map and the next reconnect will replay it; we just await the
            // oneshot as usual.
            let _ = write_tx.send(frame);

            break rx;
        };

        let result = match timeout(
            self.inner.request_timeout,
            wait_for_response(rx, &self.inner.state_changed, &self.inner.error_state),
        )
        .await
        {
            Ok(r) => r,
            Err(_) => Err(error::fmt!(SocketError, "QWP/WS request timed out")),
        };

        drop(permit);
        result
    }
}

async fn wait_for_response(
    rx: oneshot::Receiver<Result<(), Error>>,
    state_changed: &Notify,
    error_state: &StdMutex<Option<Error>>,
) -> crate::Result<()> {
    tokio::select! {
        biased;
        r = rx => match r {
            Ok(res) => res,
            Err(_) => Err(error_state.lock().unwrap().clone()
                .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WS connection lost"))),
        },
        _ = wait_for_failed(state_changed, error_state) => {
            Err(error_state.lock().unwrap().clone()
                .unwrap_or_else(|| error::fmt!(SocketError, "QWP/WS connection closed")))
        }
    }
}

/// Wakes up only when the connection has reached a terminal state.
async fn wait_for_failed(state_changed: &Notify, error_state: &StdMutex<Option<Error>>) {
    loop {
        if error_state.lock().unwrap().is_some() {
            return;
        }
        state_changed.notified().await;
    }
}

impl Inner {
    fn snapshot_error(&self) -> Option<Error> {
        self.error_state.lock().unwrap().clone()
    }

    /// Mark the sender as terminally failed: latch the error, drain in-flight,
    /// close the semaphore, set state to Failed, wake everyone. Idempotent.
    fn fail_terminal(&self, err: Error) {
        {
            let mut state_err = self.error_state.lock().unwrap();
            if state_err.is_some() {
                return;
            }
            *state_err = Some(err.clone());
        }
        let pending: Vec<(u64, InFlight)> = {
            let mut map = self.in_flight.lock().unwrap();
            std::mem::take(&mut *map).into_iter().collect()
        };
        for (_seq, inflight) in pending {
            let _ = inflight.tx.send(Err(err.clone()));
        }
        *self.state.lock().unwrap() = ConnState::Failed;
        self.in_flight_sem.close();
        self.state_changed.notify_waiters();
    }

    /// Attempt to start a reconnect. Returns `true` if this caller is the one
    /// that should drive the reconnect (via `reconnect_supervisor`).
    fn try_begin_reconnect(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        match &*state {
            ConnState::Healthy { .. } => {
                *state = ConnState::Reconnecting;
                self.state_changed.notify_waiters();
                true
            }
            ConnState::Reconnecting | ConnState::Failed => false,
        }
    }
}

impl Drop for AsyncSender {
    fn drop(&mut self) {
        // The reader/writer/supervisor tasks share `Arc<Inner>`, so they keep
        // running until they observe the failure. Latch a terminal error so
        // pending flushes wake immediately and tasks exit on the next I/O.
        self.inner
            .fail_terminal(error::fmt!(SocketError, "QWP/WS sender dropped"));
    }
}

fn random_mask() -> [u8; 4] {
    let mut mask = [0u8; 4];
    rand::rng().fill_bytes(&mut mask);
    mask
}

// ---------- background tasks ----------

async fn writer_task(
    inner: Arc<Inner>,
    mut write_half: WriteHalfKind,
    mut write_rx: mpsc::UnboundedReceiver<Vec<u8>>,
) {
    while let Some(frame) = write_rx.recv().await {
        if let Err(io) = write_half.write_all(&frame).await {
            handle_io_failure(
                &inner,
                error::fmt!(SocketError, "QWP/WS write failed: {}", io),
            );
            return;
        }
        if let Err(io) = write_half.flush().await {
            handle_io_failure(
                &inner,
                error::fmt!(SocketError, "QWP/WS flush failed: {}", io),
            );
            return;
        }
    }
    // Channel closed (sender dropped, or this generation's write_tx was
    // replaced by the supervisor). Nothing more to do.
}

async fn reader_task(
    inner: Arc<Inner>,
    mut read_half: ReadHalfKind,
    write_tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut payload: Vec<u8> = Vec::new();
    loop {
        match read_one_message(&mut read_half, &write_tx, &mut payload).await {
            Ok(Some(opcode)) => {
                if opcode != WS_OPCODE_BINARY {
                    continue;
                }
                match codec::parse_pipelined_response(&payload) {
                    Ok(PipelinedResponse::Ok { sequence }) => {
                        if let Some(inflight) =
                            inner.in_flight.lock().unwrap().remove(&sequence)
                        {
                            let _ = inflight.tx.send(Ok(()));
                        }
                    }
                    Ok(PipelinedResponse::Error { sequence, err }) => {
                        // Per-message server errors are non-terminal: they go
                        // back to the matching flush, the connection stays.
                        if let Some(inflight) =
                            inner.in_flight.lock().unwrap().remove(&sequence)
                        {
                            let _ = inflight.tx.send(Err(err));
                        }
                    }
                    Ok(PipelinedResponse::DurableAck) => continue,
                    Err(e) => {
                        handle_io_failure(&inner, e);
                        return;
                    }
                }
            }
            Ok(None) => {
                handle_io_failure(
                    &inner,
                    error::fmt!(SocketError, "QWP/WS connection closed by server"),
                );
                return;
            }
            Err(e) => {
                handle_io_failure(&inner, e);
                return;
            }
        }
    }
}

/// Common path for reader/writer-detected I/O failure. With failover enabled,
/// transitions to Reconnecting and spawns the supervisor; otherwise latches
/// the error.
fn handle_io_failure(inner: &Arc<Inner>, err: Error) {
    if !inner.failover {
        inner.fail_terminal(err);
        return;
    }
    if inner.try_begin_reconnect() {
        let inner_cloned = inner.clone();
        tokio::spawn(async move {
            reconnect_supervisor(inner_cloned, err).await;
        });
    }
    // If we lost the race, the other task already kicked off the supervisor.
}

async fn reconnect_supervisor(inner: Arc<Inner>, _initial_err: Error) {
    let cfg = &inner.reconnect.qwp_ws;
    let attempts = *cfg.max_failover_attempts;
    let mut backoff = *cfg.failover_initial_backoff;
    let max_backoff = *cfg.failover_max_backoff;
    let deadline = Instant::now() + *cfg.failover_total_budget;

    let mut last_err: Option<Error> = None;
    for _ in 0..attempts {
        if Instant::now() >= deadline {
            break;
        }
        sleep(backoff).await;
        backoff = backoff.saturating_mul(2).min(max_backoff);

        match try_reconnect(&inner).await {
            Ok(()) => {
                if let Some(cb) = inner.on_failover_reset.as_ref() {
                    let cb = cb.0.clone();
                    // The callback is `Fn`, so synchronous from our side.
                    cb();
                }
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    inner.fail_terminal(
        last_err.unwrap_or_else(|| error::fmt!(SocketError, "QWP/WS failover exhausted")),
    );
}

async fn try_reconnect(inner: &Arc<Inner>) -> crate::Result<()> {
    // 1. Re-establish the underlying transport + WebSocket upgrade.
    let (stream, version) = establish_connection(
        &inner.reconnect.host,
        &inner.reconnect.port,
        inner.reconnect.use_tls,
        inner.reconnect.tls_settings.clone(),
        &inner.reconnect.qwp_ws,
        inner.reconnect.auth_header.as_deref(),
    )
    .await?;
    let (read_half, write_half) = stream.split();

    // 2. Reset connection-scoped state and prepare a new write channel.
    let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    {
        let mut enc_guard = inner.encoder.lock().await;
        let enc = &mut *enc_guard;
        enc.global_dict = SymbolGlobalDict::new();
        enc.schema_registry = SchemaRegistry::new();
        enc.next_sequence = 0;

        // 3. Drain in-flight in submission order; re-encode each buffer
        //    against the fresh state and re-register under new sequences,
        //    keeping the original oneshots so the awaiting flushes resolve.
        let pending: Vec<(u64, InFlight)> = {
            let mut map = inner.in_flight.lock().unwrap();
            std::mem::take(&mut *map).into_iter().collect()
        };
        for (_old_seq, inflight) in pending {
            // The buffer was a clone snapshot at submission time; QWP buffers
            // implement `Clone` and `as_qwp()` returns the QWP view.
            let qwp = match inflight.buffer.as_qwp() {
                Some(q) => q,
                None => {
                    let _ = inflight
                        .tx
                        .send(Err(error::fmt!(InvalidApiCall, "QWP/WS replay: non-QWP buffer")));
                    continue;
                }
            };
            enc.next_sequence = enc.next_sequence.wrapping_add(1);
            let new_seq = enc.next_sequence;
            enc.scratch.message.clear();
            if let Err(e) = qwp.encode_ws_message(
                &mut enc.scratch,
                &mut enc.global_dict,
                &mut enc.schema_registry,
                version,
            ) {
                let _ = inflight.tx.send(Err(e));
                continue;
            }
            let mut frame = Vec::with_capacity(enc.scratch.message.len() + 14);
            codec::write_frame_to_buf(
                &mut frame,
                true,
                WS_OPCODE_BINARY,
                &enc.scratch.message,
                random_mask(),
            );
            inner.in_flight.lock().unwrap().insert(new_seq, inflight);
            let _ = write_tx.send(frame);
        }
    }

    // 4. Spawn fresh reader/writer tasks bound to the new halves and
    //    transition the state back to Healthy.
    tokio::spawn(writer_task(inner.clone(), write_half, write_rx));
    tokio::spawn(reader_task(inner.clone(), read_half, write_tx.clone()));

    *inner.negotiated_version.lock().unwrap() = version;
    *inner.state.lock().unwrap() = ConnState::Healthy { write_tx };
    inner.state_changed.notify_waiters();
    Ok(())
}

/// Read one logical WebSocket message into `payload`. Returns `Some(opcode)`
/// for data frames, `None` if the peer sent a CLOSE. PING is handled inline.
async fn read_one_message(
    read_half: &mut ReadHalfKind,
    write_tx: &mpsc::UnboundedSender<Vec<u8>>,
    payload: &mut Vec<u8>,
) -> crate::Result<Option<u8>> {
    payload.clear();
    let mut first_opcode: Option<u8> = None;
    loop {
        let (fin, opcode, frame_payload) = read_frame(read_half).await?;
        match opcode {
            WS_OPCODE_PING => {
                let mut pong = Vec::new();
                codec::write_frame_to_buf(
                    &mut pong,
                    true,
                    WS_OPCODE_PONG,
                    &frame_payload,
                    random_mask(),
                );
                if write_tx.send(pong).is_err() {
                    return Err(error::fmt!(
                        SocketError,
                        "Could not send WebSocket PONG: writer task gone"
                    ));
                }
                continue;
            }
            WS_OPCODE_PONG => continue,
            WS_OPCODE_CLOSE => return Ok(None),
            WS_OPCODE_TEXT | WS_OPCODE_BINARY => {
                if first_opcode.is_some() {
                    return Err(error::fmt!(
                        SocketError,
                        "Unexpected new data frame mid-message"
                    ));
                }
                first_opcode = Some(opcode);
                payload.extend_from_slice(&frame_payload);
            }
            WS_OPCODE_CONTINUATION => {
                if first_opcode.is_none() {
                    return Err(error::fmt!(
                        SocketError,
                        "Continuation frame without prior data frame"
                    ));
                }
                payload.extend_from_slice(&frame_payload);
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
            return Ok(Some(first_opcode.unwrap()));
        }
    }
}

async fn read_frame(read_half: &mut ReadHalfKind) -> crate::Result<(bool, u8, Vec<u8>)> {
    let mut hdr = [0u8; 2];
    read_exact(read_half, &mut hdr, "WebSocket frame header").await?;
    let fin = (hdr[0] & 0x80) != 0;
    let opcode = hdr[0] & 0x0F;
    let masked = (hdr[1] & 0x80) != 0;
    let len_short = hdr[1] & 0x7F;
    let payload_len: u64 = match len_short {
        126 => {
            let mut b = [0u8; 2];
            read_exact(read_half, &mut b, "WebSocket frame length").await?;
            u16::from_be_bytes(b) as u64
        }
        127 => {
            let mut b = [0u8; 8];
            read_exact(read_half, &mut b, "WebSocket frame length").await?;
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
    let mut mask = [0u8; 4];
    if masked {
        read_exact(read_half, &mut mask, "WebSocket frame mask").await?;
    }
    let mut payload = vec![0u8; payload_len as usize];
    if !payload.is_empty() {
        read_exact(read_half, &mut payload, "WebSocket frame payload").await?;
    }
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((fin, opcode, payload))
}

async fn read_exact(
    read_half: &mut ReadHalfKind,
    buf: &mut [u8],
    what: &str,
) -> crate::Result<()> {
    read_half
        .read_exact(buf)
        .await
        .map_err(|io| error::fmt!(SocketError, "Could not read {}: {}", what, io))
}

// ---------- HTTP/1.1 upgrade ----------

#[allow(clippy::too_many_arguments)]
async fn perform_upgrade(
    stream: &mut FullStream,
    host_header: &str,
    auth_header: Option<&str>,
    max_version: u32,
    client_id: Option<&str>,
    request_durable_ack: bool,
) -> crate::Result<u8> {
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
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|io| error::fmt!(SocketError, "Could not send WebSocket upgrade request: {}", io))?;

    let header_block = read_http_header_block(stream).await?;
    let parsed = codec::parse_http_header_block(&header_block)?;
    let expected_accept = codec::compute_accept(&key_b64);
    codec::validate_upgrade_response(&parsed, &expected_accept)
}

async fn read_http_header_block(stream: &mut FullStream) -> crate::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream
            .read(&mut tmp)
            .await
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

/// Establish a fresh TCP/(TLS)/WebSocket-upgrade connection. Used both at
/// initial connect and on every reconnect attempt.
async fn establish_connection(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<&str>,
) -> crate::Result<(FullStream, u8)> {
    let connect_timeout = *qwp_ws.connect_timeout;
    let request_timeout = *qwp_ws.request_timeout;

    let port_num: u16 = port
        .parse()
        .map_err(|_| error::fmt!(ConfigError, "Invalid port: {:?}", port))?;
    let addr = format!("{host}:{port_num}");

    let tcp = match timeout(connect_timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(io)) => {
            return Err(error::fmt!(
                SocketError,
                "Could not connect to {}: {}",
                addr,
                io
            ));
        }
        Err(_) => {
            return Err(error::fmt!(
                SocketError,
                "Timed out connecting to {}",
                addr
            ));
        }
    };
    tcp.set_nodelay(true).ok();

    let mut stream: FullStream = if use_tls {
        let tls = tls_settings.ok_or_else(|| {
            error::fmt!(ConfigError, "TLS settings missing for QWP/WebSocket Secure")
        })?;
        let cfg: Arc<rustls::ClientConfig> = configure_tls(tls)?;
        let server_name = host
            .to_string()
            .try_into()
            .map_err(|e| error::fmt!(TlsError, "Invalid TLS server name {:?}: {}", host, e))?;
        let connector = tokio_rustls::TlsConnector::from(cfg);
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| error::fmt!(TlsError, "TLS handshake failed: {}", e))?;
        FullStream::Tls(Box::new(tls_stream))
    } else {
        FullStream::Plain(tcp)
    };

    let host_header = if (use_tls && port == "443") || (!use_tls && port == "80") {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };

    let max_version = *qwp_ws.max_protocol_version;
    let client_id = qwp_ws.client_id.as_deref();
    let request_durable_ack = *qwp_ws.request_durable_ack;

    let negotiated_version = match timeout(
        request_timeout,
        perform_upgrade(
            &mut stream,
            &host_header,
            auth_header,
            max_version,
            client_id,
            request_durable_ack,
        ),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => return Err(error::fmt!(SocketError, "WebSocket upgrade timed out")),
    };

    Ok((stream, negotiated_version))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn connect_async_qwp_ws(
    host: &str,
    port: &str,
    use_tls: bool,
    tls_settings: Option<TlsSettings>,
    qwp_ws: &QwpWsConfig,
    auth_header: Option<String>,
    max_buf_size: usize,
    on_failover_reset: Option<FailoverCallback>,
) -> crate::Result<AsyncSender> {
    let max_in_flight = *qwp_ws.max_in_flight;
    let request_timeout = *qwp_ws.request_timeout;
    let failover = *qwp_ws.failover;

    let (stream, negotiated_version) = establish_connection(
        host,
        port,
        use_tls,
        tls_settings.clone(),
        qwp_ws,
        auth_header.as_deref(),
    )
    .await?;
    let (read_half, write_half) = stream.split();

    let (write_tx, write_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let in_flight_sem = Arc::new(Semaphore::new(max_in_flight));

    let inner = Arc::new(Inner {
        encoder: AsyncMutex::new(Encoder {
            global_dict: SymbolGlobalDict::new(),
            schema_registry: SchemaRegistry::new(),
            scratch: QwpWsEncodeScratch::new(),
            next_sequence: 0,
        }),
        in_flight: StdMutex::new(BTreeMap::new()),
        in_flight_sem,
        state: StdMutex::new(ConnState::Healthy {
            write_tx: write_tx.clone(),
        }),
        state_changed: Notify::new(),
        error_state: StdMutex::new(None),
        reconnect: ReconnectParams {
            host: host.to_string(),
            port: port.to_string(),
            use_tls,
            tls_settings,
            auth_header,
            qwp_ws: qwp_ws.clone(),
        },
        failover,
        on_failover_reset,
        max_buf_size,
        request_timeout,
        negotiated_version: StdMutex::new(negotiated_version),
    });

    // The reader/writer tasks share `Arc<Inner>` and outlive any individual
    // generation of the connection. On failure they spawn the supervisor,
    // which re-spawns fresh reader/writer tasks for the new connection.
    let _writer_handle: JoinHandle<()> =
        tokio::spawn(writer_task(inner.clone(), write_half, write_rx));
    let _reader_handle: JoinHandle<()> =
        tokio::spawn(reader_task(inner.clone(), read_half, write_tx));

    Ok(AsyncSender { inner })
}
