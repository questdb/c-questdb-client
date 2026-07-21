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

//! Unified QWP sender pool + flush integration tests (WS-0 through WS-2).
//!
//! - WS-0: eager-open, borrow/return, multi-thread concurrent borrows,
//!   fail-fast at `pool_max`, idle reaper.
//! - WS-1: synchronous `flush` round-trip for empty chunks; `AckLevel::Durable`
//!   opt-in guard.
//! - WS-2: numeric / fixed-width column round-trip with a designated
//!   timestamp; schema reuse across repeated flushes.
//!
//! Pool slots own unified QWP publication cores. The mock server accepts the
//! HTTP→WebSocket upgrade, then either parks on the connection or reads each
//! QWP frame and replies with an OK ack (status 0x00).

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::QuestDb;
use crate::ingress::column_sender::Chunk;
use crate::ingress::sender::has_any_sfa_file as slot_has_sfa_file;
use crate::ingress::{AckLevel, ProtocolVersion, SenderBuilder, TimestampNanos};
use crate::tests::qwp_ws::{
    perform_server_upgrade, perform_server_upgrade_durable, read_frame,
    upgrade_mock_stream_with_max_batch_size, write_qwp_durable_ack_response,
    write_qwp_error_response, write_qwp_ok_response, write_qwp_ok_response_with_table_entries,
    write_server_frame,
};
use tempfile::TempDir;

const QWP_STATUS_SCHEMA_MISMATCH: u8 = 0x03;

#[derive(Clone, Debug)]
enum MockMode {
    /// Park the connection after upgrade — used by pool-only tests.
    Park,
    /// Park after advertising a negotiated server-side frame cap.
    ParkWithMaxBatchSize(usize),
    /// Read every QWP frame the client sends and reply with an OK ack.
    AckEachFrame,
    /// Reply to every QWP frame with an error ack carrying `status`.
    ErrorEachFrame(u8),
    /// Capture every binary frame but delay ACKs until the flag is set.
    AckWhenReleased(Arc<AtomicBool>),
    /// Complete the WS upgrade, then immediately close the socket. A client
    /// that opened the connection succeeds, but its first `flush`/`sync` read
    /// hits EOF and surfaces a transient (`FailoverRetry`) transport failure —
    /// simulating a peer that dies after connect. Used to drive failover.
    UpgradeThenClose,
    /// Ack the first `n` binary frames, then close the socket — a peer that
    /// dies mid-stream after committing a prefix. The client's next read hits
    /// EOF and surfaces a transient (`FailoverRetry`) failure.
    #[cfg(feature = "arrow-ingress")]
    AckThenClose(usize),
    /// Read (consume) the first `n` binary frames — so the client's writes
    /// provably succeed — then close **without** acking. Models a peer that
    /// ingests a published frame and then dies before acknowledging it: the
    /// client's ACK-wait read hits EOF, a *post-publication* delivery-unknown
    /// failure.
    ReadThenClose(usize),
    /// Durable-ACK mode: upgrade with `X-QWP-Durable-Ack: enabled`, OK each
    /// data frame with a `trades` table seq_txn, and answer every keepalive
    /// ping with a pong + a durable-ACK frame so a `Durable` boundary commits.
    AckEachFrameDurable,
    /// The first accepted connection reads one data frame and closes without
    /// ACKing; later connections ACK normally. Drives deterministic replay and
    /// same-endpoint reconnect in the store-and-forward runner.
    ReconnectAfterFirstFrame,
    /// Reject the WebSocket upgrade with HTTP 401.
    RejectAuth,
}

/// Spawn a mock server that performs the WS upgrade for up to `max_accepts`
/// connections, then parks each accepted connection (drains until EOF). The
/// returned guard's `Drop` signals the accept loop to stop.
struct MockServer {
    port: u16,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn spawn(max_accepts: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::Park)
    }

    fn spawn_with_max_batch_size(max_accepts: usize, max_batch_size: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::ParkWithMaxBatchSize(max_batch_size))
    }

    fn spawn_acking(max_accepts: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::AckEachFrame)
    }

    fn spawn_erroring(max_accepts: usize, status: u8) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::ErrorEachFrame(status))
    }

    fn spawn_ack_when_released_capturing(
        max_accepts: usize,
    ) -> (Self, Arc<AtomicBool>, mpsc::Receiver<Vec<u8>>) {
        let release = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        let server = Self::spawn_with_mode_capture(
            max_accepts,
            MockMode::AckWhenReleased(Arc::clone(&release)),
            Some(tx),
        );
        (server, release, rx)
    }

    fn spawn_upgrade_then_close(max_accepts: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::UpgradeThenClose)
    }

    fn spawn_read_then_close(max_accepts: usize, frames: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::ReadThenClose(frames))
    }

    #[cfg(feature = "arrow-ingress")]
    fn spawn_ack_then_close(max_accepts: usize, ack_first: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::AckThenClose(ack_first))
    }

    fn spawn_with_mode(max_accepts: usize, mode: MockMode) -> Self {
        Self::spawn_with_mode_capture(max_accepts, mode, None)
    }

    /// Like [`spawn_acking`] but also forwards every received binary frame
    /// payload (the unmasked QWP frame bytes) over the returned channel so a
    /// test can assert on the wire.
    fn spawn_acking_capturing(max_accepts: usize) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let server = Self::spawn_with_mode_capture(max_accepts, MockMode::AckEachFrame, Some(tx));
        (server, rx)
    }

    fn spawn_acking_durable_capturing(max_accepts: usize) -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let server =
            Self::spawn_with_mode_capture(max_accepts, MockMode::AckEachFrameDurable, Some(tx));
        (server, rx)
    }

    fn spawn_reconnecting(max_accepts: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::ReconnectAfterFirstFrame)
    }

    fn spawn_auth_rejecting(max_accepts: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::RejectAuth)
    }

    #[cfg(feature = "polars-ingress")]
    fn spawn_acking_on_port_after_delay(port: u16, max_accepts: usize, delay: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop_clone = Arc::clone(&stop);
        let accepted_clone = Arc::clone(&accepted);

        let join = thread::Builder::new()
            .name("qwp-ingress-pool-delayed-mock-server".to_string())
            .spawn(move || {
                thread::sleep(delay);
                let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind delayed port");
                listener
                    .set_nonblocking(true)
                    .expect("set_nonblocking on delayed listener");
                run_mock_server_accept_loop(
                    listener,
                    max_accepts,
                    MockMode::AckEachFrame,
                    None,
                    stop_clone,
                    accepted_clone,
                );
            })
            .expect("spawn delayed mock server");

        Self {
            port,
            stop,
            accepted,
            join: Some(join),
        }
    }

    fn spawn_with_mode_capture(
        max_accepts: usize,
        mode: MockMode,
        capture: Option<mpsc::Sender<Vec<u8>>>,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on listener");
        let port = listener.local_addr().expect("local_addr").port();

        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop_clone = Arc::clone(&stop);
        let accepted_clone = Arc::clone(&accepted);

        let join = thread::Builder::new()
            .name("qwp-ingress-pool-mock-server".to_string())
            .spawn(move || {
                run_mock_server_accept_loop(
                    listener,
                    max_accepts,
                    mode,
                    capture,
                    stop_clone,
                    accepted_clone,
                );
            })
            .expect("spawn mock server");

        Self {
            port,
            stop,
            accepted,
            join: Some(join),
        }
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }
}

fn run_mock_server_accept_loop(
    listener: TcpListener,
    max_accepts: usize,
    mode: MockMode,
    capture: Option<mpsc::Sender<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
) {
    let mut handles = Vec::new();
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let accept_index = accepted.fetch_add(1, Ordering::SeqCst);
                if accept_index >= max_accepts {
                    // Past the budget — drop without upgrade so the client sees
                    // a failed connect.
                    continue;
                }
                stream
                    .set_nonblocking(false)
                    .expect("set_nonblocking(false)");
                let stop = Arc::clone(&stop);
                let capture = capture.clone();
                let mode = mode.clone();
                let h = thread::spawn(move || {
                    if matches!(mode, MockMode::RejectAuth) {
                        reject_upgrade_auth(&mut stream);
                        return;
                    }
                    // Durable mode needs the `X-QWP-Durable-Ack: enabled` upgrade
                    // header; every other mode uses the plain upgrade.
                    let upgraded = if matches!(mode, MockMode::AckEachFrameDurable) {
                        perform_server_upgrade_durable(&mut stream).is_ok()
                    } else if let MockMode::ParkWithMaxBatchSize(max_batch_size) = &mode {
                        upgrade_mock_stream_with_max_batch_size(&mut stream, Some(*max_batch_size));
                        true
                    } else {
                        perform_server_upgrade(&mut stream).is_ok()
                    };
                    if upgraded {
                        match mode {
                            MockMode::Park => park_connection(&mut stream, &stop),
                            MockMode::ParkWithMaxBatchSize(_) => {
                                park_connection(&mut stream, &stop)
                            }
                            MockMode::AckEachFrame => ack_each_frame(&mut stream, &stop, capture),
                            MockMode::AckEachFrameDurable => {
                                ack_each_frame_durable(&mut stream, &stop, capture)
                            }
                            MockMode::ReconnectAfterFirstFrame if accept_index == 0 => {
                                read_then_close(&mut stream, &stop, 1)
                            }
                            MockMode::ReconnectAfterFirstFrame => {
                                ack_each_frame(&mut stream, &stop, capture)
                            }
                            MockMode::RejectAuth => unreachable!("handled before upgrade"),
                            MockMode::ErrorEachFrame(status) => {
                                error_each_frame(&mut stream, &stop, status)
                            }
                            MockMode::AckWhenReleased(release) => {
                                ack_when_released(&mut stream, &stop, &release, capture)
                            }
                            MockMode::UpgradeThenClose => {
                                // Drop the stream immediately: the client's
                                // next read sees EOF.
                            }
                            #[cfg(feature = "arrow-ingress")]
                            MockMode::AckThenClose(n) => ack_then_close(&mut stream, &stop, n),
                            MockMode::ReadThenClose(n) => read_then_close(&mut stream, &stop, n),
                        }
                    }
                });
                handles.push(h);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
    for h in handles {
        let _ = h.join();
    }
}

fn reject_upgrade_auth(stream: &mut std::net::TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let mut request = Vec::new();
    let mut buf = [0u8; 256];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => request.extend_from_slice(&buf[..n]),
        }
    }
    let _ = stream
        .write_all(b"HTTP/1.1 401 Unauthorized\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

/// Durable-ACK variant of [`ack_each_frame`]: OK each data frame with a
/// `("trades", seq_txn)` table entry and answer each keepalive ping (opcode
/// 0x9) with a pong (0xA) + a durable-ACK frame carrying the same seq_txn, so
/// the runner's durable watermark advances and a `Durable` boundary commits.
fn ack_each_frame_durable(
    stream: &mut std::net::TcpStream,
    stop: &AtomicBool,
    capture: Option<mpsc::Sender<Vec<u8>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut next_wire_seq: u64 = 0;
    let mut seq_txn: i64 = 0;
    while !stop.load(Ordering::SeqCst) {
        match read_frame(stream) {
            Ok((_fin, opcode, payload)) => match opcode {
                0x8 => break, // close
                0x9 => {
                    // Keepalive ping: pong, then confirm everything OK'd so far
                    // as durable.
                    if write_server_frame(stream, 0xA, &payload, false).is_err() {
                        break;
                    }
                    if write_qwp_durable_ack_response(stream, &[("trades", seq_txn)]).is_err() {
                        break;
                    }
                }
                0x2 => {
                    if let Some(tx) = &capture {
                        let _ = tx.send(payload);
                    }
                    seq_txn += 1;
                    if write_qwp_ok_response_with_table_entries(
                        stream,
                        next_wire_seq,
                        &[("trades", seq_txn)],
                    )
                    .is_err()
                    {
                        break;
                    }
                    next_wire_seq += 1;
                }
                _ => {}
            },
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

fn park_connection(stream: &mut std::net::TcpStream, stop: &AtomicBool) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
    let mut buf = [0u8; 1024];
    while !stop.load(Ordering::SeqCst) {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

/// Read each WebSocket binary frame the client sends and reply with a QWP
/// OK ack, incrementing the wire sequence per frame. Control frames are
/// ignored. Exits on EOF or `stop`.
fn ack_each_frame(
    stream: &mut std::net::TcpStream,
    stop: &AtomicBool,
    capture: Option<mpsc::Sender<Vec<u8>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut next_wire_seq: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        match read_frame(stream) {
            Ok((_fin, opcode, payload)) => {
                // Opcode 0x2 = binary; 0x8 = close; everything else is ignored.
                if opcode == 0x8 {
                    break;
                }
                if opcode != 0x2 {
                    continue;
                }
                if let Some(tx) = &capture {
                    let _ = tx.send(payload);
                }
                if write_qwp_ok_response(stream, next_wire_seq).is_err() {
                    break;
                }
                next_wire_seq += 1;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

/// Like [`ack_each_frame`] but replies to each binary frame with a QWP
/// error ack carrying `status`, so tests can exercise the server-error
/// latch + pool-drop path.
fn error_each_frame(stream: &mut std::net::TcpStream, stop: &AtomicBool, status: u8) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut next_wire_seq: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        match read_frame(stream) {
            Ok((_fin, opcode, _payload)) => {
                if opcode == 0x8 {
                    break;
                }
                if opcode != 0x2 {
                    continue;
                }
                if write_qwp_error_response(stream, status, next_wire_seq, b"injected").is_err() {
                    break;
                }
                next_wire_seq += 1;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

fn ack_when_released(
    stream: &mut std::net::TcpStream,
    stop: &AtomicBool,
    release: &AtomicBool,
    capture: Option<mpsc::Sender<Vec<u8>>>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut next_wire_seq: u64 = 0;
    while !stop.load(Ordering::SeqCst) {
        match read_frame(stream) {
            Ok((_fin, opcode, payload)) => {
                if opcode == 0x8 {
                    break;
                }
                if opcode != 0x2 {
                    continue;
                }
                if let Some(tx) = &capture {
                    let _ = tx.send(payload);
                }
                while !stop.load(Ordering::SeqCst) && !release.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(10));
                }
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                if write_qwp_ok_response(stream, next_wire_seq).is_err() {
                    break;
                }
                next_wire_seq += 1;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
}

/// Ack the first `n` binary frames the client sends, then close the socket so
/// the client's next read hits EOF. Models a peer that commits a prefix and
/// then dies mid-stream.
#[cfg(feature = "arrow-ingress")]
fn ack_then_close(stream: &mut std::net::TcpStream, stop: &AtomicBool, n: usize) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut next_wire_seq: u64 = 0;
    let mut acked = 0usize;
    while !stop.load(Ordering::SeqCst) && acked < n {
        match read_frame(stream) {
            Ok((_fin, opcode, _payload)) => {
                if opcode == 0x8 {
                    break;
                }
                if opcode != 0x2 {
                    continue;
                }
                if write_qwp_ok_response(stream, next_wire_seq).is_err() {
                    break;
                }
                next_wire_seq += 1;
                acked += 1;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    // Returning drops the stream: the client's next read sees EOF.
}

/// Read (consume) the first `n` binary frames the client sends — so its
/// `write_all`s provably succeed — then close without ever acking. The client's
/// subsequent ACK-wait read hits EOF.
fn read_then_close(stream: &mut std::net::TcpStream, stop: &AtomicBool, n: usize) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
    let mut read = 0usize;
    while !stop.load(Ordering::SeqCst) && read < n {
        match read_frame(stream) {
            Ok((_fin, opcode, _payload)) => {
                if opcode == 0x8 {
                    break;
                }
                if opcode != 0x2 {
                    continue;
                }
                read += 1;
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(_) => break,
        }
    }
    // Returning drops the stream: the client's ACK-wait read sees EOF.
}

fn conf_for(port: u16, extras: &str) -> String {
    format!(
        "ws::addr=127.0.0.1:{port};auth_timeout=2000;reconnect_max_duration_millis=1000;{extras}"
    )
}

/// Build a conf string with a comma-joined endpoint list (`addr=h1,h2,...`),
/// which enables endpoint rotation / failover in the pool's connect path.
fn conf_for_endpoints(ports: &[u16], extras: &str) -> String {
    let addrs = ports
        .iter()
        .map(|p| format!("127.0.0.1:{p}"))
        .collect::<Vec<_>>()
        .join(",");
    format!("ws::addr={addrs};auth_timeout=2000;reconnect_max_duration_millis=1000;{extras}")
}

fn append_one_symbol_row<'a>(chunk: &mut Chunk<'a>, symbol: &'a [u8], timestamp: &'a [i64; 1]) {
    static CODES: [i32; 1] = [0];
    static OFFSETS: [i32; 2] = [0, 5];
    assert_eq!(
        symbol.len(),
        5,
        "test helper expects fixed-width symbol payloads"
    );
    chunk
        .symbol_i32("sym", &CODES, &OFFSETS, symbol, None)
        .unwrap();
    chunk.at_nanos(timestamp).unwrap();
}

fn one_symbol_buffer(db: &QuestDb, symbol: &str) -> crate::ingress::Buffer {
    let mut buffer = db.new_buffer();
    buffer
        .table("trades")
        .unwrap()
        .symbol("sym", symbol)
        .unwrap()
        .at_now()
        .unwrap();
    buffer
}

#[cfg(feature = "arrow-ingress")]
fn symbol_arrow_batch(values: Vec<&str>) -> arrow::array::RecordBatch {
    use arrow::array::StringArray;
    use arrow::datatypes::{DataType, Field, Schema};

    let schema = Arc::new(Schema::new(vec![Field::new("sym", DataType::Utf8, false)]));
    let symbols = Arc::new(StringArray::from(values));
    arrow::array::RecordBatch::try_new(schema, vec![symbols]).unwrap()
}

fn read_test_varint(bytes: &[u8], pos: &mut usize) -> u64 {
    let mut shift = 0;
    let mut value = 0u64;
    loop {
        let b = bytes[*pos];
        *pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return value;
        }
        shift += 7;
    }
}

fn read_test_bytes<'a>(bytes: &'a [u8], pos: &mut usize) -> &'a [u8] {
    let len = read_test_varint(bytes, pos) as usize;
    let start = *pos;
    *pos += len;
    &bytes[start..start + len]
}

fn decode_test_hex(hex: &str) -> Vec<u8> {
    let compact: Vec<u8> = hex
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert_eq!(compact.len() % 2, 0, "hex fixture must contain byte pairs");
    compact
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

/// Returns `(delta_start, new_symbols)` from a captured frame's delta-dict
/// prefix (header(12) then `delta_start`, count, then each new symbol).
fn read_symbol_prefix(payload: &[u8]) -> (u64, Vec<Vec<u8>>) {
    const QWP_HEADER_LEN: usize = 12;
    let mut pos = QWP_HEADER_LEN;
    let delta_start = read_test_varint(payload, &mut pos);
    let count = read_test_varint(payload, &mut pos);
    let symbols = (0..count)
        .map(|_| read_test_bytes(payload, &mut pos).to_vec())
        .collect();
    (delta_start, symbols)
}

fn frame_table_name(payload: &[u8]) -> String {
    const QWP_HEADER_LEN: usize = 12;
    let mut pos = QWP_HEADER_LEN;
    read_test_varint(payload, &mut pos); // delta_start
    let new_symbols = read_test_varint(payload, &mut pos);
    for _ in 0..new_symbols {
        read_test_bytes(payload, &mut pos);
    }
    std::str::from_utf8(read_test_bytes(payload, &mut pos))
        .unwrap()
        .to_owned()
}

fn unused_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind unused local port");
    listener.local_addr().expect("unused local addr").port()
}

/// Parse the `row_count` field out of a captured QWP frame: header(12) then
/// `delta_start`, the new-symbol delta, the table name, then `row_count`.
fn frame_row_count(payload: &[u8]) -> u64 {
    const QWP_HEADER_LEN: usize = 12;
    let mut pos = QWP_HEADER_LEN;
    read_test_varint(payload, &mut pos); // delta_start
    let new_symbols = read_test_varint(payload, &mut pos);
    for _ in 0..new_symbols {
        read_test_bytes(payload, &mut pos);
    }
    read_test_bytes(payload, &mut pos); // table name
    read_test_varint(payload, &mut pos)
}

fn sorted_slot_names(sf_dir: &Path) -> Vec<String> {
    let mut names = fs::read_dir(sf_dir)
        .unwrap()
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    names.sort();
    names
}

fn seed_async_qwp_ws_slot(sf_dir: &Path, sender_id: &str, value: i64) {
    let port = unused_local_port();
    let conf = format!(
        "ws::addr=127.0.0.1:{port};initial_connect_retry=async;\
         sf_dir={};sender_id={sender_id};sf_max_segment_bytes=256;sf_max_total_bytes=1024;\
         close_flush_timeout_millis=0;",
        sf_dir.display()
    );
    let mut sender = SenderBuilder::from_conf(&conf).unwrap().build().unwrap();
    let mut buf = sender.new_buffer();
    buf.table("legacy")
        .unwrap()
        .column_i64("value", value)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush(&mut buf).unwrap();
    drop(sender);
    assert!(
        slot_has_sfa_file(&sf_dir.join(sender_id)),
        "seeded slot {sender_id} should contain queued SFA data"
    );
}

#[test]
fn refuses_non_qwp_ws_schema() {
    let err = QuestDb::connect("http::addr=localhost:9000;").unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("QWP/WebSocket"));
}

#[test]
fn at_cap_borrow_waits_for_a_return_within_acquire_timeout() {
    let server = MockServer::spawn(2);
    let conf = conf_for_endpoints(
        &[server.port()],
        "sender_pool_min=1;sender_pool_max=1;pool_reap=manual;",
    );
    let db = std::sync::Arc::new(QuestDb::connect(&conf).unwrap());
    let held = db.borrow_sender().expect("first borrow fills the cap");

    let db2 = std::sync::Arc::clone(&db);
    let waiter = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let borrowed = db2.borrow_sender();
        (start.elapsed(), borrowed.is_ok())
    });

    std::thread::sleep(std::time::Duration::from_millis(150));
    drop(held);

    let (waited, ok) = waiter.join().unwrap();
    assert!(ok, "the at-cap waiter must receive the returned sender");
    assert!(
        waited >= std::time::Duration::from_millis(100),
        "the waiter must have blocked for the return, waited {waited:?}"
    );
    assert!(
        waited < std::time::Duration::from_secs(5),
        "the waiter must not run into the acquire timeout, waited {waited:?}"
    );
}

#[test]
fn at_cap_borrow_fails_fast_with_zero_acquire_timeout() {
    let server = MockServer::spawn(2);
    let conf = conf_for_endpoints(
        &[server.port()],
        "sender_pool_min=1;sender_pool_max=1;acquire_timeout_ms=0;pool_reap=manual;",
    );
    let db = QuestDb::connect(&conf).unwrap();
    let _held = db.borrow_sender().expect("first borrow fills the cap");

    let start = std::time::Instant::now();
    let err = db
        .borrow_sender()
        .expect_err("second borrow exceeds sender_pool_max");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg().contains("sender_pool_max") && err.msg().contains("acquire_timeout_ms"),
        "{}",
        err.msg()
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(1),
        "acquire_timeout_ms=0 must fail fast"
    );
}

#[test]
fn disk_store_and_forward_ingress_pool_uses_distinct_slots_up_to_pool_max() {
    let server = MockServer::spawn(4);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=cols;sender_pool_min=1;sender_pool_max=3;\
             acquire_timeout_ms=0;pool_reap=manual;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let b0 = db.borrow_sender().expect("slot 0");
    let b1 = db.borrow_sender().expect("slot 1");
    let b2 = db.borrow_sender().expect("slot 2");
    assert_eq!(db.in_use_count(), 3);
    assert_eq!(
        sorted_slot_names(dir.path()),
        vec!["cols-ingest-0", "cols-ingest-1", "cols-ingest-2"]
    );

    let err = db
        .borrow_sender()
        .expect_err("fourth borrow exceeds pool_max");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "{}", err.msg());

    drop(b1);
    let _again = db.borrow_sender().expect("returned slot is reusable");
    assert_eq!(
        sorted_slot_names(dir.path()),
        vec!["cols-ingest-0", "cols-ingest-1", "cols-ingest-2"]
    );

    drop(b0);
    drop(b2);
}

#[test]
fn disk_store_and_forward_preopens_dirty_in_range_slot_at_connect() {
    let dir = TempDir::new().unwrap();
    seed_async_qwp_ws_slot(dir.path(), "selfrace-ingest-1", 44);

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=selfrace;sender_pool_min=1;sender_pool_max=2;\
             pool_reap=manual;max_background_drainers=1;close_flush_timeout_millis=0;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let payload = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("dirty in-range slot should replay during connect-time pre-open");
    assert_eq!(frame_table_name(&payload), "legacy");
    assert!(
        wait_until(Duration::from_secs(2), || db.free_count() == 1),
        "pre-opened recovery sender should park in the free list"
    );
}

#[cfg(feature = "ffi-support")]
#[test]
fn disk_store_and_forward_borrower_rechecks_free_sender_after_close_wait_wake() {
    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(3);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=waitfree;sender_pool_min=1;sender_pool_max=2;\
             pool_reap=manual;close_flush_timeout_millis=2000;",
            dir.path().display()
        ),
    );
    let db = Arc::new(QuestDb::connect(&conf).unwrap());

    let mut closing = db
        .borrow_sender_owned()
        .expect("borrow slot that will close");
    let healthy = db.borrow_sender_owned().expect("borrow healthy slot");

    let values = [42_i64];
    let timestamps = [42_i64];
    let mut chunk = one_i64_row("waitfree", &values, &timestamps);
    closing
        .get_mut()
        .flush(&mut chunk)
        .expect("publish frame through closing slot");
    closing.get_mut().mark_must_close();
    let payload = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("closing slot frame should reach mock server");
    assert!(!payload.is_empty());

    let closer = thread::spawn(move || drop(closing));
    assert!(
        wait_until(Duration::from_secs(2), || db.closing_count() == 1),
        "closing sender did not enter the slot-close path"
    );

    let (tx, rx) = mpsc::channel();
    let waiter_db = Arc::clone(&db);
    let waiter = thread::spawn(move || {
        let result = waiter_db
            .borrow_sender_owned()
            .map(|_| ())
            .map_err(|err| err.msg().to_owned());
        tx.send(result).expect("send waiter result");
    });

    assert!(
        rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "borrower should wait while the pool is at cap with only a closing slot"
    );

    drop(healthy);
    rx.recv_timeout(Duration::from_secs(2))
        .expect("borrower should wake when a healthy sender returns")
        .expect("borrower must reuse the free sender, not report pool exhaustion");

    release_acks.store(true, Ordering::SeqCst);
    closer.join().expect("closer thread");
    waiter.join().expect("waiter thread");
}

#[cfg(feature = "ffi-support")]
#[test]
fn disk_store_and_forward_at_cap_borrow_waits_for_closing_slot_to_release_index() {
    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(2);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=closefree;sender_pool_min=1;sender_pool_max=1;\
             pool_reap=manual;close_flush_timeout_millis=2000;",
            dir.path().display()
        ),
    );
    let db = Arc::new(QuestDb::connect(&conf).unwrap());

    let mut closing = db
        .borrow_sender_owned()
        .expect("borrow slot that will close");
    let values = [55_i64];
    let timestamps = [55_i64];
    let mut chunk = one_i64_row("closefree", &values, &timestamps);
    closing
        .get_mut()
        .flush(&mut chunk)
        .expect("publish frame through closing slot");
    let payload = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("closing slot frame should reach mock server");
    assert_eq!(frame_table_name(&payload), "closefree");
    closing.get_mut().mark_must_close();

    let closer = thread::spawn(move || drop(closing));
    assert!(
        wait_until(Duration::from_secs(2), || db.closing_count() == 1),
        "closing sender did not enter the slot-close path"
    );

    let (tx, rx) = mpsc::channel();
    let waiter_db = Arc::clone(&db);
    let waiter = thread::spawn(move || {
        let result = waiter_db
            .borrow_sender_owned()
            .map(|_| ())
            .map_err(|err| err.msg().to_owned());
        tx.send(result).expect("send waiter result");
    });

    assert!(
        rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "borrower should wait while the only slot is closing"
    );

    release_acks.store(true, Ordering::SeqCst);
    rx.recv_timeout(Duration::from_secs(5))
        .expect("borrower should wake when the closing slot releases its index")
        .expect("borrower must mint the freed slot instead of reporting pool exhaustion");
    closer.join().expect("closer thread");
    waiter.join().expect("waiter thread");
}

#[test]
fn disk_store_and_forward_buffer_and_chunk_borrow_and_flush_together() {
    let (server, frames) = MockServer::spawn_acking_capturing(4);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=mixed;sender_pool_min=1;sender_pool_max=2;pool_reap=manual;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let mut chunk_sender = db.borrow_sender().expect("chunk sender");
    let mut buffer_sender = db.borrow_sender().expect("buffer sender");
    assert_eq!(
        sorted_slot_names(dir.path()),
        vec!["mixed-ingest-0", "mixed-ingest-1"]
    );

    let val = [11_i64];
    let ts = [11_i64];
    let mut chunk = one_i64_row("col_table", &val, &ts);
    chunk_sender
        .flush_and_wait(&mut chunk, AckLevel::Ok)
        .expect("Chunk flush while Buffer sender is borrowed");

    let mut buf = buffer_sender.new_buffer();
    buf.table("row_table")
        .unwrap()
        .column_i64("value", 22)
        .unwrap()
        .at_now()
        .unwrap();
    buffer_sender
        .flush_buffer_and_wait(&mut buf, AckLevel::Ok)
        .expect("Buffer flush while Chunk sender is borrowed");

    assert!(
        !frames
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_empty()
    );
    assert!(
        !frames
            .recv_timeout(Duration::from_secs(5))
            .unwrap()
            .is_empty()
    );
    assert_eq!(db.in_use_count(), 2);
    drop(buffer_sender);
    assert_eq!(db.in_use_count(), 1);
    drop(chunk_sender);
    assert_eq!(db.in_use_count(), 0);
}

#[test]
fn disk_store_and_forward_duplicate_pool_collides_on_managed_slot() {
    let port = unused_local_port();
    let dir = TempDir::new().unwrap();
    let conf = format!(
        "ws::addr=127.0.0.1:{port};auth_timeout=200;\
         sf_dir={};sender_id=shared;sender_pool_min=1;sender_pool_max=2;\
         pool_reap=manual;close_flush_timeout_millis=0;",
        dir.path().display()
    );
    let db1 = QuestDb::connect(&conf).unwrap();
    let db2 = QuestDb::connect(&conf).unwrap();

    let _held = db1
        .borrow_sender()
        .expect("first pool owns shared-ingest-0");
    let err = db2
        .borrow_sender()
        .expect_err("second pool must hit the slot flock");
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(
        err.msg().contains("shared-ingest-0")
            && err
                .msg()
                .to_ascii_lowercase()
                .contains("another process or pool")
            && err.msg().contains("unique sender_id"),
        "msg: {}",
        err.msg()
    );
}

#[test]
fn disk_store_and_forward_duplicate_pool_connect_warn_skips_flocked_slots() {
    let port = unused_local_port();
    let dir = TempDir::new().unwrap();
    let conf = format!(
        "ws::addr=127.0.0.1:{port};auth_timeout=200;initial_connect_retry=async;\
         sf_dir={};sender_id=dupe;sender_pool_min=1;sender_pool_max=1;\
         pool_reap=manual;close_flush_timeout_millis=0;",
        dir.path().display()
    );
    let db1 = QuestDb::connect(&conf).unwrap();

    let mut sender = db1.borrow_sender().expect("first pool owns dupe-ingest-0");

    let val = [1_i64];
    let ts = [1_i64];
    let mut chunk = one_i64_row("dupecol", &val, &ts);
    sender.flush(&mut chunk).expect("queue Chunk frame");

    let mut buf = sender.new_buffer();
    buf.table("duperow")
        .unwrap()
        .column_i64("value", 1)
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush_buffer(&mut buf).expect("queue Buffer frame");

    let db2 = QuestDb::connect(&conf).expect("duplicate pool connect skips recovery failures");
    assert_eq!(db2.free_count(), 0);

    let first_err = db2
        .borrow_sender()
        .expect_err("borrow still collides on the flocked ingestion slot");
    assert_eq!(first_err.code(), ErrorCode::ConfigError);
    assert!(
        first_err.msg().contains("dupe-ingest-0"),
        "{}",
        first_err.msg()
    );

    let retry_err = db2
        .borrow_sender()
        .expect_err("a retry still collides without leaking the pool cap");
    assert_eq!(retry_err.code(), ErrorCode::ConfigError);
    assert!(
        retry_err.msg().contains("dupe-ingest-0"),
        "{}",
        retry_err.msg()
    );
    assert_eq!(db2.in_use_count(), 0);

    drop(sender);
}

#[test]
fn disk_store_and_forward_restart_replays_reminted_and_out_of_range_managed_slots() {
    let dir = TempDir::new().unwrap();
    let seed_port = unused_local_port();
    let seed_conf = format!(
        "ws::addr=127.0.0.1:{seed_port};auth_timeout=200;\
         reconnect_max_duration_millis=100;sf_dir={};sender_id=replay;\
         sender_pool_min=1;sender_pool_max=2;pool_reap=manual;close_flush_timeout_millis=0;",
        dir.path().display()
    );
    {
        let db = QuestDb::connect(&seed_conf).unwrap();
        let mut s0 = db.borrow_sender().expect("seed slot 0");
        let mut s1 = db.borrow_sender().expect("seed slot 1");

        let v0 = [101_i64];
        let t0 = [101_i64];
        let mut c0 = one_i64_row("replay0", &v0, &t0);
        s0.flush(&mut c0).expect("append slot 0");

        let v1 = [202_i64];
        let t1 = [202_i64];
        let mut c1 = one_i64_row("replay1", &v1, &t1);
        s1.flush(&mut c1).expect("append slot 1");
    }
    assert!(slot_has_sfa_file(&dir.path().join("replay-ingest-0")));
    assert!(slot_has_sfa_file(&dir.path().join("replay-ingest-1")));

    let (server, frames) = MockServer::spawn_acking_capturing(4);
    let replay_conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=replay;sender_pool_min=1;sender_pool_max=1;pool_reap=manual;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&replay_conf).unwrap();
    let mut s0 = db
        .borrow_sender()
        .expect("reopen slot 0 and start out-of-range managed-slot recovery");

    let first = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("reminted slot replay");
    let second = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("out-of-range managed slot replay");
    assert!(!first.is_empty());
    assert!(!second.is_empty());
    s0.wait(AckLevel::Ok, Duration::from_secs(5))
        .expect("reminted slot replay acked");
}

#[test]
fn disk_store_and_forward_restart_same_pool_max_replays_in_range_slots_without_borrow() {
    let dir = TempDir::new().unwrap();
    let seed_port = unused_local_port();
    let seed_conf = format!(
        "ws::addr=127.0.0.1:{seed_port};auth_timeout=200;\
         reconnect_max_duration_millis=100;sf_dir={};sender_id=samepool;\
         sender_pool_min=1;sender_pool_max=2;pool_reap=manual;close_flush_timeout_millis=0;",
        dir.path().display()
    );
    {
        let db = QuestDb::connect(&seed_conf).unwrap();
        let mut s0 = db.borrow_sender().expect("seed slot 0");
        let mut s1 = db.borrow_sender().expect("seed slot 1");

        let v0 = [301_i64];
        let t0 = [301_i64];
        let mut c0 = one_i64_row("samepool0", &v0, &t0);
        s0.flush(&mut c0).expect("append slot 0");

        let v1 = [302_i64];
        let t1 = [302_i64];
        let mut c1 = one_i64_row("samepool1", &v1, &t1);
        s1.flush(&mut c1).expect("append slot 1");
    }
    assert!(slot_has_sfa_file(&dir.path().join("samepool-ingest-0")));
    assert!(slot_has_sfa_file(&dir.path().join("samepool-ingest-1")));

    let (server, frames) = MockServer::spawn_acking_capturing(4);
    let replay_conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=samepool;sender_pool_min=1;sender_pool_max=2;\
             pool_reap=manual;max_background_drainers=1;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&replay_conf).unwrap();

    let first = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("slot 0 replay");
    let second = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("slot 1 replay");
    let tables = [frame_table_name(&first), frame_table_name(&second)]
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert!(
        wait_until(Duration::from_secs(2), || db.free_count() == 2),
        "both pre-opened recovery senders should park in the free list"
    );
    assert_eq!(
        tables,
        BTreeSet::from(["samepool0".to_string(), "samepool1".to_string()])
    );

    let mut s0 = db.borrow_sender().expect("borrow replayed slot");
    let mut s1 = db.borrow_sender().expect("borrow other replayed slot");
    s0.wait(AckLevel::Ok, Duration::from_secs(5))
        .expect("first replay acked");
    s1.wait(AckLevel::Ok, Duration::from_secs(5))
        .expect("second replay acked");
    assert!(
        frames.recv_timeout(Duration::from_millis(500)).is_err(),
        "borrowing parked recovery senders must not replay duplicate frames"
    );
}

#[test]
fn disk_store_and_forward_pool_drains_unsuffixed_slot_only_with_orphan_drain_enabled() {
    let dir = TempDir::new().unwrap();
    seed_async_qwp_ws_slot(dir.path(), "legacy", 33);

    let (server, frames) = MockServer::spawn_acking_capturing(4);
    let default_conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=legacy;sender_pool_min=1;sender_pool_max=2;\
             pool_reap=manual;max_background_drainers=1;",
            dir.path().display()
        ),
    );
    {
        let db = QuestDb::connect(&default_conf).unwrap();
        let _sender = db
            .borrow_sender()
            .expect("managed slot opens without adopting unsuffixed slot by default");
        assert!(
            frames.recv_timeout(Duration::from_millis(200)).is_err(),
            "unsuffixed slot must not drain without drain_orphans=on"
        );
    }
    assert!(slot_has_sfa_file(&dir.path().join("legacy")));

    let drain_conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=legacy;sender_pool_min=1;sender_pool_max=2;\
             pool_reap=manual;max_background_drainers=1;drain_orphans=on;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&drain_conf).unwrap();
    let _sender = db
        .borrow_sender()
        .expect("managed slot opens and starts orphan drainer");

    let payload = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("unsuffixed slot should be replayed with drain_orphans=on");
    assert!(!payload.is_empty());
    assert!(
        wait_until(Duration::from_secs(2), || {
            !slot_has_sfa_file(&dir.path().join("legacy"))
        }),
        "unsuffixed orphan slot should be drained"
    );
    assert!(!dir.path().join("legacy").join(".failed").exists());
    assert_eq!(
        sorted_slot_names(dir.path()),
        vec!["legacy", "legacy-ingest-0"]
    );
}

#[test]
fn store_and_forward_column_sender_reports_fsn_progress() {
    let server = MockServer::spawn_acking(8);
    let conf = conf_for_endpoints(&[server.port()], "pool_reap=manual;");
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    assert_eq!(sender.published_fsn().unwrap(), None);
    assert_eq!(sender.acked_fsn().unwrap(), None);

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();

    let fsn = sender
        .flush_and_get_fsn(&mut chunk)
        .expect("SFA flush should publish")
        .expect("chunk flush publishes a frame");
    assert_eq!(chunk.row_count(), 0);
    assert_eq!(sender.published_fsn().unwrap(), Some(fsn));

    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();
    assert!(
        sender
            .acked_fsn()
            .unwrap()
            .is_some_and(|acked| acked >= fsn),
        "acked watermark must cover published FSN"
    );
}

#[test]
fn store_and_forward_pool_borrow_buffers_with_no_server() {
    let port = unused_local_port();
    let conf = conf_for_endpoints(&[port], "pool_reap=manual;close_flush_timeout_millis=0;");
    let db = QuestDb::connect(&conf).unwrap();

    let mut sender = db
        .borrow_sender()
        .expect("lazy SF pool borrow must not require a live server");
    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();

    let fsn = sender
        .flush_and_get_fsn(&mut chunk)
        .expect("SF flush must publish to the local queue without a server")
        .expect("non-empty chunk publishes a frame");

    assert_eq!(chunk.row_count(), 0);
    assert_eq!(sender.published_fsn().unwrap(), Some(fsn));
    assert_eq!(sender.acked_fsn().unwrap(), None);
}

#[test]
fn pooled_buffer_factory_uses_configured_name_limit_without_borrow() {
    let port = unused_local_port();
    let conf = conf_for_endpoints(
        &[port],
        "max_name_len=16;pool_reap=manual;close_flush_timeout_millis=0;",
    );
    let db = QuestDb::connect(&conf).unwrap();

    let mut buffer = db.new_buffer();
    let err = buffer
        .table("table_name_len_17")
        .expect_err("the pool-configured name limit must be applied at creation");
    assert_eq!(err.code(), ErrorCode::InvalidName);
    assert_eq!(db.in_use_count(), 0, "buffer creation must not borrow");
    assert_eq!(db.free_count(), 0, "buffer creation must not open a slot");
}

#[test]
fn pooled_buffer_rejects_non_qwp_ws_without_modification() {
    let port = unused_local_port();
    let db = QuestDb::connect(&conf_for_endpoints(
        &[port],
        "pool_reap=manual;close_flush_timeout_millis=0;",
    ))
    .unwrap();
    let mut sender = db.borrow_sender().unwrap();
    let mut buffer = crate::ingress::Buffer::new(ProtocolVersion::V2);
    buffer
        .table("trades")
        .unwrap()
        .column_i64("qty", 7)
        .unwrap()
        .at_now()
        .unwrap();
    let len = buffer.len();
    let rows = buffer.row_count();

    let err = sender
        .flush_buffer(&mut buffer)
        .expect_err("an ILP buffer must be rejected by pooled QWP ingestion");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert_eq!(buffer.len(), len);
    assert_eq!(buffer.row_count(), rows);
    assert!(!buffer.is_empty());
    assert_eq!(sender.published_fsn().unwrap(), None);
}

#[test]
fn pooled_buffer_empty_incomplete_keep_clear_multi_table_and_fsn_contract() {
    let (server, frames) = MockServer::spawn_acking_capturing(4);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_reap=manual;")).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut empty = db.new_buffer();
    empty.set_marker().unwrap();
    assert_eq!(
        sender.flush_buffer_and_keep_and_get_fsn(&empty).unwrap(),
        None
    );
    empty
        .rewind_to_marker()
        .expect("keep must preserve an empty buffer's marker");
    empty.set_marker().unwrap();
    assert_eq!(sender.flush_buffer_and_get_fsn(&mut empty).unwrap(), None);
    assert!(
        empty.rewind_to_marker().is_err(),
        "clearing flush must clear retained marker state even when empty"
    );
    assert!(frames.try_recv().is_err(), "empty buffers publish no frame");

    let mut single = db.new_buffer();
    single
        .table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_f64("price", 2615.54)
        .unwrap();
    let err = sender
        .flush_buffer_and_keep(&single)
        .expect_err("an incomplete row must be rejected before encoding");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(!single.is_empty(), "incomplete rejection must retain input");
    assert_eq!(sender.published_fsn().unwrap(), None);

    single.at_now().unwrap();
    let first_fsn = sender
        .flush_buffer_and_keep_and_get_fsn(&single)
        .unwrap()
        .expect("a completed row publishes one frame");
    assert_eq!(single.row_count(), 1, "keep must retain completed rows");
    let single_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        u16::from_le_bytes([single_payload[6], single_payload[7]]),
        1
    );

    let mut barrier = db.new_buffer();
    barrier.set_marker().unwrap();
    sender
        .flush_buffer_and_wait(&mut barrier, AckLevel::Ok)
        .expect("an empty waited flush is a barrier for prior publications");
    assert!(
        sender
            .acked_fsn()
            .unwrap()
            .is_some_and(|acked| acked >= first_fsn)
    );
    assert!(barrier.rewind_to_marker().is_err());

    let mut multi = db.new_buffer();
    multi
        .table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    multi
        .table("quotes")
        .unwrap()
        .column_f64("bid", 42.5)
        .unwrap()
        .at_now()
        .unwrap();
    sender
        .flush_buffer_and_wait(&mut multi, AckLevel::Ok)
        .unwrap();
    assert!(multi.is_empty(), "successful waited flush must clear");
    let multi_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(u16::from_le_bytes([multi_payload[6], multi_payload[7]]), 2);
    assert!(
        sender.published_fsn().unwrap().unwrap() > first_fsn,
        "Buffer FSNs must advance monotonically"
    );
}

#[test]
fn pooled_buffer_too_large_is_not_split_and_keeps_input() {
    let port = unused_local_port();
    let db = QuestDb::connect(&conf_for_endpoints(
        &[port],
        "max_buf_size=1024;pool_reap=manual;close_flush_timeout_millis=0;",
    ))
    .unwrap();
    let mut sender = db.borrow_sender().unwrap();
    let oversized = "x".repeat(2048);
    let mut buffer = db.new_buffer();
    buffer
        .table("trades")
        .unwrap()
        .column_str("payload", &oversized)
        .unwrap()
        .at_now()
        .unwrap();

    let err = sender
        .flush_buffer(&mut buffer)
        .expect_err("a Buffer is one indivisible publication");
    assert_eq!(err.code(), ErrorCode::BatchTooLarge);
    assert!(err.msg().contains("QWP frame"));
    assert!(!buffer.is_empty(), "size rejection must retain input");
    assert_eq!(buffer.row_count(), 1);
    assert_eq!(sender.published_fsn().unwrap(), None);
}

#[test]
fn pooled_buffer_append_timeout_rolls_back_symbols_and_keeps_input() {
    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_reap=manual;max_in_flight=1;sf_append_deadline_millis=25;",
    ))
    .unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut first = db.new_buffer();
    first
        .table("trades")
        .unwrap()
        .symbol("sym", "alpha")
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush_buffer(&mut first).unwrap();
    let first_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        read_symbol_prefix(&first_payload),
        (0, vec![b"alpha".to_vec()])
    );

    let mut failed = db.new_buffer();
    failed
        .table("trades")
        .unwrap()
        .symbol("sym", "bravo")
        .unwrap()
        .at_now()
        .unwrap();
    let err = sender
        .flush_buffer(&mut failed)
        .expect_err("the full local queue must reject before append");
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(
        err.msg()
            .contains("timed out waiting for local queue capacity")
    );
    assert!(!failed.is_empty(), "failed local append must retain input");

    release_acks.store(true, Ordering::SeqCst);
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();

    let mut third = db.new_buffer();
    third
        .table("trades")
        .unwrap()
        .symbol("sym", "gamma")
        .unwrap()
        .at_now()
        .unwrap();
    sender.flush_buffer(&mut third).unwrap();
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();
    let third_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        read_symbol_prefix(&third_payload),
        (1, vec![b"gamma".to_vec()]),
        "the failed Buffer's symbol ID must be rolled back and reused"
    );
}

#[test]
fn pooled_buffer_wait_preflight_and_post_publish_failure_contract() {
    let durable_server = MockServer::spawn(1);
    let durable_db =
        QuestDb::connect(&conf_for(durable_server.port(), "pool_reap=manual;")).unwrap();
    let mut durable_sender = durable_db.borrow_sender().unwrap();
    let mut retained = durable_db.new_buffer();
    retained
        .table("trades")
        .unwrap()
        .column_i64("qty", 1)
        .unwrap()
        .at_now()
        .unwrap();
    let err = durable_sender
        .flush_buffer_and_wait(&mut retained, AckLevel::Durable)
        .expect_err("durable ACK must be rejected before publication without opt-in");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(!retained.is_empty());
    assert_eq!(durable_sender.published_fsn().unwrap(), None);

    let rejecting_server = MockServer::spawn_erroring(1, QWP_STATUS_SCHEMA_MISMATCH);
    let rejecting_db =
        QuestDb::connect(&conf_for(rejecting_server.port(), "pool_reap=manual;")).unwrap();
    let mut rejecting_sender = rejecting_db.borrow_sender().unwrap();
    let mut published = rejecting_db.new_buffer();
    published
        .table("trades")
        .unwrap()
        .column_i64("qty", 2)
        .unwrap()
        .at_now()
        .unwrap();
    let err = rejecting_sender
        .flush_buffer_and_wait(&mut published, AckLevel::Ok)
        .expect_err("a terminal ACK must surface after local publication");
    assert_eq!(err.code(), ErrorCode::ServerRejection);
    assert!(err.in_doubt());
    assert!(published.is_empty(), "post-publish wait failure must clear");
}

#[test]
fn pooled_buffer_is_origin_independent_sendable_and_offline_first() {
    let port = unused_local_port();
    let db = Arc::new(
        QuestDb::connect(&conf_for_endpoints(
            &[port],
            "pool_reap=manual;close_flush_timeout_millis=0;",
        ))
        .unwrap(),
    );
    let buffer = db.new_buffer();
    let mut buffer = thread::spawn(move || {
        let mut buffer = buffer;
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", "offline")
            .unwrap()
            .column_i64("qty", 1)
            .unwrap()
            .at_now()
            .unwrap();
        buffer
    })
    .join()
    .unwrap();

    let worker_db = Arc::clone(&db);
    let (fsn, published, empty) = thread::spawn(move || {
        let mut sender = worker_db
            .borrow_sender()
            .expect("offline-first borrow must not require an endpoint");
        let fsn = sender
            .flush_buffer_and_get_fsn(&mut buffer)
            .expect("local acceptance must work while the endpoint is unavailable")
            .expect("the non-empty Buffer publishes a frame");
        (fsn, sender.published_fsn().unwrap(), buffer.is_empty())
    })
    .join()
    .unwrap();
    assert_eq!(published, Some(fsn));
    assert!(empty);
}

#[test]
fn pooled_buffer_payload_matches_m0_checked_in_golden() {
    const SYMBOL_COUNT: usize = 10;
    const BASE_TS_NANOS: i64 = 1_700_000_000_000_000_000;
    const GOLDEN: &str = include_str!("interop/qwp-unified-ingress/m0-equivalent-buffer.hex");

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_reap=manual;")).unwrap();
    let mut buffer = db.new_buffer();
    for idx in 0..SYMBOL_COUNT {
        buffer
            .table("trades")
            .unwrap()
            .symbol("sym", format!("SYM_{idx:03}"))
            .unwrap()
            .column_i64("qty", idx as i64)
            .unwrap()
            .column_f64("px", 100.0 + idx as f64)
            .unwrap()
            .at(TimestampNanos::new(BASE_TS_NANOS + idx as i64))
            .unwrap();
    }

    let mut sender = db.borrow_sender().unwrap();
    sender
        .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
        .unwrap();
    let payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(payload, decode_test_hex(GOLDEN));
    assert!(buffer.is_empty());
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn mixed_sfa_shapes_share_symbols_fsns_ack_timeout_and_pool_reborrow() {
    use crate::ingress::column_sender::ArrowColumnOverride;

    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_reap=manual;")).unwrap();

    let first_fsn = {
        let mut sender = db.borrow_sender().unwrap();
        let mut buffer = one_symbol_buffer(&db, "alpha");
        let fsn = sender
            .flush_buffer_and_get_fsn(&mut buffer)
            .unwrap()
            .unwrap();
        assert!(buffer.is_empty());
        fsn
    };
    assert_eq!(db.free_count(), 1, "the live SFA stream is pooled");

    let mut sender = db
        .borrow_sender()
        .expect("reborrow the same stream with its queued Buffer frame");
    assert_eq!(sender.published_fsn().unwrap(), Some(first_fsn));

    let codes = [0_i32, 1_i32];
    let offsets = [0_i32, 5_i32, 10_i32];
    let timestamps = [1_i64, 2_i64];
    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &codes, &offsets, b"alphabravo", None)
        .unwrap();
    chunk.at_nanos(&timestamps).unwrap();
    let chunk_fsn = sender.flush_and_get_fsn(&mut chunk).unwrap().unwrap();
    assert!(chunk.is_empty());

    let batch = symbol_arrow_batch(vec!["bravo", "charlie"]);
    let overrides = [ArrowColumnOverride::Symbol { column: "sym" }];
    let arrow_fsn = sender
        .flush_arrow_batch_at_now_and_get_fsn("trades", &batch, &overrides)
        .unwrap()
        .unwrap();

    let mut reused = one_symbol_buffer(&db, "alpha");
    let final_fsn = sender
        .flush_buffer_and_get_fsn(&mut reused)
        .unwrap()
        .unwrap();
    assert!(reused.is_empty());
    assert!(
        first_fsn < chunk_fsn && chunk_fsn < arrow_fsn && arrow_fsn < final_fsn,
        "FSNs must be monotonic across Buffer, Chunk, Arrow, Buffer"
    );

    let first_payload = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("the peer must receive the first frame before withholding ACKs");
    let err = sender
        .wait(AckLevel::Ok, Duration::from_millis(150))
        .expect_err("one wait over the mixed sequence must observe ACK starvation");
    assert_eq!(err.code(), ErrorCode::FailoverRetry);
    assert!(err.msg().contains("no ack progress"), "{err}");

    release_acks.store(true, Ordering::SeqCst);
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("one cumulative wait must cover every mixed-shape FSN");
    assert!(
        sender
            .acked_fsn()
            .unwrap()
            .is_some_and(|acked| acked >= final_fsn)
    );

    let mut captured = vec![first_payload];
    captured.extend(frames.try_iter());
    let data_frames: Vec<&Vec<u8>> = captured
        .iter()
        .filter(|frame| {
            frame.len() >= 12
                && &frame[..4] == b"QWP1"
                && u16::from_le_bytes([frame[6], frame[7]]) >= 1
        })
        .collect();
    assert_eq!(data_frames.len(), 4);
    assert_eq!(
        parse_delta_dict_prefix(data_frames[0]),
        (0, vec![b"alpha".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(data_frames[1]),
        (1, vec![b"bravo".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(data_frames[2]),
        (2, vec![b"charlie".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(data_frames[3]),
        (3, Vec::new()),
        "a Buffer must reuse alpha's id after Chunk and Arrow extended the namespace"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn mixed_sfa_queue_pressure_rolls_back_the_failing_encoder_namespace() {
    use crate::ingress::column_sender::ArrowColumnOverride;

    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_reap=manual;max_in_flight=2;sf_append_deadline_millis=25;",
    ))
    .unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut first = one_symbol_buffer(&db, "alpha");
    let first_fsn = sender
        .flush_buffer_and_get_fsn(&mut first)
        .unwrap()
        .unwrap();
    let first_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();

    let codes = [0_i32];
    let offsets = [0_i32, 5_i32];
    let timestamps = [2_i64];
    let mut second = Chunk::new("trades");
    second
        .symbol_i32("sym", &codes, &offsets, b"bravo", None)
        .unwrap();
    second.at_nanos(&timestamps).unwrap();
    let second_fsn = sender.flush_and_get_fsn(&mut second).unwrap().unwrap();
    assert!(second_fsn > first_fsn);

    let failed_batch = symbol_arrow_batch(vec!["charlie"]);
    let overrides = [ArrowColumnOverride::Symbol { column: "sym" }];
    let err = sender
        .flush_arrow_batch_at_now_and_get_fsn("trades", &failed_batch, &overrides)
        .expect_err("the third mixed frame must time out behind max_in_flight=2");
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(
        err.msg()
            .contains("timed out waiting for local queue capacity")
    );
    assert_eq!(sender.published_fsn().unwrap(), Some(second_fsn));

    release_acks.store(true, Ordering::SeqCst);
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();
    let second_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();

    let mut after_failure = one_symbol_buffer(&db, "delta");
    let final_fsn = sender
        .flush_buffer_and_get_fsn(&mut after_failure)
        .unwrap()
        .unwrap();
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();
    let final_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(final_fsn > second_fsn);

    assert_eq!(
        parse_delta_dict_prefix(&first_payload),
        (0, vec![b"alpha".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(&second_payload),
        (1, vec![b"bravo".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(&final_payload),
        (2, vec![b"delta".to_vec()]),
        "the rejected Arrow frame must free charlie's id for the next Buffer"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn mixed_sfa_namespace_survives_endpoint_failover_and_catch_up() {
    use crate::ingress::column_sender::ArrowColumnOverride;

    let first = MockServer::spawn_ack_then_close(1, 1);
    let (live, frames) = MockServer::spawn_acking_capturing(4);
    let conf = format!(
        "ws::addr=127.0.0.1:{},127.0.0.1:{};auth_timeout=2000;\
         reconnect_max_duration_millis=10000;pool_reap=manual;",
        first.port(),
        live.port()
    );
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut initial = one_symbol_buffer(&db, "alpha");
    sender
        .flush_buffer_and_wait(&mut initial, AckLevel::Ok)
        .expect("the first endpoint ACKs alpha before closing");
    let initial_fsn = sender.published_fsn().unwrap().unwrap();

    let codes = [0_i32, 1_i32];
    let offsets = [0_i32, 5_i32, 10_i32];
    let timestamps = [2_i64, 3_i64];
    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &codes, &offsets, b"alphabravo", None)
        .unwrap();
    chunk.at_nanos(&timestamps).unwrap();
    let chunk_fsn = sender.flush_and_get_fsn(&mut chunk).unwrap().unwrap();

    let batch = symbol_arrow_batch(vec!["bravo", "charlie"]);
    let overrides = [ArrowColumnOverride::Symbol { column: "sym" }];
    let arrow_fsn = sender
        .flush_arrow_batch_at_now_and_get_fsn("trades", &batch, &overrides)
        .unwrap()
        .unwrap();

    let mut reused = one_symbol_buffer(&db, "alpha");
    let final_fsn = sender
        .flush_buffer_and_get_fsn(&mut reused)
        .unwrap()
        .unwrap();
    assert!(initial_fsn < chunk_fsn && chunk_fsn < arrow_fsn && arrow_fsn < final_fsn);

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match sender.wait(AckLevel::Ok, Duration::from_secs(30)) {
            Ok(()) => break,
            Err(err) if err.code() == ErrorCode::FailoverRetry && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => panic!("mixed failover did not recover: {err}"),
        }
    }

    let captured: Vec<Vec<u8>> = frames.try_iter().collect();
    let catch_ups: Vec<&Vec<u8>> = captured
        .iter()
        .filter(|frame| {
            frame.len() >= 12
                && &frame[..4] == b"QWP1"
                && u16::from_le_bytes([frame[6], frame[7]]) == 0
        })
        .collect();
    let data_frames: Vec<&Vec<u8>> = captured
        .iter()
        .filter(|frame| {
            frame.len() >= 12
                && &frame[..4] == b"QWP1"
                && u16::from_le_bytes([frame[6], frame[7]]) >= 1
        })
        .collect();
    let catch_up = catch_ups
        .first()
        .expect("the replacement endpoint must receive a dictionary catch-up");
    let (catch_up_start, catch_up_symbols) = parse_delta_dict_prefix(catch_up);
    assert_eq!(catch_up_start, 0);
    assert!(
        catch_up_symbols == vec![b"alpha".to_vec()]
            || catch_up_symbols == vec![b"alpha".to_vec(), b"bravo".to_vec()],
        "the old socket may fail before or after its final write, but catch-up must be a contiguous alpha[/bravo] prefix: {catch_up_symbols:?}"
    );
    assert_eq!(data_frames.len(), 3);
    assert_eq!(
        parse_delta_dict_prefix(data_frames[0]),
        (1, vec![b"bravo".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(data_frames[1]),
        (2, vec![b"charlie".to_vec()])
    );
    assert_eq!(parse_delta_dict_prefix(data_frames[2]), (3, Vec::new()));
    assert_eq!(live.accepted(), 1);
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn disk_recovery_orphan_drains_mixed_shapes_with_one_dictionary() {
    use crate::ingress::column_sender::ArrowColumnOverride;

    let dir = TempDir::new().unwrap();
    let seed_port = unused_local_port();
    let seed_conf = format!(
        "ws::addr=127.0.0.1:{seed_port};auth_timeout=200;\
         reconnect_max_duration_millis=10000;sf_dir={};sender_id=mixedrec;\
         sender_pool_min=1;sender_pool_max=2;pool_reap=manual;close_flush_timeout_millis=0;",
        dir.path().display()
    );
    {
        let db = QuestDb::connect(&seed_conf).unwrap();
        let _slot_zero = db.borrow_sender().expect("hold slot zero");
        let mut sender = db.borrow_sender().expect("seed slot one");

        let mut first = one_symbol_buffer(&db, "alpha");
        sender.flush_buffer(&mut first).unwrap();

        let codes = [0_i32, 1_i32];
        let offsets = [0_i32, 5_i32, 10_i32];
        let timestamps = [2_i64, 3_i64];
        let mut chunk = Chunk::new("trades");
        chunk
            .symbol_i32("sym", &codes, &offsets, b"alphabravo", None)
            .unwrap();
        chunk.at_nanos(&timestamps).unwrap();
        sender.flush(&mut chunk).unwrap();

        let batch = symbol_arrow_batch(vec!["bravo", "charlie"]);
        let overrides = [ArrowColumnOverride::Symbol { column: "sym" }];
        sender
            .flush_arrow_batch_at_now_and_get_fsn("trades", &batch, &overrides)
            .unwrap()
            .unwrap();

        let mut reused = one_symbol_buffer(&db, "alpha");
        sender.flush_buffer(&mut reused).unwrap();
    }

    let orphan = dir.path().join("mixedrec-ingest-1");
    assert!(slot_has_sfa_file(&orphan));
    let side_file = std::fs::read(orphan.join(".symbol-dict")).unwrap();
    for symbol in [
        b"alpha".as_slice(),
        b"bravo".as_slice(),
        b"charlie".as_slice(),
    ] {
        assert!(
            side_file
                .windows(symbol.len())
                .any(|window| window == symbol),
            "persisted mixed dictionary must contain {}",
            String::from_utf8_lossy(symbol)
        );
    }

    let (live, frames) = MockServer::spawn_acking_capturing(8);
    let replay_conf = conf_for_endpoints(
        &[live.port()],
        &format!(
            "sf_dir={};sender_id=mixedrec;sender_pool_min=1;sender_pool_max=1;\
             pool_reap=manual;max_background_drainers=1;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&replay_conf).unwrap();
    let _sender = db
        .borrow_sender()
        .expect("slot zero starts out-of-range orphan recovery");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut captured = Vec::new();
    while Instant::now() < deadline {
        captured.extend(frames.try_iter());
        let data_count = captured
            .iter()
            .filter(|frame| {
                frame.len() >= 12
                    && &frame[..4] == b"QWP1"
                    && u16::from_le_bytes([frame[6], frame[7]]) >= 1
            })
            .count();
        if data_count >= 4 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let catch_ups: Vec<&Vec<u8>> = captured
        .iter()
        .filter(|frame| {
            frame.len() >= 12
                && &frame[..4] == b"QWP1"
                && u16::from_le_bytes([frame[6], frame[7]]) == 0
        })
        .collect();
    let data_frames: Vec<&Vec<u8>> = captured
        .iter()
        .filter(|frame| {
            frame.len() >= 12
                && &frame[..4] == b"QWP1"
                && u16::from_le_bytes([frame[6], frame[7]]) >= 1
        })
        .collect();
    assert_eq!(
        parse_delta_dict_prefix(
            catch_ups
                .first()
                .expect("orphan recovery must register its persisted dictionary")
        ),
        (
            0,
            vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()]
        )
    );
    assert_eq!(data_frames.len(), 4, "all mixed frames must replay");
    assert_eq!(
        parse_delta_dict_prefix(data_frames[0]),
        (0, vec![b"alpha".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(data_frames[1]),
        (1, vec![b"bravo".to_vec()])
    );
    assert_eq!(
        parse_delta_dict_prefix(data_frames[2]),
        (2, vec![b"charlie".to_vec()])
    );
    assert_eq!(parse_delta_dict_prefix(data_frames[3]), (3, Vec::new()));
    assert!(
        wait_until(Duration::from_secs(5), || !slot_has_sfa_file(&orphan)),
        "the out-of-range mixed slot must drain completely"
    );
    assert!(!orphan.join(".failed").exists());
}

#[test]
fn terminal_sfa_sender_is_not_recycled_into_the_next_borrow() {
    let server = MockServer::spawn_erroring(2, QWP_STATUS_SCHEMA_MISMATCH);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_reap=manual;")).unwrap();
    {
        let mut sender = db.borrow_sender().unwrap();
        let mut buffer = one_symbol_buffer(&db, "alpha");
        let err = sender
            .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
            .expect_err("the first stream must latch the terminal server rejection");
        assert_eq!(err.code(), ErrorCode::ServerRejection);
        assert!(sender.must_close_for_test());
        assert!(
            buffer.is_empty(),
            "the rejected frame was locally published"
        );
    }
    assert_eq!(db.free_count(), 0, "terminal SFA state must not recycle");
    assert_eq!(db.in_use_count(), 0);

    let fresh = db
        .borrow_sender()
        .expect("the next borrow must construct a fresh SFA stream");
    assert!(!fresh.must_close_for_test());
    assert_eq!(fresh.published_fsn().unwrap(), None);
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 2),
        "the fresh borrow must open a new physical connection"
    );
}

fn check_store_and_forward_sync_reports_terminal_schema_rejection(extras: &str) {
    let server = MockServer::spawn_erroring(1, QWP_STATUS_SCHEMA_MISMATCH);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty1 = [1_i64];
    let ts1 = [1_i64];
    chunk.column_i64("qty", &qty1, None).unwrap();
    chunk.at_nanos(&ts1).unwrap();
    sender.flush(&mut chunk).unwrap();
    let err = sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect_err("first SFA frame is schema-rejected");
    assert_eq!(err.code(), ErrorCode::ServerRejection);
    assert_eq!(
        err.qwp_ws_rejection().and_then(|error| error.status),
        Some(QWP_STATUS_SCHEMA_MISMATCH)
    );

    assert!(sender.must_close_for_test());
}

fn check_store_and_forward_sync_times_out_on_silent_but_alive_peer(extras: &str) {
    // `Park` mode finishes the WS upgrade and keeps the connection alive
    // (draining frames) but never acks — the back-pressured-WAL / stuck-commit
    // case. Without a deadline the SFA `sync` poll loop would spin forever;
    // with one it must surface a `FailoverRetry` so the caller regains control,
    // matching the direct backend's `request_timeout`-bounded behaviour.
    let server = MockServer::spawn(1);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();
    sender.flush(&mut chunk).unwrap();

    let start = Instant::now();
    let err = sender
        .wait(AckLevel::Ok, Duration::from_millis(150))
        .expect_err("silent-but-alive peer must not block sync forever");
    let elapsed = start.elapsed();

    assert_eq!(err.code(), ErrorCode::FailoverRetry, "{}", err.msg());
    assert!(
        err.msg().contains("timed out") && err.msg().contains("no ack progress"),
        "unexpected timeout message: {}",
        err.msg()
    );
    assert!(
        elapsed >= Duration::from_millis(150),
        "sync returned before the deadline elapsed: {elapsed:?}"
    );
    // Generous upper bound: proves the loop terminated near the deadline
    // rather than hanging, without being flaky on slow CI.
    assert!(
        elapsed < Duration::from_secs(5),
        "sync should bail out near the deadline, took {elapsed:?}"
    );
}

#[test]
fn drop_with_in_flight_best_effort_commits_and_recycles() {
    // A borrow dropped with un-sync'd deferred frames must best-effort sync
    // (committing the tail) and recycle the clean connection — not silently
    // discard the frames and latch the connection must_close.
    let server = MockServer::spawn_acking(1);
    let conf = conf_for_endpoints(&[server.port()], "pool_reap=manual;");
    let db = QuestDb::connect(&conf).unwrap();
    {
        let mut sender = db.borrow_direct_column_sender().unwrap();
        let qty = [1_i64];
        let ts = [1_i64];
        let mut c1 = Chunk::new("trades");
        c1.column_i64("qty", &qty, None).unwrap();
        c1.at_nanos(&ts).unwrap();
        sender.flush(&mut c1).unwrap(); // first frame: committed inline

        let mut c2 = Chunk::new("trades");
        c2.column_i64("qty", &qty, None).unwrap();
        c2.at_nanos(&ts).unwrap();
        sender.flush(&mut c2).unwrap(); // deferred: published but uncommitted
        assert!(sender.in_flight() > 0, "deferred flush must be in-flight");
    }
    assert_eq!(
        db.direct_free_count(),
        1,
        "healthy connection must be recycled after drop best-effort sync"
    );
    assert_eq!(db.direct_in_use_count(), 0);
}

#[test]
fn direct_flush_splits_oversize_chunk_into_capped_deferred_frames() {
    // A chunk larger than the negotiated cap must split into multiple frames,
    // each within the cap, all but the last deferred so the whole chunk still
    // commits at a single boundary, and with every row sent exactly once.
    const CAP: usize = 2048;
    const ROWS: usize = 512;
    const FLAG_DEFER_COMMIT: u8 = 0x01;

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let conf = conf_for(
        server.port(),
        &format!("max_buf_size={CAP};pool_reap=manual;"),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let qty: Vec<i64> = (0..ROWS as i64).collect();
    let ts: Vec<i64> = (0..ROWS as i64)
        .map(|x| 1_700_000_000_000_000_000 + x)
        .collect();
    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();

    {
        let mut sender = db.borrow_direct_column_sender().unwrap();
        sender
            .flush_and_wait(&mut chunk, AckLevel::Ok)
            .expect("oversize chunk splits, sends, and commits");
    }

    // flush_and_wait has returned, so every frame is already on the channel.
    let mut captured = Vec::new();
    while let Ok(frame) = frames.recv_timeout(Duration::from_millis(500)) {
        captured.push(frame);
    }

    assert!(
        captured.len() > 1,
        "oversize chunk must split into multiple frames, got {}",
        captured.len()
    );
    for (i, frame) in captured.iter().enumerate() {
        assert!(
            frame.len() <= CAP,
            "frame {i} is {} bytes, exceeds cap {CAP}",
            frame.len()
        );
        let deferred = frame[5] & FLAG_DEFER_COMMIT != 0;
        if i + 1 < captured.len() {
            assert!(deferred, "frame {i} (not the last) must be deferred");
        } else {
            assert!(!deferred, "the last frame must carry the commit boundary");
        }
    }
    let total: u64 = captured.iter().map(|f| frame_row_count(f)).sum();
    assert_eq!(
        total, ROWS as u64,
        "split frames must cover every row exactly once"
    );
}

#[test]
fn direct_flush_split_floor_marks_must_close_to_discard_uncommitted_prefix() {
    // A chunk whose small-row prefix fits but whose final row is irreducibly
    // larger than the cap: splitting publishes the prefix as deferred frames,
    // then the floor fails with batch_too_large. The connection must be marked
    // must_close so the drop-time best-effort commit discards the uncommitted
    // prefix rather than committing a partial chunk.
    const CAP: usize = 2048;
    const PREFIX_ROWS: usize = 200;
    let server = MockServer::spawn_acking(1);
    let conf = conf_for(
        server.port(),
        &format!("max_buf_size={CAP};pool_reap=manual;"),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let big = "x".repeat(CAP * 2);
    let mut offsets = vec![0i32];
    let mut bytes = Vec::new();
    for _ in 0..PREFIX_ROWS {
        bytes.push(b's');
        offsets.push(bytes.len() as i32);
    }
    bytes.extend_from_slice(big.as_bytes());
    offsets.push(bytes.len() as i32);
    let ts: Vec<i64> = (0..=PREFIX_ROWS as i64).collect();

    let mut chunk = Chunk::new("trades");
    chunk.column_str("v", &offsets, &bytes, None).unwrap();
    chunk.at_nanos(&ts).unwrap();

    let mut sender = db.borrow_direct_column_sender().unwrap();
    let err = sender
        .flush(&mut chunk)
        .expect_err("the irreducible final row must fail the flush");
    assert_eq!(err.code(), ErrorCode::BatchTooLarge);
    assert!(
        sender.must_close_for_test(),
        "connection must be torn down so the uncommitted deferred prefix is \
         discarded instead of committed on drop"
    );
}

#[test]
fn store_and_forward_flush_splits_oversize_chunk_into_self_sufficient_frames() {
    // The store-and-forward backend also splits an oversize chunk, but into
    // independently-committed self-sufficient frames — never deferred ones,
    // which the frame-granular replay queue could drop on a reconnect that
    // trims them after their ack but before a commit boundary.
    const CAP: usize = 2048;
    const ROWS: usize = 512;
    const FLAG_DEFER_COMMIT: u8 = 0x01;

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "max_buf_size={CAP};sf_dir={};pool_reap=manual;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let qty: Vec<i64> = (0..ROWS as i64).collect();
    let ts: Vec<i64> = (0..ROWS as i64)
        .map(|x| 1_700_000_000_000_000_000 + x)
        .collect();
    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();

    let mut sender = db.borrow_sender().unwrap();
    let fsn = sender
        .flush_and_get_fsn(&mut chunk)
        .expect("oversize chunk splits and appends")
        .expect("non-empty chunk publishes a frame");
    assert_eq!(sender.published_fsn().unwrap(), Some(fsn));
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("all split frames commit");
    assert!(
        sender
            .acked_fsn()
            .unwrap()
            .is_some_and(|acked| acked >= fsn),
        "acked watermark must cover returned split boundary"
    );

    let mut captured = Vec::new();
    while let Ok(frame) = frames.recv_timeout(Duration::from_millis(500)) {
        captured.push(frame);
    }

    assert!(
        captured.len() > 1,
        "oversize chunk must split into multiple frames, got {}",
        captured.len()
    );
    assert_eq!(
        fsn as usize,
        captured.len() - 1,
        "returned FSN must be the last split frame boundary"
    );
    for (i, frame) in captured.iter().enumerate() {
        assert!(
            frame.len() <= CAP,
            "frame {i} is {} bytes, exceeds cap {CAP}",
            frame.len()
        );
        assert_eq!(
            frame[5] & FLAG_DEFER_COMMIT,
            0,
            "store-and-forward frame {i} must be self-sufficient, not deferred"
        );
    }
    let total: u64 = captured.iter().map(|f| frame_row_count(f)).sum();
    assert_eq!(
        total, ROWS as u64,
        "split frames must cover every row exactly once"
    );
}

#[test]
fn store_and_forward_split_valve_engages_at_segment_cap_not_max_buf_size() {
    // Regression: the split valve compared against max_buf_size (100 MiB
    // default) while the store-and-forward queue rejects any frame above the
    // sf_max_segment_bytes-derived segment payload capacity. A flush between the two
    // caps hard-failed with PayloadExceedsByteCapacity instead of splitting.
    // max_buf_size is deliberately left at its default so the segment cap is
    // the binding limit.
    const SEGMENT: usize = 2048;
    // Segment payload capacity: SEGMENT minus the 24-byte segment header and
    // one 8-byte frame header; the split target halves the remainder after a
    // second frame header so two frames pack per segment.
    const SPLIT_TARGET: usize = (SEGMENT - 32 - 8) / 2;
    const ROWS: usize = 512;

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let conf = conf_for(
        server.port(),
        &format!("sf_max_segment_bytes={SEGMENT};pool_reap=manual;"),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let qty: Vec<i64> = (0..ROWS as i64).collect();
    let ts: Vec<i64> = (0..ROWS as i64)
        .map(|x| 1_700_000_000_000_000_000 + x)
        .collect();
    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();

    let mut sender = db.borrow_sender().unwrap();
    let fsn = sender
        .flush_and_get_fsn(&mut chunk)
        .expect("a flush above the segment cap must split, not hard-fail")
        .expect("non-empty chunk publishes a frame");
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("all split frames commit");

    let mut captured = Vec::new();
    while let Ok(frame) = frames.recv_timeout(Duration::from_millis(500)) {
        captured.push(frame);
    }
    assert!(
        captured.len() > 1,
        "flush above the segment cap must split into multiple frames, got {}",
        captured.len()
    );
    assert_eq!(
        fsn as usize,
        captured.len() - 1,
        "returned FSN must be the last split frame boundary"
    );
    for (i, frame) in captured.iter().enumerate() {
        assert!(
            frame.len() <= SPLIT_TARGET,
            "frame {i} is {} bytes; split frames must pack two per segment \
             (<= {SPLIT_TARGET} bytes)",
            frame.len()
        );
    }
    let total: u64 = captured.iter().map(|f| frame_row_count(f)).sum();
    assert_eq!(
        total, ROWS as u64,
        "split frames must cover every row exactly once"
    );
}

#[test]
fn store_and_forward_irreducible_frame_over_segment_cap_is_batch_too_large() {
    // At the split floor the hard cap (the segment payload capacity here)
    // decides: an irreducible single-row frame above it must surface a clean
    // BatchTooLarge naming the per-frame cap. Before the fix it sailed past
    // the max_buf_size-only check and died on the queue's internal
    // PayloadExceedsByteCapacity rejection instead.
    const SEGMENT: usize = 2048;
    let server = MockServer::spawn_acking(1);
    let conf = conf_for(
        server.port(),
        &format!("sf_max_segment_bytes={SEGMENT};pool_reap=manual;"),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let big = "x".repeat(SEGMENT * 2);
    let offsets = [0i32, big.len() as i32];
    let ts = [1_700_000_000_000_000_000i64];
    let mut chunk = Chunk::new("trades");
    chunk
        .column_str("v", &offsets, big.as_bytes(), None)
        .unwrap();
    chunk.at_nanos(&ts).unwrap();

    let mut sender = db.borrow_sender().unwrap();
    let err = sender
        .flush_and_get_fsn(&mut chunk)
        .expect_err("an irreducible over-cap row must fail the flush");
    assert_eq!(err.code(), ErrorCode::BatchTooLarge);
    assert!(
        err.msg().contains("per-frame cap"),
        "size error must name the binding per-frame cap, got: {}",
        err.msg()
    );
    assert_eq!(
        sender.published_fsn().unwrap(),
        None,
        "nothing may be queued for a rejected irreducible frame"
    );
}

fn check_store_and_forward_drop_on_return_drops_backend_and_reopens_on_next_borrow(extras: &str) {
    let server = MockServer::spawn(4);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();

    {
        let mut sender = db.borrow_sender().unwrap();
        assert!(
            wait_until(Duration::from_secs(2), || server.accepted() == 1),
            "first SFA borrow should start its background connection; accepted={}",
            server.accepted()
        );
        sender.drop_on_return();
        assert!(sender.must_close_for_test());
    }

    assert_eq!(db.free_count(), 0, "forced SFA backend must not recycle");
    assert_eq!(db.in_use_count(), 0);

    let _again = db
        .borrow_sender()
        .expect("next borrow should reopen the SFA slot");
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 2),
        "SFA force-drop should reopen on next borrow; accepted={}",
        server.accepted()
    );
}

fn check_store_and_forward_append_timeout_rolls_back_symbols_and_keeps_chunk(extras: &str) {
    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(1);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let ts1 = [1_i64];
    let mut first = Chunk::new("trades");
    append_one_symbol_row(&mut first, b"alpha", &ts1);
    sender.flush(&mut first).unwrap();
    assert!(
        first.is_empty(),
        "successful SFA flush should clear the chunk"
    );
    let first_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(
        read_symbol_prefix(&first_payload),
        (0, vec![b"alpha".to_vec()])
    );

    let ts2 = [2_i64];
    let mut failed = Chunk::new("trades");
    append_one_symbol_row(&mut failed, b"bravo", &ts2);
    let err = sender
        .flush(&mut failed)
        .expect_err("second publish should time out behind max_in_flight=1");
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert!(
        err.msg()
            .contains("timed out waiting for local queue capacity"),
        "msg: {}",
        err.msg()
    );
    assert!(
        !failed.is_empty(),
        "definitely-not-appended SFA failure must keep the chunk retryable"
    );

    release_acks.store(true, Ordering::SeqCst);
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();

    let ts3 = [3_i64];
    let mut third = Chunk::new("trades");
    append_one_symbol_row(&mut third, b"gamma", &ts3);
    sender.flush(&mut third).unwrap();
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();
    let third_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    // Both storage modes delta-encode: the rolled-back "bravo" must leave no
    // residue, so the third frame resumes from the watermark and ships only
    // "gamma" at delta_start == 1 (bravo's would-be slot), not id 2. In file mode
    // the dictionary rollback also truncated "bravo" from the persisted side-file,
    // keeping it an exact mirror of the reused-id dictionary.
    assert_eq!(
        read_symbol_prefix(&third_payload),
        (1, vec![b"gamma".to_vec()]),
        "failed bravo publish must not remain in the replay symbol dictionary"
    );
}

fn check_store_and_forward_flush_and_wait_waits_for_ok_boundary(extras: &str) {
    let server = MockServer::spawn_acking(1);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();
    sender
        .flush_and_wait(&mut chunk, AckLevel::Ok)
        .expect("SFA ACKing flush must wait for the local boundary to reach OK");
    assert!(
        chunk.is_empty(),
        "successful SFA ACKing flush clears the chunk"
    );

    // A trailing sync on the satisfied boundary is a cheap re-check (the
    // watermark cache was written back by the ACKing flush).
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("trailing sync on the satisfied boundary must succeed");
}

#[test]
fn store_and_forward_flush_and_wait_durable_without_opt_in_keeps_chunk() {
    let server = MockServer::spawn(1);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!("sf_dir={};pool_reap=manual;", dir.path().display()),
    );
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();
    // Durable is validated before encode/append, so the chunk is never
    // published and stays replayable.
    let err = sender
        .flush_and_wait(&mut chunk, AckLevel::Durable)
        .expect_err("durable without opt-in must be rejected up front");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg().contains("request_durable_ack"),
        "msg: {}",
        err.msg()
    );
    assert!(
        !chunk.is_empty(),
        "pre-append rejection must leave the chunk replayable"
    );
}

fn check_store_and_forward_flush_and_wait_timeout_after_append_clears_chunk(extras: &str) {
    // Park mode finishes the upgrade and drains frames but never acks. The
    // local append succeeds (the frame is queued and replayable), then the
    // boundary wait times out: a `FailoverRetry` whose delivery is unknown.
    let server = MockServer::spawn(1);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();
    sender
        .flush(&mut chunk)
        .expect("publish to the local SFA queue");
    let err = sender
        .wait(AckLevel::Ok, Duration::from_millis(150))
        .expect_err("silent-but-alive peer must time out the boundary wait");
    assert_eq!(err.code(), ErrorCode::FailoverRetry, "{}", err.msg());
    assert!(
        err.msg().contains("timed out") && err.msg().contains("no ack progress"),
        "unexpected timeout message: {}",
        err.msg()
    );
    assert!(
        chunk.is_empty(),
        "the frame was appended to the local queue, so the chunk is cleared"
    );
}

fn check_store_and_forward_flush_and_wait_surfaces_server_rejection(extras: &str) {
    let server = MockServer::spawn_erroring(1, QWP_STATUS_SCHEMA_MISMATCH);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.at_nanos(&ts).unwrap();
    let err = sender
        .flush_and_wait(&mut chunk, AckLevel::Ok)
        .expect_err("server rejection inside the waited range must surface");
    assert_eq!(err.code(), ErrorCode::ServerRejection);
    assert_eq!(
        err.qwp_ws_rejection().and_then(|error| error.status),
        Some(QWP_STATUS_SCHEMA_MISMATCH)
    );
}

fn check_store_and_forward_flush_and_wait_durable_succeeds_with_opt_in(extras: &str) {
    // With `request_durable_ack=on` and a server that confirms durability, an
    // `AckLevel::Durable` ACKing flush commits and clears the chunk (the
    // success counterpart to the durable opt-in *guard* tests).
    let (server, _frames) = MockServer::spawn_acking_durable_capturing(2);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();
    assert!(sender.is_store_and_forward());
    // Bound the no-progress wait so a protocol regression fails fast instead of
    // blocking on the 30s request timeout.

    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &[7_i64], None).unwrap();
    chunk.at_nanos(&[1_i64]).unwrap();
    sender
        .flush(&mut chunk)
        .expect("publish to the local SFA queue");
    sender
        .wait(AckLevel::Durable, Duration::from_secs(5))
        .expect("durable wait must commit once the durable ACK arrives");
    assert!(
        chunk.is_empty(),
        "a committed durable ACKing flush clears the chunk"
    );
}

#[test]
fn store_and_forward_flush_and_wait_durable_succeeds_with_opt_in_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_flush_and_wait_durable_succeeds_with_opt_in(&sf_disk_extras(
        &dir,
        "pool_reap=manual;request_durable_ack=on;durable_ack_keepalive_interval_millis=1;",
    ));
}
#[test]
fn store_and_forward_flush_and_wait_durable_succeeds_with_opt_in_memory() {
    check_store_and_forward_flush_and_wait_durable_succeeds_with_opt_in(
        "pool_reap=manual;request_durable_ack=on;durable_ack_keepalive_interval_millis=1;",
    );
}

#[test]
fn store_and_forward_runner_reconnects_and_replays_after_transport_death() {
    // The in-memory SF background runner owns reconnects: when the first
    // endpoint dies mid-stream, the runner rotates to a live endpoint and
    // replays its queue, so the row lands without the caller re-driving from
    // source. The caller only retries `sync` (which surfaces `FailoverRetry`
    // until the runner has caught up).
    let dead = MockServer::spawn_upgrade_then_close(1);
    let (live, frames) = MockServer::spawn_acking_capturing(4);
    // No `sf_dir` -> in-memory SF; a longer reconnect budget so the runner can
    // rotate to the live endpoint.
    let conf = format!(
        "ws::addr=127.0.0.1:{},127.0.0.1:{};auth_timeout=2000;\
         reconnect_max_duration_millis=10000;pool_reap=manual;",
        dead.port(),
        live.port()
    );
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    assert!(sender.is_store_and_forward());

    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &[7_i64], None).unwrap();
    chunk.at_nanos(&[1_i64]).unwrap();
    sender.flush(&mut chunk).unwrap();

    // Retry `sync` until the runner has reconnected to the live endpoint and
    // the OK boundary advances (bounded so a stuck runner fails rather than
    // hangs).
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match sender.wait(AckLevel::Ok, Duration::from_secs(30)) {
            Ok(()) => break,
            Err(e) if e.code() == ErrorCode::FailoverRetry && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("sync did not recover after reconnect: {}", e.msg()),
        }
    }

    // `sync` returned OK, so the live endpoint acked the replayed frame: the
    // runner reconnected and re-sent the queued row there (not the dead peer).
    let replayed: Vec<Vec<u8>> = frames.try_iter().collect();
    assert!(
        !replayed.is_empty(),
        "the live endpoint must receive the replayed data frame after reconnect"
    );
    assert_eq!(
        live.accepted(),
        1,
        "the runner must reconnect to the live endpoint exactly once"
    );
}

// Each `check_store_and_forward_*` behaviour above runs on both backends that
// `borrow_sender` uses: disk-backed SF (`sf_dir` set, pool-minted slot
// dirs) and in-memory SF (no `sf_dir`). The body is backend-agnostic; only the
// conf differs. The `_dir` `TempDir` outlives each `check_*` call because the
// call opens and drops its `QuestDb` before the wrapper returns.
fn sf_disk_extras(dir: &TempDir, extra: &str) -> String {
    format!("sf_dir={};{extra}", dir.path().display())
}

#[test]
fn store_and_forward_sync_reports_terminal_schema_rejection_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_sync_reports_terminal_schema_rejection(&sf_disk_extras(
        &dir,
        "pool_reap=manual;",
    ));
}
#[test]
fn store_and_forward_sync_reports_terminal_schema_rejection_memory() {
    check_store_and_forward_sync_reports_terminal_schema_rejection("pool_reap=manual;");
}

#[test]
fn store_and_forward_sync_times_out_on_silent_but_alive_peer_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_sync_times_out_on_silent_but_alive_peer(&sf_disk_extras(
        &dir,
        "pool_reap=manual;",
    ));
}
#[test]
fn store_and_forward_sync_times_out_on_silent_but_alive_peer_memory() {
    check_store_and_forward_sync_times_out_on_silent_but_alive_peer("pool_reap=manual;");
}

#[test]
fn store_and_forward_drop_on_return_drops_backend_and_reopens_on_next_borrow_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_drop_on_return_drops_backend_and_reopens_on_next_borrow(
        &sf_disk_extras(&dir, "pool_reap=manual;"),
    );
}
#[test]
fn store_and_forward_drop_on_return_drops_backend_and_reopens_on_next_borrow_memory() {
    check_store_and_forward_drop_on_return_drops_backend_and_reopens_on_next_borrow(
        "pool_reap=manual;",
    );
}

#[test]
fn store_and_forward_append_timeout_rolls_back_symbols_and_keeps_chunk_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_append_timeout_rolls_back_symbols_and_keeps_chunk(&sf_disk_extras(
        &dir,
        "pool_reap=manual;max_in_flight=1;sf_append_deadline_millis=25;",
    ));
}
#[test]
fn store_and_forward_append_timeout_rolls_back_symbols_and_keeps_chunk_memory() {
    check_store_and_forward_append_timeout_rolls_back_symbols_and_keeps_chunk(
        "pool_reap=manual;max_in_flight=1;sf_append_deadline_millis=25;",
    );
}

#[test]
fn store_and_forward_file_mode_writes_symbols_ahead_to_side_file() {
    // File-mode SF delta-encodes, so each frame's new symbols are written ahead to
    // the slot's `.symbol-dict` side-file *before* the frame is published -- that
    // file is how a fresh process rebuilds the dictionary the stored delta frames
    // reference. Drive two frames introducing "alpha" then "bravo" and assert the
    // side-file mirrors them in id order. The peer never acks, so the frames stay
    // in the slot and the side-file is not removed by a drained close.
    let (server, _release, _frames) = MockServer::spawn_ack_when_released_capturing(1);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &sf_disk_extras(&dir, "pool_reap=manual;sender_id=recov;"),
    );
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let mut first = Chunk::new("trades");
    append_one_symbol_row(&mut first, b"alpha", &[1_i64]);
    sender.flush(&mut first).unwrap();
    let mut second = Chunk::new("trades");
    append_one_symbol_row(&mut second, b"bravo", &[2_i64]);
    sender.flush(&mut second).unwrap();

    // The write-ahead persisted both symbols, in ascending id order, each in its
    // own CRC-committed record. Assert format-agnostically (each record's payload
    // carries the `[len]"symbol"` entry) that both are present and alpha precedes
    // bravo, rather than hardcoding the framing/CRC bytes. The pool mints a
    // managed slot per borrowed sender, so the first one lives under
    // `<sender_id>-ingest-0`, not the bare `sender_id`.
    let side_file = dir.path().join("recov-ingest-0").join(".symbol-dict");
    let bytes = std::fs::read(&side_file).expect("side-file must exist after file-mode flushes");
    let alpha_pos = bytes
        .windows(6)
        .position(|w| w == b"\x05alpha")
        .expect("alpha persisted");
    let bravo_pos = bytes
        .windows(6)
        .position(|w| w == b"\x05bravo")
        .expect("bravo persisted");
    assert!(
        alpha_pos < bravo_pos,
        "write-ahead must persist both symbols in id order"
    );
}

#[test]
fn store_and_forward_file_mode_recovers_and_replays_queued_frame_after_reopen() {
    // Recoverability round-trip for the disk-backed unified sender: a symbol frame
    // flushed to a file-mode slot but left unacked must survive the sender/db being
    // dropped (a process restart) and be replayed + delivered when a FRESH QuestDb
    // reopens the same slot -- proving the queued data (and its persisted
    // dictionary) is recovered from disk, not abandoned. Complements
    // store_and_forward_file_mode_writes_symbols_ahead_to_side_file, which asserts
    // only that the side-file bytes are written, never that they are recovered.
    let dir = TempDir::new().unwrap();

    // Phase 1: queue a symbol frame to the slot against a peer that never acks,
    // then drop everything so only the on-disk slot survives.
    {
        let dead = MockServer::spawn_upgrade_then_close(1);
        let conf = conf_for_endpoints(
            &[dead.port()],
            &sf_disk_extras(&dir, "pool_reap=manual;sender_id=recov;"),
        );
        let db = QuestDb::connect(&conf).unwrap();
        let mut sender = db.borrow_sender().unwrap();
        let mut chunk = Chunk::new("trades");
        append_one_symbol_row(&mut chunk, b"alpha", &[1_i64]);
        sender.flush(&mut chunk).unwrap();
        drop(sender);
        drop(db);
    }

    // Phase 2: a fresh acking peer + a fresh QuestDb over the SAME slot dir and
    // sender_id. The recovered slot replays its queued frame there autonomously
    // (background runner), re-registering the recovered dictionary via a catch-up
    // first. (No port reuse: the on-disk slot, not the address, carries the data.)
    let (live, frames) = MockServer::spawn_acking_capturing(4);
    let conf = conf_for_endpoints(
        &[live.port()],
        &sf_disk_extras(&dir, "pool_reap=manual;sender_id=recov;"),
    );
    let db = QuestDb::connect(&conf).unwrap();
    let _sender = db.borrow_sender().unwrap();

    // Count replayed DATA frames (table_count >= 1 at bytes 6..8); the table-less
    // catch-up frame that precedes them carries table_count == 0.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut data_frames = 0usize;
    while Instant::now() < deadline && data_frames == 0 {
        data_frames += frames
            .try_iter()
            .filter(|f| {
                f.len() >= 12 && &f[..4] == b"QWP1" && u16::from_le_bytes([f[6], f[7]]) >= 1
            })
            .count();
        thread::sleep(Duration::from_millis(50));
    }
    assert!(
        data_frames >= 1,
        "the reopened slot must replay the queued data frame to the fresh peer"
    );
    assert_eq!(
        live.accepted(),
        1,
        "recovery must connect to the fresh peer and replay exactly once"
    );
}

#[test]
fn store_and_forward_file_mode_value_corruption_is_healed_and_segment_kept() {
    // Issue-4 end-to-end: a same-length VALUE corruption in the persisted
    // `.symbol-dict` -- a host/power-crash bit-flip that keeps an entry's length
    // but changes a symbol byte -- must be caught by the per-entry CRC on
    // recovery and NOT silently recovered as the wrong symbol. The CRC-failed
    // entry is dropped (healed) at open, so the corrupt symbol never reaches the
    // dictionary, and the queued segment stays on disk (recoverable). (A recovered
    // mid-stream delta that DEPENDS on a dropped id then fails loudly at the send
    // loop's torn-dict guard -- `StoreResendRequired` -- covered by the driver- and
    // dict-level unit tests.)
    use crate::ingress::sender::qwp_ws_sfa_symbol_dict::PersistedSymbolDict;

    let dir = TempDir::new().unwrap();

    // Phase 1: queue a symbol frame to a file-mode slot (the write-ahead persists
    // the dictionary), then drop so only the on-disk slot survives.
    {
        let dead = MockServer::spawn_upgrade_then_close(1);
        let conf = conf_for_endpoints(
            &[dead.port()],
            &sf_disk_extras(&dir, "pool_reap=manual;sender_id=recov;"),
        );
        let db = QuestDb::connect(&conf).unwrap();
        let mut sender = db.borrow_sender().unwrap();
        let mut chunk = Chunk::new("trades");
        append_one_symbol_row(&mut chunk, b"alpha", &[1_i64]);
        sender.flush(&mut chunk).unwrap();
        drop(sender);
        drop(db);
    }

    // A host/power crash flips a byte of the persisted symbol, keeping its length.
    // The pool mints a managed slot per borrowed sender, so the first
    // one lives under `<sender_id>-ingest-0`, not the bare `sender_id`.
    let slot_dir = dir.path().join("recov-ingest-0");
    let side_file = slot_dir.join(".symbol-dict");
    {
        let mut bytes =
            std::fs::read(&side_file).expect("phase 1 must have written a delta-mode side-file");
        let idx = bytes
            .windows(5)
            .position(|w| w == b"alpha")
            .expect("alpha payload present");
        bytes[idx] = b'X'; // same length ("Xlpha"), different value
        std::fs::write(&side_file, &bytes).unwrap();
    }

    // Recovery: the entry's CRC now fails, so `open` heals it -- the corrupt
    // symbol is NOT recovered (the recovered dictionary is empty, never "Xlpha").
    let recovered = PersistedSymbolDict::open(&slot_dir).unwrap();
    assert!(
        recovered.read_loaded_symbols().is_empty(),
        "a CRC-failed record must be dropped on recovery, never recovered as the \
         corrupted symbol; got {:?}",
        recovered.read_loaded_symbols()
    );

    // The queued frame's segment must stay on disk (recoverable), never deleted by
    // the corrupt-dict recovery.
    let segment_survives = std::fs::read_dir(&slot_dir)
        .unwrap()
        .filter_map(Result::ok)
        .any(|e| e.path().extension().is_some_and(|ext| ext == "sfa"));
    assert!(
        segment_survives,
        "the queued frame's segment must survive corrupt-dict recovery (recoverable)"
    );
}

#[test]
fn store_and_forward_file_mode_recovers_a_mid_stream_delta_frame() {
    // The entire point of the persisted side-file + catch-up: a NON-self-sufficient
    // stored frame (`delta_start > 0`) becomes recoverable across a process
    // restart. Phase 1 flushes two distinct symbols to a file-mode slot, so the
    // second frame is a mid-stream delta (`delta_start = 1`) that references a
    // symbol registered by the first frame. Both are left unacked. Phase 2 reopens
    // the slot against a fresh server that never saw the dictionary: recovery must
    // re-register the whole dictionary (alpha, bravo) via a table-less catch-up,
    // then replay BOTH data frames -- including the mid-stream delta -- so the
    // fresh server can resolve its ids. Complements the reconnect-level catch-up
    // test and the `delta_start = 0` recovery test, neither of which exercises a
    // recovered `delta_start > 0` frame end-to-end.
    let dir = TempDir::new().unwrap();

    // Phase 1: alpha (id 0) then bravo (id 1 -> the second frame bases at 1), both
    // unacked, then drop so only the on-disk slot survives.
    {
        let dead = MockServer::spawn_upgrade_then_close(1);
        let conf = conf_for_endpoints(
            &[dead.port()],
            &sf_disk_extras(&dir, "pool_reap=manual;sender_id=recov;"),
        );
        let db = QuestDb::connect(&conf).unwrap();
        let mut sender = db.borrow_sender().unwrap();
        let mut first = Chunk::new("trades");
        append_one_symbol_row(&mut first, b"alpha", &[1_i64]);
        sender.flush(&mut first).unwrap();
        let mut second = Chunk::new("trades");
        append_one_symbol_row(&mut second, b"bravo", &[2_i64]);
        sender.flush(&mut second).unwrap();
        drop(sender);
        drop(db);
    }

    // Phase 2: fresh acking server + fresh QuestDb over the SAME slot. It replays
    // autonomously (background runner): a table-less catch-up (table_count 0) then
    // the two data frames (table_count >= 1).
    let (live, frames) = MockServer::spawn_acking_capturing(8);
    let conf = conf_for_endpoints(
        &[live.port()],
        &sf_disk_extras(&dir, "pool_reap=manual;sender_id=recov;"),
    );
    let db = QuestDb::connect(&conf).unwrap();
    let _sender = db.borrow_sender().unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut captured: Vec<Vec<u8>> = Vec::new();
    while Instant::now() < deadline {
        captured.extend(frames.try_iter());
        let data_seen = captured
            .iter()
            .filter(|f| {
                f.len() >= 12 && &f[..4] == b"QWP1" && u16::from_le_bytes([f[6], f[7]]) >= 1
            })
            .count();
        if data_seen >= 2 {
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }

    let qwp: Vec<&Vec<u8>> = captured
        .iter()
        .filter(|f| f.len() >= 12 && &f[..4] == b"QWP1")
        .collect();
    let catch_ups: Vec<&Vec<u8>> = qwp
        .iter()
        .copied()
        .filter(|f| u16::from_le_bytes([f[6], f[7]]) == 0)
        .collect();
    let data_frames: Vec<&Vec<u8>> = qwp
        .iter()
        .copied()
        .filter(|f| u16::from_le_bytes([f[6], f[7]]) >= 1)
        .collect();

    // The recovered slot re-registers the whole dictionary from id 0 before replay.
    let catch_up = catch_ups
        .first()
        .expect("recovery must re-register the dictionary via a table-less catch-up first");
    let (cu_start, cu_syms) = parse_delta_dict_prefix(catch_up);
    assert_eq!(cu_start, 0, "catch-up re-registers from id 0");
    assert_eq!(
        cu_syms,
        vec![b"alpha".to_vec(), b"bravo".to_vec()],
        "catch-up re-registers the whole recovered dictionary in id order"
    );

    assert_eq!(
        data_frames.len(),
        2,
        "both queued frames replay after recovery"
    );
    // The second data frame is a recovered MID-STREAM delta: it bases at id 1
    // (above 0, so it is NOT self-sufficient -- it relies on the catch-up having
    // re-registered the id-0 prefix) and ships only its own new symbol. Proving a
    // `delta_start > 0` frame survived the restart and replays correctly is the
    // whole point of the persisted dictionary + catch-up.
    let (start2, syms2) = parse_delta_dict_prefix(data_frames[1]);
    assert_eq!(
        start2, 1,
        "the recovered second frame is a mid-stream delta (bases above id 0)"
    );
    assert_eq!(
        syms2,
        vec![b"bravo".to_vec()],
        "the mid-stream frame ships its own new symbol (bravo, id 1)"
    );
    assert_eq!(
        live.accepted(),
        1,
        "recovery connects to the fresh peer and replays exactly once"
    );
}

#[test]
fn store_and_forward_flush_and_wait_waits_for_ok_boundary_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_flush_and_wait_waits_for_ok_boundary(&sf_disk_extras(
        &dir,
        "pool_reap=manual;",
    ));
}
#[test]
fn store_and_forward_flush_and_wait_waits_for_ok_boundary_memory() {
    check_store_and_forward_flush_and_wait_waits_for_ok_boundary("pool_reap=manual;");
}

#[test]
fn store_and_forward_flush_and_wait_timeout_after_append_clears_chunk_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_flush_and_wait_timeout_after_append_clears_chunk(&sf_disk_extras(
        &dir,
        "pool_reap=manual;",
    ));
}
#[test]
fn store_and_forward_flush_and_wait_timeout_after_append_clears_chunk_memory() {
    check_store_and_forward_flush_and_wait_timeout_after_append_clears_chunk("pool_reap=manual;");
}

#[test]
fn store_and_forward_flush_and_wait_surfaces_server_rejection_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_flush_and_wait_surfaces_server_rejection(&sf_disk_extras(
        &dir,
        "pool_reap=manual;",
    ));
}
#[test]
fn store_and_forward_flush_and_wait_surfaces_server_rejection_memory() {
    check_store_and_forward_flush_and_wait_surfaces_server_rejection("pool_reap=manual;");
}

#[test]
fn pool_is_lazy_and_opens_on_first_borrow() {
    let server = MockServer::spawn(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=3;sender_pool_max=4;",
    ))
    .unwrap();
    // Lazy pool, like the row-major sender: `connect` opens nothing.
    assert_eq!(db.free_count(), 0);
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(server.accepted(), 0);
    // The first borrow opens exactly one connection.
    let _b = db.borrow_sender().expect("borrow");
    assert_eq!(db.in_use_count(), 1);
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 1),
        "first borrow opens one connection; accepted={}",
        server.accepted()
    );
}

#[test]
fn borrow_sender_is_in_memory_store_and_forward_without_sf_dir() {
    // Without `sf_dir`, `borrow_sender` yields an in-memory
    // store-and-forward sender (mirroring the row-major sender). It pools
    // freely up to `pool_max`, just like disk-backed SF with per-borrower
    // slots.
    let server = MockServer::spawn(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;acquire_timeout_ms=0;",
    ))
    .unwrap();

    let b1 = db.borrow_sender().expect("b1");
    assert!(
        b1.is_store_and_forward(),
        "borrow_sender must be store-and-forward even without sf_dir"
    );

    // In-memory SF pools freely: concurrent borrows succeed up to `pool_max`.
    let b2 = db.borrow_sender().expect("b2 (in-memory SF pools freely)");
    let b3 = db.borrow_sender().expect("b3 (in-memory SF pools freely)");
    assert!(b2.is_store_and_forward());
    assert!(b3.is_store_and_forward());
    assert_eq!(db.in_use_count(), 3);

    // Each in-memory SF borrower has its own connection + background runner.
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 3),
        "each in-memory SF borrow opens its own connection; accepted={}",
        server.accepted()
    );

    // At the cap, the next borrow fails fast like any pooled resource.
    let err = db.borrow_sender().expect_err("must fail-fast at pool_max");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());
}

#[test]
fn borrow_and_return_reuses_connection() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();
    // Lazy pool: nothing open until the first borrow.
    assert_eq!(db.free_count(), 0);
    {
        let _borrow = db.borrow_sender().expect("borrow");
        assert_eq!(db.free_count(), 0);
        assert_eq!(db.in_use_count(), 1);
        assert!(
            wait_until(Duration::from_secs(2), || server.accepted() == 1),
            "first borrow should start one background connection; accepted={}",
            server.accepted()
        );
    }
    // Drop returns the sender to the pool.
    assert_eq!(db.free_count(), 1);
    assert_eq!(db.in_use_count(), 0);
    // Re-borrow reuses it — the server only ever accepted one connection.
    let _again = db.borrow_sender().expect("reuse");
    assert_eq!(server.accepted(), 1);
}

#[cfg(feature = "ffi-support")]
#[test]
fn owned_sender_observes_pool_close_and_drops_after_close() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;close_flush_timeout_millis=50;",
    ))
    .unwrap();
    let owned = db.borrow_sender_owned().expect("borrow owned sender");
    assert_eq!(db.free_count(), 0);
    assert_eq!(db.in_use_count(), 1);
    assert!(!owned.pool_closed());

    db.close();
    assert!(owned.pool_closed());
    drop(owned);
}

#[test]
fn auto_grow_opens_new_connection_until_pool_max() {
    let server = MockServer::spawn(4);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;",
    ))
    .unwrap();
    let b1 = db.borrow_sender().expect("b1");
    let b2 = db.borrow_sender().expect("b2 (auto-grow)");
    let b3 = db.borrow_sender().expect("b3 (auto-grow)");
    assert_eq!(db.free_count(), 0);
    assert_eq!(db.in_use_count(), 3);
    wait_until(Duration::from_secs(2), || server.accepted() == 3);
    drop(b1);
    drop(b2);
    drop(b3);
    assert_eq!(db.free_count(), 3);
    drop(db);
}

#[test]
fn fail_fast_at_pool_max() {
    let server = MockServer::spawn(4);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;acquire_timeout_ms=0;",
    ))
    .unwrap();
    let _b1 = db.borrow_sender().expect("b1");
    let _b2 = db.borrow_sender().expect("b2");
    let err = db.borrow_sender().expect_err("must fail-fast at cap");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());
}

// ---------------------------------------------------------------------------
// Direct column-sender pool (`borrow_direct_column_sender`).
//
// A second, always-direct pool that exists independently of `sf_dir`: it is
// lazy (no eager open), never store-and-forward, and poolable up to `pool_max`
// on its own free list, separate from the main `borrow_sender` pool.
// ---------------------------------------------------------------------------

#[test]
fn direct_pool_is_lazy_and_hands_out_direct_senders() {
    let server = MockServer::spawn(4);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=4;",
    ))
    .unwrap();

    // Both pools are lazy: `connect` opens nothing.
    assert_eq!(db.free_count(), 0);
    assert_eq!(db.direct_free_count(), 0);
    assert_eq!(db.direct_in_use_count(), 0);

    {
        let sender = db.borrow_direct_column_sender().expect("borrow direct");
        assert!(
            !sender.is_store_and_forward(),
            "direct pool must never hand out a store-and-forward sender"
        );
        assert_eq!(db.direct_in_use_count(), 1);
        assert_eq!(db.direct_free_count(), 0);
        // A direct borrow leaves the main pool untouched.
        assert_eq!(db.free_count(), 0);
        assert_eq!(db.in_use_count(), 0);
    }

    // Drop recycles the direct sender onto the direct free list.
    assert_eq!(db.direct_in_use_count(), 0);
    assert_eq!(db.direct_free_count(), 1);
    drop(db);
}

#[test]
fn direct_pool_recycles_the_same_connection() {
    let server = MockServer::spawn(4);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=4;",
    ))
    .unwrap();

    {
        let _b = db
            .borrow_direct_column_sender()
            .expect("first direct borrow");
    }
    assert_eq!(db.direct_free_count(), 1);
    let after_first = server.accepted();

    // Re-borrow reuses the recycled connection: no new server accept.
    let _b2 = db
        .borrow_direct_column_sender()
        .expect("reuse recycled direct");
    assert_eq!(db.direct_free_count(), 0);
    assert_eq!(db.direct_in_use_count(), 1);
    assert_eq!(
        server.accepted(),
        after_first,
        "re-borrow must reuse the recycled connection, not open a new one"
    );
}

#[test]
fn direct_pool_auto_grows_and_fails_fast_at_pool_max() {
    let server = MockServer::spawn(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;acquire_timeout_ms=0;",
    ))
    .unwrap();

    let b1 = db.borrow_direct_column_sender().expect("d1");
    let b2 = db.borrow_direct_column_sender().expect("d2 (auto-grow)");
    let b3 = db.borrow_direct_column_sender().expect("d3 (auto-grow)");
    assert_eq!(db.direct_in_use_count(), 3);
    assert_eq!(db.direct_free_count(), 0);

    let err = db
        .borrow_direct_column_sender()
        .expect_err("direct pool must fail-fast at pool_max");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());

    drop(b1);
    drop(b2);
    drop(b3);
    assert_eq!(db.direct_free_count(), 3);
    drop(db);
}

#[test]
fn direct_and_main_pools_are_independent() {
    let server = MockServer::spawn(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let _main = db.borrow_sender().expect("main borrow");
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.direct_in_use_count(), 0);

    let _direct = db.borrow_direct_column_sender().expect("direct borrow");
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.direct_in_use_count(), 1);

    // Each pool enforces `pool_max` on its own free list, so the main pool can
    // still grow to its cap while a direct borrow is outstanding.
    let _main2 = db.borrow_sender().expect("main grows to cap");
    assert_eq!(db.in_use_count(), 2);
    assert_eq!(db.direct_in_use_count(), 1);
}

#[test]
fn direct_pool_is_direct_even_when_sf_dir_is_set() {
    // With `sf_dir` the main pool is disk-backed store-and-forward. The direct
    // pool must still hand out a plain direct sender from its own free list, so
    // direct borrows co-exist with multiple SFA main-pool borrows.
    let server = MockServer::spawn(6);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=directmix;sender_pool_max=2;pool_reap=manual;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let main = db.borrow_sender().expect("main SFA borrow");
    assert!(
        main.is_store_and_forward(),
        "with sf_dir the main pool must be store-and-forward"
    );
    let main2 = db
        .borrow_sender()
        .expect("second main SFA borrow gets its own slot");
    assert!(main2.is_store_and_forward());
    assert_eq!(
        sorted_slot_names(dir.path()),
        vec!["directmix-ingest-0", "directmix-ingest-1"]
    );

    // The direct pool is unaffected: it yields a direct sender concurrently.
    let direct = db
        .borrow_direct_column_sender()
        .expect("direct borrow alongside the SFA borrow");
    assert!(
        !direct.is_store_and_forward(),
        "direct pool must be direct even when sf_dir is set"
    );
    assert_eq!(db.direct_in_use_count(), 1);

    drop(direct);
    drop(main2);
    drop(main);
    drop(db);
}

#[test]
fn direct_pool_reaps_idle_connections() {
    let server = MockServer::spawn(4);
    // Short idle timeout + manual reap so the test drives reaping itself.
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=4;idle_timeout_ms=1;pool_reap=manual;",
    ))
    .unwrap();

    {
        let _b = db.borrow_direct_column_sender().expect("borrow direct");
    }
    assert_eq!(db.direct_free_count(), 1);

    // The direct pool is lazy (no warm-min floor), so an idle entry past the
    // timeout is fully reaped.
    let reaped = wait_until(Duration::from_secs(2), || {
        db.reap_idle();
        db.direct_free_count() == 0
    });
    assert!(reaped, "idle direct sender must be reaped");
    assert_eq!(db.direct_free_count(), 0);
    drop(db);
}

#[test]
fn buffer_sender_pool_borrows_recycles_and_caps() {
    let server = MockServer::spawn_acking(16);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;acquire_timeout_ms=0;",
    ))
    .unwrap();

    // Without disk-SF recovery, nothing exists until the first borrow.
    assert_eq!(db.free_count(), 0);
    assert_eq!(db.in_use_count(), 0);

    {
        let _s1 = db.borrow_sender().expect("borrow sender");
        assert_eq!(db.in_use_count(), 1);
        assert_eq!(db.free_count(), 0);
    } // Drop returns it to the ingestion pool.

    assert_eq!(db.in_use_count(), 0);
    assert_eq!(
        db.free_count(),
        1,
        "a clean sender must be recycled on return"
    );

    // Re-borrow reuses the recycled sender (no new connection).
    let s2 = db.borrow_sender().expect("reuse recycled");
    assert_eq!(db.free_count(), 0);
    assert_eq!(db.in_use_count(), 1);

    // Auto-grow up to the unified ingestion pool's `pool_max`.
    let s3 = db.borrow_sender().expect("grow to pool_max");
    assert_eq!(db.in_use_count(), 2);

    // A third concurrent borrow exceeds sender_pool_max=2 — fail-fast.
    let err = db.borrow_sender().expect_err("must fail-fast at cap");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());

    drop(s2);
    drop(s3);
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(db.free_count(), 2);
    drop(db);
}

#[test]
fn buffer_sender_pool_flush_round_trip() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_sender().expect("borrow sender");
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_f64("price", 2615.54)
        .unwrap()
        .at_now()
        .unwrap();
    let fsn = sender
        .flush_buffer_and_get_fsn(&mut buf)
        .expect("Buffer flush over a pooled QWP/WS sender")
        .expect("non-empty buffer publishes a frame");
    assert_eq!(sender.published_fsn().expect("published fsn"), Some(fsn));
    sender
        .wait(AckLevel::Ok, Duration::from_secs(2))
        .expect("Buffer wait over a pooled QWP/WS sender");
    assert!(
        sender
            .acked_fsn()
            .expect("acked fsn")
            .is_some_and(|v| v >= fsn),
        "acked watermark must cover the published frame"
    );

    let empty = sender.new_buffer();
    assert_eq!(
        sender
            .flush_buffer_and_keep_and_get_fsn(&empty)
            .expect("empty keep flush"),
        None
    );
    sender
        .flush_buffer_and_keep(&empty)
        .expect("empty keep flush");

    drop(sender);

    // The flushed sender is clean, so it returns to the pool for reuse.
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(db.free_count(), 1);
    drop(db);
}

#[test]
fn buffer_sender_flush_and_wait_commits_at_boundary() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_sender().expect("borrow sender");
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_f64("price", 2615.54)
        .unwrap()
        .at_now()
        .unwrap();
    sender
        .flush_buffer_and_wait(&mut buf, AckLevel::Ok)
        .expect("combined Buffer publish+wait over a pooled QWP/WS sender");
    assert!(
        buf.is_empty(),
        "successful flush_and_wait clears the buffer"
    );
    let published = sender
        .published_fsn()
        .expect("published fsn")
        .expect("the buffer published a frame");
    assert!(
        sender
            .acked_fsn()
            .expect("acked fsn")
            .is_some_and(|v| v >= published),
        "flush_and_wait returns only after the ack watermark covers the frame"
    );
}

#[test]
fn buffer_sender_flush_and_wait_durable_without_opt_in_keeps_buffer() {
    let server = MockServer::spawn(1);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_sender().expect("borrow sender");
    let mut buf = sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .column_f64("price", 2615.54)
        .unwrap()
        .at_now()
        .unwrap();
    let err = sender
        .flush_buffer_and_wait(&mut buf, AckLevel::Durable)
        .expect_err("durable without opt-in must be rejected up front");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg().contains("request_durable_ack"),
        "msg: {}",
        err.msg()
    );
    assert!(
        !buf.is_empty(),
        "pre-publish rejection must leave the buffer intact"
    );
}

#[cfg(feature = "ffi-support")]
#[test]
fn buffer_sender_owned_borrow_flushes_and_recycles() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    // The owned handle is the FFI escape hatch backing
    // `questdb_db_borrow_sender`: it carries an `Arc<DbInner>` and
    // returns the sender to the pool on Drop.
    let mut owned = db.borrow_sender_owned().expect("borrow owned sender");
    assert_eq!(db.in_use_count(), 1);
    assert!(!owned.must_close());

    let mut buf = db.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "ETH-USD")
        .unwrap()
        .column_f64("price", 2615.54)
        .unwrap()
        .at_now()
        .unwrap();
    owned
        .get_mut()
        .flush_buffer(&mut buf)
        .expect("Buffer flush over an owned pooled QWP/WS sender");
    drop(owned);

    // Clean sender returns to the pool for reuse.
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(db.free_count(), 1);

    // `_with_retry` with a zero budget makes a single attempt and reuses the
    // recycled sender.
    let owned2 = db
        .borrow_sender_owned_with_retry(Duration::ZERO)
        .expect("owned retry borrow");
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.free_count(), 0);
    drop(owned2);
    assert_eq!(db.free_count(), 1);
    drop(db);
}

#[cfg(feature = "ffi-support")]
#[test]
fn buffer_sender_owned_mark_must_close_drops_not_recycles() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut owned = db.borrow_sender_owned().expect("borrow owned");
    owned.mark_must_close();
    assert!(owned.must_close());
    drop(owned);

    // Marked must-close: dropped, not recycled.
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(db.free_count(), 0);
    drop(db);
}

#[cfg(feature = "ffi-support")]
#[test]
fn owned_buffer_sender_observes_pool_close_and_drops_after_close() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;close_flush_timeout_millis=50;",
    ))
    .unwrap();

    let owned = db.borrow_sender_owned().expect("borrow owned sender");
    assert_eq!(db.in_use_count(), 1);
    assert!(!owned.pool_closed());
    assert!(!owned.must_close());

    db.close();
    assert!(owned.pool_closed());
    assert!(owned.must_close());
    drop(owned);
}

#[test]
fn manual_reap_closes_idle_buffer_senders() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;idle_timeout_ms=50;pool_reap=manual;",
    ))
    .unwrap();

    // Park two Buffer-capable senders in the unified free list.
    let b1 = db.borrow_sender().expect("b1");
    let b2 = db.borrow_sender().expect("b2 (grow)");
    drop(b1);
    drop(b2);
    assert_eq!(db.free_count(), 2);

    // Reap before the idle timeout — nothing closed.
    assert_eq!(db.reap_idle(), 0);
    assert_eq!(db.free_count(), 2);

    // Past the timeout: reap the excess sender while preserving `sender_pool_min=1`.
    thread::sleep(Duration::from_millis(120));
    let closed = db.reap_idle();
    assert_eq!(closed, 1, "the excess idle Buffer sender must be reaped");
    assert_eq!(db.free_count(), 1, "the warm minimum must remain");
    drop(db);
}

#[test]
fn reaper_keeps_undelivered_recovery_buffer_sender() {
    let dir = TempDir::new().unwrap();
    seed_async_qwp_ws_slot(dir.path(), "rowreap-ingest-0", 77);

    let (_server, release, frames) = MockServer::spawn_ack_when_released_capturing(1);
    let conf = conf_for_endpoints(
        &[_server.port()],
        &format!(
            "sf_dir={};sender_id=rowreap;sender_pool_min=1;sender_pool_max=2;\
             idle_timeout_ms=1;pool_reap=manual;close_flush_timeout_millis=2000;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let payload = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("recovery Buffer frame reaches mock server");
    assert_eq!(frame_table_name(&payload), "legacy");
    assert!(
        wait_until(Duration::from_secs(2), || db.free_count() == 1),
        "pre-opened Buffer recovery sender should park in the free list"
    );

    thread::sleep(Duration::from_millis(50));
    assert_eq!(
        db.reap_idle(),
        0,
        "undelivered Buffer sender must stay parked"
    );
    assert_eq!(db.free_count(), 1);

    release.store(true, Ordering::SeqCst);
    // Create one excess idle sender after delivery. The recovered sender may
    // satisfy the first borrow, so hold it while opening the second slot.
    let first = db.borrow_sender().expect("borrow recovered sender");
    let second = db.borrow_sender().expect("open excess sender");
    drop(first);
    drop(second);
    assert_eq!(db.free_count(), 2);
    assert!(
        wait_until(Duration::from_secs(5), || {
            db.reap_idle();
            db.free_count() == 1
        }),
        "delivered recovery sender should become reapable above the warm minimum"
    );
}

#[test]
fn disk_store_and_forward_restart_preopens_dirty_buffer_slot() {
    let dir = TempDir::new().unwrap();
    seed_async_qwp_ws_slot(dir.path(), "rowrec-ingest-0", 55);

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!(
            "sf_dir={};sender_id=rowrec;sender_pool_min=1;sender_pool_max=1;\
             pool_reap=manual;max_background_drainers=1;close_flush_timeout_millis=0;",
            dir.path().display()
        ),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let payload = frames
        .recv_timeout(Duration::from_secs(5))
        .expect("dirty Buffer slot should replay during connect-time pre-open");
    assert_eq!(frame_table_name(&payload), "legacy");
    assert!(
        wait_until(Duration::from_secs(2), || db.free_count() == 1),
        "pre-opened Buffer recovery sender should park in the free list"
    );
}

#[test]
fn buffer_sender_pool_grows_and_reuses_physical_connections() {
    let server = MockServer::spawn_acking(16);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=4;",
    ))
    .unwrap();

    // Without disk-SF recovery, `connect` opens nothing.
    assert_eq!(server.accepted(), 0);

    // Three concurrent unified borrows each open a fresh connection.
    let r1 = db.borrow_sender().expect("r1");
    let r2 = db.borrow_sender().expect("r2 (grow)");
    let r3 = db.borrow_sender().expect("r3 (grow)");
    assert_eq!(db.in_use_count(), 3);
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 3),
        "each sender borrow must open a fresh connection; accepted={}",
        server.accepted()
    );

    drop(r1);
    drop(r2);
    drop(r3);
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(db.free_count(), 3);

    // Re-borrowing reuses recycled connections — no new accepts.
    let _a = db.borrow_sender().expect("reuse 1");
    let _b = db.borrow_sender().expect("reuse 2");
    assert_eq!(db.free_count(), 1);
    assert_eq!(server.accepted(), 3, "reuse must not open new connections");
}

#[test]
fn buffer_sender_drop_on_return_drops_instead_of_recycling() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 1),
        "the first sender must connect before it is forced closed"
    );
    sender.drop_on_return();
    drop(sender);

    assert_eq!(db.in_use_count(), 0);
    assert_eq!(
        db.free_count(),
        0,
        "a must-close sender must be dropped, not recycled"
    );

    // The next borrow therefore opens a brand-new connection.
    let _fresh = db.borrow_sender().expect("re-borrow after drop");
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 2),
        "re-borrow must open a new connection (2 borrows total); accepted={}",
        server.accepted()
    );
}

#[test]
fn one_cap_covers_buffer_and_chunk_senders_borrowed_together() {
    let server = MockServer::spawn_acking(16);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;acquire_timeout_ms=0;",
    ))
    .unwrap();

    let mut chunk_sender = db.borrow_sender().expect("Chunk sender");
    let mut buffer_sender = db.borrow_sender().expect("Buffer sender");

    assert_eq!(db.in_use_count(), 2);
    let cap_err = db
        .borrow_sender()
        .expect_err("payload shape must not create another pool allowance");
    assert_eq!(cap_err.code(), ErrorCode::InvalidApiCall);

    let value = [7_i64];
    let timestamp = [7_i64];
    let mut chunk = one_i64_row("chunk_table", &value, &timestamp);
    chunk_sender
        .flush(&mut chunk)
        .expect("Chunk flush while a Buffer sender is borrowed");

    let mut buf = buffer_sender.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "x")
        .unwrap()
        .column_f64("price", 1.0)
        .unwrap()
        .at_now()
        .unwrap();
    buffer_sender
        .flush_buffer(&mut buf)
        .expect("Buffer flush while a Chunk sender is borrowed");

    drop(buffer_sender);
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.free_count(), 1);

    drop(chunk_sender);
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(db.free_count(), 2);
    drop(db);
}

#[test]
fn concurrent_buffer_sender_borrow_and_return_does_not_deadlock_or_leak() {
    let server = MockServer::spawn_acking(32);
    let db = Arc::new(
        QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=8;",
        ))
        .unwrap(),
    );
    let mut handles = Vec::new();
    for _ in 0..8 {
        let db = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for _ in 0..16 {
                let borrow = db.borrow_sender().expect("borrow_sender under contention");
                std::hint::black_box(&borrow);
                thread::yield_now();
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread");
    }
    // After all workers finish: every borrow returned, nothing leaked, and the
    // free list never exceeded the cap.
    assert_eq!(db.in_use_count(), 0);
    assert!(db.free_count() >= 1);
    assert!(
        db.free_count() <= 8,
        "free list must not exceed pool_max; free={}",
        db.free_count()
    );
}

#[test]
fn auto_reaper_closes_idle_buffer_senders() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;idle_timeout_ms=100;pool_reap=auto;",
    ))
    .unwrap();
    let b1 = db.borrow_sender().expect("b1");
    let b2 = db.borrow_sender().expect("b2 (grow)");
    drop(b1);
    drop(b2);
    assert_eq!(db.free_count(), 2);

    // The background reaper wakes on a `max(5s, timeout/12)` ticker (the 5s
    // floor applies here). The unified pool preserves its one warm sender.
    let reaped = wait_until(Duration::from_secs(8), || db.free_count() == 1);
    assert!(
        reaped,
        "auto reaper failed to drain the excess Buffer sender; free={}",
        db.free_count()
    );
    drop(db);
}

#[test]
fn buffer_sender_local_build_failure_releases_in_use_slot() {
    // Network unavailability is not a build failure for this offline-first
    // pool. Force a local build failure instead by flocking its only managed
    // disk slot from another pool, then prove the failed borrow releases the
    // in-use reservation rather than permanently burning the cap.
    let dir = TempDir::new().unwrap();
    let port = unused_local_port();
    let conf = format!(
        "ws::addr=127.0.0.1:{port};auth_timeout=200;sf_dir={};\
         sender_id=buildfail;sender_pool_min=1;sender_pool_max=1;pool_reap=manual;\
         close_flush_timeout_millis=0;",
        dir.path().display()
    );
    let owner = QuestDb::connect(&conf).unwrap();
    let _held = owner.borrow_sender().expect("owner flocks ingest slot 0");
    let contender = QuestDb::connect(&conf).unwrap();

    let err = contender
        .borrow_sender()
        .expect_err("local sender build must fail on the flocked slot");
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("buildfail-ingest-0"), "{}", err.msg());
    assert_eq!(
        contender.in_use_count(),
        0,
        "a failed build must not leak an in_use slot"
    );
    assert_eq!(contender.free_count(), 0);
}

#[test]
fn concurrent_borrow_and_return_does_not_deadlock_or_leak() {
    let server = MockServer::spawn(16);
    let db = Arc::new(
        QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=8;",
        ))
        .unwrap(),
    );
    let mut handles = Vec::new();
    for _ in 0..8 {
        let db = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for _ in 0..16 {
                let borrow = db.borrow_sender().expect("borrow_sender under contention");
                // Tiny critical section to encourage contention.
                std::hint::black_box(&borrow);
                thread::yield_now();
            }
        }));
    }
    for h in handles {
        h.join().expect("worker thread");
    }
    // After all workers finish: every borrow returned.
    assert_eq!(db.in_use_count(), 0);
    assert!(db.free_count() >= 1);
}

#[test]
fn manual_reap_closes_excess_idle_connections() {
    let server = MockServer::spawn(4);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;idle_timeout_ms=50;pool_reap=manual;",
    ))
    .unwrap();
    let b1 = db.borrow_sender().expect("b1");
    let b2 = db.borrow_sender().expect("b2 (grow)");
    let b3 = db.borrow_sender().expect("b3 (grow)");
    drop(b1);
    drop(b2);
    drop(b3);
    assert_eq!(db.free_count(), 3);

    // Reap before the idle timeout — nothing should be closed.
    let immediate = db.reap_idle();
    assert_eq!(immediate, 0);
    assert_eq!(db.free_count(), 3);

    // Wait past the idle timeout, then reap. Must keep `pool_size` warm.
    thread::sleep(Duration::from_millis(120));
    let closed = db.reap_idle();
    assert_eq!(closed, 2, "should reap the two excess-over-pool_size slots");
    assert_eq!(db.free_count(), 1, "pool_size warm slot must stay");
    drop(db);
}

#[test]
fn manual_reap_keeps_warm_floor_with_borrows_outstanding() {
    let server = MockServer::spawn(5);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=3;sender_pool_max=5;idle_timeout_ms=50;pool_reap=manual;",
    ))
    .unwrap();
    let b1 = db.borrow_sender().expect("b1");
    let b2 = db.borrow_sender().expect("b2");
    let b3 = db.borrow_sender().expect("b3 (grow)");
    let b4 = db.borrow_sender().expect("b4 (grow)");
    // Two stay borrowed; two return to the free list. total()=4, in_use=2.
    drop(b3);
    drop(b4);
    assert_eq!(db.in_use_count(), 2);
    assert_eq!(db.free_count(), 2);

    // Reap while b1/b2 are still in use. total()=4 exceeds sender_pool_min=3 by one,
    // so exactly one idle slot is reaped and the other is kept warm to hold
    // total() at the pool_size floor — the warm floor under `in_use < pool_size`.
    thread::sleep(Duration::from_millis(120));
    let closed = db.reap_idle();
    assert_eq!(
        closed, 1,
        "only the slot above the pool_size floor may be reaped"
    );
    assert_eq!(db.free_count(), 1, "one idle slot stays warm at the floor");
    assert_eq!(
        db.in_use_count(),
        2,
        "borrowed senders are untouched by the reaper"
    );

    drop(b1);
    drop(b2);
    drop(db);
}

#[test]
fn auto_reaper_closes_excess_idle_connections() {
    let server = MockServer::spawn(4);
    // tick = max(5s, timeout/12); use a long-enough timeout that timeout/12
    // > 5s so the reaper wakes promptly on its own ticker.
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;idle_timeout_ms=100;pool_reap=auto;",
    ))
    .unwrap();
    let b1 = db.borrow_sender().expect("b1");
    let b2 = db.borrow_sender().expect("b2");
    let b3 = db.borrow_sender().expect("b3");
    drop(b1);
    drop(b2);
    drop(b3);
    assert_eq!(db.free_count(), 3);

    // Auto reaper wakes on a `max(5s, timeout/12)` ticker. With timeout=100ms,
    // the floor of 5s applies. Wait > 5s for the first wake-up.
    let reaped = wait_until(Duration::from_secs(8), || db.free_count() == 1);
    assert!(
        reaped,
        "auto reaper failed to drain excess; free={}",
        db.free_count()
    );
    drop(db);
}

// ---------- WS-1: flush round-trip ----------

#[test]
fn refuses_durable_ack_without_opt_in() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    let err = sender
        .wait(AckLevel::Durable, Duration::from_secs(30))
        .expect_err("durable without opt-in must fail");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg().contains("request_durable_ack"),
        "msg: {}",
        err.msg()
    );
}

#[test]
fn durable_ack_without_opt_in_does_not_publish_commit_frame() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
    let port = listener.local_addr().expect("local_addr").port();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        perform_server_upgrade(&mut stream).expect("upgrade");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        let frame = match read_frame(&mut stream) {
            Ok((_fin, opcode, _payload)) => Some(opcode),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                None
            }
            Err(e) => panic!("unexpected server read error: {e}"),
        };
        tx.send(frame).expect("send frame observation");
    });

    let db = QuestDb::connect(&conf_for(port, "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    let err = sender
        .wait(AckLevel::Durable, Duration::from_secs(30))
        .expect_err("durable without opt-in must fail before publish");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg().contains("request_durable_ack"),
        "msg: {}",
        err.msg()
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2))
            .expect("server observation"),
        None,
        "sync must reject durable ACK before sending a commit frame"
    );

    drop(sender);
    drop(db);
    handle.join().expect("server thread");
}

#[test]
fn empty_chunk_flush_round_trips() {
    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    let mut chunk = Chunk::new("trades");
    assert_eq!(chunk.row_count(), 0);
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("empty-chunk flush must round-trip");
    // Flush clears the chunk.
    assert_eq!(chunk.row_count(), 0);
}

#[test]
fn deferred_flush_reserves_slot_for_sync_commit() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(server.port(), "close_flush_timeout_millis=50;")).unwrap();
    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    let mut chunk = Chunk::new("trades");

    for _ in 0..127 {
        sender.flush(&mut chunk).expect("flush below reserve");
    }

    chunk.column_i64("qty", &[42], None).expect("column_i64");
    chunk
        .at_nanos(&[1_700_000_000_000_000_000])
        .expect("designated timestamp");
    let err = sender
        .flush(&mut chunk)
        .expect_err("deferred flush must preserve the sync commit slot");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("sync()"), "msg: {}", err.msg());
    assert!(
        !err.in_doubt(),
        "a pre-publication (not-delivered) failure is never in_doubt"
    );
    assert_eq!(
        chunk.row_count(),
        1,
        "capacity failure must leave the caller's chunk untouched"
    );
}

#[test]
fn flush_clears_chunk_for_reuse_and_can_repeat() {
    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    let mut chunk = Chunk::new("trades");
    for _ in 0..3 {
        sender.flush(&mut chunk).unwrap();
        sender
            .wait(AckLevel::Ok, Duration::from_secs(30))
            .expect("repeated empty flush");
    }
}

// ---------------------------------------------------------------------------
// Direct-mode ACKing flush (`flush_and_wait`)
// ---------------------------------------------------------------------------

/// Build a one-row `i64` chunk for `table` at `ts` nanos.
fn one_i64_row<'a>(table: &'a str, val: &'a [i64; 1], ts: &'a [i64; 1]) -> Chunk<'a> {
    let mut chunk = Chunk::new(table);
    chunk.column_i64("qty", val, None).unwrap();
    chunk.at_nanos(ts).unwrap();
    chunk
}

#[test]
fn flush_and_wait_publishes_and_waits_for_ok() {
    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");

    let val = [42_i64];
    let ts = [1_700_000_000_000_000_000_i64];
    let mut chunk = one_i64_row("trades", &val, &ts);
    sender
        .flush(&mut chunk)
        .expect("publish to the local SFA queue");
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("wait must return after the OK ack");
    assert!(chunk.is_empty(), "successful ACKing flush clears the chunk");
}

#[test]
fn flush_and_wait_empty_chunk_behaves_like_sync() {
    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    let mut chunk = Chunk::new("trades");
    assert_eq!(chunk.row_count(), 0);
    sender
        .flush(&mut chunk)
        .expect("publish-only flush of the empty chunk");
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("empty-chunk flush + wait collapses to a bare wait");
    assert_eq!(chunk.row_count(), 0);
}

#[test]
fn flush_and_wait_durable_without_opt_in_leaves_chunk_untouched() {
    // Mirror `durable_ack_without_opt_in_does_not_publish_commit_frame` but for
    // the ACKing flush of a *data* chunk: the durable opt-in is a preflight, so
    // no frame is published and the chunk is retained.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
    let port = listener.local_addr().expect("local_addr").port();
    let (tx, rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        perform_server_upgrade(&mut stream).expect("upgrade");
        stream
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("set read timeout");
        let frame = match read_frame(&mut stream) {
            Ok((_fin, opcode, _payload)) => Some(opcode),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                None
            }
            Err(e) => panic!("unexpected server read error: {e}"),
        };
        tx.send(frame).expect("send frame observation");
    });

    let db = QuestDb::connect(&conf_for(port, "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    let val = [7_i64];
    let ts = [1_i64];
    let chunk = one_i64_row("trades", &val, &ts);
    // Durable is validated by `wait` before it touches the wire; with no
    // `flush` no frame is published and the chunk is left untouched.
    let err = sender
        .wait(AckLevel::Durable, Duration::from_secs(30))
        .expect_err("durable without opt-in must fail before publish");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(
        err.msg().contains("request_durable_ack"),
        "msg: {}",
        err.msg()
    );
    assert_eq!(
        chunk.row_count(),
        1,
        "pre-publication rejection must leave the chunk untouched"
    );
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(2))
            .expect("server observation"),
        None,
        "ACKing flush must reject durable ACK before publishing any frame"
    );

    drop(sender);
    drop(db);
    handle.join().expect("server thread");
}

#[test]
fn flush_and_wait_boundary_covers_prior_flush() {
    // `flush(A)` (publish-only) then `flush_and_wait(B, Ok)` — the boundary
    // covers both frames, so the server must ack two frames before the call
    // returns.
    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");

    let a_val = [1_i64];
    let a_ts = [1_i64];
    let mut a = one_i64_row("trades", &a_val, &a_ts);
    sender.flush(&mut a).expect("publish-only flush of A");
    assert!(a.is_empty());

    let b_val = [2_i64];
    let b_ts = [2_i64];
    let mut b = one_i64_row("trades", &b_val, &b_ts);
    sender.flush(&mut b).expect("publish-only flush of B");
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("wait after B must drain A and B");
    assert!(b.is_empty());
    assert_eq!(
        sender.in_flight(),
        0,
        "a successful ACKing flush drains all in-flight frames to zero"
    );
}

#[test]
fn flush_and_wait_skips_the_deferred_reserve_guard() {
    // Fill in-flight to the deferred reserve (a 128th *deferred* flush would
    // trip the slot guard), then prove an ACKing flush still publishes — it
    // goes out non-deferred, so it never consults the reserve guard, and
    // `sync_all_acks` drains everything to zero.
    let (server, release, _frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_direct_column_sender().expect("borrow");

    let mut filler = Chunk::new("trades");
    for _ in 0..127 {
        sender
            .flush(&mut filler)
            .expect("deferred flush below the reserve");
    }
    assert_eq!(sender.in_flight(), 127, "filled to the deferred reserve");

    // Unblock the held acks shortly after, so the ACKing flush's `sync` drains.
    let releaser = {
        let release = Arc::clone(&release);
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            release.store(true, Ordering::SeqCst);
        })
    };

    let val = [9_i64];
    let ts = [9_i64];
    let mut chunk = one_i64_row("trades", &val, &ts);
    sender
        .flush_and_wait(&mut chunk, AckLevel::Ok)
        .expect("ACKing flush must not trip the deferred-reserve guard");
    assert!(chunk.is_empty());
    assert_eq!(sender.in_flight(), 0);
    releaser.join().expect("releaser thread");
}

#[test]
fn flush_and_wait_ack_wait_failure_after_publish_clears_chunk() {
    // The server reads (consumes) the published frame — so the write provably
    // succeeds and the chunk is cleared (design §7.4) — then closes without
    // acking. The subsequent `sync_all_acks` read hits EOF: a post-publication
    // transport death whose delivery is *unknown*, surfaced as `FailoverRetry`
    // with the conn latched `must_close`.
    let server = MockServer::spawn_read_then_close(1, 1);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_direct_column_sender().expect("borrow");

    let val = [5_i64];
    let ts = [5_i64];
    let mut chunk = one_i64_row("trades", &val, &ts);
    let err = sender
        .flush_and_wait(&mut chunk, AckLevel::Ok)
        .expect_err("server died during the ACK wait");
    assert_eq!(err.code(), ErrorCode::FailoverRetry, "{}", err.msg());
    assert!(
        err.in_doubt(),
        "a post-publication delivery-unknown failure must be flagged in_doubt \
         even though it reports FailoverRetry"
    );
    assert!(
        chunk.is_empty(),
        "the frame was published, so the chunk is cleared even though the ACK wait failed"
    );
    assert!(
        sender.must_close_for_test(),
        "a delivery-unknown failure must latch the conn for pool discard"
    );
}

#[test]
fn flush_rejects_chunk_with_no_designated_timestamp() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
    let mut chunk = Chunk::new("trades");
    chunk
        .column_i64("price", &[1, 2, 3], None)
        .expect("column_i64");
    let err = sender
        .flush(&mut chunk)
        .expect_err("non-empty chunk without designated_ts must error");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("designated"), "msg: {}", err.msg());
    // Chunk is left untouched on failure.
    assert_eq!(chunk.row_count(), 3);
}

#[test]
fn non_empty_chunk_with_numeric_columns_round_trips() {
    use crate::ingress::column_sender::Validity;

    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");

    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &[10, 20, 30], None).unwrap();
    chunk.column_f64("price", &[1.1, 2.2, 3.3], None).unwrap();
    // Nullable column: bit 1 (row 1) is null.
    let bits = [0b0000_0101];
    let v = Validity::from_bitmap(&bits, 3).unwrap();
    chunk
        .column_uuid("id", &[[0x10; 16], [0; 16], [0x20; 16]], Some(&v))
        .unwrap();
    chunk
        .at_nanos(&[
            1_700_000_000_000_000_000,
            1_700_000_000_000_001_000,
            1_700_000_000_000_002_000,
        ])
        .unwrap();
    assert_eq!(chunk.row_count(), 3);

    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("numeric chunk flush");
    assert!(chunk.is_empty(), "flush must clear the chunk");

    // Second flush with the SAME schema re-inlines the schema (QWP is
    // single-version with inline schemas — no REFERENCE shortcut): it must
    // still round-trip cleanly.
    chunk.column_i64("qty", &[40, 50], None).unwrap();
    chunk.column_f64("price", &[4.4, 5.5], None).unwrap();
    chunk
        .column_uuid("id", &[[0x30; 16], [0x40; 16]], None)
        .unwrap();
    chunk
        .at_nanos(&[1_700_000_000_000_003_000, 1_700_000_000_000_004_000])
        .unwrap();
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("second flush (schema reuse)");
}

#[test]
fn varchar_chunk_round_trips() {
    use crate::ingress::column_sender::Validity;

    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");

    let mut chunk = Chunk::new("logs");
    // 4 rows: "alpha", null, "gamma", "δ" (multi-byte UTF-8).
    let bytes = b"alphagamma\xCE\xB4";
    // Offsets length must be row_count + 1 = 5. The null row reuses the
    // same offset on both sides per the plan's "skip slicing for null
    // rows" rule.
    let offsets: [i32; 5] = [0, 5, 5, 10, 12];
    let bits = [0b0000_1101]; // 0,2,3 valid; 1 null
    let v = Validity::from_bitmap(&bits, 4).unwrap();
    chunk.column_str("msg", &offsets, bytes, Some(&v)).unwrap();
    chunk
        .column_i64("seq", &[100, 101, 102, 103], None)
        .unwrap();
    chunk
        .at_nanos(&[
            1_700_000_000_000_000_000,
            1_700_000_000_000_001_000,
            1_700_000_000_000_002_000,
            1_700_000_000_000_003_000,
        ])
        .unwrap();
    assert_eq!(chunk.row_count(), 4);
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("varchar flush");
    assert!(chunk.is_empty());
}

#[test]
fn symbol_chunk_round_trips_and_reuses_global_dict() {
    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");

    // Caller has a 3-entry dict; first chunk only references entries 0 and 2,
    // so the wire's delta-symbol-dict prefix carries those two new symbols.
    let dict_bytes = b"alphabetagamma";
    let dict_offsets: [i32; 4] = [0, 5, 9, 14];

    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &[0, 2, 0, 2], &dict_offsets, dict_bytes, None)
        .expect("symbol_i32 first flush");
    chunk.at_nanos(&[1, 2, 3, 4]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("symbol flush 1");

    // Second flush re-uses entry 0 ("alpha", already in the global dict)
    // and adds entry 1 ("beta"). With the connection-scoped dict the
    // wire prefix only resends "beta"; the round-trip must still succeed.
    chunk
        .symbol_i32("sym", &[1, 0, 1, 0], &dict_offsets, dict_bytes, None)
        .expect("symbol_i32 second flush");
    chunk.at_nanos(&[5, 6, 7, 8]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("symbol flush 2");
}

/// Read a LEB128 varint at `*pos`, advancing `pos`.
fn read_varint(buf: &[u8], pos: &mut usize) -> u64 {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = buf[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    value
}

/// Parse the QWP frame's delta-symbol-dict prefix (written immediately after
/// the 12-byte header): `delta_start` varint, new-symbol count varint, then
/// each new symbol as a length-prefixed byte string.
fn parse_delta_dict_prefix(frame: &[u8]) -> (u64, Vec<Vec<u8>>) {
    assert_eq!(&frame[..4], b"QWP1", "frame magic");
    let mut pos = 12; // QWP header length
    let delta_start = read_varint(frame, &mut pos);
    let count = read_varint(frame, &mut pos) as usize;
    let mut symbols = Vec::with_capacity(count);
    for _ in 0..count {
        let len = read_varint(frame, &mut pos) as usize;
        symbols.push(frame[pos..pos + len].to_vec());
        pos += len;
    }
    (delta_start, symbols)
}

#[test]
fn symbol_dict_reuse_resends_only_new_symbols_on_the_wire() {
    let (server, frames) = MockServer::spawn_acking_capturing(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_direct_column_sender().expect("borrow");

    let dict_bytes = b"alphabetagamma";
    let dict_offsets: [i32; 4] = [0, 5, 9, 14];

    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &[0, 2, 0, 2], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.at_nanos(&[1, 2, 3, 4]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender.commit(AckLevel::Ok).expect("symbol flush 1");

    chunk
        .symbol_i32("sym", &[1, 0, 1, 0], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.at_nanos(&[5, 6, 7, 8]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender.commit(AckLevel::Ok).expect("symbol flush 2");

    drop(sender);
    drop(db);
    drop(server);

    // Each `flush` emits a deferred data frame (table_count = 1); the trailing
    // `sync` emits a header-only commit frame (table_count = 0). Keep only the
    // data frames, which carry the delta-symbol-dict prefix.
    let captured: Vec<Vec<u8>> = frames.try_iter().collect();
    let data_frames: Vec<Vec<u8>> = captured
        .into_iter()
        .filter(|f| f.len() >= 12 && &f[..4] == b"QWP1" && u16::from_le_bytes([f[6], f[7]]) >= 1)
        .collect();
    assert_eq!(
        data_frames.len(),
        2,
        "expected two data frames among the captured frames"
    );

    // First flush references dict entries 0 and 2 ("alpha", "gamma"); the
    // delta prefix interns both starting at global id 0.
    let (start0, syms0) = parse_delta_dict_prefix(&data_frames[0]);
    assert_eq!(start0, 0);
    assert_eq!(syms0, vec![b"alpha".to_vec(), b"gamma".to_vec()]);

    // Second flush references entries 1 and 0 ("beta", "alpha"). "alpha" is
    // already in the connection-scoped global dict, so only "beta" is resent,
    // resuming from the global watermark (id 2).
    let (start1, syms1) = parse_delta_dict_prefix(&data_frames[1]);
    assert_eq!(start1, 2, "second frame resumes from the global watermark");
    assert_eq!(
        syms1,
        vec![b"beta".to_vec()],
        "only the new symbol is resent"
    );
}

#[test]
fn sfa_symbol_dict_reuse_delta_encodes_second_frame() {
    let (server, frames) = MockServer::spawn_acking_capturing(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    // borrow_sender is memory-mode store-and-forward, where delta symbol
    // dictionaries are now enabled: the background driver re-registers the whole
    // dictionary via a catch-up frame on reconnect, so per-frame deltas are safe.
    let mut sender = db.borrow_sender().expect("borrow");

    let dict_bytes = b"alphabetagamma";
    let dict_offsets: [i32; 4] = [0, 5, 9, 14];

    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_i32("sym", &[0, 2, 0, 2], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.at_nanos(&[1, 2, 3, 4]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("symbol flush 1");

    chunk
        .symbol_i32("sym", &[1, 0, 1, 0], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.at_nanos(&[5, 6, 7, 8]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("symbol flush 2");

    drop(sender);
    drop(db);
    drop(server);

    let captured: Vec<Vec<u8>> = frames.try_iter().collect();
    let data_frames: Vec<Vec<u8>> = captured
        .into_iter()
        .filter(|f| f.len() >= 12 && &f[..4] == b"QWP1" && u16::from_le_bytes([f[6], f[7]]) >= 1)
        .collect();
    assert_eq!(data_frames.len(), 2, "expected two SFA data frames");

    // First frame interns alpha (id 0) and gamma (id 1) starting at id 0.
    let (start0, syms0) = parse_delta_dict_prefix(&data_frames[0]);
    assert_eq!(start0, 0);
    assert_eq!(syms0, vec![b"alpha".to_vec(), b"gamma".to_vec()]);

    // Memory-mode SFA now delta-encodes: the second frame resumes from the global
    // watermark (id 2) and ships only the new symbol, instead of re-shipping the
    // whole dictionary from id 0 as the old dense encoder did.
    let (start1, syms1) = parse_delta_dict_prefix(&data_frames[1]);
    assert_eq!(
        start1, 2,
        "SFA second frame resumes from the global watermark (delta)"
    );
    assert_eq!(
        syms1,
        vec![b"beta".to_vec()],
        "SFA resends only the new symbol"
    );
}

#[test]
fn server_error_latches_conn_and_pool_drops_it() {
    // Status 0x09 = QWP write error → ServerFlushError.
    let server = MockServer::spawn_erroring(4, 0x09);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;close_flush_timeout_millis=50;",
    ))
    .unwrap();
    {
        let mut sender = db.borrow_direct_column_sender().expect("borrow");
        let err = sender
            .commit(AckLevel::Ok)
            .expect_err("server error must surface");
        assert_eq!(err.code(), ErrorCode::ServerFlushError);
        // The server's status byte and message must survive the round-trip.
        assert!(err.msg().contains("0x09"), "msg: {}", err.msg());
        assert!(err.msg().contains("injected"), "msg: {}", err.msg());
        assert!(sender.must_close_for_test(), "errored conn must be latched");
        assert_eq!(db.direct_in_use_count(), 1);
    }
    // The latched connection must be dropped, not returned to the free pool.
    assert_eq!(
        db.direct_free_count(),
        0,
        "latched conn must not be recycled"
    );
    assert_eq!(db.direct_in_use_count(), 0);
    // The next borrow must therefore open a brand-new physical connection.
    let _fresh = db
        .borrow_direct_column_sender()
        .expect("re-borrow after drop");
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 2),
        "re-borrow must open a new connection; accepted={}",
        server.accepted()
    );
}

#[test]
fn close_joins_reaper_cleanly() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        // close_flush_timeout_millis bounds the per-Sender close drain, which
        // otherwise can wait up to 5s for the mock server's (absent) WS close
        // handshake. We only care here that the reaper thread joins.
        "sender_pool_min=1;sender_pool_max=2;idle_timeout_ms=500;pool_reap=auto;close_flush_timeout_millis=200;",
    ))
    .unwrap();
    // Borrow + return so we have something to reap eventually.
    {
        let _sender = db.borrow_sender().expect("borrow");
    }
    // close() must return promptly (no hang) — the join is the test.
    let start = Instant::now();
    db.close();
    // The bar is "does not hang indefinitely", not strict latency. The
    // mock server never replies to a WS close frame, so Sender::drop waits
    // out the (200 ms) close-flush timeout; 10 s is plenty of headroom on
    // a CI runner under load.
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "close() must not hang on the reaper (took {:?})",
        start.elapsed()
    );
}

// ---------------------------------------------------------------------------
// Store-and-forward durability on pool close / reap (in-memory queue).
//
// The BorrowedSender contract is that a parked connection's background runner
// keeps delivering, and that pool close / reap do not silently drop frames the
// runner has accepted but not yet delivered. These tests pin the three teardown
// paths that enforce it. The mock captures a frame when it is *sent* (eagerly,
// before the ack), so "loss" is observed through the client-side contract —
// reap protecting an undelivered connection, and close blocking on delivery —
// not through the capture channel.
// ---------------------------------------------------------------------------

/// Reap must not evict an idle connection whose store-and-forward queue still
/// holds undelivered (published-but-unacked) frames — its runner is still
/// delivering. Three connections go idle above the warm floor; only the empty
/// one is reapable, the two with held-back acks are skipped.
///
/// Without the skip, reap would evict the two oldest (one of them undelivered)
/// down to the floor: it would report 2 reaped and leave 1 idle. With it, it
/// reports 1 reaped (the empty connection) and leaves the 2 undelivered ones.
#[test]
fn reap_skips_connections_with_undelivered_frames() {
    let (server, release, _frames) = MockServer::spawn_ack_when_released_capturing(3);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=3;idle_timeout_ms=1;pool_reap=manual;\
         close_flush_timeout_millis=2000;",
    ))
    .unwrap();

    // Open three distinct connections; b1 stays empty, b2 and b3 each publish a
    // frame whose ack the server withholds, so they read as undelivered.
    let b1 = db.borrow_sender().expect("b1");
    let mut b2 = db.borrow_sender().expect("b2");
    let mut b3 = db.borrow_sender().expect("b3");
    assert!(wait_until(Duration::from_secs(5), || server.accepted() == 3));

    let v = [1_i64];
    let t = [1_i64];
    let mut c2 = one_i64_row("trades", &v, &t);
    b2.flush(&mut c2).expect("publish-only flush on b2");
    let mut c3 = one_i64_row("trades", &v, &t);
    b3.flush(&mut c3).expect("publish-only flush on b3");

    // Return to the free list in order [b1, b2, b3] (oldest first).
    drop(b1);
    drop(b2);
    drop(b3);
    assert_eq!(db.free_count(), 3);

    // Let the idle timeout (1 ms) elapse, then reap. Only the empty b1 may go.
    thread::sleep(Duration::from_millis(50));
    let reaped = db.reap_idle();
    assert_eq!(
        reaped, 1,
        "only the empty connection is reapable; the undelivered ones are skipped"
    );
    assert_eq!(
        db.free_count(),
        2,
        "both connections with undelivered frames must survive the reap"
    );

    // Drain cleanly on teardown.
    release.store(true, Ordering::SeqCst);
    drop(db);
}

/// `db.close()` must block until a parked connection's store-and-forward queue
/// has actually delivered its frames — not return immediately and strand them
/// by stopping the runner. With the server withholding acks, close stays
/// blocked; once the acks are released, delivery resolves and close returns.
///
/// Without the close-time drain this fails: `close()` returns promptly while
/// the acks are still held.
#[test]
fn close_blocks_until_store_and_forward_queue_is_delivered() {
    let (server, release, _frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        // Generous drain budget so close blocks on delivery, not on the timeout.
        "pool_reap=manual;close_flush_timeout_millis=30000;",
    ))
    .unwrap();

    {
        let mut sender = db.borrow_sender().expect("borrow");
        let v = [7_i64];
        let t = [7_i64];
        let mut chunk = one_i64_row("trades", &v, &t);
        sender.flush(&mut chunk).expect("publish-only flush");
    } // handle returned to the pool; runner still owns the unacked frame.
    assert!(wait_until(Duration::from_secs(5), || server.accepted() == 1));

    let closed = Arc::new(AtomicBool::new(false));
    let closed_thread = Arc::clone(&closed);
    let closer = thread::spawn(move || {
        db.close();
        closed_thread.store(true, Ordering::SeqCst);
    });

    // While the acks are held, close must stay blocked in the drain.
    assert!(
        !wait_until(Duration::from_millis(500), || closed.load(Ordering::SeqCst)),
        "close() must not return while published frames are still undelivered"
    );

    // Release the acks: delivery resolves and close can finish.
    release.store(true, Ordering::SeqCst);
    assert!(
        wait_until(Duration::from_secs(35), || closed.load(Ordering::SeqCst)),
        "close() must return once delivery completes"
    );
    closer.join().expect("closer thread");
}

/// A silent-but-alive peer (connected, never acks) must not make `close()` hang:
/// the close-time drain is bounded by `close_flush_timeout`, after which the
/// undelivered frame is discarded with a warning and close returns.
#[test]
fn close_drain_is_bounded_when_peer_never_acks() {
    // Acks are withheld for the whole test (never released).
    let (server, _release, _frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_reap=manual;close_flush_timeout_millis=200;",
    ))
    .unwrap();

    {
        let mut sender = db.borrow_sender().expect("borrow");
        let v = [5_i64];
        let t = [5_i64];
        let mut chunk = one_i64_row("trades", &v, &t);
        sender.flush(&mut chunk).expect("publish-only flush");
    }
    assert!(wait_until(Duration::from_secs(5), || server.accepted() == 1));

    let start = Instant::now();
    db.close();
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "close() must be bounded by close_flush_timeout, not hang (took {:?})",
        start.elapsed()
    );
}

// ---------- F0: endpoint rotation + health, transient classification ----------

#[test]
fn transient_transport_failure_maps_to_failover_retry() {
    // A peer that upgrades then closes: the client's sync read hits EOF, a
    // transport death that must surface as the distinct FailoverRetry code
    // (not SocketError), so callers can tell "retry on a fresh conn" apart.
    let server = MockServer::spawn_upgrade_then_close(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    let err = sender
        .commit(AckLevel::Ok)
        .expect_err("server closed mid-sync must error");
    assert_eq!(err.code(), ErrorCode::FailoverRetry);
    assert!(
        sender.must_close_for_test(),
        "transport-dead conn must be latched"
    );
}

#[test]
fn server_data_rejection_stays_terminal_not_failover_retry() {
    // A server-data rejection (status 0x09 → ServerFlushError) is terminal:
    // re-driving on a fresh conn would fail identically. It must NOT be
    // re-tagged FailoverRetry.
    let server = MockServer::spawn_erroring(2, 0x09);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    let err = sender
        .commit(AckLevel::Ok)
        .expect_err("server data rejection must surface");
    assert_eq!(err.code(), ErrorCode::ServerFlushError);
    assert_ne!(err.code(), ErrorCode::FailoverRetry);
}

#[test]
fn reborrow_after_primary_failure_lands_on_live_endpoint_and_skips_dead() {
    // Endpoint A (first in the list) is the primary that the first borrow lands
    // on, then dies on the first sync. Endpoint B is a live acking server.
    // After the transient failure, `reborrow_from_pool` must rotate to B and
    // must NOT re-attempt the dead A (the pool-level health tracker marks it
    // unhealthy on the dead conn's return).
    let primary = MockServer::spawn_upgrade_then_close(1);
    let live = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for_endpoints(
        &[primary.port(), live.port()],
        "sender_pool_min=1;sender_pool_max=1;",
    ))
    .unwrap();

    // The first (lazy) borrow connects to the primary (first endpoint).
    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || primary.accepted() == 1),
        "first borrow must connect to the primary; accepted={}",
        primary.accepted()
    );
    assert_eq!(live.accepted(), 0, "live endpoint must be untouched so far");

    let err = sender
        .commit(AckLevel::Ok)
        .expect_err("primary died mid-sync");
    assert_eq!(err.code(), ErrorCode::FailoverRetry);

    // Swap onto a live connection behind the same handle.
    sender
        .reborrow_from_pool()
        .expect("re-borrow must land on the live endpoint");
    sender
        .commit(AckLevel::Ok)
        .expect("sync on the live endpoint must succeed");

    assert!(
        wait_until(Duration::from_secs(2), || live.accepted() == 1),
        "re-borrow must connect to the live endpoint; accepted={}",
        live.accepted()
    );
    assert_eq!(
        primary.accepted(),
        1,
        "the dead primary must be skipped, not re-attempted"
    );
}

#[test]
fn failed_reborrow_keeps_handle_erroring_without_panicking() {
    let primary = MockServer::spawn_upgrade_then_close(1);
    let unreachable_port = unused_local_port();
    let db = QuestDb::connect(&conf_for_endpoints(
        &[primary.port(), unreachable_port],
        "sender_pool_min=1;sender_pool_max=1;\
         reconnect_initial_backoff_millis=1;\
         reconnect_max_backoff_millis=1;",
    ))
    .unwrap();

    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || primary.accepted() == 1),
        "first borrow must connect to the primary; accepted={}",
        primary.accepted()
    );

    let err = sender.commit(AckLevel::Ok).expect_err("primary died");
    assert_eq!(err.code(), ErrorCode::FailoverRetry);

    let err = sender
        .reborrow_from_pool()
        .expect_err("replacement endpoint is unreachable");
    assert_eq!(err.code(), ErrorCode::SocketError);
    assert_eq!(
        db.direct_in_use_count(),
        1,
        "failed same-handle reborrow must retain the logical pool slot"
    );

    let sync_after_failed_reborrow =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| sender.commit(AckLevel::Ok)));
    let err = sync_after_failed_reborrow
        .expect("using the sender after failed reborrow must not panic")
        .expect_err("the retained terminal sender should report an error");
    assert_eq!(err.code(), ErrorCode::FailoverRetry);

    drop(sender);
    assert_eq!(db.direct_in_use_count(), 0);
}

#[test]
fn reborrow_on_single_endpoint_pool_reuses_the_same_endpoint() {
    // A single-endpoint pool must behave exactly as today: a re-borrow simply
    // opens a fresh connection to the one endpoint.
    let server = MockServer::spawn_acking(3);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    sender.commit(AckLevel::Ok).expect("first sync");

    sender
        .reborrow_from_pool()
        .expect("re-borrow on a single endpoint");
    sender.commit(AckLevel::Ok).expect("sync after re-borrow");

    // Exactly one slot remains in use behind the handle (no leak, no growth
    // past the borrow).
    assert_eq!(db.direct_in_use_count(), 1);
    drop(sender);
    assert_eq!(db.direct_in_use_count(), 0);
}

#[test]
fn dead_endpoint_stays_skipped_across_repeated_reborrows() {
    // Once the primary is marked unhealthy, it stays skipped on every
    // subsequent borrow that the live endpoint can serve — the pool does not
    // rediscover the dead peer one connection at a time. The live endpoint
    // takes all the traffic; the dead one's accept count never grows past the
    // single eager-open.
    let dead = MockServer::spawn_upgrade_then_close(1);
    let live = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for_endpoints(
        &[dead.port(), live.port()],
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();
    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || dead.accepted() == 1),
        "first borrow must land on the first endpoint"
    );
    // First sync hits the dead conn.
    let err = sender.commit(AckLevel::Ok).expect_err("primary died");
    assert_eq!(err.code(), ErrorCode::FailoverRetry);

    for _ in 0..3 {
        sender
            .reborrow_from_pool()
            .expect("re-borrow rotates to live");
        sender
            .commit(AckLevel::Ok)
            .expect("live endpoint accepts the sync");
    }

    assert_eq!(
        dead.accepted(),
        1,
        "the dead endpoint must stay skipped, never re-attempted"
    );
}

fn wait_until<F: FnMut() -> bool>(timeout: Duration, mut predicate: F) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if predicate() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

// ---------- F1: retry-from-source at the DataFrame entry ----------

// Used by both the arrow-ingress and polars-ingress tests below.
// `polars-ingress` implies `arrow-ingress`, so gate on the latter to keep
// the helper available whenever either test set compiles.
#[cfg(feature = "arrow-ingress")]
fn data_frame_count(frames: &mpsc::Receiver<Vec<u8>>) -> usize {
    // A QWP data frame carries `table_count >= 1` at bytes 6..8; the
    // header-only commit frame the `sync` sends has `table_count == 0`.
    frames
        .try_iter()
        .filter(|f| f.len() >= 12 && &f[..4] == b"QWP1" && u16::from_le_bytes([f[6], f[7]]) >= 1)
        .count()
}

// Decode the single i64 column of every captured QWP data frame so a re-drive
// is checked for the exact rows it lands, not just the frame count. Layout:
// 12-byte header, delta-dict prefix, table, row/col counts, signature, then
// the column body `flag(0) + row_count * i64_le`.
#[cfg(feature = "arrow-ingress")]
fn redriven_i64_rows(frames: &mpsc::Receiver<Vec<u8>>) -> Vec<i64> {
    fn varint(f: &[u8], pos: &mut usize) -> u64 {
        let (mut shift, mut value) = (0u32, 0u64);
        loop {
            let byte = f[*pos];
            *pos += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
            shift += 7;
        }
    }
    fn skip_lp(f: &[u8], pos: &mut usize) {
        let len = varint(f, pos) as usize;
        *pos += len;
    }
    let mut rows = Vec::new();
    for f in frames.try_iter() {
        if f.len() < 12 || &f[..4] != b"QWP1" || u16::from_le_bytes([f[6], f[7]]) < 1 {
            continue;
        }
        let mut pos = 12;
        let _delta_start = varint(&f, &mut pos);
        let new_syms = varint(&f, &mut pos);
        for _ in 0..new_syms {
            skip_lp(&f, &mut pos);
        }
        skip_lp(&f, &mut pos);
        let row_count = varint(&f, &mut pos) as usize;
        let col_count = varint(&f, &mut pos);
        assert_eq!(col_count, 1, "expected a single-column df frame");
        skip_lp(&f, &mut pos);
        pos += 1;
        assert_eq!(f[pos], 0, "i64 column must not set the bitmap flag");
        pos += 1;
        for _ in 0..row_count {
            rows.push(i64::from_le_bytes(f[pos..pos + 8].try_into().unwrap()));
            pos += 8;
        }
    }
    rows
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn direct_flush_arrow_batch_splits_oversize_batch_into_capped_frames() {
    // The Arrow RecordBatch path must split an oversize batch into cap-sized
    // frames just like the chunk path; every row must land exactly once.
    use arrow::array::{ArrayRef, Int64Array, RecordBatch};
    use std::sync::Arc;

    const CAP: usize = 2048;
    const ROWS: usize = 512; // ~8 B/row -> ~4 KB, vs the 2048 B cap

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let conf = conf_for(
        server.port(),
        &format!("max_buf_size={CAP};pool_reap=manual;"),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let vals: Vec<i64> = (0..ROWS as i64).collect();
    let arr: ArrayRef = Arc::new(Int64Array::from(vals.clone()));
    let batch = RecordBatch::try_from_iter([("seq", arr)]).unwrap();

    let mut sender = db.borrow_direct_column_sender().unwrap();
    sender
        .flush_arrow_batch_at_now_and_wait("trades", &batch, &[], AckLevel::Ok)
        .expect("oversize arrow batch splits, publishes, and commits at one boundary");

    // Drain the channel once: counting and decoding both consume `try_iter`,
    // so collect first and derive both from the same captured frames.
    let captured: Vec<Vec<u8>> = frames.try_iter().collect();
    let data_frames = captured
        .iter()
        .filter(|f| f.len() >= 12 && &f[..4] == b"QWP1" && u16::from_le_bytes([f[6], f[7]]) >= 1)
        .count();
    assert!(
        data_frames > 1,
        "oversize arrow batch must split into multiple frames, got {data_frames}"
    );
    let (replay_tx, replay_rx) = mpsc::channel();
    for f in captured {
        replay_tx.send(f).unwrap();
    }
    drop(replay_tx);
    let mut got = redriven_i64_rows(&replay_rx);
    got.sort_unstable();
    assert_eq!(
        got, vals,
        "split frames must cover every row of the batch exactly once"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn store_and_forward_arrow_batch_reports_fsn_progress_and_split_boundary() {
    use arrow::array::{ArrayRef, Int64Array, RecordBatch};
    use std::sync::Arc;

    const CAP: usize = 2048;
    const ROWS: usize = 512;

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let conf = conf_for(
        server.port(),
        &format!("max_buf_size={CAP};pool_reap=manual;"),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let vals: Vec<i64> = (0..ROWS as i64).collect();
    let arr: ArrayRef = Arc::new(Int64Array::from(vals.clone()));
    let batch = RecordBatch::try_from_iter([("seq", arr)]).unwrap();

    let mut sender = db.borrow_sender().unwrap();
    assert_eq!(sender.published_fsn().unwrap(), None);
    assert_eq!(sender.acked_fsn().unwrap(), None);

    let fsn = sender
        .flush_arrow_batch_at_now_and_get_fsn("trades", &batch, &[])
        .expect("SFA Arrow flush should publish")
        .expect("non-empty Arrow batch publishes a frame");
    assert_eq!(sender.published_fsn().unwrap(), Some(fsn));
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();
    assert!(
        sender
            .acked_fsn()
            .unwrap()
            .is_some_and(|acked| acked >= fsn),
        "acked watermark must cover returned Arrow split boundary"
    );

    let captured: Vec<Vec<u8>> = frames.try_iter().collect();
    let data_frames = captured
        .iter()
        .filter(|f| f.len() >= 12 && &f[..4] == b"QWP1" && u16::from_le_bytes([f[6], f[7]]) >= 1)
        .count();
    assert!(
        data_frames > 1,
        "oversize Arrow batch must split into multiple frames, got {data_frames}"
    );
    assert_eq!(
        fsn as usize,
        data_frames - 1,
        "returned FSN must be the last split frame boundary"
    );

    let (replay_tx, replay_rx) = mpsc::channel();
    for f in captured {
        replay_tx.send(f).unwrap();
    }
    drop(replay_tx);
    let mut got = redriven_i64_rows(&replay_rx);
    got.sort_unstable();
    assert_eq!(
        got, vals,
        "split frames must cover every row of the batch exactly once"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn store_and_forward_arrow_batch_at_column_reports_fsn_progress() {
    use std::sync::Arc;

    use arrow::array::{Float64Array, RecordBatch, TimestampNanosecondArray};
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

    let server = MockServer::spawn_acking(1);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_reap=manual;")).unwrap();

    let schema = Arc::new(Schema::new(vec![
        Field::new("price", DataType::Float64, false),
        Field::new("ts", DataType::Timestamp(TimeUnit::Nanosecond, None), false),
    ]));
    let price = Arc::new(Float64Array::from(vec![1.0, 2.0]));
    let ts = Arc::new(TimestampNanosecondArray::from(vec![
        1_700_000_000_000_000_000,
        1_700_000_000_000_000_001,
    ]));
    let batch = RecordBatch::try_new(schema, vec![price, ts]).unwrap();

    let mut sender = db.borrow_sender().unwrap();
    let ts_col = crate::ingress::ColumnName::new("ts").unwrap();
    let fsn = sender
        .flush_arrow_batch_at_column_and_get_fsn("trades", &batch, ts_col, &[])
        .expect("SFA Arrow at-column flush should publish")
        .expect("non-empty Arrow batch publishes a frame");
    assert_eq!(sender.published_fsn().unwrap(), Some(fsn));
    sender.wait(AckLevel::Ok, Duration::from_secs(30)).unwrap();
    assert!(
        sender
            .acked_fsn()
            .unwrap()
            .is_some_and(|acked| acked >= fsn),
        "acked watermark must cover Arrow at-column FSN"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn store_and_forward_file_mode_arrow_symbol_writes_symbols_ahead_to_side_file() {
    // The Arrow SFA path (`publish_arrow_sfa`) delta-encodes symbol columns and
    // write-aheads their symbols to the slot's `.symbol-dict` side-file, exactly
    // like the chunk path (`store_and_forward_file_mode_writes_symbols_ahead_to_side_file`).
    // A batch whose SYMBOL column introduces "alpha" then "bravo" must persist both
    // in id order before the (unacked) frame is queued. The peer never acks, so the
    // frame stays in the slot and the side-file is not removed by a drained close.
    use std::sync::Arc;

    use arrow::array::{Float64Array, RecordBatch, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};

    use crate::ingress::column_sender::ArrowColumnOverride;

    let (server, _release, _frames) = MockServer::spawn_ack_when_released_capturing(1);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &sf_disk_extras(&dir, "pool_reap=manual;sender_id=recov;"),
    );
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_sender().unwrap();

    let schema = Arc::new(Schema::new(vec![
        Field::new("sym", DataType::Utf8, false),
        Field::new("price", DataType::Float64, false),
    ]));
    let sym = Arc::new(StringArray::from(vec!["alpha", "bravo"]));
    let price = Arc::new(Float64Array::from(vec![1.0, 2.0]));
    let batch = RecordBatch::try_new(schema, vec![sym, price]).unwrap();

    let overrides = [ArrowColumnOverride::Symbol { column: "sym" }];
    sender
        .flush_arrow_batch_at_now_and_get_fsn("trades", &batch, &overrides)
        .expect("Arrow SFA symbol flush should publish")
        .expect("non-empty Arrow batch publishes a frame");

    // The Arrow write-ahead persisted both symbols, in ascending id order, each in
    // its own CRC-committed record, exactly as the chunk path does. Assert
    // format-agnostically (each record's payload carries the `[len]"symbol"` entry)
    // that both are present and alpha precedes bravo, rather than hardcoding the
    // framing/CRC bytes. The pool mints a kind-scoped slot per borrowed column
    // sender, so the first one lives under `<sender_id>-ingest-0`, not the bare
    // `sender_id`.
    let side_file = dir.path().join("recov-ingest-0").join(".symbol-dict");
    let bytes =
        std::fs::read(&side_file).expect("side-file must exist after an Arrow symbol flush");
    let alpha_pos = bytes
        .windows(6)
        .position(|w| w == b"\x05alpha")
        .expect("alpha persisted");
    let bravo_pos = bytes
        .windows(6)
        .position(|w| w == b"\x05bravo")
        .expect("bravo persisted");
    assert!(
        alpha_pos < bravo_pos,
        "Arrow write-ahead must persist both symbols in id order"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn store_and_forward_flush_arrow_batch_and_wait_commits_at_boundary() {
    use std::sync::Arc;

    use arrow::array::{ArrayRef, Float64Array, Int64Array, RecordBatch, TimestampNanosecondArray};
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

    fn assert_flush_waits_for_ack<F>(
        label: &'static str,
        db: Arc<QuestDb>,
        release_acks: Arc<AtomicBool>,
        frames: &mpsc::Receiver<Vec<u8>>,
        flush: F,
    ) where
        F: FnOnce(Arc<QuestDb>) -> std::result::Result<(), String> + Send + 'static,
    {
        release_acks.store(false, Ordering::SeqCst);
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = done_tx.send(flush(db));
        });

        if let Err(e) = frames.recv_timeout(Duration::from_secs(5)) {
            release_acks.store(true, Ordering::SeqCst);
            let _ = worker.join();
            panic!("{label} did not publish a frame before waiting: {e}");
        }
        match done_rx.recv_timeout(Duration::from_millis(150)) {
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(res) => {
                release_acks.store(true, Ordering::SeqCst);
                let _ = worker.join();
                panic!("{label} returned before the mock server released the ACK: {res:?}");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                release_acks.store(true, Ordering::SeqCst);
                let _ = worker.join();
                panic!("{label} worker exited before the ACK was released");
            }
        }

        release_acks.store(true, Ordering::SeqCst);
        done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("combined Arrow flush must return after ACK release")
            .unwrap_or_else(|e| panic!("{label} failed after ACK release: {e}"));
        worker.join().expect("combined Arrow flush worker");
    }

    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = Arc::new(QuestDb::connect(&conf_for(server.port(), "pool_reap=manual;")).unwrap());

    assert_flush_waits_for_ack(
        "SFA Arrow at-now combined flush",
        Arc::clone(&db),
        Arc::clone(&release_acks),
        &frames,
        |db| {
            let qty: ArrayRef = Arc::new(Int64Array::from(vec![1_i64, 2]));
            let batch = RecordBatch::try_from_iter([("qty", qty)]).unwrap();
            let mut sender = db
                .borrow_sender()
                .map_err(|e| format!("{:?}: {}", e.code(), e.msg()))?;
            sender
                .flush_arrow_batch_at_now_and_wait("trades", &batch, &[], AckLevel::Ok)
                .map_err(|e| format!("{:?}: {}", e.code(), e.msg()))
        },
    );

    assert_flush_waits_for_ack(
        "SFA Arrow at-column combined flush",
        Arc::clone(&db),
        Arc::clone(&release_acks),
        &frames,
        |db| {
            let schema = Arc::new(Schema::new(vec![
                Field::new("price", DataType::Float64, false),
                Field::new("ts", DataType::Timestamp(TimeUnit::Nanosecond, None), false),
            ]));
            let price = Arc::new(Float64Array::from(vec![1.0, 2.0]));
            let ts = Arc::new(TimestampNanosecondArray::from(vec![
                1_700_000_000_000_000_000,
                1_700_000_000_000_000_001,
            ]));
            let batch = RecordBatch::try_new(schema, vec![price, ts]).unwrap();
            let ts_col = crate::ingress::ColumnName::new("ts").unwrap();
            let mut sender = db
                .borrow_sender()
                .map_err(|e| format!("{:?}: {}", e.code(), e.msg()))?;
            sender
                .flush_arrow_batch_at_column_and_wait("trades", &batch, ts_col, &[], AckLevel::Ok)
                .map_err(|e| format!("{:?}: {}", e.code(), e.msg()))
        },
    );
}

#[cfg(feature = "polars-ingress")]
#[test]
fn flush_polars_dataframe_redrives_whole_df_onto_live_endpoint() {
    use crate::ingress::polars::PolarsIngestOptions;
    use polars::prelude::{IntoColumn, NamedFrom, PlSmallStr, Series};

    // Endpoint A is the eager-open primary that dies on the checkpoint `sync`;
    // endpoint B is a live acking server. The DataFrame entry must catch the
    // transient failure, re-borrow onto B, and re-drive every batch there so
    // all rows land (at-least-once).
    let primary = MockServer::spawn_upgrade_then_close(1);
    let (live, frames) = MockServer::spawn_acking_capturing(2);
    let db = QuestDb::connect(&conf_for_endpoints(
        &[primary.port(), live.port()],
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || primary.accepted() == 1),
        "first borrow must connect to the primary; accepted={}",
        primary.accepted()
    );

    let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3, 4, 5, 6]).into_column();
    let df = crate::polars_ffi::df_from_columns(vec![i]).unwrap();

    sender
        .flush_polars_dataframe("trades", &df, &PolarsIngestOptions::new().max_rows(2))
        .expect("failover must re-drive the df onto the live endpoint");
    drop(sender);

    // The whole df (the primary died before any checkpoint committed) is
    // re-driven onto the live endpoint: every row exactly once, none dropped
    // or duplicated, in order.
    let mut got = redriven_i64_rows(&frames);
    got.sort_unstable();
    assert_eq!(
        got,
        vec![1, 2, 3, 4, 5, 6],
        "the live endpoint must receive every row of the re-driven df exactly once"
    );
    assert_eq!(
        primary.accepted(),
        1,
        "the dead primary must not be re-attempted"
    );
}

#[cfg(feature = "polars-ingress")]
#[test]
fn flush_polars_dataframe_redrives_only_the_uncommitted_tail() {
    use crate::ingress::polars::PolarsIngestOptions;
    use polars::prelude::{IntoColumn, NamedFrom, PlSmallStr, Series};

    // The primary acks one full checkpoint and then dies mid-stream. With one
    // row per batch and a 66-row df, the first 64 batches plus the checkpoint
    // `sync`'s commit frame are 65 binary frames; acking 66 commits that
    // checkpoint (`committed = 64`) and lands the kill before the final commit
    // (frame 68), so the entry fails over and must re-drive only the 2-batch
    // tail onto the live endpoint — not the already-committed 64-batch prefix.
    let primary = MockServer::spawn_ack_then_close(1, 66);
    let (live, frames) = MockServer::spawn_acking_capturing(2);
    let db = QuestDb::connect(&conf_for_endpoints(
        &[primary.port(), live.port()],
        "sender_pool_min=1;sender_pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || primary.accepted() == 1),
        "first borrow must connect to the primary; accepted={}",
        primary.accepted()
    );

    let vals: Vec<i64> = (1..=66).collect();
    let i = Series::new(PlSmallStr::from("i"), vals.as_slice()).into_column();
    let df = crate::polars_ffi::df_from_columns(vec![i]).unwrap();

    sender
        .flush_polars_dataframe("trades", &df, &PolarsIngestOptions::new().max_rows(1))
        .expect("failover must re-drive the uncommitted tail onto the live endpoint");
    drop(sender);

    // 66 batches − 64 committed on the primary (one CHECKPOINT_BATCHES run) = 2
    // re-driven; the committed prefix (rows 1..=64) is not re-sent, so only the
    // uncommitted tail rows 65 and 66 reach the live endpoint, exactly once.
    let mut got = redriven_i64_rows(&frames);
    got.sort_unstable();
    assert_eq!(
        got,
        vec![65, 66],
        "only the uncommitted tail rows must reach the live endpoint, exactly once"
    );
    assert_eq!(
        primary.accepted(),
        1,
        "the dead primary must not be re-attempted"
    );
}

#[cfg(feature = "polars-ingress")]
#[test]
fn flush_polars_dataframe_retries_reborrow_connect_until_endpoint_recovers() {
    use crate::ingress::polars::PolarsIngestOptions;
    use polars::prelude::{IntoColumn, NamedFrom, PlSmallStr, Series};

    // The primary is the eager-open connection and dies during the DataFrame
    // flush. The replacement endpoint is initially unreachable but starts
    // accepting inside the reconnect budget, so `flush_polars_dataframe` should
    // keep trying the replacement-connect step instead of surfacing the first
    // SocketError from `reborrow_from_pool`.
    let primary = MockServer::spawn_upgrade_then_close(1);
    let recovery_port = unused_local_port();
    let recovery =
        MockServer::spawn_acking_on_port_after_delay(recovery_port, 2, Duration::from_millis(150));
    let db = QuestDb::connect(&conf_for_endpoints(
        &[primary.port(), recovery_port],
        "sender_pool_min=1;sender_pool_max=2;\
         reconnect_initial_backoff_millis=20;\
         reconnect_max_backoff_millis=20;",
    ))
    .unwrap();

    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || primary.accepted() == 1),
        "first borrow must connect to the primary; accepted={}",
        primary.accepted()
    );

    let i = Series::new(PlSmallStr::from("i"), &[1i64, 2]).into_column();
    let df = crate::polars_ffi::df_from_columns(vec![i]).unwrap();

    sender
        .flush_polars_dataframe("trades", &df, &PolarsIngestOptions::new().max_rows(2))
        .expect("reborrow connect failures must retry until the recovery endpoint is live");
    drop(sender);

    assert!(
        wait_until(Duration::from_secs(2), || recovery.accepted() >= 1),
        "the delayed recovery endpoint must eventually be used"
    );
}

#[cfg(feature = "polars-ingress")]
#[test]
fn flush_polars_dataframe_single_endpoint_commits_in_one_pass() {
    use crate::ingress::polars::PolarsIngestOptions;
    use polars::prelude::{IntoColumn, NamedFrom, PlSmallStr, Series};

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};", server.port())).unwrap();

    let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3, 4]).into_column();
    let df = crate::polars_ffi::df_from_columns(vec![i]).unwrap();

    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    sender
        .flush_polars_dataframe("trades", &df, &PolarsIngestOptions::new().max_rows(2))
        .expect("healthy single-endpoint flush must commit in one pass");
    drop(sender);

    assert_eq!(
        server.accepted(),
        1,
        "a healthy endpoint needs no re-borrow"
    );
    assert_eq!(
        data_frame_count(&frames),
        2,
        "4 rows / 2 per batch = 2 data frames"
    );
}

#[cfg(feature = "polars-ingress")]
#[test]
fn flush_polars_dataframe_applies_column_overrides() {
    use crate::ingress::column_sender::ArrowColumnOverride;
    use crate::ingress::polars::PolarsIngestOptions;
    use polars::prelude::{IntoColumn, NamedFrom, PlSmallStr, Series};

    // `ArrowColumnOverride` was documented for "Polars frames built without
    // pyarrow" yet was previously unreachable through `flush_polars_dataframe`.
    // A Symbol override for a plain Utf8 column must now thread through to every
    // sliced batch and commit cleanly.
    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};", server.port())).unwrap();

    let s = Series::new(PlSmallStr::from("s"), &["a", "b", "c", "d"]).into_column();
    let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3, 4]).into_column();
    let df = crate::polars_ffi::df_from_columns(vec![s, i]).unwrap();

    let overrides = [ArrowColumnOverride::Symbol { column: "s" }];
    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    sender
        .flush_polars_dataframe(
            "trades",
            &df,
            &PolarsIngestOptions::new().max_rows(2).overrides(&overrides),
        )
        .expect("symbol override must thread through the polars path and commit");
    drop(sender);

    assert_eq!(
        data_frame_count(&frames),
        2,
        "4 rows / 2 per batch = 2 data frames with the override applied"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn flush_arrow_batch_at_now_commits_in_one_call() {
    use std::sync::Arc;

    use arrow::array::{Int64Array, RecordBatch};
    use arrow::datatypes::{DataType, Field, Schema};

    // `db.flush_arrow_batch(.., None, ..)` borrows a direct sender internally,
    // publishes one server-stamped batch as a commit boundary, waits for the
    // `Ok` ack, and returns the sender to the pool — all without the caller
    // touching a sender.
    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};", server.port())).unwrap();

    let schema = Arc::new(Schema::new(vec![Field::new("i", DataType::Int64, false)]));
    let arr = Arc::new(Int64Array::from(vec![1i64, 2, 3, 4]));
    let batch = RecordBatch::try_new(schema, vec![arr]).unwrap();

    db.flush_arrow_batch("trades", &batch, None, &[], None)
        .expect("server-stamped single-batch flush must commit in one call");

    assert_eq!(
        server.accepted(),
        1,
        "a healthy endpoint needs no re-borrow"
    );
    assert_eq!(
        data_frame_count(&frames),
        1,
        "one batch = one data frame (the ACKing flush folds the sync in)"
    );
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn flush_arrow_batch_durable_without_opt_in_is_rejected() {
    use std::sync::Arc;

    use crate::ErrorCode;
    use crate::ingress::AckLevel;
    use arrow::array::{Int64Array, RecordBatch};
    use arrow::datatypes::{DataType, Field, Schema};

    // The connect string did not set `request_durable_ack=on`, so a
    // caller-named `Durable` level must be rejected up front rather than
    // accepted without durable opt-in.
    let (server, _frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};", server.port())).unwrap();

    let schema = Arc::new(Schema::new(vec![Field::new("i", DataType::Int64, false)]));
    let arr = Arc::new(Int64Array::from(vec![1i64, 2]));
    let batch = RecordBatch::try_new(schema, vec![arr]).unwrap();

    let err = db
        .flush_arrow_batch("trades", &batch, None, &[], Some(AckLevel::Durable))
        .expect_err("Durable without request_durable_ack=on must be rejected");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
}

#[cfg(feature = "arrow-ingress")]
#[test]
fn flush_arrow_batch_at_column_commits_in_one_call() {
    use std::sync::Arc;

    use arrow::array::{Float64Array, RecordBatch, TimestampNanosecondArray};
    use arrow::datatypes::{DataType, Field, Schema, TimeUnit};

    // The `Some(ts)` arm sources the designated timestamp from the named
    // column and threads through to `flush_arrow_batch_at_column_and_wait`.
    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("ws::addr=127.0.0.1:{};", server.port())).unwrap();

    let schema = Arc::new(Schema::new(vec![
        Field::new("price", DataType::Float64, false),
        Field::new("ts", DataType::Timestamp(TimeUnit::Nanosecond, None), false),
    ]));
    let price = Arc::new(Float64Array::from(vec![1.0, 2.0]));
    let ts = Arc::new(TimestampNanosecondArray::from(vec![
        1_000_000_000,
        2_000_000_000,
    ]));
    let batch = RecordBatch::try_new(schema, vec![price, ts]).unwrap();

    let ts_col = crate::ingress::ColumnName::new("ts").unwrap();
    // Explicit `Some(AckLevel::Ok)` is honored (and valid without the durable
    // opt-in).
    db.flush_arrow_batch(
        "trades",
        &batch,
        Some(ts_col),
        &[],
        Some(crate::ingress::AckLevel::Ok),
    )
    .expect("column-stamped single-batch flush must commit in one call");

    assert_eq!(
        server.accepted(),
        1,
        "a healthy endpoint needs no re-borrow"
    );
    assert_eq!(data_frame_count(&frames), 1, "one batch = one data frame");
}

/// Reader-pool (egress) ergonomic API tests: [`QuestDb::borrow_reader`] /
/// [`crate::BorrowedReader`].
///
/// Gated on `sync-reader-qwp-ws` (which provides `Reader` and implies `_egress`).
/// The mock endpoint completes the WS upgrade (QWP version 1), emits one
/// minimal `SERVER_INFO` frame — the reader's first expected frame at connect
/// — then parks the connection, draining to EOF. That is enough to drive
/// pool borrow / return / grow / reap / cap mechanics without a full query
/// round-trip. The same endpoint also serves any lazily-opened ingestion-sender
/// borrow (which ignores the unsolicited `SERVER_INFO` while parked).
#[cfg(feature = "sync-reader-qwp-ws")]
mod reader_pool {
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::{conf_for, park_connection, wait_until};
    use crate::ErrorCode;
    // Front-door import: `QuestDb` is re-exported at the crate root.
    use crate::QuestDb;
    use crate::tests::qwp_ws::{perform_server_upgrade, write_server_info_frame};

    /// Mock egress endpoint. See the module docs for the per-connection
    /// behaviour (upgrade → `SERVER_INFO` → park).
    struct ReaderMockServer {
        port: u16,
        stop: Arc<AtomicBool>,
        accepted: Arc<AtomicUsize>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl ReaderMockServer {
        fn spawn(max_accepts: usize) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1");
            listener
                .set_nonblocking(true)
                .expect("set_nonblocking on listener");
            let port = listener.local_addr().expect("local_addr").port();

            let stop = Arc::new(AtomicBool::new(false));
            let accepted = Arc::new(AtomicUsize::new(0));
            let stop_c = Arc::clone(&stop);
            let accepted_c = Arc::clone(&accepted);

            let join = thread::Builder::new()
                .name("reader-pool-mock-server".to_string())
                .spawn(move || {
                    let mut handles = Vec::new();
                    while !stop_c.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((mut stream, _)) => {
                                if accepted_c.fetch_add(1, Ordering::SeqCst) >= max_accepts {
                                    // Past budget: drop without upgrading so the
                                    // client observes a failed connect.
                                    continue;
                                }
                                stream
                                    .set_nonblocking(false)
                                    .expect("set_nonblocking(false)");
                                let stop_h = Arc::clone(&stop_c);
                                handles.push(thread::spawn(move || {
                                    if perform_server_upgrade(&mut stream).is_ok()
                                        && write_server_info_frame(&mut stream).is_ok()
                                    {
                                        park_connection(&mut stream, &stop_h);
                                    }
                                }));
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(_) => break,
                        }
                    }
                    for h in handles {
                        let _ = h.join();
                    }
                })
                .expect("spawn reader mock server");

            Self {
                port,
                stop,
                accepted,
                join: Some(join),
            }
        }

        fn port(&self) -> u16 {
            self.port
        }

        fn accepted(&self) -> usize {
            self.accepted.load(Ordering::SeqCst)
        }
    }

    impl Drop for ReaderMockServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(h) = self.join.take() {
                let _ = h.join();
            }
        }
    }

    /// Lazy-init: no readers exist until the first borrow; a borrow then a
    /// drop recycles the same physical connection (no second connect).
    #[test]
    fn reader_borrow_returns_and_recycles_connection() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=2;",
        ))
        .unwrap();

        // The reader pool starts empty; it has no disk-SF recovery pre-open.
        assert_eq!(db.reader_free_count(), 0);
        assert_eq!(db.reader_in_use_count(), 0);

        let reader = db.borrow_reader().expect("borrow reader");
        assert_eq!(db.reader_in_use_count(), 1);
        assert_eq!(db.reader_free_count(), 0);
        let after_first_borrow = server.accepted();

        drop(reader);
        assert_eq!(db.reader_in_use_count(), 0);
        assert_eq!(db.reader_free_count(), 1, "a clean reader must be recycled");

        // Re-borrow reuses the recycled reader — no new connection.
        let _again = db.borrow_reader().expect("re-borrow reuses");
        assert_eq!(db.reader_in_use_count(), 1);
        assert_eq!(db.reader_free_count(), 0);
        assert_eq!(
            server.accepted(),
            after_first_borrow,
            "reuse must not open a new connection"
        );
    }

    /// `dbg_pool_counts` reflects a reader borrow in the `reader` field, leaves
    /// the three sender pools at zero, and returns to baseline on drop. This is
    /// the snapshot the soak harness samples to catch connection / FD leaks.
    #[test]
    fn dbg_pool_counts_tracks_borrow_and_return() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=2;",
        ))
        .unwrap();

        let before = db.dbg_pool_counts();
        assert_eq!(before.reader.in_use, 0);
        assert_eq!(before.reader.free, 0);
        assert_eq!(before.ingress.in_use, 0);
        assert_eq!(before.column_direct.in_use, 0);
        assert_eq!(before.ingress.in_use, 0);

        let reader = db.borrow_reader().expect("borrow reader");
        let during = db.dbg_pool_counts();
        assert_eq!(during.reader.in_use, 1);
        assert_eq!(during.reader.free, 0);
        // Borrowing a reader must not perturb the sender pools.
        assert_eq!(during.ingress.in_use, 0);
        assert_eq!(during.column_direct.in_use, 0);
        assert_eq!(during.ingress.in_use, 0);

        drop(reader);
        let after = db.dbg_pool_counts();
        assert_eq!(after.reader.in_use, 0);
        assert_eq!(
            after.reader.free, 1,
            "a clean reader must be recycled, not leaked"
        );
    }

    /// `BorrowedReader` derefs to the underlying [`crate::egress::Reader`] for
    /// both `&self` and `&mut self` methods.
    #[test]
    fn borrowed_reader_derefs_to_underlying_reader() {
        let server = ReaderMockServer::spawn(4);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=2;",
        ))
        .unwrap();

        let mut reader = db.borrow_reader().expect("borrow reader");
        // Deref (&Reader): a `&self` accessor.
        let _ = reader.bytes_received();
        // DerefMut (&mut Reader): build — but do not execute — a query, which
        // is a `&mut self` method that performs no I/O.
        {
            let _query = reader.prepare("SELECT 1");
        }
        drop(reader);
        assert_eq!(db.reader_in_use_count(), 0);
        assert_eq!(db.reader_free_count(), 1);
    }

    /// The reader pool auto-grows up to `pool_max` under concurrent borrows
    /// and reuses recycled connections afterwards.
    #[test]
    fn reader_pool_grows_and_reuses_physical_connections() {
        let server = ReaderMockServer::spawn(16);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=4;",
        ))
        .unwrap();

        // Without disk-SF recovery, `connect` opens nothing.
        assert_eq!(server.accepted(), 0);

        // Three concurrent reader borrows each open a fresh connection.
        let r1 = db.borrow_reader().expect("r1");
        let r2 = db.borrow_reader().expect("r2 (grow)");
        let r3 = db.borrow_reader().expect("r3 (grow)");
        assert_eq!(db.reader_in_use_count(), 3);
        assert!(
            wait_until(Duration::from_secs(2), || server.accepted() == 3),
            "each reader borrow must open a fresh connection (3 readers); accepted={}",
            server.accepted()
        );

        drop(r1);
        drop(r2);
        drop(r3);
        assert_eq!(db.reader_in_use_count(), 0);
        assert_eq!(db.reader_free_count(), 3);

        // Re-borrowing reuses recycled connections — no new accepts.
        let _a = db.borrow_reader().expect("reuse 1");
        let _b = db.borrow_reader().expect("reuse 2");
        assert_eq!(db.reader_free_count(), 1);
        assert_eq!(server.accepted(), 3, "reuse must not open new connections");
    }

    /// Borrowing past `query_pool_max` with `acquire_timeout_ms=0` fails
    /// fast with an egress `InvalidApiCall` instead of over-committing.
    #[test]
    fn reader_pool_fails_fast_at_cap() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "query_pool_min=1;query_pool_max=2;acquire_timeout_ms=0;",
        ))
        .unwrap();

        let _r1 = db.borrow_reader().expect("r1");
        let _r2 = db.borrow_reader().expect("r2 (grow to cap)");
        let err = db
            .borrow_reader()
            .expect_err("must fail-fast at the reader cap");
        assert_eq!(err.code(), ErrorCode::InvalidApiCall);
        assert!(
            err.msg().contains("Reader pool exhausted"),
            "unexpected message: {}",
            err.msg()
        );
        // The cap rejection must not have leaked an `in_use` slot.
        assert_eq!(db.reader_in_use_count(), 2);
    }

    /// `drop_on_return` forces the reader to be dropped (not recycled) on
    /// return, so the next borrow opens a brand-new connection.
    #[test]
    fn reader_drop_on_return_drops_instead_of_recycling() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=2;",
        ))
        .unwrap();

        let mut reader = db.borrow_reader().expect("borrow");
        reader.drop_on_return();
        drop(reader);

        assert_eq!(db.reader_in_use_count(), 0);
        assert_eq!(
            db.reader_free_count(),
            0,
            "a must-close reader must be dropped, not recycled"
        );

        // The next borrow therefore opens a brand-new connection.
        let _fresh = db.borrow_reader().expect("re-borrow after must-close");
        assert!(
            wait_until(Duration::from_secs(2), || server.accepted() == 2),
            "re-borrow must open a new connection (2 readers total); accepted={}",
            server.accepted()
        );
    }

    /// The reader, unified ingestion, and direct-ingestion pools are capped
    /// and tracked independently: all three can be borrowed at once from a
    /// single `QuestDb` even when each pool's `pool_max` is only 2 (combined
    /// live connection ceiling `3 * pool_max`).
    #[test]
    fn reader_and_sender_pools_are_independent() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=2;",
        ))
        .unwrap();

        let sender = db.borrow_sender().expect("unified sender"); // opens a fresh connection
        let direct = db.borrow_direct_column_sender().expect("direct sender"); // opens a fresh connection
        let reader = db.borrow_reader().expect("reader"); // opens a fresh connection

        // Each pool tracks its own borrow on an independent counter.
        assert_eq!(db.in_use_count(), 1);
        assert_eq!(db.direct_in_use_count(), 1);
        assert_eq!(db.reader_in_use_count(), 1);

        // 1 unified ingress + 1 direct ingress + 1 reader = three independent
        // live connections, each pool capped separately at sender_pool_max=2.
        assert!(
            wait_until(Duration::from_secs(2), || server.accepted() == 3),
            "expected 3 independent connections; accepted={}",
            server.accepted()
        );

        drop(reader);
        assert_eq!(db.reader_in_use_count(), 0);
        assert_eq!(db.reader_free_count(), 1);
        // The sender borrows are unaffected by reader-pool activity.
        assert_eq!(db.in_use_count(), 1);
        assert_eq!(db.direct_in_use_count(), 1);

        drop(direct);
        drop(sender);
        assert_eq!(db.in_use_count(), 0);
        assert_eq!(db.direct_in_use_count(), 0);
        assert_eq!(db.reader_in_use_count(), 0);
        drop(db);
    }

    /// A failed reader build (dead endpoint) releases the `in_use` slot it
    /// reserved instead of permanently burning a pool slot, and surfaces a
    /// connect error rather than a pool-cap error.
    #[test]
    fn reader_build_failure_releases_in_use_slot() {
        let server = ReaderMockServer::spawn(4);
        let port = server.port();
        let db = QuestDb::connect(&conf_for(port, "")).unwrap();
        drop(server); // the port now refuses connections

        assert!(
            wait_until(Duration::from_secs(2), || {
                std::net::TcpStream::connect(("127.0.0.1", port)).is_err()
            }),
            "mock server port must stop accepting after drop"
        );

        let err = db
            .borrow_reader()
            .expect_err("reader build must fail against a dead endpoint");
        assert_ne!(
            err.code(),
            ErrorCode::InvalidApiCall,
            "expected a connect error, not a pool-cap error: {}",
            err.msg()
        );
        assert_eq!(
            db.reader_in_use_count(),
            0,
            "a failed build must not leak an in_use slot"
        );
        assert_eq!(db.reader_free_count(), 0);
        drop(db);
    }

    /// Many threads hammering borrow/return on the reader pool must neither
    /// deadlock nor leak slots, and the free list must never exceed the cap.
    #[test]
    fn concurrent_reader_borrow_and_return_does_not_deadlock_or_leak() {
        let server = ReaderMockServer::spawn(64);
        let db = Arc::new(
            QuestDb::connect(&conf_for(
                server.port(),
                "sender_pool_min=1;sender_pool_max=8;",
            ))
            .unwrap(),
        );
        let mut handles = Vec::new();
        for _ in 0..8 {
            let db = Arc::clone(&db);
            handles.push(thread::spawn(move || {
                for _ in 0..16 {
                    let borrow = db.borrow_reader().expect("borrow_reader under contention");
                    std::hint::black_box(&borrow);
                    thread::yield_now();
                }
            }));
        }
        for h in handles {
            h.join().expect("worker thread");
        }
        // After all workers finish: every borrow returned, nothing leaked, and
        // the free list never exceeded the cap.
        assert_eq!(db.reader_in_use_count(), 0);
        assert!(db.reader_free_count() >= 1);
        assert!(
            db.reader_free_count() <= 8,
            "free list must not exceed pool_max; free={}",
            db.reader_free_count()
        );
    }

    /// `pool_reap=manual`: idle readers above the `query_pool_min` warm floor
    /// are closed only when `reap_idle` is called, and only after the idle
    /// timeout.
    #[test]
    fn manual_reap_closes_idle_readers() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "query_pool_min=0;query_pool_max=3;idle_timeout_ms=50;pool_reap=manual;",
        ))
        .unwrap();

        let b1 = db.borrow_reader().expect("b1");
        let b2 = db.borrow_reader().expect("b2 (grow)");
        drop(b1);
        drop(b2);
        assert_eq!(db.reader_free_count(), 2);

        // Reap before the idle timeout — nothing closed.
        let _ = db.reap_idle();
        assert_eq!(db.reader_free_count(), 2);

        // Past the timeout: with `query_pool_min=0` there is no warm floor,
        // so every idle reader is drained.
        thread::sleep(Duration::from_millis(120));
        let _ = db.reap_idle();
        assert_eq!(
            db.reader_free_count(),
            0,
            "idle readers past the timeout must be reaped"
        );
        drop(db);
    }

    /// `pool_reap=auto`: the background reaper drains idle readers without an
    /// explicit `reap_idle` call.
    #[test]
    fn auto_reaper_closes_idle_readers() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "query_pool_min=0;query_pool_max=3;idle_timeout_ms=100;pool_reap=auto;",
        ))
        .unwrap();

        let b1 = db.borrow_reader().expect("b1");
        let b2 = db.borrow_reader().expect("b2 (grow)");
        drop(b1);
        drop(b2);
        assert_eq!(db.reader_free_count(), 2);

        // The background reaper wakes on a `max(5s, timeout/12)` ticker (the
        // 5s floor applies here). With `query_pool_min=0` there is no warm
        // floor, so every idle reader is drained.
        let reaped = wait_until(Duration::from_secs(8), || db.reader_free_count() == 0);
        assert!(
            reaped,
            "auto reaper failed to drain idle readers; free={}",
            db.reader_free_count()
        );
        drop(db);
    }
}

// ===========================================================================
// Connection lifecycle events
// ===========================================================================

mod conn_event_tests {
    use super::*;
    use crate::ingress::conn_events::{ConnectionEvent, ConnectionEventKind};
    use std::sync::Mutex as StdMutex;
    use std::time::Instant;

    fn collecting_listener() -> (
        Arc<StdMutex<Vec<ConnectionEvent>>>,
        crate::ingress::ConnectionListener,
    ) {
        let seen: Arc<StdMutex<Vec<ConnectionEvent>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen_in_listener = Arc::clone(&seen);
        let listener: crate::ingress::ConnectionListener =
            Arc::new(move |event: &ConnectionEvent| {
                seen_in_listener.lock().unwrap().push(event.clone());
            });
        (seen, listener)
    }

    fn wait_for_kinds(
        seen: &Arc<StdMutex<Vec<ConnectionEvent>>>,
        want: &[ConnectionEventKind],
    ) -> Vec<ConnectionEvent> {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            {
                let events = seen.lock().unwrap();
                let kinds: Vec<ConnectionEventKind> = events.iter().map(|e| e.kind).collect();
                if want.iter().all(|k| kinds.contains(k)) {
                    return events.clone();
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {want:?}; saw {:?}",
                seen.lock()
                    .unwrap()
                    .iter()
                    .map(|e| e.kind)
                    .collect::<Vec<_>>()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn first_borrow_fires_connected_with_endpoint() {
        let server = MockServer::spawn(4);
        let conf = conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=2;pool_reap=manual;",
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        let borrowed = db.borrow_direct_column_sender().expect("borrow");
        let events = wait_for_kinds(&seen, &[ConnectionEventKind::Connected]);
        let connected = events
            .iter()
            .find(|e| e.kind == ConnectionEventKind::Connected)
            .unwrap();
        assert_eq!(connected.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            connected.port.as_deref(),
            Some(server.port().to_string()).as_deref()
        );
        // The delivered counter advances after the listener returns, so it can
        // trail the `seen` push observed by wait_for_kinds.
        assert!(
            wait_until(Duration::from_secs(2), || db.connection_events_delivered()
                == 1),
            "Connected event did not advance the delivered counter"
        );
        assert_eq!(db.connection_events_dropped(), 0);
        drop(borrowed);

        // Pool growth to the same endpoint with no intervening failure is
        // narration-silent: a second fresh connection fires nothing.
        let a = db.borrow_direct_column_sender().expect("reuse");
        let b = db.borrow_direct_column_sender().expect("grow");
        thread::sleep(Duration::from_millis(50));
        assert_eq!(
            seen.lock()
                .unwrap()
                .iter()
                .filter(|e| e.kind == ConnectionEventKind::Connected)
                .count(),
            1
        );
        drop(a);
        drop(b);
    }

    #[test]
    fn unreachable_endpoint_fires_attempt_failed_and_unreachable() {
        // Bind a port and close the listener so connects are refused.
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().unwrap().port()
        };
        let conf = format!(
            "ws::addr=127.0.0.1:{port};auth_timeout=2000;\
             reconnect_max_duration_millis=200;connect_timeout=100;\
             sender_pool_min=1;sender_pool_max=1;pool_reap=manual;"
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        let err = db
            .borrow_direct_column_sender()
            .expect_err("no server listening");
        assert_eq!(err.code(), ErrorCode::SocketError);

        let events = wait_for_kinds(
            &seen,
            &[
                ConnectionEventKind::EndpointAttemptFailed,
                ConnectionEventKind::AllEndpointsUnreachable,
            ],
        );
        let attempt = events
            .iter()
            .find(|e| e.kind == ConnectionEventKind::EndpointAttemptFailed)
            .unwrap();
        assert_eq!(attempt.host.as_deref(), Some("127.0.0.1"));
        assert!(attempt.attempt_number.is_some());
        assert!(attempt.cause_code.is_some());
        let unreachable = events
            .iter()
            .find(|e| e.kind == ConnectionEventKind::AllEndpointsUnreachable)
            .unwrap();
        assert!(
            unreachable
                .cause_msg
                .as_deref()
                .unwrap_or("")
                .contains("unreachable")
        );
    }

    #[test]
    fn failover_to_second_endpoint_fires_failed_over() {
        // First endpoint accepts exactly one connection then refuses; the
        // second endpoint accepts. The first borrow lands on endpoint A
        // (Connected); after its connection dies, the next borrow walks to
        // endpoint B (FailedOver with previous endpoint recorded).
        let server_a = MockServer::spawn(1);
        let server_b = MockServer::spawn(4);
        let conf = conf_for_endpoints(
            &[server_a.port(), server_b.port()],
            "connect_timeout=200;sender_pool_min=1;sender_pool_max=2;pool_reap=manual;",
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        let first = db.borrow_direct_column_sender().expect("first borrow");
        let events = wait_for_kinds(&seen, &[ConnectionEventKind::Connected]);
        let connected_port = events
            .iter()
            .find(|e| e.kind == ConnectionEventKind::Connected)
            .unwrap()
            .port
            .clone()
            .unwrap();
        drop(first);

        // Kill both mock accept loops for endpoint A by stopping the server;
        // then force fresh connects until the pool walks to endpoint B.
        drop(server_a);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(mut borrowed) = db.borrow_direct_column_sender() {
                borrowed.drop_on_return();
                let saw_failover = seen
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|e| e.kind == ConnectionEventKind::FailedOver);
                if saw_failover {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "no FailedOver observed");
            thread::sleep(Duration::from_millis(10));
        }
        let events = seen.lock().unwrap();
        let failed_over = events
            .iter()
            .find(|e| e.kind == ConnectionEventKind::FailedOver)
            .unwrap();
        assert_eq!(
            failed_over.previous_port.as_deref(),
            Some(connected_port.as_str())
        );
        drop(events);
        drop(server_b);
    }

    #[test]
    fn sfa_first_borrow_fires_connected_with_endpoint_and_counter() {
        let server = MockServer::spawn(2);
        let conf = conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=1;pool_reap=manual;close_flush_timeout_millis=0;",
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        let borrowed = db.borrow_sender().expect("SFA borrow");
        let events = wait_for_kinds(&seen, &[ConnectionEventKind::Connected]);
        let connected = events
            .iter()
            .find(|event| event.kind == ConnectionEventKind::Connected)
            .unwrap();
        assert_eq!(connected.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            connected.port.as_deref(),
            Some(server.port().to_string()).as_deref()
        );
        assert!(
            wait_until(Duration::from_secs(2), || db.connection_events_delivered()
                >= 1),
            "SFA Connected event did not advance the delivered counter"
        );
        assert_eq!(db.connection_events_dropped(), 0);
        drop(borrowed);
    }

    #[test]
    fn sfa_connected_observes_negotiated_server_frame_cap() {
        let server_cap = 4096;
        let server = MockServer::spawn_with_max_batch_size(2, server_cap);
        let conf = conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=1;pool_reap=manual;close_flush_timeout_millis=0;",
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        let sender = db.borrow_sender().expect("SFA borrow");
        wait_for_kinds(&seen, &[ConnectionEventKind::Connected]);
        assert_eq!(
            sender.effective_frame_cap_for_test(),
            (server_cap, true),
            "Connected must be delivered after the negotiated frame cap is visible"
        );
    }

    #[test]
    fn sfa_unreachable_endpoint_fires_attempt_failed_and_unreachable() {
        let port = unused_local_port();
        let conf = format!(
            "ws::addr=127.0.0.1:{port};auth_timeout=2000;\
             reconnect_max_duration_millis=200;connect_timeout=100;\
             sender_pool_min=1;sender_pool_max=1;pool_reap=manual;close_flush_timeout_millis=0;"
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        // Pool SFA opens asynchronously: the borrow succeeds and the runner
        // narrates its failed endpoint sweep on the shared source.
        let borrowed = db.borrow_sender().expect("async SFA borrow");
        let events = wait_for_kinds(
            &seen,
            &[
                ConnectionEventKind::EndpointAttemptFailed,
                ConnectionEventKind::AllEndpointsUnreachable,
            ],
        );
        let attempt = events
            .iter()
            .find(|event| event.kind == ConnectionEventKind::EndpointAttemptFailed)
            .unwrap();
        assert_eq!(attempt.host.as_deref(), Some("127.0.0.1"));
        assert!(attempt.attempt_number.is_some());
        assert!(attempt.cause_code.is_some());
        assert!(
            wait_until(Duration::from_secs(2), || db.connection_events_delivered()
                >= 2),
            "SFA endpoint failures did not advance the delivered counter"
        );
        drop(borrowed);
    }

    #[test]
    fn sfa_auth_rejection_fires_auth_failed() {
        let server = MockServer::spawn_auth_rejecting(1);
        let conf = conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=1;pool_reap=manual;close_flush_timeout_millis=0;",
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        let borrowed = db.borrow_sender().expect("async SFA borrow");
        let events = wait_for_kinds(&seen, &[ConnectionEventKind::AuthFailed]);
        let auth = events
            .iter()
            .find(|event| event.kind == ConnectionEventKind::AuthFailed)
            .unwrap();
        assert_eq!(auth.cause_code, Some(ErrorCode::AuthError));
        assert!(auth.attempt_number.is_some());
        assert!(
            wait_until(Duration::from_secs(2), || db.connection_events_delivered()
                >= 1),
            "SFA AuthFailed event did not advance the delivered counter"
        );
        drop(borrowed);
    }

    #[test]
    fn sfa_transport_death_fires_disconnected_then_reconnected() {
        let server = MockServer::spawn_reconnecting(4);
        let conf = conf_for(
            server.port(),
            "sender_pool_min=1;sender_pool_max=1;pool_reap=manual;close_flush_timeout_millis=0;",
        );
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        let mut sender = db.borrow_sender().expect("SFA borrow");
        let mut buffer = one_symbol_buffer(&db, "alpha");
        sender
            .flush_buffer_and_wait(&mut buffer, AckLevel::Ok)
            .expect("runner should reconnect and replay the unacked frame");

        let events = wait_for_kinds(
            &seen,
            &[
                ConnectionEventKind::Connected,
                ConnectionEventKind::Disconnected,
                ConnectionEventKind::Reconnected,
            ],
        );
        let position = |kind| {
            events
                .iter()
                .position(|event| event.kind == kind)
                .expect("event kind present")
        };
        assert!(
            position(ConnectionEventKind::Connected) < position(ConnectionEventKind::Disconnected)
        );
        assert!(
            position(ConnectionEventKind::Disconnected)
                < position(ConnectionEventKind::Reconnected)
        );
        assert!(server.accepted() >= 2, "runner did not reconnect");
        assert!(
            wait_until(Duration::from_secs(2), || db.connection_events_delivered()
                >= 3),
            "SFA reconnect events did not advance the delivered counter"
        );
    }

    #[test]
    fn disk_sfa_recovery_runner_reports_through_connect_time_listener() {
        let dir = TempDir::new().unwrap();
        seed_async_qwp_ws_slot(dir.path(), "late-events-ingest-0", 71);
        let (server, frames) = MockServer::spawn_acking_capturing(1);
        let conf = conf_for_endpoints(
            &[server.port()],
            &format!(
                "sf_dir={};sender_id=late-events;sender_pool_min=1;sender_pool_max=1;\
                 pool_reap=manual;max_background_drainers=1;\
                 close_flush_timeout_millis=0;",
                dir.path().display()
            ),
        );

        // connect() registers the listener before it constructs and starts
        // the dirty-slot recovery runner, so the runner's initial connect is
        // observed even though it happens in the background.
        let (seen, listener) = collecting_listener();
        let db = QuestDb::connect_with_listener(&conf, listener, 0).unwrap();

        wait_for_kinds(&seen, &[ConnectionEventKind::Connected]);
        let payload = frames
            .recv_timeout(Duration::from_secs(5))
            .expect("pre-opened recovery sender should replay its frame");
        assert_eq!(frame_table_name(&payload), "legacy");
        assert!(
            wait_until(Duration::from_secs(2), || db.connection_events_delivered()
                >= 1),
            "recovery runner event did not advance the delivered counter"
        );
    }
}

#[test]
fn borrow_recheck_retires_connection_that_latched_terminal_while_parked() {
    let server = MockServer::spawn_erroring(2, QWP_STATUS_SCHEMA_MISMATCH);
    let seen: Arc<std::sync::Mutex<Vec<crate::ingress::QwpWsSenderError>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_in_handler = Arc::clone(&seen);
    let db = QuestDb::connect_with_handlers(
        &conf_for(
            server.port(),
            "pool_reap=manual;sender_pool_max=2;close_flush_timeout_millis=0;",
        ),
        crate::db::ConnectHandlers {
            error_handler: Some(crate::ingress::QwpWsErrorHandler::new(
                move |error: &crate::ingress::QwpWsSenderError| {
                    seen_in_handler.lock().unwrap().push(error.clone());
                },
            )),
            ..Default::default()
        },
    )
    .unwrap();

    {
        let mut sender = db.borrow_sender().unwrap();
        let mut buffer = one_symbol_buffer(&db, "alpha");
        sender.flush_buffer(&mut buffer).unwrap();
    }

    assert!(
        wait_until(Duration::from_secs(5), || {
            let sender = db.borrow_sender().unwrap();
            let fresh = !sender.must_close_for_test();
            drop(sender);
            server.accepted() >= 2 && fresh
        }),
        "borrow must retire the parked terminal connection and lend a fresh one"
    );
    assert!(
        wait_until(Duration::from_secs(5), || db.rejection_events_delivered()
            >= 1),
        "the rejection nobody waited for must reach the pool handler"
    );
    let seen = seen.lock().unwrap();
    let rejection = seen
        .iter()
        .find(|error| error.category == crate::ingress::QwpWsErrorCategory::SchemaMismatch)
        .expect("handler must receive the schema-mismatch rejection");
    assert_eq!(
        rejection.applied_policy,
        crate::ingress::QwpWsErrorPolicy::Terminal
    );
    assert_eq!(db.rejection_events_dropped(), 0);
}

#[test]
fn reborrowed_lease_wait_covers_only_its_own_publications() {
    let (server, release_acks, frames) = MockServer::spawn_ack_when_released_capturing(1);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_reap=manual;")).unwrap();

    {
        let mut sender = db.borrow_sender().unwrap();
        let mut buffer = one_symbol_buffer(&db, "alpha");
        sender.flush_buffer(&mut buffer).unwrap();
    }
    frames
        .recv_timeout(Duration::from_secs(5))
        .expect("the peer must receive the first lease's frame");

    let mut sender = db.borrow_sender().unwrap();
    let start = Instant::now();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(5))
        .expect("a lease that published nothing has nothing to await");
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "wait must not block on the previous lease's unacked frame"
    );

    let mut buffer = one_symbol_buffer(&db, "bravo");
    sender.flush_buffer(&mut buffer).unwrap();
    let err = sender
        .wait(AckLevel::Ok, Duration::from_millis(150))
        .expect_err("the lease's own publication still awaits the withheld ack");
    assert_eq!(err.code(), ErrorCode::FailoverRetry);

    release_acks.store(true, Ordering::SeqCst);
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("released acks must complete the lease's own frame");
    assert_eq!(db.rejection_events_delivered(), 0);
}

mod sender_conn_event_tests {
    use super::*;
    use crate::ingress::SenderBuilder;
    use crate::ingress::conn_events::{ConnectionEvent, ConnectionEventKind};
    use std::sync::Mutex as StdMutex;
    use std::time::Instant;

    fn collecting_listener() -> (
        Arc<StdMutex<Vec<ConnectionEvent>>>,
        crate::ingress::ConnectionListener,
    ) {
        let seen: Arc<StdMutex<Vec<ConnectionEvent>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen_in_listener = Arc::clone(&seen);
        let listener: crate::ingress::ConnectionListener =
            Arc::new(move |event: &ConnectionEvent| {
                seen_in_listener.lock().unwrap().push(event.clone());
            });
        (seen, listener)
    }

    fn wait_for_kind(
        seen: &Arc<StdMutex<Vec<ConnectionEvent>>>,
        want: ConnectionEventKind,
    ) -> ConnectionEvent {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(event) = seen
                .lock()
                .unwrap()
                .iter()
                .find(|e| e.kind == want)
                .cloned()
            {
                return event;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {want:?}; saw {:?}",
                seen.lock()
                    .unwrap()
                    .iter()
                    .map(|e| e.kind)
                    .collect::<Vec<_>>()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn sender_build_fires_connected() {
        let server = MockServer::spawn(2);
        let (seen, listener) = collecting_listener();
        let sender = SenderBuilder::from_conf(conf_for(server.port(), ""))
            .unwrap()
            .connection_listener(listener, 0)
            .unwrap()
            .build()
            .unwrap();
        let connected = wait_for_kind(&seen, ConnectionEventKind::Connected);
        assert_eq!(connected.host.as_deref(), Some("127.0.0.1"));
        assert_eq!(
            connected.port.as_deref(),
            Some(server.port().to_string()).as_deref()
        );
        // The delivered counter advances after the listener returns, so it can
        // trail the `seen` push observed by wait_for_kind.
        assert!(
            wait_until(Duration::from_secs(2), || sender
                .connection_events_delivered()
                == 1),
            "Connected event did not advance the delivered counter"
        );
        assert_eq!(sender.connection_events_dropped(), 0);
        drop(sender);
    }

    #[test]
    fn sender_unreachable_fires_attempt_failed_and_unreachable() {
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            listener.local_addr().unwrap().port()
        };
        let (seen, listener) = collecting_listener();
        let conf = format!(
            "ws::addr=127.0.0.1:{port};auth_timeout=2000;\
             reconnect_max_duration_millis=200;connect_timeout=100;"
        );
        let err = SenderBuilder::from_conf(conf)
            .unwrap()
            .connection_listener(listener, 0)
            .unwrap()
            .build()
            .expect_err("no server listening");
        assert_eq!(err.code(), ErrorCode::SocketError);
        let attempt = wait_for_kind(&seen, ConnectionEventKind::EndpointAttemptFailed);
        assert!(attempt.attempt_number.is_some());
        assert!(attempt.cause_code.is_some());
        wait_for_kind(&seen, ConnectionEventKind::AllEndpointsUnreachable);
    }

    #[test]
    fn second_builder_listener_rejected() {
        let (_seen, listener) = collecting_listener();
        let (_seen2, listener2) = collecting_listener();
        let err = SenderBuilder::from_conf("ws::addr=127.0.0.1:1;")
            .unwrap()
            .connection_listener(listener, 0)
            .unwrap()
            .connection_listener(listener2, 0)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }

    #[cfg(feature = "sync-sender-http")]
    #[test]
    fn non_ws_builder_listener_rejected() {
        let (_seen, listener) = collecting_listener();
        let err = SenderBuilder::from_conf("http::addr=127.0.0.1:9000;")
            .unwrap()
            .connection_listener(listener, 0)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
    }
}
