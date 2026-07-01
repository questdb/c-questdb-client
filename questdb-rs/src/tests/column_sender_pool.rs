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

//! Column-sender pool + flush integration tests (WS-0 through WS-2).
//!
//! - WS-0: eager-open, borrow/return, multi-thread concurrent borrows,
//!   fail-fast at `pool_max`, idle reaper.
//! - WS-1: synchronous `flush` round-trip for empty chunks; `AckLevel::Durable`
//!   opt-in guard.
//! - WS-2: numeric / fixed-width column round-trip with a designated
//!   timestamp; schema reuse across repeated flushes.
//!
//! Pool slots are real [`crate::ingress::Sender`] instances. The mock server
//! defined here accepts the HTTP→WebSocket upgrade so `Sender::build()`
//! succeeds, then either parks on the connection or reads each QWP frame
//! and replies with an OK ack (status 0x00).

use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ErrorCode;
use crate::QuestDb;
use crate::ingress::AckLevel;
use crate::ingress::column_sender::Chunk;
use crate::tests::qwp_ws::{
    perform_server_upgrade, perform_server_upgrade_durable, read_frame,
    write_qwp_durable_ack_response, write_qwp_error_response, write_qwp_ok_response,
    write_qwp_ok_response_with_table_entries, write_server_frame,
};
use tempfile::TempDir;

const QWP_STATUS_SCHEMA_MISMATCH: u8 = 0x03;

#[derive(Clone, Debug)]
enum MockMode {
    /// Park the connection after upgrade — used by pool-only tests.
    Park,
    /// Read every QWP frame the client sends and reply with an OK ack.
    AckEachFrame,
    /// Reply to every QWP frame with an error ack carrying `status`.
    ErrorEachFrame(u8),
    /// Reject the first QWP frame with `status`, then ACK later frames.
    ErrorFirstThenAck(u8),
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
    #[cfg(feature = "polars-ingress")]
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

    fn spawn_acking(max_accepts: usize) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::AckEachFrame)
    }

    fn spawn_erroring(max_accepts: usize, status: u8) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::ErrorEachFrame(status))
    }

    fn spawn_error_first_then_ack(max_accepts: usize, status: u8) -> Self {
        Self::spawn_with_mode(max_accepts, MockMode::ErrorFirstThenAck(status))
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

    #[cfg(feature = "polars-ingress")]
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

    #[cfg(feature = "polars-ingress")]
    fn spawn_acking_on_port_after_delay(port: u16, max_accepts: usize, delay: Duration) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop_clone = Arc::clone(&stop);
        let accepted_clone = Arc::clone(&accepted);

        let join = thread::Builder::new()
            .name("column-sender-pool-delayed-mock-server".to_string())
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
            .name("column-sender-pool-mock-server".to_string())
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
                if accepted.fetch_add(1, Ordering::SeqCst) >= max_accepts {
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
                    // Durable mode needs the `X-QWP-Durable-Ack: enabled` upgrade
                    // header; every other mode uses the plain upgrade.
                    let upgraded = if matches!(mode, MockMode::AckEachFrameDurable) {
                        perform_server_upgrade_durable(&mut stream).is_ok()
                    } else {
                        perform_server_upgrade(&mut stream).is_ok()
                    };
                    if upgraded {
                        match mode {
                            MockMode::Park => park_connection(&mut stream, &stop),
                            MockMode::AckEachFrame => ack_each_frame(&mut stream, &stop, capture),
                            MockMode::AckEachFrameDurable => {
                                ack_each_frame_durable(&mut stream, &stop, capture)
                            }
                            MockMode::ErrorEachFrame(status) => {
                                error_each_frame(&mut stream, &stop, status)
                            }
                            MockMode::ErrorFirstThenAck(status) => {
                                error_first_then_ack(&mut stream, &stop, status)
                            }
                            MockMode::AckWhenReleased(release) => {
                                ack_when_released(&mut stream, &stop, &release, capture)
                            }
                            MockMode::UpgradeThenClose => {
                                // Drop the stream immediately: the client's
                                // next read sees EOF.
                            }
                            #[cfg(feature = "polars-ingress")]
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

fn error_first_then_ack(stream: &mut std::net::TcpStream, stop: &AtomicBool, status: u8) {
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
                let result = if next_wire_seq == 0 {
                    write_qwp_error_response(stream, status, next_wire_seq, b"injected")
                } else {
                    write_qwp_ok_response(stream, next_wire_seq)
                };
                if result.is_err() {
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
#[cfg(feature = "polars-ingress")]
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
        "qwpws::addr=127.0.0.1:{port};auth_timeout=2000;reconnect_max_duration_millis=1000;{extras}"
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
    format!("qwpws::addr={addrs};auth_timeout=2000;reconnect_max_duration_millis=1000;{extras}")
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
        .symbol_dict_i32("sym", &CODES, &OFFSETS, symbol, None)
        .unwrap();
    chunk.designated_timestamp_nanos(timestamp).unwrap();
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

fn read_symbol_prefix(payload: &[u8]) -> Vec<Vec<u8>> {
    const QWP_HEADER_LEN: usize = 12;
    let mut pos = QWP_HEADER_LEN;
    assert_eq!(read_test_varint(payload, &mut pos), 0, "delta_start");
    let count = read_test_varint(payload, &mut pos);
    (0..count)
        .map(|_| read_test_bytes(payload, &mut pos).to_vec())
        .collect()
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

#[test]
fn refuses_non_qwp_ws_schema() {
    let err = QuestDb::connect("http::addr=localhost:9000;").unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("QWP/WebSocket"));
}

#[test]
fn store_and_forward_pool_allows_one_active_borrower() {
    let server = MockServer::spawn(2);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!("sf_dir={};pool_reap=manual;", dir.path().display()),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let sender = db.borrow_column_sender().unwrap();
    let err = db.borrow_column_sender().unwrap_err();
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("store-and-forward"), "{}", err.msg());

    drop(sender);
    let _again = db.borrow_column_sender().unwrap();
}

fn check_store_and_forward_sync_reports_drop_and_continue_once(extras: &str) {
    let server = MockServer::spawn_error_first_then_ack(1, QWP_STATUS_SCHEMA_MISMATCH);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_column_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty1 = [1_i64];
    let ts1 = [1_i64];
    chunk.column_i64("qty", &qty1, None).unwrap();
    chunk.designated_timestamp_nanos(&ts1).unwrap();
    sender.flush(&mut chunk).unwrap();
    let err = sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect_err("first SFA frame is schema-rejected");
    assert_eq!(err.code(), ErrorCode::ServerRejection);
    assert_eq!(
        err.qwp_ws_rejection().and_then(|error| error.status),
        Some(QWP_STATUS_SCHEMA_MISMATCH)
    );

    let qty2 = [2_i64];
    let ts2 = [2_i64];
    chunk.column_i64("qty", &qty2, None).unwrap();
    chunk.designated_timestamp_nanos(&ts2).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("old drop-and-continue rejection must not poison later sync");
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
    let mut sender = db.borrow_column_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.designated_timestamp_nanos(&ts).unwrap();
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
        c1.designated_timestamp_nanos(&ts).unwrap();
        sender.flush(&mut c1).unwrap(); // first frame: committed inline

        let mut c2 = Chunk::new("trades");
        c2.column_i64("qty", &qty, None).unwrap();
        c2.designated_timestamp_nanos(&ts).unwrap();
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
    chunk.designated_timestamp_nanos(&ts).unwrap();

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
    chunk.column_varchar("v", &offsets, &bytes, None).unwrap();
    chunk.designated_timestamp_nanos(&ts).unwrap();

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
    chunk.designated_timestamp_nanos(&ts).unwrap();

    let mut sender = db.borrow_column_sender().unwrap();
    sender
        .flush(&mut chunk)
        .expect("oversize chunk splits and appends");
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("all split frames commit");

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

fn check_store_and_forward_drop_on_return_drops_backend_and_reopens_on_next_borrow(extras: &str) {
    let server = MockServer::spawn(4);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();

    {
        let mut sender = db.borrow_column_sender().unwrap();
        sender.drop_on_return();
        assert!(sender.must_close_for_test());
    }

    assert_eq!(db.free_count(), 0, "forced SFA backend must not recycle");
    assert_eq!(db.in_use_count(), 0);

    let _again = db
        .borrow_column_sender()
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
    let mut sender = db.borrow_column_sender().unwrap();

    let ts1 = [1_i64];
    let mut first = Chunk::new("trades");
    append_one_symbol_row(&mut first, b"alpha", &ts1);
    sender.flush(&mut first).unwrap();
    assert!(
        first.is_empty(),
        "successful SFA flush should clear the chunk"
    );
    let first_payload = frames.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(read_symbol_prefix(&first_payload), vec![b"alpha".to_vec()]);

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
    assert_eq!(
        read_symbol_prefix(&third_payload),
        vec![b"alpha".to_vec(), b"gamma".to_vec()],
        "failed bravo publish must not remain in the replay symbol dictionary"
    );
}

fn check_store_and_forward_flush_and_wait_waits_for_ok_boundary(extras: &str) {
    let server = MockServer::spawn_acking(1);
    let conf = conf_for_endpoints(&[server.port()], extras);
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_column_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.designated_timestamp_nanos(&ts).unwrap();
    sender
        .flush(&mut chunk)
        .expect("publish to the local SFA queue");
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
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
    let mut sender = db.borrow_column_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.designated_timestamp_nanos(&ts).unwrap();
    // Durable is validated by `wait`, the ack barrier; with no `flush` the
    // chunk is never published and stays replayable.
    let err = sender
        .wait(AckLevel::Durable, Duration::from_secs(30))
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
    let mut sender = db.borrow_column_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.designated_timestamp_nanos(&ts).unwrap();
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
    let mut sender = db.borrow_column_sender().unwrap();

    let mut chunk = Chunk::new("trades");
    let qty = [1_i64];
    let ts = [1_i64];
    chunk.column_i64("qty", &qty, None).unwrap();
    chunk.designated_timestamp_nanos(&ts).unwrap();
    sender
        .flush(&mut chunk)
        .expect("publish to the local SFA queue");
    let err = sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
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
    let mut sender = db.borrow_column_sender().unwrap();
    assert!(sender.is_store_and_forward());
    // Bound the no-progress wait so a protocol regression fails fast instead of
    // blocking on the 30s request timeout.

    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &[7_i64], None).unwrap();
    chunk.designated_timestamp_nanos(&[1_i64]).unwrap();
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
        "qwpws::addr=127.0.0.1:{},127.0.0.1:{};auth_timeout=2000;\
         reconnect_max_duration_millis=10000;pool_reap=manual;",
        dead.port(),
        live.port()
    );
    let db = QuestDb::connect(&conf).unwrap();
    let mut sender = db.borrow_column_sender().expect("borrow");
    assert!(sender.is_store_and_forward());

    let mut chunk = Chunk::new("trades");
    chunk.column_i64("qty", &[7_i64], None).unwrap();
    chunk.designated_timestamp_nanos(&[1_i64]).unwrap();
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
// `borrow_column_sender` uses: disk-backed SF (`sf_dir` set, single-borrower)
// and in-memory SF (no `sf_dir`, pools freely). The body is backend-agnostic;
// only the conf differs. The `_dir` `TempDir` outlives each `check_*` call
// because the call opens and drops its `QuestDb` before the wrapper returns.
fn sf_disk_extras(dir: &TempDir, extra: &str) -> String {
    format!("sf_dir={};{extra}", dir.path().display())
}

#[test]
fn store_and_forward_sync_reports_drop_and_continue_once_disk() {
    let dir = TempDir::new().unwrap();
    check_store_and_forward_sync_reports_drop_and_continue_once(&sf_disk_extras(
        &dir,
        "pool_reap=manual;",
    ));
}
#[test]
fn store_and_forward_sync_reports_drop_and_continue_once_memory() {
    check_store_and_forward_sync_reports_drop_and_continue_once("pool_reap=manual;");
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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=3;pool_max=4;")).unwrap();
    // Lazy pool, like the row-major sender: `connect` opens nothing.
    assert_eq!(db.free_count(), 0);
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(server.accepted(), 0);
    // The first borrow opens exactly one connection.
    let _b = db.borrow_column_sender().expect("borrow");
    assert_eq!(db.in_use_count(), 1);
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 1),
        "first borrow opens one connection; accepted={}",
        server.accepted()
    );
}

#[test]
fn borrow_column_sender_is_in_memory_store_and_forward_without_sf_dir() {
    // Without `sf_dir`, `borrow_column_sender` yields an in-memory
    // store-and-forward sender (mirroring the row-major sender). Unlike
    // disk-backed SF it pools freely up to `pool_max` rather than being capped
    // to a single active borrower.
    let server = MockServer::spawn(8);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=3;")).unwrap();

    let b1 = db.borrow_column_sender().expect("b1");
    assert!(
        b1.is_store_and_forward(),
        "borrow_column_sender must be store-and-forward even without sf_dir"
    );

    // In-memory SF pools freely: concurrent borrows succeed (disk-backed SF
    // would reject the second with a single-borrower error).
    let b2 = db
        .borrow_column_sender()
        .expect("b2 (in-memory SF pools freely)");
    let b3 = db
        .borrow_column_sender()
        .expect("b3 (in-memory SF pools freely)");
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
    let err = db
        .borrow_column_sender()
        .expect_err("must fail-fast at pool_max");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());
}

#[test]
fn borrow_and_return_reuses_connection() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();
    // Lazy pool: nothing open until the first borrow.
    assert_eq!(db.free_count(), 0);
    {
        let _borrow = db.borrow_column_sender().expect("borrow");
        assert_eq!(db.free_count(), 0);
        assert_eq!(db.in_use_count(), 1);
    }
    // Drop returns the sender to the pool.
    assert_eq!(db.free_count(), 1);
    assert_eq!(db.in_use_count(), 0);
    // Re-borrow reuses it — the server only ever accepted one connection.
    let _again = db.borrow_column_sender().expect("reuse");
    assert_eq!(server.accepted(), 1);
}

#[cfg(feature = "ffi-support")]
#[test]
fn owned_column_sender_observes_pool_close_and_drops_after_close() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_size=1;pool_max=2;close_flush_timeout_millis=50;",
    ))
    .unwrap();
    let owned = db
        .borrow_column_sender_owned()
        .expect("borrow owned column sender");
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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=3;")).unwrap();
    let b1 = db.borrow_column_sender().expect("b1");
    let b2 = db.borrow_column_sender().expect("b2 (auto-grow)");
    let b3 = db.borrow_column_sender().expect("b3 (auto-grow)");
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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();
    let _b1 = db.borrow_column_sender().expect("b1");
    let _b2 = db.borrow_column_sender().expect("b2");
    let err = db
        .borrow_column_sender()
        .expect_err("must fail-fast at cap");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());
}

// ---------------------------------------------------------------------------
// Direct column-sender pool (`borrow_direct_column_sender`).
//
// A second, always-direct pool that exists independently of `sf_dir`: it is
// lazy (no eager open), never store-and-forward, and poolable up to `pool_max`
// on its own free list, separate from the main `borrow_column_sender` pool.
// ---------------------------------------------------------------------------

#[test]
fn direct_pool_is_lazy_and_hands_out_direct_senders() {
    let server = MockServer::spawn(4);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=4;")).unwrap();

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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=4;")).unwrap();

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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=3;")).unwrap();

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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

    let _main = db.borrow_column_sender().expect("main borrow");
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.direct_in_use_count(), 0);

    let _direct = db.borrow_direct_column_sender().expect("direct borrow");
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.direct_in_use_count(), 1);

    // Each pool enforces `pool_max` on its own free list, so the main pool can
    // still grow to its cap while a direct borrow is outstanding.
    let _main2 = db.borrow_column_sender().expect("main grows to cap");
    assert_eq!(db.in_use_count(), 2);
    assert_eq!(db.direct_in_use_count(), 1);
}

#[test]
fn direct_pool_is_direct_even_when_sf_dir_is_set() {
    // With `sf_dir` the main pool is store-and-forward (single active
    // borrower). The direct pool must still hand out a plain direct sender,
    // from its own free list, so a direct borrow co-exists with the single
    // SFA borrow.
    let server = MockServer::spawn(4);
    let dir = TempDir::new().unwrap();
    let conf = conf_for_endpoints(
        &[server.port()],
        &format!("sf_dir={};pool_reap=manual;", dir.path().display()),
    );
    let db = QuestDb::connect(&conf).unwrap();

    let main = db.borrow_column_sender().expect("main SFA borrow");
    assert!(
        main.is_store_and_forward(),
        "with sf_dir the main pool must be store-and-forward"
    );
    // The main pool is single-borrower in SFA mode.
    let err = db.borrow_column_sender().expect_err("second main borrow");
    assert!(err.msg().contains("store-and-forward"), "{}", err.msg());

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
    drop(main);
    drop(db);
}

#[test]
fn direct_pool_reaps_idle_connections() {
    let server = MockServer::spawn(4);
    // Short idle timeout + manual reap so the test drives reaping itself.
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_size=1;pool_max=4;pool_idle_timeout_ms=1;pool_reap=manual;",
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
fn row_sender_pool_borrows_recycles_and_caps() {
    let server = MockServer::spawn_acking(16);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

    // The row-sender pool is lazy: nothing exists until the first borrow.
    assert_eq!(db.row_sender_free_count(), 0);
    assert_eq!(db.row_sender_in_use_count(), 0);

    {
        let _s1 = db.borrow_row_sender().expect("borrow row sender");
        assert_eq!(db.row_sender_in_use_count(), 1);
        assert_eq!(db.row_sender_free_count(), 0);
    } // Drop returns it to the row pool.

    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(
        db.row_sender_free_count(),
        1,
        "a clean row sender must be recycled on return"
    );

    // Re-borrow reuses the recycled sender (no new connection).
    let s2 = db.borrow_row_sender().expect("reuse recycled");
    assert_eq!(db.row_sender_free_count(), 0);
    assert_eq!(db.row_sender_in_use_count(), 1);

    // Auto-grow up to the row pool's independent `pool_max`.
    let s3 = db.borrow_row_sender().expect("grow to pool_max");
    assert_eq!(db.row_sender_in_use_count(), 2);

    // A third concurrent borrow exceeds pool_max=2 — fail-fast.
    let err = db.borrow_row_sender().expect_err("must fail-fast at cap");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());

    drop(s2);
    drop(s3);
    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(db.row_sender_free_count(), 2);
    drop(db);
}

#[test]
fn row_sender_pool_flush_round_trip() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

    let mut sender = db.borrow_row_sender().expect("borrow row sender");
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
        .flush_and_get_fsn(&mut buf)
        .expect("row-major flush over a pooled QWP/WS sender")
        .expect("non-empty buffer publishes a frame");
    assert_eq!(sender.published_fsn().expect("published fsn"), Some(fsn));
    sender
        .wait(AckLevel::Ok, Duration::from_secs(2))
        .expect("row-major wait over a pooled QWP/WS sender");
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
            .flush_and_keep_and_get_fsn(&empty)
            .expect("empty keep flush"),
        None
    );
    #[cfg(feature = "sync-sender-http")]
    sender
        .flush_and_keep_with_flags(&empty, false)
        .expect("empty non-transactional flush with explicit flags");

    drop(sender);

    // The flushed sender is clean, so it returns to the pool for reuse.
    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(db.row_sender_free_count(), 1);
    drop(db);
}

#[cfg(feature = "ffi-support")]
#[test]
fn row_sender_owned_borrow_flushes_and_recycles() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

    // The owned handle is the FFI escape hatch backing
    // `questdb_db_borrow_row_sender`: it carries an `Arc<DbInner>` and
    // returns the sender to the pool on Drop.
    let mut owned = db
        .borrow_row_sender_owned()
        .expect("borrow owned row sender");
    assert_eq!(db.row_sender_in_use_count(), 1);
    assert!(!owned.must_close());

    let sender = owned.get_mut();
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
        .flush(&mut buf)
        .expect("row-major flush over an owned pooled QWP/WS sender");
    drop(owned);

    // Clean sender returns to the pool for reuse.
    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(db.row_sender_free_count(), 1);

    // `_with_retry` with a zero budget makes a single attempt and reuses the
    // recycled sender.
    let owned2 = db
        .borrow_row_sender_owned_with_retry(Duration::ZERO)
        .expect("owned retry borrow");
    assert_eq!(db.row_sender_in_use_count(), 1);
    assert_eq!(db.row_sender_free_count(), 0);
    drop(owned2);
    assert_eq!(db.row_sender_free_count(), 1);
    drop(db);
}

#[cfg(feature = "ffi-support")]
#[test]
fn row_sender_owned_mark_must_close_drops_not_recycles() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

    let mut owned = db.borrow_row_sender_owned().expect("borrow owned");
    owned.mark_must_close();
    assert!(owned.must_close());
    drop(owned);

    // Marked must-close: dropped, not recycled.
    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(db.row_sender_free_count(), 0);
    drop(db);
}

#[cfg(feature = "ffi-support")]
#[test]
fn owned_row_sender_observes_pool_close_and_drops_after_close() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_size=1;pool_max=2;close_flush_timeout_millis=50;",
    ))
    .unwrap();

    let owned = db
        .borrow_row_sender_owned()
        .expect("borrow owned row sender");
    assert_eq!(db.row_sender_in_use_count(), 1);
    assert!(!owned.pool_closed());
    assert!(!owned.must_close());

    db.close();
    assert!(owned.pool_closed());
    assert!(owned.must_close());
    drop(owned);
}

#[test]
fn manual_reap_closes_idle_row_senders() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_size=1;pool_max=3;pool_idle_timeout_ms=50;pool_reap=manual;",
    ))
    .unwrap();

    // Park two row senders in the free list.
    let b1 = db.borrow_row_sender().expect("b1");
    let b2 = db.borrow_row_sender().expect("b2 (grow)");
    drop(b1);
    drop(b2);
    assert_eq!(db.row_sender_free_count(), 2);

    // Reap before the idle timeout — nothing closed.
    assert_eq!(db.reap_idle(), 0);
    assert_eq!(db.row_sender_free_count(), 2);

    // Past the timeout: the row pool keeps no warm floor, so both are reaped.
    thread::sleep(Duration::from_millis(120));
    let closed = db.reap_idle();
    assert_eq!(closed, 2, "both idle row senders must be reaped");
    assert_eq!(db.row_sender_free_count(), 0);
    drop(db);
}

#[test]
fn row_sender_pool_grows_and_reuses_physical_connections() {
    let server = MockServer::spawn_acking(16);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=4;")).unwrap();

    // Lazy pools: `connect` opens nothing.
    assert_eq!(server.accepted(), 0);

    // Three concurrent row borrows each open a fresh connection.
    let r1 = db.borrow_row_sender().expect("r1");
    let r2 = db.borrow_row_sender().expect("r2 (grow)");
    let r3 = db.borrow_row_sender().expect("r3 (grow)");
    assert_eq!(db.row_sender_in_use_count(), 3);
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 3),
        "each row borrow must open a fresh connection; accepted={}",
        server.accepted()
    );

    drop(r1);
    drop(r2);
    drop(r3);
    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(db.row_sender_free_count(), 3);

    // Re-borrowing reuses recycled connections — no new accepts.
    let _a = db.borrow_row_sender().expect("reuse 1");
    let _b = db.borrow_row_sender().expect("reuse 2");
    assert_eq!(db.row_sender_free_count(), 1);
    assert_eq!(server.accepted(), 3, "reuse must not open new connections");
}

#[test]
fn row_sender_drop_on_return_drops_instead_of_recycling() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

    let mut sender = db.borrow_row_sender().expect("borrow");
    sender.drop_on_return();
    drop(sender);

    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(
        db.row_sender_free_count(),
        0,
        "a must-close row sender must be dropped, not recycled"
    );

    // The next borrow therefore opens a brand-new connection.
    let _fresh = db.borrow_row_sender().expect("re-borrow after drop");
    assert!(
        wait_until(Duration::from_secs(2), || server.accepted() == 2),
        "re-borrow must open a new connection (2 row borrows total); accepted={}",
        server.accepted()
    );
}

#[test]
fn row_and_column_senders_borrowed_together_are_independent() {
    let server = MockServer::spawn_acking(16);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

    let col = db.borrow_column_sender().expect("column sender");
    let mut row = db.borrow_row_sender().expect("row sender");

    // Each pool tracks its own borrow on an independent counter.
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.row_sender_in_use_count(), 1);

    // The row sender works while a column sender is concurrently held.
    let mut buf = row.new_buffer();
    buf.table("trades")
        .unwrap()
        .symbol("sym", "x")
        .unwrap()
        .column_f64("price", 1.0)
        .unwrap()
        .at_now()
        .unwrap();
    row.flush(&mut buf)
        .expect("row flush while a column sender is also borrowed");

    drop(row);
    assert_eq!(db.row_sender_in_use_count(), 0);
    assert_eq!(db.row_sender_free_count(), 1);
    // The column borrow is unaffected by row-pool activity.
    assert_eq!(db.in_use_count(), 1);
    assert_eq!(db.free_count(), 0);

    drop(col);
    assert_eq!(db.in_use_count(), 0);
    assert_eq!(db.free_count(), 1);
    drop(db);
}

#[test]
fn concurrent_row_borrow_and_return_does_not_deadlock_or_leak() {
    let server = MockServer::spawn_acking(32);
    let db =
        Arc::new(QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=8;")).unwrap());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let db = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for _ in 0..16 {
                let borrow = db
                    .borrow_row_sender()
                    .expect("borrow_row_sender under contention");
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
    assert_eq!(db.row_sender_in_use_count(), 0);
    assert!(db.row_sender_free_count() >= 1);
    assert!(
        db.row_sender_free_count() <= 8,
        "free list must not exceed pool_max; free={}",
        db.row_sender_free_count()
    );
}

#[test]
fn auto_reaper_closes_idle_row_senders() {
    let server = MockServer::spawn_acking(8);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_size=1;pool_max=3;pool_idle_timeout_ms=100;pool_reap=auto;",
    ))
    .unwrap();
    let b1 = db.borrow_row_sender().expect("b1");
    let b2 = db.borrow_row_sender().expect("b2 (grow)");
    drop(b1);
    drop(b2);
    assert_eq!(db.row_sender_free_count(), 2);

    // The background reaper wakes on a `max(5s, timeout/12)` ticker (the 5s
    // floor applies here). The row pool keeps no warm floor, so every idle row
    // sender is drained.
    let reaped = wait_until(Duration::from_secs(8), || db.row_sender_free_count() == 0);
    assert!(
        reaped,
        "auto reaper failed to drain idle row senders; free={}",
        db.row_sender_free_count()
    );
    drop(db);
}

#[test]
fn row_sender_build_failure_releases_in_use_slot() {
    // Bring the pool up against a live server, then kill the server so a
    // subsequent row-sender build cannot connect. The
    // failed build must release the `in_use` slot it reserved rather than
    // permanently burning a pool slot.
    let server = MockServer::spawn_acking(4);
    let port = server.port();
    let db = QuestDb::connect(&format!(
        "qwpws::addr=127.0.0.1:{port};auth_timeout=500;reconnect_max_duration_millis=100;"
    ))
    .unwrap();
    drop(server); // the port now refuses connections

    // Make sure the port is actually closed before exercising the build path.
    assert!(
        wait_until(Duration::from_secs(2), || {
            std::net::TcpStream::connect(("127.0.0.1", port)).is_err()
        }),
        "mock server port must stop accepting after drop"
    );

    let err = db
        .borrow_row_sender()
        .expect_err("build must fail against a dead endpoint");
    assert_ne!(
        err.code(),
        ErrorCode::InvalidApiCall,
        "expected a connect error, not a pool-cap error: {}",
        err.msg()
    );
    assert_eq!(
        db.row_sender_in_use_count(),
        0,
        "a failed build must not leak an in_use slot"
    );
    assert_eq!(db.row_sender_free_count(), 0);
    drop(db);
}

#[test]
fn concurrent_borrow_and_return_does_not_deadlock_or_leak() {
    let server = MockServer::spawn(16);
    let db =
        Arc::new(QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=8;")).unwrap());
    let mut handles = Vec::new();
    for _ in 0..8 {
        let db = Arc::clone(&db);
        handles.push(thread::spawn(move || {
            for _ in 0..16 {
                let borrow = db
                    .borrow_column_sender()
                    .expect("borrow_column_sender under contention");
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
        "pool_size=1;pool_max=3;pool_idle_timeout_ms=50;pool_reap=manual;",
    ))
    .unwrap();
    let b1 = db.borrow_column_sender().expect("b1");
    let b2 = db.borrow_column_sender().expect("b2 (grow)");
    let b3 = db.borrow_column_sender().expect("b3 (grow)");
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
        "pool_size=3;pool_max=5;pool_idle_timeout_ms=50;pool_reap=manual;",
    ))
    .unwrap();
    let b1 = db.borrow_column_sender().expect("b1");
    let b2 = db.borrow_column_sender().expect("b2");
    let b3 = db.borrow_column_sender().expect("b3 (grow)");
    let b4 = db.borrow_column_sender().expect("b4 (grow)");
    // Two stay borrowed; two return to the free list. total()=4, in_use=2.
    drop(b3);
    drop(b4);
    assert_eq!(db.in_use_count(), 2);
    assert_eq!(db.free_count(), 2);

    // Reap while b1/b2 are still in use. total()=4 exceeds pool_size=3 by one,
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
        "pool_size=1;pool_max=3;pool_idle_timeout_ms=100;pool_reap=auto;",
    ))
    .unwrap();
    let b1 = db.borrow_column_sender().expect("b1");
    let b2 = db.borrow_column_sender().expect("b2");
    let b3 = db.borrow_column_sender().expect("b3");
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
    let mut sender = db.borrow_column_sender().expect("borrow");
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
    let mut sender = db.borrow_column_sender().expect("borrow");
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
    let mut sender = db.borrow_column_sender().expect("borrow");
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
        .designated_timestamp_nanos(&[1_700_000_000_000_000_000])
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
    let mut sender = db.borrow_column_sender().expect("borrow");
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
    chunk.designated_timestamp_nanos(ts).unwrap();
    chunk
}

#[test]
fn flush_and_wait_publishes_and_waits_for_ok() {
    let server = MockServer::spawn_acking(2);
    let db = QuestDb::connect(&conf_for(server.port(), "")).unwrap();
    let mut sender = db.borrow_column_sender().expect("borrow");

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
    let mut sender = db.borrow_column_sender().expect("borrow");
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
    let mut sender = db.borrow_column_sender().expect("borrow");
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
    let mut sender = db.borrow_column_sender().expect("borrow");

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
    let mut sender = db.borrow_column_sender().expect("borrow");
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
    let mut sender = db.borrow_column_sender().expect("borrow");

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
        .designated_timestamp_nanos(&[
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
        .designated_timestamp_nanos(&[1_700_000_000_000_003_000, 1_700_000_000_000_004_000])
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
    let mut sender = db.borrow_column_sender().expect("borrow");

    let mut chunk = Chunk::new("logs");
    // 4 rows: "alpha", null, "gamma", "δ" (multi-byte UTF-8).
    let bytes = b"alphagamma\xCE\xB4";
    // Offsets length must be row_count + 1 = 5. The null row reuses the
    // same offset on both sides per the plan's "skip slicing for null
    // rows" rule.
    let offsets: [i32; 5] = [0, 5, 5, 10, 12];
    let bits = [0b0000_1101]; // 0,2,3 valid; 1 null
    let v = Validity::from_bitmap(&bits, 4).unwrap();
    chunk
        .column_varchar("msg", &offsets, bytes, Some(&v))
        .unwrap();
    chunk
        .column_i64("seq", &[100, 101, 102, 103], None)
        .unwrap();
    chunk
        .designated_timestamp_nanos(&[
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
    let mut sender = db.borrow_column_sender().expect("borrow");

    // Caller has a 3-entry dict; first chunk only references entries 0 and 2,
    // so the wire's delta-symbol-dict prefix carries those two new symbols.
    let dict_bytes = b"alphabetagamma";
    let dict_offsets: [i32; 4] = [0, 5, 9, 14];

    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_dict_i32("sym", &[0, 2, 0, 2], &dict_offsets, dict_bytes, None)
        .expect("symbol_dict_i32 first flush");
    chunk.designated_timestamp_nanos(&[1, 2, 3, 4]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender
        .wait(AckLevel::Ok, Duration::from_secs(30))
        .expect("symbol flush 1");

    // Second flush re-uses entry 0 ("alpha", already in the global dict)
    // and adds entry 1 ("beta"). With the connection-scoped dict the
    // wire prefix only resends "beta"; the round-trip must still succeed.
    chunk
        .symbol_dict_i32("sym", &[1, 0, 1, 0], &dict_offsets, dict_bytes, None)
        .expect("symbol_dict_i32 second flush");
    chunk.designated_timestamp_nanos(&[5, 6, 7, 8]).unwrap();
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
        .symbol_dict_i32("sym", &[0, 2, 0, 2], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.designated_timestamp_nanos(&[1, 2, 3, 4]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender.commit(AckLevel::Ok).expect("symbol flush 1");

    chunk
        .symbol_dict_i32("sym", &[1, 0, 1, 0], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.designated_timestamp_nanos(&[5, 6, 7, 8]).unwrap();
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
fn server_error_latches_conn_and_pool_drops_it() {
    // Status 0x09 = QWP write error → ServerFlushError.
    let server = MockServer::spawn_erroring(4, 0x09);
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_size=1;pool_max=2;close_flush_timeout_millis=50;",
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
        "pool_size=1;pool_max=2;pool_idle_timeout_ms=500;pool_reap=auto;close_flush_timeout_millis=200;",
    ))
    .unwrap();
    // Borrow + return so we have something to reap eventually.
    {
        let _sender = db.borrow_column_sender().expect("borrow");
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
// The SfColumnSender contract is that a parked connection's background runner
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
        "pool_size=1;pool_max=3;pool_idle_timeout_ms=1;pool_reap=manual;\
         close_flush_timeout_millis=2000;",
    ))
    .unwrap();

    // Open three distinct connections; b1 stays empty, b2 and b3 each publish a
    // frame whose ack the server withholds, so they read as undelivered.
    let b1 = db.borrow_column_sender().expect("b1");
    let mut b2 = db.borrow_column_sender().expect("b2");
    let mut b3 = db.borrow_column_sender().expect("b3");
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
        let mut sender = db.borrow_column_sender().expect("borrow");
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
        let mut sender = db.borrow_column_sender().expect("borrow");
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
        "pool_size=1;pool_max=1;",
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
        "pool_size=1;pool_max=1;\
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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

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
        "pool_size=1;pool_max=2;",
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
    use arrow_array::{ArrayRef, Int64Array, RecordBatch};
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

#[cfg(feature = "polars-ingress")]
#[test]
fn flush_polars_dataframe_redrives_whole_df_onto_live_endpoint() {
    use crate::ingress::polars::PolarsIngestOptions;
    use polars::prelude::{DataFrame, IntoColumn, NamedFrom, PlSmallStr, Series};

    // Endpoint A is the eager-open primary that dies on the checkpoint `sync`;
    // endpoint B is a live acking server. The DataFrame entry must catch the
    // transient failure, re-borrow onto B, and re-drive every batch there so
    // all rows land (at-least-once).
    let primary = MockServer::spawn_upgrade_then_close(1);
    let (live, frames) = MockServer::spawn_acking_capturing(2);
    let db = QuestDb::connect(&conf_for_endpoints(
        &[primary.port(), live.port()],
        "pool_size=1;pool_max=2;",
    ))
    .unwrap();

    let mut sender = db.borrow_direct_column_sender().expect("borrow");
    assert!(
        wait_until(Duration::from_secs(2), || primary.accepted() == 1),
        "first borrow must connect to the primary; accepted={}",
        primary.accepted()
    );

    let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3, 4, 5, 6]).into_column();
    let df = DataFrame::new_with_height(6, vec![i]).unwrap();

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
    use polars::prelude::{DataFrame, IntoColumn, NamedFrom, PlSmallStr, Series};

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
        "pool_size=1;pool_max=2;",
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
    let df = DataFrame::new_with_height(66, vec![i]).unwrap();

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
    use polars::prelude::{DataFrame, IntoColumn, NamedFrom, PlSmallStr, Series};

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
        "pool_size=1;pool_max=2;\
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
    let df = DataFrame::new_with_height(2, vec![i]).unwrap();

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
    use polars::prelude::{DataFrame, IntoColumn, NamedFrom, PlSmallStr, Series};

    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("qwpws::addr=127.0.0.1:{};", server.port())).unwrap();

    let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3, 4]).into_column();
    let df = DataFrame::new_with_height(4, vec![i]).unwrap();

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
    use polars::prelude::{DataFrame, IntoColumn, NamedFrom, PlSmallStr, Series};

    // `ArrowColumnOverride` was documented for "Polars frames built without
    // pyarrow" yet was previously unreachable through `flush_polars_dataframe`.
    // A Symbol override for a plain Utf8 column must now thread through to every
    // sliced batch and commit cleanly.
    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("qwpws::addr=127.0.0.1:{};", server.port())).unwrap();

    let s = Series::new(PlSmallStr::from("s"), &["a", "b", "c", "d"]).into_column();
    let i = Series::new(PlSmallStr::from("i"), &[1i64, 2, 3, 4]).into_column();
    let df = DataFrame::new_with_height(4, vec![s, i]).unwrap();

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

    use arrow_array::{Int64Array, RecordBatch};
    use arrow_schema::{DataType, Field, Schema};

    // `db.flush_arrow_batch(.., None, ..)` borrows a direct sender internally,
    // publishes one server-stamped batch as a commit boundary, waits for the
    // `Ok` ack, and returns the sender to the pool — all without the caller
    // touching a sender.
    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("qwpws::addr=127.0.0.1:{};", server.port())).unwrap();

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
    use arrow_array::{Int64Array, RecordBatch};
    use arrow_schema::{DataType, Field, Schema};

    // The connect string did not set `request_durable_ack=on`, so a
    // caller-named `Durable` level must be rejected up front rather than
    // silently downgraded.
    let (server, _frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("qwpws::addr=127.0.0.1:{};", server.port())).unwrap();

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

    use arrow_array::{Float64Array, RecordBatch, TimestampNanosecondArray};
    use arrow_schema::{DataType, Field, Schema, TimeUnit};

    // The `Some(ts)` arm sources the designated timestamp from the named
    // column and threads through to `flush_arrow_batch_at_column_and_wait`.
    let (server, frames) = MockServer::spawn_acking_capturing(1);
    let db = QuestDb::connect(&format!("qwpws::addr=127.0.0.1:{};", server.port())).unwrap();

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
/// round-trip. The same endpoint also serves any lazily-opened column-sender
/// borrow (which ignores the unsolicited `SERVER_INFO` while parked).
#[cfg(feature = "sync-reader-qwp-ws")]
mod reader_pool {
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    use super::{conf_for, park_connection, wait_until};
    use crate::egress::error::ErrorCode as EgressErrorCode;
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
        let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

        // All pools are lazy, so the reader pool starts empty.
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

    /// `BorrowedReader` derefs to the underlying [`crate::egress::Reader`] for
    /// both `&self` and `&mut self` methods.
    #[test]
    fn borrowed_reader_derefs_to_underlying_reader() {
        let server = ReaderMockServer::spawn(4);
        let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

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
        let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=4;")).unwrap();

        // Lazy pools: `connect` opens nothing.
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

    /// Borrowing past `pool_max` fails fast with an egress `InvalidApiCall`
    /// rather than blocking or over-committing.
    #[test]
    fn reader_pool_fails_fast_at_cap() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

        let _r1 = db.borrow_reader().expect("r1");
        let _r2 = db.borrow_reader().expect("r2 (grow to cap)");
        let err = db
            .borrow_reader()
            .expect_err("must fail-fast at the reader cap");
        assert_eq!(err.code(), EgressErrorCode::InvalidApiCall);
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
        let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

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

    /// The reader, column-sender, and row-sender pools are capped and tracked
    /// independently: all three can be borrowed at once from a single
    /// `QuestDb` even when each pool's `pool_max` is only 2 (combined live
    /// connection ceiling `3 * pool_max`).
    #[test]
    fn reader_and_sender_pools_are_independent() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();

        let col = db.borrow_column_sender().expect("column sender"); // opens a fresh connection
        let row = db.borrow_row_sender().expect("row sender"); // opens a fresh connection
        let reader = db.borrow_reader().expect("reader"); // opens a fresh connection

        // Each pool tracks its own borrow on an independent counter.
        assert_eq!(db.in_use_count(), 1);
        assert_eq!(db.row_sender_in_use_count(), 1);
        assert_eq!(db.reader_in_use_count(), 1);

        // 1 column + 1 row + 1 reader = three independent live connections,
        // each pool capped separately at pool_max=2.
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
        assert_eq!(db.row_sender_in_use_count(), 1);

        drop(row);
        drop(col);
        assert_eq!(db.in_use_count(), 0);
        assert_eq!(db.row_sender_in_use_count(), 0);
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
            EgressErrorCode::InvalidApiCall,
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
            QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=8;")).unwrap(),
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

    /// `pool_reap=manual`: idle readers above the (zero) warm floor are closed
    /// only when `reap_idle` is called, and only after the idle timeout.
    #[test]
    fn manual_reap_closes_idle_readers() {
        let server = ReaderMockServer::spawn(8);
        let db = QuestDb::connect(&conf_for(
            server.port(),
            "pool_size=1;pool_max=3;pool_idle_timeout_ms=50;pool_reap=manual;",
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

        // Past the timeout: the reader pool keeps no warm floor (lazy-init),
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
            "pool_size=1;pool_max=3;pool_idle_timeout_ms=100;pool_reap=auto;",
        ))
        .unwrap();

        let b1 = db.borrow_reader().expect("b1");
        let b2 = db.borrow_reader().expect("b2 (grow)");
        drop(b1);
        drop(b2);
        assert_eq!(db.reader_free_count(), 2);

        // The background reaper wakes on a `max(5s, timeout/12)` ticker (the
        // 5s floor applies here). The reader pool keeps no warm floor, so
        // every idle reader is drained.
        let reaped = wait_until(Duration::from_secs(8), || db.reader_free_count() == 0);
        assert!(
            reaped,
            "auto reaper failed to drain idle readers; free={}",
            db.reader_free_count()
        );
        drop(db);
    }
}
