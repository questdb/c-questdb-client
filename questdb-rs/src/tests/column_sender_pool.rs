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
use crate::ingress::column_sender::{AckLevel, Chunk, QuestDb};
use crate::tests::qwp_ws::{
    perform_server_upgrade, read_frame, write_qwp_error_response, write_qwp_ok_response,
};

#[derive(Clone, Copy, Debug)]
enum MockMode {
    /// Park the connection after upgrade — used by pool-only tests.
    Park,
    /// Read every QWP frame the client sends and reply with an OK ack.
    AckEachFrame,
    /// Reply to every QWP frame with an error ack carrying `status`.
    ErrorEachFrame(u8),
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
                let mut handles = Vec::new();
                while !stop_clone.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            if accepted_clone.fetch_add(1, Ordering::SeqCst) >= max_accepts {
                                // Past the budget — drop without upgrade so
                                // the client sees a failed connect.
                                continue;
                            }
                            stream
                                .set_nonblocking(false)
                                .expect("set_nonblocking(false)");
                            let stop = Arc::clone(&stop_clone);
                            let capture = capture.clone();
                            let h = thread::spawn(move || {
                                if perform_server_upgrade(&mut stream).is_ok() {
                                    match mode {
                                        MockMode::Park => park_connection(&mut stream, &stop),
                                        MockMode::AckEachFrame => {
                                            ack_each_frame(&mut stream, &stop, capture)
                                        }
                                        MockMode::ErrorEachFrame(status) => {
                                            error_each_frame(&mut stream, &stop, status)
                                        }
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

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.join.take() {
            let _ = h.join();
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

fn conf_for(port: u16, extras: &str) -> String {
    format!(
        "qwpws::addr=127.0.0.1:{port};auth_timeout=2000;reconnect_max_duration_millis=1000;{extras}"
    )
}

#[test]
fn refuses_non_qwp_ws_schema() {
    let err = QuestDb::connect("http::addr=localhost:9000;").unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(err.msg().contains("QWP/WebSocket"));
}

#[test]
fn refuses_sf_dir() {
    let err = QuestDb::connect("qwpws::addr=localhost:9000;sf_dir=/tmp/sf;").unwrap_err();
    assert_eq!(err.code(), ErrorCode::ConfigError);
    assert!(
        err.msg().contains("store-and-forward") && err.msg().contains("sf_dir"),
        "msg: {}",
        err.msg()
    );
}

#[test]
fn eager_open_opens_pool_size_connections() {
    let server = MockServer::spawn(8);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=3;pool_max=4;")).unwrap();
    assert_eq!(db.free_count(), 3);
    assert_eq!(db.in_use_count(), 0);
    // Give the server thread time to register the accepts (the upgrades
    // complete before `connect` returns, but the AtomicUsize is incremented
    // before `perform_server_upgrade`).
    wait_until(Duration::from_secs(2), || server.accepted() == 3);
    drop(db);
}

#[test]
fn borrow_and_return_reuses_connection() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();
    assert_eq!(db.free_count(), 1);
    {
        let _borrow = db.borrow_sender().expect("borrow");
        assert_eq!(db.free_count(), 0);
        assert_eq!(db.in_use_count(), 1);
    }
    // Drop returns the sender to the pool.
    assert_eq!(db.free_count(), 1);
    assert_eq!(db.in_use_count(), 0);
    // Same physical connection — server only ever accepted one.
    assert_eq!(server.accepted(), 1);
    drop(db);
}

#[test]
fn auto_grow_opens_new_connection_until_pool_max() {
    let server = MockServer::spawn(4);
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=3;")).unwrap();
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
    let db = QuestDb::connect(&conf_for(server.port(), "pool_size=1;pool_max=2;")).unwrap();
    let _b1 = db.borrow_sender().expect("b1");
    let _b2 = db.borrow_sender().expect("b2");
    let err = db.borrow_sender().expect_err("must fail-fast at cap");
    assert_eq!(err.code(), ErrorCode::InvalidApiCall);
    assert!(err.msg().contains("pool_max"), "msg: {}", err.msg());
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
        "pool_size=1;pool_max=3;pool_idle_timeout_ms=50;pool_reap=manual;",
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
fn auto_reaper_closes_excess_idle_connections() {
    let server = MockServer::spawn(4);
    // tick = max(5s, timeout/12); use a long-enough timeout that timeout/12
    // > 5s so the reaper wakes promptly on its own ticker.
    let db = QuestDb::connect(&conf_for(
        server.port(),
        "pool_size=1;pool_max=3;pool_idle_timeout_ms=100;pool_reap=auto;",
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
        .sync(AckLevel::Durable)
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
        .sync(AckLevel::Durable)
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
        .sync(AckLevel::Ok)
        .expect("empty-chunk flush must round-trip");
    // Flush clears the chunk.
    assert_eq!(chunk.row_count(), 0);
}

#[test]
fn deferred_flush_reserves_slot_for_sync_commit() {
    let server = MockServer::spawn(2);
    let db = QuestDb::connect(&conf_for(server.port(), "close_flush_timeout_millis=50;")).unwrap();
    let mut sender = db.borrow_sender().expect("borrow");
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
        sender.sync(AckLevel::Ok).expect("repeated empty flush");
    }
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
        .designated_timestamp_nanos(&[
            1_700_000_000_000_000_000,
            1_700_000_000_000_001_000,
            1_700_000_000_000_002_000,
        ])
        .unwrap();
    assert_eq!(chunk.row_count(), 3);

    sender.flush(&mut chunk).unwrap();
    sender.sync(AckLevel::Ok).expect("numeric chunk flush");
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
        .sync(AckLevel::Ok)
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
    sender.sync(AckLevel::Ok).expect("varchar flush");
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
        .symbol_dict_i32("sym", &[0, 2, 0, 2], &dict_offsets, dict_bytes, None)
        .expect("symbol_dict_i32 first flush");
    chunk.designated_timestamp_nanos(&[1, 2, 3, 4]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender.sync(AckLevel::Ok).expect("symbol flush 1");

    // Second flush re-uses entry 0 ("alpha", already in the global dict)
    // and adds entry 1 ("beta"). With the connection-scoped dict the
    // wire prefix only resends "beta"; the round-trip must still succeed.
    chunk
        .symbol_dict_i32("sym", &[1, 0, 1, 0], &dict_offsets, dict_bytes, None)
        .expect("symbol_dict_i32 second flush");
    chunk.designated_timestamp_nanos(&[5, 6, 7, 8]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender.sync(AckLevel::Ok).expect("symbol flush 2");
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
    let mut sender = db.borrow_sender().expect("borrow");

    let dict_bytes = b"alphabetagamma";
    let dict_offsets: [i32; 4] = [0, 5, 9, 14];

    let mut chunk = Chunk::new("trades");
    chunk
        .symbol_dict_i32("sym", &[0, 2, 0, 2], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.designated_timestamp_nanos(&[1, 2, 3, 4]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender.sync(AckLevel::Ok).expect("symbol flush 1");

    chunk
        .symbol_dict_i32("sym", &[1, 0, 1, 0], &dict_offsets, dict_bytes, None)
        .unwrap();
    chunk.designated_timestamp_nanos(&[5, 6, 7, 8]).unwrap();
    sender.flush(&mut chunk).unwrap();
    sender.sync(AckLevel::Ok).expect("symbol flush 2");

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
    assert_eq!(syms1, vec![b"beta".to_vec()], "only the new symbol is resent");
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
        let mut sender = db.borrow_sender().expect("borrow");
        let err = sender
            .sync(AckLevel::Ok)
            .expect_err("server error must surface");
        assert_eq!(err.code(), ErrorCode::ServerFlushError);
        // The server's status byte and message must survive the round-trip.
        assert!(err.msg().contains("0x09"), "msg: {}", err.msg());
        assert!(err.msg().contains("injected"), "msg: {}", err.msg());
        assert!(sender.must_close(), "errored conn must be latched");
        assert_eq!(db.in_use_count(), 1);
    }
    // The latched connection must be dropped, not returned to the free pool.
    assert_eq!(db.free_count(), 0, "latched conn must not be recycled");
    assert_eq!(db.in_use_count(), 0);
    // The next borrow must therefore open a brand-new physical connection.
    let _fresh = db.borrow_sender().expect("re-borrow after drop");
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
    let _ = db.borrow_sender().expect("borrow").must_close();
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
