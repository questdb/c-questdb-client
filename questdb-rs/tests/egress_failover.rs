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

//! Mid-query failover tests for the QWP egress reader.
//!
//! These run against an in-process tungstenite-based mock that scripts
//! a deterministic sequence of frames per connection. Each scenario
//! spins up one or more mocks, points the Reader at the address list,
//! and verifies the cursor's reconnect/replay behaviour.

#![cfg(feature = "sync-reader-ws")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use questdb::egress::{ErrorCode, FailoverEvent, Reader, ServerRole};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::http::HeaderValue;
use tungstenite::{Message, WebSocket, accept_hdr};

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

const MAGIC: [u8; 4] = *b"QWP1";
const MSG_QUERY_REQUEST: u8 = 0x10;
const MSG_RESULT_END: u8 = 0x12;
const MSG_SERVER_INFO: u8 = 0x18;

/// Wrap a payload in a 12-byte QWP1 frame header.
fn framed(version: u8, flags: u8, table_count: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + payload.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(version);
    buf.push(flags);
    buf.extend_from_slice(&table_count.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

fn encode_varint_u64(mut v: u64, out: &mut Vec<u8>) {
    while v & !0x7F != 0 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn server_info_frame(role: ServerRole, node_id: &str, cluster_id: &str) -> Vec<u8> {
    let role_byte = match role {
        ServerRole::Standalone => 0x00,
        ServerRole::Primary => 0x01,
        ServerRole::Replica => 0x02,
        ServerRole::PrimaryCatchup => 0x03,
        ServerRole::Other(b) => b,
    };
    let mut payload = vec![MSG_SERVER_INFO, role_byte];
    payload.extend_from_slice(&0u64.to_le_bytes()); // epoch
    payload.extend_from_slice(&0u32.to_le_bytes()); // capabilities
    payload.extend_from_slice(&0i64.to_le_bytes()); // server_wall_ns
    payload.extend_from_slice(&(cluster_id.len() as u16).to_le_bytes());
    payload.extend_from_slice(cluster_id.as_bytes());
    payload.extend_from_slice(&(node_id.len() as u16).to_le_bytes());
    payload.extend_from_slice(node_id.as_bytes());
    framed(2, 0, 0, &payload)
}

fn result_end_frame(request_id: i64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.push(MSG_RESULT_END);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(0, &mut payload); // final_seq
    encode_varint_u64(0, &mut payload); // total_rows
    framed(2, 0, 0, &payload)
}

// ---------------------------------------------------------------------------
// MockServer
// ---------------------------------------------------------------------------

/// Per-connection scripted action.
#[derive(Debug, Clone)]
enum Action {
    /// Send the SERVER_INFO handshake frame.
    SendServerInfo { role: ServerRole, node_id: String },
    /// Block until a QUERY_REQUEST arrives from the client.
    AwaitQueryRequest,
    /// Reply with RESULT_END (using the request_id from the most-recent
    /// AwaitQueryRequest).
    SendResultEnd,
    /// Drop the underlying TCP connection without a clean WS close.
    HardDrop,
    /// Sleep for the given duration before processing the next action.
    /// Used to give the client time to call `cancel()` while the
    /// server is alive on the wire (so the CANCEL write succeeds and
    /// `cancelling=true` actually gets set).
    Sleep(Duration),
    /// Reject the WS upgrade with a 401 Unauthorized.
    Reject401,
    /// Send a single WS binary message verbatim. Lets a script deliver
    /// a malformed/corrupt frame and assert the client's decode-error
    /// path (which is deliberately not failover-eligible).
    SendRaw(Vec<u8>),
    /// Abortive close: set `SO_LINGER=0` on the TCP socket and drop
    /// it, causing the kernel to send a TCP RST instead of a FIN.
    /// Unlike `HardDrop` (which sends FIN — the client's next *write*
    /// can still succeed because data has nowhere immediately to fail)
    /// this guarantees the client's next read or write fails
    /// synchronously with "Connection reset by peer", letting tests
    /// reliably exercise paths that depend on a failed write.
    AbortiveRst,
}

/// Behaviour for a single accepted connection.
type Script = Vec<Action>;

/// In-process QWP mock. Each accepted connection runs the next Script
/// from the per-server queue (round-robin if exhausted: re-uses the
/// last script).
struct MockServer {
    addr: SocketAddr,
    /// Held only to keep the script queue alive while the listener
    /// thread (which clones this `Arc` into its closure) still runs.
    /// The field itself is never read on `&self` — `#[allow(dead_code)]`
    /// suppresses the resulting lint.
    #[allow(dead_code)]
    scripts: Arc<Mutex<Vec<Script>>>,
    accept_count: Arc<AtomicUsize>,
    /// Set when the listener thread should exit.
    shutdown: Arc<Mutex<bool>>,
    /// Listener loop handle (joined on drop).
    handle: Option<thread::JoinHandle<()>>,
    /// Per-connection worker handles. Collected here so `Drop` can
    /// join them — leaking detached workers to process exit lets a
    /// stale send/read from test N survive into test N+1, and on
    /// `--test-threads != 1` the leaked threads accumulate FDs.
    workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
    /// Captures the full payload bytes (msg_kind + body) of every
    /// QUERY_REQUEST seen by any worker for this server. Tests use
    /// this to assert the wire-level replay invariants — bind
    /// payload preservation across failover, request_id rotation,
    /// SQL identity. One entry per accepted connection that read a
    /// QUERY_REQUEST; preserves arrival order.
    captured_requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl MockServer {
    fn start(scripts: Vec<Script>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        listener.set_nonblocking(false).expect("blocking listener");
        let addr = listener.local_addr().expect("local_addr");
        let scripts = Arc::new(Mutex::new(scripts));
        let scripts_clone = Arc::clone(&scripts);
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_clone = Arc::clone(&accept_count);
        let shutdown = Arc::new(Mutex::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
        let workers_clone = Arc::clone(&workers);
        let captured_requests: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_clone_outer = Arc::clone(&captured_requests);

        // The listener thread spawns a per-connection worker and
        // stashes its `JoinHandle` so `MockServer::Drop` can join
        // them. Workers pull the next script off the front of the
        // queue (the last script is repeated if the queue is
        // exhausted, so a test doesn't need to enumerate every
        // accept that may happen).
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if *shutdown_clone.lock().unwrap() {
                    break;
                }
                let stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let n = accept_count_clone.fetch_add(1, Ordering::SeqCst);
                let script = {
                    let q = scripts_clone.lock().unwrap();
                    if n < q.len() {
                        q[n].clone()
                    } else {
                        q.last().cloned().unwrap_or_default()
                    }
                };
                let captured_clone_inner = Arc::clone(&captured_clone_outer);
                let worker =
                    thread::spawn(move || run_script(stream, script, captured_clone_inner));
                workers_clone.lock().unwrap().push(worker);
            }
        });

        // No "tickle" sleep here. `TcpListener::bind` returns once the
        // listener socket is in `LISTEN` state, so the kernel queues
        // SYNs in the listen backlog from this point — `accept()`
        // returning sooner or later doesn't change behaviour.

        MockServer {
            addr,
            scripts,
            accept_count,
            shutdown,
            handle: Some(handle),
            workers,
            captured_requests,
        }
    }

    fn url(&self) -> String {
        format!("{}", self.addr)
    }

    fn accepts(&self) -> usize {
        self.accept_count.load(Ordering::SeqCst)
    }

    /// Snapshot of every QUERY_REQUEST payload (msg_kind + body)
    /// observed by this server's workers, in arrival order. Each
    /// entry is the bare client-to-server frame as written by the
    /// cursor — no QWP1 header (only server frames carry that).
    fn captured_requests(&self) -> Vec<Vec<u8>> {
        self.captured_requests.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        *self.shutdown.lock().unwrap() = true;
        // Tickle the listener to wake the accept() so the thread exits.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        // Drain the worker queue. Joining lets in-flight `ws.read()`
        // calls observe the dropped `TcpStream` and return cleanly,
        // so they don't survive into the next test.
        let workers = std::mem::take(&mut *self.workers.lock().unwrap());
        for w in workers {
            let _ = w.join();
        }
    }
}

/// Per-connection worker: handle WS handshake (or reject), then run
/// the script to completion. Errors are swallowed — the test asserts
/// against the client side, not the mock side.
fn run_script(stream: TcpStream, script: Script, captured_requests: Arc<Mutex<Vec<Vec<u8>>>>) {
    // Decide upfront if this connection wants to reject the upgrade.
    let reject = script.iter().any(|a| matches!(a, Action::Reject401));
    if reject {
        reject_upgrade(stream);
        return;
    }

    let mut ws = match accept_hdr(stream, |_req: &Request, mut resp: Response| {
        // Inject the X-QWP-Version response header so the client's
        // handshake validator is happy. Always negotiate v2 in tests
        // (matches what we send in SERVER_INFO).
        resp.headers_mut()
            .insert("x-qwp-version", HeaderValue::from_static("2"));
        Ok(resp)
    }) {
        Ok(ws) => ws,
        Err(_) => return,
    };

    let mut last_request_id: Option<i64> = None;

    for action in script {
        match action {
            Action::Reject401 => unreachable!("handled above"),
            Action::SendServerInfo { role, node_id } => {
                let frame = server_info_frame(role, &node_id, "test-cluster");
                if ws.send(Message::Binary(frame.into())).is_err() {
                    return;
                }
            }
            Action::AwaitQueryRequest => {
                match read_until_query_request(&mut ws, &captured_requests) {
                    Some(rid) => last_request_id = Some(rid),
                    None => return,
                }
            }
            Action::SendResultEnd => {
                let rid = last_request_id.expect("AwaitQueryRequest before SendResultEnd");
                let frame = result_end_frame(rid);
                if ws.send(Message::Binary(frame.into())).is_err() {
                    return;
                }
            }
            Action::HardDrop => {
                drop(ws);
                return;
            }
            Action::Sleep(d) => std::thread::sleep(d),
            Action::SendRaw(bytes) => {
                if ws.send(Message::Binary(bytes.into())).is_err() {
                    return;
                }
            }
            Action::AbortiveRst => {
                // `TcpStream::set_linger` is still unstable, so go via
                // `socket2::SockRef` to set SO_LINGER=0 on the borrowed
                // stream. With linger=0, the kernel sends a TCP RST
                // (instead of FIN) when the socket is closed.
                let _ =
                    socket2::SockRef::from(ws.get_ref()).set_linger(Some(Duration::from_secs(0)));
                drop(ws);
                return;
            }
        }
    }
}

/// Tungstenite-based HTTP error reply (avoids depending on the WS
/// upgrade machinery for the 401 path). We hand-roll a minimal HTTP
/// response since the real auth-error path on the client side just
/// inspects the status code.
fn reject_upgrade(mut stream: TcpStream) {
    let mut buf = [0u8; 1024];
    // Drain the request line + headers (best-effort). We don't actually
    // parse them — just need to consume so the client sees the
    // response after its request hits the wire.
    let _ = stream.read(&mut buf);
    let _ = stream
        .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

/// Pump frames from the client until a QUERY_REQUEST (msg_kind 0x10)
/// is observed; return its request_id and append the full payload
/// bytes (msg_kind + body) to `captured` so tests can inspect what
/// the cursor actually sent. Client→server frames are bare payloads
/// (no QWP1 header), so the request_id is at offset 1.
fn read_until_query_request(
    ws: &mut WebSocket<TcpStream>,
    captured: &Arc<Mutex<Vec<Vec<u8>>>>,
) -> Option<i64> {
    loop {
        match ws.read() {
            Ok(Message::Binary(b)) if !b.is_empty() && b[0] == MSG_QUERY_REQUEST => {
                if b.len() < 9 {
                    return None;
                }
                let mut id = [0u8; 8];
                id.copy_from_slice(&b[1..9]);
                captured.lock().unwrap().push(b.to_vec());
                return Some(i64::from_le_bytes(id));
            }
            Ok(Message::Binary(_)) | Ok(Message::Text(_)) => continue,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => continue,
            Ok(Message::Close(_)) | Err(_) => return None,
        }
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn happy_script(role: ServerRole, node_id: &str) -> Script {
    vec![
        Action::SendServerInfo {
            role,
            node_id: node_id.into(),
        },
        Action::AwaitQueryRequest,
        Action::SendResultEnd,
    ]
}

fn drop_after_query_script(role: ServerRole, node_id: &str) -> Script {
    vec![
        Action::SendServerInfo {
            role,
            node_id: node_id.into(),
        },
        Action::AwaitQueryRequest,
        Action::HardDrop,
    ]
}

/// Drops the TCP stream immediately after the WS upgrade — before
/// even sending SERVER_INFO. The client's `connect_endpoint` then
/// fails inside `consume_server_info`, which surfaces as a
/// failover-eligible transport error. Use this script when a test
/// wants the failover *connect* attempts to fail (not just the
/// post-QUERY_REQUEST stream).
fn drop_at_connect_script() -> Script {
    vec![Action::HardDrop]
}

/// Sends SERVER_INFO (so `connect_endpoint` succeeds), then drops the
/// TCP stream **before** reading the client's QUERY_REQUEST. The
/// client's `write_message(QUERY_REQUEST)` race-fails on this dead
/// socket — exercises the M3 path where reconnect succeeds but the
/// immediate replay write fails.
fn drop_after_server_info_script(role: ServerRole, node_id: &str) -> Script {
    vec![
        Action::SendServerInfo {
            role,
            node_id: node_id.into(),
        },
        Action::HardDrop,
    ]
}

fn build_addr_list(servers: &[&MockServer]) -> String {
    servers
        .iter()
        .map(|s| s.url())
        .collect::<Vec<_>>()
        .join(",")
}

/// Reserve a loopback port via `:0`, capture its address, then drop
/// the listener. The returned `host:port` will refuse subsequent
/// connects on the test host — far more reliable than hard-coding
/// "port 1" (which Docker bridge networks and userspace TCP stacks
/// can legitimately bind).
fn reserve_then_close_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
    let addr = listener.local_addr().expect("local_addr");
    drop(listener);
    format!("{}", addr)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn happy_path_no_failover() {
    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n1")]);
    let conf = format!("qwp::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");

    // Verify the on_failover_reset callback is NEVER invoked when the
    // query completes cleanly. Asserting only `failover_resets() == 0`
    // would let a regression slip through if the counter is updated
    // without the callback (or vice versa) — the contract is that the
    // counter and the callback move together.
    let callback_fires = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cb_clone = std::sync::Arc::clone(&callback_fires);
    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |_| {
            cb_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .execute()
        .expect("execute");
    assert!(cursor.next_batch().expect("next").is_none());
    assert_eq!(cursor.failover_resets(), 0);
    assert_eq!(
        callback_fires.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "on_failover_reset must not fire on the happy path"
    );
}

#[test]
fn mid_query_close_triggers_failover() {
    // Server A: closes after QUERY_REQUEST. Server B: completes.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    assert_eq!(
        reader.current_addr().port,
        srv_a.addr.port(),
        "initial connect lands on A"
    );

    let observed: Arc<Mutex<Vec<FailoverEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |ev: &FailoverEvent| {
            observed_clone.lock().unwrap().push(ev.clone());
        })
        .execute()
        .expect("execute");

    // First next_batch sees A close, fails over to B, replays, gets RESULT_END.
    assert!(cursor.next_batch().expect("next after failover").is_none());
    assert_eq!(cursor.failover_resets(), 1);

    {
        let events = observed.lock().unwrap();
        assert_eq!(events.len(), 1, "callback fired once");
        assert_eq!(events[0].attempts, 1);
        assert!(events[0].new_request_id != 0);

        // Enriched fields (m1 + m2): failed/new addresses, trigger
        // code, elapsed time. Addresses must round-trip from the
        // connect string. Trigger is a transport-flavour error
        // (RST/close from server A). Elapsed bounds: > 0 (we did
        // *something* — at minimum the dial + handshake), and
        // < a generous ceiling so a wedged future change can't
        // pretend to "succeed instantly" by skipping the reconnect.
        assert_eq!(events[0].failed_addr.host, "127.0.0.1");
        assert_eq!(events[0].failed_addr.port, srv_a.addr.port());
        assert_eq!(events[0].new_addr.host, "127.0.0.1");
        assert_eq!(events[0].new_addr.port, srv_b.addr.port());
        assert!(
            matches!(
                events[0].trigger.code(),
                ErrorCode::SocketError | ErrorCode::ProtocolError
            ),
            "trigger should be a transport error, got {:?}: {}",
            events[0].trigger.code(),
            events[0].trigger.msg()
        );
        // M7 regression guard: the trigger carries the full error,
        // not just the code. The message must be non-empty so log
        // pipelines / diagnostics have something to work with.
        assert!(
            !events[0].trigger.msg().is_empty(),
            "trigger error message must be populated for diagnostics"
        );
        assert!(events[0].elapsed > Duration::ZERO);
        assert!(events[0].elapsed < Duration::from_secs(5));

        // m9 regression guard: `new_server_info` must reflect the
        // actually-bound new endpoint (B), not be silently `None`.
        // The mock advertises QWP v2 for every accept, so v1-only
        // SERVER_INFO absence is not in play here.
        let info = events[0]
            .new_server_info
            .as_ref()
            .expect("v2 mock must surface SERVER_INFO of the new endpoint");
        assert_eq!(info.role, ServerRole::Standalone);
        assert_eq!(info.node_id, "b");
    }

    // Accept counts are guidelines, not contracts: a busy CI box
    // could deliver an extra spurious dial without violating the
    // failover semantics. The contract — "exactly one user-visible
    // failover event happened" — is asserted via the callback count
    // above. Use `>= 1` here so scheduler noise doesn't cause flakes.
    assert!(
        srv_a.accepts() >= 1,
        "A should be dialed at least once (the initial connect); got {}",
        srv_a.accepts()
    );
    assert!(
        srv_b.accepts() >= 1,
        "B should be dialed at least once (the failover target); got {}",
        srv_b.accepts()
    );

    // `Reader::current_addr` must reflect the post-failover endpoint
    // after the cursor releases its mutable borrow.
    drop(cursor);
    let ep = reader.current_addr();
    assert_eq!(ep.host, "127.0.0.1");
    assert_eq!(
        ep.port,
        srv_b.addr.port(),
        "reader bound to the failover target after the cursor completes"
    );
}

#[test]
fn failover_disabled_surfaces_socket_error() {
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover=off",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.query("select 1").execute().expect("execute");
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail"),
    };
    // Either SocketError or ProtocolError, depending on whether the
    // server's hard-drop landed on the read as a clean close or a
    // mid-frame reset.
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError
        ),
        "unexpected code: {:?}",
        err.code()
    );
    assert_eq!(cursor.failover_resets(), 0);
    assert_eq!(srv_b.accepts(), 0, "B never dialed when failover off");
}

#[test]
fn attempts_exhausted_surfaces_error() {
    // A is healthy for the initial connect, then drops mid-query. B
    // is broken at connect-time (drops before SERVER_INFO). With
    // max_attempts=2, the cursor's first failure should burn 3
    // reconnect attempts (1 initial + 2 retries), all of which fail
    // because B can't even hand back SERVER_INFO and A only has a
    // single healthy script in its queue (subsequent accepts replay
    // its last script — also a connect-time failure).
    //
    // Note: the *second* and *third* attempts within reconnect_with_failover
    // will alternate (A, B, A) starting from "skip the failed one
    // first". Each individual attempt fails at the SERVER_INFO read,
    // exhausting the budget.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        // Subsequent accepts: TCP-level drop so even the connect fails.
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=2;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.query("select 1").execute().expect("execute");
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail eventually"),
    };
    // The trigger that drove failover was a transport error from the
    // A close, and every reconnect also produced one. SocketError or
    // ProtocolError both qualify (TCP reset vs clean close).
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError
        ),
        "unexpected code: {:?}",
        err.code()
    );
    // Exactly 1 initial connect to A + 3 reconnect attempts
    // (max_attempts + 1) = 4. Tightened from `>= 4` so a regression
    // that double-counts attempts becomes red.
    let total = srv_a.accepts() + srv_b.accepts();
    assert_eq!(
        total,
        4,
        "expected exactly 4 total dial attempts (1 initial + 3 reconnects); got A={}, B={}",
        srv_a.accepts(),
        srv_b.accepts()
    );
}

#[test]
fn reader_poisoned_after_failover_exhaustion_returns_err_not_panic() {
    // Regression: after `Cursor::failover_reconnect_and_replay`
    // exhausts its retry budget, `Reader::transport` is left as
    // `None`. The doc on `Reader::from_config` promises that
    // subsequent operations on the Reader fail at the transport
    // layer; previously they panicked via `Option::expect` inside
    // `transport_mut`. This test pins the documented behaviour:
    // every public Reader method must return `SocketError`, not
    // panic.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=1;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    {
        let mut cursor = reader.query("select 1").execute().expect("execute");
        let err = match cursor.next_batch() {
            Err(e) => e,
            Ok(_) => panic!("budget exhausts and surfaces an error"),
        };
        assert!(
            matches!(
                err.code(),
                ErrorCode::SocketError | ErrorCode::ProtocolError
            ),
            "unexpected exhaustion code: {:?}",
            err.code()
        );
        // cursor dropped here; cursor_active=false so Drop skips its
        // close — Reader.transport stays None.
    }

    // server_version must surface SocketError, not panic.
    let err = reader
        .server_version()
        .expect_err("server_version on a poisoned Reader must error");
    assert_eq!(err.code(), ErrorCode::SocketError);

    // A fresh query.execute() must surface SocketError, not panic.
    let err = match reader.query("select 2").execute() {
        Err(e) => e,
        Ok(_) => panic!("execute on a poisoned Reader must error"),
    };
    assert_eq!(err.code(), ErrorCode::SocketError);
}

#[test]
fn mid_query_auth_failure_not_retried() {
    // A serves the initial query, then closes. The failover loop
    // rotates to B, which 401s the upgrade. Because AuthError is
    // not failover-eligible, the cursor should bail immediately
    // rather than burning the rest of the retry budget against B.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![vec![Action::Reject401]]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=5;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.query("select 1").execute().expect("execute");
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail with auth"),
    };
    assert_eq!(err.code(), ErrorCode::AuthError);
    // B got a single dial attempt (the one that 401'd) — no extra
    // budget burned bouncing off it after auth was rejected.
    assert_eq!(srv_b.accepts(), 1);
}

#[test]
fn initial_connect_walks_all_endpoints() {
    // First endpoint is unreachable, second is healthy. The initial
    // walk should surface the healthy endpoint instead of failing on
    // the first refused connect. Use a freshly-released loopback
    // port (vs hard-coded "port 1") — port 1 can be legitimately
    // bound on Docker bridge networks and userspace TCP stacks.
    let dead_addr = reserve_then_close_addr();
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!("qwp::addr={},{}", dead_addr, srv_b.url());
    let mut reader = Reader::from_conf(&conf).expect("walk past unreachable");
    assert_eq!(
        reader.current_addr().port,
        srv_b.addr.port(),
        "walked past the unreachable endpoint to B"
    );
    let mut cursor = reader.query("select 1").execute().expect("execute");
    assert!(cursor.next_batch().expect("ok").is_none());
}

#[test]
fn backoff_grows_between_attempts() {
    // A is healthy on the initial connect, then drops mid-query. All
    // subsequent connects (to A or B) fail at the SERVER_INFO read,
    // so the failover budget actually exhausts. With initial=20ms,
    // max=200ms, max_attempts=3 → 1 initial reconnect + 3 retries =
    // 4 attempts; sleeps happen *between* attempts → 3 sleeps of
    // 20, 40, 80 ms = 140ms minimum. Be lenient: schedulers are noisy.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=3;failover_backoff_initial_ms=20;failover_backoff_max_ms=200",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.query("select 1").execute().expect("execute");
    let start = Instant::now();
    let _ = cursor.next_batch();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(120),
        "elapsed {:?} below the lower bound of the backoff schedule (~140ms)",
        elapsed
    );
}

#[test]
fn cancelling_cursor_does_not_failover_on_drop() {
    // Cursor: connects to A, executes the query, calls cancel(), then
    // drains. While the drain is waiting, A drops the socket. The
    // drain's next_batch read fails — but because `cancelling=true`,
    // the cursor must NOT trigger failover (it's on its way out, not
    // recovering from a transport hiccup). B is healthy and is here
    // only as a tripwire: any failover attempt would dial B.
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        // Sleep long enough for the client to call cancel() and enter
        // its drain loop while we're still alive on the wire — that
        // way the CANCEL write succeeds and `cancelling=true` gets
        // set before the drop arrives.
        Action::Sleep(Duration::from_millis(150)),
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.query("select 1").execute().expect("execute");

    // cancel() writes CANCEL (succeeds while A is sleeping), sets
    // cancelling=true, drains via next_batch. When A drops, the read
    // fails — `cancelling=true` short-circuits the failover branch
    // and surfaces the transport error directly.
    let cancel_result = cursor.cancel();
    // Either the drain saw a SocketError/ProtocolError (server dropped
    // during the drain, no STATUS_CANCELLED reply ever arrived), or it
    // returned Ok (rare — the server might have buffered the CANCEL
    // write until after the drop). Both outcomes are valid; what we're
    // verifying is that B was NEVER dialed.
    drop(cancel_result);
    drop(cursor);
    assert_eq!(
        srv_b.accepts(),
        0,
        "cancellation must not trigger failover; B should never be dialed"
    );
    assert_eq!(srv_a.accepts(), 1, "exactly one initial connect to A");
}

#[test]
fn single_endpoint_failover_exhausts_budget() {
    // With a single address in the list, the failover rotation
    // (`(0+1+attempt) % 1`) collapses to the same endpoint. If that
    // endpoint stays dead, the cursor MUST eventually surface a hard
    // error rather than retry indefinitely. With max_attempts=2 we
    // expect 1 initial connect + 3 reconnect attempts = 4 dials,
    // all of which fail post-handshake.
    let srv = MockServer::start(vec![
        // First accept: serve the initial query, then drop mid-stream
        // (so the cursor's first read fails and triggers failover).
        drop_after_query_script(ServerRole::Standalone, "lonely"),
        // Subsequent accepts: drop at connect so the failover budget
        // actually exhausts instead of looping on a still-healthy peer.
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=2;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        srv.url()
    );
    let mut reader = Reader::from_conf(&conf).expect("initial connect");
    let mut cursor = reader.query("select 1").execute().expect("execute");
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail eventually"),
    };
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError
        ),
        "unexpected code: {:?}",
        err.code()
    );
    // Exactly 1 initial connect + (max_attempts + 1) = 3 inner
    // reconnect attempts = 4 total dials. Tightened from `>= 4` so
    // a regression that double-counts attempts becomes red — and
    // for parity with `attempts_exhausted_surfaces_error` which
    // makes the same assertion. The earlier "M3 retry could add a
    // 5th" rationale doesn't apply here: every inner attempt fails
    // at `connect_endpoint` (TCP-level drop), so the outer
    // `failover_reconnect_and_replay` loop never reaches the
    // post-reconnect write_message that would arm the M3 cycle.
    assert_eq!(
        srv.accepts(),
        4,
        "expected exactly 4 dials against the single endpoint (1 initial + 3 reconnects); got {}",
        srv.accepts()
    );
}

#[test]
fn write_fails_on_freshly_reconnected_socket_retries_once() {
    // A: serves the initial query, then drops mid-stream → triggers
    // failover. B: accepts the WS upgrade and sends SERVER_INFO (so
    // connect_endpoint returns Ok), then drops before the client's
    // QUERY_REQUEST write lands → write_message fails on a "freshly
    // connected" socket. The cursor should NOT give up here: it
    // should rotate to the next endpoint (back to A's repeat slot)
    // and try once more. C: healthy, completes the query.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        // After the first failover lands on A again (via rotation),
        // serve cleanly so the cursor has somewhere to land.
        happy_script(ServerRole::Standalone, "a-recovered"),
    ]);
    let srv_b = MockServer::start(vec![drop_after_server_info_script(
        ServerRole::Standalone,
        "b",
    )]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    assert_eq!(
        reader.current_addr().port,
        srv_a.addr.port(),
        "initial connect lands on A"
    );

    let resets = std::sync::Arc::new(std::sync::Mutex::new(0u32));
    let resets_clone = std::sync::Arc::clone(&resets);
    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |_| {
            *resets_clone.lock().unwrap() += 1;
        })
        .execute()
        .expect("execute");

    // The cursor must recover. Two paths can land here depending on
    // when the kernel surfaces B's dropped TCP to tungstenite's
    // buffered send:
    //   (a) `write_message(QUERY_REQUEST)` to B fails synchronously —
    //       the M3 in-call retry kicks in, reconnects to A's recovered
    //       slot, and fires the callback exactly once;
    //   (b) tungstenite buffers the send and reports `Ok` — the
    //       cursor returns from the first failover, then `next_batch`
    //       reads from B, sees the close, and triggers a second
    //       outer failover that lands on A. Two callbacks.
    // Either outcome matches the contract: the cursor completes
    // and the user sees at least one reset event.
    assert!(cursor.next_batch().expect("must complete").is_none());
    let r = *resets.lock().unwrap();
    assert!(
        (1..=2).contains(&r),
        "expected 1 or 2 failover resets, got {}",
        r
    );
    // The recovered cursor must end up on A's recovered slot.
    drop(cursor);
    assert_eq!(
        reader.current_addr().port,
        srv_a.addr.port(),
        "recovered cursor must end up bound to A's recovered slot"
    );
}

#[test]
fn failover_event_attempts_is_cumulative_across_rotations() {
    // M3 regression guard: `FailoverEvent.attempts` must be the
    // cumulative reconnect count, not just the count of the cycle
    // that landed. Force the rotation to skip past one dead endpoint
    // before landing — the first reconnect attempt fails (B is dead),
    // the second succeeds (A's recovered slot). The callback must
    // see `attempts >= 2`.
    //
    // Pre-fix, `reconnect_with_failover` returned its local
    // `attempt + 1`, which counts only the rotation steps inside
    // its own call — and `failover_reconnect_and_replay` reported
    // that verbatim. With multiple rotation steps in a single cycle
    // both old and new code agree (the value comes back as 2 from
    // the inner function), but the doc claim "cumulative" was a lie
    // when MAX_REPLAY_CYCLES kicked in. This test pins the rotation
    // path; `write_fails_on_freshly_reconnected_socket_retries_once`
    // exercises the cycle-2 path indirectly.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        happy_script(ServerRole::Standalone, "a-recovered"),
    ]);
    // B is dead at connect-time forever. Rotation lands on B first
    // (skip-failed-first), fails, then continues to A's recovered slot.
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    let observed: std::sync::Arc<std::sync::Mutex<Vec<u32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_clone = std::sync::Arc::clone(&observed);
    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |ev| {
            observed_clone.lock().unwrap().push(ev.attempts);
        })
        .execute()
        .expect("execute");
    assert!(cursor.next_batch().expect("must complete").is_none());

    let attempts = observed.lock().unwrap().clone();
    assert_eq!(attempts.len(), 1, "callback fired exactly once");
    assert!(
        attempts[0] >= 2,
        "expected cumulative attempts >= 2 (rotation skipped past dead B); got {}",
        attempts[0],
    );
}

#[test]
fn backoff_caps_at_max_ms() {
    // Counterpart to `backoff_grows_between_attempts` (which only
    // checks the lower bound). Here we set the cap WAY below the
    // value the doubling would otherwise reach, then verify that
    // total elapsed is closer to "8 sleeps × cap" than to "8
    // sleeps in pure doubling".
    //
    // initial=10, max=20, max_attempts=8 → 8 sleeps:
    //   - capped:    10 + 20*7 ≈ 150 ms  (plus dial time)
    //   - uncapped: 10+20+40+80+160+320+640+1280 ≈ 2550 ms
    // Anything well below the uncapped figure proves the `.min(max_ms)`
    // is firing.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=8;failover_backoff_initial_ms=10;failover_backoff_max_ms=20",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("initial connect");
    let mut cursor = reader.query("select 1").execute().expect("execute");
    let start = Instant::now();
    let _ = cursor.next_batch();
    let elapsed = start.elapsed();
    // Generous upper bound: a working cap finishes in ~150ms+dials;
    // a broken cap (no `.min`) would take ~2.5s. 800ms is well below
    // the uncapped figure but well above any realistic capped run.
    assert!(
        elapsed < Duration::from_millis(800),
        "elapsed {:?} suggests the backoff cap is not being applied",
        elapsed
    );
}

#[test]
fn role_filter_propagates_through_failover() {
    // A is Replica, B is Primary, C is Replica. With target=primary,
    // the initial connect should accept B; if B drops mid-query,
    // failover should rotate past C (replica) and... since neither A
    // nor C matches, and B is the failed one, we expect the cursor
    // to error with a RoleMismatch-flavored failure (or exhaust).
    let a = MockServer::start(vec![happy_script(ServerRole::Replica, "a")]);
    // B's first accept is the initial-connect target (Primary). Once
    // it drops mid-query, the failover loop will keep rotating
    // through A/C (Replica → role-mismatched) and back to B. Make B's
    // subsequent accepts also fail at connect so the budget actually
    // exhausts instead of looping back to a still-healthy B.
    let b = MockServer::start(vec![
        drop_after_query_script(ServerRole::Primary, "b"),
        drop_at_connect_script(),
    ]);
    let c = MockServer::start(vec![happy_script(ServerRole::Replica, "c")]);
    let conf = format!(
        "qwp::addr={};target=primary;failover_max_attempts=2;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&a, &b, &c])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to B");
    assert_eq!(
        reader.current_addr().port,
        b.addr.port(),
        "initial picks B (the only primary)"
    );

    let mut cursor = reader.query("select 1").execute().expect("execute");
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail — no other primary"),
    };
    // Now that the surface logic prefers diagnostic codes over the
    // transport trigger, the user MUST see RoleMismatch even though
    // the last attempt may have hit a transport drop on B. Anything
    // else is a regression of M1 (silent restart hiding the real
    // configuration cause).
    assert_eq!(
        err.code(),
        ErrorCode::RoleMismatch,
        "expected RoleMismatch surfaced over transport trigger; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

#[test]
fn decode_error_does_not_trigger_failover_and_closes_transport() {
    // Server A serves the initial query, then sends a malformed frame
    // (well-formed QWP1 header, but a bogus msg_kind in the payload that
    // `decode_frame` will reject). The cursor MUST surface the decode
    // error as a hard `ProtocolError` — decode failures are deliberately
    // not failover-eligible (a wire/state bug isn't fixed by reconnecting,
    // and silently retrying would mask it from the user).
    //
    // Server B is a tripwire: any failover attempt would dial B.
    //
    // Additionally, the regression we're guarding against is C1 from
    // the review: on a decode error, the cursor used to leave the WS
    // open while the server kept streaming frames for the dead
    // request_id. A subsequent `Reader::query()` on the same Reader
    // would then read those stale frames and trip the cursor's
    // request_id check. We assert here that a follow-up query on the
    // same Reader fails at the transport layer (the WS was torn down)
    // rather than with a stale-request_id ProtocolError.
    let bogus_payload = vec![0xEEu8, 0, 0, 0, 0, 0, 0, 0, 0]; // unknown msg_kind.
    let bogus_frame = framed(2, 0, 0, &bogus_payload);
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendRaw(bogus_frame),
    ]]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    let callback_fires = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cb_clone = Arc::clone(&callback_fires);
    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |_| {
            cb_clone.fetch_add(1, Ordering::SeqCst);
        })
        .execute()
        .expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must surface a decode error"),
    };
    assert_eq!(
        err.code(),
        ErrorCode::ProtocolError,
        "decode error must surface as ProtocolError, got {:?}: {}",
        err.code(),
        err.msg()
    );
    assert_eq!(
        cursor.failover_resets(),
        0,
        "decode errors must not failover"
    );
    assert_eq!(
        callback_fires.load(Ordering::SeqCst),
        0,
        "on_failover_reset must not fire on decode errors"
    );
    assert_eq!(
        srv_b.accepts(),
        0,
        "B must never be dialed on a decode error"
    );
    drop(cursor);

    // C1 regression guard: the WS to A was torn down by the cursor,
    // so any follow-up `query()` on this Reader must fail at the
    // transport layer (write/read on a closed WS), NOT with a stale
    // ProtocolError from leftover RESULT_BATCH frames carrying the
    // previous cursor's request_id. The server-side worker has by
    // now seen our Close (or the half-closed TCP) and stopped its
    // script, so any frames the server might have queued are gone.
    let result = reader
        .query("select 1")
        .execute()
        .and_then(|mut c| c.next_batch().map(|_| ()));
    match result {
        Err(e) => {
            // A torn-down WS surfaces as a transport-flavoured failure
            // (SocketError on the write or read), or — if tungstenite
            // happened to flush our QUERY_REQUEST onto the socket
            // before the close fully landed — a HandshakeError from
            // the next read. ProtocolError with a request_id mismatch
            // is the regression we're guarding against; spell that
            // out so a future change can't pretend "it errored, good
            // enough."
            let msg = e.msg();
            assert!(
                !(e.code() == ErrorCode::ProtocolError && msg.contains("request_id")),
                "follow-up query saw stale request_id frames — \
                 the decode-error path failed to close the WS. err: {:?}: {}",
                e.code(),
                msg
            );
        }
        Ok(()) => panic!("follow-up query unexpectedly succeeded — the WS to A should be closed"),
    }
}

#[test]
fn cancel_write_failure_does_not_trigger_failover() {
    // M1 regression guard: when the CANCEL frame write fails synchronously
    // (because the server already RST'd the TCP connection by the time the
    // client tries to write), the cursor must NOT fall into the failover
    // path on a subsequent operation. The user explicitly asked to cancel
    // the query — silently replaying it on another endpoint violates that
    // contract.
    //
    // Reproducing the race:
    //   - Server A scripts: SERVER_INFO → AwaitQueryRequest → AbortiveRst
    //     (linger=0 + drop, so the next packet from the client gets RST'd
    //     by the kernel rather than FIN'd).
    //   - Client connects, executes, sleeps long enough for A's RST to be
    //     observed by its local kernel, then calls cancel().
    //   - The CANCEL write fails synchronously (Broken pipe / Connection
    //     reset). Without the M1 fix, `self.cancelling` would still be
    //     `false` at this point; the next `next_batch()` would see a
    //     transport error, classify it as failover-eligible, and reconnect
    //     to B to replay the cancelled query.
    //
    // Server B is here purely as a tripwire: any failover dial would
    // land on B. We assert `srv_b.accepts() == 0` regardless of whether
    // cancel() returned Ok or Err — the race may resolve either way; the
    // contract holds in both cases.
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::AbortiveRst,
    ]]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.query("select 1").execute().expect("execute");

    // Give the kernel time to observe A's RST on the client side. 100ms
    // is well over the loopback round-trip; flake risk is low.
    std::thread::sleep(Duration::from_millis(100));

    // cancel() may return Ok or Err depending on whether the client's
    // CANCEL write hit the kernel send buffer before or after the RST
    // landed. Both are valid for THIS test — the invariant under check
    // is "B is never dialed."
    let _ = cursor.cancel();
    // Drain anything the cursor still considers in flight. With the M1
    // fix, `cancelling=true` blocks the failover branch in next_batch
    // so transport errors propagate without reconnecting.
    while let Ok(Some(_)) = cursor.next_batch() {}

    drop(cursor);
    assert_eq!(
        srv_b.accepts(),
        0,
        "cancel() must record intent before writing — failed CANCEL write \
         must not failover-replay the cancelled query; got B accepts={}",
        srv_b.accepts()
    );
}

#[test]
fn unable_to_connect_classifies_as_socket_error() {
    // m10 regression guard: tungstenite's `UrlError::UnableToConnect`
    // (refused / unreachable / DNS-failed connect) is reclassified
    // as `SocketError`, not `ConfigError`. Without this, the failover
    // machinery — which keys on `is_failover_eligible` — would
    // short-circuit on a refused port and never walk past it.
    //
    // This test exercises the reclassification directly: connect to
    // a freshly-released loopback port (single endpoint, so no walk
    // can mask the result) and assert the surfaced code is
    // `SocketError`. A regression flipping it back to `ConfigError`
    // — or to anything non-failover-eligible — goes red here.
    let dead_addr = reserve_then_close_addr();
    let conf = format!("qwp::addr={}", dead_addr);
    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!("connecting to a closed port must error"),
    };
    assert_eq!(
        err.code(),
        ErrorCode::SocketError,
        "UnableToConnect must map to SocketError, got {:?}: {}",
        err.code(),
        err.msg(),
    );
}

#[test]
fn initial_connect_walks_past_auth_to_healthy_endpoint() {
    // Heterogeneous cluster: A 401s the upgrade, B accepts. AuthError
    // is *not* a guaranteed cluster-wide signal (mixed-version nodes,
    // partial credential rotation), so the connect walk must keep
    // going past it. If a later endpoint succeeds, we bind to that
    // one — A's auth rejection is observed but doesn't poison the
    // walk.
    let srv_a = MockServer::start(vec![vec![Action::Reject401]]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!("qwp::addr={}", build_addr_list(&[&srv_a, &srv_b]));

    let reader = Reader::from_conf(&conf).expect("walk past A's 401, bind to B");
    assert_eq!(
        reader.current_addr().port,
        srv_b.addr.port(),
        "must bind to B after A rejected with 401"
    );
    assert_eq!(srv_a.accepts(), 1, "A must have been dialed once");
    assert_eq!(srv_b.accepts(), 1, "B must have been dialed once");
}

#[test]
fn initial_connect_surfaces_auth_when_no_endpoint_succeeds() {
    // When the walk exhausts without success, the most diagnostic
    // error wins. AuthError tells the user *what to fix* — it must
    // rank above a generic transport flop on the other endpoint.
    let srv_a = MockServer::start(vec![vec![Action::Reject401]]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!("qwp::addr={}", build_addr_list(&[&srv_a, &srv_b]));

    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!("from_conf must error when no endpoint accepts"),
    };
    assert_eq!(
        err.code(),
        ErrorCode::AuthError,
        "AuthError must be preferred over the SocketError from B; got {:?}: {}",
        err.code(),
        err.msg(),
    );
}

#[test]
fn replay_preserves_payload_and_changes_request_id() {
    // T3 + T7 + M6 regression guard.
    //
    // After mid-query failover, the replayed QUERY_REQUEST sent on
    // the new connection must:
    //   (a) carry every original bind payload byte-for-byte (T3 / M6:
    //       guards against a regression where Bind cloning, builder
    //       mutation, or re-encode produces a different wire payload
    //       than the initial encode);
    //   (b) carry a freshly-allocated request_id distinct from the
    //       original (T7: the server must demux the new stream from
    //       any straggling frames the dead connection might emit, and
    //       the cursor must never replay with `request_id=0` — that's
    //       the server-side "no active streaming request" sentinel).
    //
    // Setup: A captures the initial QUERY_REQUEST then drops mid-stream
    // → triggers failover → B captures the replayed QUERY_REQUEST then
    // sends RESULT_END so the cursor completes cleanly.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    // Bind a couple of values so the replay actually exercises bind
    // encoding (not just SQL string identity). Mix integer + string
    // to cover both fixed-width and length-prefixed Bind variants.
    let mut cursor = reader
        .query("select * from t where i = $1 and s = $2")
        .bind_i64(42)
        .bind_varchar("hello world")
        .execute()
        .expect("execute");
    assert!(
        cursor
            .next_batch()
            .expect("complete after failover")
            .is_none(),
        "cursor must complete on B's RESULT_END after failover from A"
    );
    assert_eq!(
        cursor.failover_resets(),
        1,
        "exactly one successful failover (A drop → B replay)"
    );
    drop(cursor);

    let captured_a = srv_a.captured_requests();
    let captured_b = srv_b.captured_requests();
    assert_eq!(
        captured_a.len(),
        1,
        "A must have captured exactly one QUERY_REQUEST (the initial); got {}",
        captured_a.len()
    );
    assert_eq!(
        captured_b.len(),
        1,
        "B must have captured exactly one QUERY_REQUEST (the replay); got {}",
        captured_b.len()
    );
    let payload_a = &captured_a[0];
    let payload_b = &captured_b[0];

    // QUERY_REQUEST wire layout:
    //   [0]    msg_kind (= QueryRequest, 0x10)
    //   [1..9] request_id (i64 LE, 8 bytes)
    //   [9..]  varint sql_len, sql, varint initial_credit, varint
    //          binds_len, encoded binds...
    assert_eq!(
        payload_a[0], MSG_QUERY_REQUEST,
        "A's payload doesn't start with MsgKind::QueryRequest"
    );
    assert_eq!(
        payload_b[0], MSG_QUERY_REQUEST,
        "B's payload doesn't start with MsgKind::QueryRequest"
    );

    // T3 + M6: the body — SQL + binds — MUST be byte-identical
    // across the original and the replay. A regression here means
    // the cursor's stashed `encoded_request` was either re-encoded
    // (potentially picking up different bind state) or mutated
    // beyond the request_id span.
    assert_eq!(
        &payload_a[9..],
        &payload_b[9..],
        "QUERY_REQUEST body (sql + binds) must be byte-identical across replay",
    );

    // T7: request_id must change. Both must be strictly positive
    // (0 is the server's "no active stream" sentinel; alloc_request_id
    // must skip it on wrap).
    let rid_a = i64::from_le_bytes(payload_a[1..9].try_into().unwrap());
    let rid_b = i64::from_le_bytes(payload_b[1..9].try_into().unwrap());
    assert!(rid_a > 0, "original request_id must be > 0, got {}", rid_a);
    assert!(rid_b > 0, "replayed request_id must be > 0, got {}", rid_b);
    assert_ne!(
        rid_a, rid_b,
        "request_id must be re-allocated across failover (was {}, replayed as {})",
        rid_a, rid_b
    );
}

#[test]
fn failover_resets_counter_after_success_then_exhaustion() {
    // T5 regression guard. When a cursor successfully fails over
    // once, then a second mid-query failure exhausts the retry
    // budget, the user-observable counter must reflect the SUCCESS
    // count — not the attempt count, not double-counted, not zeroed.
    //
    // Trace:
    //   1. Initial connect lands on A. Cursor runs query. A drops
    //      mid-stream → next_batch read fails → failover #1 starts.
    //   2. Failover #1 reconnects to B (rotation skips the failed A
    //      first). Replay write to B succeeds → failover_resets=1,
    //      callback fires.
    //   3. Cursor reads from B. B drops mid-stream too → failover #2
    //      starts.
    //   4. Failover #2 walks the address list. With both A's and B's
    //      repeat slots being TCP-level drops at connect time, every
    //      inner attempt fails → reconnect_with_failover returns Err
    //      → outer cursor terminates.
    //
    // Expected end state:
    //   - cursor.next_batch() returned Err (transport-flavoured)
    //   - failover_resets() == 1 (only failover #1 succeeded)
    //   - on_failover_reset callback fired exactly once
    //   - cursor is terminal: a follow-up next_batch returns Ok(None)
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "b"),
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=1;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    let resets = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let resets_clone = Arc::clone(&resets);
    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |_| {
            resets_clone.fetch_add(1, Ordering::SeqCst);
        })
        .execute()
        .expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must surface budget-exhausted error after second failover"),
    };
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError
        ),
        "unexpected error code: {:?}: {}",
        err.code(),
        err.msg()
    );

    // The cursor saw exactly one successful reset (failover #1
    // landed on B and replayed). Failover #2 exhausted on the inner
    // reconnect_with_failover loop — no successful reset, so the
    // counter must NOT increment past 1.
    assert_eq!(
        cursor.failover_resets(),
        1,
        "exactly one successful reset; failover #2 exhausted before reconnect"
    );
    assert_eq!(
        resets.load(Ordering::SeqCst),
        1,
        "callback must have fired exactly once"
    );

    // Cursor terminal: a follow-up next_batch returns Ok(None),
    // not Err and not a stale frame.
    assert!(
        cursor
            .next_batch()
            .expect("terminal returns Ok(None)")
            .is_none(),
        "cursor must be terminal after exhaustion"
    );
}

#[test]
fn cursor_current_addr_tracks_failover_endpoint_switch() {
    // Regression guard for the `Cursor::current_addr()` accessor.
    //
    // The Reader's `current_addr()` is unreachable while a cursor
    // is live (the cursor mutably borrows the Reader), so the
    // user's only in-stream signal for "which endpoint did this
    // batch come from?" is `Cursor::current_addr`. This test pins
    // three observation points:
    //
    //   1. Right after `execute()` and before any frame arrives:
    //      the cursor must report the initial endpoint (A).
    //   2. Inside the `on_failover_reset` callback: by the time the
    //      user-supplied closure runs, the cursor must already be
    //      bound to the *new* endpoint — the contract is that the
    //      callback fires *before* the first replayed batch arrives,
    //      so an accessor read at this point must see B.
    //   3. After the cursor drains to terminal: still B, because
    //      no further reconnects happened.
    //
    // Without (2), users have to keep their own `Endpoint` shadow
    // copy via `FailoverEvent.new_addr` instead of asking the cursor
    // directly — the whole point of adding `Cursor::current_addr`.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    // Sanity: pre-cursor, the Reader sees A.
    assert_eq!(reader.current_addr().port, srv_a.addr.port());

    // Capture the addr observed inside the callback so the assertion
    // happens after the callback has executed (the callback's `&mut`
    // closure can't directly assert on the cursor — the cursor is
    // mid-call into `next_batch`).
    let observed_in_cb: Arc<Mutex<Option<(String, u16)>>> = Arc::new(Mutex::new(None));
    let observed_in_cb_clone = Arc::clone(&observed_in_cb);

    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |ev: &FailoverEvent| {
            // The callback receives the new endpoint via the event.
            // Record it; the test verifies `cursor.current_addr()`
            // matches once the closure returns.
            *observed_in_cb_clone.lock().unwrap() =
                Some((ev.new_addr.host.clone(), ev.new_addr.port));
        })
        .execute()
        .expect("execute");

    // (1) Pre-failover: cursor's accessor must report A.
    let pre = cursor.current_addr();
    assert_eq!(pre.host, "127.0.0.1");
    assert_eq!(
        pre.port,
        srv_a.addr.port(),
        "cursor.current_addr before any frame must be the initial endpoint A"
    );

    // Drive the failover.
    assert!(cursor.next_batch().expect("next after failover").is_none());
    assert_eq!(cursor.failover_resets(), 1);

    // (2) In-callback observation: the FailoverEvent should already
    // describe B, and `cursor.current_addr` should agree once the
    // call completes — both must reflect the new endpoint.
    let cb_addr = observed_in_cb
        .lock()
        .unwrap()
        .clone()
        .expect("callback fired and recorded the new addr");
    assert_eq!(cb_addr.0, "127.0.0.1");
    assert_eq!(
        cb_addr.1,
        srv_b.addr.port(),
        "FailoverEvent.new_addr passed to the callback must be the failover target B"
    );

    // (3) Post-drain: the cursor's accessor must agree with what
    // the callback saw — no further reconnects happened.
    let post = cursor.current_addr();
    assert_eq!(post.host, "127.0.0.1");
    assert_eq!(
        post.port,
        srv_b.addr.port(),
        "cursor.current_addr after the cursor terminates must be the failover target B"
    );

    // And once the cursor is dropped, Reader::current_addr agrees too —
    // the public accessor on Reader and Cursor must not diverge.
    drop(cursor);
    assert_eq!(reader.current_addr().port, srv_b.addr.port());
}

#[test]
fn failover_callback_runs_before_replayed_read() {
    // Documented contract on `ReaderQuery::on_failover_reset`:
    //   "The closure ... runs *before* any replayed `RESULT_BATCH`
    //    arrives — the user-side handler must use this signal to
    //    discard rows it had accumulated from the previous (now-dead)
    //    connection."
    //
    // The cursor calls the closure synchronously inside
    // `failover_reconnect_and_replay`, before the outer `next_batch`
    // loop continues to read the first frame off the new transport.
    // That ordering is what lets users clear accumulated state
    // without racing the next batch.
    //
    // We pin it by parking inside the callback. If the callback is
    // genuinely on the pre-read path, the wall-clock time
    // `next_batch` takes must include the park time. If a future
    // refactor moves the callback after the first read (or onto a
    // background thread), `next_batch` would return well before the
    // park finishes and this test goes red.
    //
    // 100ms is comfortably above any plausible reconnect+handshake
    // jitter on loopback (single-digit ms in practice) so the
    // upper-bound assertion below stays reliable.
    let parked_for = Duration::from_millis(100);

    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    // Capture the wall-clock instant the callback fires so we can
    // assert it ran *during* the next_batch call, not after.
    let cb_started_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let cb_started_clone = Arc::clone(&cb_started_at);

    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |_ev: &FailoverEvent| {
            *cb_started_clone.lock().unwrap() = Some(Instant::now());
            std::thread::sleep(parked_for);
        })
        .execute()
        .expect("execute");

    let next_started = Instant::now();
    assert!(cursor.next_batch().expect("next").is_none());
    let next_elapsed = next_started.elapsed();

    let cb_at = cb_started_at
        .lock()
        .unwrap()
        .expect("callback must have fired before next_batch returned");

    // The callback must have started AFTER next_batch began (it can't
    // run before the read failure is observed) and at least one parked
    // duration must have elapsed before next_batch returned.
    assert!(
        cb_at >= next_started,
        "callback fired before next_batch even started? clock skew?"
    );
    assert!(
        next_elapsed >= parked_for,
        "next_batch returned in {:?}, less than the {:?} the callback parked for — \
         the callback must run inline before next_batch returns, not after or async",
        next_elapsed,
        parked_for,
    );

    // Sanity: the cursor really did reset and land on B.
    assert_eq!(cursor.failover_resets(), 1);
}

#[test]
fn rotation_wraps_to_index_zero_when_failed_is_last() {
    // Pins the wrap path of `(failed_idx + 1 + attempt) % n`.
    //
    // Topology: 4 servers, parsed in order S0, S1, S2, S3. We force
    // initial connect to land on S3 (idx 3) by making S0..S2 reject
    // their first connect. Then S3 drops mid-query. With `n = 4` and
    // `failed_idx = 3`, the very first failover dial is
    // `(3 + 1 + 0) % 4 == 0` — i.e. S0. So:
    //
    //   * If the rotation arithmetic is correct, S0's *second* accept
    //     receives the dial and answers happily; the cursor terminates
    //     bound to S0.
    //   * If the rotation skipped S0 (e.g. wrapped to a different
    //     index), the cursor would land on S1 or S2 (both still
    //     dead), the failover budget would exhaust, and the
    //     final-endpoint assertion would fail.
    //
    // `failover_max_attempts=1` (so `attempts_total=2`) keeps the
    // budget tight: only ONE failover dial is permitted to land,
    // forcing the rotation to be correct on the first try.
    let s0 = MockServer::start(vec![
        // First accept fails the initial walk.
        drop_at_connect_script(),
        // Second accept = the failover-target dial. If rotation is
        // correct, this is the slot that completes the query.
        happy_script(ServerRole::Standalone, "s0-recovered"),
    ]);
    let s1 = MockServer::start(vec![drop_at_connect_script()]);
    let s2 = MockServer::start(vec![drop_at_connect_script()]);
    let s3 = MockServer::start(vec![
        // Initial walk: only S3 succeeds, so addr_idx lands on 3.
        drop_after_query_script(ServerRole::Standalone, "s3"),
        // Future accepts: dead. Prevents the rotation from
        // accidentally healing S3 if the test is wrong about which
        // slot the dial hits.
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=1;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&s0, &s1, &s2, &s3])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect walks to S3");
    assert_eq!(
        reader.current_addr().port,
        s3.addr.port(),
        "initial connect must land on the only-healthy endpoint S3 (idx 3)"
    );

    let mut cursor = reader.query("select 1").execute().expect("execute");
    assert!(
        cursor
            .next_batch()
            .expect("must complete via wrap to S0")
            .is_none(),
        "cursor must complete after wrapping to idx 0"
    );
    assert_eq!(cursor.failover_resets(), 1);
    drop(cursor);

    assert_eq!(
        reader.current_addr().port,
        s0.addr.port(),
        "rotation must wrap from failed_idx=3 to idx 0 — final endpoint must be S0"
    );

    // S1 and S2 must NOT have been dialed during failover. With
    // `attempts_total=2` and a successful first dial, only one
    // failover attempt happens and it must hit S0 (the wrap target).
    // If S1 or S2 saw a connect during failover, the rotation
    // produced a different first index. (Initial-walk dials count
    // toward `accepts()` too — those are 1 each on S1 and S2.)
    assert_eq!(
        s1.accepts(),
        1,
        "S1 must only see the initial-walk dial, not a failover dial"
    );
    assert_eq!(
        s2.accepts(),
        1,
        "S2 must only see the initial-walk dial, not a failover dial"
    );
}

#[test]
fn on_failover_reset_callback_replacement() {
    // The builder's `on_failover_reset` doc states: "Calling this
    // method twice on the same `ReaderQuery` *replaces* the previous
    // closure — only the most recent callback is invoked." Pin that.
    //
    // Without this guard, a refactor that switched from
    // `Option<Box<dyn FnMut>>` to e.g. a `Vec<...>` of stacked
    // callbacks would break user code that relies on idempotent
    // builder reuse (set once, override later) without any compile
    // error.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    let first_fires = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let second_fires = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let first_clone = Arc::clone(&first_fires);
    let second_clone = Arc::clone(&second_fires);

    let mut cursor = reader
        .query("select 1")
        // First callback — should be replaced by the call below.
        .on_failover_reset(move |_| {
            first_clone.fetch_add(1, Ordering::SeqCst);
        })
        // Second callback — must be the only one that fires.
        .on_failover_reset(move |_| {
            second_clone.fetch_add(1, Ordering::SeqCst);
        })
        .execute()
        .expect("execute");

    assert!(cursor.next_batch().expect("next").is_none());
    assert_eq!(cursor.failover_resets(), 1);
    assert_eq!(
        first_fires.load(Ordering::SeqCst),
        0,
        "the first callback must have been REPLACED, not stacked"
    );
    assert_eq!(
        second_fires.load(Ordering::SeqCst),
        1,
        "only the second (most-recently-installed) callback may fire"
    );
}

#[test]
fn all_role_mismatch_endpoints_during_failover_surfaces_role_mismatch() {
    // Test gap from the review: `role_filter_propagates_through_failover`
    // mixes RoleMismatch with transport drops on the rotation. There
    // was no pure all-RoleMismatch reconnect test exercising the
    // soft-skip path: every reconnect attempt must connect cleanly,
    // get a SERVER_INFO advertising a non-matching role, return
    // RoleMismatch from `connect_endpoint`, accumulate it as
    // `last_role_mismatch` in `reconnect_with_failover`, and walk
    // past. After budget exhaustion, the cursor's surfaced error
    // must be RoleMismatch (not a transport flop, not a generic
    // SocketError).
    //
    // Topology: A is Primary on the first accept (so initial connect
    // lands), then drops mid-query. On every subsequent accept of
    // any server, the role advertised is Replica — so the failover
    // loop walks the full rotation, gets RoleMismatch from each, and
    // exhausts. With `target=primary`, NONE of those endpoints can
    // satisfy the filter.
    //
    // Without this guard, a regression that promoted RoleMismatch to
    // a hard error (returning immediately from
    // `reconnect_with_failover` instead of accumulating it) would
    // surface AuthError-style behaviour against a perfectly normal
    // mid-query topology change — and a regression that demoted
    // RoleMismatch to a soft transport flop would surface SocketError
    // to the user and lose the diagnostic-rich code.
    let a = MockServer::start(vec![
        // Initial-walk dial: Primary, so initial connect succeeds.
        drop_after_query_script(ServerRole::Primary, "a-primary"),
        // Subsequent dials: Replica; cleanly handshakes and advertises
        // SERVER_INFO so `connect_endpoint` reaches the role check
        // and returns RoleMismatch (not a transport error).
        happy_script(ServerRole::Replica, "a-replica"),
    ]);
    let b = MockServer::start(vec![happy_script(ServerRole::Replica, "b")]);
    let c = MockServer::start(vec![happy_script(ServerRole::Replica, "c")]);
    let conf = format!(
        "qwp::addr={};target=primary;failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&a, &b, &c])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A as Primary");
    assert_eq!(
        reader.current_addr().port,
        a.addr.port(),
        "initial picks A (the only Primary on first accept)"
    );

    let cb_fires = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let cb_clone = Arc::clone(&cb_fires);
    let mut cursor = reader
        .query("select 1")
        .on_failover_reset(move |_| {
            cb_clone.fetch_add(1, Ordering::SeqCst);
        })
        .execute()
        .expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail — every reconnect target advertises Replica"),
    };
    assert_eq!(
        err.code(),
        ErrorCode::RoleMismatch,
        "cursor must surface RoleMismatch over the transport trigger; got {:?}: {}",
        err.code(),
        err.msg()
    );
    assert_eq!(
        cursor.failover_resets(),
        0,
        "no successful reset happened (every attempt was RoleMismatch)"
    );
    assert_eq!(
        cb_fires.load(Ordering::SeqCst),
        0,
        "on_failover_reset must NOT fire when failover exhausts without success"
    );

    // The cursor must be terminal — a follow-up next_batch returns
    // Ok(None), not Err and not a stale frame.
    assert!(
        cursor
            .next_batch()
            .expect("terminal returns Ok(None)")
            .is_none(),
        "cursor must be terminal after RoleMismatch exhaustion"
    );
}

#[test]
fn failover_constants_reexported_at_egress_root() {
    // The defaults and hard caps that drive failover behaviour
    // (`DEFAULT_FAILOVER_*`, `MAX_FAILOVER_MAX_ATTEMPTS`, `MAX_ADDRS`,
    // `MAX_FAILOVER_BACKOFF_MAX_MS`) are part of the public contract:
    // user code wires them into its own configuration code paths,
    // metric labels, and validation. The natural import path for
    // them is `questdb::egress::*`, alongside `Endpoint`, `Reader`,
    // and friends — not `questdb::egress::config::*`. This test
    // pins the re-export and would go red if any of the constants
    // were demoted to `pub(crate)` or dropped from `mod.rs`'s
    // `pub use config::{...}` list.
    //
    // Asserts each constant against its documented default/cap so
    // a value drift (e.g. a future tweak from 8 to 4 retry attempts)
    // also forces this test — and the constants table in the module
    // docs — to be revisited together.
    use questdb::egress::{
        DEFAULT_FAILOVER_BACKOFF_INITIAL_MS, DEFAULT_FAILOVER_BACKOFF_MAX_MS,
        DEFAULT_FAILOVER_ENABLED, DEFAULT_FAILOVER_MAX_ATTEMPTS, MAX_ADDRS,
        MAX_FAILOVER_BACKOFF_MAX_MS, MAX_FAILOVER_MAX_ATTEMPTS,
    };

    // `const` block to satisfy `clippy::assertions_on_constants`
    // and `clippy::bool_assert_comparison` simultaneously: an
    // `assert_eq!(.., true)` lints the same as `assert!(const)`.
    const _: () = assert!(DEFAULT_FAILOVER_ENABLED);
    assert_eq!(DEFAULT_FAILOVER_MAX_ATTEMPTS, 8);
    assert_eq!(DEFAULT_FAILOVER_BACKOFF_INITIAL_MS, 50);
    assert_eq!(DEFAULT_FAILOVER_BACKOFF_MAX_MS, 1_000);
    assert_eq!(MAX_FAILOVER_MAX_ATTEMPTS, 1024);
    assert_eq!(MAX_ADDRS, 1024);
    assert_eq!(MAX_FAILOVER_BACKOFF_MAX_MS, 60 * 60 * 1_000);

    // Cross-check: the parsed `ReaderConfig` defaults must match the
    // re-exported constants. If they ever drift (someone bumps the
    // const but forgets the parser default, or vice versa), users
    // who compare against the constants would see surprising
    // behaviour at runtime — pin the equality.
    let cfg = questdb::egress::ReaderConfig::from_conf("qwp::addr=h:1").expect("parse");
    assert_eq!(cfg.failover, DEFAULT_FAILOVER_ENABLED);
    assert_eq!(cfg.failover_max_attempts, DEFAULT_FAILOVER_MAX_ATTEMPTS);
    assert_eq!(
        cfg.failover_backoff_initial_ms,
        DEFAULT_FAILOVER_BACKOFF_INITIAL_MS
    );
    assert_eq!(cfg.failover_backoff_max_ms, DEFAULT_FAILOVER_BACKOFF_MAX_MS);
}
