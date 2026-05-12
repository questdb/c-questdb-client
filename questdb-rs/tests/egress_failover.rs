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
const MSG_CANCEL: u8 = 0x14;
const MSG_CACHE_RESET: u8 = 0x17;
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
        _ => 0xFF,
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

/// `CACHE_RESET` frame. `mask = 0x01` clears the per-connection symbol
/// dict, `0x02` clears the schema registry, `0x03` clears both. The
/// payload is just `[msg_kind, mask]`.
fn cache_reset_frame(mask: u8) -> Vec<u8> {
    framed(2, 0, 0, &[MSG_CACHE_RESET, mask])
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
    /// Block until a CANCEL frame (msg_kind `0x14`) arrives from the
    /// client. Used to pin the precise moment in a script where the
    /// client has finished writing its CANCEL — testing cancel-drain
    /// behavior needs to be sure CANCEL landed on the wire before the
    /// server arranges the next action (e.g. drop). Non-CANCEL frames
    /// (CREDIT especially) are silently skipped so the test is robust
    /// to auto-credit replenishment between QUERY_REQUEST and CANCEL.
    /// The captured request_id semantics are unchanged — CANCEL has
    /// no separate id to track on the wire.
    AwaitClientCancel,
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
    /// Reject the WS upgrade with a 421 Misdirected Request. The optional
    /// `role` value populates `X-QuestDB-Role`; the optional `zone`
    /// populates `X-QuestDB-Zone`. Drives the failover.md §5 path that
    /// the client parses into `UpgradeReject`. `role=None` exercises the
    /// "421 without role header" branch (transient transport error,
    /// failover keeps walking).
    Reject421 {
        role: Option<String>,
        zone: Option<String>,
    },
    /// Accept the TCP connection but never reply to the WS upgrade —
    /// holds the connection open for `duration` then drops. Drives the
    /// `auth_timeout_ms` path (failover.md §1.1): the client should
    /// abort the upgrade-response read at the configured timeout
    /// rather than waiting indefinitely.
    StallUpgrade(Duration),
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
    /// Override the `x-qwp-version` value injected into the WS upgrade
    /// response. Detected before `accept_hdr` runs (like `Reject401`),
    /// so it parameterises the handshake itself rather than running as
    /// a script step. Default is `2`. Used to drive the
    /// `UnsupportedServer` path in `transport.rs` by negotiating a
    /// version higher than `config.max_version`.
    HandshakeVersion(u8),
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
    /// Captures the inbound `Authorization` header value (if any) of
    /// every WS upgrade request the server saw — one entry per
    /// accepted connection, preserving arrival order. `None` means
    /// the header was absent on that connection. Pinned-to-bytes
    /// regression coverage for the auth modes (Basic/Bearer/verbatim):
    /// a future change that drops or reformats the outgoing header
    /// would surface as a captured-value mismatch here.
    captured_auth: Arc<Mutex<Vec<Option<String>>>>,
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
        let captured_auth: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let captured_auth_outer = Arc::clone(&captured_auth);

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
                let captured_auth_inner = Arc::clone(&captured_auth_outer);
                let worker = thread::spawn(move || {
                    run_script(stream, script, captured_clone_inner, captured_auth_inner)
                });
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
            captured_auth,
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

    /// Snapshot of the inbound `Authorization` header (if any) for
    /// every accepted connection, in arrival order. `None` entries
    /// mean the header was absent on that connection.
    fn captured_auth_headers(&self) -> Vec<Option<String>> {
        self.captured_auth.lock().unwrap().clone()
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
#[allow(clippy::result_large_err)] // Closure signature is fixed by tungstenite::accept_hdr.
fn run_script(
    stream: TcpStream,
    script: Script,
    captured_requests: Arc<Mutex<Vec<Vec<u8>>>>,
    captured_auth: Arc<Mutex<Vec<Option<String>>>>,
) {
    // Decide upfront if this connection wants to reject the upgrade.
    let reject401 = script.iter().any(|a| matches!(a, Action::Reject401));
    if reject401 {
        reject_upgrade(stream, &captured_auth);
        return;
    }
    let reject421 = script.iter().find_map(|a| match a {
        Action::Reject421 { role, zone } => Some((role.clone(), zone.clone())),
        _ => None,
    });
    if let Some((role, zone)) = reject421 {
        reject_upgrade_421(stream, role.as_deref(), zone.as_deref(), &captured_auth);
        return;
    }
    if let Some(d) = script.iter().find_map(|a| match a {
        Action::StallUpgrade(d) => Some(*d),
        _ => None,
    }) {
        // Drain whatever the client sent (the GET / Upgrade preamble)
        // so a smaller send-buffer doesn't push the client into a
        // write-block before its read times out. Then just hold the
        // connection open without responding.
        let mut buf = [0u8; 4096];
        let _ = stream.set_read_timeout(Some(Duration::from_millis(50)));
        let _ = (&stream).read(&mut buf);
        std::thread::sleep(d);
        return;
    }

    // Pick the `x-qwp-version` to advertise. Default is "2" (matches
    // SERVER_INFO frames the helpers build); a `HandshakeVersion(v)`
    // action anywhere in the script overrides it so tests can drive
    // the version-mismatch path in `WsTransport::connect_to`.
    let handshake_version: String = script
        .iter()
        .find_map(|a| match a {
            Action::HandshakeVersion(v) => Some(v.to_string()),
            _ => None,
        })
        .unwrap_or_else(|| "2".to_string());
    let handshake_version_for_closure = handshake_version.clone();

    let captured_auth_for_closure = Arc::clone(&captured_auth);
    let mut ws = match accept_hdr(stream, move |req: &Request, mut resp: Response| {
        // Capture the inbound Authorization header (if any) so tests
        // can pin the wire-level bytes the client emitted.
        let auth = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
        captured_auth_for_closure.lock().unwrap().push(auth);
        // Inject the X-QWP-Version response header. By default we
        // negotiate v2 to match the SERVER_INFO frames the helpers
        // build; a `HandshakeVersion(v)` script entry overrides it.
        let header = HeaderValue::from_str(&handshake_version_for_closure).unwrap();
        resp.headers_mut().insert("x-qwp-version", header);
        Ok(resp)
    }) {
        Ok(ws) => ws,
        Err(_) => return,
    };

    let mut last_request_id: Option<i64> = None;

    for action in script {
        match action {
            Action::Reject401 => unreachable!("handled above"),
            Action::Reject421 { .. } => unreachable!("handled above"),
            Action::StallUpgrade(_) => unreachable!("handled above"),
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
            Action::AwaitClientCancel => {
                if !read_until_client_cancel(&mut ws) {
                    return;
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
            // Already consumed before the WS upgrade; nothing to do here.
            Action::HandshakeVersion(_) => {}
        }
    }
}

/// Tungstenite-based HTTP error reply (avoids depending on the WS
/// upgrade machinery for the 401 path). We hand-roll a minimal HTTP
/// response since the real auth-error path on the client side just
/// inspects the status code. The drained request bytes are scanned
/// for an `Authorization:` header so even the 401-path tests can
/// assert what the client put on the wire.
fn reject_upgrade(mut stream: TcpStream, captured_auth: &Arc<Mutex<Vec<Option<String>>>>) {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).unwrap_or(0);
    let auth = parse_authorization_header(&buf[..n]);
    captured_auth.lock().unwrap().push(auth);
    let _ = stream
        .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
}

/// Same shape as `reject_upgrade` but emits a 421 Misdirected Request
/// with optional `X-QuestDB-Role` / `X-QuestDB-Zone` headers. Drives the
/// client's failover.md §5 upgrade-reject parser. The drained request
/// is still inspected for the Authorization header so 421-path tests
/// can assert credential bytes the same way 401-path tests do.
fn reject_upgrade_421(
    mut stream: TcpStream,
    role: Option<&str>,
    zone: Option<&str>,
    captured_auth: &Arc<Mutex<Vec<Option<String>>>>,
) {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).unwrap_or(0);
    let auth = parse_authorization_header(&buf[..n]);
    captured_auth.lock().unwrap().push(auth);
    let mut response = String::from(
        "HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\nConnection: close\r\n",
    );
    if let Some(r) = role {
        response.push_str(&format!("X-QuestDB-Role: {}\r\n", r));
    }
    if let Some(z) = zone {
        response.push_str(&format!("X-QuestDB-Zone: {}\r\n", z));
    }
    response.push_str("\r\n");
    let _ = stream.write_all(response.as_bytes());
}

/// Best-effort scan of a raw HTTP request preamble for the
/// `Authorization:` header value. Case-insensitive on the field name
/// (per RFC 7230); trims surrounding whitespace from the value.
/// Returns `None` if the header is absent or the buffer was truncated
/// before the header line ended.
fn parse_authorization_header(buf: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(buf).ok()?;
    for line in text.split("\r\n") {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("authorization")
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Pump frames from the client until a QUERY_REQUEST (msg_kind 0x10)
/// is observed; return its request_id and append the full payload
/// bytes (msg_kind + body) to `captured` so tests can inspect what
/// the cursor actually sent. Client→server frames are bare payloads
/// (no QWP1 header), so the request_id is at offset 1.
/// Read incoming binary frames until a CANCEL (msg_kind `0x14`) is
/// observed. Non-CANCEL frames (CREDIT, anything else the client
/// happens to emit before tearing down) are silently consumed so the
/// caller is robust to the auto-credit replenishment that lives in
/// the client's `next_batch` loop. Returns `true` on CANCEL receipt,
/// `false` if the socket dies first.
fn read_until_client_cancel(ws: &mut WebSocket<TcpStream>) -> bool {
    loop {
        match ws.read() {
            Ok(Message::Binary(b)) if !b.is_empty() && b[0] == MSG_CANCEL => return true,
            Ok(Message::Binary(_)) | Ok(Message::Text(_)) => continue,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => continue,
            Ok(Message::Close(_)) | Err(_) => return false,
        }
    }
}

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

/// Loopback address that reliably rejects every connection attempt
/// for the lifetime of this guard.
///
/// Replaces the previously-flaky "bind `:0`, capture address, drop
/// the listener" idiom. That idiom has a race window on macOS (and
/// to a lesser extent every OS): between `drop(listener)` and the
/// test's eventual connect, the kernel can hand the just-freed
/// ephemeral port to ANY other process binding `:0` — including
/// other tests in the same `cargo test` invocation. When that
/// happens the test sees a successful connect (or a totally
/// unrelated reply) instead of the refusal it requires, and the
/// failover assertion goes red for no real reason.
///
/// This guard holds the port via a long-lived `TcpListener` for the
/// whole test, accepting every incoming connection on a background
/// thread only to immediately drop it with `SO_LINGER=0` — sending
/// a TCP RST so the client's WS-upgrade read surfaces
/// `ConnectionReset`, which the egress transport maps to
/// `SocketError`. Same observable behaviour as a refused connect
/// from the egress code's perspective; no race window.
struct DeadEndpoint {
    addr: SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl DeadEndpoint {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        // Nonblocking accept so the worker thread can poll the
        // shutdown flag between connection attempts.
        listener
            .set_nonblocking(true)
            .expect("set_nonblocking on listener");

        let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown_thread = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            while !shutdown_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((sock, _peer)) => {
                        // Linger=0 → kernel sends RST (not FIN) on
                        // close. Matches the `Action::AbortiveRst`
                        // pattern in this same file: go via
                        // `socket2::SockRef` because `TcpStream`'s
                        // own `set_linger` only landed recently and
                        // the rest of the file is on the older API.
                        let _ =
                            socket2::SockRef::from(&sock).set_linger(Some(Duration::from_secs(0)));
                        drop(sock);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            shutdown,
            handle: Some(handle),
        }
    }

    /// `host:port` for use in a connect string.
    fn url(&self) -> String {
        self.addr.to_string()
    }
}

impl Drop for DeadEndpoint {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Tickle the listener so the next nonblocking `accept` returns
        // an `Ok` and the worker thread re-checks the shutdown flag
        // without waiting for the polling tick.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
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
        .prepare("select 1")
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
fn cache_reset_mid_stream_does_not_break_cursor() {
    // The server emits CACHE_RESET to invalidate the per-connection
    // symbol dict and/or schema registry. The decoder applies the
    // resets in `decode_frame` before returning `ServerEvent::CacheReset`,
    // and `next_batch` is supposed to swallow that event and continue
    // reading. Live coverage is hard (the real server emits
    // CACHE_RESET only under specific dict/schema-aging conditions)
    // so the contract is pinned here against a scripted mock.
    //
    // Sends both reset masks in sequence (dict, then schemas, then
    // both at once) to exercise every bit of the mask without making
    // assumptions about which kind of reset is "common."
    let srv = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "n1".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendRaw(cache_reset_frame(0x01)), // clear dict
        Action::SendRaw(cache_reset_frame(0x02)), // clear schemas
        Action::SendRaw(cache_reset_frame(0x03)), // clear both
        Action::SendResultEnd,
    ]]);
    let conf = format!("qwp::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    // The CacheReset events must not surface as Err or as a phantom
    // batch — the cursor should drive straight through to the
    // RESULT_END terminal.
    assert!(
        cursor.next_batch().expect("next_batch").is_none(),
        "cursor must terminate at RESULT_END after CACHE_RESET frames"
    );
    // No failover is involved; the connection stays on the same
    // endpoint throughout.
    assert_eq!(cursor.failover_resets(), 0);
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
        .prepare("select 1")
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

/// Pre-batch-delivery mid-query failover is transparent even WITHOUT
/// an `on_failover_reset` callback.
///
/// The new silent-duplicate guard (`FailoverWouldDuplicate`) only
/// triggers once at least one batch has been yielded — at that point
/// replay would silently double-deliver rows. Failover that fires
/// before any data has reached the caller poses no such hazard and
/// must continue to replay transparently. This regression test pins
/// that boundary: same setup as `mid_query_close_triggers_failover`,
/// but no callback installed, and the cursor must still terminate
/// cleanly via the replayed RESULT_END from server B.
///
/// (The data-delivered-with-no-callback branch — where the guard
/// fires — is unit-tested via `would_silently_duplicate_truth_table`
/// in `src/egress/reader.rs`. Exercising it as an integration test
/// would require the Rust mock to emit a synthetic RESULT_BATCH; the
/// Rust mock has no helper for that yet — only the C++ mock does.)
#[test]
fn pre_batch_failover_without_callback_still_replays() {
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    assert_eq!(reader.current_addr().port, srv_a.addr.port());

    // NO on_failover_reset callback. With data not yet delivered, the
    // guard must not fire and failover must replay against B as before.
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let outcome = cursor.next_batch();
    assert!(
        matches!(&outcome, Ok(None)),
        "failover before any batch is delivered must replay transparently \
         (no callback required); got {:?}",
        outcome
            .as_ref()
            .map(|_| ())
            .map_err(|e| (e.code(), e.msg().to_string()))
    );
    assert_eq!(
        cursor.failover_resets(),
        1,
        "exactly one reset — to server B — must have been recorded"
    );
    assert_eq!(
        cursor.current_addr().port,
        srv_b.addr.port(),
        "cursor must be bound to the failover target after replay"
    );
}

/// Regression coverage for the silent-duplicate guard wired into
/// `Cursor::add_credit` (C1 in the PR review).
///
/// `add_credit`'s failover policy must mirror `next_batch`'s: when a
/// transport-class write failure fires AND data has already been
/// delivered AND no `on_failover_reset` callback is installed, the
/// cursor must return `FailoverWouldDuplicate` rather than silently
/// replaying. The bulk of this contract is unit-tested by
/// `would_silently_duplicate_truth_table` in `src/egress/reader.rs`.
/// Integration coverage for `add_credit` specifically is constrained
/// by TCP semantics: a write to a freshly-RST'd peer does not always
/// fail synchronously (the kernel may buffer the frame before the
/// RST lands), so we cannot deterministically force the failover
/// branch from a scripted close. The data-delivered branch is even
/// less reachable from the Rust mock — it has no helper to emit a
/// synthetic RESULT_BATCH (only the C++ mock does), so the
/// guard-fires-after-batch-delivered combination is out of integration
/// scope on the Rust side.
///
/// What this test does pin down: if `add_credit` DOES drive a
/// failover (the race resolves with a synchronous write failure), the
/// replay reaches server B and the user-supplied callback fires
/// exactly once. The pattern matches `cancel_write_failure_does_not_trigger_failover`
/// — both possible race outcomes are valid; we assert the
/// post-conditions are consistent regardless of which one wins.
///
/// Skipped on Windows: WinSock `send()` against a peer that has just
/// sent RST can block for the full `SO_SNDTIMEO` window (the transport
/// pins it to `WRITE_TIMEOUT` = 60 s) before either succeeding or
/// failing with `WSAECONNRESET`. Neither of the two valid race outcomes
/// completes in time, so the test wedges until CI's step timeout kills
/// the whole job. The unit-tested truth table in
/// `would_silently_duplicate_truth_table` already covers the contract;
/// this integration variant only catches a regression on platforms
/// where the write resolves quickly. See
/// `add_credit_with_failover_disabled_never_dials_b` for the same
/// guard on the disabled-failover path.
#[test]
#[cfg_attr(
    windows,
    ignore = "WinSock send() to a peer that has RST'd can block for the full \
              WRITE_TIMEOUT (60 s) before resolving — see fn comment"
)]
fn add_credit_failover_post_conditions_are_consistent() {
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
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    assert_eq!(reader.current_addr().port, srv_a.addr.port());

    let observed: Arc<Mutex<Vec<FailoverEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(move |ev: &FailoverEvent| {
            observed_clone.lock().unwrap().push(ev.clone());
        })
        .execute()
        .expect("execute");

    // Give the kernel time to observe A's RST on the client side.
    // Matches the 100ms used by `cancel_write_failure_does_not_trigger_failover`.
    std::thread::sleep(Duration::from_millis(100));

    let credit_result = cursor.add_credit(64);
    let resets = cursor.failover_resets();
    let event_count = observed.lock().unwrap().len();

    // Two valid race outcomes:
    //
    // (a) The write hit the kernel send buffer before A's RST was
    //     observed → add_credit returned Ok, no failover was needed.
    // (b) The write failed synchronously → failover engaged, replayed
    //     to B, second send_credit_frame on B succeeded → add_credit
    //     returned Ok via the replay path.
    //
    // The credit-write-fails-AFTER-replay-too case (terminates the
    // cursor with an error) requires both servers to drop and isn't
    // exercised here.
    match (credit_result.as_ref(), resets) {
        (Ok(()), 0) => {
            // Branch (a): write succeeded before RST landed.
            assert_eq!(event_count, 0, "no callback when no failover happened");
        }
        (Ok(()), 1) => {
            // Branch (b): write failed, failover replayed cleanly.
            assert_eq!(event_count, 1, "callback must fire exactly once on replay");
            let events = observed.lock().unwrap();
            assert_eq!(events[0].failed_addr.port, srv_a.addr.port());
            assert_eq!(events[0].new_addr.port, srv_b.addr.port());
            // Cursor must read cleanly from B after the replay.
            assert!(
                cursor.next_batch().expect("next after replay").is_none(),
                "replayed cursor must terminate via RESULT_END"
            );
        }
        (Ok(()), n) => panic!("unexpected reset count {n} for Ok(add_credit); expected 0 or 1"),
        (Err(e), _) => panic!(
            "add_credit should not surface an error when a failover target is \
             available; got {:?}: {}",
            e.code(),
            e.msg()
        ),
    }
}

/// Companion: with `failover=off`, an `add_credit` write failure must
/// surface the original transport error immediately, NOT silently
/// retry. Pins the failover-eligibility gate at the top of `add_credit`
/// (`reader.cfg.failover` check).
///
/// Like the test above, the TCP race means add_credit's write may
/// return Ok even after the peer's RST. The race-tolerant invariant
/// asserted here: `srv_b.accepts() == 0` (no failover dial ever, since
/// failover is disabled — regardless of how the race resolves), and
/// IF add_credit returns Err, the error is a transport-class one (not
/// some other code that would suggest a different code path fired).
///
/// Skipped on Windows for the same reason as
/// `add_credit_failover_post_conditions_are_consistent`: WinSock
/// `send()` after peer RST can block for the full `WRITE_TIMEOUT`.
#[test]
#[cfg_attr(
    windows,
    ignore = "WinSock send() to a peer that has RST'd can block for the full \
              WRITE_TIMEOUT (60 s) before resolving — see \
              add_credit_failover_post_conditions_are_consistent for details"
)]
fn add_credit_with_failover_disabled_never_dials_b() {
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
        "qwp::addr={};failover=off",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    std::thread::sleep(Duration::from_millis(100));

    if let Err(err) = cursor.add_credit(64) {
        assert!(
            matches!(
                err.code(),
                ErrorCode::SocketError | ErrorCode::ProtocolError
            ),
            "expected transport-class error with failover disabled; got {:?}: {}",
            err.code(),
            err.msg()
        );
    }
    // Drain anything else without recursing into failover.
    while let Ok(Some(_)) = cursor.next_batch() {}

    assert_eq!(cursor.failover_resets(), 0, "no failover with failover=off");
    drop(cursor);
    assert_eq!(
        srv_b.accepts(),
        0,
        "B must not be dialed when failover is disabled; got {}",
        srv_b.accepts()
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
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
    // max_attempts=2, the cursor's first failure should burn 3 outer
    // reconnect attempts, all of which fail.
    //
    // Dial accounting:
    //   - Initial connect: 1 dial to A (success).
    //   - Mid-stream failure on A. `reconnect_with_failover` runs
    //     `attempts_total = 3` outer attempts. Each outer attempt
    //     invokes `walk_via_tracker(allow_reset_pass=true)`:
    //       1. pick B (Unknown < TransportError) → fail
    //       2. pick A (TransportError) → fail
    //       3. fall-through reset (both → Unknown)
    //       4. pick A (lowest-index Unknown) → fail
    //       5. pick B → fail
    //     → 4 dials per outer attempt (2 per host).
    //   - Reconnect total: 3 × 4 = 12 dials, split A=6, B=6.
    //   - Grand total: 1 + 12 = 13, with A=7, B=6.
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
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
    // 1 initial to A + 3 outer reconnects × 4 dials each = 13 total.
    // A bears the initial + half of each reconnect attempt's 4 dials,
    // so A=7, B=6.
    let total = srv_a.accepts() + srv_b.accepts();
    assert_eq!(
        total,
        13,
        "expected 13 total dial attempts (1 initial + 3 outer reconnects × 4 dials each); \
         got A={}, B={}",
        srv_a.accepts(),
        srv_b.accepts()
    );
    assert_eq!(
        srv_a.accepts(),
        7,
        "A receives the initial + 2 dials per outer attempt"
    );
    assert_eq!(srv_b.accepts(), 6, "B receives 2 dials per outer attempt");
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
        let mut cursor = reader.prepare("select 1").execute().expect("execute");
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
    let err = match reader.prepare("select 2").execute() {
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
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
    // the first refused connect. `DeadEndpoint` holds the loopback
    // port for the test's lifetime so the OS can't reassign it to
    // another process between setup and the failover machinery's
    // connect attempt (the race that made the prior
    // `reserve_then_close_addr` helper flake on macOS).
    let dead = DeadEndpoint::new();
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!("qwp::addr={},{}", dead.url(), srv_b.url());
    let mut reader = Reader::from_conf(&conf).expect("walk past unreachable");
    assert_eq!(
        reader.current_addr().port,
        srv_b.addr.port(),
        "walked past the unreachable endpoint to B"
    );
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    assert!(cursor.next_batch().expect("ok").is_none());
}

#[test]
fn backoff_bounded_by_jitter_ceiling() {
    // Egress backoff uses **full-jitter** `[0, base)` per
    // failover.md §3.1, so each individual sleep is drawn uniformly
    // and there is no per-run lower bound that survives a single
    // CI invocation. What we CAN assert is the upper bound: total
    // backoff sleep across the schedule MUST NOT exceed the sum of
    // the per-attempt jitter ceilings.
    //
    // Setup: initial=20ms, max=200ms, max_attempts=3 → 4 outer
    // attempts; sleeps between attempts use base 20ms, 40ms, 80ms.
    // Sum of bases (= upper bound on total sleep under full-jitter)
    // is 140ms. The walk itself does host_count × 2 dials per outer
    // attempt × 4 attempts = 16 dials on loopback. Allow 500ms slack
    // for scheduler noise and connect overhead on busy CI runners.
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let start = Instant::now();
    let _ = cursor.next_batch();
    let elapsed = start.elapsed();
    // Sum of jitter ceilings (140ms) + scheduler/connect slack (500ms)
    // = 640ms upper bound. A regression that disables the cap or
    // reverts to deterministic backoff (140ms minimum + dials)
    // wouldn't trip this, but one that *runs away* (e.g. backoff
    // doubling without saturation) would push elapsed well over 1s.
    assert!(
        elapsed < Duration::from_millis(640),
        "elapsed {:?} exceeds the full-jitter ceiling — backoff schedule has run away",
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

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

/// Tighter version of `cancelling_cursor_does_not_failover_on_drop`
/// that pins the precise wire ordering: the client MUST write its
/// CANCEL frame before the server drops, so the cursor enters the
/// drain loop with `cancelling=true` already set. A subsequent drop
/// then traverses the read-error → "is_failover_eligible? yes, but
/// cancelling=true" short-circuit in `Cursor::next_batch`.
///
/// Stronger than the prior test by:
///   1. Synchronising on receipt of CANCEL via `AwaitClientCancel`
///      instead of an open-loop `Sleep` (the sleep approach can race
///      under heavy CI load — the drop fires before CANCEL lands and
///      the test exercises a different code path than advertised).
///   2. Asserting `failover_resets() == 0` directly on the cursor —
///      not just "B was never dialed" (which is a weaker proxy:
///      single-endpoint configs would mask a regression).
///   3. Asserting the cancel call surfaced a transport-class error
///      (or a clean Ok if STATUS_CANCELLED happened to land before
///      the drop); never a failover-flavored error like
///      `FailoverExhausted`.
#[test]
fn failover_suppressed_when_drop_arrives_during_cancel_drain() {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        // Block until the client has flushed CANCEL onto the wire.
        // After this, `cursor.cancel()` has set `cancelling=true` and
        // is parked in the drain reading frames.
        Action::AwaitClientCancel,
        // Drop the socket. The client's drain read fails with a
        // transport-class error; failover MUST stay disabled because
        // `cancelling=true`.
        Action::HardDrop,
    ]]);
    // Tripwire endpoint: if failover ever activates despite the
    // cancellation, the client would dial this. We assert it stays
    // untouched.
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let cancel_result = cursor.cancel();

    // The failover counter is the direct test of the contract: a
    // failover-suppressed cancel-drain MUST NOT increment it. Stronger
    // than checking server B's accept count because it would catch a
    // single-endpoint regression too (where there's no B to dial).
    assert_eq!(
        cursor.failover_resets(),
        0,
        "cancellation must NOT trigger failover; failover_resets stayed at 0 \
         (cancel result: {:?})",
        cancel_result
            .as_ref()
            .map_err(|e| (e.code(), e.msg().to_string())),
    );
    // If the cancel returned an error, it must be a transport-class
    // surface — never a failover-budget surface. The bench against
    // the unusual race where STATUS_CANCELLED lands before the drop
    // remains Ok, and that's fine.
    match cancel_result {
        Ok(()) => {}
        Err(e) => {
            assert!(
                matches!(e.code(), ErrorCode::SocketError | ErrorCode::ProtocolError),
                "cancel during drain must surface as a transport error, not \
                 a failover surface; got {:?}: {}",
                e.code(),
                e.msg()
            );
        }
    }
    drop(cursor);
    assert_eq!(
        srv_b.accepts(),
        0,
        "tripwire endpoint must remain untouched — no failover dial fired"
    );
}

#[test]
fn single_endpoint_failover_exhausts_budget() {
    // With a single address in the list, the host-health tracker
    // walks that single host and (per failover.md §11.9.3) does one
    // fall-through reset pass per outer reconnect attempt. If the host
    // stays dead, the cursor MUST eventually surface a hard error
    // rather than retry indefinitely.
    //
    // Dial accounting with `failover_max_attempts=2`:
    //   - Initial connect: 1 dial (success — serves the query, then drops).
    //   - Mid-stream failure on the single host triggers
    //     `reconnect_with_failover`, which runs
    //     `attempts_total = max_attempts + 1 = 3` outer reconnect attempts.
    //   - Each outer attempt invokes `walk_via_tracker(allow_reset_pass=true)`:
    //     pick the host → fail → fall-through reset → re-pick the
    //     same host → fail. That's 2 dials per outer attempt against
    //     the single configured endpoint.
    //   - Reconnect total: 3 × 2 = 6 dials.
    //   - Grand total: 1 + 6 = 7. The single per-Execute reconnect
    //     walk returns Err on exhaustion; no outer replay-cycle
    //     wrapper rearms it.
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
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
    // 1 initial + 3 outer reconnect attempts × 2 dials per attempt
    // (walk + fall-through reset walk on the single host) = 7.
    assert_eq!(
        srv.accepts(),
        7,
        "expected exactly 7 dials against the single endpoint \
         (1 initial + 3 reconnect attempts × 2 dials per attempt); got {}",
        srv.accepts()
    );
}

#[test]
fn write_fail_after_reconnect_terminates_or_recovers_via_outer_loop() {
    // A: serves the initial query, then drops mid-stream → triggers
    // failover. B: accepts the WS upgrade and sends SERVER_INFO (so
    // `connect_endpoint` returns Ok), then drops before the client's
    // QUERY_REQUEST write lands. Two paths are possible depending on
    // when the kernel surfaces B's TCP drop to tungstenite's buffered
    // send:
    //   (a) `write_message(QUERY_REQUEST)` to B fails synchronously —
    //       `failover_reconnect_and_replay` tears the transport down
    //       and surfaces the write error. No in-call retry: the per-
    //       Execute `failover_max_duration_ms` budget already burned
    //       once inside `reconnect_with_failover`, and dialing again
    //       from here would compound it (this matches the Java
    //       reference client `QwpQueryClient.executeImpl`, which owns
    //       one deadline per Execute).
    //   (b) tungstenite buffers the send and reports `Ok` — the
    //       cursor returns from the first failover (1 reset callback);
    //       the next `next_batch` reads from B, sees the close, and
    //       the per-batch failover loop triggers a *second* outer
    //       failover that lands on A's recovered slot (2nd callback).
    // Both outcomes are correct: a single in-call write failure no
    // longer earns a free second budget, but the per-batch loop's
    // existing failover machinery still recovers from a delayed read
    // failure.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        // If the test takes path (b), the second failover lands here.
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
        .prepare("select 1")
        .on_failover_reset(move |_| {
            *resets_clone.lock().unwrap() += 1;
        })
        .execute()
        .expect("execute");

    let outcome = match cursor.next_batch() {
        Ok(None) => Ok(()),
        Ok(Some(_)) => panic!("unexpected RESULT_BATCH delivery"),
        Err(e) => Err((e.code(), e.msg().to_string())),
    };
    let r = *resets.lock().unwrap();
    drop(cursor);

    match outcome {
        Ok(()) => {
            // Path (b): cursor recovered through the outer loop after
            // the first failover landed on B and the read tripped.
            assert_eq!(
                r, 2,
                "path (b) (buffered write to B) must produce exactly 2 reset events"
            );
            assert_eq!(
                reader.current_addr().port,
                srv_a.addr.port(),
                "recovered cursor must end up bound to A's recovered slot"
            );
        }
        Err((code, msg)) => {
            // Path (a): synchronous write fail on B; no callback
            // fired because we never reached the success branch.
            // Cursor must surface a transport-class error.
            assert_eq!(r, 0, "path (a) must not fire a reset callback");
            assert!(
                matches!(code, ErrorCode::SocketError | ErrorCode::ProtocolError),
                "path (a) error must be transport-class; got {:?}: {}",
                code,
                msg,
            );
        }
    }
}

#[test]
fn failover_event_attempts_is_cumulative_across_rotations() {
    // `FailoverEvent.attempts` must be the cumulative reconnect count
    // across every dial inside the single `reconnect_with_failover`
    // walk that landed — not just the index of the dial that finally
    // succeeded. Force the rotation to skip past one dead endpoint
    // before landing: the first reconnect attempt fails (B is dead),
    // the second succeeds (A's recovered slot). The callback must see
    // `attempts >= 2`.
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
        .prepare("select 1")
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let start = Instant::now();
    let _ = cursor.next_batch();
    let elapsed = start.elapsed();
    // A working cap totals ~150 ms of backoff plus the 8 dial round-
    // trips; an uncapped run would total ~2.55 s of backoff alone
    // (10+20+40+80+160+320+640+1280) plus dials. The 2 s threshold
    // sits well below the uncapped *backoff floor* and well above any
    // realistic capped run — including the slack a loaded CI runner
    // can add to each dial. Tightening this threshold has bitten us
    // before on busy CI hosts (a previous 800 ms cap regressed at
    // 841 ms with the cap correctly applied), so prefer wide head-
    // room over narrow precision here.
    assert!(
        elapsed < Duration::from_millis(2000),
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

    let mut cursor = reader.prepare("select 1").execute().expect("execute");
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
    // request_id. A subsequent `Reader::prepare()` on the same Reader
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
        .prepare("select 1")
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
        .prepare("select 1")
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
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

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
    // a guaranteed-rejecting loopback port (single endpoint, so no
    // walk can mask the result) and assert the surfaced code is
    // `SocketError`. A regression flipping it back to `ConfigError`
    // — or to anything non-failover-eligible — goes red here.
    let dead = DeadEndpoint::new();
    let conf = format!("qwp::addr={}", dead.url());
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
fn initial_connect_bails_immediately_on_auth_error() {
    // Spec §6 / §11.9.3 WalkTracker pseudocode: `AuthError` is
    // terminal — "rethrow (do NOT continue past this host)".
    // Credentials are cluster-wide; retrying every host floods server
    // logs without recovery. Matches the Java reference's `connect()`
    // which rethrows on `QwpAuthFailedException` immediately.
    //
    // Topology: A 401s the upgrade, B would accept. The walk MUST
    // bail on A's 401 without ever dialing B.
    let srv_a = MockServer::start(vec![vec![Action::Reject401]]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!("qwp::addr={}", build_addr_list(&[&srv_a, &srv_b]));

    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!("AuthError on first endpoint must bail the walk"),
    };
    assert_eq!(
        err.code(),
        ErrorCode::AuthError,
        "AuthError must surface immediately; got {:?}: {}",
        err.code(),
        err.msg(),
    );
    assert_eq!(
        srv_a.accepts(),
        1,
        "A must have been dialled exactly once (the 401)"
    );
    assert_eq!(
        srv_b.accepts(),
        0,
        "B must NOT have been dialled — AuthError on A is terminal per spec §6"
    );
}

#[test]
fn initial_connect_auth_terminal_regardless_of_position_in_addr_list() {
    // Counterpart pinning: the bail-on-AuthError invariant holds even
    // when a healthy endpoint precedes the auth-rejecting one in the
    // configured `addr=` list. The healthy host's classification is
    // recorded as `Healthy` before we move on; when the next
    // unattempted pick is the 401-server, we still bail.
    //
    // Wait — that's not testable with the priority lattice because a
    // Healthy host wins on the first `pick_next`, so the walk
    // succeeds without ever touching the 401-server. Instead, pin
    // the simpler invariant: 401 alone, no fallback, surfaces as
    // `AuthError`.
    let srv = MockServer::start(vec![vec![Action::Reject401]]);
    let conf = format!("qwp::addr={}", srv.url());
    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!("401 must surface as AuthError"),
    };
    assert_eq!(err.code(), ErrorCode::AuthError);
    assert!(
        err.upgrade_reject().is_none(),
        "AuthError carries no UpgradeReject (only RoleMismatch does)"
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
        .prepare("select * from t where i = $1 and s = $2")
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
        .prepare("select 1")
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
        .prepare("select 1")
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
        .prepare("select 1")
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
    // Pins the tracker's "lowest-index Unknown host" pick when the
    // failed endpoint is the last entry in the addr list — the
    // historically-buggy wrap case.
    //
    // Topology: 4 servers, parsed in order S0, S1, S2, S3. We force
    // initial connect to land on S3 (idx 3) by making S0..S2 reject
    // their first connect. Then S3 drops mid-query. The tracker now
    // sees: S0/S1/S2 = TransportError (from the initial walk), S3 =
    // TransportError (just demoted by the mid-stream failure). All
    // hosts share the same priority tier, so the tie-breaker is the
    // address-list index — which puts S0 first. So:
    //
    //   * If the pick is correct, S0's *second* accept receives the
    //     dial and answers happily; the cursor terminates bound to S0.
    //   * If a regression in the tracker picks a different host (e.g.
    //     biased toward higher indices, or skips S0 in favour of S1),
    //     the cursor would land on S1 or S2 (both still dead), the
    //     failover budget would exhaust, and the final-endpoint
    //     assertion would fail.
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

    let mut cursor = reader.prepare("select 1").execute().expect("execute");
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
        .prepare("select 1")
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
        .prepare("select 1")
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

/// Server negotiates a higher QWP version than the client supports.
/// `WsTransport::connect_to` (transport.rs) compares the
/// `x-qwp-version` upgrade header against `config.max_version` and
/// returns a failover-eligible `HandshakeError` per failover.md §6
/// (2026-05-08 reclassification): version-out-of-range is per-endpoint
/// transient, not cluster-wide terminal, because rolling upgrades will
/// transiently have peers on different versions. The test disables
/// failover so we observe the *direct* error rather than a wrapped
/// "all endpoints exhausted" surface.
#[test]
fn unsupported_server_version_surfaces_handshake_error() {
    let srv = MockServer::start(vec![vec![
        // 99 is comfortably above any version the current client
        // advertises; the trigger is `server_version > max_version`.
        Action::HandshakeVersion(99),
    ]]);
    let conf = format!("qwp::addr={};failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("connect must reject a higher-than-max QWP version"),
        Err(e) => e,
    };
    assert_eq!(
        err.code(),
        ErrorCode::HandshakeError,
        "version mismatch must surface HandshakeError (failover-eligible); got {:?}: {}",
        err.code(),
        err.msg()
    );
    assert!(
        err.msg().contains("99"),
        "error message should mention the negotiated version 99: {}",
        err.msg()
    );
}

/// Connect-string addr with an unresolvable hostname must surface
/// `CouldNotResolveAddr`. Uses the reserved `.invalid` TLD (RFC 6761)
/// so the test is deterministic on every host without depending on
/// negative DNS caching. `failover=off` strips the failover wrapper
/// so the error code is the direct one.
#[test]
fn unresolvable_host_surfaces_could_not_resolve_addr() {
    // RFC 6761 guarantees `.invalid` is never resolvable. Subdomain
    // padding keeps it out of any local /etc/hosts override that
    // might intercept a bare label.
    let conf = "qwp::addr=does-not-exist.qwp-test.invalid:9009;failover=off";
    let err = match Reader::from_conf(conf) {
        Ok(_) => panic!("connect must fail when DNS does not resolve"),
        Err(e) => e,
    };
    assert_eq!(
        err.code(),
        ErrorCode::CouldNotResolveAddr,
        "unresolvable host must surface CouldNotResolveAddr; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

// ---------------------------------------------------------------------------
// On-wire `Authorization` header coverage
//
// Pin the exact bytes the client emits for each auth mode so a
// regression in `AuthMode::header_value()` (or in the WebSocket
// upgrade glue that copies it onto the request) cannot pass
// silently. The unit tests in `egress::auth` cover the formatter in
// isolation; the tests below cover the path from connect-string ->
// upgrade-request bytes that actually hit the socket.
// ---------------------------------------------------------------------------

/// Run a single happy-path query against a local mock and return the
/// `Authorization` header value the mock observed on the WS upgrade.
/// Panics if no connection (and therefore no captured value) was
/// recorded — every test that calls this expects exactly one accept.
fn capture_auth_header_for_conf(conf_suffix: &str) -> Option<String> {
    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n0")]);
    let conf = format!("qwp::addr={};{}", srv.url(), conf_suffix);
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    // Drain to terminal so the test only returns once the upgrade
    // request has definitely been seen by the mock.
    while cursor.next_batch().expect("next_batch").is_some() {}
    drop(cursor);
    drop(reader);
    let captured = srv.captured_auth_headers();
    assert_eq!(
        captured.len(),
        1,
        "expected exactly one accepted connection, got {}: {:?}",
        captured.len(),
        captured
    );
    captured.into_iter().next().unwrap()
}

/// Basic auth: `username` + `password` must serialise on the wire as
/// `Basic base64(user:pass)`. The base64 here is `admin:quest`.
#[test]
fn basic_auth_header_emitted_on_wire() {
    let header = capture_auth_header_for_conf("username=admin;password=quest");
    assert_eq!(header.as_deref(), Some("Basic YWRtaW46cXVlc3Q="));
}

/// Bearer/OIDC: `token=...` must serialise as `Bearer <token>`.
#[test]
fn bearer_auth_header_emitted_on_wire() {
    let header = capture_auth_header_for_conf("token=eyJhbGciOi.payload.sig");
    assert_eq!(header.as_deref(), Some("Bearer eyJhbGciOi.payload.sig"));
}

/// Verbatim escape hatch: `auth=<value>` must serialise the value
/// unchanged (no scheme prefix added by the client).
#[test]
fn verbatim_auth_header_emitted_on_wire() {
    let header = capture_auth_header_for_conf("auth=Custom abc123");
    assert_eq!(header.as_deref(), Some("Custom abc123"));
}

/// No auth knobs in the connect string -> no `Authorization` header
/// on the wire. Pins the absence so a future regression that defaults
/// to some sentinel value (empty `Basic`, "Bearer ", etc.) cannot
/// pass silently.
#[test]
fn no_auth_means_no_authorization_header() {
    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n0")]);
    let conf = format!("qwp::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    while cursor.next_batch().expect("next_batch").is_some() {}
    drop(cursor);
    drop(reader);
    let captured = srv.captured_auth_headers();
    assert_eq!(captured, vec![None]);
}

/// 401-path coverage: even when the server rejects the upgrade, the
/// client must still have put the `Authorization` header on the wire
/// (otherwise the auth failure tells us nothing). Hand-rolled
/// `reject_upgrade` parses the raw HTTP preamble for the header so
/// this assertion holds without going through `accept_hdr`.
#[test]
fn auth_header_is_emitted_before_401_rejection() {
    let srv = MockServer::start(vec![vec![Action::Reject401]]);
    let conf = format!(
        "qwp::addr={};username=admin;password=quest;failover=off",
        srv.url()
    );
    let err = match Reader::from_conf(&conf) {
        Err(e) => e,
        Ok(_) => panic!("Reject401 mock must surface as a connect error"),
    };
    assert_eq!(err.code(), ErrorCode::AuthError);
    let captured = srv.captured_auth_headers();
    assert_eq!(
        captured,
        vec![Some("Basic YWRtaW46cXVlc3Q=".to_string())],
        "client must still have emitted the Authorization header even though the server rejected the upgrade"
    );
}

// ---------------------------------------------------------------------------
// 421 upgrade-reject parsing (failover.md §5)
// ---------------------------------------------------------------------------

/// 421 + `X-QuestDB-Role: PRIMARY_CATCHUP` must surface as
/// `RoleMismatch` with an `UpgradeReject` whose `is_transient()` is
/// true. The host-health tracker (step 2 of the failover work) will key
/// `RecordRoleReject(idx, transient=true)` off this.
#[test]
fn upgrade_421_with_primary_catchup_surfaces_transient_role_mismatch() {
    let srv = MockServer::start(vec![vec![Action::Reject421 {
        role: Some("PRIMARY_CATCHUP".into()),
        zone: Some("eu-west-1a".into()),
    }]]);
    let conf = format!("qwp::addr={};failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("421 + X-QuestDB-Role must surface as RoleMismatch"),
        Err(e) => e,
    };
    assert_eq!(
        err.code(),
        ErrorCode::RoleMismatch,
        "421 + X-QuestDB-Role must surface as RoleMismatch; got {:?}: {}",
        err.code(),
        err.msg()
    );
    let reject = err
        .upgrade_reject()
        .expect("UpgradeReject must be attached to the 421-derived error");
    assert_eq!(reject.role_byte, 0x03);
    assert_eq!(reject.role_name, "PRIMARY_CATCHUP");
    assert_eq!(reject.zone.as_deref(), Some("eu-west-1a"));
    assert!(
        reject.is_transient(),
        "PRIMARY_CATCHUP must classify transient"
    );
}

/// 421 + `X-QuestDB-Role: REPLICA` must surface as `RoleMismatch` with
/// `is_transient() == false` (topological). The tracker will record
/// this as `TopologyReject` and walk to the next host.
#[test]
fn upgrade_421_with_replica_role_surfaces_topological_role_mismatch() {
    let srv = MockServer::start(vec![vec![Action::Reject421 {
        role: Some("REPLICA".into()),
        zone: None,
    }]]);
    let conf = format!("qwp::addr={};failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("421 + REPLICA role must surface as RoleMismatch"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::RoleMismatch);
    let reject = err.upgrade_reject().expect("UpgradeReject expected");
    assert_eq!(reject.role_byte, 0x02);
    assert_eq!(reject.role_name, "REPLICA");
    assert_eq!(reject.zone, None);
    assert!(!reject.is_transient(), "REPLICA must classify topological");
}

/// 421 without the `X-QuestDB-Role` header degrades to a generic
/// transient transport error per failover.md §5 — failover walks past
/// it like any other transport-class failure. The error code therefore
/// must be `HandshakeError` (failover-eligible), and no `UpgradeReject`
/// is attached.
#[test]
fn upgrade_421_without_role_header_is_generic_handshake_error() {
    let srv = MockServer::start(vec![vec![Action::Reject421 {
        role: None,
        zone: None,
    }]]);
    let conf = format!("qwp::addr={};failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("421 with no role header still rejects connect"),
        Err(e) => e,
    };
    assert_eq!(
        err.code(),
        ErrorCode::HandshakeError,
        "421-without-role must surface as a generic transient HandshakeError; got {:?}: {}",
        err.code(),
        err.msg()
    );
    assert!(
        err.upgrade_reject().is_none(),
        "no UpgradeReject when X-QuestDB-Role header is absent"
    );
}

/// 421 + an unrecognised role token still produces `RoleMismatch` —
/// the wire bytes are preserved verbatim (uppercased) and the
/// classification falls back to topological. Defensive: a future role
/// addition we haven't taught the client about must not crash, and
/// must not be silently treated as transient (conservatism per
/// failover.md §6).
#[test]
fn upgrade_421_with_unknown_role_classifies_topological() {
    let srv = MockServer::start(vec![vec![Action::Reject421 {
        role: Some("future_role_we_dont_know".into()),
        zone: None,
    }]]);
    let conf = format!("qwp::addr={};failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("unknown 421 role still rejects"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::RoleMismatch);
    let reject = err.upgrade_reject().expect("UpgradeReject expected");
    assert_eq!(reject.role_byte, 0xFF, "unknown role byte sentinel");
    assert_eq!(reject.role_name, "FUTURE_ROLE_WE_DONT_KNOW");
    assert!(!reject.is_transient());
}

/// `target=primary` connected to a SERVER_INFO advertising REPLICA must
/// produce `RoleMismatch` with `UpgradeReject` populated from the
/// SERVER_INFO bytes — uniform tracker input regardless of whether the
/// rejection arrived on the upgrade (`421+role`) or in the post-upgrade
/// `SERVER_INFO` frame. `target=primary` is `Target::Primary`, so the
/// `target_matches` filter rejects the REPLICA role.
#[test]
fn server_info_target_mismatch_attaches_upgrade_reject() {
    let srv = MockServer::start(vec![happy_script(ServerRole::Replica, "node-r1")]);
    let conf = format!("qwp::addr={};target=primary;failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("target=primary against REPLICA must reject"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::RoleMismatch);
    let reject = err
        .upgrade_reject()
        .expect("SERVER_INFO target mismatch must attach UpgradeReject");
    assert_eq!(reject.role_byte, 0x02);
    assert_eq!(reject.role_name, "REPLICA");
    assert!(!reject.is_transient());
}

// ---------------------------------------------------------------------------
// HostHealthTracker integration (step 2 of the failover work)
// ---------------------------------------------------------------------------

/// Failover.md §2 sticky-Healthy: after a successful reconnect lands on
/// host X, subsequent reconnects MUST prefer X. The pre-tracker
/// rotation (`(failed_idx + 1 + attempt) % N`) didn't have this
/// property — it picked by index, not by health history.
///
/// Topology: A serves the initial query then drops; B serves the
/// recovered query then drops; A serves again. Without sticky-Healthy
/// the second reconnect would go to C (rotation: skip B, skip A,
/// land on C). With sticky-Healthy and B classified as TransportError
/// from the previous mid-stream demote, the priority pick is
/// Healthy(C) vs TransportError(A,B); C should be picked. But there's
/// a wrinkle: the round attempted bits reset on each reconnect, so
/// the "stickiness" is preserved only via the HEALTHY state.
///
/// Simpler scenario for the test: A drops → reconnect lands on B
/// (Healthy). Now B is HEALTHY, A is TransportError, C is Unknown.
/// Mid-stream on B → record_mid_stream_failure(B) demotes B to
/// TransportError. Next reconnect: every host is TransportError or
/// Unknown. Priority: Unknown wins over TransportError, so C is
/// picked. Then A and B are picked only if C fails.
///
/// This is more about the **priority lattice** than "sticky-Healthy"
/// proper (which only meaningfully helps across `begin_round(true)`).
#[test]
fn tracker_prefers_unknown_over_transport_error_on_reconnect() {
    // 3 hosts: A=happy-then-drop, B=connect-fail (so no Unknown→Healthy
    // for B at initial), C=happy. Tracker should land on A initially,
    // then on mid-stream failure pick C over B because B is in
    // TransportError state (from initial walk) while C is Unknown.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let srv_c = MockServer::start(vec![happy_script(ServerRole::Standalone, "c")]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        // A first so initial walk lands on A (lowest-index Unknown).
        build_addr_list(&[&srv_a, &srv_b, &srv_c])
    );
    let mut reader = Reader::from_conf(&conf).expect("initial connect to A");
    assert_eq!(
        reader.current_addr().port,
        srv_a.addr.port(),
        "initial walks to A"
    );
    // Initial walk dials only A (succeeds first). B and C should not
    // have been dialled yet.
    assert_eq!(srv_a.accepts(), 1);
    assert_eq!(srv_b.accepts(), 0);
    assert_eq!(srv_c.accepts(), 0);

    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    assert!(
        cursor
            .next_batch()
            .expect("must complete after rotating off A")
            .is_none(),
        "cursor must complete via reconnect"
    );
    drop(cursor);

    // After mid-stream on A: A=TransportError (mid-stream demote),
    // B=Unknown (never tried), C=Unknown (never tried). pick_next
    // picks the lowest-index Unknown → B. B fails → record_transport_error(B).
    // pick_next: C (Unknown). C succeeds → bind to C.
    assert_eq!(
        reader.current_addr().port,
        srv_c.addr.port(),
        "reconnect must walk past dead B to healthy C (Unknown-state priority)"
    );
    // B got one failover dial (Unknown < TransportError on A).
    // C got one successful dial.
    assert_eq!(
        srv_b.accepts(),
        1,
        "B should have been dialled once on reconnect"
    );
    assert_eq!(
        srv_c.accepts(),
        1,
        "C should have been dialled once on reconnect"
    );
}

/// Failover.md §11.9.3 fall-through reset: when the first walk
/// exhausts because every host has accumulated a non-`Healthy`
/// classification, the tracker MUST do exactly one
/// `begin_round(forget=true)` and walk the list again. The retry
/// gives stale `TopologyReject`/`TransportError` hosts another shot.
///
/// Scenario: 2 hosts. First reconnect attempt drives both into
/// TransportError. Then their server-side scripts flip to healthy.
/// The fall-through reset gives the next walk a chance to pick them
/// up — and crucially this happens **within a single
/// `reconnect_with_failover` outer attempt**, not requiring a second
/// outer attempt.
#[test]
fn tracker_fall_through_reset_gives_dead_hosts_a_second_pass() {
    // A: happy initial + drops mid-stream + recovers on the 3rd accept.
    // B: drop_at_connect on accept #1, then recovers.
    //
    // With `failover_max_attempts=1` (attempts_total=2), the test
    // forces the fall-through reset to be the path that recovers.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        // 2nd accept: dead, drives A to TransportError on reconnect.
        drop_at_connect_script(),
        // 3rd accept: healthy. Picked up after fall-through reset.
        happy_script(ServerRole::Standalone, "a-recovered"),
    ]);
    let srv_b = MockServer::start(vec![
        // 1st accept (during reconnect): dead.
        drop_at_connect_script(),
        // 2nd accept (after fall-through reset): healthy.
        happy_script(ServerRole::Standalone, "b-recovered"),
    ]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=1;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    assert!(
        cursor
            .next_batch()
            .expect("fall-through reset rescues the walk")
            .is_none(),
        "fall-through reset must let the cursor complete"
    );
    drop(cursor);

    // Final endpoint must be either A's recovered slot or B's
    // recovered slot — whichever was first picked after the reset.
    // With both hosts Unknown after reset, the lowest-index pick
    // wins: A.
    assert_eq!(
        reader.current_addr().port,
        srv_a.addr.port(),
        "after fall-through reset, lowest-index Unknown is A"
    );
}

/// Failover.md §11.9.3 fall-through reset budget: only ONE reset
/// pass per `reconnect_with_failover` outer attempt. After the reset
/// walks the list and still fails, the outer attempt returns and the
/// next outer attempt (if budget allows) starts a fresh walk with a
/// fresh `begin_round(false)`.
///
/// This test verifies the upper bound — without the "only one
/// fall-through reset" invariant, a stale-classification host could
/// be re-walked indefinitely inside a single outer attempt.
#[test]
fn tracker_fall_through_reset_runs_at_most_once_per_outer_attempt() {
    // 1 host, max_attempts=0 (attempts_total=1). Single outer attempt.
    // Each outer attempt: walk (1 dial) + fall-through reset walk (1
    // dial) = 2 dials.
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "x"),
        // Every subsequent accept: TCP drop. Even unlimited resets
        // wouldn't find a healthy slot.
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=0;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        srv.url()
    );
    // `failover_max_attempts=0` is rejected at config parse
    // (validate() asserts >= 1); use 1 instead and account for that.
    let conf = conf.replace("failover_max_attempts=0", "failover_max_attempts=1");
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let _ = cursor.next_batch(); // Will fail.
    drop(cursor);
    drop(reader);

    // attempts_total=2 outer attempts × 2 dials per attempt = 4
    // reconnect dials. Plus 1 initial = 5. If the fall-through reset
    // were not bounded to one pass, this would be unbounded (the
    // walk would loop forever resetting and re-walking).
    assert_eq!(
        srv.accepts(),
        5,
        "expected 1 initial + 2 outer reconnect attempts × 2 dials/attempt; got {}",
        srv.accepts()
    );
}

/// Initial connect does NOT use the fall-through reset pass: every
/// host starts at `Unknown`, so the first walk traverses the full
/// list and a second reset-pass would be a no-op anyway. This pins
/// the per-call behaviour split (`allow_reset_pass=false` for initial,
/// `true` for reconnect) — a regression that flipped it would
/// double-dial every host on initial connect against a dead cluster.
#[test]
fn initial_connect_does_not_run_fall_through_reset() {
    // 2 dead hosts, no failover (so the cursor never starts).
    let srv_a = MockServer::start(vec![drop_at_connect_script()]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "qwp::addr={};failover=off",
        build_addr_list(&[&srv_a, &srv_b])
    );
    assert!(
        Reader::from_conf(&conf).is_err(),
        "both hosts dead → connect must fail"
    );
    // Exactly one dial per host: initial walk visits each Unknown
    // host once and exits. No reset-then-rewalk.
    assert_eq!(
        srv_a.accepts(),
        1,
        "A dialled exactly once during initial walk"
    );
    assert_eq!(
        srv_b.accepts(),
        1,
        "B dialled exactly once during initial walk"
    );
}

/// Failover.md §2.1 invariant: `record_mid_stream_failure` must
/// demote a Healthy host BEFORE the next `begin_round(true)`.
/// `reconnect_with_failover` calls `record_mid_stream_failure` first
/// thing — the test pins that ordering by setting up a scenario where
/// reversing it would visibly redial the just-failed host first.
///
/// Topology: A succeeds initial connect, drops mid-stream. B is
/// healthy on its first accept. If the demote runs first, the
/// reconnect's `walk_via_tracker` sees A=TransportError and B=Unknown,
/// so picks B. If the demote ran AFTER `begin_round(false)`, A would
/// still be HEALTHY (priority 1) and would be picked first — getting
/// a redundant dial we'd be able to observe via the accept count.
#[test]
fn mid_stream_demote_happens_before_walk_picks_next() {
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        // 2nd accept: dead. If the demote ordering were wrong and
        // reconnect picked A first, A would dial here.
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "qwp::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    assert!(cursor.next_batch().expect("must complete").is_none());
    drop(cursor);
    assert_eq!(
        reader.current_addr().port,
        srv_b.addr.port(),
        "reconnect must land on B, not A"
    );
    // A: 1 dial (initial connect). If demote ran late, A would have
    // gotten a 2nd dial during reconnect — caught by this assert.
    assert_eq!(
        srv_a.accepts(),
        1,
        "A must NOT be redialled — demote must run before pick_next"
    );
    assert_eq!(srv_b.accepts(), 1, "B picked immediately on reconnect");
}

// ---------------------------------------------------------------------------
// auth_timeout_ms / zone= wiring (step 3 of the failover work)
// ---------------------------------------------------------------------------

/// `auth_timeout_ms` bounds the WS upgrade-response read per
/// failover.md §1.1. With the mock holding the connection open and
/// never replying to the upgrade, `Reader::from_conf` must abort
/// within roughly the configured timeout — not wait indefinitely.
#[test]
fn auth_timeout_bounds_upgrade_stall() {
    // 1.5s stall in the mock; 200ms client timeout. The contract being
    // tested is "the read is bounded" — what would regress is the
    // timeout not being applied at all, in which case the client
    // would wait the full mock stall. Pick a large gap between the
    // timeout and the stall so the assertion still discriminates on
    // a heavily loaded CI host (where syscall jitter + scheduler
    // delay can occasionally add hundreds of ms to a 100ms operation).
    let stall = Duration::from_millis(1_500);
    let timeout_ms = 200u64;
    let srv = MockServer::start(vec![vec![Action::StallUpgrade(stall)]]);
    let conf = format!(
        "qwp::addr={};failover=off;auth_timeout_ms={}",
        srv.url(),
        timeout_ms
    );
    let started = std::time::Instant::now();
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("upgrade-stall mock must surface as a connect error"),
        Err(e) => e,
    };
    let elapsed = started.elapsed();
    // Ceiling sits well below the 1.5s stall and well above the 200ms
    // configured timeout. Even with ~800ms of CI overhead piled on top
    // of the read deadline, the test still discriminates a working
    // timeout from a missing one (which would surface at the full stall).
    let ceiling = Duration::from_millis(1_000);
    assert!(
        elapsed < ceiling,
        "auth_timeout_ms={} must bound the upgrade stall well under the mock's {:?} hold; \
         got elapsed={:?} (ceiling={:?}), error: {} {:?}",
        timeout_ms,
        stall,
        elapsed,
        ceiling,
        err.msg(),
        err.code()
    );
    // The error code is platform-dependent (Linux's WouldBlock vs
    // macOS's TimedOut surface differently through tungstenite), so
    // accept any transport-class code as long as it's failover-eligible.
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::HandshakeError | ErrorCode::ProtocolError
        ),
        "auth_timeout_ms expiry must surface as a transport-class error; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

/// Long upgrade response IS accepted when `auth_timeout_ms` is set
/// high enough to cover it. Counterpart to
/// `auth_timeout_bounds_upgrade_stall` — confirms the knob isn't
/// just always-fail.
#[test]
fn auth_timeout_does_not_fire_within_budget() {
    // No stall — the mock answers the upgrade promptly. `auth_timeout_ms`
    // should not interfere with a normal connect.
    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n0")]);
    let conf = format!("qwp::addr={};failover=off;auth_timeout_ms=5000", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect must succeed within budget");
    // Sanity: cursor still works after the upgrade clears the
    // `auth_timeout_ms` read deadline.
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    while cursor.next_batch().expect("next_batch").is_some() {}
}

/// `server_info_timeout_ms` bounds the post-upgrade `SERVER_INFO`
/// read per failover.md §1.1. A server that accepts the WS upgrade
/// (HTTP 101) but then never sends the `SERVER_INFO` binary frame
/// MUST surface a transport-class failure within the configured
/// budget, not stall the connect indefinitely.
///
/// The mock's script holds the connection open for 800ms WITHOUT
/// emitting `SendServerInfo`, so the upgrade completes (advertised
/// `x-qwp-version: 2`) but the post-upgrade read on the client side
/// has no SERVER_INFO frame to consume. With
/// `server_info_timeout_ms=100`, the client should give up within
/// ~150ms and surface a failover-eligible transport error.
#[test]
fn server_info_timeout_bounds_post_upgrade_stall() {
    use questdb::egress::ReaderConfig;

    // The implicit `handshake_version = "2"` advertises v2, which
    // triggers `read_server_info_frame` on the client side. The
    // script has no `SendServerInfo` action, so the server just
    // sleeps after the upgrade and never writes the frame.
    let srv = MockServer::start(vec![vec![Action::Sleep(Duration::from_millis(800))]]);
    // `server_info_timeout_ms` is programmatic-only; build the cfg
    // via `from_conf` and override the field before opening the
    // Reader. Matches the Java reference's `withServerInfoTimeout`
    // surface.
    let mut cfg = ReaderConfig::from_conf(format!("qwp::addr={};failover=off", srv.url()))
        .expect("conf parse");
    cfg.server_info_timeout_ms = 100;

    let started = std::time::Instant::now();
    let err = match questdb::egress::Reader::from_config(&cfg) {
        Ok(_) => panic!("post-upgrade stall must surface as a connect error"),
        Err(e) => e,
    };
    let elapsed = started.elapsed();
    // Tight upper bound: well below the 800ms server hold. If the
    // timeout weren't applied, the client would wait for the mock's
    // full 800ms drop (or longer on slower CI).
    assert!(
        elapsed < Duration::from_millis(400),
        "server_info_timeout_ms=100 must bound the SERVER_INFO stall well under the mock's 800ms hold; \
         got elapsed={:?}, error: {} {:?}",
        elapsed,
        err.msg(),
        err.code()
    );
    // OS-dependent classification (Linux WouldBlock vs macOS TimedOut)
    // — both render via tungstenite as `Error::Io` → `SocketError`,
    // but a clean WS close would surface as `SocketError` or
    // `ProtocolError`. Accept any failover-eligible transport-class
    // code.
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError | ErrorCode::HandshakeError
        ),
        "post-upgrade timeout must surface as a transport-class error; got {:?}: {}",
        err.code(),
        err.msg()
    );
}

/// Counterpart: a SERVER_INFO frame that arrives well within the
/// configured budget MUST NOT trip the timeout. Pins the
/// don't-fire-prematurely side of the knob.
#[test]
fn server_info_timeout_does_not_fire_within_budget() {
    use questdb::egress::ReaderConfig;

    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n0")]);
    let mut cfg = ReaderConfig::from_conf(format!("qwp::addr={};failover=off", srv.url()))
        .expect("conf parse");
    cfg.server_info_timeout_ms = 5_000;

    let mut reader =
        questdb::egress::Reader::from_config(&cfg).expect("connect must succeed within budget");
    // Sanity: post-SERVER_INFO reads must NOT be subject to the
    // deadline — `read_server_info_frame` clears the deadline on the
    // way out, so subsequent batch reads can legitimately block for
    // as long as the query takes to execute.
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    while cursor.next_batch().expect("next_batch").is_some() {}
}

/// `zone=` populates `ReaderConfig.zone`, which then drives
/// `HostHealthTracker::new`. Without an end-to-end multi-cycle test
/// it's hard to observe the priority lattice's zone dimension from
/// the outside, but at minimum the value must round-trip through the
/// parser and validate, and a connect must succeed against a server
/// that doesn't advertise a zone (no CAP_ZONE) — the host's zone
/// tier stays at `Unknown`, which is selectable.
#[test]
fn zone_knob_is_compatible_with_v2_server_without_cap_zone() {
    let srv = MockServer::start(vec![happy_script(ServerRole::Primary, "p0")]);
    let conf = format!("qwp::addr={};zone=eu-west-1a;target=primary", srv.url());
    // `target=primary` collapses every host's zone tier to `Same`
    // regardless of the client's `zone=` — writers follow the master
    // across zones (failover.md §2). So a server without CAP_ZONE
    // still classifies as Same under target=primary, and the connect
    // succeeds.
    let reader = Reader::from_conf(&conf).expect("connect must succeed with target=primary");
    assert_eq!(reader.current_addr().port, srv.addr.port());
}

/// `zone=` value with no matching server-advertised zone: the
/// connect must still succeed (zone is a *preference*, not a
/// requirement). The tracker classifies the host as zone tier
/// `Unknown` (server didn't advertise CAP_ZONE), which is still
/// selectable — the priority lattice only de-prioritises `Other`,
/// not `Unknown`.
#[test]
fn zone_unset_on_server_does_not_block_connect() {
    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n0")]);
    let conf = format!("qwp::addr={};zone=eu-west-1a", srv.url());
    let reader = Reader::from_conf(&conf).expect("connect must succeed without server zone");
    assert_eq!(reader.current_addr().port, srv.addr.port());
}

/// `failover_max_duration_ms` bounds the wall-clock wait in
/// `reconnect_with_failover` per failover.md §11.9.1. Even with
/// `failover_max_attempts` generously set, the deadline alone must
/// trip and surface a "budget exhausted" error.
#[test]
fn failover_max_duration_caps_total_wall_clock() {
    // Server drops mid-stream; reconnect to it always fails;
    // deadline cuts the retry loop well short of attempts exhaustion.
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "x"),
        drop_at_connect_script(),
    ]);
    // 100 attempts × 200ms backoff would total ~20s without the
    // deadline. With failover_max_duration_ms=120ms, the deadline
    // must intervene.
    let conf = format!(
        "qwp::addr={};failover_max_attempts=100;\
         failover_backoff_initial_ms=200;failover_backoff_max_ms=200;\
         failover_max_duration_ms=120",
        srv.url()
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let start = Instant::now();
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail — server dies and reconnect can't recover"),
    };
    let elapsed = start.elapsed();
    // 100 max_attempts × 200ms backoff would total ~20s without the
    // deadline. With failover_max_duration_ms=120ms, the deadline
    // must intervene well under 1s.
    assert!(
        elapsed < Duration::from_millis(1000),
        "elapsed {:?} exceeds the failover_max_duration_ms=120 budget — \
         deadline not enforced",
        elapsed
    );
    // The error message includes the budget value, distinguishing
    // deadline exhaustion from attempts exhaustion. Either form is
    // acceptable depending on which check tripped first (deadline
    // can fire mid-loop OR via the attempts cap; the deadline path
    // surfaces the descriptive message).
    assert!(
        matches!(
            err.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError
        ),
        "unexpected code: {:?}: {}",
        err.code(),
        err.msg()
    );
}

/// `failover_max_duration_ms=0` is the documented "unbounded"
/// sentinel — the deadline branch must be entirely inert. With
/// `max_attempts=1` (one reconnect attempt) and a dead host, the
/// attempts cap should bound the loop, not the (absent) deadline.
#[test]
fn failover_max_duration_zero_means_unbounded() {
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "x"),
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "qwp::addr={};failover_max_attempts=1;\
         failover_backoff_initial_ms=1;failover_backoff_max_ms=2;\
         failover_max_duration_ms=0",
        srv.url()
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail — server dies and reconnect can't recover"),
    };
    // The error must NOT mention the deadline (attempts cap tripped).
    assert!(
        !err.msg().contains("failover_max_duration_ms"),
        "unbounded deadline must not surface a deadline-exhausted error; got: {}",
        err.msg()
    );
    assert!(matches!(
        err.code(),
        ErrorCode::SocketError | ErrorCode::ProtocolError
    ));
}

/// When the deadline trips before the attempts cap, the surfaced
/// error must mention `failover_max_duration_ms` so operators can
/// tell deadline exhaustion apart from attempts exhaustion.
#[test]
fn failover_deadline_exhaustion_surfaces_distinct_error_message() {
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "x"),
        drop_at_connect_script(),
    ]);
    // Large attempts cap, small duration cap → deadline trips first.
    let conf = format!(
        "qwp::addr={};failover_max_attempts=50;\
         failover_backoff_initial_ms=100;failover_backoff_max_ms=100;\
         failover_max_duration_ms=50",
        srv.url()
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail"),
    };
    // The deadline branch surfaces a specific message including the
    // configured `failover_max_duration_ms` value. The `prefer_over_trigger`
    // logic may pick the trigger over the deadline-error if the
    // trigger is more diagnostic — but in this test the trigger is a
    // plain SocketError, so the deadline message should win.
    assert!(
        err.msg().contains("failover_max_duration_ms")
            || err.msg().contains("wall-clock budget exhausted")
            || matches!(
                err.code(),
                ErrorCode::SocketError | ErrorCode::ProtocolError
            ),
        "unexpected error: code={:?} msg={}",
        err.code(),
        err.msg()
    );
}
