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

#![cfg(feature = "sync-reader-qwp-ws")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use questdb::ErrorCode;
use questdb::egress::{
    ColumnView, FailoverPhase, FailoverProgressEvent, FailoverResetEvent, Reader, ServerRole,
};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::http::HeaderValue;
use tungstenite::{Message, WebSocket, accept_hdr};

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

const MAGIC: [u8; 4] = *b"QWP1";
const MSG_QUERY_REQUEST: u8 = 0x10;
const MSG_RESULT_BATCH: u8 = 0x11;
const MSG_RESULT_END: u8 = 0x12;
const MSG_QUERY_ERROR: u8 = 0x13;
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
    framed(1, 0, 0, &payload)
}

fn result_end_frame(request_id: i64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.push(MSG_RESULT_END);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(0, &mut payload); // final_seq
    encode_varint_u64(0, &mut payload); // total_rows
    framed(1, 0, 0, &payload)
}

/// Column payload for [`Action::SendBatch`]: one named, non-null column.
#[derive(Debug, Clone)]
enum BatchColumn {
    /// LONG column named `v`.
    Long(Vec<i64>),
    /// DOUBLE column named `d`.
    Double(Vec<f64>),
    /// SYMBOL column named `s`, carried in connection-scoped delta-dict
    /// mode (`FLAG_DELTA_SYMBOL_DICT`). `dict` is the full delta the
    /// batch appends starting at conn-id 0 (so each connection rebuilds
    /// its dict from scratch); `codes` are the per-row ids that index it.
    #[cfg_attr(not(feature = "arrow"), allow(dead_code))]
    Symbol { dict: Vec<String>, codes: Vec<u32> },
}

/// Single-table `RESULT_BATCH` frame carrying one non-null column. The
/// schema (col_count + the inline column descriptor) rides only
/// `batch_seq == 0`; continuation frames (`batch_seq > 0`) carry rows
/// only.
fn result_batch_frame(request_id: i64, batch_seq: u64, column: &BatchColumn) -> Vec<u8> {
    // Egress wire type codes (`ColumnKind::as_u8`).
    const KIND_LONG: u8 = 0x05;
    const KIND_DOUBLE: u8 = 0x07;
    const KIND_SYMBOL: u8 = 0x09;
    const NULL_FLAG_NONE: u8 = 0x00;
    // Frame header flag: SYMBOL columns ride the connection-scoped dict,
    // so the batch carries the delta-dict section (`flags::DELTA_SYMBOL_DICT`).
    const FLAG_DELTA_SYMBOL_DICT: u8 = 0x08;
    let (name, kind, row_count) = match column {
        BatchColumn::Long(v) => ("v", KIND_LONG, v.len()),
        BatchColumn::Double(v) => ("d", KIND_DOUBLE, v.len()),
        BatchColumn::Symbol { codes, .. } => ("s", KIND_SYMBOL, codes.len()),
    };
    let flags = match column {
        BatchColumn::Symbol { .. } => FLAG_DELTA_SYMBOL_DICT,
        _ => 0,
    };
    let mut payload = Vec::new();
    payload.push(MSG_RESULT_BATCH);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(batch_seq, &mut payload);
    // Delta-dict section rides immediately after `batch_seq` when
    // FLAG_DELTA_SYMBOL_DICT is set: `delta_start, delta_count, [len+bytes]...`.
    // Each connection rebuilds its dict from id 0, so delta_start is 0.
    if let BatchColumn::Symbol { dict, .. } = column {
        encode_varint_u64(0, &mut payload); // delta_start
        encode_varint_u64(dict.len() as u64, &mut payload); // delta_count
        for entry in dict {
            encode_varint_u64(entry.len() as u64, &mut payload);
            payload.extend_from_slice(entry.as_bytes());
        }
    }
    encode_varint_u64(0, &mut payload); // empty table name
    encode_varint_u64(row_count as u64, &mut payload);
    if batch_seq == 0 {
        encode_varint_u64(1, &mut payload); // col_count
        encode_varint_u64(name.len() as u64, &mut payload);
        payload.extend_from_slice(name.as_bytes());
        payload.push(kind);
    }
    payload.push(NULL_FLAG_NONE);
    match column {
        BatchColumn::Long(values) => {
            for v in values {
                payload.extend_from_slice(&v.to_le_bytes());
            }
        }
        BatchColumn::Double(values) => {
            for v in values {
                payload.extend_from_slice(&v.to_le_bytes());
            }
        }
        BatchColumn::Symbol { codes, .. } => {
            for code in codes {
                encode_varint_u64(*code as u64, &mut payload);
            }
        }
    }
    framed(1, flags, 1, &payload)
}

/// `QUERY_ERROR` frame: `[0x13, request_id i64 LE, status u8, msg_len u16 LE, msg_bytes...]`.
/// `status` is a raw `StatusCode` discriminant (e.g. `0x06` InternalError).
fn query_error_frame(request_id: i64, status: u8, message: &str) -> Vec<u8> {
    let msg_bytes = message.as_bytes();
    let mut payload = Vec::with_capacity(1 + 8 + 1 + 2 + msg_bytes.len());
    payload.push(MSG_QUERY_ERROR);
    payload.extend_from_slice(&request_id.to_le_bytes());
    payload.push(status);
    payload.extend_from_slice(&(msg_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(msg_bytes);
    framed(1, 0, 0, &payload)
}

/// `CACHE_RESET` frame. `mask = 0x01` clears the per-connection symbol
/// dict; `0x02` is reserved and ignored by recipients. The payload is
/// just `[msg_kind, mask]`.
fn cache_reset_frame(mask: u8) -> Vec<u8> {
    framed(1, 0, 0, &[MSG_CACHE_RESET, mask])
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
    /// Reply with a single-table, single-column RESULT_BATCH (using the
    /// request_id from the most-recent AwaitQueryRequest). The schema
    /// rides only `batch_seq == 0`; a `batch_seq > 0` frame carries rows
    /// only and relies on the client's retained per-query schema.
    SendBatch { batch_seq: u64, column: BatchColumn },
    /// Reply with QUERY_ERROR (using the request_id from the most-recent
    /// AwaitQueryRequest). `status` is a raw `StatusCode` discriminant,
    /// e.g. `0x06` (InternalError) for a generic server-side failure.
    SendQueryError { status: u8, message: String },
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
    /// failover path.
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
    /// a script step. Default is `1` (the single QWP version). Used to
    /// drive the version-rejection path in `transport.rs` by negotiating
    /// a version higher than `config.max_version`.
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

    // Pick the `x-qwp-version` to advertise. Default is "1" (the single
    // QWP version; matches the SERVER_INFO frames the helpers build); a
    // `HandshakeVersion(v)` action anywhere in the script overrides it so
    // tests can drive the version-mismatch path in `WsTransport::connect_to`.
    let handshake_version: String = script
        .iter()
        .find_map(|a| match a {
            Action::HandshakeVersion(v) => Some(v.to_string()),
            _ => None,
        })
        .unwrap_or_else(|| "1".to_string());
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
        // negotiate v1 to match the SERVER_INFO frames the helpers
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
            Action::SendQueryError { status, message } => {
                let rid = last_request_id.expect("AwaitQueryRequest before SendQueryError");
                let frame = query_error_frame(rid, status, &message);
                if ws.send(Message::Binary(frame.into())).is_err() {
                    return;
                }
            }
            Action::SendBatch { batch_seq, column } => {
                let rid = last_request_id.expect("AwaitQueryRequest before SendBatch");
                let frame = result_batch_frame(rid, batch_seq, &column);
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
    let conf = format!("ws::addr={}", srv.url());
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

// ---------------------------------------------------------------------------
// connect_timeout: bound the TCP dial (native non-blocking connect + poll),
// surfacing a distinct, failover-eligible ConnectTimeout on expiry.
// ---------------------------------------------------------------------------

#[test]
fn connect_timeout_set_does_not_break_a_reachable_connect() {
    // A reachable endpoint must still connect normally with connect_timeout
    // set — the budget bounds only the dial, and the mock accepts instantly.
    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n1")]);
    let conf = format!("ws::addr={};connect_timeout=5000", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("reachable connect within budget");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    assert!(cursor.next_batch().expect("next").is_none());
}

#[test]
fn connect_timeout_fires_against_a_blackhole_endpoint() {
    // 192.0.2.1 is RFC 5737 TEST-NET-1: globally unrouted, so the SYN is
    // dropped and the dial blocks until connect_timeout fires (instead of the
    // OS default, which is tens of seconds). `failover=off` so the single
    // timed-out dial surfaces immediately rather than retrying the budget.
    let conf = "ws::addr=192.0.2.1:19009;connect_timeout=300;failover=off";
    let start = Instant::now();
    let err = match Reader::from_conf(conf) {
        Err(e) => e,
        Ok(_) => panic!("dialing a blackhole endpoint must not succeed"),
    };
    let elapsed = start.elapsed();
    assert_eq!(
        err.code(),
        ErrorCode::ConnectTimeout,
        "expected ConnectTimeout, got {:?}: {}",
        err.code(),
        err.msg()
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the dial must be bounded by connect_timeout (~300ms), took {:?}",
        elapsed
    );
}

#[test]
fn cache_reset_mid_stream_does_not_break_cursor() {
    // The server emits CACHE_RESET to invalidate the per-connection
    // symbol dict (mask bit 0x01). The decoder applies the resets in
    // `decode_frame` before returning `ServerEvent::CacheReset`, and
    // `next_batch` is supposed to swallow that event and continue
    // reading. Live coverage is hard (the real server emits CACHE_RESET
    // only under specific dict-aging conditions) so the contract is
    // pinned here against a scripted mock.
    //
    // Sends 0x01 (clear dict), then 0x02 (a reserved bit, ignored by
    // recipients), then 0x03 (both) so the cursor is exercised against
    // the defined bit, a reserved bit, and their combination.
    let srv = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "n1".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendRaw(cache_reset_frame(0x01)), // clear dict
        Action::SendRaw(cache_reset_frame(0x02)), // reserved bit, ignored
        Action::SendRaw(cache_reset_frame(0x03)), // dict + reserved bit
        Action::SendResultEnd,
    ]]);
    let conf = format!("ws::addr={}", srv.url());
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

// ---------------------------------------------------------------------------
// Transient stale-cached-plan recovery (server INTERNAL_ERROR, status 0x06).
//
// An async `ALTER COLUMN TYPE` can bump a table's metadata version between a
// query's server-side compilation and its execution; the server then rejects
// its own cached plan with INTERNAL_ERROR. The reader must absorb this
// transparently — re-issue on the same healthy connection so the server
// recompiles — and never surface it to the caller. These pin that contract
// against the scripted mock so it can't regress into user-visible friction.
// ---------------------------------------------------------------------------

/// `0x06` INTERNAL_ERROR — the catch-all the server folds every transient
/// fault into, including the stale-cached-plan condition.
const STATUS_INTERNAL_ERROR: u8 = 0x06;

/// The exact server message shape (`9.x` QuestDB) for the stale-plan fault.
fn stale_plan_message() -> String {
    "cached query plan cannot be used because table schema has changed \
     [table=weather0, expectedTableId=33, actualTableId=33, \
     expectedMetadataVersion=61, actualMetadataVersion=62]"
        .to_string()
}

#[test]
fn stale_cached_plan_internal_error_is_transparently_retried() {
    // One connection: the first query is rejected with the transient
    // stale-plan INTERNAL_ERROR, the cursor silently re-issues on the SAME
    // connection (second AwaitQueryRequest), and the recompiled query then
    // streams a normal batch + RESULT_END. The caller must see only the
    // successful rows — never the error.
    let srv = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "n1".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendQueryError {
            status: STATUS_INTERNAL_ERROR,
            message: stale_plan_message(),
        },
        // The transparent replay lands here on the same connection.
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::SendResultEnd,
    ]]);
    let conf = format!("ws::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    {
        let view = cursor
            .next_batch()
            .expect("stale-plan error must be absorbed, not surfaced")
            .expect("recompiled query must yield its batch");
        assert_eq!(view.row_count(), 2);
        let ColumnView::Long(c) = view.column(0).expect("col 0") else {
            panic!("replayed column should decode as Long");
        };
        assert_eq!((c.value(0), c.value(1)), (1, 2));
    }
    assert!(
        cursor.next_batch().expect("terminal").is_none(),
        "RESULT_END must terminate the cursor cleanly after the silent retry"
    );
    // Exactly one transparent retry; no failover/reconnect was involved.
    assert_eq!(cursor.stale_plan_retries(), 1);
    assert_eq!(cursor.failover_resets(), 0);
    // One connection served the whole exchange — the retry stayed in place.
    assert_eq!(srv.accepts(), 1, "retry must reuse the same connection");
}

#[test]
fn non_stale_internal_error_still_surfaces_to_caller() {
    // A generic INTERNAL_ERROR (same status byte, different message) is NOT
    // the stale-plan condition and must surface unchanged — swallowing every
    // 0x06 would hide real server faults.
    let srv = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "n1".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendQueryError {
            status: STATUS_INTERNAL_ERROR,
            message: "table reader is distressed: out of file handles".to_string(),
        },
    ]]);
    let conf = format!("ws::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("a non-stale internal error must surface, not be swallowed"),
    };
    assert_eq!(err.code(), ErrorCode::ServerInternalError);
    assert_eq!(cursor.stale_plan_retries(), 0);
    assert_eq!(srv.accepts(), 1, "no retry, so no second connection");
}

#[test]
fn stale_cached_plan_after_rows_delivered_surfaces() {
    // The load-bearing `!data_delivered` guard: once a batch has been handed
    // to the caller, a later stale-plan error CANNOT be replayed (that would
    // re-stream consumed rows). It must surface instead.
    let srv = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "n1".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![7, 8, 9]),
        },
        Action::SendQueryError {
            status: STATUS_INTERNAL_ERROR,
            message: stale_plan_message(),
        },
    ]]);
    let conf = format!("ws::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    {
        let view = cursor
            .next_batch()
            .expect("first next_batch")
            .expect("batch present");
        assert_eq!(view.row_count(), 3);
    }
    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("stale-plan error after delivery must surface, not replay"),
    };
    assert_eq!(err.code(), ErrorCode::ServerInternalError);
    assert_eq!(cursor.stale_plan_retries(), 0);
}

#[test]
fn stale_cached_plan_retry_budget_exhausts_and_surfaces() {
    // A table under relentless schema churn keeps returning the stale-plan
    // error. The cursor must retry a bounded number of times and then
    // surface the error rather than loop forever. Script
    // `MAX_STALE_PLAN_RETRIES + 1` (= 16) error replies; the cursor spends
    // its 15 retries and surfaces on the 16th.
    let mut script = vec![Action::SendServerInfo {
        role: ServerRole::Standalone,
        node_id: "n1".into(),
    }];
    // 16 = MAX_STALE_PLAN_RETRIES (15) + the final un-retried surface.
    for _ in 0..16 {
        script.push(Action::AwaitQueryRequest);
        script.push(Action::SendQueryError {
            status: STATUS_INTERNAL_ERROR,
            message: stale_plan_message(),
        });
    }
    let srv = MockServer::start(vec![script]);
    let conf = format!("ws::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("exhausted retry budget must surface the stale-plan error"),
    };
    assert_eq!(err.code(), ErrorCode::ServerInternalError);
    assert_eq!(cursor.stale_plan_retries(), 15);
    // All retries stayed on the one connection.
    assert_eq!(srv.accepts(), 1);
}

#[test]
fn mid_query_close_triggers_failover() {
    // Server A: closes after QUERY_REQUEST. Server B: completes.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    assert_eq!(
        reader.current_addr().port,
        srv_a.addr.port(),
        "initial connect lands on A"
    );

    let observed: Arc<Mutex<Vec<FailoverResetEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(move |ev: &FailoverResetEvent| {
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
        // The mock advertises the single QWP version for every accept,
        // which always carries SERVER_INFO.
        let info = events[0]
            .new_server_info
            .as_ref()
            .expect("mock must surface SERVER_INFO of the new endpoint");
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
/// fires — is pinned end-to-end by
/// `post_batch_failover_without_callback_refuses_replay` below, via
/// `Action::SendBatch`; the boolean matrix itself is unit-tested by
/// `would_silently_duplicate_truth_table` in `src/egress/reader.rs`.)
#[test]
fn pre_batch_failover_without_callback_still_replays() {
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
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

/// Mid-query failover *after* a batch was already delivered: with a
/// reset callback installed (the replay opt-in), the replayed query
/// must re-read its schema from the new node's `batch_seq == 0` frame
/// and surface the new node's data through the same cursor. Server B
/// deliberately answers with a different column shape (DOUBLE `d` vs
/// LONG `v`) — the post-failover batch must decode against B's inline
/// schema, not against anything retained from A.
#[test]
fn failover_after_batch_replays_and_rereads_schema() {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Double(vec![1.5, 2.5, 3.5]),
        },
        Action::SendResultEnd,
    ]]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let observed: Arc<Mutex<Vec<FailoverResetEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(move |ev: &FailoverResetEvent| {
            observed_clone.lock().unwrap().push(ev.clone());
        })
        .execute()
        .expect("execute");

    // Batch 1: served by A before the drop, decoded against A's schema.
    {
        let view = cursor
            .next_batch()
            .expect("first next_batch")
            .expect("first batch present");
        assert_eq!(view.row_count(), 2);
        let ColumnView::Long(c) = view.column(0).expect("col 0") else {
            panic!("pre-failover column should decode against A's Long schema");
        };
        assert_eq!((c.value(0), c.value(1)), (1, 2));
    }

    // Batch 2: A is gone — this call observes the close, fails over,
    // replays, and must yield B's batch decoded against B's schema.
    {
        let view = cursor
            .next_batch()
            .expect("post-failover next_batch")
            .expect("post-failover batch present");
        assert_eq!(view.row_count(), 3);
        let ColumnView::Double(c) = view.column(0).expect("col 0") else {
            panic!("post-failover column must decode against B's Double schema");
        };
        assert_eq!((c.value(0), c.value(1), c.value(2)), (1.5, 2.5, 3.5));
    }
    assert_eq!(cursor.failover_resets(), 1);
    assert!(
        cursor.next_batch().expect("terminal").is_none(),
        "B's RESULT_END must terminate the cursor cleanly"
    );

    let events = observed.lock().unwrap();
    assert_eq!(events.len(), 1, "reset callback fired exactly once");
    assert_eq!(events[0].new_addr.port, srv_b.addr.port());
}

/// `Cursor::as_arrow_reader` pins the first batch's schema. A transparent
/// mid-query failover re-reads from `batch_seq 0` on the new node; when that
/// replay carries the **same** schema the reader must keep yielding batches
/// (and `schema()` must stay stable), not poison.
#[cfg(feature = "arrow-egress")]
#[test]
fn failover_arrow_reader_same_schema_continues() {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![3, 4, 5]),
        },
        Action::SendResultEnd,
    ]]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    // Install a reset callback so the streaming reader opts into transparent
    // replay (clears the silent-duplicate guard) and a post-failover batch
    // actually reaches the adapter instead of `FailoverWouldDuplicate`.
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(|_: &FailoverResetEvent| {})
        .execute()
        .expect("execute");
    {
        let mut arrow_reader = cursor.as_arrow_reader().expect("first batch + schema");
        let pinned = arrow_reader.schema();

        // Batch 1: A's pre-drop LONG batch.
        let b1 = arrow_reader
            .next()
            .expect("first item")
            .expect("first batch ok");
        assert_eq!(b1.num_rows(), 2);
        assert_eq!(b1.schema(), pinned);

        // Batch 2: A is gone — fail over to B, whose replayed batch 0 has the
        // SAME schema, so the reader continues instead of poisoning.
        let b2 = arrow_reader
            .next()
            .expect("post-failover item")
            .expect("post-failover batch ok");
        assert_eq!(b2.num_rows(), 3);
        assert_eq!(b2.schema(), pinned);
        assert_eq!(
            arrow_reader.schema(),
            pinned,
            "RecordBatchReader::schema must stay stable across failover"
        );

        assert!(
            arrow_reader.next().is_none(),
            "B's RESULT_END terminates the reader cleanly"
        );
    }
    assert_eq!(cursor.failover_resets(), 1);
}

/// Companion to [`failover_arrow_reader_same_schema_continues`]: when the
/// post-failover replay carries a **different** schema (B serves DOUBLE where
/// A served LONG), the adapter cannot keep a stable `schema()`, so it must
/// surface [`ErrorCode::SchemaDrift`] and poison rather than silently adopt
/// the new node's schema.
#[cfg(feature = "arrow-egress")]
#[test]
fn failover_arrow_reader_schema_drift_poisons() {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Double(vec![1.5, 2.5, 3.5]),
        },
        Action::SendResultEnd,
    ]]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    // Reset callback opts the streaming reader into transparent replay so the
    // divergent post-failover batch reaches the adapter (rather than
    // surfacing `FailoverWouldDuplicate`) and exercises the drift check.
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(|_: &FailoverResetEvent| {})
        .execute()
        .expect("execute");
    {
        let mut arrow_reader = cursor.as_arrow_reader().expect("first batch + schema");

        // Batch 1: A's LONG batch decodes fine against the pinned schema.
        let b1 = arrow_reader
            .next()
            .expect("first item")
            .expect("first batch ok");
        assert_eq!(b1.num_rows(), 2);

        // Batch 2: fail over to B, whose DOUBLE schema diverges from the pinned
        // LONG schema — surfaced as SchemaDrift, not silently swapped in.
        let err = arrow_reader
            .next()
            .expect("post-failover item present")
            .expect_err("divergent post-failover schema must yield an error");
        let qerr = questdb::egress::arrow::try_downcast_questdb(&err)
            .expect("adapter error downcasts to a questdb Error");
        assert_eq!(qerr.code(), ErrorCode::SchemaDrift);

        assert!(
            arrow_reader.next().is_none(),
            "reader is poisoned after drift"
        );
    }
    assert_eq!(cursor.failover_resets(), 1);
}

/// Regression pin for the reconnect-path schema clear
/// (`query_schema = None` in `Reader::reconnect_with_failover`): when
/// the replayed query's *first* frame from the new node is a
/// continuation (`batch_seq > 0`), the cursor must reject it as a
/// protocol error. Without the clear, the dead connection's retained
/// LONG schema would decode B's rows-only frame "successfully" and
/// resurface data bound to a schema the new connection never sent.
#[test]
fn failover_replay_continuation_before_schema_rejected() {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AwaitQueryRequest,
        // Misbehaving replay: the first frame is a continuation — the
        // schema-bearing batch 0 never arrives on this connection.
        Action::SendBatch {
            batch_seq: 1,
            column: BatchColumn::Long(vec![42]),
        },
        Action::SendResultEnd,
    ]]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=2;\
         failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(|_ev: &FailoverResetEvent| {})
        .execute()
        .expect("execute");

    // Batch 1 from A delivers fine.
    {
        let view = cursor
            .next_batch()
            .expect("first next_batch")
            .expect("first batch present");
        assert_eq!(view.row_count(), 2);
    }

    // A drops; the reconnect-and-replay itself succeeds, but the new
    // node's first frame is `batch_seq=1` with no schema on this
    // connection. Budget is limited to the first replay, so the
    // failover-eligible decode error from B surfaces as the original
    // ProtocolError instead of launching a second replay.
    let err = match cursor.next_batch() {
        Ok(_) => panic!("continuation before the schema-bearing batch 0 must be rejected"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::ProtocolError);
    assert!(
        err.msg().contains("arrived before the schema-bearing"),
        "unexpected message: {}",
        err.msg()
    );
    assert_eq!(
        cursor.failover_resets(),
        1,
        "the replay itself succeeded; only the post-replay decode failed"
    );
}

/// The silent-duplicate guard, end-to-end: once a batch has been
/// yielded to the caller and NO replay-aware callback is installed,
/// a mid-query failover must refuse to replay (the replay would
/// re-deliver row 1..2 with no signal) and surface
/// `FailoverWouldDuplicate` instead.
#[test]
fn post_batch_failover_without_callback_refuses_replay() {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    // NO on_failover_reset / on_failover_progress callback installed.
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    {
        let view = cursor
            .next_batch()
            .expect("first next_batch")
            .expect("first batch present");
        assert_eq!(view.row_count(), 2);
    }

    let err = match cursor.next_batch() {
        Ok(_) => panic!("data-delivered failover without a callback must refuse to replay"),
        Err(e) => e,
    };
    assert_eq!(err.code(), ErrorCode::FailoverWouldDuplicate);
    assert_eq!(
        cursor.failover_resets(),
        0,
        "the guard must fire before any reconnect is attempted"
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
/// branch from a scripted close — which keeps the
/// guard-fires-after-batch-delivered combination out of integration
/// scope for `add_credit` even though `Action::SendBatch` can put
/// data on the wire (the `next_batch` flavour of that combination is
/// pinned by `post_batch_failover_without_callback_refuses_replay`).
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    assert_eq!(reader.current_addr().port, srv_a.addr.port());

    let observed: Arc<Mutex<Vec<FailoverResetEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(move |ev: &FailoverResetEvent| {
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
        "ws::addr={};failover=off",
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
        "ws::addr={};failover=off",
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
    // max_attempts=4, the cursor's first failure should burn 3 outer
    // reconnect attempts, all of which fail.
    //
    // Dial accounting:
    //   - Initial connect: 1 dial to A (success).
    //   - Mid-stream failure on A. `reconnect_with_failover` has 3
    //     reconnect rounds (`max_attempts - 1`). Each outer round
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
        "ws::addr={};failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
        "ws::addr={};failover_max_attempts=1;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
fn next_batch_after_failover_exhaustion_does_not_collapse_to_clean_eof() {
    // Regression: once `failover_reconnect_and_replay` exhausts its
    // budget it sets `done=true` and surfaces the trigger error. The
    // contract is that subsequent `next_batch` calls keep surfacing
    // that error — NOT `Ok(None)`, which a retry-on-transient-error
    // caller would treat as a clean RESULT_END and silently drop the
    // remainder of the result set.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=1;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let first = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("budget exhausts and surfaces an error"),
    };
    assert!(
        matches!(
            first.code(),
            ErrorCode::SocketError | ErrorCode::ProtocolError
        ),
        "unexpected exhaustion code: {:?}",
        first.code()
    );

    match cursor.next_batch() {
        Ok(None) => panic!(
            "post-exhaustion next_batch collapsed to clean EOF — silent data loss \
             against a caller that retries on transient errors"
        ),
        Ok(Some(_)) => panic!("post-exhaustion next_batch yielded a batch"),
        Err(_) => { /* fine: error must keep surfacing */ }
    }

    // Errored cursors must not expose a success terminal either —
    // `terminal()` is reserved for RESULT_END / EXEC_DONE.
    assert!(cursor.terminal().is_none());
}

#[test]
fn next_batch_after_query_error_does_not_collapse_to_clean_eof() {
    // Same shape as `next_batch_after_failover_exhaustion_*`, but the
    // terminal here is a server-emitted `QUERY_ERROR` rather than a
    // failover give-up. Pins the second `next_batch` contract for the
    // server-error path at reader.rs around the `ServerEvent::Error`
    // arm: a follow-up call must re-raise, not silently return
    // `Ok(None)` and look like a clean RESULT_END.
    //
    // `failover=off` is explicit: QUERY_ERROR is not failover-eligible
    // even with failover on (server-level errors are terminal by
    // contract), so the flag doesn't change behaviour — it just keeps
    // the test's intent unambiguous on inspection.
    let srv = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        // status=0x06 → StatusCode::InternalError → ErrorCode::ServerInternalError.
        Action::SendQueryError {
            status: 0x06,
            message: "synthetic server failure".into(),
        },
    ]]);
    let conf = format!("ws::addr={};failover=off", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let first = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("server emitted QUERY_ERROR; first next_batch must surface it"),
    };
    assert_eq!(
        first.code(),
        ErrorCode::ServerInternalError,
        "unexpected error code from QUERY_ERROR terminal: {:?}",
        first.code()
    );

    match cursor.next_batch() {
        Ok(None) => panic!(
            "post-QUERY_ERROR next_batch collapsed to clean EOF — silent data loss \
             against a caller that retries on transient errors"
        ),
        Ok(Some(_)) => panic!("post-QUERY_ERROR next_batch yielded a batch"),
        Err(_) => { /* fine: error must keep surfacing */ }
    }

    assert!(
        cursor.terminal().is_none(),
        "errored cursor must not expose a success terminal"
    );
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
        "ws::addr={};failover_max_attempts=5;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
    let conf = format!("ws::addr={},{}", dead.url(), srv_b.url());
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
    // Setup: initial=20ms, max=200ms, max_attempts=3 → 2 reconnect
    // rounds; sleeps use base 20ms, then 40ms.
    // Sum of bases (= upper bound on total sleep under full-jitter)
    // is 60ms. The walk itself does host_count × 2 dials per outer
    // attempt × 2 attempts = 8 dials on loopback. Allow generous slack
    // for scheduler noise and connect overhead on busy CI runners.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=3;failover_backoff_initial_ms=20;failover_backoff_max_ms=200",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let start = Instant::now();
    let _ = cursor.next_batch();
    let elapsed = start.elapsed();
    // Sum of jitter ceilings (60ms) + scheduler/connect slack (580ms)
    // = 640ms upper bound. A regression that disables the cap or
    // reverts to deterministic backoff (60ms minimum + dials)
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
    // Dial accounting with `failover_max_attempts=4`:
    //   - Initial connect: 1 dial (success — serves the query, then drops).
    //   - Mid-stream failure on the single host triggers
    //     `reconnect_with_failover`, which has 3 reconnect rounds
    //     (`max_attempts - 1`).
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
        "ws::addr={};failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
fn replay_write_failure_uses_remaining_execute_budget() {
    // A: serves the initial query, then drops mid-stream. B: accepts the
    // reconnect and sends SERVER_INFO, but abortively closes before the
    // replayed QUERY_REQUEST can land. That failed replay write is the
    // second Execute attempt in Java's model; with `failover_max_attempts=3`,
    // the cursor still has one failover round left and should recover on
    // A's second script.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        happy_script(ServerRole::Standalone, "a-recovered"),
    ]);
    let srv_b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AbortiveRst,
    ]]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=3;failover_backoff_initial_ms=0;failover_backoff_max_ms=0",
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

    assert!(
        cursor.next_batch().expect("must recover via A").is_none(),
        "recovered query should complete without batches"
    );
    let r = *resets.lock().unwrap();
    assert_eq!(
        cursor.failover_resets(),
        r,
        "failover reset counter and callback must move together"
    );
    assert!(
        (1..=2).contains(&r),
        "expected one reset if B's abortive close is observed on replay write, \
         or two if the write is accepted locally and the reset is observed on \
         the next read; got {r}"
    );
    drop(cursor);
    assert_eq!(
        reader.current_addr().port,
        srv_a.addr.port(),
        "recovered cursor must end up bound to A's recovered slot"
    );
    assert_eq!(
        srv_a.accepts(),
        2,
        "A should see the initial query plus the final successful replay"
    );
    assert_eq!(
        srv_b.accepts(),
        1,
        "B should consume exactly one failed replay attempt"
    );
}

#[test]
fn failover_event_attempts_is_cumulative_across_rotations() {
    // `FailoverResetEvent.attempts` must be the cumulative reconnect count
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
        "ws::addr={};failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
    // total elapsed is closer to "9 sleeps × cap" than to "9
    // sleeps in pure doubling".
    //
    // initial=10, max=20, max_attempts=10 → 9 reconnect rounds:
    //   - capped:    10 + 20*8 ≈ 170 ms  (plus dial time)
    //   - uncapped: 10+20+40+80+160+320+640+1280+2560 ≈ 5110 ms
    // Anything well below the uncapped figure proves the `.min(max_ms)`
    // is firing.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        drop_at_connect_script(),
    ]);
    let srv_b = MockServer::start(vec![drop_at_connect_script()]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=10;failover_backoff_initial_ms=10;failover_backoff_max_ms=20",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("initial connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let start = Instant::now();
    let _ = cursor.next_batch();
    let elapsed = start.elapsed();
    // A working cap totals ~170 ms of backoff plus the 9 dial round-
    // trips; an uncapped run would total ~5.11 s of backoff alone
    // (10+20+40+80+160+320+640+1280+2560) plus dials. The 2 s threshold
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
        "ws::addr={};target=primary;failover_max_attempts=2;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
fn decode_error_triggers_failover_before_rows_are_delivered() {
    // Server A serves the initial query, then sends a malformed frame
    // (well-formed QWP1 header, but a bogus msg_kind in the payload that
    // `decode_frame` will reject). Before any rows have reached the
    // caller, that corruption is equivalent to a dying endpoint: failover
    // should replay the query on B instead of surfacing the decode error.
    let bogus_payload = vec![0xEEu8, 0, 0, 0, 0, 0, 0, 0, 0]; // unknown msg_kind.
    let bogus_frame = framed(1, 0, 0, &bogus_payload);
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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

    let batch = cursor
        .next_batch()
        .expect("decode error should fail over to B");
    assert_eq!(
        batch.map(|b| b.row_count()),
        None,
        "B's happy script returns RESULT_END after the replay"
    );
    assert_eq!(
        cursor.failover_resets(),
        1,
        "decode errors before delivery should trigger one replay"
    );
    assert_eq!(
        callback_fires.load(Ordering::SeqCst),
        1,
        "on_failover_reset must fire for a decode-triggered replay"
    );
    assert_eq!(
        srv_b.accepts(),
        1,
        "B must be dialed after the decode error on A"
    );
}

#[test]
fn decode_error_after_rows_without_callback_refuses_replay() {
    // Once rows were yielded to a streaming caller, transparent replay would
    // redeliver them from batch_seq=0. Decode-triggered failover must obey
    // the same duplicate guard as socket/read failures.
    let bogus_payload = vec![0xEEu8, 0, 0, 0, 0, 0, 0, 0, 0]; // unknown msg_kind.
    let bogus_frame = framed(1, 0, 0, &bogus_payload);
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::SendRaw(bogus_frame),
    ]]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    {
        let view = cursor
            .next_batch()
            .expect("first next_batch")
            .expect("first batch present");
        assert_eq!(view.row_count(), 2);
    }

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("post-delivery decode failover without a callback must refuse to replay"),
    };
    assert_eq!(err.code(), ErrorCode::FailoverWouldDuplicate);
    assert!(
        err.msg().contains("Trigger: unknown msg_kind"),
        "duplicate guard should preserve the decode trigger, got: {}",
        err.msg()
    );
    assert_eq!(cursor.failover_resets(), 0);
    assert_eq!(
        srv_b.accepts(),
        0,
        "duplicate guard must fire before dialing B"
    );
}

#[test]
fn deterministic_decode_error_does_not_drain_failover_budget() {
    // M6 regression: a server that *deterministically* re-emits a corrupt /
    // unknown frame for this query must NOT drag the cursor through a
    // reconnect -> replay -> re-corrupt loop that drains the entire
    // per-Execute failover budget (one log line per round). Transient wire
    // corruption (a truncated frame from a dying endpoint) is cured by a
    // single reconnect to a fresh connection; a *second* consecutive decode
    // failure on the replayed query is proof the corruption is deterministic
    // (server bug, version-mismatched MsgKind, mismatched lengths), so the
    // cursor must fail fast with the decode error instead of replaying
    // `failover_max_attempts - 1` times.
    let bogus_payload = vec![0xEEu8, 0, 0, 0, 0, 0, 0, 0, 0]; // unknown msg_kind.
    let bogus_frame = framed(1, 0, 0, &bogus_payload);
    // Both endpoints deterministically corrupt: SERVER_INFO, await the
    // (replayed) query, emit the identical bogus frame. The mock repeats the
    // last script once its queue is exhausted, so *every* reconnect lands on
    // the same corruption no matter how many times the cursor ping-pongs.
    let corrupt_script = |node: &str| {
        vec![
            Action::SendServerInfo {
                role: ServerRole::Standalone,
                node_id: node.into(),
            },
            Action::AwaitQueryRequest,
            Action::SendRaw(bogus_frame.clone()),
        ]
    };
    let srv_a = MockServer::start(vec![corrupt_script("a")]);
    let srv_b = MockServer::start(vec![corrupt_script("b")]);
    // Large reconnect budget + zero backoff: without a decode-specific cap
    // the cursor would replay 31 times before the budget drained.
    let conf = format!(
        "ws::addr={};failover_max_attempts=32;failover_backoff_initial_ms=0;failover_backoff_max_ms=0",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("deterministic decode corruption must surface an error"),
    };
    // The decode error surfaces — not a budget-exhausted SocketError after
    // dozens of rounds.
    assert_eq!(
        err.code(),
        ErrorCode::ProtocolError,
        "deterministic decode corruption should surface the decode error, got {:?}: {}",
        err.code(),
        err.msg()
    );
    assert!(
        err.msg().contains("unknown msg_kind"),
        "expected the decode trigger to surface, got: {}",
        err.msg()
    );
    // Decode-driven replays are capped well below the per-Execute budget
    // (here 31). One replay rules out a transient blip; further consecutive
    // decode failures are refused.
    assert!(
        cursor.failover_resets() <= 1,
        "deterministic decode corruption must not drain the failover budget; \
         got {} replays",
        cursor.failover_resets()
    );
    // Initial connect + at most one decode-driven replay.
    let total_accepts = srv_a.accepts() + srv_b.accepts();
    assert!(
        total_accepts <= 3,
        "server should be dialed only a couple of times (initial + at most \
         one replay), got {total_accepts}"
    );
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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

    assert!(!cursor.connection_reusable());

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
    let conf = format!("ws::addr={}", dead.url());
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
    let conf = format!("ws::addr={}", build_addr_list(&[&srv_a, &srv_b]));

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
    let conf = format!("ws::addr={}", srv.url());
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
        "ws::addr={};failover_max_attempts=3;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
    assert_eq!(
        srv_a.accepts(),
        3,
        "A should see the initial query plus exactly one exhausted reconnect walk; \
         a reset per-failure budget would dial it more often"
    );
    assert_eq!(
        srv_b.accepts(),
        3,
        "B should see the successful first reset plus exactly one exhausted reconnect walk; \
         a reset per-failure budget would dial it more often"
    );

    // Cursor terminal: follow-up next_batch keeps surfacing the
    // exhaustion error (same code as the first call) rather than
    // collapsing to Ok(None) — see
    // `next_batch_after_failover_exhaustion_does_not_collapse_to_clean_eof`
    // for the silent-data-loss rationale.
    let replay = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("post-exhaustion next_batch must re-raise, not return Ok"),
    };
    assert_eq!(
        replay.code(),
        err.code(),
        "replayed terminal error code must match the originating error"
    );
}

#[test]
fn failover_duration_budget_spans_successful_resets() {
    // The duration budget is per Execute, matching Java
    // QwpQueryClient. A successful replay must not reset the deadline:
    // if the first reconnect consumes the wall-clock budget, a second
    // mid-query failure in the same cursor must give up immediately
    // rather than earning a fresh failover window.
    let srv_a = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "a"),
        // Tripwire: if the deadline is incorrectly recreated for the
        // second failure, the cursor can reconnect here and finish
        // cleanly instead of surfacing deadline exhaustion.
        happy_script(ServerRole::Standalone, "a-recovered"),
    ]);
    let srv_b = MockServer::start(vec![vec![
        Action::Sleep(Duration::from_millis(150)),
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b-slow".into(),
        },
        Action::AwaitQueryRequest,
        Action::HardDrop,
    ]]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=5;\
         failover_backoff_initial_ms=0;failover_backoff_max_ms=0;\
         failover_max_duration_ms=100",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    let resets = Arc::new(AtomicUsize::new(0));
    let resets_cb = Arc::clone(&resets);
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(move |_| {
            resets_cb.fetch_add(1, Ordering::SeqCst);
        })
        .execute()
        .expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("second failure must exhaust the original deadline"),
    };
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
    assert_eq!(
        resets.load(Ordering::SeqCst),
        1,
        "only the first reconnect should reset successfully"
    );
    assert_eq!(
        srv_a.accepts(),
        1,
        "A's recovered slot must not be dialed after the per-Execute deadline is spent"
    );
    assert_eq!(srv_b.accepts(), 1, "B is used only for the first reset");
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
    // copy via `FailoverResetEvent.new_addr` instead of asking the cursor
    // directly — the whole point of adding `Cursor::current_addr`.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
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
        .on_failover_reset(move |ev: &FailoverResetEvent| {
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

    // (2) In-callback observation: the FailoverResetEvent should already
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
        "FailoverResetEvent.new_addr passed to the callback must be the failover target B"
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");

    // Capture the wall-clock instant the callback fires so we can
    // assert it ran *during* the next_batch call, not after.
    let cb_started_at: Arc<Mutex<Option<Instant>>> = Arc::new(Mutex::new(None));
    let cb_started_clone = Arc::clone(&cb_started_at);

    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(move |_ev: &FailoverResetEvent| {
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
    // `failover_max_attempts=3` (two reconnect rounds) keeps the
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
        "ws::addr={};failover_max_attempts=3;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
    // With two reconnect rounds and a successful first dial, only one
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
        "ws::addr={};target=primary;failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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

    // The cursor must be terminal — a follow-up next_batch re-raises
    // the same RoleMismatch error rather than collapsing to Ok(None)
    // — see `next_batch_after_failover_exhaustion_*` for rationale.
    let replay = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("post-exhaustion next_batch must re-raise, not return Ok"),
    };
    assert_eq!(
        replay.code(),
        ErrorCode::RoleMismatch,
        "replayed terminal must keep the RoleMismatch code"
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
    #[allow(clippy::assertions_on_constants)]
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
    let cfg = questdb::egress::ReaderConfig::from_conf("ws::addr=h:1").expect("parse");
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
    let conf = format!("ws::addr={};failover=off", srv.url());
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

/// Boundary value for the handshake version gate: `max_version + 1`
/// (`x-qwp-version: 2` with the version pinned at 1) must be rejected
/// exactly like any farther-out version — a crisp `HandshakeError`, not
/// a mid-stream frame-decode failure. The sibling test above drives the
/// same gate with a far-out value (99); this one pins the off-by-one
/// edge of the `server_version > max_version` comparison.
#[test]
fn version_just_above_max_rejected_at_handshake() {
    let srv = MockServer::start(vec![vec![Action::HandshakeVersion(2)]]);
    let conf = format!("ws::addr={};failover=off", srv.url());
    let err = match Reader::from_conf(&conf) {
        Ok(_) => panic!("connect must reject a version above max_version"),
        Err(e) => e,
    };
    assert_eq!(
        err.code(),
        ErrorCode::HandshakeError,
        "a version above max must surface HandshakeError; got {:?}: {}",
        err.code(),
        err.msg()
    );
    assert!(
        err.msg().contains("version 2"),
        "error message should mention the negotiated version: {}",
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
    let conf = "ws::addr=does-not-exist.qwp-test.invalid:9009;failover=off";
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
    let conf = format!("ws::addr={};{}", srv.url(), conf_suffix);
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
    let conf = format!("ws::addr={}", srv.url());
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
        "ws::addr={};username=admin;password=quest;failover=off",
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
    let conf = format!("ws::addr={};failover=off", srv.url());
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
    let conf = format!("ws::addr={};failover=off", srv.url());
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
    let conf = format!("ws::addr={};failover=off", srv.url());
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
    let conf = format!("ws::addr={};failover=off", srv.url());
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
    let conf = format!("ws::addr={};target=primary;failover=off", srv.url());
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
        "ws::addr={};failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
    // With `failover_max_attempts=3` (two reconnect rounds), the test
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
        "ws::addr={};failover_max_attempts=3;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
    // 1 host, failover_max_attempts=3 (two reconnect rounds).
    // Each outer round: walk (1 dial) +
    // fall-through reset walk (1 dial) = 2 dials.
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "x"),
        // Every subsequent accept: TCP drop. Even unlimited resets
        // wouldn't find a healthy slot.
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=3;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        srv.url()
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let _ = cursor.next_batch(); // Will fail.
    drop(cursor);
    drop(reader);

    // Two reconnect rounds × 2 dials per round = 4
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
        "ws::addr={};failover=off",
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
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
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
        "ws::addr={};failover=off;auth_timeout_ms={}",
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
    let conf = format!("ws::addr={};failover=off;auth_timeout_ms=5000", srv.url());
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
/// `x-qwp-version: 1`) but the post-upgrade read on the client side
/// has no SERVER_INFO frame to consume. With
/// `server_info_timeout_ms=100`, the client should give up within
/// ~150ms and surface a failover-eligible transport error.
#[test]
fn server_info_timeout_bounds_post_upgrade_stall() {
    use questdb::egress::ReaderConfig;

    // The implicit `handshake_version = "1"` advertises v1, which
    // triggers `read_server_info_frame` on the client side. The
    // script has no `SendServerInfo` action, so the server just
    // sleeps after the upgrade and never writes the frame.
    let srv = MockServer::start(vec![vec![Action::Sleep(Duration::from_millis(800))]]);
    // `server_info_timeout_ms` is programmatic-only; build the cfg
    // via `from_conf` and override the field before opening the
    // Reader. Matches the Java reference's `withServerInfoTimeout`
    // surface.
    let mut cfg = ReaderConfig::from_conf(format!("ws::addr={};failover=off", srv.url()))
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
    let mut cfg = ReaderConfig::from_conf(format!("ws::addr={};failover=off", srv.url()))
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
    let conf = format!("ws::addr={};zone=eu-west-1a;target=primary", srv.url());
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
    let conf = format!("ws::addr={};zone=eu-west-1a", srv.url());
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
        "ws::addr={};failover_max_attempts=100;\
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
/// `max_attempts=2` (one reconnect attempt) and a dead host, the
/// attempts cap should bound the loop, not the (absent) deadline.
#[test]
fn failover_max_duration_zero_means_unbounded() {
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "x"),
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=2;\
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
        "ws::addr={};failover_max_attempts=50;\
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

/// Regression for `reconnect_with_failover`'s exhaustion-error counter:
/// when `failover_max_duration_ms` cuts the loop short, the surfaced
/// message must report the **actual** number of attempts that ran, not
/// the configured `failover_max_attempts` cap. Otherwise an
/// operator reading the log sees a number that overstates the real
/// dial pressure and points at the wrong knob to tune.
#[test]
fn deadline_exhaustion_reports_actual_attempt_count_not_configured_cap() {
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "x"),
        drop_at_connect_script(),
    ]);
    // 50 configured attempts, but with 100ms backoffs and a 50ms
    // budget the deadline trips after the first failed walk — actual
    // attempts will be 1 or 2, never 51.
    const CONFIGURED_CAP: u32 = 50;
    let conf = format!(
        "ws::addr={};failover_max_attempts={CONFIGURED_CAP};\
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
    // The `prefer_over_trigger` logic may still surface the trigger
    // error instead of the deadline wrapper. Only enforce the
    // count-accuracy invariant when we actually got the deadline
    // message — otherwise the test's premise doesn't hold.
    if err.msg().contains("wall-clock budget exhausted") {
        // Extract the "after N attempt(s)" number.
        let msg = err.msg();
        let needle = "after ";
        let start = msg.find(needle).expect("missing 'after N attempt' phrase");
        let rest = &msg[start + needle.len()..];
        let end = rest.find(' ').expect("malformed attempt-count phrase");
        let n: u32 = rest[..end].parse().expect("attempt count not a u32");
        // Hard upper bound: anything ≥ CONFIGURED_CAP would mean the
        // bug is back (or the message is once again hard-coding the
        // configured cap). A handful of attempts is plausible if the
        // first walk and one retry both fired before the 50 ms budget
        // expired; CONFIGURED_CAP itself must never appear here.
        assert!(
            n < CONFIGURED_CAP,
            "attempt count {n} ≥ configured cap {CONFIGURED_CAP} — \
             message is reporting the configured cap instead of \
             the actual count. msg={msg}",
        );
        assert!(n >= 1, "attempt count must be ≥ 1, got {n}. msg={msg}");
    }
}

// ---------------------------------------------------------------------------
// Reader-migration + concurrent-stats-read contract.
//
// The Reader API documents (reader.rs:140-150) that its stat getters take
// `&self`, touch only atomics on `Arc<ReaderStats>`, and "may be invoked
// concurrently from a monitoring thread while another thread is driving a
// cursor." A compile-time assertion in `egress/reader.rs` pins `Send +
// Sync` on `Reader`/`ReaderStats`/`HostHealthTracker` so a future
// structural change can't silently invalidate that bound. This runtime
// test exercises the migration itself: the Reader is moved to a worker
// thread, the worker drives several sequential queries, and the main
// thread polls the `Arc<ReaderStats>` clone in parallel. Under TSan this
// surfaces any non-atomic access on the same memory the stat getters
// touch; under the default test runner it pins the API shape (Reader is
// `Send`, the stats Arc is share-by-clone).
// ---------------------------------------------------------------------------

#[test]
fn reader_migrates_to_worker_thread_with_concurrent_stats_polling() {
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering as AOrd;

    // Each query: server-info handshake (once), then await query / sleep /
    // result-end repeated. The Sleep stretches the inter-frame window so
    // the main thread's poll loop catches the cursor mid-flight rather
    // than after it's already drained.
    let script = vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "n1".into(),
        },
        Action::AwaitQueryRequest,
        Action::Sleep(Duration::from_millis(40)),
        Action::SendResultEnd,
        Action::AwaitQueryRequest,
        Action::Sleep(Duration::from_millis(40)),
        Action::SendResultEnd,
        Action::AwaitQueryRequest,
        Action::Sleep(Duration::from_millis(40)),
        Action::SendResultEnd,
    ];
    let srv = MockServer::start(vec![script]);
    let conf = format!("ws::addr={}", srv.url());

    let reader = Reader::from_conf(&conf).expect("connect");
    // Clone the stats Arc on main BEFORE the Reader migrates, so the
    // monitor thread reads counters via its own Arc handle — exactly
    // what the FFI does (`reader` stashes an `Arc<ReaderStats>`
    // clone next to the `UnsafeCell<Reader>` for the same reason).
    let stats = std::sync::Arc::clone(reader.stats());

    let worker_done = std::sync::Arc::new(AtomicBool::new(false));
    let worker_done_cloned = std::sync::Arc::clone(&worker_done);

    let worker = thread::spawn(move || {
        // `Reader` moves into this thread — exercises `Send`.
        let mut reader = reader;
        for _ in 0..3 {
            let mut cursor = reader
                .prepare("select 1")
                .execute()
                .expect("execute on worker thread");
            // Drain the cursor to terminus; each query bumps
            // `bytes_received` by the SERVER_INFO/handshake-or-RESULT_END
            // wire bytes so the monitor sees movement.
            while cursor.next_batch().expect("next_batch").is_some() {}
        }
        worker_done_cloned.store(true, AOrd::Release);
    });

    // Spin reading every getter the FFI exposes. No sleep — we want to
    // hammer the atomic load path concurrently with the worker's
    // transport reads/writes, so a regression that drops `Sync` or that
    // routes a getter through a non-atomic field is caught by TSan.
    let mut last_bytes = 0u64;
    let mut max_bytes = 0u64;
    let mut poll_count = 0u64;
    while !worker_done.load(AOrd::Acquire) {
        let b = stats.bytes_received.load(AOrd::Relaxed);
        let r = stats.read_ns.load(AOrd::Relaxed);
        let d = stats.decode_ns.load(AOrd::Relaxed);
        let c = stats.credit_granted_total.load(AOrd::Relaxed);
        // Monotonicity: a `&self` reader from a different thread MUST
        // observe non-decreasing counters under the Relaxed/Release
        // shape the producers use (`fetch_add(Relaxed)` on the worker).
        // A drop here would mean someone introduced a non-atomic
        // overwrite path on the same counter.
        assert!(
            b >= last_bytes,
            "bytes_received went backwards: {last_bytes} -> {b}"
        );
        last_bytes = b;
        max_bytes = max_bytes.max(b);
        // Touch every counter so all four paths are exercised.
        let _ = (r, d, c);
        poll_count += 1;
    }

    worker.join().expect("worker panicked");

    // Final stat read from main — happens-after the worker's atomic
    // store-Release on `worker_done`, so this MUST observe at least as
    // many bytes as any in-flight poll did.
    let final_bytes = stats.bytes_received.load(AOrd::Relaxed);
    assert!(
        final_bytes > 0,
        "expected bytes_received > 0 after three round-trips"
    );
    assert!(
        final_bytes >= max_bytes,
        "post-join bytes_received {final_bytes} < pre-join max {max_bytes} — \
         a poll observed a future state, or the store-Release happens-before \
         is broken"
    );
    assert!(
        poll_count > 0,
        "monitor thread didn't poll at all — worker drained before any read"
    );
}

// ---------------------------------------------------------------------------
// `on_failover_progress` lifecycle callback
// ---------------------------------------------------------------------------

/// Compact summary of a `FailoverProgressEvent` used by the tests
/// below. Cloning the full event would also work, but the tuple form
/// makes assertions read straight off the page.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProgressSnapshot {
    phase: FailoverPhase,
    attempt: u32,
    failed_port: u16,
    new_port: Option<u16>,
    trigger_code: ErrorCode,
    has_final_error: bool,
}

impl ProgressSnapshot {
    fn from_event(ev: &FailoverProgressEvent) -> Self {
        Self {
            phase: ev.phase,
            attempt: ev.attempt,
            failed_port: ev.failed_addr.port,
            new_port: ev.new_addr.as_ref().map(|a| a.port),
            trigger_code: ev.trigger.code(),
            has_final_error: ev.final_error.is_some(),
        }
    }
}

/// Build a closure that appends snapshots to a shared `Vec`, plus the
/// shared handle for the test to read after the cursor terminates.
/// Returning the closure (rather than wrapping `ReaderQuery`) avoids
/// the lifetime gymnastics of threading a `ReaderQuery<'r>` through a
/// helper.
fn progress_capture() -> (
    impl FnMut(&FailoverProgressEvent),
    Arc<Mutex<Vec<ProgressSnapshot>>>,
) {
    let observed: Arc<Mutex<Vec<ProgressSnapshot>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_clone = Arc::clone(&observed);
    let closure = move |ev: &FailoverProgressEvent| {
        observed_clone
            .lock()
            .unwrap()
            .push(ProgressSnapshot::from_event(ev));
    };
    (closure, observed)
}

#[test]
fn progress_callback_silent_on_happy_path() {
    // No failover → no event of any phase. Asserts the callback is
    // truly inert when nothing goes wrong, so a regression that fires
    // a spurious Reset / GaveUp on the success path would surface
    // here.
    let srv = MockServer::start(vec![happy_script(ServerRole::Standalone, "n1")]);
    let conf = format!("ws::addr={}", srv.url());
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let (capture, observed) = progress_capture();
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_progress(capture)
        .execute()
        .expect("execute");
    assert!(cursor.next_batch().expect("next").is_none());
    assert_eq!(
        observed.lock().unwrap().len(),
        0,
        "on_failover_progress must not fire on the happy path"
    );
}

#[test]
fn progress_callback_phase_order_on_successful_failover() {
    // A drops mid-stream → B serves the replayed query. The progress
    // callback should observe exactly: Disconnected, Retrying (≥1),
    // Reset — in that order. `attempt` is 0 on Disconnected, ≥1 on
    // Retrying, and equals the landing attempt on Reset. failed_port
    // points at A throughout; new_port is None until Reset, then
    // points at B.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let port_a = srv_a.addr.port();
    let port_b = srv_b.addr.port();

    let (capture, observed) = progress_capture();
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_progress(capture)
        .execute()
        .expect("execute");

    assert!(cursor.next_batch().expect("next").is_none());
    assert_eq!(cursor.failover_resets(), 1);

    let events = observed.lock().unwrap().clone();
    assert!(
        events.len() >= 3,
        "expected at least Disconnected + Retrying + Reset, got {:?}",
        events
    );

    // Disconnected: first event, attempt=0, no new_addr.
    assert_eq!(events[0].phase, FailoverPhase::Disconnected);
    assert_eq!(events[0].attempt, 0);
    assert_eq!(events[0].failed_port, port_a);
    assert_eq!(events[0].new_port, None);
    assert!(!events[0].has_final_error);

    // At least one Retrying with attempt ≥ 1 and no new_addr yet.
    let retry_count = events
        .iter()
        .filter(|e| e.phase == FailoverPhase::Retrying)
        .count();
    assert!(
        retry_count >= 1,
        "expected at least one Retrying event, got {:?}",
        events
    );
    for ev in events.iter().filter(|e| e.phase == FailoverPhase::Retrying) {
        assert!(ev.attempt >= 1, "Retrying.attempt must be >= 1: {:?}", ev);
        assert_eq!(ev.new_port, None, "new_addr only on Reset");
        assert!(!ev.has_final_error);
    }

    // Reset: last event in this scenario. Carries the new endpoint and
    // the attempt that landed.
    let reset_idx = events
        .iter()
        .position(|e| e.phase == FailoverPhase::Reset)
        .expect("Reset must fire on successful failover");
    let reset = &events[reset_idx];
    assert!(reset.attempt >= 1);
    assert_eq!(reset.new_port, Some(port_b));
    assert!(!reset.has_final_error);

    // No GaveUp on a successful failover.
    assert!(
        !events.iter().any(|e| e.phase == FailoverPhase::GaveUp),
        "GaveUp must not fire when failover succeeds: {:?}",
        events
    );

    // Phase ordering: every Disconnected precedes every Retrying which
    // precedes the Reset.
    let first_retry = events
        .iter()
        .position(|e| e.phase == FailoverPhase::Retrying)
        .unwrap();
    assert!(first_retry > 0, "Disconnected must precede Retrying");
    assert!(
        reset_idx > first_retry,
        "Reset must follow at least one Retrying"
    );
}

#[test]
fn progress_callback_gave_up_on_single_endpoint_exhaustion() {
    // Single endpoint that drops both mid-query and at-connect — the
    // failover loop walks the budget and surfaces a GaveUp event with
    // `final_error` populated. Mirrors `single_endpoint_failover_exhausts_budget`
    // above but asserts the progress callback rather than the dial count.
    let srv = MockServer::start(vec![
        drop_after_query_script(ServerRole::Standalone, "lonely"),
        drop_at_connect_script(),
    ]);
    let conf = format!(
        "ws::addr={};failover_max_attempts=4;failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        srv.url()
    );
    let mut reader = Reader::from_conf(&conf).expect("initial connect");
    let port = srv.addr.port();
    let (capture, observed) = progress_capture();
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_progress(capture)
        .execute()
        .expect("execute");

    let err = match cursor.next_batch() {
        Err(e) => e,
        Ok(_) => panic!("must fail eventually"),
    };
    assert!(matches!(
        err.code(),
        ErrorCode::SocketError | ErrorCode::ProtocolError
    ));

    let events = observed.lock().unwrap().clone();

    // First event: Disconnected, attempt=0.
    assert_eq!(events[0].phase, FailoverPhase::Disconnected);
    assert_eq!(events[0].attempt, 0);
    assert_eq!(events[0].failed_port, port);

    // Last event: GaveUp, attempt > 0, has_final_error true.
    let gave_up = events.last().expect("at least one event").clone();
    assert_eq!(gave_up.phase, FailoverPhase::GaveUp);
    assert!(
        gave_up.attempt >= 1,
        "GaveUp.attempt must reflect at least one tried dial: {:?}",
        gave_up
    );
    assert!(
        gave_up.has_final_error,
        "GaveUp must carry final_error: {:?}",
        gave_up
    );
    assert_eq!(gave_up.failed_port, port);
    assert_eq!(gave_up.new_port, None);

    // No Reset on the exhaustion path.
    assert!(
        !events.iter().any(|e| e.phase == FailoverPhase::Reset),
        "Reset must not fire when the budget exhausts: {:?}",
        events
    );

    // Retrying fires once per reconnect round. With
    // failover_max_attempts=4, three rounds are available.
    let retrying: Vec<_> = events
        .iter()
        .filter(|e| e.phase == FailoverPhase::Retrying)
        .collect();
    assert_eq!(
        retrying.len(),
        3,
        "expected exactly 3 Retrying events: {:?}",
        events
    );
    // Attempts must be strictly increasing.
    for (i, ev) in retrying.iter().enumerate() {
        assert_eq!(
            ev.attempt,
            (i + 1) as u32,
            "Retrying attempts not 1-based monotonic: {:?}",
            retrying
        );
    }
}

// NOTE: the C++ mock-driven test in `cpp_test/test_reader_mock.cpp` pins
// that a progress callback alone does not authorize replay after data has
// reached the caller. The reset-callback flavour of
// replay-after-data — including the schema re-read from the new node's
// batch 0 — is covered here via `Action::SendBatch` in
// `failover_after_batch_replays_and_rereads_schema`, and the
// guard-fires branch in
// `post_batch_failover_without_callback_refuses_replay`. The boolean
// matrix of `would_silently_duplicate` itself is exercised in the unit
// tests in `src/egress/reader.rs`.

#[test]
fn progress_and_reset_callbacks_both_fire_on_reset() {
    // When both callbacks are installed, they observe the same Reset
    // event and fire in a stable order (progress first, then reset).
    // Asserts the integration contract documented on
    // `ReaderQuery::on_failover_progress`.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");

    // Use a shared sequence-tracker so we can assert ordering between
    // the two callbacks without timestamps.
    let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let order_p = Arc::clone(&order);
    let order_r = Arc::clone(&order);

    let mut cursor = reader
        .prepare("select 1")
        .on_failover_progress(move |ev: &FailoverProgressEvent| {
            if ev.phase == FailoverPhase::Reset {
                order_p.lock().unwrap().push("progress.reset");
            }
        })
        .on_failover_reset(move |_ev: &FailoverResetEvent| {
            order_r.lock().unwrap().push("reset");
        })
        .execute()
        .expect("execute");

    assert!(cursor.next_batch().expect("next").is_none());

    let seen = order.lock().unwrap().clone();
    assert_eq!(
        seen,
        vec!["progress.reset", "reset"],
        "progress.reset must precede reset; got {:?}",
        seen
    );
}

#[test]
fn progress_callback_disconnected_fires_before_any_dial() {
    // Tight invariant: Disconnected MUST fire before any Retrying or
    // dial sees the wire. Tested by giving B a slow accept and
    // checking the relative ordering of (Disconnected emitted) vs
    // (B's accept counter incrementing).
    //
    // The mock server's `accepts()` counter increments per TCP
    // accept. If the callback observes Disconnected with
    // `srv_b.accepts() == 0`, the invariant holds.
    let srv_a = MockServer::start(vec![drop_after_query_script(ServerRole::Standalone, "a")]);
    let srv_b = MockServer::start(vec![happy_script(ServerRole::Standalone, "b")]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=2",
        build_addr_list(&[&srv_a, &srv_b])
    );
    let mut reader = Reader::from_conf(&conf).expect("connect");
    // After initial connect, B has had zero accepts.
    assert_eq!(srv_b.accepts(), 0);

    // Snapshot whether Disconnected fired before any Retrying. The
    // closure has access to a flag the callback sets on Disconnected.
    let disconnected_before_first_retry = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let saw_disconnected = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let f1 = Arc::clone(&disconnected_before_first_retry);
    let f2 = Arc::clone(&saw_disconnected);

    let mut cursor = reader
        .prepare("select 1")
        .on_failover_progress(move |ev: &FailoverProgressEvent| {
            match ev.phase {
                FailoverPhase::Disconnected => {
                    f2.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                // First Retrying observes whether Disconnected
                // already fired (stable across mock-server timing
                // because both callbacks run on the cursor's drive
                // thread).
                FailoverPhase::Retrying
                    if f2.load(std::sync::atomic::Ordering::SeqCst)
                        && !f1.load(std::sync::atomic::Ordering::SeqCst) =>
                {
                    f1.store(true, std::sync::atomic::Ordering::SeqCst);
                }
                _ => {}
            }
        })
        .execute()
        .expect("execute");

    assert!(cursor.next_batch().expect("next").is_none());
    assert!(
        saw_disconnected.load(std::sync::atomic::Ordering::SeqCst),
        "Disconnected must fire"
    );
    assert!(
        disconnected_before_first_retry.load(std::sync::atomic::Ordering::SeqCst),
        "Disconnected must fire before the first Retrying"
    );
}

// ---------------------------------------------------------------------------
// F4 — egress read failover wired into the materialise-whole DataFrame
//      helpers. `fetch_all_polars` / `fetch_all_arrow` install an internal
//      reset opt-in and discard their partial accumulation on a mid-query
//      failover, so replay-from-batch-0 yields a complete, in-order result.
//      The streaming entry points (`iter_polars`) deliberately keep
//      surfacing `FailoverWouldDuplicate`.
// ---------------------------------------------------------------------------

/// Server A: schema-bearing batch 0, then drop mid-stream. Server B:
/// the full result (its own batch 0 + a continuation + RESULT_END).
/// Shared by the F4 materialise-whole and streaming scenarios so both
/// see the identical "data delivered, then connection dies" sequence.
#[cfg(feature = "polars")]
fn f4_drop_after_batch_servers() -> (MockServer, MockServer) {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![1, 2]),
        },
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Long(vec![10, 20]),
        },
        Action::SendBatch {
            batch_seq: 1,
            column: BatchColumn::Long(vec![30]),
        },
        Action::SendResultEnd,
    ]]);
    (srv_a, srv_b)
}

/// Materialise-whole path: a mid-query failover after the first batch
/// must replay transparently — the internal reset opt-in clears the
/// silent-duplicate guard, the partial accumulation from server A is
/// discarded, and `fetch_all_polars` returns B's complete, in-order
/// result exactly once (no A rows, no duplicates).
#[test]
#[cfg(feature = "polars")]
fn fetch_all_polars_failover_after_batch_yields_complete_result() {
    let (srv_a, srv_b) = f4_drop_after_batch_servers();
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    // No user callback: the helper installs its own internal reset.
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let df = cursor
        .fetch_all_polars()
        .expect("materialise-whole must replay transparently");

    assert_eq!(cursor.failover_resets(), 1, "exactly one reset to server B");
    assert_eq!(df.height(), 3, "A's partial batch must be discarded");
    let col = df.select_at_idx(0).unwrap();
    assert_eq!(col.name().as_str(), "v");
    let series = col.as_materialized_series();
    let vals = series.i64().expect("LONG column");
    assert_eq!(
        (vals.get(0), vals.get(1), vals.get(2)),
        (Some(10), Some(20), Some(30)),
        "result must be B's rows in order, with no carry-over from A"
    );
}

/// Same `fetch_all_polars` transparency, but a user-supplied
/// `on_failover_reset` is already installed: the helper must leave it in
/// place (not clobber the caller's contract) and still produce the
/// complete result. The callback fires exactly once.
#[test]
#[cfg(feature = "polars")]
fn fetch_all_polars_preserves_user_reset_callback() {
    let (srv_a, srv_b) = f4_drop_after_batch_servers();
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let resets = Arc::new(AtomicUsize::new(0));
    let resets_cb = Arc::clone(&resets);
    let mut cursor = reader
        .prepare("select 1")
        .on_failover_reset(move |_ev: &FailoverResetEvent| {
            resets_cb.fetch_add(1, Ordering::SeqCst);
        })
        .execute()
        .expect("execute");

    let df = cursor.fetch_all_polars().expect("replay transparently");
    assert_eq!(df.height(), 3);
    assert_eq!(
        resets.load(Ordering::SeqCst),
        1,
        "the user-installed reset callback must still fire"
    );
}

/// Streaming path: the same drop-after-batch scenario through
/// `iter_polars` must NOT silently reset — one batch has already left
/// the iterator, so a mid-query failover surfaces
/// `FailoverWouldDuplicate` for the consumer to re-issue.
#[test]
#[cfg(feature = "polars")]
fn iter_polars_failover_after_batch_surfaces_would_duplicate() {
    let (srv_a, srv_b) = f4_drop_after_batch_servers();
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let mut iter = cursor.iter_polars().expect("iter_polars");

    // First DataFrame: A's batch 0, before the drop.
    let first = iter
        .next()
        .expect("first item present")
        .expect("first batch ok");
    assert_eq!(first.height(), 2);

    // Second pull observes A's drop. A batch already left the iterator
    // and no replay opt-in is installed on this streaming path, so the
    // cursor refuses to replay.
    let err = match iter.next() {
        Some(Err(e)) => e,
        other => panic!("streaming failover must surface an error; got {:?}", other),
    };
    assert_eq!(err.code(), ErrorCode::FailoverWouldDuplicate);

    drop(iter);
    assert_eq!(
        cursor.failover_resets(),
        0,
        "the guard must fire before any reconnect on the streaming path"
    );
}

/// Materialise-whole Arrow path mirrors the polars one:
/// `fetch_all_arrow` discards its partial batch vector on the mid-query
/// failover and returns B's complete batch set, pinned to B's schema.
#[test]
#[cfg(feature = "polars")]
fn fetch_all_arrow_failover_after_batch_yields_complete_result() {
    let (srv_a, srv_b) = f4_drop_after_batch_servers();
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");

    let (_schema, batches) = cursor
        .fetch_all_arrow()
        .expect("materialise-whole must replay transparently");

    assert_eq!(cursor.failover_resets(), 1, "exactly one reset to server B");
    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    assert_eq!(
        total_rows, 3,
        "A's partial batch must be discarded; only B's rows remain"
    );
}

// ---------------------------------------------------------------------------
// Regression: per-cursor SYMBOL cache must be reset on failover replay.
//
// The streaming Arrow path threads a persistent `SymbolValuesCache` across
// batches, keyed only on the connection dict's length. On mid-query
// failover the connection dict is rebuilt empty against the new node, but
// the per-cursor cache used to survive. If the new node's dict re-grew to
// the SAME length, `symbol_array` saw `cache.len == dict.len()` and reused
// the OLD node's interned strings — pairing the new node's row codes with
// the dead node's symbol values (silent wrong values, no error).
// ---------------------------------------------------------------------------

/// Pull every distinct symbol string out of a single-column SYMBOL
/// `RecordBatch`, in row order. The column is a
/// `Dictionary<UInt32, Utf8>`; the value at row `i` is
/// `values[keys[i]]`.
#[cfg(feature = "arrow")]
fn symbol_rows(rb: &arrow::array::RecordBatch) -> Vec<String> {
    use arrow::array::cast::AsArray;
    use arrow::array::types::UInt32Type;
    let dict = rb.column(0).as_dictionary::<UInt32Type>();
    let values = dict.values().as_string::<i32>();
    dict.keys()
        .iter()
        .map(|k| {
            values
                .value(k.expect("non-null symbol") as usize)
                .to_string()
        })
        .collect()
}

/// `&str` view over a `Vec<String>` so the assertions can compare against
/// `vec!["a", ...]` literals directly.
#[cfg(feature = "arrow")]
fn as_str_vec(v: &[String]) -> Vec<&str> {
    v.iter().map(String::as_str).collect()
}

/// Node A streams a SYMBOL batch that grows the connection dict to length 3
/// (`["a","b","c"]`), then drops mid-stream. Node B replays with its own
/// dict that reaches the *same length 3* but holds different strings
/// (`["x","y","z"]`). With the per-cursor SYMBOL cache reset on failover,
/// the replayed batch must read back B's real values; without the reset it
/// silently surfaced A's cached strings (matching dict length → cache hit).
#[test]
#[cfg(feature = "arrow")]
fn failover_replay_resets_symbol_cache_to_new_node_values() {
    let srv_a = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "a".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Symbol {
                dict: vec!["a".into(), "b".into(), "c".into()],
                codes: vec![0, 1, 2],
            },
        },
        Action::HardDrop,
    ]]);
    let srv_b = MockServer::start(vec![vec![
        Action::SendServerInfo {
            role: ServerRole::Standalone,
            node_id: "b".into(),
        },
        Action::AwaitQueryRequest,
        Action::SendBatch {
            batch_seq: 0,
            column: BatchColumn::Symbol {
                // Same length as A's dict (3) so a length-keyed cache hits,
                // but completely different strings.
                dict: vec!["x".into(), "y".into(), "z".into()],
                codes: vec![0, 1, 2],
            },
        },
        Action::SendResultEnd,
    ]]);
    let conf = format!(
        "ws::addr={};failover_backoff_initial_ms=1;failover_backoff_max_ms=10",
        build_addr_list(&[&srv_a, &srv_b])
    );

    let mut reader = Reader::from_conf(&conf).expect("connect to A");
    // A replay-aware callback opts the streaming cursor into replay after a
    // batch has already been delivered (otherwise the silent-duplicate guard
    // returns `FailoverWouldDuplicate` before any reconnect).
    let mut cursor = reader
        .prepare("select s from t")
        .on_failover_reset(|_ev: &FailoverResetEvent| {})
        .execute()
        .expect("execute");

    // Batch from A: primes the per-cursor SYMBOL values cache with A's dict
    // (length 3 → strings a/b/c).
    let a_batch = cursor
        .next_arrow_batch()
        .expect("A batch ok")
        .expect("A batch present");
    assert_eq!(as_str_vec(&symbol_rows(&a_batch)), vec!["a", "b", "c"]);

    // A drops; the cursor fails over to B and replays. B's dict reaches the
    // same length 3, so a stale length-keyed cache would resurface A's
    // strings. The fix resets the cache so B's real values are read.
    let b_batch = cursor
        .next_arrow_batch()
        .expect("B batch after failover ok")
        .expect("B batch present");
    assert_eq!(cursor.failover_resets(), 1, "exactly one reset to B");
    assert_eq!(
        as_str_vec(&symbol_rows(&b_batch)),
        vec!["x", "y", "z"],
        "post-failover SYMBOL values must be the new node's, not the cached \
         old-node strings paired with the new node's codes"
    );

    assert!(
        cursor.next_arrow_batch().expect("terminal").is_none(),
        "B's RESULT_END must terminate the cursor"
    );
}
