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

//! In-process QWP mock server shared by egress test binaries.
//!
//! Extracted from `egress_failover.rs` (which stood this up privately)
//! so other test files can script a deterministic sequence of frames
//! per connection without copying the harness. This module speaks QWP
//! over `tungstenite` on a `TcpListener` — no live QuestDB required.
//!
//! Included via `#[path = "common/qwp_mock.rs"] mod qwp_mock;` rather
//! than through `tests/common/mod.rs`, because that file is the
//! separate live-server harness and already declares its own contents.

// This file is compiled once per integration-test binary that includes
// it (Rust's "tests/<name>.rs each is a separate crate" model). Helpers
// that only some binaries need surface as `dead_code` in the others.
// Mark the module as such to keep `clippy -D warnings` quiet without
// peppering individual items with `#[allow]` (same convention as
// `tests/common/mod.rs`).
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use questdb::egress::ServerRole;
use tungstenite::handshake::server::{Request, Response};
use tungstenite::http::HeaderValue;
use tungstenite::{Message, WebSocket, accept_hdr};

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

pub const MAGIC: [u8; 4] = *b"QWP1";
pub const MSG_QUERY_REQUEST: u8 = 0x10;
pub const MSG_RESULT_BATCH: u8 = 0x11;
pub const MSG_RESULT_END: u8 = 0x12;
pub const MSG_QUERY_ERROR: u8 = 0x13;
pub const MSG_CANCEL: u8 = 0x14;
pub const MSG_CACHE_RESET: u8 = 0x17;
pub const MSG_SERVER_INFO: u8 = 0x18;

/// Wrap a payload in a 12-byte QWP1 frame header.
pub fn framed(version: u8, flags: u8, table_count: u16, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(12 + payload.len());
    buf.extend_from_slice(&MAGIC);
    buf.push(version);
    buf.push(flags);
    buf.extend_from_slice(&table_count.to_le_bytes());
    buf.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

pub fn encode_varint_u64(mut v: u64, out: &mut Vec<u8>) {
    while v & !0x7F != 0 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

pub fn server_info_frame(role: ServerRole, node_id: &str, cluster_id: &str) -> Vec<u8> {
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

pub fn result_end_frame(request_id: i64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.push(MSG_RESULT_END);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(0, &mut payload); // final_seq
    encode_varint_u64(0, &mut payload); // total_rows
    framed(1, 0, 0, &payload)
}

/// Column payload for [`Action::SendBatch`]: one named, non-null column.
#[derive(Debug, Clone)]
pub enum BatchColumn {
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
pub fn result_batch_frame(request_id: i64, batch_seq: u64, column: &BatchColumn) -> Vec<u8> {
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
pub fn query_error_frame(request_id: i64, status: u8, message: &str) -> Vec<u8> {
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
pub fn cache_reset_frame(mask: u8) -> Vec<u8> {
    framed(1, 0, 0, &[MSG_CACHE_RESET, mask])
}

// ---------------------------------------------------------------------------
// MockServer
// ---------------------------------------------------------------------------

/// Per-connection scripted action.
#[derive(Debug, Clone)]
pub enum Action {
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
pub type Script = Vec<Action>;

/// In-process QWP mock. Each accepted connection runs the next Script
/// from the per-server queue (round-robin if exhausted: re-uses the
/// last script).
pub struct MockServer {
    pub addr: SocketAddr,
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
    pub fn start(scripts: Vec<Script>) -> Self {
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

    pub fn url(&self) -> String {
        format!("{}", self.addr)
    }

    pub fn accepts(&self) -> usize {
        self.accept_count.load(Ordering::SeqCst)
    }

    /// Snapshot of every QUERY_REQUEST payload (msg_kind + body)
    /// observed by this server's workers, in arrival order. Each
    /// entry is the bare client-to-server frame as written by the
    /// cursor — no QWP1 header (only server frames carry that).
    pub fn captured_requests(&self) -> Vec<Vec<u8>> {
        self.captured_requests.lock().unwrap().clone()
    }

    /// Snapshot of the inbound `Authorization` header (if any) for
    /// every accepted connection, in arrival order. `None` entries
    /// mean the header was absent on that connection.
    pub fn captured_auth_headers(&self) -> Vec<Option<String>> {
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
pub fn run_script(
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
pub fn reject_upgrade(mut stream: TcpStream, captured_auth: &Arc<Mutex<Vec<Option<String>>>>) {
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
pub fn reject_upgrade_421(
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
pub fn parse_authorization_header(buf: &[u8]) -> Option<String> {
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
pub fn read_until_client_cancel(ws: &mut WebSocket<TcpStream>) -> bool {
    loop {
        match ws.read() {
            Ok(Message::Binary(b)) if !b.is_empty() && b[0] == MSG_CANCEL => return true,
            Ok(Message::Binary(_)) | Ok(Message::Text(_)) => continue,
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Frame(_)) => continue,
            Ok(Message::Close(_)) | Err(_) => return false,
        }
    }
}

pub fn read_until_query_request(
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

pub fn happy_script(role: ServerRole, node_id: &str) -> Script {
    vec![
        Action::SendServerInfo {
            role,
            node_id: node_id.into(),
        },
        Action::AwaitQueryRequest,
        Action::SendResultEnd,
    ]
}

pub fn drop_after_query_script(role: ServerRole, node_id: &str) -> Script {
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
pub fn drop_at_connect_script() -> Script {
    vec![Action::HardDrop]
}

pub fn build_addr_list(servers: &[&MockServer]) -> String {
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
pub struct DeadEndpoint {
    addr: SocketAddr,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl DeadEndpoint {
    pub fn new() -> Self {
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
    pub fn url(&self) -> String {
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
