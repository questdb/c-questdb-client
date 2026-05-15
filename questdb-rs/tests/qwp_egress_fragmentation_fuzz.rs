/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2026 QuestDB
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

//! Network-fragmentation fuzz harness for the QWP egress reader.
//!
//! Port of `core/src/test/java/io/questdb/test/cutlass/qwp/QwpEgressFragmentationFuzzTest.java`
//! from the OSS questdb repo. The Java reference drives the JVM server with
//! `DEBUG_HTTP_FORCE_{SEND,RECV}_FRAGMENTATION_CHUNK_SIZE` so every wire byte
//! ends up its own TCP segment, exercising the HTTP/WS state machines under
//! the same kinds of partial-read / park-resume conditions a Nagle-disabled
//! production server would emit when the network is congested.
//!
//! This Rust port reproduces the **client-visible** half: an in-process mock
//! whose `TcpStream` is wrapped in a [`ChunkingStream`] that splits every
//! socket read and write into at most `chunk_size` bytes (with `TCP_NODELAY`
//! so the kernel doesn't reaggregate sub-MTU writes). The mock then drives a
//! canned `SERVER_INFO` → `QUERY_REQUEST` (read) → `RESULT_BATCH` →
//! `RESULT_END` exchange and the test asserts the [`Reader`] sees every row
//! intact across the fragmented wire.
//!
//! Wire helpers and the WS-handshake plumbing are copied (not factored) from
//! `tests/egress_failover.rs`. The Java reference's `pickChunk()` returns
//! `1 + nextInt(500)`; we mirror that with proptest seeds and run three of
//! the four Java scenarios — credit-flow is intentionally out of scope
//! because it would need full ingestion-credit plumbing in the mock.

#![cfg(feature = "sync-reader-ws")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use questdb::egress::{ColumnView, Reader};
use tungstenite::handshake::server::{Request, Response};
use tungstenite::http::HeaderValue;
use tungstenite::{Message, WebSocket, accept_hdr};

// ---------------------------------------------------------------------------
// Wire constants and helpers (copied from tests/egress_failover.rs;
// kept local so this file is self-contained — the existing mock helpers
// are private to that module and the fragmentation harness only needs a
// subset of them).
// ---------------------------------------------------------------------------

const MAGIC: [u8; 4] = *b"QWP1";
const MSG_KIND_QUERY_REQUEST: u8 = 0x10;
const MSG_KIND_RESULT_BATCH: u8 = 0x11;
const MSG_KIND_RESULT_END: u8 = 0x12;
const MSG_KIND_SERVER_INFO: u8 = 0x18;
const SCHEMA_MODE_FULL: u8 = 0x00;
const NULL_FLAG_NONE: u8 = 0x00;
const COL_KIND_LONG: u8 = 0x05;

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

fn server_info_frame(node_id: &str) -> Vec<u8> {
    // role=Standalone (0x00), epoch=0, capabilities=0, server_wall_ns=0,
    // empty cluster_id, supplied node_id. The reader doesn't care about
    // the wall clock or capability bits for this fuzz; we just need the
    // frame to parse cleanly.
    let mut payload = vec![MSG_KIND_SERVER_INFO, 0x00];
    payload.extend_from_slice(&0u64.to_le_bytes()); // epoch
    payload.extend_from_slice(&0u32.to_le_bytes()); // capabilities
    payload.extend_from_slice(&0i64.to_le_bytes()); // server_wall_ns
    payload.extend_from_slice(&0u16.to_le_bytes()); // cluster_id length
    let node_bytes = node_id.as_bytes();
    payload.extend_from_slice(&(node_bytes.len() as u16).to_le_bytes());
    payload.extend_from_slice(node_bytes);
    framed(2, 0, 0, &payload)
}

fn result_end_frame(request_id: i64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(16);
    payload.push(MSG_KIND_RESULT_END);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(0, &mut payload); // final_seq
    encode_varint_u64(0, &mut payload); // total_rows_affected
    framed(2, 0, 0, &payload)
}

/// Build a `RESULT_BATCH` payload carrying a single 1-column LONG result
/// with `row_count` rows, where row `i` contains the value `i + 1` (so the
/// expected id sum is `n*(n+1)/2`, mirroring the Java reference's
/// `idSum` assertion).
fn result_batch_frame_seq(request_id: i64, batch_seq: u64, row_count: usize) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(MSG_KIND_RESULT_BATCH);
    payload.extend_from_slice(&request_id.to_le_bytes());
    encode_varint_u64(batch_seq, &mut payload);

    // Table block: empty name, row_count, col_count=1.
    encode_varint_u64(0, &mut payload);
    encode_varint_u64(row_count as u64, &mut payload);
    encode_varint_u64(1, &mut payload);

    // Schema section: Full, schema_id=1, one column "id" of type LONG.
    payload.push(SCHEMA_MODE_FULL);
    encode_varint_u64(1, &mut payload);
    encode_varint_u64(2, &mut payload); // name_len
    payload.extend_from_slice(b"id");
    payload.push(COL_KIND_LONG);

    // Column body: no nulls, then row_count × i64_le with monotonic ids.
    payload.push(NULL_FLAG_NONE);
    for i in 0..row_count {
        let v = (i as i64) + 1;
        payload.extend_from_slice(&v.to_le_bytes());
    }

    framed(2, 0, 1, &payload)
}

// ---------------------------------------------------------------------------
// `ChunkingStream`: cap every read/write at `chunk_size` bytes.
//
// `TCP_NODELAY` keeps the kernel from coalescing back-to-back small writes
// into larger packets; without it Nagle would defeat the point on loopback
// since the sender and receiver share the same machine. Each tungstenite
// `write_message` therefore turns into N short syscalls and the client
// observes them as N partial reads on the other side.
// ---------------------------------------------------------------------------

struct ChunkingStream {
    inner: TcpStream,
    chunk_size: usize,
}

impl ChunkingStream {
    fn new(inner: TcpStream, chunk_size: usize) -> std::io::Result<Self> {
        inner.set_nodelay(true)?;
        Ok(Self { inner, chunk_size })
    }
}

impl Read for ChunkingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.chunk_size);
        self.inner.read(&mut buf[..n])
    }
}

impl Write for ChunkingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.chunk_size);
        self.inner.write(&buf[..n])
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

// ---------------------------------------------------------------------------
// Mock server: accept WS connection through a `ChunkingStream`, send a
// canned SERVER_INFO + RESULT_BATCH + RESULT_END exchange, optionally
// for multiple sequential connections (back-to-back queries reuse the
// same mock).
// ---------------------------------------------------------------------------

struct FragMock {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
    accept_count: Arc<AtomicUsize>,
    /// Per-connection rows-to-send. Wrapping: connection N reads
    /// `rows_per_conn[N % len]`.
    #[allow(dead_code)]
    rows_per_conn: Arc<Mutex<Vec<usize>>>,
}

impl FragMock {
    /// Start a mock that, on each accepted connection, sends a result of
    /// `rows` rows (looking up by accept-index modulo length) through a
    /// `ChunkingStream` capped at `chunk_size`.
    fn start(rows_per_conn: Vec<usize>, chunk_size: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        let addr = listener.local_addr().expect("local_addr");
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_t = Arc::clone(&shutdown);
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_count_t = Arc::clone(&accept_count);
        let rows_per_conn = Arc::new(Mutex::new(rows_per_conn));
        let rows_t = Arc::clone(&rows_per_conn);

        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                if shutdown_t.load(Ordering::Relaxed) {
                    break;
                }
                let stream = match stream {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                let n = accept_count_t.fetch_add(1, Ordering::SeqCst);
                let rows = {
                    let q = rows_t.lock().unwrap();
                    if q.is_empty() { 0 } else { q[n % q.len()] }
                };
                let cs = match ChunkingStream::new(stream, chunk_size) {
                    Ok(cs) => cs,
                    Err(_) => continue,
                };
                // One worker per connection. Failures inside the worker
                // are swallowed — the test asserts against the client
                // side, not the mock's IO results.
                thread::spawn(move || run_session(cs, rows));
            }
        });

        FragMock {
            addr,
            shutdown,
            handle: Some(handle),
            accept_count,
            rows_per_conn,
        }
    }

    fn url(&self) -> String {
        self.addr.to_string()
    }

    fn accepts(&self) -> usize {
        self.accept_count.load(Ordering::SeqCst)
    }
}

impl Drop for FragMock {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Tickle the listener so accept() returns and the thread exits.
        let _ = TcpStream::connect(self.addr);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Handle one accepted connection: HTTP/WS upgrade (replying with
/// x-qwp-version=2 to match the SERVER_INFO frame), send SERVER_INFO,
/// read the client's QUERY_REQUEST, then emit RESULT_BATCH (rows) +
/// RESULT_END. Errors close the connection cleanly.
fn run_session(stream: ChunkingStream, rows: usize) {
    let mut ws: WebSocket<ChunkingStream> =
        match accept_hdr(stream, |_req: &Request, mut resp: Response| {
            resp.headers_mut()
                .insert("x-qwp-version", HeaderValue::from_static("2"));
            Ok(resp)
        }) {
            Ok(w) => w,
            Err(_) => return,
        };

    // SERVER_INFO is the first frame the reader expects post-upgrade.
    if ws
        .send(Message::Binary(server_info_frame("n1").into()))
        .is_err()
    {
        return;
    }
    let _ = ws.flush();

    // Read until we observe a QUERY_REQUEST (msg_kind 0x10). Other
    // client-side frames (CREDIT etc.) are not emitted by Reader for
    // this fuzz, but the loop tolerates them defensively.
    let request_id = match read_until_query_request(&mut ws) {
        Some(rid) => rid,
        None => return,
    };

    // Single batch + terminator. Larger results would split across
    // multiple RESULT_BATCH frames; one is enough to exercise the
    // partial-read path (the batch's bytes still trickle out chunk by
    // chunk through the ChunkingStream).
    if ws
        .send(Message::Binary(
            result_batch_frame_seq(request_id, 0, rows).into(),
        ))
        .is_err()
    {
        return;
    }
    let _ = ws.flush();

    let _ = ws.send(Message::Binary(result_end_frame(request_id).into()));
    let _ = ws.flush();

    // Give the client time to drain before we close so the chunked
    // close handshake doesn't preempt a still-in-flight read.
    thread::sleep(Duration::from_millis(20));
    let _ = ws.close(None);
}

/// Pull binary frames from the WS until one starts with msg_kind
/// `QUERY_REQUEST` (0x10). **Client → server messages on QWP egress are
/// emitted without the 12-byte QWP1 frame header** — only server → client
/// frames carry it (e.g. SERVER_INFO, RESULT_BATCH, RESULT_END). So the
/// QUERY_REQUEST layout is just `msg_kind(1) + request_id(8) + …`
/// directly. This matches the `read_until_query_request` helper in the
/// failover test (egress_failover.rs:545).
fn read_until_query_request(ws: &mut WebSocket<ChunkingStream>) -> Option<i64> {
    loop {
        match ws.read() {
            Ok(Message::Binary(bytes))
                if !bytes.is_empty() && bytes[0] == MSG_KIND_QUERY_REQUEST =>
            {
                if bytes.len() < 1 + 8 {
                    return None;
                }
                let mut id = [0u8; 8];
                id.copy_from_slice(&bytes[1..9]);
                return Some(i64::from_le_bytes(id));
            }
            Ok(Message::Close(_)) | Err(_) => return None,
            Ok(_) => continue,
        }
    }
}

// ---------------------------------------------------------------------------
// Test driver: connect a Reader, run a SELECT, sum the `id` column.
// ---------------------------------------------------------------------------

/// Run a single SELECT against the mock at `addr`, summing the `id`
/// column. Returns `(row_count, id_sum)`. The query SQL is irrelevant
/// — the mock ignores it and always emits the canned LONG result.
fn run_and_sum(addr: &str) -> (usize, i64) {
    let conf = format!("qwp::addr={}", addr);
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let mut cursor = reader.prepare("select 1").execute().expect("execute");
    let mut row_count = 0usize;
    let mut id_sum: i64 = 0;
    while let Some(view) = cursor.next_batch().expect("next_batch") {
        let n = view.row_count();
        if let ColumnView::Long(col) = view.column(0).expect("column 0") {
            for r in 0..n {
                id_sum = id_sum.wrapping_add(col.value(r));
            }
        } else {
            panic!("expected Long column, got something else");
        }
        row_count += n;
    }
    (row_count, id_sum)
}

fn expected_sum(rows: usize) -> i64 {
    let n = rows as i64;
    n * (n + 1) / 2
}

// ---------------------------------------------------------------------------
// Pseudo-random chunk picker.
//
// Java's `pickChunk` is `1 + random.nextInt(500)` per test. We do the
// same via a SplitMix64 seeded from a constant per scenario so failures
// surface the same way the Java seeds do: re-running the test with the
// same constant reproduces the failure. Could be promoted to a proptest
// strategy later; pinning matches the Java reference's
// `TestUtils.generateRandom(LOG, 492919964565416L, 1776636105288L)`
// pattern of "use a checked-in seed pair as the regression baseline".
// ---------------------------------------------------------------------------

fn pick_chunk(seed: u64) -> usize {
    // Splitmix64 step.
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    1 + (z as usize) % 500
}

// ---------------------------------------------------------------------------
// Tests (mirroring Java scenario names).
// ---------------------------------------------------------------------------

/// Mirrors `testFragmentedBackToBackQueries`. The Java reference runs 5
/// queries through one client against an 8000-row table; we run 3
/// queries through one Reader (a new Reader per query keeps the mock
/// scheduling simple) against a 200-row result. Chunk size is pseudo-
/// random per the pinned seed.
#[test]
fn fragmented_back_to_back_queries() {
    let chunk = pick_chunk(0x1234_5678_9ABC_DEF0);
    let rows = 200;
    let mock = FragMock::start(vec![rows; 4], chunk);
    let url = mock.url();
    for _ in 0..3 {
        let (n, sum) = run_and_sum(&url);
        assert_eq!(n, rows, "chunk={} row_count drift", chunk);
        assert_eq!(sum, expected_sum(rows), "chunk={} id_sum drift", chunk);
    }
    // Sanity: each query should have produced exactly one mock accept.
    assert!(
        mock.accepts() >= 3,
        "expected at least 3 accepts, saw {}",
        mock.accepts()
    );
}

/// Mirrors `testFragmentedStreamingBigResult`. Larger result, single
/// query — exercises the streaming path under sustained fragmentation.
/// 2000 rows is enough to span several large WS frames at chunk=1..500
/// without making the test slow.
#[test]
fn fragmented_streaming_big_result() {
    let chunk = pick_chunk(0xDEAD_BEEF_CAFE_BABE);
    let rows = 2000;
    let mock = FragMock::start(vec![rows], chunk);
    let (n, sum) = run_and_sum(&mock.url());
    assert_eq!(n, rows, "chunk={} row_count drift", chunk);
    assert_eq!(sum, expected_sum(rows), "chunk={} id_sum drift", chunk);
}

/// Mirrors `testHandshakeSurvivesMicroChunk`. Chunk pinned at 5 — the
/// ~220-byte WS 101 response fragments across ~44 socket writes,
/// forcing repeat park-resume. The Java reference was added as the
/// regression for the "Egress 101 handshake blocked" bug where any
/// chunk smaller than the handshake response would deadlock.
#[test]
fn handshake_survives_micro_chunk() {
    let mock = FragMock::start(vec![3], 5);
    let (n, sum) = run_and_sum(&mock.url());
    assert_eq!(n, 3, "chunk=5 row_count drift");
    assert_eq!(sum, expected_sum(3), "chunk=5 id_sum drift");
}

/// Sanity baseline: chunk size effectively unlimited (1 MiB) so the mock
/// behaves like the existing non-fragmented helpers. If this passes but
/// the fragmenting tests above hang, the chunking is the culprit; if
/// this also hangs, the wire-format synthesis is broken.
#[test]
fn unchunked_baseline_passes() {
    let mock = FragMock::start(vec![5], 1_000_000);
    let (n, sum) = run_and_sum(&mock.url());
    assert_eq!(n, 5);
    assert_eq!(sum, expected_sum(5));
}
