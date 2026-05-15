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

//! Live-server fuzz port of
//! [`io.questdb.test.cutlass.qwp.QwpEgressFragmentationFuzzTest`](https://github.com/questdb/questdb/blob/master/core/src/test/java/io/questdb/test/cutlass/qwp/QwpEgressFragmentationFuzzTest.java).
//!
//! Stresses the egress reader against a real QuestDB whose socket
//! layer is forced to chunk every send/recv at a tiny boundary. The
//! `debug.http.force.{recv,send}.fragmentation.chunk.size` server
//! props clamp every read/write to `chunk` bytes — handshake bytes,
//! WS frame headers, QWP preludes, CREDIT frames, batch payloads. The
//! client's resume-on-partial-read state machine must survive every
//! boundary.
//!
//! Each `#[test]` boots its own `QuestDbServer` via
//! `QuestDbServer::start_with_config(...)` so the chunk size is set
//! per test rather than racing a shared singleton. Four tests × one
//! JVM each ≈ ~60 s of boot overhead for the file; the protocol-level
//! coverage is worth it.
//!
//! Gated behind the `live-server-tests` Cargo feature so the default
//! `cargo test` doesn't try to spin up four JVMs. Seeded via
//! `QWP_EGRESS_FUZZ_SEED` (decimal or `0x...` hex) — failures reproduce
//! by setting the printed seed and rerunning.

#![cfg(feature = "live-server-tests")]

mod common;

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;

use common::QuestDbServer;

// ---------------------------------------------------------------------------
// SplitMix64 — same impl as the bind-fuzz file. Local copy is cheaper
// than wiring a shared crate-test module.
// ---------------------------------------------------------------------------

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self {
            state: seed | 0x9E37_79B9_7F4A_7C15,
        }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn gen_range_u32(&mut self, bound: u32) -> u32 {
        (self.next_u64() % bound as u64) as u32
    }
}

// ---------------------------------------------------------------------------
// Seed plumbing — mirrors `egress_live_server_bind_fuzz.rs`.
// ---------------------------------------------------------------------------

const DEFAULT_SEED: u64 = 0x6f93_a3e7_15b3_27c1;

fn fuzz_seed_for(test_name: &str) -> u64 {
    let base = std::env::var("QWP_EGRESS_FUZZ_SEED")
        .ok()
        .and_then(|raw| {
            let s = raw.trim();
            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                u64::from_str_radix(hex, 16).ok()
            } else {
                s.parse::<u64>().ok()
            }
        })
        .unwrap_or(DEFAULT_SEED);
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for b in test_name.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100_0000_01B3);
    }
    let combined = base.wrapping_add(hash);
    eprintln!("[qwp_egress_fuzz seed] {test_name} seed=0x{combined:016x}");
    combined
}

/// Java: `pickChunk()` — `1 + random.nextInt(500)` → `[1, 500]`.
fn pick_chunk(rng: &mut SplitMix64) -> u32 {
    1 + rng.gen_range_u32(500)
}

// ---------------------------------------------------------------------------
// Per-test server: starts a fresh QuestDB with the fragmentation knobs
// clamped to `chunk` bytes.
// ---------------------------------------------------------------------------

/// Mirrors Java's `startFragmented(int chunk)`. Sets both the recv and
/// send fragmentation chunk size on the HTTP layer so the WebSocket
/// codec, frame parser and credit accountant are all stressed.
fn start_fragmented(chunk: u32) -> QuestDbServer {
    let chunk_s = chunk.to_string();
    QuestDbServer::start_with_config(&[
        ("debug.http.force.recv.fragmentation.chunk.size", &chunk_s),
        ("debug.http.force.send.fragmentation.chunk.size", &chunk_s),
    ])
}

fn make_reader(srv: &QuestDbServer) -> Reader {
    Reader::from_conf(srv.qwp_conf()).expect("reader")
}

// ---------------------------------------------------------------------------
// Verification helpers.
// ---------------------------------------------------------------------------

/// Run `SELECT * FROM <table>` and sum the `id` LONG column across all
/// batches. Returns `(row_count, id_sum)`. The Java test verifies both
/// the row count and the closed-form sum `n * (n+1) / 2`, which catches
/// silent row corruption that a count-only check would miss.
fn select_all_sum_id(srv: &QuestDbServer, table: &str) -> (usize, i64) {
    let mut reader = make_reader(srv);
    let sql = format!("SELECT * FROM \"{table}\"");
    let mut cur = reader.prepare(sql).execute().expect("execute");
    let mut rows = 0usize;
    let mut id_sum: i64 = 0;
    while let Some(view) = cur.next_batch().expect("next_batch") {
        let n = view.row_count();
        // The Java test reads column 0 (the `id` long) directly via
        // `valuesAddr(0) + 8L * nonNullIndex(0)[r]`. The Rust
        // ColumnView::Long iterator hides the non-null index, but
        // since these fixtures never insert NULLs into `id`, iterating
        // rows 0..n is equivalent.
        if let ColumnView::Long(c) = view.column(0).unwrap() {
            for r in 0..n {
                id_sum = id_sum.wrapping_add(c.value(r));
            }
        } else {
            panic!("col 0 not Long");
        }
        rows += n;
    }
    (rows, id_sum)
}

/// Expected sum of `id` 1..=n inclusive.
fn expected_sum(n: usize) -> i64 {
    let n = n as i64;
    n * (n + 1) / 2
}

/// Poll until the table has applied at least `expected` rows. Same
/// pattern as the bind-fuzz file; necessary because WAL apply is
/// asynchronous from the INSERT's HTTP response.
fn wait_for_rows(srv: &QuestDbServer, table: &str, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let sql = format!("select count(*) from \"{table}\"");
    while std::time::Instant::now() < deadline {
        if let Ok(mut r) = Reader::from_conf(srv.qwp_conf())
            && let Ok(mut cur) = r.prepare(&sql).execute()
            && let Ok(Some(view)) = cur.next_batch()
            && let Ok(c) = view.column(0)
        {
            let n = match c {
                ColumnView::Long(c) => c.value(0),
                ColumnView::Int(c) => c.value(0) as i64,
                _ => -1,
            };
            if n as usize >= expected {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
    }
    panic!("{table} did not reach {expected} rows within 60s");
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// Ports `testFragmentedBackToBackQueries`. Pins cross-query state
/// survival under fragmentation: same connection runs the same
/// `SELECT *` query 5 times against an 8000-row table.
#[test]
fn fragmented_back_to_back_queries() {
    let mut rng = SplitMix64::new(fuzz_seed_for("fragmented_back_to_back_queries"));
    let chunk = pick_chunk(&mut rng);
    eprintln!("[fragmented_back_to_back_queries] chunk={chunk}");
    let srv = start_fragmented(chunk);

    let create = "create table btb(id LONG, v DOUBLE, ts TIMESTAMP) \
                  timestamp(ts) partition by day wal";
    let status = srv.http_exec(create);
    assert!((200..400).contains(&status), "create http={status}");
    let insert = "insert into btb \
                  select x, CAST(x * 2.5 AS DOUBLE), x::TIMESTAMP \
                  from long_sequence(8000)";
    let status = srv.http_exec(insert);
    assert!((200..400).contains(&status), "insert http={status}");
    wait_for_rows(&srv, "btb", 8000);

    let mut reader = make_reader(&srv);
    for q in 0..5 {
        let mut cur = reader
            .prepare("SELECT * FROM btb")
            .execute()
            .expect("execute");
        let mut rows = 0usize;
        let mut id_sum: i64 = 0;
        while let Some(view) = cur.next_batch().expect("next_batch") {
            let n = view.row_count();
            if let ColumnView::Long(c) = view.column(0).unwrap() {
                for r in 0..n {
                    id_sum = id_sum.wrapping_add(c.value(r));
                }
            }
            rows += n;
        }
        assert_eq!(rows, 8000, "q={q}: row_count drift");
        assert_eq!(id_sum, expected_sum(8000), "q={q}: id_sum drift");
        drop(cur);
    }
}

/// Ports `testFragmentedCreditFlow`. Small initial credit forces
/// CREDIT round-trips, so fragmentation must not break the credit
/// state machine when CREDIT frames interleave with chunked bytes.
#[test]
fn fragmented_credit_flow() {
    let mut rng = SplitMix64::new(fuzz_seed_for("fragmented_credit_flow"));
    let chunk = pick_chunk(&mut rng);
    eprintln!("[fragmented_credit_flow] chunk={chunk}");
    let srv = start_fragmented(chunk);

    let create = "create table cf as ( \
                  select x as id, x::TIMESTAMP as ts from long_sequence(20000) \
                  ) timestamp(ts) partition by day wal";
    let status = srv.http_exec(create);
    assert!((200..400).contains(&status), "create http={status}");
    wait_for_rows(&srv, "cf", 20_000);

    let mut reader = make_reader(&srv);
    let mut cur = reader
        .prepare("SELECT * FROM cf")
        .initial_credit(2 * 1024)
        .execute()
        .expect("execute");
    let mut rows = 0usize;
    let mut id_sum: i64 = 0;
    while let Some(view) = cur.next_batch().expect("next_batch") {
        let n = view.row_count();
        if let ColumnView::Long(c) = view.column(0).unwrap() {
            for r in 0..n {
                id_sum = id_sum.wrapping_add(c.value(r));
            }
        }
        rows += n;
    }
    assert_eq!(rows, 20_000, "row_count");
    assert_eq!(id_sum, expected_sum(20_000), "id_sum");
}

/// Ports `testFragmentedStreamingBigResult`. 50k-row multi-column
/// streaming under fragmentation; same row-count + sum verification.
/// The extra DOUBLE and SYMBOL columns force more bytes through the
/// fragmented path.
#[test]
fn fragmented_streaming_big_result() {
    let mut rng = SplitMix64::new(fuzz_seed_for("fragmented_streaming_big_result"));
    let chunk = pick_chunk(&mut rng);
    eprintln!("[fragmented_streaming_big_result] chunk={chunk}");
    let srv = start_fragmented(chunk);

    let create = "create table bigt as ( \
                  select x as id, CAST(x * 1.5 AS DOUBLE) as v, \
                  CAST('s_' || (x % 100) AS SYMBOL) as s, x::TIMESTAMP as ts \
                  from long_sequence(50000) \
                  ) timestamp(ts) partition by day wal";
    let status = srv.http_exec(create);
    assert!((200..400).contains(&status), "create http={status}");
    wait_for_rows(&srv, "bigt", 50_000);

    let (rows, id_sum) = select_all_sum_id(&srv, "bigt");
    assert_eq!(rows, 50_000, "row_count");
    assert_eq!(id_sum, expected_sum(50_000), "id_sum");
}

/// Ports `testHandshakeSurvivesMicroChunk`. Chunk pinned at 5 — the
/// ~220 B WebSocket 101 handshake fragments across ~44 socket writes,
/// forcing the upgrade path's park-resume state machine onto every
/// chunk boundary. Regression for the "Egress 101 handshake blocked"
/// bug fixed by deferring send to `onRequestComplete`.
#[test]
fn handshake_survives_micro_chunk() {
    eprintln!("[handshake_survives_micro_chunk] chunk=5 (pinned)");
    let srv = start_fragmented(5);

    let create = "create table tiny(id LONG, ts TIMESTAMP) timestamp(ts) partition by day wal";
    let status = srv.http_exec(create);
    assert!((200..400).contains(&status), "create http={status}");
    let insert = "insert into tiny select x, x::TIMESTAMP from long_sequence(3)";
    let status = srv.http_exec(insert);
    assert!((200..400).contains(&status), "insert http={status}");
    wait_for_rows(&srv, "tiny", 3);

    let (rows, id_sum) = select_all_sum_id(&srv, "tiny");
    assert_eq!(rows, 3, "row_count");
    assert_eq!(id_sum, expected_sum(3), "id_sum");
}
