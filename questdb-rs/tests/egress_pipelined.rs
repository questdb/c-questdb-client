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

//! Live-server integration tests for the pipelined QWP egress reader.
//!
//! Same fixture as `egress_live_server.rs`. Each test asserts that the
//! pipelined path produces results identical to the sync path on the
//! same data, so any divergence in framing / decode / state-management
//! between the two implementations would fail loudly here rather than
//! showing up as a subtle off-by-one in production.
//!
//! Gated behind `live-server-tests`.

#![cfg(feature = "live-server-tests")]

mod common;

use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use questdb::egress::column::ColumnView;
use questdb::egress::pipelined_reader::{Event, PipelinedReader, PipelinedTerminal};
use questdb::egress::reader::{Reader, Terminal};
use questdb::ingress::{Buffer, Sender, TimestampMicros};

use common::QuestDbServer;

fn server() -> &'static QuestDbServer {
    static SERVER: OnceLock<QuestDbServer> = OnceLock::new();
    SERVER.get_or_init(QuestDbServer::start)
}

fn unique_table(stem: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // Full `u128` nanos, formatted as-is. The previous shape masked
    // the low 32 bits which made cross-run collisions possible inside
    // any ~4-second window (PID + COUNTER would still differ, but
    // there was no reason to throw away the high bits).
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "egress_pipelined_{}_{}_{}_{}",
        stem,
        std::process::id(),
        nanos,
        n
    )
}

fn make_sender(srv: &QuestDbServer) -> Sender {
    Sender::from_conf(format!("{};protocol_version=2", srv.http_conf())).expect("ingress sender")
}

/// Wait until `select count(*) from <table>` returns at least `expected` rows.
fn wait_for_rows(srv: &QuestDbServer, table: &str, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(15);
    let sql = format!("select count(*) from \"{}\"", table);
    while Instant::now() < deadline {
        let conf = srv.qwp_conf();
        if let Ok(mut r) = Reader::from_conf(&conf)
            && let Ok(mut cur) = r.prepare(&sql).execute()
            && let Ok(Some(view)) = cur.next_batch()
            && let Ok(ColumnView::Long(c)) = view.column(0)
        {
            let n = c.value(0);
            let _ = cur.next_batch();
            if n as usize >= expected {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("wait_for_rows({}, {}) timed out", table, expected);
}

/// Ingest `n` rows of `(ts, id, price, sym)` into `table`. The schema
/// mirrors the `qwp_egress_read` example so the same query exercises
/// fixed + symbol columns at once.
fn ingest(srv: &QuestDbServer, table: &str, n: u64) {
    let symbols = ["AAPL", "MSFT", "GOOG", "AMZN"];
    let mut sender = make_sender(srv);
    let mut buf = Buffer::new(sender.protocol_version());
    for i in 1..=n {
        buf.table(table)
            .unwrap()
            .symbol("sym", symbols[(i as usize) % symbols.len()])
            .unwrap()
            .column_i64("id", i as i64)
            .unwrap()
            .column_f64("price", i as f64 * 1.25)
            .unwrap()
            .at(TimestampMicros::new(i as i64 * 10_000))
            .unwrap();
        if i % 5_000 == 0 {
            sender.flush(&mut buf).unwrap();
        }
    }
    if !buf.is_empty() {
        sender.flush(&mut buf).unwrap();
    }
}

/// One materialised row from the `(ts, id, price, sym)` schema, in the
/// shape produced by `ingest`. Captured per row so the test can pin
/// per-type content equivalence between the sync and pipelined paths
/// — not just an XOR checksum that could collapse swapped column
/// projections to the same digest.
#[derive(Debug, PartialEq)]
struct EquivRow {
    id: i64,
    price_bits: u64,
    sym: Option<String>,
}

/// Pull every batch from `cursor`, return (row_count, checksum, rows).
/// The XOR checksum is kept for fast pairwise comparison; `rows`
/// carries the materialised per-row values for the strict
/// element-wise assertion the caller runs at the end.
fn drain_sync(cur: &mut questdb::egress::reader::Cursor<'_>) -> (u64, u64, Vec<EquivRow>) {
    let mut rows = 0u64;
    let mut sum = 0u64;
    let mut out = Vec::new();
    while let Some(view) = cur.next_batch().expect("next_batch") {
        let id = match view.column(1).unwrap() {
            ColumnView::Long(c) => c,
            _ => panic!("id column must be Long"),
        };
        let price = match view.column(2).unwrap() {
            ColumnView::Double(c) => c,
            _ => panic!("price column must be Double"),
        };
        let sym = match view.column(3).unwrap() {
            ColumnView::Symbol(c) => c,
            _ => panic!("sym column must be Symbol"),
        };
        for r in 0..view.row_count() {
            let id_v = id.value(r);
            let price_bits = price.value(r).to_bits();
            let sym_s = sym.resolve(r).map(str::to_owned);
            let sym_len = sym_s.as_deref().map(str::len).unwrap_or(0) as u64;
            sum = sum.wrapping_add(id_v as u64 ^ price_bits ^ sym_len);
            out.push(EquivRow {
                id: id_v,
                price_bits,
                sym: sym_s,
            });
            rows += 1;
        }
    }
    (rows, sum, out)
}

fn drain_pipelined(
    cur: &mut questdb::egress::pipelined_reader::PipelinedCursor<'_>,
) -> (u64, u64, Vec<EquivRow>) {
    let mut rows = 0u64;
    let mut sum = 0u64;
    let mut out = Vec::new();
    loop {
        match cur.take_event().expect("take_event") {
            Event::Batch(b) => {
                let id = match b.column(1).unwrap() {
                    ColumnView::Long(c) => c,
                    _ => panic!("id column must be Long"),
                };
                let price = match b.column(2).unwrap() {
                    ColumnView::Double(c) => c,
                    _ => panic!("price column must be Double"),
                };
                let sym = match b.column(3).unwrap() {
                    ColumnView::Symbol(c) => c,
                    _ => panic!("sym column must be Symbol"),
                };
                for r in 0..b.row_count() {
                    let id_v = id.value(r);
                    let price_bits = price.value(r).to_bits();
                    let sym_s = sym.resolve(r).map(str::to_owned);
                    let sym_len = sym_s.as_deref().map(str::len).unwrap_or(0) as u64;
                    sum = sum.wrapping_add(id_v as u64 ^ price_bits ^ sym_len);
                    out.push(EquivRow {
                        id: id_v,
                        price_bits,
                        sym: sym_s,
                    });
                    rows += 1;
                }
            }
            Event::End { .. } | Event::ExecDone { .. } => break,
            Event::FailoverReset(_) => {
                panic!("unexpected FailoverReset in single-endpoint test")
            }
            _ => continue,
        }
    }
    (rows, sum, out)
}

#[test]
fn pipelined_streams_same_rows_as_sync() {
    let srv = server();
    let table = unique_table("equiv");
    srv.http_exec(&format!(
        "CREATE TABLE \"{}\" (ts TIMESTAMP, id LONG, price DOUBLE, sym SYMBOL) \
         TIMESTAMP(ts) PARTITION BY HOUR WAL",
        table
    ));
    const N: u64 = 25_000;
    ingest(srv, &table, N);
    wait_for_rows(srv, &table, N as usize);

    let sql = format!("SELECT ts, id, price, sym FROM \"{}\"", table);

    // Sync baseline.
    let (sync_rows, sync_sum, sync_values) = {
        let conf = srv.qwp_conf();
        let mut r = Reader::from_conf(&conf).unwrap();
        let mut cur = r.prepare(&sql).execute().unwrap();
        let res = drain_sync(&mut cur);
        match cur.terminal() {
            Some(Terminal::End { total_rows, .. }) => {
                assert_eq!(*total_rows as u64, N, "sync terminal total_rows mismatch");
            }
            other => panic!("sync terminal unexpected: {:?}", other),
        }
        res
    };

    // Pipelined path. The drop at end of scope releases the worker's
    // event channel and the reader's worker thread.
    let (pipelined_rows, pipelined_sum, pipelined_values, pipelined_read_ns, pipelined_decode_ns) = {
        let conf = srv.qwp_conf();
        let mut r = PipelinedReader::from_conf(&conf).unwrap();
        let mut cur = r.prepare(&sql).execute().unwrap();
        let (rows, sum, values) = drain_pipelined(&mut cur);
        match cur.terminal() {
            Some(PipelinedTerminal::End { total_rows, .. }) => {
                assert_eq!(
                    *total_rows as u64, N,
                    "pipelined terminal total_rows mismatch"
                );
            }
            other => panic!("pipelined terminal unexpected: {:?}", other),
        }
        // Drop the cursor before reading stats: `cur` holds
        // `&mut r`, and `r.read_ns()` needs `&r` (shared). The
        // counters live on the shared `Arc<ReaderStats>` and are
        // unaffected by the cursor's drop sequence.
        drop(cur);
        let read_ns = r.read_ns();
        let decode_ns = r.decode_ns();
        (rows, sum, values, read_ns, decode_ns)
    };

    assert_eq!(sync_rows, N, "sync row count");
    assert_eq!(pipelined_rows, N, "pipelined row count");
    assert_eq!(
        sync_sum, pipelined_sum,
        "sync and pipelined produced different content checksums"
    );

    // Strict per-row equivalence. The XOR checksum above would
    // collapse a regression that swapped
    // two columns' projections between the sync and pipelined
    // paths (XOR is commutative); element-wise equality catches
    // that. The per-row `EquivRow` carries the same i64 / f64
    // (compared by bit pattern so NaN matches NaN if both produce
    // it) / Option<String> shape on both sides.
    assert_eq!(
        sync_values.len(),
        pipelined_values.len(),
        "captured-row vectors must have the same length",
    );
    for (i, (s, p)) in sync_values.iter().zip(pipelined_values.iter()).enumerate() {
        assert_eq!(s, p, "row {} diverged: sync={:?} pipelined={:?}", i, s, p,);
    }

    // Regression: both `read_ns` and `decode_ns` MUST be non-zero
    // on the pipelined path after a non-trivial query. Pre-fix the
    // pipelined worker had no read-timing wrapper around
    // `read_frame_or_timeout`, so every `read_ns` accessor (Rust,
    // C FFI reader-bound, C FFI detached stats, C++ wrapper)
    // returned 0 forever — the example printed `read=0 ms`
    // silently regardless of actual wire time. `decode_ns` was
    // already instrumented; we pin both here so a future
    // regression that drops EITHER instrumentation
    // fails loudly. Lower bound is `> 0`; a 25k-row query reading
    // at least one frame must accumulate at least one nanosecond.
    assert!(
        pipelined_read_ns > 0,
        "pipelined read_ns must be non-zero after reading {} rows (got {})",
        N,
        pipelined_read_ns,
    );
    assert!(
        pipelined_decode_ns > 0,
        "pipelined decode_ns must be non-zero after reading {} rows (got {})",
        N,
        pipelined_decode_ns,
    );
}

#[test]
fn pipelined_drop_mid_stream_returns_reader_to_idle() {
    let srv = server();
    let table = unique_table("drop");
    srv.http_exec(&format!(
        "CREATE TABLE \"{}\" (ts TIMESTAMP, id LONG, price DOUBLE, sym SYMBOL) \
         TIMESTAMP(ts) PARTITION BY HOUR WAL",
        table
    ));
    // Enough rows that we definitely have multiple batches to drop mid-stream.
    const N: u64 = 50_000;
    ingest(srv, &table, N);
    wait_for_rows(srv, &table, N as usize);

    let sql = format!("SELECT ts, id, price, sym FROM \"{}\"", table);
    let conf = srv.qwp_conf();
    let mut r = PipelinedReader::from_conf(&conf).unwrap();

    // First query: consume one batch then drop.
    {
        let mut cur = r.prepare(&sql).execute().unwrap();
        match cur.take_event().unwrap() {
            Event::Batch(_) => {}
            other => panic!("expected first event to be a Batch, got {:?}", other),
        }
        // Implicit Drop here cancels + drains to terminal.
    }
    assert!(!r.has_active_query(), "reader must be idle after drop");

    // Second query on the same reader should work cleanly.
    let mut cur = r.prepare(&sql).execute().unwrap();
    let (rows, _sum, _values) = drain_pipelined(&mut cur);
    assert_eq!(rows, N, "second query row count");
}

#[test]
fn pipelined_explicit_cancel_terminates_cleanly() {
    let srv = server();
    let table = unique_table("cancel");
    srv.http_exec(&format!(
        "CREATE TABLE \"{}\" (ts TIMESTAMP, id LONG, price DOUBLE, sym SYMBOL) \
         TIMESTAMP(ts) PARTITION BY HOUR WAL",
        table
    ));
    const N: u64 = 100_000;
    ingest(srv, &table, N);
    wait_for_rows(srv, &table, N as usize);

    let sql = format!("SELECT ts, id, price, sym FROM \"{}\"", table);
    let conf = srv.qwp_conf();
    let mut r = PipelinedReader::from_conf(&conf).unwrap();
    let mut cur = r.prepare(&sql).execute().unwrap();

    // Consume a few events then ask the server to cancel.
    for _ in 0..2 {
        match cur.take_event().unwrap() {
            Event::Batch(_) => {}
            Event::End { .. } | Event::ExecDone { .. } => {
                // Query finished before our 2-batch warm-up; that's
                // fine, the cancel-after-terminal path is a no-op.
                cur.cancel().unwrap();
                return;
            }
            _ => continue,
        }
    }
    // Drain via cancel; must end without panic and without returning Err
    // beyond a clean Cancelled classification (which `cancel` itself
    // converts to `Ok(())`).
    cur.cancel().expect("cancel returned an unexpected error");
    drop(cur);
    assert!(
        !r.has_active_query(),
        "reader must be idle after explicit cancel"
    );

    // A follow-up query still works.
    let mut cur2 = r.prepare(&sql).execute().unwrap();
    // Drain only one batch to keep this test fast; the equivalence
    // test above already covers full-drain correctness.
    let _ = cur2.take_event().unwrap();
    drop(cur2);
}

#[test]
fn pipelined_exec_done_terminal() {
    let srv = server();
    let table = unique_table("exec");
    srv.http_exec(&format!(
        "CREATE TABLE \"{}\" (ts TIMESTAMP, id LONG) \
         TIMESTAMP(ts) PARTITION BY HOUR WAL",
        table
    ));
    let conf = srv.qwp_conf();
    let mut r = PipelinedReader::from_conf(&conf).unwrap();
    let sql = format!("INSERT INTO \"{}\" VALUES (1234567890, 42)", table);
    let mut cur = r.prepare(&sql).execute().unwrap();
    match cur.take_event().unwrap() {
        Event::ExecDone { rows_affected, .. } => {
            assert_eq!(rows_affected, 1, "INSERT VALUES should affect 1 row");
        }
        other => panic!("expected ExecDone, got {:?}", other),
    }
}
