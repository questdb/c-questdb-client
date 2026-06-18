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

//! Live-server concurrency tests for the pooled [`Db`] facade.
//!
//! Boots a real QuestDB from the `questdb/` submodule and hammers the ingest
//! (`Sender`) and egress (`Reader`) pools from many threads sharing one cloned
//! `Db` handle, proving that concurrent borrowers never error spuriously, the
//! pools serialise / grow correctly under contention, and a full ingest+query
//! round trip is correct across threads.
//!
//! Verification strategy:
//! * **Ingress** tests verify row counts via the HTTP `/exec` endpoint, so they
//!   exercise the *sender pool* without depending on the egress endpoint.
//! * **Egress** tests drive the *reader pool*; they begin with
//!   [`wait_egress_ready`] (the QWP/WS egress endpoint can lag `/ping` at boot).
//!
//! Gated behind `live-server-tests` (which pulls in `pool`) so the default
//! `cargo test` doesn't spin up a JVM.

#![cfg(all(feature = "live-server-tests", feature = "pool"))]

mod common;

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use questdb::db::{Db, DbError};
use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;
use questdb::ingress::TimestampNanos;

use common::QuestDbServer;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn server() -> &'static QuestDbServer {
    static SERVER: OnceLock<QuestDbServer> = OnceLock::new();
    SERVER.get_or_init(QuestDbServer::start)
}

fn unique_table(stem: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "dbpool_{}_{}_{}_{}",
        stem,
        std::process::id(),
        nanos as u64 & 0xFFFF_FFFF,
        n
    )
}

/// `http://host:port` base derived from the server's HTTP connect string.
fn http_base(srv: &QuestDbServer) -> String {
    let conf = srv.http_conf(); // "http::addr=H:P"
    let addr = conf
        .strip_prefix("http::addr=")
        .expect("http_conf shape")
        .trim_end_matches(';');
    format!("http://{addr}")
}

/// `select count() from <table>` via HTTP `/exec` (independent of egress).
fn http_count(srv: &QuestDbServer, table: &str) -> i64 {
    let url = format!("{}/exec", http_base(srv));
    let sql = format!("select count() from \"{table}\"");
    let mut resp = ureq::get(&url)
        .query("query", &sql)
        .call()
        .expect("/exec call");
    let body = resp.body_mut().read_to_string().expect("/exec body");
    parse_dataset_scalar(&body)
        .unwrap_or_else(|| panic!("could not parse count from /exec body: {body}"))
}

/// Pull the first scalar out of a `{"dataset":[[N,...]],...}` `/exec` reply.
fn parse_dataset_scalar(body: &str) -> Option<i64> {
    let idx = body.find("\"dataset\":[[")?;
    let tail = &body[idx + "\"dataset\":[[".len()..];
    let end = tail.find([',', ']'])?;
    tail[..end].trim().parse().ok()
}

fn wait_for_http_count(srv: &QuestDbServer, table: &str, expected: i64) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if http_count(srv, table) >= expected {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "{table} did not reach {expected} rows within 30s (last count={})",
        http_count(srv, table)
    );
}

/// Retry an egress reader connect until it succeeds or the deadline passes.
/// The QWP/WS egress endpoint can accept connections slightly after `/ping`
/// goes green, so the first reader connect may need a few retries.
fn wait_egress_ready(srv: &QuestDbServer) {
    let conf = srv.qwp_conf();
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match Reader::from_conf(&conf) {
            Ok(_reader) => return,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("egress endpoint not ready within 45s: {e}");
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

fn create_table(srv: &QuestDbServer, table: &str) {
    let status = srv.http_exec(&format!(
        "CREATE TABLE \"{table}\" (sym SYMBOL, v LONG, ts TIMESTAMP) \
         TIMESTAMP(ts) PARTITION BY DAY WAL"
    ));
    assert_eq!(status, 200, "create table failed (HTTP {status})");
}

/// Elastic `Db` with a lazy (min 0) query pool — for ingress-only tests that
/// must not touch the egress endpoint.
fn make_db_ingest(srv: &QuestDbServer) -> Db {
    Db::builder()
        .ingest_config(&srv.http_conf())
        .query_config(&srv.qwp_conf())
        .sender_pool_min(1)
        .sender_pool_max(6)
        .query_pool_min(0)
        .query_pool_max(4)
        .acquire_timeout(Duration::from_secs(30))
        .housekeeper_interval(Duration::from_millis(500))
        .build()
        .expect("build Db")
}

/// Elastic `Db` with both pools warm — for egress tests (call
/// [`wait_egress_ready`] first).
fn make_db_full(srv: &QuestDbServer) -> Db {
    Db::builder()
        .ingest_config(&srv.http_conf())
        .query_config(&srv.qwp_conf())
        .sender_pool_min(1)
        .sender_pool_max(6)
        .query_pool_min(1)
        .query_pool_max(4)
        .acquire_timeout(Duration::from_secs(30))
        .housekeeper_interval(Duration::from_millis(500))
        .build()
        .expect("build Db")
}

/// Ingest `count` rows tagged with `tag` via a pooled sender.
fn ingest_rows(db: &Db, table: &str, tag: &str, base: i64, count: i64) -> Result<(), DbError> {
    let mut sender = db.borrow_sender()?;
    let mut buf = sender.new_buffer();
    for i in 0..count {
        buf.table(table)?
            .symbol("sym", tag)?
            .column_i64("v", base + i)?
            .at(TimestampNanos::now())?;
    }
    sender.flush(&mut buf)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Ingress concurrency (sender pool) — verified over HTTP /exec.
// ---------------------------------------------------------------------------

/// Many threads ingest into one table through the shared sender pool. No borrow
/// should error, and every row must land.
#[test]
fn db_concurrent_ingest_pooled_senders() {
    let srv = server();
    let db = make_db_ingest(srv);
    let table = unique_table("ingest");
    create_table(srv, &table);

    let threads = 8;
    let per_thread = 500i64;

    let mut handles = Vec::new();
    for t in 0..threads {
        let db = db.clone();
        let table = table.clone();
        handles.push(std::thread::spawn(move || {
            ingest_rows(&db, &table, "ingest", t as i64 * per_thread, per_thread)
                .expect("concurrent ingest must not error");
        }));
    }
    for h in handles {
        h.join().expect("ingest thread panicked");
    }

    let expected = threads as i64 * per_thread;
    wait_for_http_count(srv, &table, expected);
    assert_eq!(http_count(srv, &table), expected);
    db.close();
}

/// Hold every borrowed sender simultaneously (barrier) so the pool is forced to
/// grow to the cap; prove all borrows succeed and the pool grew past `min`.
#[test]
fn db_sender_pool_grows_under_contention() {
    use std::sync::{Arc, Barrier};

    let srv = server();
    let db = make_db_ingest(srv);
    let table = unique_table("grow");
    create_table(srv, &table);

    let threads = 6; // == sender_pool_max
    let per_thread = 100i64;
    let barrier = Arc::new(Barrier::new(threads));

    let mut handles = Vec::new();
    for t in 0..threads {
        let db = db.clone();
        let table = table.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(std::thread::spawn(move || {
            let mut sender = db.borrow_sender().expect("borrow");
            // Force all slots to be held at once -> the pool must grow to max.
            barrier.wait();
            let mut buf = sender.new_buffer();
            for i in 0..per_thread {
                buf.table(table.as_str())
                    .unwrap()
                    .symbol("sym", "grow")
                    .unwrap()
                    .column_i64("v", t as i64 * per_thread + i)
                    .unwrap()
                    .at(TimestampNanos::now())
                    .unwrap();
            }
            sender.flush(&mut buf).expect("flush");
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    assert!(
        db.sender_pool_size() > 1,
        "pool should have grown beyond min under contention, got {}",
        db.sender_pool_size()
    );
    assert!(
        db.sender_pool_size() <= 6,
        "pool exceeded max: {}",
        db.sender_pool_size()
    );

    let expected = threads as i64 * per_thread;
    wait_for_http_count(srv, &table, expected);
    assert_eq!(http_count(srv, &table), expected);
    db.close();
}

/// A deliberately tiny sender pool (one slot) with many contenders and a
/// generous acquire timeout: borrows must serialise, never time out.
#[test]
fn db_tight_pool_serialises_without_timeout() {
    let srv = server();
    let db = Db::builder()
        .ingest_config(&srv.http_conf())
        .query_config(&srv.qwp_conf())
        .sender_pool_size(1)
        .query_pool_min(0)
        .query_pool_max(1)
        .acquire_timeout(Duration::from_secs(60))
        .build()
        .expect("build Db");
    let table = unique_table("tight");
    create_table(srv, &table);

    let threads = 6;
    let per_thread = 200i64;

    let mut handles = Vec::new();
    for t in 0..threads {
        let db = db.clone();
        let table = table.clone();
        handles.push(std::thread::spawn(move || {
            ingest_rows(&db, &table, "tight", t as i64 * per_thread, per_thread)
                .expect("tight-pool ingest must serialise, not time out");
        }));
    }
    for h in handles {
        h.join().expect("tight thread panicked");
    }

    let expected = threads as i64 * per_thread;
    wait_for_http_count(srv, &table, expected);
    assert_eq!(http_count(srv, &table), expected);
    assert_eq!(db.sender_pool_size(), 1, "tight pool must stay at 1");
    db.close();
}

/// Unified `Db::from_conf` (single `ws::` string -> http ingest + ws query)
/// round trip across threads, ingress verified over HTTP.
#[test]
fn db_from_conf_unified_ingest() {
    let srv = server();
    let db = Db::builder()
        .from_conf(&srv.qwp_conf())
        .expect("from_conf")
        .query_pool_min(0)
        .build()
        .expect("build Db");
    let table = unique_table("unified");
    create_table(srv, &table);

    let threads = 4;
    let per_thread = 250i64;
    let mut handles = Vec::new();
    for t in 0..threads {
        let db = db.clone();
        let table = table.clone();
        handles.push(std::thread::spawn(move || {
            ingest_rows(&db, &table, "unified", t as i64 * per_thread, per_thread)
                .expect("unified ingest");
        }));
    }
    for h in handles {
        h.join().expect("unified thread panicked");
    }

    let expected = threads as i64 * per_thread;
    wait_for_http_count(srv, &table, expected);
    assert_eq!(http_count(srv, &table), expected);
    db.close();
}

// ---------------------------------------------------------------------------
// Egress concurrency (reader pool). Requires the QWP/WS egress endpoint.
// ---------------------------------------------------------------------------

/// `select count() from <table>` through the pooled reader.
fn db_count(db: &Db, table: &str) -> i64 {
    let sql = format!("select count() from \"{table}\"");
    let mut out: i64 = -1;
    db.execute_query(&sql, |batch| {
        if batch.row_count() > 0
            && let Ok(ColumnView::Long(c)) = batch.column(0)
            && !c.is_null(0)
        {
            out = c.value(0);
        }
        true
    })
    .expect("count query");
    out
}

/// Seed once, then many threads run queries through the shared reader pool
/// concurrently. Every query must see the full row set.
#[test]
fn db_concurrent_query_pooled_readers() {
    let srv = server();
    wait_egress_ready(srv);
    let db = make_db_full(srv);
    let table = unique_table("query");
    create_table(srv, &table);

    let total: i64 = 2000;
    ingest_rows(&db, &table, "seed", 0, total).expect("seed");
    wait_for_http_count(srv, &table, total);

    let threads = 8;
    let iters = 15;
    let select = format!("select v from \"{table}\"");

    let mut handles = Vec::new();
    for _ in 0..threads {
        let db = db.clone();
        let select = select.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..iters {
                let mut seen: u64 = 0;
                let summary = db
                    .execute_query(&select, |batch| {
                        seen += batch.row_count() as u64;
                        true
                    })
                    .expect("concurrent query must not error");
                assert_eq!(summary.rows, total as u64);
                assert_eq!(seen, total as u64);
            }
        }));
    }
    for h in handles {
        h.join().expect("query thread panicked");
    }
    db.close();
}

/// Threads simultaneously ingest *and* query, exercising both pools at once.
/// Nothing must error; the final count must equal everything ingested.
#[test]
fn db_concurrent_mixed_ingest_and_query() {
    let srv = server();
    wait_egress_ready(srv);
    let db = make_db_full(srv);
    let table = unique_table("mixed");
    create_table(srv, &table);

    let writers = 5;
    let readers = 5;
    let per_writer = 300i64;

    let mut handles = Vec::new();

    for t in 0..writers {
        let db = db.clone();
        let table = table.clone();
        handles.push(std::thread::spawn(move || {
            for batch in 0..3 {
                let base = (t as i64 * 3 + batch) * per_writer;
                ingest_rows(&db, &table, "mixed", base, per_writer)
                    .expect("mixed ingest must not error");
            }
        }));
    }

    for _ in 0..readers {
        let db = db.clone();
        let table = table.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..20 {
                // Counts climb as writers run; we only assert the calls never
                // error or panic.
                let _ = db_count(&db, &table);
                std::thread::sleep(Duration::from_millis(5));
            }
        }));
    }

    for h in handles {
        h.join().expect("mixed thread panicked");
    }

    let expected = writers as i64 * 3 * per_writer;
    wait_for_http_count(srv, &table, expected);
    assert_eq!(db_count(&db, &table), expected);
    db.close();
}

/// Stopping a query early (handler returns false) must cancel cleanly and
/// leave the pooled reader reusable for the next borrower.
#[test]
fn db_query_early_stop_keeps_reader_reusable() {
    let srv = server();
    wait_egress_ready(srv);
    let db = make_db_full(srv);
    let table = unique_table("earlystop");
    create_table(srv, &table);

    let total: i64 = 1000;
    ingest_rows(&db, &table, "es", 0, total).expect("seed");
    wait_for_http_count(srv, &table, total);

    let select = format!("select v from \"{table}\"");

    // Stop after the first batch.
    let summary = db
        .execute_query(&select, |_batch| false)
        .expect("early-stop query");
    assert!(summary.stopped_early, "expected early stop");

    // Reader must have returned clean: follow-up full queries still work,
    // repeatedly, reusing pooled readers.
    for _ in 0..10 {
        assert_eq!(db_count(&db, &table), total);
    }
    db.close();
}
