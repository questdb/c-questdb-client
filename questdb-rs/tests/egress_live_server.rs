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

//! Live-server integration tests for the QWP egress reader.
//!
//! Boots a real QuestDB from the `questdb/` submodule, seeds rows via
//! the existing ingress sender, then verifies that the egress reader
//! decodes the expected values for every column type the client
//! supports today.
//!
//! Gated behind the `live-server-tests` Cargo feature so the default
//! `cargo test` doesn't try to spin up a JVM.

#![cfg(feature = "live-server-tests")]

mod common;

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;
use questdb::ingress::{ProtocolVersion, Sender, TimestampNanos};

use common::QuestDbServer;

fn server() -> &'static QuestDbServer {
    static SERVER: OnceLock<QuestDbServer> = OnceLock::new();
    SERVER.get_or_init(QuestDbServer::start)
}

/// Append a unique suffix so parallel tests don't collide.
fn unique_table(stem: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("egress_{}_{}_{}",
        stem,
        std::process::id(),
        nanos as u64 & 0xFFFF_FFFF)
}

fn make_sender(srv: &QuestDbServer) -> Sender {
    Sender::from_conf(format!("{};protocol_version=2", srv.http_conf()))
        .expect("ingress sender")
}

/// Wait for a SELECT to return the expected row count via /exec — the
/// ingress flush is async, so the first `Reader::query` after the flush
/// can race the WAL apply.
fn wait_for_rows(srv: &QuestDbServer, table: &str, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        let sql = format!("select count(*) from \"{}\"", table);
        if srv.http_exec(&sql) == 200 {
            // The /exec endpoint returns 200 even with 0 rows; we lean on
            // the egress query for the actual count below. A short delay is
            // enough because we're already polling.
            std::thread::sleep(std::time::Duration::from_millis(150));
            // Quick probe via egress.
            let conf = srv.qwp_conf();
            let mut r = Reader::from_conf(&conf).expect("reader");
            let mut cur = r.query(&sql).execute().expect("execute count");
            if let Some(view) = cur.next_batch().expect("next_batch count") {
                if let Ok(ColumnView::Long(c)) = view.column(0) {
                    let n = c.value(0);
                    if n as usize >= expected {
                        return;
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!(
        "{} did not reach {} rows within 15s",
        table, expected
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Minimal smoke test: connect, run `select 1`, validate. Helps isolate
/// transport / handshake issues from data-path issues.
#[test]
fn smoke_select_literal() {
    let srv = server();
    let conf = srv.qwp_conf();
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = match reader.query("select 1 as v").execute() {
        Ok(c) => c,
        Err(e) => {
            srv.dump_recent_log(60);
            panic!("execute failed: {e:?}");
        }
    };
    let view = match cursor.next_batch() {
        Ok(v) => v,
        Err(e) => {
            srv.dump_recent_log(60);
            panic!("next_batch failed: {e:?}");
        }
    };
    let view = view.expect("Some batch");
    assert_eq!(view.row_count(), 1);
    let col = view.column(0).expect("col 0");
    eprintln!("smoke col kind={:?}", col.kind());
    match col {
        ColumnView::Long(c) => assert_eq!(c.value(0), 1),
        ColumnView::Int(c) => assert_eq!(c.value(0), 1),
        other => panic!("unexpected col kind: {:?}", other.kind()),
    }
}

#[test]
fn long_double_boolean_int_no_nulls() {
    let srv = server();
    let table = unique_table("primitives");
    srv.http_exec(&format!(
        "create table \"{}\" (l long, d double, b boolean, i int, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    let mut sender = make_sender(srv);
    let mut buf = sender.new_buffer();
    for i in 0..3i64 {
        buf.table(table.as_str())
            .unwrap()
            .column_i64("l", 100 + i)
            .unwrap()
            .column_f64("d", 1.5 * (i as f64))
            .unwrap()
            .column_bool("b", i % 2 == 0)
            .unwrap()
            .column_i64("i", i + 1)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + i * 1_000_000))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");

    wait_for_rows(srv, &table, 3);

    let conf = srv.qwp_conf();
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!("select l, d, b, i from \"{}\" order by ts", table))
        .execute()
        .expect("execute");

    let view = cursor
        .next_batch()
        .expect("next_batch")
        .expect("Some batch");
    assert_eq!(view.row_count(), 3);
    assert_eq!(view.column_count(), 4);

    let ColumnView::Long(l) = view.column(0).unwrap() else { panic!("col 0") };
    let ColumnView::Double(d) = view.column(1).unwrap() else { panic!("col 1") };
    let ColumnView::Boolean(b) = view.column(2).unwrap() else { panic!("col 2") };
    // QuestDB CREATE TABLE `int` maps to QWP INT column, but ILP `column_i64`
    // sends a LONG; the server widens the destination if needed. So the
    // returned column will surface as Int (4-byte) even though we sent i64.
    let i_col = view.column(3).unwrap();

    assert_eq!(l.value(0), 100);
    assert_eq!(l.value(1), 101);
    assert_eq!(l.value(2), 102);

    assert_eq!(d.value(0), 0.0);
    assert_eq!(d.value(1), 1.5);
    assert_eq!(d.value(2), 3.0);

    assert_eq!(b.value(0), 1);
    assert_eq!(b.value(1), 0);
    assert_eq!(b.value(2), 1);

    match i_col {
        ColumnView::Int(c) => {
            assert_eq!(c.value(0), 1);
            assert_eq!(c.value(1), 2);
            assert_eq!(c.value(2), 3);
        }
        ColumnView::Long(c) => {
            assert_eq!(c.value(0), 1);
            assert_eq!(c.value(1), 2);
            assert_eq!(c.value(2), 3);
        }
        other => panic!("unexpected i column kind: {:?}", other.kind()),
    }
}

#[test]
fn symbol_with_dict() {
    let srv = server();
    let table = unique_table("symbols");
    srv.http_exec(&format!(
        "create table \"{}\" (s symbol, v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    let mut sender = make_sender(srv);
    let mut buf = sender.new_buffer();
    let symbols = ["AAPL", "MSFT", "GOOG", "AAPL", "MSFT"];
    for (i, sym) in symbols.iter().enumerate() {
        buf.table(table.as_str())
            .unwrap()
            .symbol("s", *sym)
            .unwrap()
            .column_i64("v", (i as i64) * 10)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + i as i64 * 1_000_000))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, symbols.len());

    let conf = srv.qwp_conf();
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!("select s, v from \"{}\" order by ts", table))
        .execute()
        .expect("execute");

    let view = cursor
        .next_batch()
        .expect("next_batch")
        .expect("Some batch");
    assert_eq!(view.row_count(), symbols.len());

    let ColumnView::Symbol(s) = view.column(0).unwrap() else {
        panic!("col 0 not symbol")
    };
    let ColumnView::Long(v) = view.column(1).unwrap() else {
        panic!("col 1 not long")
    };
    for (i, expected) in symbols.iter().enumerate() {
        assert_eq!(s.resolve(i), Some(*expected));
        assert_eq!(v.value(i), i as i64 * 10);
    }
}

#[test]
fn timestamp_nanos_gorilla_path() {
    let srv = server();
    let table = unique_table("ts_gorilla");
    srv.http_exec(&format!(
        "create table \"{}\" (v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    // 16 rows with mostly-uniform deltas + occasional jitter — exercises
    // the small (1-bit / 9-bit) buckets of the Gorilla encoder.
    let mut sender = make_sender(srv);
    let mut buf = sender.new_buffer();
    let mut expected_ts: Vec<i64> = Vec::with_capacity(16);
    for i in 0..16i64 {
        let ts = 1_700_000_000_000_000_000 + i * 1_000_000 + (i % 4) * 137;
        expected_ts.push(ts);
        buf.table(table.as_str())
            .unwrap()
            .column_i64("v", i)
            .unwrap()
            .at(TimestampNanos::new(ts))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, expected_ts.len());

    let conf = srv.qwp_conf();
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!(
            "select ts, v from \"{}\" order by ts",
            table
        ))
        .execute()
        .expect("execute");

    let view = cursor
        .next_batch()
        .expect("next_batch")
        .expect("Some batch");
    assert_eq!(view.row_count(), expected_ts.len());

    // QuestDB's `timestamp` column is microsecond precision (QWP type
    // 0x0A); `at(TimestampNanos)` writes ns and the server truncates to
    // microseconds on storage. The Gorilla decoder runs for >=3 non-null
    // rows when the server sets FLAG_GORILLA on the batch.
    let ColumnView::Timestamp(ts_col) = view.column(0).unwrap() else {
        panic!("col 0 not timestamp")
    };
    let ColumnView::Long(v) = view.column(1).unwrap() else {
        panic!("col 1 not long")
    };
    for (i, expected_ns) in expected_ts.iter().enumerate() {
        let expected_us = expected_ns / 1_000;
        assert_eq!(ts_col.value(i), expected_us, "row {}", i);
        assert_eq!(v.value(i), i as i64);
    }
}

#[test]
fn varchar_round_trip() {
    let srv = server();
    let table = unique_table("varchar_roundtrip");
    srv.http_exec(&format!(
        "create table \"{}\" (s varchar, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    let mut sender = make_sender(srv);
    let mut buf = sender.new_buffer();
    let strings = ["hello", "", "café", "日本語"];
    for (i, s) in strings.iter().enumerate() {
        buf.table(table.as_str())
            .unwrap()
            .column_str("s", *s)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + i as i64 * 1_000_000))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, strings.len());

    let conf = srv.qwp_conf();
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!("select s from \"{}\" order by ts", table))
        .execute()
        .expect("execute");

    let view = cursor
        .next_batch()
        .expect("next_batch")
        .expect("Some batch");
    assert_eq!(view.row_count(), strings.len());

    let ColumnView::Varchar(c) = view.column(0).unwrap() else {
        panic!("col 0 not varchar")
    };
    for (i, expected) in strings.iter().enumerate() {
        assert_eq!(c.value(i), Some(*expected), "row {}", i);
    }
}

// Silence the "unused" warning for ProtocolVersion when the feature picks
// only the http sender path.
#[allow(dead_code)]
fn _unused(_: ProtocolVersion) {}
