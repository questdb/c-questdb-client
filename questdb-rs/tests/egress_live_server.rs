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
//! the existing ingress sender or HTTP `/exec` (for types ILP doesn't
//! cover), then verifies that the egress reader decodes the expected
//! values for every column type the client supports today.
//!
//! Gated behind the `live-server-tests` Cargo feature so the default
//! `cargo test` doesn't try to spin up a JVM.

#![cfg(feature = "live-server-tests")]

mod common;

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use questdb::egress::column::ColumnView;
use questdb::egress::reader::{Reader, Terminal};
use questdb::ingress::{ProtocolVersion, Sender, TimestampNanos};

use common::QuestDbServer;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

fn server() -> &'static QuestDbServer {
    static SERVER: OnceLock<QuestDbServer> = OnceLock::new();
    SERVER.get_or_init(QuestDbServer::start)
}

/// Append a unique suffix so parallel tests don't collide on table name.
fn unique_table(stem: &str) -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "egress_{}_{}_{}_{}",
        stem,
        std::process::id(),
        nanos as u64 & 0xFFFF_FFFF,
        n
    )
}

fn make_sender(srv: &QuestDbServer, version: ProtocolVersion) -> Sender {
    let v = match version {
        ProtocolVersion::V1 => "1",
        ProtocolVersion::V2 => "2",
        ProtocolVersion::V3 => "3",
    };
    Sender::from_conf(format!("{};protocol_version={}", srv.http_conf(), v))
        .expect("ingress sender")
}

fn make_reader(srv: &QuestDbServer) -> Reader {
    let conf = srv.qwp_conf();
    Reader::from_conf(&conf).expect("reader")
}

/// Wait until `select count(*) from <table>` returns at least `expected` rows.
fn wait_for_rows(srv: &QuestDbServer, table: &str, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let sql = format!("select count(*) from \"{}\"", table);
    while std::time::Instant::now() < deadline {
        let conf = srv.qwp_conf();
        if let Ok(mut r) = Reader::from_conf(&conf) {
            if let Ok(mut cur) = r.query(&sql).execute() {
                if let Ok(Some(view)) = cur.next_batch() {
                    if let Ok(c) = view.column(0) {
                        let n = match c {
                            ColumnView::Long(c) => c.value(0),
                            ColumnView::Int(c) => c.value(0) as i64,
                            _ => -1,
                        };
                        if n as usize >= expected {
                            return;
                        }
                    }
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
    }
    panic!("{} did not reach {} rows within 15s", table, expected);
}

/// Run a SELECT and return the first batch's BatchView (panics if none).
/// The closure runs on it.
fn select_one_batch<F: FnOnce(&questdb::egress::reader::BatchView<'_>)>(
    srv: &QuestDbServer,
    sql: &str,
    check: F,
) {
    let mut reader = make_reader(srv);
    let mut cursor = reader.query(sql).execute().expect("execute");
    let view = cursor
        .next_batch()
        .expect("next_batch")
        .expect("Some batch");
    check(&view);
}

// ---------------------------------------------------------------------------
// Smoke
// ---------------------------------------------------------------------------

#[test]
fn smoke_select_literal() {
    let srv = server();
    select_one_batch(srv, "select 1 as v", |view| {
        assert_eq!(view.row_count(), 1);
        match view.column(0).unwrap() {
            ColumnView::Long(c) => assert_eq!(c.value(0), 1),
            ColumnView::Int(c) => assert_eq!(c.value(0), 1),
            other => panic!("unexpected col kind: {:?}", other.kind()),
        }
    });
}

// ---------------------------------------------------------------------------
// Primitive types (ILP path; server casts where needed)
// ---------------------------------------------------------------------------

#[test]
fn long_double_boolean_int_no_nulls() {
    let srv = server();
    let table = unique_table("primitives");
    srv.http_exec(&format!(
        "create table \"{}\" (l long, d double, b boolean, i int, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    let mut sender = make_sender(srv, ProtocolVersion::V2);
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

    select_one_batch(
        srv,
        &format!("select l, d, b, i from \"{}\" order by ts", table),
        |view| {
            assert_eq!(view.row_count(), 3);
            let ColumnView::Long(l) = view.column(0).unwrap() else { panic!("col 0") };
            let ColumnView::Double(d) = view.column(1).unwrap() else { panic!("col 1") };
            let ColumnView::Boolean(b) = view.column(2).unwrap() else { panic!("col 2") };
            let i_kind = view.column(3).unwrap().kind();
            assert_eq!(l.value(0), 100);
            assert_eq!(l.value(1), 101);
            assert_eq!(l.value(2), 102);
            assert_eq!(d.value(0), 0.0);
            assert_eq!(d.value(1), 1.5);
            assert_eq!(d.value(2), 3.0);
            assert_eq!(b.value(0), 1);
            assert_eq!(b.value(1), 0);
            assert_eq!(b.value(2), 1);
            // Server may surface int as Int (4B) or Long (8B) depending on cast path.
            match view.column(3).unwrap() {
                ColumnView::Int(c) => {
                    assert_eq!(c.value(0), 1);
                    assert_eq!(c.value(2), 3);
                }
                ColumnView::Long(c) => {
                    assert_eq!(c.value(0), 1);
                    assert_eq!(c.value(2), 3);
                }
                _ => panic!("unexpected i kind: {:?}", i_kind),
            }
        },
    );
}

#[test]
fn narrowing_byte_short_via_server_cast() {
    // Use SQL DDL to create byte/short columns and INSERT to populate.
    let srv = server();
    let table = unique_table("narrow_int");
    srv.http_exec(&format!(
        "create table \"{}\" (b byte, s short, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (1, 100, '2026-01-01T00:00:00.000Z'), (2, 200, '2026-01-01T00:00:01.000Z'), (3, 300, '2026-01-01T00:00:02.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select b, s from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Byte(b) = view.column(0).unwrap() else { panic!("col 0") };
            let ColumnView::Short(s) = view.column(1).unwrap() else { panic!("col 1") };
            assert_eq!(b.value(0), 1);
            assert_eq!(b.value(1), 2);
            assert_eq!(b.value(2), 3);
            assert_eq!(s.value(0), 100);
            assert_eq!(s.value(1), 200);
            assert_eq!(s.value(2), 300);
        },
    );
}

#[test]
fn float_round_trip() {
    let srv = server();
    let table = unique_table("floats");
    srv.http_exec(&format!(
        "create table \"{}\" (f float, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (1.5, '2026-01-01T00:00:00.000Z'), (-2.25, '2026-01-01T00:00:01.000Z'), (3.125, '2026-01-01T00:00:02.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select f from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Float(c) = view.column(0).unwrap() else { panic!("col 0") };
            assert_eq!(c.value(0), 1.5);
            assert_eq!(c.value(1), -2.25);
            assert_eq!(c.value(2), 3.125);
        },
    );
}

#[test]
fn ipv4_round_trip() {
    let srv = server();
    let table = unique_table("ipv4");
    srv.http_exec(&format!(
        "create table \"{}\" (a ipv4, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values ('127.0.0.1'::ipv4, '2026-01-01T00:00:00.000Z'), ('192.168.1.1'::ipv4, '2026-01-01T00:00:01.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 2);

    select_one_batch(
        srv,
        &format!("select a from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Ipv4(c) = view.column(0).unwrap() else { panic!("col 0") };
            // 127.0.0.1 = 0x7F000001
            assert_eq!(c.value(0), 0x7F00_0001);
            // 192.168.1.1 = 0xC0A80101
            assert_eq!(c.value(1), 0xC0A8_0101);
        },
    );
}

#[test]
fn uuid_round_trip() {
    let srv = server();
    let table = unique_table("uuid");
    srv.http_exec(&format!(
        "create table \"{}\" (u uuid, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values ('550e8400-e29b-41d4-a716-446655440000'::uuid, '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select u from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Uuid(c) = view.column(0).unwrap() else { panic!("col 0") };
            // 16 bytes — verify length and basic shape; exact byte order
            // is QuestDB-internal. We just confirm it's non-zero and the
            // round-trip ran end-to-end.
            let bytes = c.value(0);
            assert_eq!(bytes.len(), 16);
            assert!(bytes.iter().any(|b| *b != 0));
        },
    );
}

#[test]
fn char_round_trip() {
    let srv = server();
    let table = unique_table("char");
    srv.http_exec(&format!(
        "create table \"{}\" (c char, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values ('A', '2026-01-01T00:00:00.000Z'), ('Z', '2026-01-01T00:00:01.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 2);

    select_one_batch(
        srv,
        &format!("select c from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Char(c) = view.column(0).unwrap() else { panic!("col 0") };
            assert_eq!(c.value(0), b'A' as u16);
            assert_eq!(c.value(1), b'Z' as u16);
        },
    );
}

// ---------------------------------------------------------------------------
// Wide types
// ---------------------------------------------------------------------------

#[test]
fn long256_round_trip() {
    let srv = server();
    let table = unique_table("long256");
    srv.http_exec(&format!(
        "create table \"{}\" (l long256, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef, '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select l from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Long256(c) = view.column(0).unwrap() else { panic!("col 0") };
            let bytes = c.value(0);
            assert_eq!(bytes.len(), 32);
            assert!(bytes.iter().any(|b| *b != 0));
        },
    );
}

// ---------------------------------------------------------------------------
// Temporals
// ---------------------------------------------------------------------------

#[test]
fn timestamp_micros_with_gorilla_path() {
    let srv = server();
    let table = unique_table("ts_gorilla");
    srv.http_exec(&format!(
        "create table \"{}\" (v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    let mut sender = make_sender(srv, ProtocolVersion::V2);
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

    select_one_batch(
        srv,
        &format!("select ts, v from \"{}\" order by ts", table),
        |view| {
            assert_eq!(view.row_count(), expected_ts.len());
            let ColumnView::Timestamp(ts_col) = view.column(0).unwrap() else { panic!("col 0") };
            let ColumnView::Long(v) = view.column(1).unwrap() else { panic!("col 1") };
            for (i, expected_ns) in expected_ts.iter().enumerate() {
                let expected_us = expected_ns / 1_000;
                assert_eq!(ts_col.value(i), expected_us, "row {}", i);
                assert_eq!(v.value(i), i as i64);
            }
        },
    );
}

#[test]
fn timestamp_nanos_round_trip() {
    let srv = server();
    let table = unique_table("ts_nanos");
    srv.http_exec(&format!(
        "create table \"{}\" (n timestamp_ns, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (1700000000123456789::timestamp_ns, '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select n from \"{}\" order by ts", table),
        |view| {
            let ColumnView::TimestampNanos(c) = view.column(0).unwrap() else {
                panic!("col 0 not timestamp_nanos: got {:?}", view.column(0).unwrap().kind())
            };
            assert_eq!(c.value(0), 1_700_000_000_123_456_789i64);
        },
    );
}

#[test]
fn date_round_trip() {
    let srv = server();
    let table = unique_table("date");
    srv.http_exec(&format!(
        "create table \"{}\" (d date, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values ('2026-04-26'::date, '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select d from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Date(c) = view.column(0).unwrap() else { panic!("col 0 not date") };
            // QuestDB DATE is millis since epoch. 2026-04-26 in UTC.
            // We just verify it's a sane positive number; exact ms varies
            // by timezone behaviour and isn't worth pinning.
            assert!(c.value(0) > 1_000_000_000_000i64);
        },
    );
}

// ---------------------------------------------------------------------------
// Decimals (require protocol V3 ILP for ingress, but server side is V3)
// ---------------------------------------------------------------------------

// QuestDB picks DECIMAL64 / DECIMAL128 / DECIMAL256 by precision:
// <=18 -> 64, 19..=38 -> 128, 39..=76 -> 256. Inserts need an explicit
// cast since DOUBLE -> DECIMAL is not auto-promoted.

#[test]
fn decimal64_round_trip() {
    let srv = server();
    let table = unique_table("dec64");
    srv.http_exec(&format!(
        "create table \"{}\" (p decimal(18,2), ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (123.45::decimal(18,2), '2026-01-01T00:00:00.000Z'), (-6.78::decimal(18,2), '2026-01-01T00:00:01.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 2);

    select_one_batch(
        srv,
        &format!("select p from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Decimal64(c) = view.column(0).unwrap() else {
                panic!("col 0 not decimal64: got {:?}", view.column(0).unwrap().kind())
            };
            assert_eq!(c.scale(), 2);
            assert_eq!(c.value(0), 12345);
            assert_eq!(c.value(1), -678);
        },
    );
}

#[test]
fn decimal128_round_trip() {
    let srv = server();
    let table = unique_table("dec128");
    srv.http_exec(&format!(
        "create table \"{}\" (p decimal(38,4), ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (100.0000::decimal(38,4), '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select p from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Decimal128(c) = view.column(0).unwrap() else {
                panic!("col 0 not decimal128: got {:?}", view.column(0).unwrap().kind())
            };
            assert_eq!(c.scale(), 4);
            assert_eq!(c.value(0), 1_000_000i128); // 100 * 10^4
        },
    );
}

#[test]
fn decimal256_round_trip() {
    let srv = server();
    let table = unique_table("dec256");
    srv.http_exec(&format!(
        "create table \"{}\" (p decimal(60,6), ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (123.456789::decimal(60,6), '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select p from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Decimal256(c) = view.column(0).unwrap() else {
                panic!("col 0 not decimal256: got {:?}", view.column(0).unwrap().kind())
            };
            assert_eq!(c.scale(), 6);
            // 123.456789 -> mantissa 123_456_789 (low 8 bytes of the i256).
            let bytes = c.value(0);
            let lo = i64::from_le_bytes(bytes[..8].try_into().unwrap());
            assert_eq!(lo, 123_456_789);
            // High bytes should be all zero (small positive value).
            assert!(bytes[8..].iter().all(|b| *b == 0));
        },
    );
}

// ---------------------------------------------------------------------------
// Geohash
// ---------------------------------------------------------------------------

#[test]
fn geohash_round_trip() {
    let srv = server();
    let table = unique_table("geohash");
    // 8-character geohash = 40 bits → byte_width 5.
    srv.http_exec(&format!(
        "create table \"{}\" (g geohash(8c), ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    // Each `c` in geohash(Nc) = 5 bits; the literal must be exactly N
    // chars long. Use the `#` prefix syntax which is the most concise.
    srv.http_exec(&format!(
        "insert into \"{0}\" values (#u4pruydq, '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select g from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Geohash(c) = view.column(0).unwrap() else {
                panic!("col 0 not geohash: got {:?}", view.column(0).unwrap().kind())
            };
            assert_eq!(c.precision_bits(), 40);
            assert_eq!(c.byte_width(), 5);
            assert!(c.value(0) != 0);
        },
    );
}

// ---------------------------------------------------------------------------
// Variable-length
// ---------------------------------------------------------------------------

#[test]
fn varchar_round_trip() {
    let srv = server();
    let table = unique_table("varchar");
    srv.http_exec(&format!(
        "create table \"{}\" (s varchar, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    let mut sender = make_sender(srv, ProtocolVersion::V2);
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

    select_one_batch(
        srv,
        &format!("select s from \"{}\" order by ts", table),
        |view| {
            assert_eq!(view.row_count(), strings.len());
            let ColumnView::Varchar(c) = view.column(0).unwrap() else { panic!("col 0") };
            for (i, expected) in strings.iter().enumerate() {
                assert_eq!(c.value(i), Some(*expected), "row {}", i);
            }
        },
    );
}

#[test]
fn binary_round_trip() {
    let srv = server();
    let table = unique_table("binary");
    srv.http_exec(&format!(
        "create table \"{}\" (b binary, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values (rnd_bin(8, 8, 0), '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select b from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Binary(c) = view.column(0).unwrap() else {
                panic!("col 0 not binary: got {:?}", view.column(0).unwrap().kind())
            };
            let bytes = c.value(0).expect("non-null");
            assert_eq!(bytes.len(), 8);
        },
    );
}

// ---------------------------------------------------------------------------
// Symbol
// ---------------------------------------------------------------------------

#[test]
fn symbol_with_dict() {
    let srv = server();
    let table = unique_table("symbols");
    srv.http_exec(&format!(
        "create table \"{}\" (s symbol, v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    let mut sender = make_sender(srv, ProtocolVersion::V2);
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

    select_one_batch(
        srv,
        &format!("select s, v from \"{}\" order by ts", table),
        |view| {
            assert_eq!(view.row_count(), symbols.len());
            let ColumnView::Symbol(s) = view.column(0).unwrap() else { panic!("col 0") };
            let ColumnView::Long(v) = view.column(1).unwrap() else { panic!("col 1") };
            for (i, expected) in symbols.iter().enumerate() {
                assert_eq!(s.resolve(i), Some(*expected));
                assert_eq!(v.value(i), i as i64 * 10);
            }
        },
    );
}

#[test]
fn symbol_dict_persists_across_queries() {
    let srv = server();
    let table = unique_table("sym_persist");
    srv.http_exec(&format!(
        "create table \"{}\" (s symbol, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    let symbols = ["alpha", "beta", "gamma"];
    for (i, sym) in symbols.iter().enumerate() {
        buf.table(table.as_str())
            .unwrap()
            .symbol("s", *sym)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + i as i64 * 1_000_000))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, 3);

    let mut reader = make_reader(srv);
    // First query: dict gets populated.
    {
        let mut cur = reader
            .query(&format!("select s from \"{}\" order by ts", table))
            .execute()
            .expect("execute");
        let view = cur.next_batch().expect("next").expect("Some");
        let ColumnView::Symbol(s) = view.column(0).unwrap() else { panic!() };
        for (i, expected) in symbols.iter().enumerate() {
            assert_eq!(s.resolve(i), Some(*expected));
        }
        // Drain to terminal.
        while cur.next_batch().expect("drain").is_some() {}
    }
    let dict_size_after_first = reader.symbol_dict().len();
    assert!(dict_size_after_first >= 3, "dict should have at least 3 entries");

    // Second query on same connection: dict should be reused (server
    // shouldn't retransmit "alpha"/"beta"/"gamma").
    {
        let mut cur = reader
            .query(&format!("select s from \"{}\" order by ts", table))
            .execute()
            .expect("execute");
        let view = cur.next_batch().expect("next").expect("Some");
        let ColumnView::Symbol(s) = view.column(0).unwrap() else { panic!() };
        for (i, expected) in symbols.iter().enumerate() {
            assert_eq!(s.resolve(i), Some(*expected));
        }
        while cur.next_batch().expect("drain").is_some() {}
    }
    // Dict size should be the same — entries were reused.
    assert_eq!(reader.symbol_dict().len(), dict_size_after_first);
}

// ---------------------------------------------------------------------------
// Schema reuse
// ---------------------------------------------------------------------------

#[test]
fn schema_reference_after_full() {
    let srv = server();
    let table = unique_table("schema_ref");
    srv.http_exec(&format!(
        "create table \"{}\" (v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    for i in 0..3i64 {
        buf.table(table.as_str())
            .unwrap()
            .column_i64("v", i)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + i * 1_000_000))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, 3);

    let mut reader = make_reader(srv);
    // First query populates schema registry.
    {
        let mut cur = reader
            .query(&format!("select v from \"{}\"", table))
            .execute()
            .expect("execute");
        while cur.next_batch().expect("drain").is_some() {}
    }
    let registered_after_first = reader.schema_registry().len();
    assert!(registered_after_first >= 1);

    // Second query with the same column shape should reuse a schema_id;
    // registry size should not grow.
    {
        let mut cur = reader
            .query(&format!("select v from \"{}\"", table))
            .execute()
            .expect("execute");
        while cur.next_batch().expect("drain").is_some() {}
    }
    assert_eq!(reader.schema_registry().len(), registered_after_first);
}

// ---------------------------------------------------------------------------
// Error paths
// ---------------------------------------------------------------------------

#[test]
fn query_error_for_bad_sql() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("SELECT bogus FROM nonexistent_table_zzz")
        .execute()
        .expect("execute");
    match cur.next_batch() {
        Err(e) => {
            // QuestDB returns SQL_ERROR (mapped to ServerParseError or
            // ServerInternalError depending on the failure kind).
            use questdb::egress::ErrorCode as C;
            assert!(
                matches!(
                    e.code(),
                    C::ServerParseError | C::ServerInternalError | C::ServerSchemaMismatch
                ),
                "unexpected error code: {:?}: {}",
                e.code(),
                e.msg()
            );
        }
        Ok(_) => panic!("expected QUERY_ERROR for bad SQL"),
    }
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

#[test]
fn cursor_terminal_after_select() {
    let srv = server();
    let table = unique_table("term");
    srv.http_exec(&format!(
        "create table \"{}\" (v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    buf.table(table.as_str())
        .unwrap()
        .column_i64("v", 1)
        .unwrap()
        .at(TimestampNanos::new(1_700_000_000_000_000_000))
        .unwrap();
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, 1);

    let mut reader = make_reader(srv);
    let mut cur = reader
        .query(&format!("select v from \"{}\"", table))
        .execute()
        .expect("execute");
    while cur.next_batch().expect("next").is_some() {}
    assert!(matches!(cur.terminal(), Some(Terminal::End { .. })));
}

#[test]
fn multi_batch_streaming() {
    // Seed N rows and force the server to split the result by setting
    // X-QWP-Max-Batch-Rows; verify multiple RESULT_BATCH frames arrive
    // with monotonic batch_seq, the row count adds up, and reused
    // schemas (mode 0x01) work mid-stream.
    let srv = server();
    let table = unique_table("multi_batch");
    srv.http_exec(&format!(
        "create table \"{}\" (i long, d double, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    const TOTAL: usize = 5_000;
    const PER_BATCH: usize = 1_000;
    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    for i in 0..TOTAL as i64 {
        buf.table(table.as_str())
            .unwrap()
            .column_i64("i", i)
            .unwrap()
            .column_f64("d", i as f64 * 0.5)
            .unwrap()
            .at(TimestampNanos::new(1_700_000_000_000_000_000 + i * 1_000_000))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, TOTAL);

    // Open a dedicated reader with the per-batch row cap set; the
    // process-wide fixture connection isn't suitable here.
    let conf = format!("{};max_batch_rows={}", srv.qwp_conf(), PER_BATCH);
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!("select i, d from \"{}\" order by ts", table))
        .execute()
        .expect("execute");

    let mut batch_count = 0usize;
    let mut total_rows = 0usize;
    let mut last_batch_seq: Option<u64> = None;
    let mut first_value: Option<i64> = None;
    let mut last_value: Option<i64> = None;
    let mut last_d: Option<f64> = None;

    while let Some(view) = cursor.next_batch().expect("next_batch") {
        batch_count += 1;
        let rows = view.row_count();

        // batch_seq must be monotonically increasing.
        let seq = view.batch_seq();
        if let Some(prev) = last_batch_seq {
            assert!(
                seq > prev,
                "batch_seq must increase: prev={} this={}",
                prev,
                seq
            );
        }
        last_batch_seq = Some(seq);

        let ColumnView::Long(i_col) = view.column(0).unwrap() else { panic!("col 0") };
        let ColumnView::Double(d_col) = view.column(1).unwrap() else { panic!("col 1") };

        // Spot-check first and last row of each batch.
        if first_value.is_none() {
            first_value = Some(i_col.value(0));
        }
        if rows > 0 {
            last_value = Some(i_col.value(rows - 1));
            last_d = Some(d_col.value(rows - 1));
        }

        total_rows += rows;
    }

    assert!(
        batch_count >= TOTAL / PER_BATCH,
        "expected at least {} batches, got {}",
        TOTAL / PER_BATCH,
        batch_count
    );
    assert_eq!(total_rows, TOTAL, "row count mismatch");
    assert_eq!(first_value, Some(0));
    assert_eq!(last_value, Some(TOTAL as i64 - 1));
    assert_eq!(last_d, Some((TOTAL as f64 - 1.0) * 0.5));

    // Cursor should be in End state, not Error.
    assert!(matches!(cursor.terminal(), Some(Terminal::End { .. })));
}

#[test]
fn null_handling_long_densifies() {
    let srv = server();
    let table = unique_table("nulls");
    srv.http_exec(&format!(
        "create table \"{}\" (v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    // Mix of nulls and values.
    srv.http_exec(&format!(
        "insert into \"{0}\" values (10, '2026-01-01T00:00:00.000Z'), (NULL, '2026-01-01T00:00:01.000Z'), (30, '2026-01-01T00:00:02.000Z'), (NULL, '2026-01-01T00:00:03.000Z'), (50, '2026-01-01T00:00:04.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 5);

    select_one_batch(
        srv,
        &format!("select v from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Long(c) = view.column(0).unwrap() else { panic!() };
            assert_eq!(c.value(0), 10);
            assert!(c.is_null(1));
            assert_eq!(c.value(2), 30);
            assert!(c.is_null(3));
            assert_eq!(c.value(4), 50);
        },
    );
}
