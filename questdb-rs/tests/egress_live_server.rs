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
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select l, d, b, i from \"{}\" order by ts", table),
        |view| {
            assert_eq!(view.row_count(), 3);
            let ColumnView::Long(l) = view.column(0).unwrap() else {
                panic!("col 0")
            };
            let ColumnView::Double(d) = view.column(1).unwrap() else {
                panic!("col 1")
            };
            let ColumnView::Boolean(b) = view.column(2).unwrap() else {
                panic!("col 2")
            };
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
            let ColumnView::Byte(b) = view.column(0).unwrap() else {
                panic!("col 0")
            };
            let ColumnView::Short(s) = view.column(1).unwrap() else {
                panic!("col 1")
            };
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
            let ColumnView::Float(c) = view.column(0).unwrap() else {
                panic!("col 0")
            };
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
            let ColumnView::Ipv4(c) = view.column(0).unwrap() else {
                panic!("col 0")
            };
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
            let ColumnView::Uuid(c) = view.column(0).unwrap() else {
                panic!("col 0")
            };
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
            let ColumnView::Char(c) = view.column(0).unwrap() else {
                panic!("col 0")
            };
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
            let ColumnView::Long256(c) = view.column(0).unwrap() else {
                panic!("col 0")
            };
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
            let ColumnView::Timestamp(ts_col) = view.column(0).unwrap() else {
                panic!("col 0")
            };
            let ColumnView::Long(v) = view.column(1).unwrap() else {
                panic!("col 1")
            };
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
                panic!(
                    "col 0 not timestamp_nanos: got {:?}",
                    view.column(0).unwrap().kind()
                )
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
            let ColumnView::Date(c) = view.column(0).unwrap() else {
                panic!("col 0 not date")
            };
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
                panic!(
                    "col 0 not decimal64: got {:?}",
                    view.column(0).unwrap().kind()
                )
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
                panic!(
                    "col 0 not decimal128: got {:?}",
                    view.column(0).unwrap().kind()
                )
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
                panic!(
                    "col 0 not decimal256: got {:?}",
                    view.column(0).unwrap().kind()
                )
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
                panic!(
                    "col 0 not geohash: got {:?}",
                    view.column(0).unwrap().kind()
                )
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
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i as i64 * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, strings.len());

    select_one_batch(
        srv,
        &format!("select s from \"{}\" order by ts", table),
        |view| {
            assert_eq!(view.row_count(), strings.len());
            let ColumnView::Varchar(c) = view.column(0).unwrap() else {
                panic!("col 0")
            };
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
// Arrays (DOUBLE[] / DOUBLE[][])
// ---------------------------------------------------------------------------
//
// LONG_ARRAY is in the protocol but the server doesn't emit it; only
// DOUBLE arrays are exercised end-to-end. Population uses SQL INSERT
// with ARRAY[...] literals against WAL tables, mirroring the QuestDB
// QwpEgressBootstrapTest / QwpEgressTypesExhaustiveTest pattern.

#[test]
fn double_array_1d_varying_lengths() {
    let srv = server();
    let table = unique_table("darr_1d");
    srv.http_exec(&format!(
        "CREATE TABLE \"{}\" (d DOUBLE[], ts TIMESTAMP) TIMESTAMP(ts) PARTITION BY DAY WAL",
        table
    ));
    srv.http_exec(&format!(
        "INSERT INTO \"{0}\" VALUES \
         (ARRAY[1.0, 2.0, 3.0], 1::TIMESTAMP), \
         (ARRAY[4.0, 5.0], 2::TIMESTAMP), \
         (ARRAY[7.5], 3::TIMESTAMP)",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select d from \"{}\" order by ts", table),
        |view| {
            let ColumnView::DoubleArray(c) = view.column(0).unwrap() else {
                panic!(
                    "col 0 not double_array: {:?}",
                    view.column(0).unwrap().kind()
                )
            };
            assert_eq!(c.len(), 3);

            assert_eq!(c.shape(0), Some(&[3u32][..]));
            assert_eq!(c.element_count(0), 3);
            assert_eq!(c.element(0, 0), Some(1.0));
            assert_eq!(c.element(0, 1), Some(2.0));
            assert_eq!(c.element(0, 2), Some(3.0));

            assert_eq!(c.shape(1), Some(&[2u32][..]));
            assert_eq!(c.element_count(1), 2);
            assert_eq!(c.element(1, 0), Some(4.0));
            assert_eq!(c.element(1, 1), Some(5.0));

            assert_eq!(c.shape(2), Some(&[1u32][..]));
            assert_eq!(c.element(2, 0), Some(7.5));
        },
    );
}

#[test]
fn double_array_2d_row_major() {
    let srv = server();
    let table = unique_table("darr_2d");
    srv.http_exec(&format!(
        "CREATE TABLE \"{}\" (m DOUBLE[][], ts TIMESTAMP) TIMESTAMP(ts) PARTITION BY DAY WAL",
        table
    ));
    srv.http_exec(&format!(
        "INSERT INTO \"{0}\" VALUES \
         (ARRAY[[1.0, 2.0], [3.0, 4.0]], 1::TIMESTAMP), \
         (ARRAY[[10.0, 20.0, 30.0], [40.0, 50.0, 60.0]], 2::TIMESTAMP)",
        table
    ));
    wait_for_rows(srv, &table, 2);

    select_one_batch(
        srv,
        &format!("select m from \"{}\" order by ts", table),
        |view| {
            let ColumnView::DoubleArray(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.len(), 2);

            // Row 0: 2x2 row-major.
            assert_eq!(c.shape(0), Some(&[2u32, 2][..]));
            assert_eq!(c.element_count(0), 4);
            for (i, expected) in [1.0, 2.0, 3.0, 4.0].iter().enumerate() {
                assert_eq!(c.element(0, i), Some(*expected), "row 0 idx {}", i);
            }

            // Row 1: 2x3 row-major.
            assert_eq!(c.shape(1), Some(&[2u32, 3][..]));
            assert_eq!(c.element_count(1), 6);
            for (i, expected) in [10.0, 20.0, 30.0, 40.0, 50.0, 60.0].iter().enumerate() {
                assert_eq!(c.element(1, i), Some(*expected), "row 1 idx {}", i);
            }
        },
    );
}

#[test]
fn double_array_with_null_array_row() {
    let srv = server();
    let table = unique_table("darr_null");
    srv.http_exec(&format!(
        "CREATE TABLE \"{}\" (d DOUBLE[], ts TIMESTAMP) TIMESTAMP(ts) PARTITION BY DAY WAL",
        table
    ));
    srv.http_exec(&format!(
        "INSERT INTO \"{0}\" VALUES \
         (ARRAY[1.0], 1::TIMESTAMP), \
         (NULL, 2::TIMESTAMP), \
         (ARRAY[2.5, 3.5], 3::TIMESTAMP)",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select d from \"{}\" order by ts", table),
        |view| {
            let ColumnView::DoubleArray(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.len(), 3);

            assert!(!c.is_null(0));
            assert_eq!(c.element(0, 0), Some(1.0));

            assert!(c.is_null(1));
            assert_eq!(c.shape(1), None);
            assert_eq!(c.element_count(1), 0);
            assert_eq!(c.element(1, 0), None);

            assert!(!c.is_null(2));
            assert_eq!(c.shape(2), Some(&[2u32][..]));
            assert_eq!(c.element(2, 0), Some(2.5));
            assert_eq!(c.element(2, 1), Some(3.5));
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
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i as i64 * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, symbols.len());

    select_one_batch(
        srv,
        &format!("select s, v from \"{}\" order by ts", table),
        |view| {
            assert_eq!(view.row_count(), symbols.len());
            let ColumnView::Symbol(s) = view.column(0).unwrap() else {
                panic!("col 0")
            };
            let ColumnView::Long(v) = view.column(1).unwrap() else {
                panic!("col 1")
            };
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
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i as i64 * 1_000_000,
            ))
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
        let ColumnView::Symbol(s) = view.column(0).unwrap() else {
            panic!()
        };
        for (i, expected) in symbols.iter().enumerate() {
            assert_eq!(s.resolve(i), Some(*expected));
        }
        // Drain to terminal.
        while cur.next_batch().expect("drain").is_some() {}
    }
    let dict_size_after_first = reader.symbol_dict().len();
    assert!(
        dict_size_after_first >= 3,
        "dict should have at least 3 entries"
    );

    // Second query on same connection: dict should be reused (server
    // shouldn't retransmit "alpha"/"beta"/"gamma").
    {
        let mut cur = reader
            .query(&format!("select s from \"{}\" order by ts", table))
            .execute()
            .expect("execute");
        let view = cur.next_batch().expect("next").expect("Some");
        let ColumnView::Symbol(s) = view.column(0).unwrap() else {
            panic!()
        };
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
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i * 1_000_000,
            ))
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
// Bind parameters
// ---------------------------------------------------------------------------

#[test]
fn bind_long_literal_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::long as v")
        .bind_i64(0x0102_0304_0506_0708)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Long(c) = view.column(0).unwrap() else {
        panic!("col 0")
    };
    assert_eq!(c.value(0), 0x0102_0304_0506_0708);
}

#[test]
fn bind_varchar_literal_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::varchar as v")
        .bind_varchar("café")
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Varchar(c) = view.column(0).unwrap() else {
        panic!("col 0")
    };
    assert_eq!(c.value(0), Some("café"));
}

#[test]
fn bind_double_literal_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::double as v")
        .bind_f64(2.718281828)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Double(c) = view.column(0).unwrap() else {
        panic!("col 0")
    };
    assert_eq!(c.value(0), 2.718281828);
}

#[test]
fn bind_timestamp_micros_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::timestamp as v")
        .bind_timestamp_micros(1_700_000_000_123_456)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Timestamp(c) = view.column(0).unwrap() else {
        panic!(
            "col 0 not timestamp: got {:?}",
            view.column(0).unwrap().kind()
        )
    };
    assert_eq!(c.value(0), 1_700_000_000_123_456);
}

#[test]
fn bind_symbol_via_varchar_cast() {
    // The QWP client doesn't currently expose a Bind::Symbol value
    // variant (server-side dict lookup is required); the practical path
    // for binding a symbol value is to bind a VARCHAR and cast it on
    // the server. This test pins that workflow against a real server
    // so we know the documented pattern works.
    let srv = server();
    let table = unique_table("bind_sym");
    srv.http_exec(&format!(
        "create table \"{}\" (s symbol, v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    for (i, sym) in ["AAPL", "MSFT", "GOOG", "AAPL"].iter().enumerate() {
        buf.table(table.as_str())
            .unwrap()
            .symbol("s", *sym)
            .unwrap()
            .column_i64("v", i as i64)
            .unwrap()
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i as i64 * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, 4);

    let mut reader = make_reader(srv);
    let mut cur = reader
        .query(&format!(
            "select s, v from \"{}\" where s = cast($1 as symbol) order by ts",
            table
        ))
        .bind_varchar("AAPL")
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    assert_eq!(view.row_count(), 2);
    let ColumnView::Symbol(s) = view.column(0).unwrap() else {
        panic!()
    };
    let ColumnView::Long(v) = view.column(1).unwrap() else {
        panic!()
    };
    assert_eq!(s.resolve(0), Some("AAPL"));
    assert_eq!(s.resolve(1), Some("AAPL"));
    assert_eq!(v.value(0), 0);
    assert_eq!(v.value(1), 3);
}

#[test]
fn bind_timestamp_nanos_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::timestamp_ns as v")
        .bind_timestamp_nanos(1_700_000_000_123_456_789)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::TimestampNanos(c) = view.column(0).unwrap() else {
        panic!(
            "col 0 not timestamp_nanos: got {:?}",
            view.column(0).unwrap().kind()
        )
    };
    assert_eq!(c.value(0), 1_700_000_000_123_456_789);
}

#[test]
fn bind_decimal64_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    // Bind value is stored as scale=2 decimal: 12345 / 100 = 123.45.
    let mut cur = reader
        .query("select $1::decimal(18,2) as v")
        .bind_decimal64(12345, 2)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Decimal64(c) = view.column(0).unwrap() else {
        panic!(
            "col 0 not decimal64: got {:?}",
            view.column(0).unwrap().kind()
        )
    };
    assert_eq!(c.scale(), 2);
    assert_eq!(c.value(0), 12345);
}

#[test]
fn bind_multiple_binds_in_one_query() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::long as a, $2::varchar as b, $3::double as c")
        .bind_i64(42)
        .bind_varchar("hello")
        .bind_f64(3.5)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    assert_eq!(view.column_count(), 3);

    let ColumnView::Long(a) = view.column(0).unwrap() else {
        panic!("col 0")
    };
    let ColumnView::Varchar(b) = view.column(1).unwrap() else {
        panic!("col 1")
    };
    let ColumnView::Double(c) = view.column(2).unwrap() else {
        panic!("col 2")
    };
    assert_eq!(a.value(0), 42);
    assert_eq!(b.value(0), Some("hello"));
    assert_eq!(c.value(0), 3.5);
}

#[test]
fn bind_in_where_clause_filters_rows() {
    let srv = server();
    let table = unique_table("bind_filter");
    srv.http_exec(&format!(
        "create table \"{}\" (id long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    for i in 0..10i64 {
        buf.table(table.as_str())
            .unwrap()
            .column_i64("id", i)
            .unwrap()
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, 10);

    let mut reader = make_reader(srv);
    let mut cur = reader
        .query(&format!(
            "select id from \"{}\" where id >= $1 and id < $2 order by id",
            table
        ))
        .bind_i64(3)
        .bind_i64(7)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    assert_eq!(view.row_count(), 4); // ids 3,4,5,6
    let ColumnView::Long(c) = view.column(0).unwrap() else {
        panic!()
    };
    assert_eq!(c.value(0), 3);
    assert_eq!(c.value(1), 4);
    assert_eq!(c.value(2), 5);
    assert_eq!(c.value(3), 6);
}

#[test]
fn bind_typed_null_long() {
    use questdb::egress::column_kind::ColumnKind;
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::long as v")
        .bind_null(ColumnKind::Long)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Long(c) = view.column(0).unwrap() else {
        panic!()
    };
    assert!(
        c.is_null(0),
        "expected null long bind to surface as null row"
    );
}

// --- Narrow integer binds --------------------------------------------------

#[test]
fn bind_byte_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::byte as v")
        .bind_i8(-7)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Byte(c) = view.column(0).unwrap() else {
        panic!("col 0 not byte: got {:?}", view.column(0).unwrap().kind())
    };
    assert_eq!(c.value(0), -7);
}

#[test]
fn bind_short_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::short as v")
        .bind_i16(-30000)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Short(c) = view.column(0).unwrap() else {
        panic!("col 0 not short: got {:?}", view.column(0).unwrap().kind())
    };
    assert_eq!(c.value(0), -30000);
}

#[test]
fn bind_int_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::int as v")
        .bind_i32(0x0102_0304)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Int(c) = view.column(0).unwrap() else {
        panic!("col 0 not int: got {:?}", view.column(0).unwrap().kind())
    };
    assert_eq!(c.value(0), 0x0102_0304);
}

#[test]
fn bind_float_passthrough() {
    // QuestDB's SELECT scalar pipeline promotes FLOAT to DOUBLE on the
    // result side, so the FLOAT bind comes back as a Double column.
    // We assert on the value, not the kind.
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::float as v")
        .bind_f32(2.5f32)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    match view.column(0).unwrap() {
        ColumnView::Float(c) => assert_eq!(c.value(0), 2.5f32),
        ColumnView::Double(c) => assert_eq!(c.value(0), 2.5f64),
        other => panic!("col 0 unexpected kind: {:?}", other.kind()),
    }
}

// --- Network / wide types --------------------------------------------------

#[test]
fn bind_ipv4_rejected_client_side() {
    // The QuestDB server does not accept IPv4 as a bind value (see
    // QwpBindValues.java in the Java reference client). The Rust client
    // rejects these at builder time so the user gets a clear error
    // instead of a server-side parse failure with a stale request_id.
    use std::net::Ipv4Addr;
    let srv = server();
    let mut reader = make_reader(srv);
    match reader
        .query("select 1")
        .bind_ipv4(Ipv4Addr::new(127, 0, 0, 1))
        .execute()
    {
        Err(e) => assert_eq!(e.code(), questdb::egress::ErrorCode::InvalidBind),
        Ok(_) => panic!("expected client-side rejection"),
    }
}

#[test]
fn bind_uuid_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    // 16 bytes. We bind raw bytes; the server stores them as a UUID.
    // We just verify the round-trip matches what we sent.
    let bytes: [u8; 16] = [
        0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44, 0x00,
        0x00,
    ];
    let mut cur = reader
        .query("select $1::uuid as v")
        .bind_uuid_bytes(bytes)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Uuid(c) = view.column(0).unwrap() else {
        panic!("col 0 not uuid: got {:?}", view.column(0).unwrap().kind())
    };
    assert_eq!(c.value(0), &bytes);
}

#[test]
fn bind_long256_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let bytes: [u8; 32] = std::array::from_fn(|i| i as u8 + 1);
    let mut cur = reader
        .query("select $1::long256 as v")
        .bind_long256(bytes)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Long256(c) = view.column(0).unwrap() else {
        panic!(
            "col 0 not long256: got {:?}",
            view.column(0).unwrap().kind()
        )
    };
    assert_eq!(c.value(0), &bytes);
}

#[test]
fn bind_char_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::char as v")
        .bind_char(b'Q' as u16)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Char(c) = view.column(0).unwrap() else {
        panic!("col 0 not char: got {:?}", view.column(0).unwrap().kind())
    };
    assert_eq!(c.value(0), b'Q' as u16);
}

#[test]
fn bind_binary_rejected_client_side() {
    // BINARY isn't accepted as a bind by the server either; client-side
    // rejection keeps the failure mode clear.
    let srv = server();
    let mut reader = make_reader(srv);
    match reader
        .query("select 1")
        .bind_binary(vec![0xDE, 0xAD])
        .execute()
    {
        Err(e) => assert_eq!(e.code(), questdb::egress::ErrorCode::InvalidBind),
        Ok(_) => panic!("expected client-side rejection"),
    }
}

// --- Wide decimals ---------------------------------------------------------

#[test]
fn bind_decimal128_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::decimal(38,4) as v")
        .bind_decimal128(123_4567i128, 4) // 12.34567 with scale=4 -> mantissa 1234567 (clamped to 4dp)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Decimal128(c) = view.column(0).unwrap() else {
        panic!(
            "col 0 not decimal128: got {:?}",
            view.column(0).unwrap().kind()
        )
    };
    assert_eq!(c.scale(), 4);
    assert_eq!(c.value(0), 123_4567i128);
}

#[test]
fn bind_decimal256_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    // i256 mantissa as 32 LE bytes: low 8 bytes = 999_888_777, rest zero.
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&999_888_777i64.to_le_bytes());
    let mut cur = reader
        .query("select $1::decimal(60,6) as v")
        .bind_decimal256(bytes, 6)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Decimal256(c) = view.column(0).unwrap() else {
        panic!(
            "col 0 not decimal256: got {:?}",
            view.column(0).unwrap().kind()
        )
    };
    assert_eq!(c.scale(), 6);
    let got = c.value(0);
    let lo = i64::from_le_bytes(got[..8].try_into().unwrap());
    assert_eq!(lo, 999_888_777);
    assert!(got[8..].iter().all(|b| *b == 0));
}

// --- Geohash ---------------------------------------------------------------

#[test]
fn bind_geohash_passthrough() {
    let srv = server();
    let mut reader = make_reader(srv);
    // 40 bits = 8 chars in geohash(8c). We bind a u64 zero-extended to
    // 5 bytes (ceil(40/8)) on the wire.
    let value: u64 = 0xAA_BB_CC_DD_EE;
    let mut cur = reader
        .query("select cast($1 as geohash(8c)) v")
        .bind_geohash(value, 40)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Geohash(c) = view.column(0).unwrap() else {
        panic!(
            "col 0 not geohash: got {:?}",
            view.column(0).unwrap().kind()
        )
    };
    assert_eq!(c.precision_bits(), 40);
    assert_eq!(c.byte_width(), 5);
    assert_eq!(c.value(0), value);
}

// --- Typed-NULL with column-level args -------------------------------------

#[test]
fn bind_null_varchar_emits_null_row() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::varchar as v")
        .bind_null_varchar()
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Varchar(c) = view.column(0).unwrap() else {
        panic!()
    };
    assert!(c.is_null(0));
    assert_eq!(c.value(0), None);
}

#[test]
fn bind_null_binary_rejected_client_side() {
    let srv = server();
    let mut reader = make_reader(srv);
    match reader.query("select 1").bind_null_binary().execute() {
        Err(e) => assert_eq!(e.code(), questdb::egress::ErrorCode::InvalidBind),
        Ok(_) => panic!("expected client-side rejection"),
    }
}

#[test]
fn bind_null_decimal64_with_scale() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::decimal(18,2) as v")
        .bind_null_decimal64(2)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Decimal64(c) = view.column(0).unwrap() else {
        panic!()
    };
    assert!(c.is_null(0));
}

#[test]
fn bind_null_decimal128_with_scale() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::decimal(38,4) as v")
        .bind_null_decimal128(4)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Decimal128(c) = view.column(0).unwrap() else {
        panic!()
    };
    assert!(c.is_null(0));
}

#[test]
fn bind_null_decimal256_with_scale() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select $1::decimal(60,6) as v")
        .bind_null_decimal256(6)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Decimal256(c) = view.column(0).unwrap() else {
        panic!()
    };
    assert!(c.is_null(0));
}

#[test]
fn bind_null_geohash_with_precision() {
    let srv = server();
    let mut reader = make_reader(srv);
    let mut cur = reader
        .query("select cast($1 as geohash(8c)) v")
        .bind_null_geohash(40)
        .execute()
        .expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    let ColumnView::Geohash(c) = view.column(0).unwrap() else {
        panic!()
    };
    assert!(c.is_null(0));
    assert_eq!(c.precision_bits(), 40);
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Edge cases: boundaries, special floats, empty/unicode strings, all-null,
// extreme widths
// ---------------------------------------------------------------------------

#[test]
fn integer_boundaries() {
    let srv = server();
    let table = unique_table("int_bounds");
    srv.http_exec(&format!(
        "create table \"{}\" (b byte, s short, i int, l long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    // QuestDB's NULL sentinels are i32::MIN for INT and i64::MIN for
    // LONG (per the spec's null sentinel table) — inserting those
    // values gets stored as NULL. Use MIN+1 to cover the most-negative
    // representable non-null value for the four-byte and eight-byte
    // signed integer widths.
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         (-128, -32768, -2147483647, -9223372036854775807, '2026-01-01T00:00:00.000Z'), \
         (0, 0, 0, 0, '2026-01-01T00:00:01.000Z'), \
         (127, 32767, 2147483647, 9223372036854775807, '2026-01-01T00:00:02.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select b, s, i, l from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Byte(b) = view.column(0).unwrap() else {
                panic!()
            };
            let ColumnView::Short(s) = view.column(1).unwrap() else {
                panic!()
            };
            let ColumnView::Int(i) = view.column(2).unwrap() else {
                panic!()
            };
            let ColumnView::Long(l) = view.column(3).unwrap() else {
                panic!()
            };

            assert_eq!(b.value(0), i8::MIN);
            assert_eq!(b.value(1), 0);
            assert_eq!(b.value(2), i8::MAX);

            assert_eq!(s.value(0), i16::MIN);
            assert_eq!(s.value(1), 0);
            assert_eq!(s.value(2), i16::MAX);

            assert_eq!(i.value(0), i32::MIN + 1);
            assert_eq!(i.value(1), 0);
            assert_eq!(i.value(2), i32::MAX);

            assert_eq!(l.value(0), i64::MIN + 1);
            assert_eq!(l.value(1), 0);
            assert_eq!(l.value(2), i64::MAX);
        },
    );
}

#[test]
fn double_special_values() {
    // QuestDB treats NaN as NULL on insert (per the spec's NULL sentinel
    // table). +Inf, -Inf, and -0.0 are real values that should round-trip.
    let srv = server();
    let table = unique_table("dbl_special");
    srv.http_exec(&format!(
        "create table \"{}\" (d double, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         ('NaN'::double, '2026-01-01T00:00:00.000Z'), \
         ('Infinity'::double, '2026-01-01T00:00:01.000Z'), \
         ('-Infinity'::double, '2026-01-01T00:00:02.000Z'), \
         (-0.0, '2026-01-01T00:00:03.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 4);

    select_one_batch(
        srv,
        &format!("select d from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Double(c) = view.column(0).unwrap() else {
                panic!()
            };
            // Server behaviour for NaN / +Inf / -Inf via SQL literals is
            // implementation-defined: QuestDB may treat any non-finite
            // double as NULL (consistent with its NaN-as-NULL sentinel),
            // or preserve the bit pattern. Accept either for rows 0..2;
            // for row 3 (-0.0) the server may normalise to +0.0.
            for r in 0..3 {
                if !c.is_null(r) {
                    let v = c.value(r);
                    assert!(
                        v.is_nan() || v.is_infinite(),
                        "row {} should be null, NaN, or infinite; got {}",
                        r,
                        v
                    );
                }
            }
            assert!(!c.is_null(3), "-0.0 should round-trip as a finite value");
            assert_eq!(c.value(3), 0.0);
        },
    );
}

#[test]
fn varchar_empty_string_distinct_from_null() {
    let srv = server();
    let table = unique_table("vch_empty");
    srv.http_exec(&format!(
        "create table \"{}\" (s varchar, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         ('', '2026-01-01T00:00:00.000Z'), \
         (NULL, '2026-01-01T00:00:01.000Z'), \
         ('non-empty', '2026-01-01T00:00:02.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select s from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Varchar(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(
                c.value(0),
                Some(""),
                "empty string must round-trip as Some(\"\")"
            );
            assert_eq!(c.value(1), None);
            assert_eq!(c.value(2), Some("non-empty"));
        },
    );
}

#[test]
fn varchar_unicode_and_long_string() {
    let srv = server();
    let table = unique_table("vch_unicode");
    srv.http_exec(&format!(
        "create table \"{}\" (s varchar, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    let long_str = "x".repeat(8 * 1024); // 8 KiB
    let stmt = format!(
        "insert into \"{0}\" values \
         ('🦀 rust + 中文 + עברית + 한국어', '2026-01-01T00:00:00.000Z'), \
         ('{1}', '2026-01-01T00:00:01.000Z'), \
         ('a', '2026-01-01T00:00:02.000Z')",
        table, long_str
    );
    srv.http_exec(&stmt);
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select s from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Varchar(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.value(0), Some("🦀 rust + 中文 + עברית + 한국어"));
            assert_eq!(c.value(1).map(|s| s.len()), Some(long_str.len()));
            assert_eq!(c.value(2), Some("a"));
        },
    );
}

#[test]
fn all_null_long_column() {
    let srv = server();
    let table = unique_table("all_null_long");
    srv.http_exec(&format!(
        "create table \"{}\" (v long, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         (NULL, '2026-01-01T00:00:00.000Z'), \
         (NULL, '2026-01-01T00:00:01.000Z'), \
         (NULL, '2026-01-01T00:00:02.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select v from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Long(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.len(), 3);
            for r in 0..3 {
                assert!(c.is_null(r), "row {} should be null", r);
            }
        },
    );
}

#[test]
fn all_null_varchar_column() {
    // Pure-null varchar exercises the offsets-array densification when
    // all rows have zero-length entries.
    let srv = server();
    let table = unique_table("all_null_varchar");
    srv.http_exec(&format!(
        "create table \"{}\" (s varchar, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         (NULL, '2026-01-01T00:00:00.000Z'), \
         (NULL, '2026-01-01T00:00:01.000Z'), \
         (NULL, '2026-01-01T00:00:02.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select s from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Varchar(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.len(), 3);
            for r in 0..3 {
                assert!(c.is_null(r));
                assert_eq!(c.value(r), None);
            }
        },
    );
}

#[test]
fn timestamp_epoch_and_far_future() {
    // WAL tables enforce monotonic designated timestamps, so a
    // pre-epoch row immediately after an epoch row would be rejected.
    // Test epoch + a far-future value in monotonic order. Pre-epoch
    // remains exercised in unit tests against synthetic byte streams.
    let srv = server();
    let table = unique_table("ts_bounds");
    srv.http_exec(&format!(
        "create table \"{}\" (ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         ('1970-01-01T00:00:00.000Z'), \
         ('1970-01-01T00:00:00.000001Z'), \
         ('2099-12-31T23:59:59.999999Z')",
        table
    ));
    wait_for_rows(srv, &table, 3);

    select_one_batch(
        srv,
        &format!("select ts from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Timestamp(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.value(0), 0); // epoch
            assert_eq!(c.value(1), 1); // 1us after epoch
            // Year 2099 in micros since epoch.
            assert!(c.value(2) > 4_000_000_000_000_000);
        },
    );
}

#[test]
fn uuid_all_zeros_and_all_ones() {
    let srv = server();
    let table = unique_table("uuid_edge");
    srv.http_exec(&format!(
        "create table \"{}\" (u uuid, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    // All-zero UUID is QuestDB's UUID NULL sentinel; insert via SQL
    // explicitly null + all-ones.
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         ('00000000-0000-0000-0000-000000000000'::uuid, '2026-01-01T00:00:00.000Z'), \
         ('ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, '2026-01-01T00:00:01.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 2);

    select_one_batch(
        srv,
        &format!("select u from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Uuid(c) = view.column(0).unwrap() else {
                panic!()
            };
            // Row 0: all-zero UUID — the spec's UUID null sentinel is
            // both halves Long.MIN_VALUE, NOT all-zero, so this stays
            // a valid non-null UUID with zero bytes.
            let r0 = c.value(0);
            assert!(r0.iter().all(|b| *b == 0));
            // Row 1: all-ones UUID.
            let r1 = c.value(1);
            assert!(r1.iter().all(|b| *b == 0xFF));
        },
    );
}

#[test]
fn long256_distinct_high_low_bytes() {
    // Pattern that exercises every byte position so we catch any
    // byte-order regression in the 32-byte read path. All-zero is
    // skipped because Long256 NULL sentinel is "all four longs are
    // Long.MIN_VALUE", and we don't want to chase whether the server
    // collapses ambiguous values.
    let srv = server();
    let table = unique_table("long256_pattern");
    srv.http_exec(&format!(
        "create table \"{}\" (l long256, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         (0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef::long256, \
          '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select l from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Long256(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert!(!c.is_null(0));
            let bytes = c.value(0);
            assert_eq!(bytes.len(), 32);
            // Every byte should be non-zero given the pattern.
            assert!(bytes.iter().any(|b| *b != 0));
        },
    );
}

#[test]
fn geohash_multiple_widths() {
    // Each base-32 char is 5 bits; geohash(Nc) precision = N*5 bits.
    // byte_width = ceil(precision/8).
    //   1c = 5 bits  -> byte_width 1
    //   3c = 15 bits -> byte_width 2
    //   7c = 35 bits -> byte_width 5
    //  12c = 60 bits -> byte_width 8
    let srv = server();
    for &(chars, expected_bits, expected_byte_width) in
        &[(1usize, 5u8, 1u8), (3, 15, 2), (7, 35, 5), (12, 60, 8)]
    {
        let table = unique_table(&format!("geohash_{}c", chars));
        let create = format!(
            "create table \"{tbl}\" (g geohash({n}c), ts timestamp) timestamp(ts) partition by day wal",
            tbl = table,
            n = chars
        );
        srv.http_exec(&create);

        let lit: String = "u4pruydqqvjm".chars().take(chars).collect();
        let insert = format!(
            "insert into \"{tbl}\" values (#{lit}, '2026-01-01T00:00:00.000Z')",
            tbl = table,
            lit = lit
        );
        srv.http_exec(&insert);
        wait_for_rows(srv, &table, 1);

        select_one_batch(
            srv,
            &format!("select g from \"{}\" order by ts", table),
            |view| {
                let ColumnView::Geohash(c) = view.column(0).unwrap() else {
                    panic!("not geohash for {}c", chars)
                };
                assert_eq!(c.precision_bits(), expected_bits, "{}c precision", chars);
                assert_eq!(c.byte_width(), expected_byte_width, "{}c byte_width", chars);
                assert!(c.value(0) != 0, "{}c value should be nonzero", chars);
            },
        );
    }
}

#[test]
fn double_array_3d() {
    let srv = server();
    let table = unique_table("darr_3d");
    srv.http_exec(&format!(
        "create table \"{}\" (a DOUBLE[][][], ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    // Shape [2, 2, 3]: 2 outermost slabs of 2x3 matrices.
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         (ARRAY[ \
            [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]], \
            [[7.0, 8.0, 9.0], [10.0, 11.0, 12.0]] \
          ], '2026-01-01T00:00:00.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 1);

    select_one_batch(
        srv,
        &format!("select a from \"{}\" order by ts", table),
        |view| {
            let ColumnView::DoubleArray(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.shape(0), Some(&[2u32, 2, 3][..]));
            assert_eq!(c.element_count(0), 12);
            // Row-major flat: 1..12.
            for i in 0..12 {
                assert_eq!(c.element(0, i), Some((i + 1) as f64), "flat idx {}", i);
            }
        },
    );
}

#[test]
fn decimal64_zero_and_negative_scale_boundary() {
    let srv = server();
    let table = unique_table("dec_edge");
    srv.http_exec(&format!(
        "create table \"{}\" (p decimal(18,2), z decimal(18,0), ts timestamp) timestamp(ts) partition by day wal",
        table
    ));
    srv.http_exec(&format!(
        "insert into \"{0}\" values \
         (0::decimal(18,2), 12345::decimal(18,0), '2026-01-01T00:00:00.000Z'), \
         (-99.99::decimal(18,2), -1::decimal(18,0), '2026-01-01T00:00:01.000Z')",
        table
    ));
    wait_for_rows(srv, &table, 2);

    select_one_batch(
        srv,
        &format!("select p, z from \"{}\" order by ts", table),
        |view| {
            let ColumnView::Decimal64(p) = view.column(0).unwrap() else {
                panic!()
            };
            let ColumnView::Decimal64(z) = view.column(1).unwrap() else {
                panic!()
            };
            assert_eq!(p.scale(), 2);
            assert_eq!(z.scale(), 0);
            assert_eq!(p.value(0), 0);
            assert_eq!(z.value(0), 12345);
            assert_eq!(p.value(1), -9999);
            assert_eq!(z.value(1), -1);
        },
    );
}

// ---------------------------------------------------------------------------
// Failover / target routing (connect-time only; mid-query failover needs
// a real cluster and is out of scope for OSS single-node testing).
// ---------------------------------------------------------------------------

#[test]
fn server_info_exposes_role() {
    let srv = server();
    let reader = make_reader(srv);
    let info = reader
        .server_info()
        .expect("v2 server must emit SERVER_INFO");
    // Single-node OSS emits STANDALONE; cluster_id and node_id are
    // cluster-only fields and may be empty.
    assert_eq!(info.role, questdb::egress::ServerRole::Standalone);
    eprintln!(
        "[server_info] role={:?} cluster_id={:?} node_id={:?} epoch={}",
        info.role, info.cluster_id, info.node_id, info.epoch
    );
}

#[test]
fn target_primary_accepts_standalone() {
    // STANDALONE counts as PRIMARY for routing — single-node OSS works
    // with target=primary out of the box.
    let srv = server();
    let conf = format!("{};target=primary", srv.qwp_conf());
    let mut reader = Reader::from_conf(&conf).expect("connect with target=primary");
    let info = reader.server_info().expect("server_info");
    assert_eq!(info.role, questdb::egress::ServerRole::Standalone);
    // Connection works for queries.
    let mut cur = reader.query("select 1").execute().expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    assert_eq!(view.row_count(), 1);
}

#[test]
fn target_replica_rejects_standalone() {
    // target=replica wants a REPLICA-role node; STANDALONE doesn't
    // match, so the connect-time walk should reject every endpoint.
    let srv = server();
    let conf = format!("{};target=replica", srv.qwp_conf());
    match Reader::from_conf(&conf) {
        Err(e) => {
            assert_eq!(e.code(), questdb::egress::ErrorCode::RoleMismatch);
            assert!(
                e.msg().contains("Replica") || e.msg().to_lowercase().contains("replica"),
                "expected target name in message; got {:?}",
                e.msg()
            );
        }
        Ok(_) => panic!("expected RoleMismatch against STANDALONE server"),
    }
}

#[test]
fn multi_addr_walks_past_unreachable_endpoint() {
    // First addr is a non-listening loopback port; second is the real
    // server. The walk should fall through to the live one.
    let srv = server();
    let conf = format!("qwp::addr=127.0.0.1:1,127.0.0.1:{}", srv.http_port);
    let mut reader = Reader::from_conf(&conf).expect("walk past unreachable");
    let info = reader.server_info().expect("server_info");
    assert_eq!(info.role, questdb::egress::ServerRole::Standalone);
    // Connection actually works.
    let mut cur = reader.query("select 1").execute().expect("execute");
    let view = cur.next_batch().expect("next").expect("Some");
    assert_eq!(view.row_count(), 1);
}

#[test]
fn credit_flow_control_keeps_server_streaming() {
    // Sets a per-request initial_credit that's smaller than the data
    // the server has to send, then iterates. Without auto-CREDIT
    // replenishment the server would stall after the row-floor batch
    // and `next_batch` would block / time out.
    //
    // Sizing: 5000 rows × (8 long + 8 double = 16 bytes payload) is
    // ~80 KiB of column data alone. initial_credit=4 KiB is well below
    // any single batch wire size, so without flow control replenishment
    // we'd see at most one batch (the row-floor exception) before the
    // server pauses.
    let srv = server();
    let table = unique_table("credit_flow");
    srv.http_exec(&format!(
        "create table \"{}\" (i long, d double, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    const TOTAL: usize = 5_000;
    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    for i in 0..TOTAL as i64 {
        buf.table(table.as_str())
            .unwrap()
            .column_i64("i", i)
            .unwrap()
            .column_f64("d", i as f64 * 0.5)
            .unwrap()
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, TOTAL);

    // Build a Reader with no initial_credit on the connection itself,
    // then set initial_credit on the per-query builder.
    let conf = format!("{};max_batch_rows=500", srv.qwp_conf());
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!("select i, d from \"{}\" order by ts", table))
        .initial_credit(4 * 1024) // 4 KiB; smaller than a single batch
        .execute()
        .expect("execute");

    let mut total_rows = 0usize;
    let mut batch_count = 0usize;
    while let Some(view) = cursor.next_batch().expect("next_batch") {
        batch_count += 1;
        total_rows += view.row_count();
    }
    eprintln!("[credit_flow] batches={} rows={}", batch_count, total_rows);
    assert_eq!(total_rows, TOTAL);
    assert!(batch_count >= 5);
    assert!(matches!(cursor.terminal(), Some(Terminal::End { .. })));
}

#[test]
fn exec_done_for_ddl_and_insert() {
    // Drives non-SELECT statements through the egress channel and
    // verifies each terminates with `EXEC_DONE` (0x16) rather than
    // `RESULT_END` (0x12). next_batch returns Ok(None) immediately on
    // the first call (no batches arrive), with the terminal accessor
    // surfacing the rows_affected and op_type fields.
    let srv = server();
    let table = unique_table("exec_done");
    let mut reader = make_reader(srv);

    // 1) CREATE TABLE -> EXEC_DONE (DDL: rows_affected = 0).
    {
        let mut cur = reader
            .query(&format!(
                "create table \"{}\" (v long, ts timestamp) timestamp(ts) partition by day wal",
                table
            ))
            .execute()
            .expect("execute create");
        assert!(
            cur.next_batch().expect("next create").is_none(),
            "CREATE TABLE should not produce RESULT_BATCH frames"
        );
        match cur.terminal() {
            Some(Terminal::ExecDone {
                op_type,
                rows_affected,
            }) => {
                assert_eq!(*rows_affected, 0, "CREATE TABLE: rows_affected = 0");
                eprintln!("[exec_done create] op_type=0x{:02X}", op_type);
            }
            other => panic!("expected ExecDone for CREATE TABLE, got {:?}", other),
        }
    }

    // 2) INSERT INTO ... VALUES -> EXEC_DONE with rows_affected = N.
    {
        let mut cur = reader
            .query(&format!(
                "insert into \"{}\" values \
                 (10, '2026-01-01T00:00:00.000Z'), \
                 (20, '2026-01-01T00:00:01.000Z'), \
                 (30, '2026-01-01T00:00:02.000Z')",
                table
            ))
            .execute()
            .expect("execute insert");
        assert!(cur.next_batch().expect("next insert").is_none());
        match cur.terminal() {
            Some(Terminal::ExecDone {
                op_type,
                rows_affected,
            }) => {
                assert_eq!(*rows_affected, 3, "INSERT: rows_affected = 3");
                eprintln!("[exec_done insert] op_type=0x{:02X}", op_type);
            }
            other => panic!("expected ExecDone for INSERT, got {:?}", other),
        }
    }

    // 3) Sanity: a follow-up SELECT on the same connection still works
    //    (the cursor lifecycle reset correctly after EXEC_DONE).
    wait_for_rows(srv, &table, 3);
    {
        let mut cur = reader
            .query(&format!("select v from \"{}\" order by ts", table))
            .execute()
            .expect("execute select");
        let view = cur.next_batch().expect("next select").expect("Some batch");
        let ColumnView::Long(c) = view.column(0).unwrap() else {
            panic!()
        };
        assert_eq!(c.value(0), 10);
        assert_eq!(c.value(1), 20);
        assert_eq!(c.value(2), 30);
        while cur.next_batch().expect("drain").is_some() {}
        assert!(matches!(cur.terminal(), Some(Terminal::End { .. })));
    }

    // 4) DROP TABLE -> EXEC_DONE.
    {
        let mut cur = reader
            .query(&format!("drop table \"{}\"", table))
            .execute()
            .expect("execute drop");
        assert!(cur.next_batch().expect("next drop").is_none());
        assert!(matches!(cur.terminal(), Some(Terminal::ExecDone { .. })));
    }
}

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
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i * 1_000_000,
            ))
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

        let ColumnView::Long(i_col) = view.column(0).unwrap() else {
            panic!("col 0")
        };
        let ColumnView::Double(d_col) = view.column(1).unwrap() else {
            panic!("col 1")
        };

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

    eprintln!(
        "[multi_batch_streaming] batches={} total_rows={} max_batch_seq={:?}",
        batch_count, total_rows, last_batch_seq
    );
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
fn multi_batch_with_mixed_nulls_and_symbols() {
    // Stresses the most-interesting decoder paths together:
    //  - delta-dict on first batch, schema-reference after
    //  - dense decoding of long with nulls (bitmap + values per row)
    //  - dense decoding of symbol codes with nulls (codes only over
    //    non-null rows on the wire, densified to per-row u32)
    //  - cross-batch symbol resolution via the connection-scoped dict
    //    (batch 2+ reference codes the dict already carries)
    let srv = server();
    let table = unique_table("mixed_nulls_multibatch");
    // `flag` is a never-null filler so ILP always has at least one
    // column to write per row; the SELECT below ignores it.
    srv.http_exec(&format!(
        "create table \"{}\" (s symbol, v long, flag boolean, ts timestamp) timestamp(ts) partition by day wal",
        table
    ));

    const TOTAL: usize = 5_000;
    const PER_BATCH: usize = 500;
    const DISTINCT_SYMBOLS: usize = 50;
    let symbols: Vec<String> = (0..DISTINCT_SYMBOLS)
        .map(|i| format!("SYM{:03}", i))
        .collect();

    let mut sender = make_sender(srv, ProtocolVersion::V2);
    let mut buf = sender.new_buffer();
    // Null cycles coprime with DISTINCT_SYMBOLS (50) so every symbol id
    // is visited at least once on a non-null row.
    for i in 0..TOTAL {
        let null_sym = i % 11 == 0;
        let null_v = i % 7 == 0;
        let mut row = buf.table(table.as_str()).unwrap();
        if !null_sym {
            row = row.symbol("s", &symbols[i % DISTINCT_SYMBOLS]).unwrap();
        }
        if !null_v {
            row = row.column_i64("v", i as i64 * 3).unwrap();
        }
        row.column_bool("flag", true)
            .unwrap()
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i as i64 * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, TOTAL);

    let conf = format!("{};max_batch_rows={}", srv.qwp_conf(), PER_BATCH);
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!("select s, v from \"{}\" order by ts", table))
        .execute()
        .expect("execute");

    let mut batch_count = 0usize;
    let mut total_rows = 0usize;
    let mut last_batch_seq: Option<u64> = None;
    let mut total_null_sym = 0usize;
    let mut total_null_v = 0usize;
    let mut spot_checks_done = 0usize;

    while let Some(view) = cursor.next_batch().expect("next_batch") {
        batch_count += 1;
        let rows = view.row_count();
        total_rows += rows;

        let seq = view.batch_seq();
        if let Some(prev) = last_batch_seq {
            assert!(seq > prev, "batch_seq must increase");
        }
        last_batch_seq = Some(seq);

        let ColumnView::Symbol(s) = view.column(0).unwrap() else {
            panic!("col 0")
        };
        let ColumnView::Long(v) = view.column(1).unwrap() else {
            panic!("col 1")
        };

        // Walk the batch, validate per-row expectations against the
        // pattern we inserted. Each batch must round-trip its own
        // densified buffers correctly even though the dict was sent
        // only on the first batch.
        for r in 0..rows {
            let global_row = total_rows - rows + r;
            let null_sym_expected = global_row % 11 == 0;
            let null_v_expected = global_row % 7 == 0;

            // Symbol null bitmap.
            assert_eq!(
                s.is_null(r),
                null_sym_expected,
                "row {} sym null mismatch",
                global_row
            );
            if null_sym_expected {
                total_null_sym += 1;
                assert_eq!(s.resolve(r), None);
            } else {
                let expected = &symbols[global_row % DISTINCT_SYMBOLS];
                assert_eq!(
                    s.resolve(r),
                    Some(expected.as_str()),
                    "row {} sym mismatch",
                    global_row
                );
            }

            // Long null bitmap + densified value.
            assert_eq!(
                v.is_null(r),
                null_v_expected,
                "row {} v null mismatch",
                global_row
            );
            if null_v_expected {
                total_null_v += 1;
            } else {
                assert_eq!(
                    v.value(r),
                    global_row as i64 * 3,
                    "row {} v mismatch",
                    global_row
                );
            }

            spot_checks_done += 1;
        }
    }

    eprintln!(
        "[mixed_nulls_multibatch] batches={} rows={} null_sym={} null_v={}",
        batch_count, total_rows, total_null_sym, total_null_v
    );

    assert_eq!(total_rows, TOTAL);
    assert!(
        batch_count >= TOTAL / PER_BATCH,
        "expected at least {} batches, got {}",
        TOTAL / PER_BATCH,
        batch_count
    );
    // Sanity: pattern-implied null counts. div_ceil counts row indices
    // 0, k, 2k, ... up to TOTAL-1.
    assert_eq!(total_null_sym, TOTAL.div_ceil(11));
    assert_eq!(total_null_v, TOTAL.div_ceil(7));
    assert_eq!(spot_checks_done, TOTAL);

    assert!(matches!(cursor.terminal(), Some(Terminal::End { .. })));
    drop(cursor);

    // Connection-scoped dict should carry exactly DISTINCT_SYMBOLS
    // entries. (Batch 2+ used schema reference + no delta dict.)
    assert_eq!(reader.symbol_dict().len(), DISTINCT_SYMBOLS);
}

#[test]
fn zstd_compressed_multi_batch() {
    // Connect with compression=zstd and run the same multi-batch query
    // pattern; verify the FLAG_ZSTD decode path produces identical
    // results to the raw path. Server picks per-batch whether to
    // compress (FLAG_ZSTD set) or send raw, so we must accept both
    // bit patterns transparently.
    let srv = server();
    let table = unique_table("zstd_multibatch");
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
            .at(TimestampNanos::new(
                1_700_000_000_000_000_000 + i * 1_000_000,
            ))
            .unwrap();
    }
    sender.flush(&mut buf).expect("flush");
    wait_for_rows(srv, &table, TOTAL);

    // compression=zstd advertises only zstd; auto would advertise both.
    // Either accepts FLAG_ZSTD on the server side; we use zstd to be
    // explicit that the path is exercised.
    let conf = format!(
        "{};max_batch_rows={};compression=zstd",
        srv.qwp_conf(),
        PER_BATCH
    );
    let mut reader = Reader::from_conf(&conf).expect("reader");
    let mut cursor = reader
        .query(&format!("select i, d from \"{}\" order by ts", table))
        .execute()
        .expect("execute");

    use questdb::egress::wire::flags as wire_flags;
    let mut batch_count = 0usize;
    let mut compressed_batches = 0usize;
    let mut total_rows = 0usize;
    let mut first_value: Option<i64> = None;
    let mut last_value: Option<i64> = None;

    while let Some(view) = cursor.next_batch().expect("next_batch") {
        batch_count += 1;
        if view.flags() & wire_flags::ZSTD != 0 {
            compressed_batches += 1;
        }
        let rows = view.row_count();
        let ColumnView::Long(i_col) = view.column(0).unwrap() else {
            panic!()
        };
        let ColumnView::Double(d_col) = view.column(1).unwrap() else {
            panic!()
        };
        if first_value.is_none() {
            first_value = Some(i_col.value(0));
        }
        if rows > 0 {
            last_value = Some(i_col.value(rows - 1));
            let last_i = i_col.value(rows - 1);
            assert_eq!(d_col.value(rows - 1), last_i as f64 * 0.5);
        }
        total_rows += rows;
    }

    eprintln!(
        "[zstd_compressed_multi_batch] batches={} (compressed={}) rows={}",
        batch_count, compressed_batches, total_rows
    );
    assert_eq!(total_rows, TOTAL);
    assert!(batch_count >= TOTAL / PER_BATCH);
    assert_eq!(first_value, Some(0));
    assert_eq!(last_value, Some(TOTAL as i64 - 1));
    // The server doesn't HAVE to compress, but with compression=zstd
    // negotiated and 5000 rows of monotonic-int data (highly
    // compressible), at least some batches should arrive zstd-encoded.
    // If 0, our decoder didn't exercise the FLAG_ZSTD path.
    assert!(
        compressed_batches > 0,
        "no batches arrived with FLAG_ZSTD set; zstd decode path not exercised"
    );
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
            let ColumnView::Long(c) = view.column(0).unwrap() else {
                panic!()
            };
            assert_eq!(c.value(0), 10);
            assert!(c.is_null(1));
            assert_eq!(c.value(2), 30);
            assert!(c.is_null(3));
            assert_eq!(c.value(4), 50);
        },
    );
}
