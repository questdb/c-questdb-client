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
//! [`io.questdb.test.cutlass.qwp.QwpEgressBindFuzzTest`](https://github.com/questdb/questdb/blob/master/core/src/test/java/io/questdb/test/cutlass/qwp/QwpEgressBindFuzzTest.java).
//!
//! Stresses the bind encoder with random scalar values, round-trips
//! them through a `SELECT $1::TYPE FROM long_sequence(1)` projection
//! on a real QuestDB, and asserts bit-level equality on the result.
//! Complements the deterministic boundary cases pinned by the existing
//! `bind_*_passthrough` tests in `egress_live_server.rs` — this file
//! catches encoder bugs that hand-picked cases would miss.
//!
//! Reuses the singleton `server()` from
//! `egress_live_server.rs`'s `tests/common/mod.rs`. None of these tests
//! need per-instance debug knobs, so paying one JVM boot amortised
//! across all four tests + their iterations is the right trade-off.
//!
//! Gated behind the `live-server-tests` Cargo feature so the default
//! `cargo test` doesn't try to spin up a JVM. Seeded via the
//! `QWP_EGRESS_FUZZ_SEED` env var (decimal or `0x...` hex); when unset
//! a deterministic default seed is used so reruns reproduce.

#![cfg(feature = "live-server-tests")]

mod common;

use std::sync::OnceLock;

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;

use common::QuestDbServer;

// ---------------------------------------------------------------------------
// Fixture (shared singleton — none of these tests need per-instance config).
// ---------------------------------------------------------------------------

fn server() -> &'static QuestDbServer {
    static SERVER: OnceLock<QuestDbServer> = OnceLock::new();
    SERVER.get_or_init(QuestDbServer::start)
}

fn make_reader(srv: &QuestDbServer) -> Reader {
    Reader::from_conf(srv.qwp_conf()).expect("reader")
}

// ---------------------------------------------------------------------------
// SplitMix64 — same impl as `qwp_egress_bounds_fuzz.rs`. Local copy is
// cheaper than wiring a shared crate-test module.
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

    fn next_i64(&mut self) -> i64 {
        self.next_u64() as i64
    }

    fn next_i32(&mut self) -> i32 {
        self.next_u64() as i32
    }

    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 0
    }

    fn gen_range_u32(&mut self, bound: u32) -> u32 {
        (self.next_u64() % bound as u64) as u32
    }
}

// ---------------------------------------------------------------------------
// Seed plumbing.
// ---------------------------------------------------------------------------

/// Default seed when `QWP_EGRESS_FUZZ_SEED` is unset. Pinning a seed
/// keeps the runs reproducible across CI re-runs; when a new failure
/// surfaces with the env override, update this constant so the broken
/// case becomes the new regression baseline. Mirrors the Java
/// fragmentation file's `(492919964565416L, 1776636105288L)` pattern.
const DEFAULT_SEED: u64 = 0x0123_4567_89AB_CDEF;

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
    // Mix the test name into the seed so test methods don't share a
    // sequence. SplitMix64-style stir over the FNV-1a hash of the name.
    let mut hash: u64 = 0xCBF2_9CE4_8422_2325;
    for b in test_name.bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100_0000_01B3);
    }
    let combined = base.wrapping_add(hash);
    eprintln!("[qwp_egress_fuzz seed] {test_name} seed=0x{combined:016x}");
    combined
}

// ---------------------------------------------------------------------------
// Value generators — port of the Java helpers from QwpEgressBindFuzzTest.
// ---------------------------------------------------------------------------

/// Java: `pickNonNullLong()` — retries `Long.MIN_VALUE` (LONG_NULL).
fn pick_non_null_long(rng: &mut SplitMix64) -> i64 {
    loop {
        let v = rng.next_i64();
        if v != i64::MIN {
            return v;
        }
    }
}

/// Java: `pickNonNullInt()` — retries `Integer.MIN_VALUE` (INT_NULL).
fn pick_non_null_int(rng: &mut SplitMix64) -> i32 {
    loop {
        let v = rng.next_i32();
        if v != i32::MIN {
            return v;
        }
    }
}

/// Java: `pickSpecialOrRandomDouble()`. Four-way pick:
///   case 0: NaN
///   case 1: 0.0
///   cases 2 / 3: `Double.longBitsToDouble(random.nextLong())`, retries Infinity
/// Note `-0.0` and any other finite are kept. The Java test asserts
/// bit-exact equality so we must too.
fn pick_special_or_random_double(rng: &mut SplitMix64) -> f64 {
    match rng.gen_range_u32(4) {
        0 => f64::NAN,
        1 => 0.0,
        _ => loop {
            let bits = rng.next_u64();
            let v = f64::from_bits(bits);
            if !v.is_infinite() {
                return v;
            }
        },
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

const ITERATIONS_PER_TEST: u32 = 25;

/// Ports `testFuzzDoubleBinds`. Round-trips 25 DOUBLE bind values per
/// run, asserting bit-exact equality (NaN included via `to_bits`).
/// FLOAT is intentionally skipped — the `::FLOAT` cast renormalises
/// some values (`-0.0` → `0.0`, sub-millionth rounding) and a random
/// comparison would flap on cast precision rather than encoder bugs.
#[test]
fn fuzz_double_binds() {
    let srv = server();
    let mut rng = SplitMix64::new(fuzz_seed_for("fuzz_double_binds"));
    let mut reader = make_reader(srv);
    for iter in 0..ITERATIONS_PER_TEST {
        let v = pick_special_or_random_double(&mut rng);
        let mut cur = reader
            .prepare("SELECT $1::DOUBLE AS d FROM long_sequence(1)")
            .bind_f64(v)
            .execute()
            .expect("execute");
        let view = cur.next_batch().expect("next_batch").expect("Some batch");
        let ColumnView::Double(c) = view.column(0).unwrap() else {
            panic!("iter {iter}: col 0 not Double");
        };
        let got = c.value(0);
        if v.is_nan() {
            assert!(got.is_nan(), "iter {iter}: expected NaN, got {got}");
        } else {
            assert_eq!(
                got.to_bits(),
                v.to_bits(),
                "iter {iter}: double bit-mismatch v=0x{:016x} got=0x{:016x}",
                v.to_bits(),
                got.to_bits()
            );
        }
        drop(cur);
    }
}

/// Ports `testFuzzIntegralBindsProjection`. Sends LONG / INT / SHORT /
/// BYTE / BOOLEAN binds in one query and verifies per-column equality.
/// All five getters are exact-integer, so no tolerance is needed.
#[test]
fn fuzz_integral_binds_projection() {
    let srv = server();
    let mut rng = SplitMix64::new(fuzz_seed_for("fuzz_integral_binds_projection"));
    let mut reader = make_reader(srv);
    for iter in 0..ITERATIONS_PER_TEST {
        let long_val = pick_non_null_long(&mut rng);
        let int_val = pick_non_null_int(&mut rng);
        let short_val = rng.next_i32() as i16;
        let byte_val = rng.next_i32() as i8;
        let bool_val = rng.next_bool();
        let mut cur = reader
            .prepare(
                "SELECT $1::LONG AS l, $2::INT AS i, $3::SHORT AS s, \
                 $4::BYTE AS b, $5::BOOLEAN AS x FROM long_sequence(1)",
            )
            .bind_i64(long_val)
            .bind_i32(int_val)
            .bind_i16(short_val)
            .bind_i8(byte_val)
            .bind_bool(bool_val)
            .execute()
            .expect("execute");
        let view = cur.next_batch().expect("next_batch").expect("Some batch");
        let ColumnView::Long(c0) = view.column(0).unwrap() else {
            panic!("iter {iter}: col 0 not Long");
        };
        let ColumnView::Int(c1) = view.column(1).unwrap() else {
            panic!("iter {iter}: col 1 not Int");
        };
        let ColumnView::Short(c2) = view.column(2).unwrap() else {
            panic!("iter {iter}: col 2 not Short");
        };
        let ColumnView::Byte(c3) = view.column(3).unwrap() else {
            panic!("iter {iter}: col 3 not Byte");
        };
        let ColumnView::Boolean(c4) = view.column(4).unwrap() else {
            panic!("iter {iter}: col 4 not Boolean");
        };
        assert_eq!(c0.value(0), long_val, "iter {iter}: long");
        assert_eq!(c1.value(0), int_val, "iter {iter}: int");
        assert_eq!(c2.value(0), short_val, "iter {iter}: short");
        assert_eq!(c3.value(0), byte_val, "iter {iter}: byte");
        // BOOLEAN surfaces as a u8 (0 / 1) on the wire.
        assert_eq!(c4.value(0) != 0, bool_val, "iter {iter}: bool");
        drop(cur);
    }
}

/// Ports `testFuzzSameSqlDifferentBindsCacheReuse`. Stresses the
/// factory-cache path: same SQL text, 50 distinct bind values, against
/// a pre-seeded table where `v = id * 7`.
#[test]
fn fuzz_same_sql_different_binds_cache_reuse() {
    let srv = server();
    let table = format!(
        "egress_bind_fuzz_cache_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    );
    // CREATE + INSERT via HTTP /exec so the bind fuzz path runs against
    // a stable, known-row table.
    let create = format!(
        "create table \"{table}\" (id LONG, v LONG, part_ts TIMESTAMP) \
         timestamp(part_ts) partition by day wal"
    );
    let status = srv.http_exec(&create);
    assert!(
        (200..400).contains(&status),
        "create returned http {status}"
    );
    // Multi-row VALUES is shorter than 100 separate INSERTs.
    let mut insert = format!("insert into \"{table}\" values ");
    for r in 0..100i64 {
        if r > 0 {
            insert.push(',');
        }
        insert.push_str(&format!("({r}, {}, CAST({} AS TIMESTAMP))", r * 7, r + 1));
    }
    let status = srv.http_exec(&insert);
    assert!(
        (200..400).contains(&status),
        "insert returned http {status}"
    );
    // WAL apply is async; wait until SELECT count(*) sees all 100 rows.
    wait_for_rows(srv, &table, 100);

    let mut rng = SplitMix64::new(fuzz_seed_for("fuzz_same_sql_different_binds_cache_reuse"));
    let mut reader = make_reader(srv);
    let sql = format!("SELECT v FROM \"{table}\" WHERE id = $1");
    for iter in 0..50u32 {
        let target = rng.gen_range_u32(100) as i32;
        let mut cur = reader
            .prepare(sql.as_str())
            .bind_i32(target)
            .execute()
            .expect("execute");
        let view = cur.next_batch().expect("next_batch").expect("Some batch");
        assert_eq!(view.row_count(), 1, "iter {iter}: row_count");
        let ColumnView::Long(c) = view.column(0).unwrap() else {
            panic!("iter {iter}: col 0 not Long");
        };
        assert_eq!(
            c.value(0),
            (target as i64) * 7,
            "iter {iter}: target={target}"
        );
        drop(cur);
    }
    // Best-effort cleanup; ignore failure (test passed by here).
    let _ = srv.http_exec(&format!("drop table \"{table}\""));
}

/// Ports `testFuzzUuidBinds`. UUID is 16 raw bytes on the wire — bind
/// random bytes and assert they round-trip. The Java test additionally
/// skips the all-`MIN_VALUE` sentinel (NULL UUID); since the spec
/// represents NULL via the null-bitmap rather than a bit-pattern, our
/// random 16-byte payload never accidentally lands on a NULL.
#[test]
fn fuzz_uuid_binds() {
    let srv = server();
    let mut rng = SplitMix64::new(fuzz_seed_for("fuzz_uuid_binds"));
    let mut reader = make_reader(srv);
    for iter in 0..ITERATIONS_PER_TEST {
        let mut bytes = [0u8; 16];
        let lo = rng.next_u64().to_le_bytes();
        let hi = rng.next_u64().to_le_bytes();
        bytes[..8].copy_from_slice(&lo);
        bytes[8..].copy_from_slice(&hi);
        let mut cur = reader
            .prepare("SELECT $1::UUID AS u FROM long_sequence(1)")
            .bind_uuid(bytes)
            .execute()
            .expect("execute");
        let view = cur.next_batch().expect("next_batch").expect("Some batch");
        let ColumnView::Uuid(c) = view.column(0).unwrap() else {
            panic!("iter {iter}: col 0 not Uuid");
        };
        assert_eq!(c.value(0), &bytes, "iter {iter}: uuid byte mismatch");
        drop(cur);
    }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Poll `SELECT count(*) FROM <table>` until at least `expected` rows
/// have applied. WAL tables apply asynchronously, so an INSERT-then-
/// SELECT race needs explicit synchronisation.
fn wait_for_rows(srv: &QuestDbServer, table: &str, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
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
    panic!("{table} did not reach {expected} rows within 15s");
}
