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
//! [`io.questdb.test.cutlass.qwp.QwpEgressFuzzTest#testSelectAlterSequenceFuzz`](https://github.com/questdb/questdb/blob/master/core/src/test/java/io/questdb/test/cutlass/qwp/QwpEgressFuzzTest.java).
//!
//! Interleaves random SELECT shapes with `ALTER TABLE ADD/DROP COLUMN`
//! against one stable table over a single connection. Pins the
//! server's stale-cache retry path on `tableId` bumps: each ALTER
//! invalidates the per-connection schema cache, and the next SELECT
//! must transparently re-fetch the schema rather than fail with
//! `ServerSchemaMismatch`.
//!
//! Distinct from `egress_live_server_fuzz.rs`'s random-schema fuzz —
//! the table here is fixed (`id LONG, v DOUBLE, cat SYMBOL, ts
//! TIMESTAMP`), the rows are seeded once with closed-form values
//! (`v = id * 1.5`, `cat = "abcd"[id % 4]`, `ts = (id - 1) * spacing`),
//! and the verifier knows the values per id without an `expected_hash`
//! table. ADDed columns are VARCHAR and never UPDATEd, so every cell
//! in them must surface as NULL when read back.
//!
//! No fragmentation. The Java original makes the same choice — its
//! comment notes that fragmentation × schema coverage is already in
//! the dedicated fragmentation file.
//!
//! Gated behind the `live-server-tests` Cargo feature. Seeded via
//! `QWP_EGRESS_FUZZ_SEED`.

#![cfg(feature = "live-server-tests")]

mod common;

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;

use common::QuestDbServer;

// ---------------------------------------------------------------------------
// SplitMix64 + seed plumbing — same shape as the other fuzz files.
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

    fn gen_range_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound as u64) as usize
    }
}

const DEFAULT_SEED: u64 = 0x9d2e_6c3a_47b1_82f5;

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

// ---------------------------------------------------------------------------
// Closed-form value oracles for the fixed schema.
// ---------------------------------------------------------------------------

const BASE_COLS: &[&str] = &["id", "v", "cat", "ts"];

/// Java `expectedV(id) = id * 1.5`. id is 1-based.
fn expected_v(id: i64) -> f64 {
    (id as f64) * 1.5
}

/// Java `expectedTs(id, spacing) = (id - 1) * spacing`. id is 1-based.
fn expected_ts(id: i64, spacing_micros: i64) -> i64 {
    (id - 1) * spacing_micros
}

/// Java `catFor(id) = "abcd"[id % 4]`. id is 1-based.
fn cat_for(id: i64) -> &'static str {
    match id.rem_euclid(4) {
        0 => "a",
        1 => "b",
        2 => "c",
        _ => "d",
    }
}

/// Closed-form group-by count. id ∈ 1..=total_rows; row matches `cat`
/// iff `id % 4 == k_mod`. Mirrors Java's `catCount`.
fn cat_count(total_rows: i64, k_mod: i64) -> i64 {
    if k_mod == 0 {
        total_rows / 4
    } else {
        (total_rows + 4 - k_mod) / 4
    }
}

/// Mirrors Java's `pickSpacingMicros()`. One of four presets that
/// control how dense partitions are — affects interval-predicate
/// performance.
fn pick_spacing_micros(rng: &mut SplitMix64) -> i64 {
    const CHOICES: [i64; 4] = [
        300_000_000,    // 5 min
        864_000_000,    // 14.4 min
        3_600_000_000,  // 1 h
        21_600_000_000, // 6 h
    ];
    CHOICES[rng.gen_range_usize(CHOICES.len())]
}

/// Mirrors Java's `pickCompression()` from the other fuzz file —
/// kept local so this binary is self-contained.
fn pick_compression(rng: &mut SplitMix64) -> String {
    match rng.gen_range_u32(5) {
        0 => String::new(),
        1 => "compression=raw".to_string(),
        2 => "compression=auto".to_string(),
        3 => "compression=zstd".to_string(),
        _ => {
            let level = 1 + rng.gen_range_u32(9);
            format!("compression=zstd;compression_level={level}")
        }
    }
}

fn make_reader_with(srv: &QuestDbServer, compression_suffix: &str) -> Reader {
    let base = srv.qwp_conf();
    let conf = if compression_suffix.is_empty() {
        base
    } else {
        format!("{base};{compression_suffix}")
    };
    Reader::from_conf(conf).expect("reader")
}

/// Poll until the count(*) reaches `expected`. Necessary because WAL
/// commits — INSERT and ALTER — apply asynchronously.
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

/// Poll `show columns` until the column count matches `expected`.
/// Mirrors `awaitTable` after `ALTER`. WAL applies the column-add /
/// column-drop asynchronously.
fn wait_for_column_count(srv: &QuestDbServer, table: &str, expected: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let sql = format!("show columns from \"{table}\"");
    while std::time::Instant::now() < deadline {
        if let Ok(mut r) = Reader::from_conf(srv.qwp_conf())
            && let Ok(mut cur) = r.prepare(&sql).execute()
        {
            let mut count = 0usize;
            while let Ok(Some(view)) = cur.next_batch() {
                count += view.row_count();
            }
            if count == expected {
                return;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(80));
    }
    panic!("{table} did not reach {expected} columns within 60s");
}

// ---------------------------------------------------------------------------
// Per-base-column verifier.
//
// Output projection for shape 4 / 5 may include any subset of the base
// columns in any order. `verify_base_cell` accepts the output column
// index, the input column name, and verifies the cell against the
// closed-form value for the given id.
// ---------------------------------------------------------------------------

/// Verifies one base-column cell against the closed-form expectation
/// for `id`. `out_col` is the index of the column in the SELECT
/// result; `in_col` names which of `id` / `v` / `cat` / `ts` is in
/// that slot.
fn verify_base_cell(
    view: &questdb::egress::reader::BatchView<'_>,
    out_col: usize,
    in_col: &str,
    r: usize,
    id: i64,
    spacing: i64,
    label: &str,
) {
    let cv = view.column(out_col).unwrap_or_else(|e| {
        panic!("{label}: column({out_col}) failed: {e:?}");
    });
    match (in_col, cv) {
        ("id", ColumnView::Long(c)) => assert_eq!(
            c.value(r),
            id,
            "{label}: out_col={out_col} (id) row={r} id-mismatch"
        ),
        ("v", ColumnView::Double(c)) => assert_eq!(
            c.value(r).to_bits(),
            expected_v(id).to_bits(),
            "{label}: out_col={out_col} (v) row={r} v-mismatch (id={id})"
        ),
        ("cat", ColumnView::Symbol(c)) => {
            let got = c
                .resolve(r)
                .unwrap_or_else(|| panic!("{label}: out_col={out_col} (cat) row={r} NULL"));
            assert_eq!(
                got,
                cat_for(id),
                "{label}: out_col={out_col} (cat) row={r} cat-mismatch (id={id})"
            );
        }
        ("ts", ColumnView::Timestamp(c)) => assert_eq!(
            c.value(r),
            expected_ts(id, spacing),
            "{label}: out_col={out_col} (ts) row={r} ts-mismatch (id={id})"
        ),
        (name, cv) => panic!(
            "{label}: out_col={out_col} expected base column {name} but got {:?}",
            cv.kind()
        ),
    }
}

// ---------------------------------------------------------------------------
// SELECT shape drivers — six shapes ported from Java `runSelectShape`.
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // mirrors Java's runSelectShape shape
fn run_select_shape(
    reader: &mut Reader,
    rng: &mut SplitMix64,
    shape: u32,
    table: &str,
    total_rows: i64,
    spacing: i64,
    live_added: &[String],
) {
    let label = format!("shape={shape}");
    match shape {
        0 => {
            // SELECT id FROM <table> — no ORDER BY (ts is designated
            // so the wal-table scan is monotonic on id).
            let sql = format!("select id from \"{table}\"");
            let mut cur = reader.prepare(sql).execute().expect("execute");
            let mut seen = 0i64;
            while let Some(view) = cur.next_batch().expect("next_batch") {
                let n = view.row_count();
                let ColumnView::Long(c) = view.column(0).unwrap() else {
                    panic!("{label}: col 0 not Long");
                };
                for r in 0..n {
                    let id = seen + r as i64 + 1;
                    assert_eq!(c.value(r), id, "{label}: row {r} id-mismatch (seen={seen})");
                }
                seen += n as i64;
            }
            assert_eq!(seen, total_rows, "{label}: row_count drift");
        }
        1 => {
            // SELECT id, v FROM <table> WHERE id > <threshold>
            let max_t = (total_rows - 1).max(1);
            let threshold = 1 + rng.gen_range_usize(max_t as usize) as i64;
            let sql = format!("select id, v from \"{table}\" where id > {threshold}");
            let mut cur = reader.prepare(sql).execute().expect("execute");
            let mut seen = 0i64;
            while let Some(view) = cur.next_batch().expect("next_batch") {
                let n = view.row_count();
                let ColumnView::Long(c0) = view.column(0).unwrap() else {
                    panic!("{label}: col 0 not Long");
                };
                let ColumnView::Double(c1) = view.column(1).unwrap() else {
                    panic!("{label}: col 1 not Double");
                };
                for r in 0..n {
                    let id = threshold + seen + r as i64 + 1;
                    assert_eq!(c0.value(r), id, "{label}: row id-mismatch");
                    assert_eq!(
                        c1.value(r).to_bits(),
                        expected_v(id).to_bits(),
                        "{label}: row v-mismatch (id={id})"
                    );
                }
                seen += n as i64;
            }
            let expected = total_rows - threshold;
            assert_eq!(seen, expected, "{label}: row_count drift");
        }
        2 => {
            // SELECT cat, COUNT(*) c FROM <table> — GROUP BY, 4 cats.
            let sql = format!("select cat, count(*) as c from \"{table}\"");
            let mut cur = reader.prepare(sql).execute().expect("execute");
            let mut got_counts: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            while let Some(view) = cur.next_batch().expect("next_batch") {
                let n = view.row_count();
                let ColumnView::Symbol(cat) = view.column(0).unwrap() else {
                    panic!("{label}: col 0 not Symbol");
                };
                let ColumnView::Long(cnt) = view.column(1).unwrap() else {
                    panic!("{label}: col 1 not Long");
                };
                for r in 0..n {
                    let s = cat
                        .resolve(r)
                        .unwrap_or_else(|| panic!("{label}: row {r} NULL cat"))
                        .to_string();
                    got_counts.insert(s, cnt.value(r));
                }
            }
            assert_eq!(got_counts.len(), 4, "{label}: 4 distinct cats expected");
            for (k_mod, name) in [(0i64, "a"), (1, "b"), (2, "c"), (3, "d")] {
                let expected = cat_count(total_rows, k_mod);
                let got = *got_counts
                    .get(name)
                    .unwrap_or_else(|| panic!("{label}: cat={name} missing"));
                assert_eq!(
                    got, expected,
                    "{label}: cat={name} count-mismatch (k_mod={k_mod})"
                );
            }
        }
        3 => {
            // SELECT id FROM <table> WHERE ts >= lo AND ts < hi —
            // ts-interval filter.
            let max_lo = (total_rows - 2).max(1) as usize;
            let lo_row = 1 + rng.gen_range_usize(max_lo) as i64;
            let max_span = (total_rows - lo_row).max(1) as usize;
            let span = 1 + rng.gen_range_usize(max_span) as i64;
            let hi_row = lo_row + span;
            let ts_lo = (lo_row - 1) * spacing;
            let ts_hi = (hi_row - 1) * spacing;
            let sql = format!(
                "select id from \"{table}\" \
                 where ts >= CAST({ts_lo}L AS TIMESTAMP) and ts < CAST({ts_hi}L AS TIMESTAMP)"
            );
            let mut cur = reader.prepare(sql).execute().expect("execute");
            let mut seen = 0i64;
            while let Some(view) = cur.next_batch().expect("next_batch") {
                let n = view.row_count();
                let ColumnView::Long(c) = view.column(0).unwrap() else {
                    panic!("{label}: col 0 not Long");
                };
                for r in 0..n {
                    let id = lo_row + seen + r as i64;
                    assert_eq!(c.value(r), id, "{label}: row id-mismatch");
                }
                seen += n as i64;
            }
            assert_eq!(seen, span, "{label}: row_count drift");
        }
        4 => {
            // Random projection of base columns, ORDER BY id.
            let pick_count = 1 + rng.gen_range_usize(BASE_COLS.len());
            let mut shuffled: Vec<usize> = (0..BASE_COLS.len()).collect();
            for i in (1..BASE_COLS.len()).rev() {
                let j = rng.gen_range_usize(i + 1);
                shuffled.swap(i, j);
            }
            shuffled.truncate(pick_count);
            let cols: Vec<&'static str> = shuffled.iter().map(|&i| BASE_COLS[i]).collect();
            let sql = format!("select {} from \"{table}\" order by id", cols.join(","));
            let mut cur = reader.prepare(sql).execute().expect("execute");
            let mut seen = 0i64;
            while let Some(view) = cur.next_batch().expect("next_batch") {
                let n = view.row_count();
                for r in 0..n {
                    let id = seen + r as i64 + 1;
                    for (out_col, &in_col) in cols.iter().enumerate() {
                        verify_base_cell(
                            &view,
                            out_col,
                            in_col,
                            r,
                            id,
                            spacing,
                            &format!("shape=4 cols={cols:?}"),
                        );
                    }
                }
                seen += n as i64;
            }
            assert_eq!(seen, total_rows, "shape=4: row_count drift");
        }
        _ => {
            // SELECT * — all base columns plus any live-added.
            let expected_cols = BASE_COLS.len() + live_added.len();
            let sql = format!("select * from \"{table}\"");
            let mut cur = reader.prepare(sql).execute().expect("execute");
            let mut seen = 0i64;
            while let Some(view) = cur.next_batch().expect("next_batch") {
                let n = view.row_count();
                assert_eq!(
                    view.column_count(),
                    expected_cols,
                    "shape=5: column count drift (live_added={})",
                    live_added.len()
                );
                for r in 0..n {
                    let id = seen + r as i64 + 1;
                    // Base columns are always in order id, v, cat, ts
                    // — they're the original CREATE TABLE order, and
                    // SELECT * preserves it. ALTER ADD COLUMN appends
                    // to the right.
                    for (out_col, &in_col) in BASE_COLS.iter().enumerate() {
                        verify_base_cell(&view, out_col, in_col, r, id, spacing, "shape=5 base");
                    }
                    // Every extra column must be NULL — we only ADD
                    // them, never UPDATE.
                    for (i, name) in live_added.iter().enumerate() {
                        let out_col = BASE_COLS.len() + i;
                        let cv = view.column(out_col).unwrap_or_else(|e| {
                            panic!("shape=5: column({out_col}) failed: {e:?}");
                        });
                        let is_null = match cv {
                            ColumnView::Varchar(x) => x.is_null(r),
                            _ => panic!(
                                "shape=5: extra column {name} expected VARCHAR, got {:?}",
                                cv.kind()
                            ),
                        };
                        assert!(
                            is_null,
                            "shape=5: extra column {name} row {r} expected NULL (id={id})"
                        );
                    }
                }
                seen += n as i64;
            }
            assert_eq!(seen, total_rows, "shape=5: row_count drift");
        }
    }
}

// ---------------------------------------------------------------------------
// Test.
// ---------------------------------------------------------------------------

/// Ports `testSelectAlterSequenceFuzz`. Interleaves random SELECT
/// shapes with `ALTER ADD/DROP COLUMN` operations against one stable
/// table. One JVM per test, no fragmentation (matches Java).
#[test]
fn select_alter_sequence() {
    let mut rng = SplitMix64::new(fuzz_seed_for("select_alter_sequence"));

    // Pre-roll all the run-shape knobs once so a re-run with the
    // same seed reproduces the same trajectory.
    let row_count = 50 + rng.gen_range_usize(951); // [50, 1000]
    let spacing = pick_spacing_micros(&mut rng);
    let op_count = 15 + rng.gen_range_usize(26); // [15, 40]
    let structural_prob_permil = 150 + rng.gen_range_u32(251); // [150, 400] permil
    let max_live_added_columns = 2 + rng.gen_range_usize(5); // [2, 6]
    let compression = pick_compression(&mut rng);
    eprintln!(
        "[select_alter_sequence] row_count={row_count} spacing={spacing} \
         op_count={op_count} structural_prob_permil={structural_prob_permil} \
         max_live_added_columns={max_live_added_columns} compression={:?}",
        if compression.is_empty() {
            "default"
        } else {
            &compression
        }
    );

    let srv = QuestDbServer::start();
    let table = "fz_seq";

    // CREATE TABLE.
    let create = format!(
        "create table \"{table}\" (id LONG, v DOUBLE, cat SYMBOL, ts TIMESTAMP) \
         timestamp(ts) partition by day wal"
    );
    let status = srv.http_exec(&create);
    assert!((200..400).contains(&status), "create http={status}");

    // Seed insert via a `long_sequence` CTAS-style expression.
    let insert = format!(
        "insert into \"{table}\" \
         select x, x * 1.5, \
                case when x % 4 = 0 then 'a' when x % 4 = 1 then 'b' \
                     when x % 4 = 2 then 'c' else 'd' end, \
                CAST((x - 1) * {spacing}L AS TIMESTAMP) \
         from long_sequence({row_count})"
    );
    let status = srv.http_exec(&insert);
    assert!((200..400).contains(&status), "seed insert http={status}");
    wait_for_rows(&srv, table, row_count);

    // One connection for the whole sequence — exercises per-connection
    // schema cache across queries and ALTER bumps.
    let mut reader = make_reader_with(&srv, &compression);

    // Seed the schema cache by running shape 0 once before the loop.
    run_select_shape(
        &mut reader,
        &mut rng,
        0,
        table,
        row_count as i64,
        spacing,
        &[],
    );

    // Mutable state across ops.
    let mut live_added: Vec<String> = Vec::new();
    let mut next_column_id: u64 = 0;

    for op in 0..op_count {
        let pick = rng.gen_range_u32(1000);
        let want_structural = pick < structural_prob_permil;
        let can_add = live_added.len() < max_live_added_columns;
        let can_drop = !live_added.is_empty();

        let did_structural = if want_structural {
            // Pick add vs drop. If only one option is available, take
            // it; if both, 60/40 favour add (matches Java).
            let do_add = match (can_add, can_drop) {
                (true, false) => true,
                (false, true) => false,
                (true, true) => rng.gen_range_u32(10) < 6,
                (false, false) => false, // fall through to a SELECT
            };
            if can_add && do_add {
                let name = format!("extra_{next_column_id}");
                next_column_id += 1;
                let alter = format!("alter table \"{table}\" add column \"{name}\" VARCHAR");
                let status = srv.http_exec(&alter);
                assert!(
                    (200..400).contains(&status),
                    "op={op} alter add http={status}"
                );
                live_added.push(name);
                wait_for_column_count(&srv, table, BASE_COLS.len() + live_added.len());
                true
            } else if can_drop && !do_add {
                let victim_idx = rng.gen_range_usize(live_added.len());
                let victim = live_added.remove(victim_idx);
                let alter = format!("alter table \"{table}\" drop column \"{victim}\"");
                let status = srv.http_exec(&alter);
                assert!(
                    (200..400).contains(&status),
                    "op={op} alter drop http={status}"
                );
                wait_for_column_count(&srv, table, BASE_COLS.len() + live_added.len());
                true
            } else {
                false
            }
        } else {
            false
        };

        if !did_structural {
            let shape = rng.gen_range_u32(6);
            run_select_shape(
                &mut reader,
                &mut rng,
                shape,
                table,
                row_count as i64,
                spacing,
                &live_added,
            );
        }
    }
}
