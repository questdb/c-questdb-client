//! Shared scenario definitions for the QWP DataFrame benchmark examples
//! (doc/historical/QWP_DATAFRAME_BENCH_PLAN.md §3.1 / §8). Both
//! `qwp_ingress_polars` and
//! `qwp_egress_polars` build their data from these helpers so the Rust
//! `rust-polars` numbers compare against the Python `py-pandas` harness
//! (`py-questdb-client/test/benchmark_pandas_columnar.py`).
//!
//! This is the **one place** the cross-client parity contract lives: the
//! column layout, the DEDUP DDL, and the exact deterministic value
//! generators (note templates, the `d{k}` formula, and the SYMBOL label
//! formats) all mirror `make_s1_narrow` / `make_s2_wide` field-for-field, so
//! the two clients put byte-identical column data on the wire.
//!
//! Kept dependency-light (no polars/questdb types) and outside Cargo's
//! example auto-discovery (subdirectory + `mod.rs`, like `bench_json`),
//! referenced by each example via `mod bench_schema;`.

#![allow(dead_code)] // each example uses a subset of the surface.

/// The benchmark scenarios shared with the Python harness.
///
/// * `S1Narrow` — 5 columns (the headline; matches Go/Rust `qwp-egress-read`).
/// * `S2Wide` — 15 columns: S1 plus 5 DOUBLE + 5 high-cardinality SYMBOL,
///   matching the Go `qwp-egress-read-wide` anchor (plan §8).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SchemaKind {
    S1Narrow,
    S2Wide,
}

/// S2-wide adds this many extra DOUBLE (`d1..d5`) and SYMBOL (`s1..s5`)
/// columns on top of the S1 five.
pub const N_WIDE_DOUBLES: usize = 5;
pub const N_WIDE_SYMS: usize = 5;

impl SchemaKind {
    /// Parse the `SCHEMA` env knob; `None` for an unknown value.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "s1-narrow" => Some(SchemaKind::S1Narrow),
            "s2-wide" => Some(SchemaKind::S2Wide),
            _ => None,
        }
    }

    /// Contract `schema` field / `--schema` value.
    pub fn name(self) -> &'static str {
        match self {
            SchemaKind::S1Narrow => "s1-narrow",
            SchemaKind::S2Wide => "s2-wide",
        }
    }

    /// Table name — matches the Python `_bench_table_name`
    /// (`bench_{schema.replace('-','_')}`).
    pub fn table(self) -> &'static str {
        match self {
            SchemaKind::S1Narrow => "bench_s1_narrow",
            SchemaKind::S2Wide => "bench_s2_wide",
        }
    }

    /// Column count (the `columns` contract field).
    pub fn columns(self) -> usize {
        match self {
            SchemaKind::S1Narrow => 5,
            SchemaKind::S2Wide => 5 + N_WIDE_DOUBLES + N_WIDE_SYMS,
        }
    }

    pub fn is_wide(self) -> bool {
        matches!(self, SchemaKind::S2Wide)
    }

    /// `CREATE TABLE` matching the Python `SCHEMA_CREATE_SQL` (DEDUP UPSERT
    /// KEYS(ts) + designated `ts`; the high-card SYMBOLs get CAPACITY 200000
    /// to fit 100k distinct values per column with slack).
    pub fn create_table_sql(self) -> &'static str {
        match self {
            SchemaKind::S1Narrow => {
                "CREATE TABLE bench_s1_narrow (\
                    id LONG, price DOUBLE, sym SYMBOL, note VARCHAR, ts TIMESTAMP\
                 ) TIMESTAMP(ts) PARTITION BY HOUR WAL DEDUP UPSERT KEYS(ts)"
            }
            SchemaKind::S2Wide => {
                "CREATE TABLE bench_s2_wide (\
                    id LONG, price DOUBLE, sym SYMBOL, note VARCHAR, \
                    d1 DOUBLE, d2 DOUBLE, d3 DOUBLE, d4 DOUBLE, d5 DOUBLE, \
                    s1 SYMBOL CAPACITY 200000, s2 SYMBOL CAPACITY 200000, \
                    s3 SYMBOL CAPACITY 200000, s4 SYMBOL CAPACITY 200000, \
                    s5 SYMBOL CAPACITY 200000, ts TIMESTAMP\
                 ) TIMESTAMP(ts) PARTITION BY HOUR WAL DEDUP UPSERT KEYS(ts)"
            }
        }
    }

    /// Egress read-back projection — every column, designated `ts` first
    /// (full parity with the Python egress `SELECT *`).
    pub fn select_sql(self) -> &'static str {
        match self {
            SchemaKind::S1Narrow => "SELECT ts, id, price, sym, note FROM bench_s1_narrow",
            SchemaKind::S2Wide => {
                "SELECT ts, id, price, sym, note, \
                 d1, d2, d3, d4, d5, s1, s2, s3, s4, s5 FROM bench_s2_wide"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic value generators (mirror the Python make_s1_narrow /
// make_s2_wide field-for-field; see plan §3.1 / §8).
// ---------------------------------------------------------------------------

/// Number of distinct VARCHAR `note` templates (low cardinality so the cost
/// tracks length, not distinctness): `min(rows, 1024)`, at least 1. Matches
/// the Python `_build_note_series` (`range(min(rows, 1024) or 1)`).
pub fn note_template_count(rows: usize) -> usize {
    rows.clamp(1, 1024)
}

/// The `idx`-th ASCII VARCHAR `note` template, length ~`varchar_len`. Matches
/// `(f"note_{idx:03}_" * varchar_len)[:varchar_len]`.
pub fn note_template(idx: usize, varchar_len: usize) -> String {
    format!("note_{idx:03}_")
        .repeat(varchar_len)
        .chars()
        .take(varchar_len)
        .collect()
}

/// Value of the wide DOUBLE column `d{k}` (k in `1..=N_WIDE_DOUBLES`) for row
/// `i`: `i * (0.5 + k)`. Matches `indexes * (0.5 + d)` in `make_s2_wide`.
pub fn wide_double(i: usize, k: usize) -> f64 {
    i as f64 * (0.5 + k as f64)
}

/// Low-cardinality SYMBOL `sym` label for category `v`: `sym_{v:04}`.
pub fn sym_label(v: usize) -> String {
    format!("sym_{v:04}")
}

/// High-cardinality SYMBOL label for the 1-based column `col` (`s1..s5`),
/// category `v`: `s{col-1}_{v:06}`. The `col-1` prefix reproduces the Python
/// `make_s2_wide` enumerate offset (column `s1` carries `s0_…` categories), so
/// the symbol-dict bytes match across clients.
pub fn hi_sym_label(col: usize, v: usize) -> String {
    format!("s{}_{:06}", col - 1, v)
}

/// Precomputed pool of low-cardinality `sym` labels: `pool[v] ==
/// sym_label(v)`, so `pool[i % pool.len()]` reproduces the per-row
/// `sym_label(i % card)` call byte-for-byte. Built once outside the timed
/// loop -- per-row `format!` would otherwise be ~45% of a row-bench pass.
#[allow(dead_code)] // not every example that includes this module ingests
pub fn sym_pool(card: usize) -> Vec<String> {
    (0..card).map(sym_label).collect()
}

/// Precomputed pools for the high-cardinality s1..s5 SYMBOL labels, indexed
/// by 0-based wide-column position: `pools[col - 1][v] == hi_sym_label(col,
/// v)` for the 1-based `col` used by `hi_sym_label`.
#[allow(dead_code)]
pub fn hi_sym_pools(card: usize) -> Vec<Vec<String>> {
    (1..=N_WIDE_SYMS)
        .map(|col| (0..card).map(|v| hi_sym_label(col, v)).collect())
        .collect()
}

/// Contiguous per-sender row ranges tiling `[0, rows)` exactly: sender `k`
/// of `n` owns `[rows*k/n, rows*(k+1)/n)` (multiply-first integer math, so
/// the ranges never drift). Panics if the tiling invariants break — a bad
/// edit fails at startup instead of silently corrupting parity. Empty
/// ranges (when `n > rows`) are legal and loop as no-ops.
#[allow(dead_code)] // not every example that includes this module ingests
pub fn sender_ranges(rows: usize, senders: usize) -> Vec<(usize, usize)> {
    let n = senders.max(1);
    let ranges: Vec<(usize, usize)> = (0..n).map(|k| (rows * k / n, rows * (k + 1) / n)).collect();
    assert_eq!(ranges[0].0, 0, "first range must start at 0");
    assert_eq!(ranges[n - 1].1, rows, "last range must end at rows");
    for pair in ranges.windows(2) {
        assert_eq!(pair[0].1, pair[1].0, "ranges must tile without gaps");
    }
    ranges
}
