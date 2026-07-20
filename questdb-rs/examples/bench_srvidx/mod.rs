//! Data contract for the srv-covidx server campaign
//! (doc/net_bench/SRV_COVIDX_PLAN.md). Campaign-specific and single-client,
//! so it lives beside — not inside — the cross-client `bench_schema`
//! parity module. Kept dependency-light and outside Cargo's example
//! auto-discovery (subdirectory + `mod.rs`, like `bench_json`).
//!
//! Everything is stateless in the global row index `i`: `f(seed, i)`
//! generators mean the dataset is byte-identical for every sender count.

#![allow(dead_code)]

/// Symbol cardinality (spec: ~2k unique symbols).
pub const SYM_CARD: usize = 2000;
/// Zipf rank-frequency exponent: over 2k ranks gives a ~2000:1
/// hottest:coldest ratio, matching the field-reported per-symbol spread.
pub const ZIPF_S: f64 = 1.0;
/// 2026-01-01T00:00:00Z in ns.
pub const TS_BASE_NANOS: i64 = 1_767_225_600_000_000_000;
/// Reference data density: ~185k rows per data-second -> ~660M rows per
/// hourly partition.
pub const TS_STEP_NANOS: i64 = 5405;
/// Pass p (warmups + iterations counted together, from 0) seeds its
/// generators with SEED_BASE + p.
pub const SEED_BASE: u64 = 42;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    Cov,
    Plain,
}

impl Variant {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "cov" => Some(Variant::Cov),
            "plain" => Some(Variant::Plain),
            _ => None,
        }
    }

    /// Report `schema` field.
    pub fn name(self) -> &'static str {
        match self {
            Variant::Cov => "s3-cov",
            Variant::Plain => "s3-plain",
        }
    }

    pub fn table(self) -> &'static str {
        match self {
            Variant::Cov => "bench_s3_cov",
            Variant::Plain => "bench_s3_plain",
        }
    }

    /// Spec DDL verbatim: no DEDUP, no CAPACITY, no PARQUET hints; WAL by
    /// server default for partitioned tables.
    pub fn create_sql(self) -> &'static str {
        match self {
            Variant::Cov => {
                "CREATE TABLE bench_s3_cov (\
                    timestamp TIMESTAMP_NS, \
                    symbol SYMBOL INDEX TYPE POSTING INCLUDE (value, timestamp), \
                    value FLOAT\
                 ) TIMESTAMP(timestamp) PARTITION BY HOUR"
            }
            Variant::Plain => {
                "CREATE TABLE bench_s3_plain (\
                    timestamp TIMESTAMP_NS, symbol SYMBOL, value FLOAT\
                 ) TIMESTAMP(timestamp) PARTITION BY HOUR"
            }
        }
    }
}

// --- generators -------------------------------------------------------------

/// SplitMix64 finalizer — the classic constants. Used as a stateless hash:
/// callers pass `seed ^ (i * GOLDEN)` style inputs.
pub fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Stateless per-row hash: decorrelates `i` with the golden ratio before
/// mixing so `f(seed, i)` and `f(seed, i+1)` share no low-bit structure.
fn row_hash(seed: u64, i: u64) -> u64 {
    splitmix64(seed ^ i.wrapping_mul(0x9E37_79B9_7F4A_7C15))
}

/// Top 53 bits -> uniform f64 in [0, 1).
fn unit_f64(h: u64) -> f64 {
    (h >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
}

/// Normalized zipf CDF over ranks 1..=card with weight 1/rank^s.
/// `cdf[r]` = P(rank <= r+1); last entry pinned to exactly 1.0 so a
/// `partition_point` lookup can never fall off the end.
pub fn build_zipf_cdf(card: usize, s: f64) -> Vec<f64> {
    assert!(card > 0);
    let mut cdf = Vec::with_capacity(card);
    let mut acc = 0.0f64;
    for r in 1..=card {
        acc += 1.0 / (r as f64).powf(s);
        cdf.push(acc);
    }
    for c in cdf.iter_mut() {
        *c /= acc;
    }
    *cdf.last_mut().unwrap() = 1.0;
    cdf
}

/// Symbol labels `sym0000`..`sym1999`, rank order == pool order (rank 0 is
/// the hottest symbol).
pub fn sym_pool() -> Vec<String> {
    (0..SYM_CARD).map(|v| format!("sym{v:04}")).collect()
}

/// Zipf-distributed symbol index for global row `i`.
pub fn row_sym_index(cdf: &[f64], seed: u64, i: u64) -> usize {
    let u = unit_f64(row_hash(seed, i));
    cdf.partition_point(|&c| c <= u).min(cdf.len() - 1)
}

/// Uniform f32 in [0, 1) for global row `i`, independent of the symbol
/// stream (second mix round). Built from 24 explicit bits — an f64->f32
/// downcast would round draws in [1 - 2^-25, 1) up to exactly 1.0f32
/// (~once per 33.5M rows), breaking the half-open contract.
pub fn row_value_f32(seed: u64, i: u64) -> f32 {
    (splitmix64(row_hash(seed, i)) >> 40) as f32 * (1.0 / (1u64 << 24) as f32)
}

/// Designated timestamp for global row `i`: strictly ascending at the
/// reference data density.
pub fn row_ts_nanos(i: u64) -> i64 {
    TS_BASE_NANOS + i as i64 * TS_STEP_NANOS
}

/// Rows owned by sender `k` of `senders` under the round-robin split
/// (`i % senders == k` over `[0, rows)`).
pub fn sender_owned_rows(rows: usize, senders: usize, k: usize) -> usize {
    let n = senders.max(1);
    if k >= rows { 0 } else { (rows - k).div_ceil(n) }
}

// --- selftest -------------------------------------------------------------

/// Generator invariants, runnable with no server (`RUN_MODE=selftest`).
/// String errors so the example can print one line and exit non-zero.
pub fn selftest() -> Result<(), String> {
    // DDL / naming.
    if Variant::parse("cov") != Some(Variant::Cov) || Variant::parse("bogus").is_some() {
        return Err("Variant::parse".into());
    }
    if Variant::Cov.table() != "bench_s3_cov" || Variant::Plain.name() != "s3-plain" {
        return Err("Variant naming".into());
    }
    if !Variant::Cov
        .create_sql()
        .contains("INDEX TYPE POSTING INCLUDE (value, timestamp)")
    {
        return Err("cov DDL lost the covering-index clause".into());
    }
    if Variant::Plain.create_sql().contains("INDEX") {
        return Err("plain DDL must not declare an index".into());
    }

    // CDF shape.
    let cdf = build_zipf_cdf(SYM_CARD, ZIPF_S);
    if cdf.len() != SYM_CARD {
        return Err(format!("cdf len {} != {SYM_CARD}", cdf.len()));
    }
    if *cdf.last().unwrap() != 1.0 {
        return Err("cdf must end exactly at 1.0".into());
    }
    for w in cdf.windows(2) {
        if w[1] <= w[0] {
            return Err("cdf must be strictly increasing".into());
        }
    }
    // s=1.0 over 2000 ranks: hottest/coldest weight ratio == 2000.
    let w_first = cdf[0];
    let w_last = cdf[SYM_CARD - 1] - cdf[SYM_CARD - 2];
    let ratio = w_first / w_last;
    if !(1999.0..=2001.0).contains(&ratio) {
        return Err(format!("hottest:coldest ratio {ratio:.2}, want ~2000"));
    }

    // Determinism (stateless in i).
    if row_sym_index(&cdf, 42, 7) != row_sym_index(&cdf, 42, 7)
        || row_value_f32(42, 7) != row_value_f32(42, 7)
    {
        return Err("generators must be deterministic".into());
    }
    if row_sym_index(&cdf, 42, 7) == row_sym_index(&cdf, 43, 7)
        && row_sym_index(&cdf, 42, 8) == row_sym_index(&cdf, 43, 8)
        && row_sym_index(&cdf, 42, 9) == row_sym_index(&cdf, 43, 9)
    {
        return Err("different seeds should not produce identical streams".into());
    }

    // Distribution sanity on 100k samples: rank-0 frequency ~= cdf[0]
    // (~12.2% for s=1, K=2000), and near-full symbol coverage.
    let n = 100_000u64;
    let mut counts = vec![0u32; SYM_CARD];
    for i in 0..n {
        counts[row_sym_index(&cdf, SEED_BASE, i)] += 1;
    }
    let f0 = counts[0] as f64 / n as f64;
    if !(0.10..=0.14).contains(&f0) {
        return Err(format!("rank-0 frequency {f0:.4}, want ~{:.4}", cdf[0]));
    }
    let distinct = counts.iter().filter(|&&c| c > 0).count();
    if distinct < 1900 {
        return Err(format!(
            "only {distinct}/{SYM_CARD} symbols sampled in 100k rows"
        ));
    }
    // Values in [0, 1).
    for i in 0..1000u64 {
        let v = row_value_f32(SEED_BASE, i);
        if !(0.0..1.0).contains(&v) {
            return Err(format!("value {v} out of [0,1)"));
        }
    }

    // Regression: these indices produced exactly 1.0f32 under the old
    // f64->f32 downcast implementation (seed 42).
    for &i in &[11_072_017u64, 36_492_305u64] {
        let v = row_value_f32(42, i);
        if !(0.0..1.0).contains(&v) {
            return Err(format!(
                "value {v} at i={i} out of [0,1) (downcast regression)"
            ));
        }
    }

    // Timestamps: exact base and step on the global index.
    if row_ts_nanos(0) != TS_BASE_NANOS || row_ts_nanos(1) - row_ts_nanos(0) != TS_STEP_NANOS {
        return Err("ts base/step broken".into());
    }

    // Round-robin ownership tiles [0, rows) exactly, odd splits included.
    for &(rows, n) in &[(10usize, 4usize), (100_000, 2), (1_000_003, 7), (5, 8)] {
        let total: usize = (0..n).map(|k| sender_owned_rows(rows, n, k)).sum();
        if total != rows {
            return Err(format!("ownership sum {total} != rows {rows} (n={n})"));
        }
    }
    if sender_owned_rows(10, 4, 0) != 3 || sender_owned_rows(10, 4, 3) != 2 {
        return Err("ownership counts wrong for rows=10 n=4".into());
    }

    // Label pool.
    let pool = sym_pool();
    if pool.len() != SYM_CARD || pool[0] != "sym0000" || pool[1999] != "sym1999" {
        return Err("sym_pool naming".into());
    }

    Ok(())
}
