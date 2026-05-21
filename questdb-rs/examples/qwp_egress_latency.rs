//! Rust counterpart to QwpEgressLatencyBenchmark (Java JMH).
//!
//! Measures wall-clock latency of a single SELECT against a QuestDB server
//! running locally, excluding connection setup. The Reader is opened once and
//! every benchmarked invocation reuses it.
//!
//! Run with:
//!     cargo run --release --example qwp_egress_latency \
//!         --features sync-reader-ws -- [SQL]
//!
//! The default SQL is `SELECT 1`, matching the Java benchmark's default.
//! Warmup: 5 iterations x 2s. Measurement: 10 iterations x 2s. Single thread.

use questdb::egress::reader::Reader;
use std::time::{Duration, Instant};

fn main() {
    let sql: String = std::env::args().nth(1).unwrap_or_else(|| "SELECT 1".into());
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "localhost".into());
    let port: u16 = std::env::var("QDB_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000);

    let conf = format!("ws::addr={host}:{port};");
    let mut reader = Reader::from_conf(&conf).expect("connect");
    println!("connected to {host}:{port}, sql = {sql:?}");

    // Prime the codec (first execute() allocates scratch + registers schema).
    drain(&mut reader, &sql);

    // Warmup
    let warmup_iters = 5;
    let warmup_dur = Duration::from_secs(2);
    for i in 0..warmup_iters {
        let (count, mean_ns) = run_iteration(&mut reader, &sql, warmup_dur);
        println!(
            "warmup  {:>2}/{}  n={:>7}  mean={:>7.2}us",
            i + 1,
            warmup_iters,
            count,
            mean_ns / 1_000.0
        );
    }

    // Measurement: collect every sample for percentile reporting.
    let meas_iters = 10;
    let meas_dur = Duration::from_secs(2);
    let mut samples: Vec<u64> = Vec::with_capacity(2_000_000);
    for i in 0..meas_iters {
        let before = samples.len();
        let iter_mean = collect_iteration(&mut reader, &sql, meas_dur, &mut samples);
        let n = samples.len() - before;
        println!(
            "measure {:>2}/{}  n={:>7}  mean={:>7.2}us",
            i + 1,
            meas_iters,
            n,
            iter_mean / 1_000.0
        );
    }

    report(&mut samples);
}

/// Run the query and discard every batch + the terminal frame.
fn drain(reader: &mut Reader, sql: &str) {
    let mut cur = reader.prepare(sql).execute().expect("execute");
    while cur.next_batch().expect("next_batch").is_some() {}
}

/// Run as many queries as fit in `dur`. Return (count, mean_ns).
fn run_iteration(reader: &mut Reader, sql: &str, dur: Duration) -> (u64, f64) {
    let start = Instant::now();
    let mut count: u64 = 0;
    let mut total_ns: u128 = 0;
    while start.elapsed() < dur {
        let t0 = Instant::now();
        drain(reader, sql);
        total_ns += t0.elapsed().as_nanos();
        count += 1;
    }
    let mean = if count == 0 {
        0.0
    } else {
        total_ns as f64 / count as f64
    };
    (count, mean)
}

/// Same as [`run_iteration`] but stores every per-call latency in nanoseconds.
fn collect_iteration(reader: &mut Reader, sql: &str, dur: Duration, out: &mut Vec<u64>) -> f64 {
    let start = Instant::now();
    let before = out.len();
    let mut total_ns: u128 = 0;
    while start.elapsed() < dur {
        let t0 = Instant::now();
        drain(reader, sql);
        let ns = t0.elapsed().as_nanos() as u64;
        out.push(ns);
        total_ns += ns as u128;
    }
    let n = (out.len() - before) as u128;
    if n == 0 {
        0.0
    } else {
        total_ns as f64 / n as f64
    }
}

fn report(samples: &mut [u64]) {
    if samples.is_empty() {
        println!("no samples collected");
        return;
    }
    samples.sort_unstable();
    let n = samples.len();
    let mean_ns = samples.iter().copied().map(u128::from).sum::<u128>() as f64 / n as f64;
    let pct = |p: f64| -> u64 {
        let idx = ((n as f64 - 1.0) * p).round() as usize;
        samples[idx]
    };
    let us = |ns: f64| ns / 1_000.0;
    println!();
    println!("--- summary (microseconds) ---");
    println!("samples : {n}");
    println!("mean    : {:>8.2}", us(mean_ns));
    println!("min     : {:>8.2}", us(samples[0] as f64));
    println!("p50     : {:>8.2}", us(pct(0.50) as f64));
    println!("p90     : {:>8.2}", us(pct(0.90) as f64));
    println!("p99     : {:>8.2}", us(pct(0.99) as f64));
    println!("p99.9   : {:>8.2}", us(pct(0.999) as f64));
    println!("p99.99  : {:>8.2}", us(pct(0.9999) as f64));
    println!("max     : {:>8.2}", us(samples[n - 1] as f64));
}
