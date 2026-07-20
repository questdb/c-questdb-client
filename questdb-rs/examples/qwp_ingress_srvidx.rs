//! srv-covidx campaign load generator (doc/net_bench/SRV_COVIDX_PLAN.md).
//!
//! Ingests the campaign's narrow 3-column schema (`bench_s3_cov` /
//! `bench_s3_plain`) with zipfian symbols and 1k-row transactions, one WAL
//! txn per flush (row path never defers commits). Unlike the client benches
//! this one measures the **server**: every pass runs against a fresh table
//! and reports both flush-ack wall ("srvidx-flush") and WAL-applied wall
//! ("srvidx-applied", flush + `wal_tables()` drain).
//!
//! Env knobs:
//!   VARIANT=cov|plain        table variant (default cov)
//!   ROWS=10000000            rows per pass
//!   SENDERS=1                connections; round-robin row split (i % n == k)
//!   MAX_BATCH_ROWS=1000      rows per flush == rows per WAL txn
//!   ITERATIONS=5  WARMUPS=2  CHECKPOINT_BATCHES=64
//!   RUN_MODE=e2e|selftest    selftest = generator invariants only, no server
//!   QDB_HOST=127.0.0.1  QDB_PORT=9000  QDB_CONF_EXTRA=
//!   SEED_BASE=42             pass p uses seed SEED_BASE + p
//!   DRAIN_DEADLINE_S=900       per-pass WAL drain deadline (raise for growth runs)

use std::error::Error;
use std::time::{Duration, Instant};

use questdb::ingress::{AckLevel, Buffer, Sender, TimestampNanos};

mod bench_json;
mod bench_srvidx;
use bench_json::{Env, PathSummary, Report};
use bench_srvidx::Variant;

/// Ack-checkpoint cadence (per-sender own batches), same default as the
/// row bench.
const DEFAULT_CHECKPOINT_BATCHES: usize = 64;
/// `Sender::wait` no-progress deadline (not a total-time cap).
const WAIT_TIMEOUT: Duration = Duration::from_secs(120);

struct SrvIdxCtx<'a> {
    variant: Variant,
    rows: usize,
    senders_n: usize,
    max_batch_rows: usize,
    checkpoint_batches: usize,
    cdf: &'a [f64],
    pool: &'a [String],
    /// WAL drain deadline per pass. Generous by default: at rig scale the
    /// backlog after a burst pass can take minutes to apply.
    drain_deadline: Duration,
}

/// Append sender `k`'s owned rows with owned-index `j` in `[lo, hi)` —
/// global row `i = k + j*n`. Symbols before columns (row-API ordering),
/// designated ts last.
fn fill_sender_batch(
    buffer: &mut Buffer,
    ctx: &SrvIdxCtx,
    seed: u64,
    k: usize,
    lo: usize,
    hi: usize,
) -> Result<(), Box<dyn Error>> {
    let table = ctx.variant.table();
    let n = ctx.senders_n;
    for j in lo..hi {
        let i = (k + j * n) as u64;
        buffer.table(table)?;
        buffer.symbol(
            "symbol",
            ctx.pool[bench_srvidx::row_sym_index(ctx.cdf, seed, i)].as_str(),
        )?;
        buffer.column_f32("value", bench_srvidx::row_value_f32(seed, i))?;
        buffer.at(TimestampNanos::new(bench_srvidx::row_ts_nanos(i)))?;
    }
    Ok(())
}

/// One flush pass: every sender thread walks its own arithmetic row
/// sequence in `max_batch_rows` chunks; **each flush is one WAL txn** (the
/// row path never defers commits). Ack checkpoint every
/// `checkpoint_batches` own batches + a final wait.
fn flush_pass(
    senders: &mut [Sender],
    buffers: &mut [Buffer],
    ctx: &SrvIdxCtx,
    seed: u64,
) -> Result<(), Box<dyn Error>> {
    std::thread::scope(|scope| -> Result<(), String> {
        let mut handles = Vec::with_capacity(senders.len());
        for (k, (sender, buffer)) in senders.iter_mut().zip(buffers.iter_mut()).enumerate() {
            handles.push(scope.spawn(move || -> Result<(), String> {
                let owned = bench_srvidx::sender_owned_rows(ctx.rows, ctx.senders_n, k);
                let mut lo = 0usize;
                let mut batch_no = 0usize;
                while lo < owned {
                    let hi = (lo + ctx.max_batch_rows).min(owned);
                    fill_sender_batch(buffer, ctx, seed, k, lo, hi).map_err(|e| e.to_string())?;
                    sender
                        .flush_and_get_fsn(buffer)
                        .map_err(|e| e.to_string())?;
                    batch_no += 1;
                    if batch_no.is_multiple_of(ctx.checkpoint_batches) {
                        sender
                            .wait(AckLevel::Ok, WAIT_TIMEOUT)
                            .map_err(|e| e.to_string())?;
                    }
                    lo = hi;
                }
                sender
                    .wait(AckLevel::Ok, WAIT_TIMEOUT)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }));
        }
        for h in handles {
            h.join()
                .map_err(|_| "sender thread panicked".to_string())??;
        }
        Ok(())
    })?;
    Ok(())
}

/// Expected WAL txn count for one pass: each sender commits one txn per
/// flushed batch.
fn expected_txns(rows: usize, senders_n: usize, max_batch_rows: usize) -> u64 {
    (0..senders_n)
        .map(|k| {
            bench_srvidx::sender_owned_rows(rows, senders_n, k).div_ceil(max_batch_rows) as u64
        })
        .sum()
}

// --- HTTP/SQL helpers (same shape as qwp_ingress_row.rs's; each QWP bench
// example carries its own copy) ---

fn http_base(host: &str, port: u16) -> String {
    format!("http://{host}:{port}")
}

fn exec_sql(base: &str, sql: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("{base}/exec");
    let mut resp = ureq::get(&url).query("query", sql).call()?;
    if resp.status() != 200 {
        return Err(format!("/exec {sql} -> HTTP {}", resp.status()).into());
    }
    Ok(resp.body_mut().read_to_string()?)
}

/// First dataset row of a two-BIGINT projection: `"dataset":[[a,b]...`.
fn parse_two_longs(body: &str) -> Option<(i64, i64)> {
    let idx = body.rfind("\"dataset\":[[")?;
    let tail = &body[idx + "\"dataset\":[[".len()..];
    let end = tail.find(']')?;
    let mut it = tail[..end].split(',');
    let a = it.next()?.trim().parse().ok()?;
    let b = it.next()?.trim().parse().ok()?;
    Some((a, b))
}

/// Poll `wal_tables()` until writerTxn == sequencerTxn for `table`.
/// Returns (drain_wall_ns, final sequencerTxn).
fn wait_for_drain(
    base: &str,
    table: &str,
    deadline_cap: Duration,
) -> Result<(u64, i64), Box<dyn Error>> {
    let sql = format!("SELECT writerTxn, sequencerTxn FROM wal_tables() WHERE name = '{table}'");
    let t0 = Instant::now();
    let deadline = t0 + deadline_cap;
    loop {
        let body = exec_sql(base, &sql)?;
        match parse_two_longs(&body) {
            Some((w, s)) if w >= s && s > 0 => {
                return Ok((t0.elapsed().as_nanos() as u64, s));
            }
            Some(_) => {}
            None => return Err(format!("{table} missing from wal_tables(): {body}").into()),
        }
        if Instant::now() >= deadline {
            return Err(
                format!("WAL drain deadline ({deadline_cap:?}) exceeded for {table}").into(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// One-shot exact count (called only after a successful drain, so no
/// polling loop is needed).
fn table_count(base: &str, table: &str) -> Result<u64, Box<dyn Error>> {
    let body = exec_sql(base, &format!("SELECT count(), 0 FROM {table}"))?;
    let (c, _) = parse_two_longs(&body).ok_or("count parse failed")?;
    Ok(c as u64)
}

fn recreate_table(base: &str, variant: Variant) -> Result<(), Box<dyn Error>> {
    exec_sql(base, &format!("DROP TABLE IF EXISTS {}", variant.table()))?;
    exec_sql(base, variant.create_sql())?;
    Ok(())
}

fn timed<T>(f: &mut impl FnMut() -> T) -> (u64, u64, T) {
    let cpu0 = bench_json::process_cpu_ns();
    let t0 = Instant::now();
    let out = f();
    let wall = t0.elapsed().as_nanos() as u64;
    let cpu = bench_json::process_cpu_ns().saturating_sub(cpu0);
    (wall, cpu, out)
}

struct PassResult {
    flush_wall: u64,
    flush_cpu: u64,
    drain_wall: u64,
    seq_txn: i64,
    count: u64,
}

/// One full pass: fresh table -> fresh senders -> timed flush -> drain poll
/// -> exact count. The HTTP calls between the flush and drain measurements
/// cost ~ms and are negligible against multi-second passes.
///
/// Senders and buffers are constructed fresh **per pass** (outside the timed
/// region): a connection's QWP schema state does not survive DROP+CREATE of
/// a same-named table — with persistent senders the first batch per sender
/// after recreation is acked Ok yet silently lost (tracked separately).
/// Connection setup stays outside the timed region regardless.
fn run_pass(
    base: &str,
    conf: &str,
    ctx: &SrvIdxCtx,
    seed: u64,
) -> Result<PassResult, Box<dyn Error>> {
    recreate_table(base, ctx.variant)?;
    let mut senders: Vec<Sender> = (0..ctx.senders_n)
        .map(|_| Sender::from_conf(conf))
        .collect::<Result<_, _>>()?;
    let mut buffers: Vec<Buffer> = senders.iter().map(|s| s.new_buffer()).collect();
    let (flush_wall, flush_cpu, r) =
        timed(&mut || flush_pass(&mut senders, &mut buffers, ctx, seed));
    r?;
    let (drain_wall, seq_txn) = wait_for_drain(base, ctx.variant.table(), ctx.drain_deadline)?;
    let count = table_count(base, ctx.variant.table())?;
    Ok(PassResult {
        flush_wall,
        flush_cpu,
        drain_wall,
        seq_txn,
        count,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "e2e".into());
    if run_mode == "selftest" {
        bench_srvidx::selftest().map_err(|e| format!("selftest FAILED: {e}"))?;
        println!("{{\"selftest\":\"ok\"}}");
        return Ok(());
    }

    let variant_name = std::env::var("VARIANT").unwrap_or_else(|_| "cov".into());
    let variant = Variant::parse(&variant_name)
        .ok_or_else(|| format!("unknown VARIANT={variant_name} (want cov | plain)"))?;
    let rows: usize = env_usize("ROWS", 10_000_000);
    let senders_n: usize = env_usize("SENDERS", 1).max(1);
    let max_batch_rows: usize = env_usize("MAX_BATCH_ROWS", 1_000);
    let iterations: usize = env_usize("ITERATIONS", 5);
    let warmups: usize = env_usize("WARMUPS", 2);
    let checkpoint_batches: usize = env_usize("CHECKPOINT_BATCHES", DEFAULT_CHECKPOINT_BATCHES);
    let seed_base: u64 = env_usize("SEED_BASE", bench_srvidx::SEED_BASE as usize) as u64;
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = env_usize("QDB_PORT", 9000) as u16;

    eprintln!(
        "[qwp_ingress_srvidx] variant={} rows={rows} senders={senders_n} \
         batch={max_batch_rows} iterations={iterations} warmups={warmups}",
        variant.name()
    );

    let cdf = bench_srvidx::build_zipf_cdf(bench_srvidx::SYM_CARD, bench_srvidx::ZIPF_S);
    let pool = bench_srvidx::sym_pool();
    let ctx = SrvIdxCtx {
        variant,
        rows,
        senders_n,
        max_batch_rows,
        checkpoint_batches,
        cdf: &cdf,
        pool: &pool,
        drain_deadline: Duration::from_secs(env_usize("DRAIN_DEADLINE_S", 900) as u64),
    };

    let base = http_base(&host, port);
    let conf_extra = std::env::var("QDB_CONF_EXTRA").unwrap_or_default();
    let conf = format!("ws::addr={host}:{port};{conf_extra}");

    let want_txns = expected_txns(rows, senders_n, max_batch_rows);
    let mut flush_walls = Vec::with_capacity(iterations);
    let mut flush_cpus = Vec::with_capacity(iterations);
    let mut applied_walls = Vec::with_capacity(iterations);
    let mut drain_walls = Vec::with_capacity(iterations);
    let mut count_ok = true;
    let mut txn_ok = true;
    let mut last_count = 0u64;
    let mut last_txns = 0i64;

    for p in 0..(warmups + iterations) {
        let seed = seed_base + p as u64;
        let label = if p < warmups { "warmup" } else { "pass" };
        eprintln!("[qwp_ingress_srvidx] {label} {p} (seed {seed}) ...");
        let pr = run_pass(&base, &conf, &ctx, seed)?;
        eprintln!(
            "[qwp_ingress_srvidx] {label} {p}: flush {:.3}s drain {:.3}s txns {} count {}",
            pr.flush_wall as f64 / 1e9,
            pr.drain_wall as f64 / 1e9,
            pr.seq_txn,
            pr.count
        );
        count_ok &= pr.count == rows as u64;
        txn_ok &= pr.seq_txn == want_txns as i64;
        last_count = pr.count;
        last_txns = pr.seq_txn;
        if p >= warmups {
            flush_walls.push(pr.flush_wall);
            flush_cpus.push(pr.flush_cpu);
            applied_walls.push(pr.flush_wall + pr.drain_wall);
            drain_walls.push(pr.drain_wall);
        }
    }

    let mut report = Report::new(variant.name(), rows, 3, "ingress", "rust-srvidx", &run_mode);
    report.warmups = warmups;
    report.senders = senders_n;
    report.env = Env::collect(&[]);
    report.add_path(
        "srvidx-flush",
        PathSummary::new(
            &flush_walls,
            &flush_cpus,
            rows,
            3,
            "e2e",
            warmups > 0,
            Some(0),
        ),
    );
    report.add_path(
        "srvidx-applied",
        PathSummary::new(
            &applied_walls,
            &flush_cpus,
            rows,
            3,
            "e2e",
            warmups > 0,
            Some(0),
        ),
    );
    // Drain-only path: rows/drain_s = the server's backlog-apply rate.
    let zeros = vec![0u64; drain_walls.len()];
    report.add_path(
        "srvidx-drain",
        PathSummary::new(&drain_walls, &zeros, rows, 3, "e2e", warmups > 0, Some(0)),
    );
    report.row_count_check = Some(bench_json::RowCountCheck {
        expected: rows as u64,
        actual: last_count,
        ok: count_ok,
        inflated: last_count > rows as u64,
    });
    report.txn_check = Some(bench_json::TxnCheck {
        expected: want_txns,
        actual: last_txns.max(0) as u64,
        ok: txn_ok,
    });
    report.real_conf = Some(conf);
    report.http_base = Some(base);
    report.compute_srvidx_headline(max_batch_rows);
    println!("{}", report.into_json());

    if count_ok && txn_ok {
        Ok(())
    } else {
        eprintln!(
            "[qwp_ingress_srvidx] GATE FAILURE: count_ok={count_ok} txn_ok={txn_ok} \
             (count {last_count}/{rows}, txns {last_txns}/{want_txns})"
        );
        std::process::exit(2);
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
