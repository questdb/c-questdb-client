//! Task 7 (docs/superpowers/plans/2026-07-13-java-qwp-bench.md) — Rust
//! **row-API** QWP ingress bench, the row-major counterpart to
//! `qwp_ingress_polars.rs`'s column-major DataFrame path. Mirrors the
//! cadence of the C twin's `ingest_pass()` (`examples/bench_ingest_c.c`):
//! append `MAX_BATCH_ROWS` rows per batch, then either clear (floor,
//! `row-build`) or flush + ack-checkpoint every 64 batches (e2e,
//! `row-flush`).
//!
//! Reuses the shared `bench_schema` value generators and `bench_json`
//! report helpers from `qwp_ingress_polars.rs` so the row-API path puts
//! byte-identical schema data on the wire and emits the same §3.2 JSON
//! contract shape (`client="rust-row"`, `direction="ingress"`).
//!
//! * **`row-build`** (floor, no network): appends each batch to a
//!   standalone [`questdb::ingress::Buffer`] built via
//!   [`questdb::ingress::Buffer::new_qwp_ws`] — no [`questdb::ingress::Sender`]
//!   or socket involved — then [`questdb::ingress::Buffer::clear`]s it. Never
//!   flushed.
//! * **`row-flush`** (e2e): same appends, but each batch is published with
//!   [`questdb::ingress::Sender::flush_and_get_fsn`]; every 64 batches (and
//!   once more after the loop) [`questdb::ingress::Sender::wait`] blocks for
//!   [`questdb::ingress::AckLevel::Ok`] coverage, matching the C twin's
//!   `commit(ok)` checkpoint.
//!
//! Run against a QWP-schema-0x3 QuestDB with QWP/WS + HTTP on :9000:
//!
//! ```bash
//! cargo run --release --example qwp_ingress_row \
//!     --features sync-sender-qwp-ws,sync-sender-http
//! ```
//!
//! Env knobs (parity with `qwp_ingress_polars`):
//!   SCHEMA=s1-narrow         scenario (s1-narrow | s2-wide)
//!   ROWS=10000000            headline row count (default 10M)
//!   QUESTDB_COLUMN_BENCH_SYM_CARD=8        low-card SYMBOL cardinality
//!   QUESTDB_COLUMN_BENCH_VARCHAR_LEN=16    VARCHAR byte length
//!   HI_SYM_CARD=100000       s2-wide high-card SYMBOL s1..s5 (uniform)
//!   ITERATIONS=5  WARMUPS=2  MAX_BATCH_ROWS=10000  RUN_MODE=full
//!   QDB_HOST=127.0.0.1  QDB_PORT=9000
//!
//! **Auto-flush knob finding**: unlike the Java client (whose row `Sender`
//! auto-flushes by default and needs `auto_flush=off` in the connect string
//! to get manual-only control), this Rust client's row-API `Sender`/`Buffer`
//! has **no auto-flush capability at all** — `flush`/`flush_and_get_fsn` are
//! the only ways a buffer is ever published (`src/ingress/sender.rs`).
//! `validate_auto_flush_params` (`src/ingress.rs`) only *validates* an
//! `auto_flush` connect-string key (rejecting anything but `"off"`); it never
//! stores or acts on the value. So no explicit auto-flush-off knob is set
//! here — the connect string is the minimal `ws::addr={host}:{port};`.

use std::error::Error;
use std::time::{Duration, Instant};

use questdb::ingress::{AckLevel, Buffer, Sender, TimestampNanos};

mod bench_json;
mod bench_schema;
use bench_json::{Env, PathSummary, Report};
use bench_schema::{N_WIDE_DOUBLES, N_WIDE_SYMS, SchemaKind};

/// µs spacing for the designated timestamp: same constants as
/// `qwp_ingress_polars.rs` so the two examples' `ts` values line up
/// row-for-row over identical `SCHEMA`/`ROWS`.
const TS_STEP_NANOS: i64 = 1_000;
const TS_BASE_NANOS: i64 = 1_704_067_200_000_000_000;

/// Ack-checkpoint cadence for the e2e `row-flush` path — matches
/// `CHECKPOINT_BATCHES` in `examples/bench_ingest_c.h`.
const CHECKPOINT_BATCHES: usize = 64;

/// No-progress deadline for `Sender::wait` — see `sender.rs:692`'s doc: it
/// only fires if the ack watermark stalls for this long, not a hard cap on
/// total wait time.
const WAIT_TIMEOUT: Duration = Duration::from_secs(120);

/// Static names for the S2-wide DOUBLE / SYMBOL columns, matching
/// `qwp_ingress_polars.rs`.
const D_NAMES: [&str; N_WIDE_DOUBLES] = ["d1", "d2", "d3", "d4", "d5"];
const S_NAMES: [&str; N_WIDE_SYMS] = ["s1", "s2", "s3", "s4", "s5"];

/// Parameters shared by the `row-build` and `row-flush` passes, bundled so
/// neither `fill_batch` nor the two `measure_*` functions need a long
/// positional argument list.
struct RowBenchCtx<'a> {
    kind: SchemaKind,
    rows: usize,
    sym_card: usize,
    hi_sym_card: usize,
    /// Precomputed VARCHAR `note` templates (`bench_schema::note_template`),
    /// cycled by `i % templates.len()` — identical values to the polars
    /// example's `note_values`.
    templates: &'a [String],
    max_batch_rows: usize,
}

/// Appends rows `[start, end)` to `buffer` in the schema's row-API column
/// order: symbols first (`sym`, then `s1..s5` for S2-wide), then
/// `id/price/note` (`d1..d5` for S2-wide), then the designated timestamp.
/// Shared by both passes so `row-build` and `row-flush` append
/// byte-identical rows — same values as `qwp_ingress_polars.rs`'s
/// `build_data`/`build_sym_col` (`sym_label(i % sym_card)`,
/// `hi_sym_label(col, i % hi_sym_card)`, `id = i`, `price = i * 0.25`,
/// `wide_double(i, k)`).
fn fill_batch(
    buffer: &mut Buffer,
    ctx: &RowBenchCtx,
    start: usize,
    end: usize,
) -> Result<(), Box<dyn Error>> {
    let table = ctx.kind.table();
    for i in start..end {
        buffer.table(table)?;
        buffer.symbol("sym", bench_schema::sym_label(i % ctx.sym_card))?;
        if ctx.kind.is_wide() {
            for (col, name) in S_NAMES.iter().enumerate() {
                buffer.symbol(
                    *name,
                    bench_schema::hi_sym_label(col + 1, i % ctx.hi_sym_card),
                )?;
            }
        }
        buffer.column_i64("id", i as i64)?;
        buffer.column_f64("price", i as f64 * 0.25)?;
        buffer.column_str("note", ctx.templates[i % ctx.templates.len()].as_str())?;
        if ctx.kind.is_wide() {
            for (k, name) in D_NAMES.iter().enumerate() {
                buffer.column_f64(*name, bench_schema::wide_double(i, k + 1))?;
            }
        }
        buffer.at(TimestampNanos::new(
            TS_BASE_NANOS + i as i64 * TS_STEP_NANOS,
        ))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/// Wall + process-CPU nanoseconds for one invocation of `f`. Same shape as
/// `qwp_ingress_polars.rs`'s `timed` helper.
fn timed<T>(f: &mut impl FnMut() -> T) -> (u64, u64, T) {
    let cpu0 = bench_json::process_cpu_ns();
    let t0 = Instant::now();
    let out = f();
    let wall = t0.elapsed().as_nanos() as u64;
    let cpu = bench_json::process_cpu_ns().saturating_sub(cpu0);
    (wall, cpu, out)
}

/// Floor `row-build`: append `max_batch_rows` rows per batch to a fresh,
/// standalone `Buffer` (`Buffer::new_qwp_ws()` — no `Sender`/socket
/// involved), then `Buffer::clear`; never flushed. Isolates the row-API
/// append cost with zero network participation, the row-major counterpart to
/// `qwp_ingress_polars.rs`'s column-major `encode-floor` path.
fn measure_row_build(
    ctx: &RowBenchCtx,
    iterations: usize,
    warmups: usize,
) -> Result<(Vec<u64>, Vec<u64>), Box<dyn Error>> {
    let mut buffer = Buffer::new_qwp_ws();
    let mut run = || -> Result<(), Box<dyn Error>> {
        let mut start = 0usize;
        while start < ctx.rows {
            let end = (start + ctx.max_batch_rows).min(ctx.rows);
            fill_batch(&mut buffer, ctx, start, end)?;
            buffer.clear();
            start = end;
        }
        Ok(())
    };
    for _ in 0..warmups {
        run()?;
    }
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (w, c, r) = timed(&mut run);
        r?;
        wall.push(w);
        cpu.push(c);
    }
    Ok((wall, cpu))
}

/// One e2e pass: every sender thread drives its own row range with the
/// single-sender cadence (flush per `max_batch_rows` batch, ack checkpoint
/// every `CHECKPOINT_BATCHES` of its OWN batches, final ack). Worker errors
/// are stringified so they can cross the thread boundary.
fn flush_pass(
    senders: &mut [Sender],
    buffers: &mut [Buffer],
    ctx: &RowBenchCtx,
    ranges: &[(usize, usize)],
) -> Result<(), Box<dyn Error>> {
    std::thread::scope(|scope| -> Result<(), String> {
        let mut handles = Vec::with_capacity(senders.len());
        for ((sender, buffer), &(lo, hi)) in
            senders.iter_mut().zip(buffers.iter_mut()).zip(ranges)
        {
            handles.push(scope.spawn(move || -> Result<(), String> {
                let mut start = lo;
                let mut batch_no = 0usize;
                while start < hi {
                    let end = (start + ctx.max_batch_rows).min(hi);
                    fill_batch(buffer, ctx, start, end).map_err(|e| e.to_string())?;
                    sender
                        .flush_and_get_fsn(buffer)
                        .map_err(|e| e.to_string())?;
                    batch_no += 1;
                    if batch_no % CHECKPOINT_BATCHES == 0 {
                        sender
                            .wait(AckLevel::Ok, WAIT_TIMEOUT)
                            .map_err(|e| e.to_string())?;
                    }
                    start = end;
                }
                sender
                    .wait(AckLevel::Ok, WAIT_TIMEOUT)
                    .map_err(|e| e.to_string())?;
                Ok(())
            }));
        }
        for h in handles {
            h.join().map_err(|_| "sender thread panicked".to_string())??;
        }
        Ok(())
    })?;
    Ok(())
}

/// e2e `row-flush` over `senders.len()` parallel connections (1 = classic
/// single-sender). Buffers are per-sender and reused across passes; sender
/// construction happens in `main`, outside every timed region.
fn measure_row_flush(
    senders: &mut [Sender],
    ctx: &RowBenchCtx,
    ranges: &[(usize, usize)],
    iterations: usize,
    warmups: usize,
) -> Result<(Vec<u64>, Vec<u64>), Box<dyn Error>> {
    let mut buffers: Vec<Buffer> = senders.iter().map(|s| s.new_buffer()).collect();
    for _ in 0..warmups {
        flush_pass(senders, &mut buffers, ctx, ranges)?;
    }
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (w, c, r) = timed(&mut || flush_pass(senders, &mut buffers, ctx, ranges));
        r?;
        wall.push(w);
        cpu.push(c);
    }
    Ok((wall, cpu))
}

// ---------------------------------------------------------------------------
// HTTP/SQL helpers (DEDUP table + WAL-aware count gate) — same shape as
// `qwp_ingress_polars.rs`'s helpers of the same name (no shared `bench_http`
// module exists in this codebase yet; every QWP bench example currently
// carries its own copy, see `qwp_egress_read.rs` / `qwp_egress_polars.rs` /
// `qwp_egress_read_wide.rs`).
// ---------------------------------------------------------------------------

fn http_base(host: &str, port: u16) -> String {
    format!("http://{host}:{port}")
}

fn exec_sql(base: &str, sql: &str) -> Result<(), Box<dyn Error>> {
    let url = format!("{base}/exec");
    let resp = ureq::get(&url).query("query", sql).call()?;
    if resp.status() != 200 {
        return Err(format!("/exec {sql} -> HTTP {}", resp.status()).into());
    }
    Ok(())
}

fn create_table(base: &str, kind: SchemaKind) -> Result<(), Box<dyn Error>> {
    exec_sql(base, &format!("DROP TABLE IF EXISTS {}", kind.table()))?;
    exec_sql(base, kind.create_table_sql())?;
    Ok(())
}

/// Poll `SELECT count()` until it reaches `expected` (WAL tables apply
/// asynchronously). Returns the final observed count. A value above
/// `expected` signals at-least-once DEDUP inflation (a failure).
fn wait_for_count(base: &str, table: &str, expected: u64) -> Result<u64, Box<dyn Error>> {
    let url = format!("{base}/exec");
    let sql = format!("SELECT count() FROM {table}");
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut last = 0u64;
    while Instant::now() < deadline {
        let mut resp = ureq::get(&url).query("query", &sql).call()?;
        let body: String = resp.body_mut().read_to_string()?;
        if let Some(idx) = body.rfind("\"dataset\":[[") {
            let tail = &body[idx + "\"dataset\":[[".len()..];
            if let Some(end) = tail.find(']')
                && let Ok(n) = tail[..end].parse::<u64>()
            {
                last = n;
                if n >= expected {
                    return Ok(n);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(last)
}

// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let schema_name = std::env::var("SCHEMA").unwrap_or_else(|_| "s1-narrow".into());
    let kind = SchemaKind::parse(&schema_name)
        .ok_or_else(|| format!("unknown SCHEMA={schema_name} (want s1-narrow | s2-wide)"))?;
    let columns = kind.columns();
    let table = kind.table();

    let rows: usize = env_usize("ROWS", 10_000_000);
    let sym_card: usize = env_usize("QUESTDB_COLUMN_BENCH_SYM_CARD", 8);
    let varchar_len: usize = env_usize("QUESTDB_COLUMN_BENCH_VARCHAR_LEN", 16);
    let hi_sym_card: usize = env_usize("HI_SYM_CARD", 100_000);
    let iterations: usize = env_usize("ITERATIONS", 5);
    let warmups: usize = env_usize("WARMUPS", 2);
    let max_batch_rows: usize = env_usize("MAX_BATCH_ROWS", 10_000);
    let senders_n: usize = env_usize("SENDERS", 1).max(1);
    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "full".into());
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = env_usize("QDB_PORT", 9000) as u16;

    eprintln!(
        "[qwp_ingress_row] schema={} rows={rows} columns={columns} sym_card={sym_card} \
         varchar_len={varchar_len} hi_sym_card={hi_sym_card} iterations={iterations} \
         warmups={warmups} max_batch_rows={max_batch_rows} senders={senders_n}",
        kind.name()
    );

    // Precompute VARCHAR note templates once — identical values to
    // `qwp_ingress_polars.rs`'s `note_values` (`templates[i % len]`).
    let template_count = bench_schema::note_template_count(rows);
    let templates: Vec<String> = (0..template_count)
        .map(|i| bench_schema::note_template(i, varchar_len))
        .collect();
    let ctx = RowBenchCtx {
        kind,
        rows,
        sym_card,
        hi_sym_card,
        templates: &templates,
        max_batch_rows,
    };

    let mut report = Report::new(kind.name(), rows, columns, "ingress", "rust-row", &run_mode);
    report.warmups = warmups;
    report.wire_bytes = 0;
    report.senders = senders_n;
    report.env = Env::collect(&[]);

    // --- Floor: row-build (no network). ---
    eprintln!("[qwp_ingress_row] measuring row-build floor ...");
    let (build_wall, build_cpu) = measure_row_build(&ctx, iterations, warmups)?;
    report.add_path(
        "row-build",
        PathSummary::new(
            &build_wall,
            &build_cpu,
            rows,
            columns,
            "floor",
            warmups > 0,
            Some(0),
        ),
    );

    // --- e2e: row-flush (real server). ---
    let base = http_base(&host, port);
    eprintln!("[qwp_ingress_row] creating DEDUP table {table} on {base} ...");
    create_table(&base, kind)?;

    // Minimal connect string: the row-API `Sender` has no auto-flush
    // machinery to disable (see the auto-flush finding in the module doc
    // comment above) and no pool to size, unlike `qwp_ingress_polars.rs`'s
    // `QuestDb::connect` pool string.
    let conf = format!("ws::addr={host}:{port};");
    let mut senders: Vec<Sender> = (0..senders_n)
        .map(|_| Sender::from_conf(&conf))
        .collect::<Result<_, _>>()?;
    let ranges = bench_schema::sender_ranges(rows, senders_n);

    eprintln!("[qwp_ingress_row] measuring row-flush e2e ({senders_n} sender(s)) ...");
    let (flush_wall, flush_cpu) =
        measure_row_flush(&mut senders, &ctx, &ranges, iterations, warmups)?;
    report.add_path(
        "row-flush",
        PathSummary::new(
            &flush_wall,
            &flush_cpu,
            rows,
            columns,
            "e2e",
            warmups > 0,
            Some(0),
        ),
    );

    // DEDUP gate: count() must equal rows exactly (same semantics as
    // `qwp_ingress_polars.rs`; `wait_for_count`'s poll loop itself only
    // requires count() >= rows to stop polling).
    eprintln!("[qwp_ingress_row] waiting for WAL apply (count() == {rows}) ...");
    let count = wait_for_count(&base, table, rows as u64)?;
    let ok = count == rows as u64;
    report.row_count_check = Some(bench_json::RowCountCheck {
        expected: rows as u64,
        actual: count,
        ok,
        inflated: count > rows as u64,
    });
    if !ok {
        eprintln!(
            "[qwp_ingress_row] WARNING: count() == {count}, expected {rows} (inflated={})",
            count > rows as u64
        );
    }
    report.real_conf = Some(conf);
    report.http_base = Some(base);

    report.compute_row_headline();
    println!("{}", report.into_json());

    if ok {
        Ok(())
    } else {
        std::process::exit(2);
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
