//! Step 3 (doc/historical/QWP_DATAFRAME_BENCH_PLAN.md §6) — Rust **Polars ingress**
//! parity for the shared S1 narrow / S2 wide schemas.
//!
//! Measures `BorrowedSender::flush_polars_dataframe()` end-to-end on a
//! `bench_schema::SchemaKind` (the same columns the pandas harness ingests),
//! and separately the columnar-payload **encode floor**
//! (`bench_encode_chunk_into`, the same path `benches/column_sender.rs`
//! reports) on identical data, so the DataFrame→batches overhead is
//! isolated. Emits the plan §3.2 JSON metric contract with
//! `client="rust-polars"`, `direction="ingress"`, matching the field
//! names the Python harness (`benchmark_pandas_columnar.py`) emits, so a
//! Step 4 aggregator consumes Python + Rust JSON uniformly.
//!
//! * **S1 narrow** (5 cols): `ts` TIMESTAMP (designated), `id` LONG,
//!   `price` DOUBLE, `sym` SYMBOL (Polars Categorical, card 8), `note`
//!   VARCHAR (Utf8, len ~16).
//! * **S2 wide** (15 cols): S1 plus `d1..d5` DOUBLE and `s1..s5`
//!   high-cardinality SYMBOL (default card 100k each — the Go
//!   `qwp-egress-read-wide` anchor). Table DDL adds DEDUP UPSERT KEYS(ts).
//!
//! Run against a QWP-schema-0x3 QuestDB with QWP/WS + HTTP on :9000:
//!
//! ```bash
//! cargo run --release --example qwp_ingress_polars \
//!     --features polars,sync-sender-qwp-ws,sync-sender-http
//! ```
//!
//! (The `polars` feature already pulls in `sync-sender-qwp-ws` + `sync-reader-qwp-ws`.)
//!
//! For **S2 wide** the high-cardinality symbol delta-dict overflows the
//! default `http.receive.buffer.size=1m`; launch the server with
//! `http.receive.buffer.size=16M` (QuestDB `QDB_HTTP_RECEIVE_BUFFER_SIZE=16M`)
//! or the QWP/WS connection is closed mid-flush.
//!
//! Env knobs (parity with the Rust columnar suite / Python harness):
//!   SCHEMA=s1-narrow         scenario (s1-narrow | s2-wide)
//!   ROWS=10000000            headline row count (default 10M)
//!   QUESTDB_COLUMN_BENCH_SYM_CARD=8        low-card SYMBOL cardinality
//!   QUESTDB_COLUMN_BENCH_VARCHAR_LEN=16    VARCHAR byte length
//!   HI_SYM_CARD=100000       s2-wide high-card SYMBOL s1..s5 (uniform)
//!   ITERATIONS=5  WARMUPS=2  MAX_BATCH_ROWS=10000  RUN_MODE=full
//!   QDB_HOST=127.0.0.1  QDB_PORT=9000
//!   SKIP_E2E=1               floor only (no server needed)

use std::error::Error;
use std::time::{Duration, Instant};

use polars::prelude::{
    CategoricalPhysical, Categories, Column, DataFrame, DataType as PlDataType, IntoColumn,
    NamedFrom, PlSmallStr, Series, TimeUnit,
};
use questdb::QuestDb;
use questdb::ingress::ColumnName;
use questdb::ingress::column_sender::_bench_internals::{
    BenchEncoderState, bench_encode_chunk_into,
};
use questdb::ingress::column_sender::Chunk;
use questdb::ingress::polars::PolarsIngestOptions;

mod bench_json;
mod bench_schema;
use bench_json::{Env, PathSummary, Report};
use bench_schema::{N_WIDE_DOUBLES, N_WIDE_SYMS, SchemaKind};

/// µs spacing for the designated timestamp: QuestDB TIMESTAMP is
/// µs-resolution, so ns-spaced rows collapse and DEDUP folds them
/// (plan §3.4). 1 µs apart keeps every row distinct and unique.
const TS_STEP_NANOS: i64 = 1_000;
const TS_BASE_NANOS: i64 = 1_704_067_200_000_000_000;

/// Static names for the S2-wide DOUBLE / SYMBOL columns. `&'static str` so a
/// `Chunk` (which copies the column name) accepts them at any lifetime.
const D_NAMES: [&str; N_WIDE_DOUBLES] = ["d1", "d2", "d3", "d4", "d5"];
const S_NAMES: [&str; N_WIDE_SYMS] = ["s1", "s2", "s3", "s4", "s5"];

/// One SYMBOL column in the compact form the columnar encoder wants: per-row
/// `codes` into a `(offsets, bytes)` dictionary. Shared by the low-card
/// `sym` and the S2-wide high-card `s1..s5`.
struct SymCol {
    codes: Vec<i32>,
    offsets: Vec<i32>,
    bytes: Vec<u8>,
}

/// The benchmark data, generated once as plain Rust vectors. Both the encode
/// floor (via [`Chunk`]) and the polars e2e path (via [`DataFrame`]) are
/// built from the *same* buffers so the only delta is the
/// DataFrame→Arrow→batch machinery. `doubles`/`hi_syms` are empty for S1.
struct BenchData {
    rows: usize,
    ts_nanos: Vec<i64>,
    id: Vec<i64>,
    price: Vec<f64>,
    /// Low-cardinality `sym`.
    sym: SymCol,
    /// Per-row VARCHAR `note` values, plus the compact offset/byte form.
    note_values: Vec<String>,
    note_offsets: Vec<i32>,
    note_bytes: Vec<u8>,
    /// S2-wide `d1..d5` DOUBLE columns (empty for S1).
    doubles: Vec<Vec<f64>>,
    /// S2-wide `s1..s5` high-card SYMBOL columns (empty for S1).
    hi_syms: Vec<SymCol>,
}

/// Build one SYMBOL column: dict entries `label(0)..label(card-1)`, codes
/// cycling the dict (`i % card`), matching the Python `from_codes` data.
fn build_sym_col(rows: usize, card: usize, label: impl Fn(usize) -> String) -> SymCol {
    let mut offsets = Vec::with_capacity(card + 1);
    let mut bytes = Vec::new();
    offsets.push(0i32);
    for v in 0..card {
        bytes.extend_from_slice(label(v).as_bytes());
        offsets.push(bytes.len() as i32);
    }
    let codes: Vec<i32> = (0..rows).map(|i| (i % card) as i32).collect();
    SymCol {
        codes,
        offsets,
        bytes,
    }
}

fn build_data(
    kind: SchemaKind,
    rows: usize,
    sym_card: usize,
    varchar_len: usize,
    hi_sym_card: usize,
) -> BenchData {
    let ts_nanos: Vec<i64> = (0..rows as i64)
        .map(|i| TS_BASE_NANOS + i * TS_STEP_NANOS)
        .collect();
    let id: Vec<i64> = (0..rows as i64).collect();
    let price: Vec<f64> = (0..rows).map(|i| i as f64 * 0.25).collect();

    let sym = build_sym_col(rows, sym_card, bench_schema::sym_label);

    // VARCHAR notes: fixed ~varchar_len strings from a small rotating
    // template pool (low card so cost tracks length, not distinctness).
    let template_count = bench_schema::note_template_count(rows);
    let templates: Vec<String> = (0..template_count)
        .map(|i| bench_schema::note_template(i, varchar_len))
        .collect();
    let mut note_values = Vec::with_capacity(rows);
    let mut note_offsets = Vec::with_capacity(rows + 1);
    let mut note_bytes = Vec::new();
    note_offsets.push(0i32);
    for i in 0..rows {
        let s = &templates[i % templates.len()];
        note_values.push(s.clone());
        note_bytes.extend_from_slice(s.as_bytes());
        note_offsets.push(note_bytes.len() as i32);
    }

    let mut doubles = Vec::new();
    let mut hi_syms = Vec::new();
    if kind.is_wide() {
        for k in 1..=N_WIDE_DOUBLES {
            doubles.push((0..rows).map(|i| bench_schema::wide_double(i, k)).collect());
        }
        for col in 1..=N_WIDE_SYMS {
            hi_syms.push(build_sym_col(rows, hi_sym_card, |v| {
                bench_schema::hi_sym_label(col, v)
            }));
        }
    }

    BenchData {
        rows,
        ts_nanos,
        id,
        price,
        sym,
        note_values,
        note_offsets,
        note_bytes,
        doubles,
        hi_syms,
    }
}

/// Reconstruct a Polars `Categorical` Series from a [`SymCol`] (per-row
/// strings → cast), matching the Python column's dtype. A per-column
/// namespace keeps each column's category mapping independent.
fn symbol_series(name: &str, sym: &SymCol) -> Result<Series, Box<dyn Error>> {
    let strings: Vec<&str> = sym
        .codes
        .iter()
        .map(|&c| {
            let start = sym.offsets[c as usize] as usize;
            let end = sym.offsets[c as usize + 1] as usize;
            std::str::from_utf8(&sym.bytes[start..end]).unwrap()
        })
        .collect();
    let cats = Categories::new(
        PlSmallStr::from(name),
        PlSmallStr::from(format!("bench_{name}")),
        CategoricalPhysical::U32,
    );
    let mapping = cats.mapping();
    Ok(Series::new(PlSmallStr::from(name), strings)
        .cast(&PlDataType::Categorical(cats, mapping))?)
}

/// Build the Polars [`DataFrame`] from the shared data, column order
/// matching the Python harness (`ts, id, price, sym, note[, d1..d5, s1..s5]`).
fn build_dataframe(kind: SchemaKind, data: &BenchData) -> Result<DataFrame, Box<dyn Error>> {
    let ts = Series::new(PlSmallStr::from("ts"), &data.ts_nanos)
        .cast(&PlDataType::Datetime(TimeUnit::Nanoseconds, None))?;
    let id = Series::new(PlSmallStr::from("id"), &data.id);
    let price = Series::new(PlSmallStr::from("price"), &data.price);
    let sym = symbol_series("sym", &data.sym)?;
    let note_refs: Vec<&str> = data.note_values.iter().map(String::as_str).collect();
    let note = Series::new(PlSmallStr::from("note"), note_refs);

    let mut columns: Vec<Column> = vec![
        ts.into_column(),
        id.into_column(),
        price.into_column(),
        sym.into_column(),
        note.into_column(),
    ];
    if kind.is_wide() {
        for (k, col) in data.doubles.iter().enumerate() {
            columns.push(Series::new(PlSmallStr::from(D_NAMES[k]), col.as_slice()).into_column());
        }
        for (i, sc) in data.hi_syms.iter().enumerate() {
            columns.push(symbol_series(S_NAMES[i], sc)?.into_column());
        }
    }
    // Height-explicit DataFrame constructor. On polars >=0.53 it's the two-arg
    // `DataFrame::new(height, columns)`; on 0.52 it was `new_with_height` (0.52's
    // `new` took columns only).
    Ok(DataFrame::new(data.rows, columns)?)
}

/// Build the matching columnar [`Chunk`] for the encode floor. Same
/// column set + designated timestamp as the e2e path, all borrowing the
/// shared buffers (no copy of row data).
fn build_chunk<'a>(kind: SchemaKind, data: &'a BenchData) -> Result<Chunk<'a>, Box<dyn Error>> {
    let mut chunk = Chunk::new(kind.table());
    chunk.column_i64("id", &data.id, None)?;
    chunk.column_f64("price", &data.price, None)?;
    chunk.symbol_i32(
        "sym",
        &data.sym.codes,
        &data.sym.offsets,
        &data.sym.bytes,
        None,
    )?;
    chunk.column_str("note", &data.note_offsets, &data.note_bytes, None)?;
    if kind.is_wide() {
        for (k, col) in data.doubles.iter().enumerate() {
            chunk.column_f64(D_NAMES[k], col.as_slice(), None)?;
        }
        for (i, sc) in data.hi_syms.iter().enumerate() {
            chunk.symbol_i32(S_NAMES[i], &sc.codes, &sc.offsets, &sc.bytes, None)?;
        }
    }
    chunk.at_nanos(&data.ts_nanos)?;
    Ok(chunk)
}

/// Wire size of one encoded chunk — the `mib_per_s` denominator. The
/// columnar QWP payload the sender pushes per frame for this schema;
/// deterministic for a given chunk, so one encode suffices. (For S2 wide a
/// single fresh-state encode carries the full 5×high-card symbol dict, so
/// this overstates the warm per-flush bytes — `rows/s` stays the
/// cross-client metric, see plan §3.2.)
fn encoded_wire_bytes(kind: SchemaKind, data: &BenchData) -> Result<u64, Box<dyn Error>> {
    let chunk = build_chunk(kind, data)?;
    let mut state = BenchEncoderState::new();
    let mut out = Vec::with_capacity(64 * 1024);
    bench_encode_chunk_into(&mut out, &chunk, &mut state)?;
    Ok(out.len() as u64)
}

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

/// Wall + process-CPU nanoseconds for one invocation of `f`. Takes
/// `&mut` so the same per-iteration closure can be re-driven in a loop.
fn timed<T>(f: &mut impl FnMut() -> T) -> (u64, u64, T) {
    let cpu0 = bench_json::process_cpu_ns();
    let t0 = Instant::now();
    let out = f();
    let wall = t0.elapsed().as_nanos() as u64;
    let cpu = bench_json::process_cpu_ns().saturating_sub(cpu0);
    (wall, cpu, out)
}

/// Encode floor: time `bench_encode_chunk_into` on the prebuilt chunk.
/// Reuses the encoder state across iterations (a warm connection's steady
/// state), exactly as `benches/column_sender.rs`'s `encode_only` arm does.
fn measure_encode_floor(
    kind: SchemaKind,
    data: &BenchData,
    iterations: usize,
    warmups: usize,
) -> Result<(Vec<u64>, Vec<u64>), Box<dyn Error>> {
    let chunk = build_chunk(kind, data)?;
    let mut state = BenchEncoderState::new();
    let mut out = Vec::with_capacity(64 * 1024);
    let mut run = || -> Result<(), Box<dyn Error>> {
        out.clear();
        bench_encode_chunk_into(&mut out, &chunk, &mut state)?;
        std::hint::black_box(&out);
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

/// e2e over `dbs.len()` parallel connections: thread k flushes its
/// pre-sliced DataFrame view (zero-copy `df.slice`) through its own pooled
/// connection. `PolarsIngestOptions` borrows a `ColumnName`, so each thread
/// builds its own options — negligible next to a 10M-row flush.
fn e2e_pass(
    dbs: &[QuestDb],
    table: &str,
    slices: &[DataFrame],
    max_batch_rows: usize,
) -> Result<(), Box<dyn Error>> {
    std::thread::scope(|scope| -> Result<(), String> {
        let handles: Vec<_> = dbs
            .iter()
            .zip(slices)
            .map(|(db, df)| {
                scope.spawn(move || -> Result<(), String> {
                    let ts_col = ColumnName::new("ts").map_err(|e| e.to_string())?;
                    let opts = PolarsIngestOptions::new()
                        .max_rows(max_batch_rows)
                        .timestamp_column(ts_col);
                    db.flush_polars_dataframe(table, df, &opts)
                        .map_err(|e| e.to_string())?;
                    Ok(())
                })
            })
            .collect();
        for h in handles {
            h.join()
                .map_err(|_| "sender thread panicked".to_string())??;
        }
        Ok(())
    })?;
    Ok(())
}

fn measure_e2e(
    dbs: &[QuestDb],
    table: &str,
    slices: &[DataFrame],
    max_batch_rows: usize,
    iterations: usize,
    warmups: usize,
) -> Result<(Vec<u64>, Vec<u64>), Box<dyn Error>> {
    for _ in 0..warmups {
        e2e_pass(dbs, table, slices, max_batch_rows)?;
    }
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (w, c, r) = timed(&mut || e2e_pass(dbs, table, slices, max_batch_rows));
        r?;
        wall.push(w);
        cpu.push(c);
    }
    Ok((wall, cpu))
}

// ---------------------------------------------------------------------------
// HTTP/SQL helpers (DEDUP table + WAL-aware count gate, plan §3.4)
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
    let skip_e2e = std::env::var("SKIP_E2E").is_ok();

    eprintln!(
        "[qwp_ingress_polars] schema={} rows={rows} columns={columns} sym_card={sym_card} \
         varchar_len={varchar_len} hi_sym_card={hi_sym_card} iterations={iterations} \
         warmups={warmups} max_batch_rows={max_batch_rows} senders={senders_n}",
        kind.name()
    );

    let data = build_data(kind, rows, sym_card, varchar_len, hi_sym_card);
    let wire_bytes = encoded_wire_bytes(kind, &data)?;
    eprintln!("[qwp_ingress_polars] encoded wire bytes/flush = {wire_bytes}");

    let mut report = Report::new(
        kind.name(),
        rows,
        columns,
        "ingress",
        "rust-polars",
        &run_mode,
    );
    report.warmups = warmups;
    report.wire_bytes = wire_bytes;
    report.env = Env::collect(&[]);
    report.senders = senders_n;

    // --- Encode floor (no network). ---
    eprintln!("[qwp_ingress_polars] measuring encode floor ...");
    let (floor_wall, floor_cpu) = measure_encode_floor(kind, &data, iterations, warmups)?;
    report.add_path(
        "encode-floor",
        PathSummary::new(
            &floor_wall,
            &floor_cpu,
            rows,
            columns,
            "floor",
            warmups > 0,
            Some(wire_bytes),
        ),
    );

    // --- e2e flush_polars_dataframe (real server). ---
    if !skip_e2e {
        let base = http_base(&host, port);
        eprintln!("[qwp_ingress_polars] creating DEDUP table {table} on {base} ...");
        create_table(&base, kind)?;

        let df = build_dataframe(kind, &data)?;
        eprintln!(
            "[qwp_ingress_polars] DataFrame shape={:?} schema={:?}",
            df.shape(),
            df.schema()
        );

        let conf = format!(
            // ingestion-only: skip the eager reader pre-open
            "ws::addr={host}:{port};sender_pool_min=1;sender_pool_max=1;\
             pool_reap=manual;query_pool_min=0;"
        );
        let dbs: Vec<QuestDb> = (0..senders_n)
            .map(|_| QuestDb::connect(&conf))
            .collect::<Result<_, _>>()?;
        let ranges = bench_schema::sender_ranges(rows, senders_n);
        // Zero-copy views: `DataFrame::slice` shares the Arc'd buffers, so
        // per-sender slices add no staging cost or memory.
        let slices: Vec<DataFrame> = ranges
            .iter()
            .map(|&(lo, hi)| df.slice(lo as i64, hi - lo))
            .collect();

        eprintln!(
            "[qwp_ingress_polars] measuring flush_polars_dataframe e2e ({senders_n} sender(s)) ..."
        );
        let (e2e_wall, e2e_cpu) =
            measure_e2e(&dbs, table, &slices, max_batch_rows, iterations, warmups)?;
        report.add_path(
            "flush-polars-dataframe",
            PathSummary::new(
                &e2e_wall,
                &e2e_cpu,
                rows,
                columns,
                "e2e",
                warmups > 0,
                Some(wire_bytes),
            ),
        );

        // DEDUP gate: count() must equal rows exactly (plan §3.4).
        eprintln!("[qwp_ingress_polars] waiting for WAL apply (count() == {rows}) ...");
        let count = wait_for_count(&base, table, rows as u64)?;
        report.row_count_check = Some(bench_json::RowCountCheck {
            expected: rows as u64,
            actual: count,
            ok: count == rows as u64,
            inflated: count > rows as u64,
        });
        if count != rows as u64 {
            eprintln!(
                "[qwp_ingress_polars] WARNING: count() == {count}, expected {rows} \
                 (inflated={})",
                count > rows as u64
            );
        }
        report.real_conf = Some(conf);
        report.http_base = Some(base);
    } else {
        eprintln!("[qwp_ingress_polars] SKIP_E2E set — floor only");
    }

    report.compute_ingress_headline();
    println!("{}", report.into_json());
    Ok(())
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
