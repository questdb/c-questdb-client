//! Step 3 (QWP_DATAFRAME_BENCH_PLAN.md §6) — Rust **Polars ingress**
//! parity for the S1 narrow schema.
//!
//! Measures `BorrowedSender::flush_polars_dataframe()` end-to-end on the
//! shared S1 schema (the same 5 columns the pandas harness ingests), and
//! separately the column-sender **encode floor**
//! (`bench_encode_chunk_into`, the same path `benches/column_sender.rs`
//! reports) on identical data, so the DataFrame→batches overhead is
//! isolated. Emits the plan §3.2 JSON metric contract with
//! `client="rust-polars"`, `direction="ingress"`, matching the field
//! names the Python harness (`benchmark_pandas_columnar.py`) emits, so a
//! Step 4 aggregator consumes Python + Rust JSON uniformly.
//!
//! S1 schema (5 cols): `ts` TIMESTAMP (designated), `id` LONG, `price`
//! DOUBLE, `sym` SYMBOL (Polars Categorical, card 8), `note` VARCHAR
//! (Utf8, len ~16). Table DDL:
//! `TIMESTAMP(ts) PARTITION BY HOUR WAL DEDUP UPSERT KEYS(ts)`.
//!
//! Run against a QWP-schema-0x3 QuestDB with QWP/WS + HTTP on :9000:
//!
//! ```bash
//! cargo +nightly run --release --example qwp_ingress_polars \
//!     --features polars,sync-sender-qwp-ws,sync-sender-http
//! ```
//!
//! (The crate's `polars` dep currently needs a nightly toolchain; the
//! `polars` feature already pulls in `sync-sender-qwp-ws` + `sync-reader-ws`.)
//!
//! Env knobs (parity with the Rust column-sender suite / Python harness):
//!   ROWS=10000000            headline row count (default 10M)
//!   QUESTDB_COLUMN_BENCH_SYM_CARD=8        SYMBOL cardinality
//!   QUESTDB_COLUMN_BENCH_VARCHAR_LEN=16    VARCHAR byte length
//!   ITERATIONS=5  WARMUPS=2  MAX_BATCH_ROWS=10000  RUN_MODE=full
//!   QDB_HOST=127.0.0.1  QDB_PORT=9000
//!   SKIP_E2E=1               floor only (no server needed)

use std::error::Error;
use std::time::{Duration, Instant};

use polars::prelude::{
    CategoricalPhysical, Categories, DataFrame, DataType as PlDataType, IntoColumn, NamedFrom,
    PlSmallStr, Series, TimeUnit,
};
use questdb::ingress::ColumnName;
use questdb::ingress::column_sender::_bench_internals::{
    BenchEncoderState, bench_encode_chunk_into,
};
use questdb::ingress::column_sender::{Chunk, QuestDb};
use questdb::ingress::polars::PolarsIngestOptions;

mod bench_json;
use bench_json::{Env, PathSummary, Report};

const TABLE: &str = "bench_s1_narrow";
const SCHEMA: &str = "s1-narrow";
const COLUMNS: usize = 5;
/// µs spacing for the designated timestamp: QuestDB TIMESTAMP is
/// µs-resolution, so ns-spaced rows collapse and DEDUP folds them
/// (plan §3.4). 1 µs apart keeps every row distinct and unique.
const TS_STEP_NANOS: i64 = 1_000;
const TS_BASE_NANOS: i64 = 1_704_067_200_000_000_000;

/// The S1 data, generated once as plain Rust vectors. Both the encode
/// floor (via [`Chunk`]) and the polars e2e path (via [`DataFrame`])
/// are built from the *same* buffers so the only delta is the
/// DataFrame→Arrow→batch machinery.
struct S1Data {
    rows: usize,
    ts_nanos: Vec<i64>,
    id: Vec<i64>,
    price: Vec<f64>,
    /// SYMBOL codes into `sym_dict` (one per row).
    sym_codes: Vec<i32>,
    sym_offsets: Vec<i32>,
    sym_bytes: Vec<u8>,
    /// Per-row VARCHAR string values, plus the compact offset/byte form
    /// the column sender wants.
    note_values: Vec<String>,
    note_offsets: Vec<i32>,
    note_bytes: Vec<u8>,
}

fn build_s1(rows: usize, sym_card: usize, varchar_len: usize) -> S1Data {
    let ts_nanos: Vec<i64> = (0..rows as i64)
        .map(|i| TS_BASE_NANOS + i * TS_STEP_NANOS)
        .collect();
    let id: Vec<i64> = (0..rows as i64).collect();
    let price: Vec<f64> = (0..rows).map(|i| i as f64 * 0.25).collect();

    // SYMBOL dict: `sym_0000`..`sym_{card-1}`; codes cycle the dict.
    let mut sym_offsets = Vec::with_capacity(sym_card + 1);
    let mut sym_bytes = Vec::new();
    sym_offsets.push(0i32);
    for i in 0..sym_card {
        sym_bytes.extend_from_slice(format!("sym_{i:04}").as_bytes());
        sym_offsets.push(sym_bytes.len() as i32);
    }
    let sym_codes: Vec<i32> = (0..rows).map(|i| (i % sym_card) as i32).collect();

    // VARCHAR notes: fixed ~varchar_len strings from a small rotating
    // template pool (cardinality low so cost tracks length, not
    // distinctness — mirrors the pandas `make_s1_narrow`).
    let template_count = rows.clamp(1, 1024);
    let templates: Vec<String> = (0..template_count)
        .map(|i| {
            let base = format!("note_{i:03}_").repeat(varchar_len);
            base.chars().take(varchar_len).collect()
        })
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

    S1Data {
        rows,
        ts_nanos,
        id,
        price,
        sym_codes,
        sym_offsets,
        sym_bytes,
        note_values,
        note_offsets,
        note_bytes,
    }
}

/// Build the S1 polars [`DataFrame`] from the shared data. `sym` is a
/// Polars `Categorical` (card 8) and `ts` a `Datetime(ns)`, matching the
/// plan's S1 dtype table.
fn build_s1_dataframe(data: &S1Data) -> Result<DataFrame, Box<dyn Error>> {
    let ts = Series::new(PlSmallStr::from("ts"), &data.ts_nanos)
        .cast(&PlDataType::Datetime(TimeUnit::Nanoseconds, None))?;
    let id = Series::new(PlSmallStr::from("id"), &data.id);
    let price = Series::new(PlSmallStr::from("price"), &data.price);

    // Reconstruct per-row symbol strings, then cast to Categorical.
    let sym_strings: Vec<&str> = data
        .sym_codes
        .iter()
        .map(|&c| {
            let start = data.sym_offsets[c as usize] as usize;
            let end = data.sym_offsets[c as usize + 1] as usize;
            std::str::from_utf8(&data.sym_bytes[start..end]).unwrap()
        })
        .collect();
    let cats = Categories::new(
        PlSmallStr::from("sym"),
        PlSmallStr::from("bench"),
        CategoricalPhysical::U32,
    );
    let mapping = cats.mapping();
    let sym = Series::new(PlSmallStr::from("sym"), sym_strings)
        .cast(&PlDataType::Categorical(cats, mapping))?;

    let note_refs: Vec<&str> = data.note_values.iter().map(String::as_str).collect();
    let note = Series::new(PlSmallStr::from("note"), note_refs);

    Ok(DataFrame::new(
        data.rows,
        vec![
            ts.into_column(),
            id.into_column(),
            price.into_column(),
            sym.into_column(),
            note.into_column(),
        ],
    )?)
}

/// Build the matching column-sender [`Chunk`] for the encode floor. Uses
/// the same column set + designated timestamp as the e2e path, all
/// borrowing the shared buffers (no copy of row data).
fn build_s1_chunk<'a>(data: &'a S1Data) -> Result<Chunk<'a>, Box<dyn Error>> {
    let mut chunk = Chunk::new(TABLE);
    chunk.column_i64("id", &data.id, None)?;
    chunk.column_f64("price", &data.price, None)?;
    chunk.symbol_dict_i32(
        "sym",
        &data.sym_codes,
        &data.sym_offsets,
        &data.sym_bytes,
        None,
    )?;
    chunk.column_varchar("note", &data.note_offsets, &data.note_bytes, None)?;
    chunk.designated_timestamp_nanos(&data.ts_nanos)?;
    Ok(chunk)
}

/// Wire size of one encoded S1 chunk — the `mib_per_s` denominator. This
/// is the columnar QWP payload the sender pushes per frame for this
/// schema; deterministic for a given chunk, so one encode suffices.
fn encoded_wire_bytes(data: &S1Data) -> Result<u64, Box<dyn Error>> {
    let chunk = build_s1_chunk(data)?;
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

/// Encode floor: time `bench_encode_chunk_into` on the prebuilt S1
/// chunk. Reuses the encoder state across iterations (a warm
/// connection's steady state), exactly as `benches/column_sender.rs`'s
/// `encode_only` arm does.
fn measure_encode_floor(
    data: &S1Data,
    iterations: usize,
    warmups: usize,
) -> Result<(Vec<u64>, Vec<u64>), Box<dyn Error>> {
    let chunk = build_s1_chunk(data)?;
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

/// e2e: time `flush_polars_dataframe()` against the real server. Each
/// iteration re-flushes the whole frame (DEDUP UPSERT KEYS(ts) folds the
/// repeats, so `count() == rows` holds regardless of iteration count).
fn measure_e2e(
    db: &QuestDb,
    df: &DataFrame,
    opts: &PolarsIngestOptions<'_>,
    iterations: usize,
    warmups: usize,
) -> Result<(Vec<u64>, Vec<u64>), Box<dyn Error>> {
    let mut run = || -> Result<(), Box<dyn Error>> {
        let mut sender = db.borrow_sender()?;
        sender.flush_polars_dataframe(TABLE, df, opts)?;
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

fn create_table(base: &str) -> Result<(), Box<dyn Error>> {
    exec_sql(base, &format!("DROP TABLE IF EXISTS {TABLE}"))?;
    exec_sql(
        base,
        &format!(
            "CREATE TABLE {TABLE} (\
                ts TIMESTAMP, id LONG, price DOUBLE, sym SYMBOL, note VARCHAR\
            ) TIMESTAMP(ts) PARTITION BY HOUR WAL DEDUP UPSERT KEYS(ts)"
        ),
    )?;
    Ok(())
}

/// Poll `SELECT count()` until it reaches `expected` (WAL tables apply
/// asynchronously). Returns the final observed count. A value above
/// `expected` signals at-least-once DEDUP inflation (a failure).
fn wait_for_count(base: &str, expected: u64) -> Result<u64, Box<dyn Error>> {
    let url = format!("{base}/exec");
    let sql = format!("SELECT count() FROM {TABLE}");
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
    let rows: usize = env_usize("ROWS", 10_000_000);
    let sym_card: usize = env_usize("QUESTDB_COLUMN_BENCH_SYM_CARD", 8);
    let varchar_len: usize = env_usize("QUESTDB_COLUMN_BENCH_VARCHAR_LEN", 16);
    let iterations: usize = env_usize("ITERATIONS", 5);
    let warmups: usize = env_usize("WARMUPS", 2);
    let max_batch_rows: usize = env_usize("MAX_BATCH_ROWS", 10_000);
    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "full".into());
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = env_usize("QDB_PORT", 9000) as u16;
    let skip_e2e = std::env::var("SKIP_E2E").is_ok();

    eprintln!(
        "[qwp_ingress_polars] schema={SCHEMA} rows={rows} sym_card={sym_card} \
         varchar_len={varchar_len} iterations={iterations} warmups={warmups} \
         max_batch_rows={max_batch_rows}"
    );

    let data = build_s1(rows, sym_card, varchar_len);
    let wire_bytes = encoded_wire_bytes(&data)?;
    eprintln!("[qwp_ingress_polars] encoded S1 wire bytes/flush = {wire_bytes}");

    let mut report = Report::new(SCHEMA, rows, COLUMNS, "ingress", "rust-polars", &run_mode);
    report.warmups = warmups;
    report.wire_bytes = wire_bytes;
    report.env = Env::collect(&[]);

    // --- Encode floor (no network). ---
    eprintln!("[qwp_ingress_polars] measuring encode floor ...");
    let (floor_wall, floor_cpu) = measure_encode_floor(&data, iterations, warmups)?;
    report.add_path(
        "encode-floor",
        PathSummary::new(
            &floor_wall,
            &floor_cpu,
            rows,
            COLUMNS,
            "floor",
            warmups > 0,
            Some(wire_bytes),
        ),
    );

    // --- e2e flush_polars_dataframe (real server). ---
    if !skip_e2e {
        let base = http_base(&host, port);
        eprintln!("[qwp_ingress_polars] creating DEDUP table on {base} ...");
        create_table(&base)?;

        let df = build_s1_dataframe(&data)?;
        eprintln!(
            "[qwp_ingress_polars] DataFrame shape={:?} schema={:?}",
            df.shape(),
            df.schema()
        );

        let conf = format!("qwpws::addr={host}:{port};pool_size=1;pool_max=1;pool_reap=manual;");
        let db = QuestDb::connect(&conf)?;
        let ts_col = ColumnName::new("ts")?;
        let opts = PolarsIngestOptions::new()
            .max_rows(max_batch_rows)
            .timestamp_column(ts_col);

        eprintln!("[qwp_ingress_polars] measuring flush_polars_dataframe e2e ...");
        let (e2e_wall, e2e_cpu) = measure_e2e(&db, &df, &opts, iterations, warmups)?;
        report.add_path(
            "flush-polars-dataframe",
            PathSummary::new(
                &e2e_wall,
                &e2e_cpu,
                rows,
                COLUMNS,
                "e2e",
                warmups > 0,
                Some(wire_bytes),
            ),
        );

        // DEDUP gate: count() must equal rows exactly (plan §3.4).
        eprintln!("[qwp_ingress_polars] waiting for WAL apply (count() == {rows}) ...");
        let count = wait_for_count(&base, rows as u64)?;
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
