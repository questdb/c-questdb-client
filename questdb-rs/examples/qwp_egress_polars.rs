//! Step 3 (QWP_DATAFRAME_BENCH_PLAN.md §6) — Rust **Polars egress**
//! parity for the S1 narrow schema.
//!
//! Reads the S1 table back over QWP/WS and measures the decode →
//! DataFrame paths, the mirror of `qwp_ingress_polars.rs`:
//!
//!   * `decode-only`     — drive `Cursor::next_batch()` over the result's
//!     Arrow batches without building a DataFrame (the egress floor; the
//!     analog of the ingress encode floor / the Python `_drain_arrow`).
//!   * `fetch-all-polars` — `Cursor::fetch_all_polars()`, the headline
//!     decode → polars `DataFrame` materialise (decode + assemble).
//!   * `iter-polars`      — `Cursor::iter_polars()`, lazy per-batch
//!     `DataFrame`s vstacked (vs the full materialise).
//!
//! `Cursor::next_polars()` is exercised once for correctness. The honest
//! headline (plan §3.6) is `decode_plus_assemble` = the `fetch_all_polars`
//! median; `decode-only` is the floor; the marginal assemble is the
//! difference. Emits the §3.2 JSON metric contract with
//! `client="rust-polars"`, `direction="egress"`, matching the Python
//! egress harness (`benchmark_pandas_egress.py`).
//!
//! By default the example **populates** the S1 table first (DEDUP UPSERT
//! KEYS(ts), µs-unique ts), waits for the WAL to apply and asserts
//! `count() == rows`, then reads it back — so it runs standalone. Set
//! `SKIP_POPULATE=1` to read back an already-ingested table (e.g. the one
//! `qwp_ingress_polars` filled).
//!
//! Run against a QWP-schema-0x3 QuestDB with QWP/WS + HTTP on :9000:
//!
//! ```bash
//! cargo +nightly run --release --example qwp_egress_polars \
//!     --features polars,sync-reader-ws,sync-sender-http
//! ```
//!
//! (The `polars` feature pulls in `sync-sender-qwp-ws` + `sync-reader-ws`;
//! `sync-sender-http` is for the table create + WAL count gate.)
//!
//! Env knobs:
//!   ROWS=10000000  ITERATIONS=5  WARMUPS=2  RUN_MODE=full
//!   QUESTDB_COLUMN_BENCH_SYM_CARD=8  QUESTDB_COLUMN_BENCH_VARCHAR_LEN=16
//!   QDB_HOST=127.0.0.1  QDB_PORT=9000  SKIP_POPULATE=1

use std::error::Error;
use std::time::{Duration, Instant};

use polars::prelude::{
    CategoricalPhysical, Categories, DataFrame, DataType as PlDataType, IntoColumn, NamedFrom,
    PlSmallStr, Series, TimeUnit,
};
use questdb::egress::Reader;
use questdb::ingress::ColumnName;
use questdb::ingress::column_sender::QuestDb;
use questdb::ingress::polars::PolarsIngestOptions;

mod bench_json;
use bench_json::{Env, PathSummary, Report};

const TABLE: &str = "bench_s1_narrow";
const SCHEMA: &str = "s1-narrow";
const COLUMNS: usize = 5;
const TS_STEP_NANOS: i64 = 1_000;
const TS_BASE_NANOS: i64 = 1_704_067_200_000_000_000;
/// Read back all five S1 columns (full parity with the Python egress
/// `SELECT *`), including the designated `ts`.
const SELECT_SQL: &str = "SELECT ts, id, price, sym, note FROM bench_s1_narrow";

// ---------------------------------------------------------------------------
// S1 DataFrame (for the populate step). Same shape as qwp_ingress_polars.
// ---------------------------------------------------------------------------

fn build_s1_dataframe(
    rows: usize,
    sym_card: usize,
    varchar_len: usize,
) -> Result<DataFrame, Box<dyn Error>> {
    let ts_nanos: Vec<i64> = (0..rows as i64)
        .map(|i| TS_BASE_NANOS + i * TS_STEP_NANOS)
        .collect();
    let ts = Series::new(PlSmallStr::from("ts"), &ts_nanos)
        .cast(&PlDataType::Datetime(TimeUnit::Nanoseconds, None))?;

    let id: Vec<i64> = (0..rows as i64).collect();
    let id = Series::new(PlSmallStr::from("id"), &id);

    let price: Vec<f64> = (0..rows).map(|i| i as f64 * 0.25).collect();
    let price = Series::new(PlSmallStr::from("price"), &price);

    let symbols: Vec<String> = (0..sym_card).map(|i| format!("sym_{i:04}")).collect();
    let sym_strings: Vec<&str> = (0..rows).map(|i| symbols[i % sym_card].as_str()).collect();
    let cats = Categories::new(
        PlSmallStr::from("sym"),
        PlSmallStr::from("bench"),
        CategoricalPhysical::U32,
    );
    let mapping = cats.mapping();
    let sym = Series::new(PlSmallStr::from("sym"), sym_strings)
        .cast(&PlDataType::Categorical(cats, mapping))?;

    let template_count = rows.clamp(1, 1024);
    let templates: Vec<String> = (0..template_count)
        .map(|i| {
            let base = format!("note_{i:03}_").repeat(varchar_len);
            base.chars().take(varchar_len).collect()
        })
        .collect();
    let note_strings: Vec<&str> = (0..rows)
        .map(|i| templates[i % templates.len()].as_str())
        .collect();
    let note = Series::new(PlSmallStr::from("note"), note_strings);

    Ok(DataFrame::new(
        rows,
        vec![
            ts.into_column(),
            id.into_column(),
            price.into_column(),
            sym.into_column(),
            note.into_column(),
        ],
    )?)
}

// ---------------------------------------------------------------------------
// Egress measurements
// ---------------------------------------------------------------------------

fn timed<T>(f: &mut impl FnMut() -> T) -> (u64, u64, T) {
    let cpu0 = bench_json::process_cpu_ns();
    let t0 = Instant::now();
    let out = f();
    let wall = t0.elapsed().as_nanos() as u64;
    let cpu = bench_json::process_cpu_ns().saturating_sub(cpu0);
    (wall, cpu, out)
}

/// Per-path timing samples: (wall-clock ns, process-CPU ns).
type Samples = (Vec<u64>, Vec<u64>);

/// Floor: drive the cursor's Arrow batches without assembling a
/// DataFrame. A fresh `Reader` per iteration so each query is a clean
/// round-trip (mirrors the Python egress harness's per-iteration
/// `client.query(sql)`).
fn measure_decode_only(
    host: &str,
    port: u16,
    rows: u64,
    iterations: usize,
    warmups: usize,
) -> Result<Samples, Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut run = || -> Result<u64, Box<dyn Error>> {
        let mut reader = Reader::from_conf(&conf)?;
        let mut cursor = reader.prepare(SELECT_SQL).execute()?;
        let mut seen: u64 = 0;
        while let Some(view) = cursor.next_batch()? {
            seen += view.row_count() as u64;
            std::hint::black_box(&view);
        }
        Ok(seen)
    };
    for _ in 0..warmups {
        assert_rows(run()?, rows)?;
    }
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (w, c, r) = timed(&mut run);
        assert_rows(r?, rows)?;
        wall.push(w);
        cpu.push(c);
    }
    Ok((wall, cpu))
}

/// Headline: `fetch_all_polars()` — decode + assemble into one polars
/// DataFrame. Returns the timings and the per-query on-wire byte count
/// (the `Reader`'s observed `bytes_received` delta).
fn measure_fetch_all_polars(
    host: &str,
    port: u16,
    rows: u64,
    iterations: usize,
    warmups: usize,
) -> Result<(Samples, u64), Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut wire_bytes = 0u64;
    let mut run = || -> Result<u64, Box<dyn Error>> {
        let mut reader = Reader::from_conf(&conf)?;
        reader.reset_timing();
        let before = reader.bytes_received();
        let df = {
            let mut cursor = reader.prepare(SELECT_SQL).execute()?;
            cursor.fetch_all_polars()?
        };
        wire_bytes = reader.bytes_received() - before;
        let h = df.height() as u64;
        std::hint::black_box(&df);
        Ok(h)
    };
    for _ in 0..warmups {
        assert_rows(run()?, rows)?;
    }
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (w, c, r) = timed(&mut run);
        assert_rows(r?, rows)?;
        wall.push(w);
        cpu.push(c);
    }
    Ok(((wall, cpu), wire_bytes))
}

/// `iter_polars()` — lazy per-batch DataFrames vstacked into one. Same
/// end result as `fetch_all_polars`, different driver (per-batch
/// materialise then concat vs whole-result build), so the two together
/// show whether the streaming path costs anything.
fn measure_iter_polars(
    host: &str,
    port: u16,
    rows: u64,
    iterations: usize,
    warmups: usize,
) -> Result<Samples, Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut run = || -> Result<u64, Box<dyn Error>> {
        let mut reader = Reader::from_conf(&conf)?;
        let mut cursor = reader.prepare(SELECT_SQL).execute()?;
        let mut acc: Option<DataFrame> = None;
        for item in cursor.iter_polars()? {
            let df = item?;
            acc = Some(match acc {
                None => df,
                Some(mut prev) => {
                    prev.vstack_mut_owned(df)?;
                    prev
                }
            });
        }
        let h = acc.map(|d| d.height() as u64).unwrap_or(0);
        Ok(h)
    };
    for _ in 0..warmups {
        assert_rows(run()?, rows)?;
    }
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (w, c, r) = timed(&mut run);
        assert_rows(r?, rows)?;
        wall.push(w);
        cpu.push(c);
    }
    Ok((wall, cpu))
}

/// Exercise `next_polars()` once for correctness: it yields one
/// DataFrame per QWP batch. Returns the total rows and chunk count seen.
fn exercise_next_polars(host: &str, port: u16) -> Result<(u64, usize), Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut reader = Reader::from_conf(&conf)?;
    let mut cursor = reader.prepare(SELECT_SQL).execute()?;
    let mut rows = 0u64;
    let mut batches = 0usize;
    while let Some(df) = cursor.next_polars()? {
        if df.width() != COLUMNS {
            return Err(format!("next_polars: width {} != {COLUMNS}", df.width()).into());
        }
        rows += df.height() as u64;
        batches += 1;
    }
    Ok((rows, batches))
}

fn assert_rows(seen: u64, expected: u64) -> Result<(), Box<dyn Error>> {
    if seen != expected {
        return Err(format!("read back {seen} rows, expected {expected}").into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Populate (DEDUP table + polars ingress + WAL count gate, plan §3.4)
// ---------------------------------------------------------------------------

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

fn populate(
    host: &str,
    port: u16,
    base: &str,
    df: &DataFrame,
    rows: u64,
) -> Result<u64, Box<dyn Error>> {
    eprintln!("[qwp_egress_polars] creating DEDUP table + ingesting {rows} S1 rows ...");
    create_table(base)?;
    let conf = format!("qwpws::addr={host}:{port};pool_size=1;pool_max=1;pool_reap=manual;");
    let db = QuestDb::connect(&conf)?;
    let ts_col = ColumnName::new("ts")?;
    let opts = PolarsIngestOptions::new()
        .max_rows(10_000)
        .timestamp_column(ts_col);
    {
        let mut sender = db.borrow_column_sender()?;
        sender.flush_polars_dataframe(TABLE, df, &opts)?;
    }
    eprintln!("[qwp_egress_polars] waiting for WAL apply (count() == {rows}) ...");
    wait_for_count(base, rows)
}

// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let rows: usize = env_usize("ROWS", 10_000_000);
    let sym_card: usize = env_usize("QUESTDB_COLUMN_BENCH_SYM_CARD", 8);
    let varchar_len: usize = env_usize("QUESTDB_COLUMN_BENCH_VARCHAR_LEN", 16);
    let iterations: usize = env_usize("ITERATIONS", 5);
    let warmups: usize = env_usize("WARMUPS", 2);
    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "full".into());
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = env_usize("QDB_PORT", 9000) as u16;
    let skip_populate = std::env::var("SKIP_POPULATE").is_ok();
    let base = format!("http://{host}:{port}");

    eprintln!(
        "[qwp_egress_polars] schema={SCHEMA} rows={rows} sym_card={sym_card} \
         varchar_len={varchar_len} iterations={iterations} warmups={warmups}"
    );

    // --- Populate (unless re-using an existing table). ---
    if !skip_populate {
        let df = build_s1_dataframe(rows, sym_card, varchar_len)?;
        let count = populate(&host, port, &base, &df, rows as u64)?;
        if count != rows as u64 {
            return Err(format!(
                "DEDUP gate failed: count() == {count}, expected {rows} (inflated={})",
                count > rows as u64
            )
            .into());
        }
        eprintln!("[qwp_egress_polars] DEDUP gate OK: count() == {count}");
    } else {
        eprintln!("[qwp_egress_polars] SKIP_POPULATE set — reading existing {TABLE}");
    }

    let mut report = Report::new(SCHEMA, rows, COLUMNS, "egress", "rust-polars", &run_mode);
    report.warmups = warmups;
    report.env = Env::collect(&[]);
    report.row_count_check = Some(bench_json::RowCountCheck {
        expected: rows as u64,
        actual: rows as u64,
        ok: true,
        inflated: false,
    });

    // --- next_polars correctness probe. ---
    eprintln!("[qwp_egress_polars] exercising next_polars ...");
    let (np_rows, np_batches) = exercise_next_polars(&host, port)?;
    assert_rows(np_rows, rows as u64)?;
    eprintln!("[qwp_egress_polars] next_polars: {np_rows} rows across {np_batches} batch(es)");

    // --- fetch_all_polars first (it discovers the on-wire byte count). ---
    eprintln!("[qwp_egress_polars] measuring fetch_all_polars ...");
    let ((fa_wall, fa_cpu), wire_bytes) =
        measure_fetch_all_polars(&host, port, rows as u64, iterations, warmups)?;
    report.wire_bytes = wire_bytes;
    eprintln!("[qwp_egress_polars] on-wire bytes/query = {wire_bytes}");

    // --- decode-only floor. ---
    eprintln!("[qwp_egress_polars] measuring decode-only floor ...");
    let (dec_wall, dec_cpu) = measure_decode_only(&host, port, rows as u64, iterations, warmups)?;
    report.add_path(
        "decode-only",
        PathSummary::new(
            &dec_wall,
            &dec_cpu,
            rows,
            COLUMNS,
            "floor",
            warmups > 0,
            Some(wire_bytes),
        ),
    );

    report.add_path(
        "fetch-all-polars",
        PathSummary::new(
            &fa_wall,
            &fa_cpu,
            rows,
            COLUMNS,
            "e2e",
            warmups > 0,
            Some(wire_bytes),
        ),
    );

    // --- iter_polars (streaming materialise). ---
    eprintln!("[qwp_egress_polars] measuring iter_polars ...");
    let (it_wall, it_cpu) = measure_iter_polars(&host, port, rows as u64, iterations, warmups)?;
    report.add_path(
        "iter-polars",
        PathSummary::new(
            &it_wall,
            &it_cpu,
            rows,
            COLUMNS,
            "e2e",
            warmups > 0,
            Some(wire_bytes),
        ),
    );

    report.real_conf = Some(format!("ws::addr={host}:{port};compression=raw;"));
    report.http_base = Some(base);
    report.compute_egress_headline();
    println!("{}", report.into_json());
    Ok(())
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
