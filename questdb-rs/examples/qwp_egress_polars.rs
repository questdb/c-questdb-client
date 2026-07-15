//! Step 3 (doc/historical/QWP_DATAFRAME_BENCH_PLAN.md §6) — Rust **Polars egress**
//! parity for the shared S1 narrow / S2 wide schemas.
//!
//! Reads the bench table back over QWP/WS and measures the decode →
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
//! By default the example **populates** the bench table first (DEDUP UPSERT
//! KEYS(ts), µs-unique ts), waits for the WAL to apply and asserts
//! `count() == rows`, then reads it back — so it runs standalone. Set
//! `SKIP_POPULATE=1` to read back an already-ingested table (e.g. the one
//! `qwp_ingress_polars` filled).
//!
//! * **S1 narrow** (5 cols) / **S2 wide** (15 cols: S1 + `d1..d5` DOUBLE +
//!   `s1..s5` high-card SYMBOL, default card 100k); see `bench_schema`.
//!
//! Run against a QWP-schema-0x3 QuestDB with QWP/WS + HTTP on :9000:
//!
//! ```bash
//! cargo run --release --example qwp_egress_polars \
//!     --features polars,sync-reader-qwp-ws,sync-sender-http
//! ```
//!
//! (The `polars` feature pulls in `sync-sender-qwp-ws` + `sync-reader-qwp-ws`;
//! `sync-sender-http` is for the table create + WAL count gate.)
//!
//! For **S2 wide** populate, launch the server with
//! `http.receive.buffer.size=16M` (`QDB_HTTP_RECEIVE_BUFFER_SIZE=16M`) — the
//! high-card symbol delta-dict overflows the 1m default (use SKIP_POPULATE to
//! read a table filled elsewhere if the server can't be reconfigured).
//!
//! Env knobs:
//!   SCHEMA=s1-narrow  ROWS=10000000  ITERATIONS=5  WARMUPS=2  RUN_MODE=full
//!   QUESTDB_COLUMN_BENCH_SYM_CARD=8  QUESTDB_COLUMN_BENCH_VARCHAR_LEN=16
//!   HI_SYM_CARD=100000  QDB_HOST=127.0.0.1  QDB_PORT=9000  SKIP_POPULATE=1

use std::error::Error;
use std::time::{Duration, Instant};

use polars::prelude::{
    CategoricalPhysical, Categories, Column, DataFrame, DataType as PlDataType, IntoColumn,
    NamedFrom, PlSmallStr, Series, TimeUnit,
};
use questdb::QuestDb;
use questdb::egress::{ColumnView, Reader};
use questdb::ingress::ColumnName;
use questdb::ingress::polars::PolarsIngestOptions;

mod bench_json;
mod bench_schema;
use bench_json::{Env, PathSummary, Report};
use bench_schema::{N_WIDE_DOUBLES, N_WIDE_SYMS, SchemaKind};

const TS_STEP_NANOS: i64 = 1_000;
const TS_BASE_NANOS: i64 = 1_704_067_200_000_000_000;

const D_NAMES: [&str; N_WIDE_DOUBLES] = ["d1", "d2", "d3", "d4", "d5"];
const S_NAMES: [&str; N_WIDE_SYMS] = ["s1", "s2", "s3", "s4", "s5"];

// ---------------------------------------------------------------------------
// Bench DataFrame (for the populate step). Same shape + values as
// qwp_ingress_polars (shared bench_schema generators), built from scratch.
// ---------------------------------------------------------------------------

/// A Polars `Categorical` Series of `rows` rows cycling `card` categories
/// `label(0)..label(card-1)` (`i % card`), matching the Python column dtype.
fn symbol_series(
    name: &str,
    rows: usize,
    card: usize,
    label: impl Fn(usize) -> String,
) -> Result<Series, Box<dyn Error>> {
    let categories: Vec<String> = (0..card).map(label).collect();
    let per_row: Vec<&str> = (0..rows).map(|i| categories[i % card].as_str()).collect();
    let cats = Categories::new(
        PlSmallStr::from(name),
        PlSmallStr::from(format!("bench_{name}")),
        CategoricalPhysical::U32,
    );
    let mapping = cats.mapping();
    Ok(Series::new(PlSmallStr::from(name), per_row)
        .cast(&PlDataType::Categorical(cats, mapping))?)
}

fn build_dataframe(
    kind: SchemaKind,
    rows: usize,
    sym_card: usize,
    varchar_len: usize,
    hi_sym_card: usize,
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

    let sym = symbol_series("sym", rows, sym_card, bench_schema::sym_label)?;

    let template_count = bench_schema::note_template_count(rows);
    let templates: Vec<String> = (0..template_count)
        .map(|i| bench_schema::note_template(i, varchar_len))
        .collect();
    let note_strings: Vec<&str> = (0..rows)
        .map(|i| templates[i % templates.len()].as_str())
        .collect();
    let note = Series::new(PlSmallStr::from("note"), note_strings);

    let mut columns: Vec<Column> = vec![
        ts.into_column(),
        id.into_column(),
        price.into_column(),
        sym.into_column(),
        note.into_column(),
    ];
    if kind.is_wide() {
        for (k, name) in D_NAMES.iter().enumerate() {
            let values: Vec<f64> = (0..rows)
                .map(|i| bench_schema::wide_double(i, k + 1))
                .collect();
            columns.push(Series::new(PlSmallStr::from(*name), values).into_column());
        }
        for (i, name) in S_NAMES.iter().enumerate() {
            let col = i + 1;
            columns.push(
                symbol_series(name, rows, hi_sym_card, |v| {
                    bench_schema::hi_sym_label(col, v)
                })?
                .into_column(),
            );
        }
    }
    // Height-explicit DataFrame constructor. On polars >=0.53 it's the two-arg
    // `DataFrame::new(height, columns)`; on 0.52 it was `new_with_height` (0.52's
    // `new` took columns only).
    Ok(DataFrame::new(rows, columns)?)
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
    select: &str,
    rows: u64,
    iterations: usize,
    warmups: usize,
) -> Result<Samples, Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut run = || -> Result<u64, Box<dyn Error>> {
        let mut reader = Reader::from_conf(&conf)?;
        let mut cursor = reader.prepare(select).execute()?;
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

/// Row-count assertion for the `materialize` pass only. Exits the
/// process with code 2 (rather than propagating a `Box<dyn Error>`,
/// which would make `main` exit 1) to match the C twin's
/// (`examples/qwp_egress_c.c`) `read_pass`/`main` mismatch handling
/// exactly.
fn assert_rows_materialize(seen: u64, expected: u64) {
    if seen != expected {
        eprintln!("[qwp_egress_polars] materialize rows {seen} != {expected}");
        std::process::exit(2);
    }
}

/// e2e: the Rust analog of the C twin's `read_pass(materialize=1)` and
/// Java's `materialize` path — touch every cell in every batch through
/// the typed `ColumnView` accessors (the Rust-user analog of assembling
/// a DataFrame) and fold everything into one `f64` checksum, so the
/// reads cannot be optimized away and the result is cross-checkable
/// against the other clients' stderr checksum for the same table.
///
/// Same kind mapping as C: `i64`-backed kinds (long / timestamp /
/// timestamp_nanos) add the raw value; double adds the value; symbol
/// adds the resolved string length; varchar adds the byte length; every
/// other kind is skipped. NULL cells contribute `0` for every kind —
/// matching the C twin's `reader_column_data_get_{i64,f64}`, whose
/// null branch returns `0`/`0.0` rather than the underlying bit
/// pattern (unlike `FixedColumn::value`, which does not consult
/// validity). Fresh `Reader` per iteration, same construction as
/// [`measure_decode_only`].
fn measure_materialize(
    host: &str,
    port: u16,
    select: &str,
    rows: u64,
    iterations: usize,
    warmups: usize,
) -> Result<(Samples, f64), Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut checksum = 0.0f64;
    let mut run = || -> Result<u64, Box<dyn Error>> {
        let mut reader = Reader::from_conf(&conf)?;
        let mut cursor = reader.prepare(select).execute()?;
        let mut seen: u64 = 0;
        let mut sum = 0.0f64;
        while let Some(view) = cursor.next_batch()? {
            let nrows = view.row_count();
            for c in 0..view.column_count() {
                match view.column(c)? {
                    ColumnView::Long(fc)
                    | ColumnView::Timestamp(fc)
                    | ColumnView::TimestampNanos(fc) => {
                        for row in 0..nrows {
                            if !fc.is_null(row) {
                                sum += fc.value(row) as f64;
                            }
                        }
                    }
                    ColumnView::Double(fc) => {
                        for row in 0..nrows {
                            if !fc.is_null(row) {
                                sum += fc.value(row);
                            }
                        }
                    }
                    ColumnView::Symbol(sc) => {
                        for row in 0..nrows {
                            sum += sc.resolve(row).map_or(0.0, |s| s.len() as f64);
                        }
                    }
                    ColumnView::Varchar(vc) => {
                        for row in 0..nrows {
                            sum += vc.value(row).map_or(0.0, |s| s.len() as f64);
                        }
                    }
                    _ => {}
                }
            }
            seen += nrows as u64;
        }
        checksum = sum;
        Ok(seen)
    };
    for _ in 0..warmups {
        let seen = run()?;
        assert_rows_materialize(seen, rows);
    }
    let mut wall = Vec::with_capacity(iterations);
    let mut cpu = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let (w, c, r) = timed(&mut run);
        let seen = r?;
        assert_rows_materialize(seen, rows);
        wall.push(w);
        cpu.push(c);
    }
    Ok(((wall, cpu), checksum))
}

/// Split point: build the Arrow `RecordBatch` per batch (decode + `convert.rs`)
/// but do not convert to polars. `to-arrow − decode-only` isolates the Arrow
/// build; `to-polars − to-arrow` isolates the Arrow→polars conversion.
fn measure_to_arrow(
    host: &str,
    port: u16,
    select: &str,
    rows: u64,
    iterations: usize,
    warmups: usize,
) -> Result<Samples, Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut run = || -> Result<u64, Box<dyn Error>> {
        let mut reader = Reader::from_conf(&conf)?;
        let mut cursor = reader.prepare(select).execute()?;
        let mut seen: u64 = 0;
        while let Some(rb) = cursor.next_arrow_batch()? {
            seen += rb.num_rows() as u64;
            std::hint::black_box(&rb);
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
    select: &str,
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
            let mut cursor = reader.prepare(select).execute()?;
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
    select: &str,
    rows: u64,
    iterations: usize,
    warmups: usize,
) -> Result<Samples, Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut run = || -> Result<u64, Box<dyn Error>> {
        let mut reader = Reader::from_conf(&conf)?;
        let mut cursor = reader.prepare(select).execute()?;
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
fn exercise_next_polars(
    host: &str,
    port: u16,
    select: &str,
    columns: usize,
) -> Result<(u64, usize), Box<dyn Error>> {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut reader = Reader::from_conf(&conf)?;
    let mut cursor = reader.prepare(select).execute()?;
    let mut rows = 0u64;
    let mut batches = 0usize;
    while let Some(df) = cursor.next_polars()? {
        if df.width() != columns {
            return Err(format!("next_polars: width {} != {columns}", df.width()).into());
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

fn create_table(base: &str, kind: SchemaKind) -> Result<(), Box<dyn Error>> {
    exec_sql(base, &format!("DROP TABLE IF EXISTS {}", kind.table()))?;
    exec_sql(base, kind.create_table_sql())?;
    Ok(())
}

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

fn populate(
    host: &str,
    port: u16,
    base: &str,
    kind: SchemaKind,
    df: &DataFrame,
    rows: u64,
) -> Result<u64, Box<dyn Error>> {
    let table = kind.table();
    eprintln!("[qwp_egress_polars] creating DEDUP table {table} + ingesting {rows} rows ...");
    create_table(base, kind)?;
    let conf =
        format!("ws::addr={host}:{port};sender_pool_min=1;sender_pool_max=1;pool_reap=manual;");
    let db = QuestDb::connect(&conf)?;
    let ts_col = ColumnName::new("ts")?;
    let opts = PolarsIngestOptions::new()
        .max_rows(10_000)
        .timestamp_column(ts_col);
    db.flush_polars_dataframe(table, df, &opts)?;
    eprintln!("[qwp_egress_polars] waiting for WAL apply (count() == {rows}) ...");
    wait_for_count(base, table, rows)
}

// ---------------------------------------------------------------------------

fn main() -> Result<(), Box<dyn Error>> {
    let schema_name = std::env::var("SCHEMA").unwrap_or_else(|_| "s1-narrow".into());
    let kind = SchemaKind::parse(&schema_name)
        .ok_or_else(|| format!("unknown SCHEMA={schema_name} (want s1-narrow | s2-wide)"))?;
    let columns = kind.columns();
    let table = kind.table();
    let select = kind.select_sql();

    let rows: usize = env_usize("ROWS", 10_000_000);
    let sym_card: usize = env_usize("QUESTDB_COLUMN_BENCH_SYM_CARD", 8);
    let varchar_len: usize = env_usize("QUESTDB_COLUMN_BENCH_VARCHAR_LEN", 16);
    let hi_sym_card: usize = env_usize("HI_SYM_CARD", 100_000);
    let iterations: usize = env_usize("ITERATIONS", 5);
    let warmups: usize = env_usize("WARMUPS", 2);
    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "full".into());
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "127.0.0.1".into());
    let port: u16 = env_usize("QDB_PORT", 9000) as u16;
    let skip_populate = std::env::var("SKIP_POPULATE").is_ok();
    let base = format!("http://{host}:{port}");

    eprintln!(
        "[qwp_egress_polars] schema={} rows={rows} columns={columns} sym_card={sym_card} \
         varchar_len={varchar_len} hi_sym_card={hi_sym_card} iterations={iterations} \
         warmups={warmups}",
        kind.name()
    );

    // --- Populate (unless re-using an existing table). ---
    if !skip_populate {
        let df = build_dataframe(kind, rows, sym_card, varchar_len, hi_sym_card)?;
        let count = populate(&host, port, &base, kind, &df, rows as u64)?;
        if count != rows as u64 {
            return Err(format!(
                "DEDUP gate failed: count() == {count}, expected {rows} (inflated={})",
                count > rows as u64
            )
            .into());
        }
        eprintln!("[qwp_egress_polars] DEDUP gate OK: count() == {count}");
    } else {
        eprintln!("[qwp_egress_polars] SKIP_POPULATE set — reading existing {table}");
    }

    let mut report = Report::new(
        kind.name(),
        rows,
        columns,
        "egress",
        "rust-polars",
        &run_mode,
    );
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
    let (np_rows, np_batches) = exercise_next_polars(&host, port, select, columns)?;
    assert_rows(np_rows, rows as u64)?;
    eprintln!("[qwp_egress_polars] next_polars: {np_rows} rows across {np_batches} batch(es)");

    // --- fetch_all_polars first (it discovers the on-wire byte count). ---
    eprintln!("[qwp_egress_polars] measuring fetch_all_polars ...");
    let ((fa_wall, fa_cpu), wire_bytes) =
        measure_fetch_all_polars(&host, port, select, rows as u64, iterations, warmups)?;
    report.wire_bytes = wire_bytes;
    eprintln!("[qwp_egress_polars] on-wire bytes/query = {wire_bytes}");

    // --- decode-only floor. ---
    eprintln!("[qwp_egress_polars] measuring decode-only floor ...");
    let (dec_wall, dec_cpu) =
        measure_decode_only(&host, port, select, rows as u64, iterations, warmups)?;
    report.add_path(
        "decode-only",
        PathSummary::new(
            &dec_wall,
            &dec_cpu,
            rows,
            columns,
            "floor",
            warmups > 0,
            Some(wire_bytes),
        ),
    );

    // --- materialize e2e (checksum walk, the Java/C `materialize` comparand). ---
    eprintln!("[qwp_egress_polars] measuring materialize ...");
    let ((mat_wall, mat_cpu), checksum) =
        measure_materialize(&host, port, select, rows as u64, iterations, warmups)?;
    report.add_path(
        "materialize",
        PathSummary::new(
            &mat_wall,
            &mat_cpu,
            rows,
            columns,
            "e2e",
            warmups > 0,
            Some(wire_bytes),
        ),
    );
    eprintln!("[qwp_egress_polars] checksum={checksum}");

    // --- to-arrow split (decode + Arrow RecordBatch build, no polars). ---
    eprintln!("[qwp_egress_polars] measuring to-arrow ...");
    let (ta_wall, ta_cpu) =
        measure_to_arrow(&host, port, select, rows as u64, iterations, warmups)?;
    report.add_path(
        "to-arrow",
        PathSummary::new(
            &ta_wall,
            &ta_cpu,
            rows,
            columns,
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
            columns,
            "e2e",
            warmups > 0,
            Some(wire_bytes),
        ),
    );

    // --- iter_polars (streaming materialise). ---
    eprintln!("[qwp_egress_polars] measuring iter_polars ...");
    let (it_wall, it_cpu) =
        measure_iter_polars(&host, port, select, rows as u64, iterations, warmups)?;
    report.add_path(
        "iter-polars",
        PathSummary::new(
            &it_wall,
            &it_cpu,
            rows,
            columns,
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
