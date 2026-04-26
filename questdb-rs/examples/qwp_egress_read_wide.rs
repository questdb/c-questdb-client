//! Rust counterpart to QwpEgressReadBenchmarkWide (Java).
//!
//! End-to-end throughput test that streams a wide table over QWP egress and
//! reports rows/sec + MiB/sec on the wire. Mirrors the Java workload:
//!
//!   CREATE TABLE egress_bench_wide (
//!       ts TIMESTAMP, id LONG, price DOUBLE, sym SYMBOL, note VARCHAR,
//!       d1 DOUBLE, d2 DOUBLE, d3 DOUBLE, d4 DOUBLE, d5 DOUBLE,
//!       s1..s5 SYMBOL capacity 200000
//!   ) TIMESTAMP(ts) PARTITION BY HOUR WAL;
//!
//! Run:
//!     cargo run --release --example qwp_egress_read_wide \
//!         --features sync-reader-ws,sync-sender-http
//!
//! Env tuning:
//!     ROW_COUNT=10000000  (default 10M)
//!     SKIP_POPULATE=1     re-use the existing table
//!     QDB_HOST=localhost  QDB_PORT=9000

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;
use questdb::ingress::{Buffer, Sender, TimestampMicros};
use std::time::{Duration, Instant};

const TABLE: &str = "egress_bench_wide";
const HIGH_CARD: usize = 100_000;
const SYMBOLS: &[&str] = &[
    "AAPL", "MSFT", "GOOG", "AMZN", "META", "TSLA", "NVDA", "NFLX",
];

fn main() {
    let row_count: u64 = std::env::var("ROW_COUNT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000_000);
    let skip_populate = std::env::var("SKIP_POPULATE").is_ok();
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "localhost".into());
    let port: u16 = std::env::var("QDB_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000);

    if !skip_populate {
        recreate_table(&host, port);
        ingest_rows(&host, port, row_count);
        wait_for_wal(&host, port, row_count);
    } else {
        println!("SKIP_POPULATE set — re-using existing {TABLE}");
    }

    println!();
    println!("=== Cold warm-up (discarded) ===");
    let _ = run_qwp(&host, port, true);

    println!();
    println!("=== Measurement ===");
    let result = run_qwp(&host, port, false);

    println!();
    println!("=== Summary ===");
    let secs = result.elapsed.as_secs_f64();
    let rows_per_sec = result.rows as f64 / secs;
    let mib_per_sec = result.bytes as f64 / secs / (1024.0 * 1024.0);
    println!(
        "{:<20} {:>10} ms  {:>14} rows/s  {:>10.2} MiB/s",
        "QWP egress (WS)",
        result.elapsed.as_millis(),
        format!("{:.0}", rows_per_sec),
        mib_per_sec
    );
}

struct Result {
    elapsed: Duration,
    rows: u64,
    bytes: u64,
}

fn run_qwp(host: &str, port: u16, warmup: bool) -> Result {
    let conf = format!("qwp::addr={host}:{port};compression=raw;");
    let mut reader = Reader::from_conf(&conf).expect("connect");
    let bytes_before = reader.bytes_received();
    let mut rows: u64 = 0;
    let mut checksum: u64 = 0;

    let sql = format!(
        "SELECT ts, id, price, sym, note, d1, d2, d3, d4, d5, s1, s2, s3, s4, s5 FROM {TABLE}"
    );
    let start = Instant::now();
    let mut cursor = reader.query(&sql).execute().expect("execute");
    while let Some(view) = cursor.next_batch().expect("next_batch") {
        let n = view.row_count();
        // Hoist column views once per batch; per-row reads are then array
        // indexing only.
        let ts = match view.column(0).unwrap() {
            ColumnView::Timestamp(c) => c,
            _ => panic!("ts not Timestamp"),
        };
        let id = match view.column(1).unwrap() {
            ColumnView::Long(c) => c,
            _ => panic!("id not Long"),
        };
        let price = match view.column(2).unwrap() {
            ColumnView::Double(c) => c,
            _ => panic!("price not Double"),
        };
        let sym = match view.column(3).unwrap() {
            ColumnView::Symbol(c) => c,
            _ => panic!("sym not Symbol"),
        };
        let note = match view.column(4).unwrap() {
            ColumnView::Varchar(c) => c,
            _ => panic!("note not Varchar"),
        };
        let d1 = match view.column(5).unwrap() {
            ColumnView::Double(c) => c,
            _ => panic!("d1 not Double"),
        };
        let d2 = match view.column(6).unwrap() {
            ColumnView::Double(c) => c,
            _ => panic!("d2 not Double"),
        };
        let d3 = match view.column(7).unwrap() {
            ColumnView::Double(c) => c,
            _ => panic!("d3 not Double"),
        };
        let d4 = match view.column(8).unwrap() {
            ColumnView::Double(c) => c,
            _ => panic!("d4 not Double"),
        };
        let d5 = match view.column(9).unwrap() {
            ColumnView::Double(c) => c,
            _ => panic!("d5 not Double"),
        };
        let s1 = match view.column(10).unwrap() {
            ColumnView::Symbol(c) => c,
            _ => panic!("s1 not Symbol"),
        };
        let s2 = match view.column(11).unwrap() {
            ColumnView::Symbol(c) => c,
            _ => panic!("s2 not Symbol"),
        };
        let s3 = match view.column(12).unwrap() {
            ColumnView::Symbol(c) => c,
            _ => panic!("s3 not Symbol"),
        };
        let s4 = match view.column(13).unwrap() {
            ColumnView::Symbol(c) => c,
            _ => panic!("s4 not Symbol"),
        };
        let s5 = match view.column(14).unwrap() {
            ColumnView::Symbol(c) => c,
            _ => panic!("s5 not Symbol"),
        };

        for r in 0..n {
            let ts_v = if ts.is_null(r) { 0 } else { ts.value(r) };
            let id_v = if id.is_null(r) { 0 } else { id.value(r) };
            let price_bits = if price.is_null(r) {
                0
            } else {
                price.value(r).to_bits() as i64
            };
            let d1b = double_bits(&d1, r);
            let d2b = double_bits(&d2, r);
            let d3b = double_bits(&d3, r);
            let d4b = double_bits(&d4, r);
            let d5b = double_bits(&d5, r);
            let sym_len = sym.resolve(r).map(str::len).unwrap_or(0) as i64;
            let note_len = note.value(r).map(str::len).unwrap_or(0) as i64;
            let s1l = sym_len_at(&s1, r);
            let s2l = sym_len_at(&s2, r);
            let s3l = sym_len_at(&s3, r);
            let s4l = sym_len_at(&s4, r);
            let s5l = sym_len_at(&s5, r);
            checksum ^= (ts_v
                ^ id_v
                ^ price_bits
                ^ d1b
                ^ d2b
                ^ d3b
                ^ d4b
                ^ d5b
                ^ sym_len
                ^ note_len
                ^ s1l
                ^ s2l
                ^ s3l
                ^ s4l
                ^ s5l) as u64;
        }
        rows += n as u64;
    }
    let elapsed = start.elapsed();
    drop(cursor);
    let bytes = reader.bytes_received() - bytes_before;
    let phase = if warmup { "[warmup]" } else { "[measure]" };
    println!(
        "{phase} QWP : {rows} rows in {} ms  ({:.2} MiB on wire, checksum=0x{:x})",
        elapsed.as_millis(),
        bytes as f64 / (1024.0 * 1024.0),
        checksum
    );
    Result {
        elapsed,
        rows,
        bytes,
    }
}

fn double_bits(c: &questdb::egress::column::FixedColumn<'_, f64>, r: usize) -> i64 {
    if c.is_null(r) {
        0
    } else {
        c.value(r).to_bits() as i64
    }
}

fn sym_len_at(c: &questdb::egress::column::SymbolColumn<'_>, r: usize) -> i64 {
    c.resolve(r).map(str::len).unwrap_or(0) as i64
}

fn ingest_rows(host: &str, port: u16, row_count: u64) {
    println!("ingesting {row_count} rows over ILP/HTTP...");
    let start = Instant::now();
    let mut sender = Sender::from_conf(format!("http::addr={host}:{port};")).expect("sender");
    let mut buf = Buffer::new(sender.protocol_version());
    let s1_pool = build_pool("s1_");
    let s2_pool = build_pool("s2_");
    let s3_pool = build_pool("s3_");
    let s4_pool = build_pool("s4_");
    let s5_pool = build_pool("s5_");
    let flush_every: u64 = 10_000;
    for i in 1..=row_count {
        let h1 = (i as usize) % HIGH_CARD;
        let h2 = (i as usize + 20_000) % HIGH_CARD;
        let h3 = (i as usize + 40_000) % HIGH_CARD;
        let h4 = (i as usize + 60_000) % HIGH_CARD;
        let h5 = (i as usize + 80_000) % HIGH_CARD;
        buf.table(TABLE)
            .unwrap()
            .symbol("sym", SYMBOLS[(i as usize) % SYMBOLS.len()])
            .unwrap()
            .symbol("s1", &s1_pool[h1])
            .unwrap()
            .symbol("s2", &s2_pool[h2])
            .unwrap()
            .symbol("s3", &s3_pool[h3])
            .unwrap()
            .symbol("s4", &s4_pool[h4])
            .unwrap()
            .symbol("s5", &s5_pool[h5])
            .unwrap()
            .column_i64("id", i as i64)
            .unwrap()
            .column_f64("price", i as f64 * 1.5)
            .unwrap()
            .column_f64("d1", i as f64 * 0.25)
            .unwrap()
            .column_f64("d2", i as f64 * 0.5)
            .unwrap()
            .column_f64("d3", i as f64 * 0.75)
            .unwrap()
            .column_f64("d4", i as f64 * 1.25)
            .unwrap()
            .column_f64("d5", i as f64 * 1.75)
            .unwrap()
            .column_str("note", format!("n{}", i & 0xFFF))
            .unwrap()
            .at(TimestampMicros::new(i as i64 * 10_000))
            .unwrap();
        if i % flush_every == 0 {
            sender.flush(&mut buf).expect("flush");
            if i % 1_000_000 == 0 {
                println!(
                    "  {i}/{row_count} rows ({} ms)",
                    start.elapsed().as_millis()
                );
            }
        }
    }
    if !buf.is_empty() {
        sender.flush(&mut buf).expect("flush");
    }
    println!(
        "ingest complete: {row_count} rows in {} ms",
        start.elapsed().as_millis()
    );
}

fn build_pool(prefix: &str) -> Vec<String> {
    (0..HIGH_CARD).map(|i| format!("{prefix}{i}")).collect()
}

fn recreate_table(host: &str, port: u16) {
    let drop = format!("DROP TABLE IF EXISTS {TABLE}");
    let create = format!(
        "CREATE TABLE {TABLE} (\
            ts TIMESTAMP, id LONG, price DOUBLE, sym SYMBOL, note VARCHAR,\
            d1 DOUBLE, d2 DOUBLE, d3 DOUBLE, d4 DOUBLE, d5 DOUBLE,\
            s1 SYMBOL capacity 200000, s2 SYMBOL capacity 200000,\
            s3 SYMBOL capacity 200000, s4 SYMBOL capacity 200000,\
            s5 SYMBOL capacity 200000\
        ) TIMESTAMP(ts) PARTITION BY HOUR WAL"
    );
    exec_sql(host, port, &drop);
    exec_sql(host, port, &create);
    println!("table recreated");
}

fn exec_sql(host: &str, port: u16, sql: &str) {
    let url = format!("http://{host}:{port}/exec");
    let resp = ureq::get(&url)
        .query("query", sql)
        .call()
        .unwrap_or_else(|e| panic!("/exec {sql}: {e}"));
    if resp.status() != 200 {
        panic!("/exec {sql} -> HTTP {}", resp.status());
    }
}

fn wait_for_wal(host: &str, port: u16, expected: u64) {
    println!("waiting for WAL apply ...");
    let url = format!("http://{host}:{port}/exec");
    let sql = format!("SELECT count() FROM {TABLE}");
    let deadline = Instant::now() + Duration::from_secs(600);
    while Instant::now() < deadline {
        let mut resp = ureq::get(&url).query("query", &sql).call().expect("/exec");
        let body: String = resp.body_mut().read_to_string().unwrap();
        if let Some(idx) = body.rfind("\"dataset\":[[") {
            let tail = &body[idx + "\"dataset\":[[".len()..];
            if let Some(end) = tail.find(']')
                && let Ok(n) = tail[..end].parse::<u64>()
                && n >= expected
            {
                println!("  applied {n} rows");
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    panic!("WAL apply timed out");
}
