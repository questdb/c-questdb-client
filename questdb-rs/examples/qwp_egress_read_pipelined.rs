//! Pipelined (background-thread) counterpart to `qwp_egress_read.rs`.
//!
//! Same workload, same table, same metrics — but the socket read +
//! frame decode happen on a dedicated I/O thread (see
//! [`questdb::egress::pipelined_reader`]). The user thread blocks on
//! `take_event()` and processes batch N while the I/O thread is
//! reading + decoding batch N+1 off the wire.
//!
//! Pair with `qwp_egress_read.rs` for a back-to-back comparison of
//! single-threaded vs. pipelined throughput on the same QuestDB
//! instance and table.
//!
//! Run:
//!     cargo run --release --example qwp_egress_read_pipelined \
//!         --features sync-reader-ws,sync-sender-http
//!
//! Env tuning:
//!     ROW_COUNT=10000000  (default 10M)
//!     SKIP_POPULATE=1     re-use the existing table
//!     QDB_HOST=localhost  QDB_PORT=9000
//!     SKIP_ITER=1         skip the per-row consume loop (decode-only timing)

use questdb::egress::column::ColumnView;
use questdb::egress::pipelined_reader::{Event, PipelinedReader};
use questdb::ingress::{Buffer, Sender, TimestampMicros};
use std::time::{Duration, Instant};

const TABLE: &str = "egress_bench";
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
    let _ = run_pipelined(&host, port, true);

    println!();
    println!("=== Measurement ===");
    let result = run_pipelined(&host, port, false);

    println!();
    println!("=== Summary ===");
    let secs = result.elapsed.as_secs_f64();
    let rows_per_sec = result.rows as f64 / secs;
    let mib_per_sec = result.bytes as f64 / secs / (1024.0 * 1024.0);
    println!(
        "{:<28} {:>10} ms  {:>14} rows/s  {:>10.2} MiB/s",
        "QWP egress (pipelined I/O)",
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

fn run_pipelined(host: &str, port: u16, warmup: bool) -> Result {
    let conf = format!("ws::addr={host}:{port};compression=raw;");
    let mut reader = PipelinedReader::from_conf(&conf).expect("connect");
    reader.reset_timing();
    let bytes_before = reader.bytes_received();
    let mut rows: u64 = 0;
    let mut checksum: u64 = 0;
    let mut iter_ns: u128 = 0;
    let skip_iter = std::env::var("SKIP_ITER").is_ok();

    let sql = format!("SELECT ts, id, price, sym, note FROM {TABLE}");
    let start = Instant::now();
    let mut cursor = reader.prepare(&sql).execute().expect("execute");
    loop {
        match cursor.take_event().expect("take_event") {
            Event::Batch(view) => {
                let n = view.row_count();
                if skip_iter {
                    rows += n as u64;
                    continue;
                }
                let t1 = Instant::now();
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

                for r in 0..n {
                    let ts_v = if ts.is_null(r) { 0 } else { ts.value(r) };
                    let id_v = if id.is_null(r) { 0 } else { id.value(r) };
                    let price_bits = if price.is_null(r) {
                        0
                    } else {
                        price.value(r).to_bits() as i64
                    };
                    let sym_len = sym.resolve(r).map(str::len).unwrap_or(0) as i64;
                    let note_len = note.value(r).map(str::len).unwrap_or(0) as i64;
                    checksum ^= (ts_v ^ id_v ^ price_bits ^ sym_len ^ note_len) as u64;
                }
                iter_ns += t1.elapsed().as_nanos();
                rows += n as u64;
            }
            Event::End { .. } | Event::ExecDone { .. } => break,
            Event::FailoverReset(ev) => {
                eprintln!(
                    "[failover] {} → {} after {} attempt(s); discarding partial state",
                    ev.failed_addr, ev.new_addr, ev.attempts
                );
                rows = 0;
                checksum = 0;
            }
            // `Event` is `#[non_exhaustive]` so future protocol
            // additions don't break this match. Skipping any
            // unfamiliar event matches the conservative-consumer
            // pattern recommended for non-exhaustive enums.
            _ => continue,
        }
    }
    let elapsed = start.elapsed();
    drop(cursor);
    let bytes = reader.bytes_received() - bytes_before;
    let read_ns = reader.read_ns();
    let decode_ns = reader.decode_ns();
    let phase = if warmup { "[warmup]" } else { "[measure]" };
    println!(
        "{phase} PIPELINED : {rows} rows in {} ms  read={} ms  decode={} ms  iter={} ms  ({:.2} MiB on wire, checksum=0x{:x})",
        elapsed.as_millis(),
        read_ns / 1_000_000,
        decode_ns / 1_000_000,
        iter_ns / 1_000_000,
        bytes as f64 / (1024.0 * 1024.0),
        checksum
    );
    Result {
        elapsed,
        rows,
        bytes,
    }
}

fn ingest_rows(host: &str, port: u16, row_count: u64) {
    println!("ingesting {row_count} rows over ILP/HTTP...");
    let start = Instant::now();
    let mut sender = Sender::from_conf(format!("http::addr={host}:{port};")).expect("sender");
    let mut buf = Buffer::new(sender.protocol_version());
    let flush_every: u64 = 10_000;
    for i in 1..=row_count {
        buf.table(TABLE)
            .unwrap()
            .symbol("sym", SYMBOLS[(i as usize) % SYMBOLS.len()])
            .unwrap()
            .column_i64("id", i as i64)
            .unwrap()
            .column_f64("price", i as f64 * 1.5)
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

fn recreate_table(host: &str, port: u16) {
    let drop = format!("DROP TABLE IF EXISTS {TABLE}");
    let create = format!(
        "CREATE TABLE {TABLE} (\
            ts TIMESTAMP, id LONG, price DOUBLE, sym SYMBOL, note VARCHAR\
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
