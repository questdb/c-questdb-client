//! Throughput benchmark for `SELECT * FROM hits` against a local QuestDB
//! instance over QWP egress.
//!
//! Schema-agnostic: just drives `next_batch()` to terminal and reports
//! rows, wire bytes, MB/s and rows/s. Splits server-read time from
//! decode time using `Reader::read_ns` / `Reader::decode_ns`.
//!
//! Defaults assume the local-dev setup: `localhost:9000`, basic auth
//! `admin/quest`. Override anything via env:
//!
//! ```text
//! QDB_ADDR=localhost:9000     host:port (single endpoint)
//! QDB_USER=admin              basic-auth user; set to "" to disable auth
//! QDB_PASS=quest              basic-auth password
//! QDB_SQL="select * from hits"
//! QDB_COMPRESSION=zstd        "zstd" (default — server picks) or "raw"
//! QDB_MAX_BATCH_ROWS=0        cap rows-per-batch (0 = server default).
//!                             Bump down (e.g. 10_000) if you see
//!                             "batch too large for send buffer" on
//!                             wide tables like ClickBench `hits`.
//! QDB_WARMUP=1                run one discarded pass first (default: on)
//! QDB_TOUCH=0                 set to 1 to read every cell of every column
//!                             (forces decode work to actually be observed
//!                             by the consumer; off by default since
//!                             next_batch already eagerly decodes the body)
//! ```
//!
//! Run:
//! ```text
//! cargo run --release --features sync-reader-ws \
//!     --example qwp_egress_hits
//! ```

use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;
use std::time::{Duration, Instant};

struct Run {
    elapsed: Duration,
    rows: u64,
    batches: u64,
    columns: usize,
    wire_bytes: u64,
    /// Sum of per-batch decoded column buffer sizes. With `compression=raw`
    /// this equals `wire_bytes` minus framing overhead. With `compression=zstd`
    /// it is the post-decompression body size — the apples-to-apples figure
    /// for comparing against other clients that report "decompressed MiB/s".
    body_bytes: u64,
    read_ns: u64,
    decode_ns: u64,
}

fn main() {
    let addr = std::env::var("QDB_ADDR").unwrap_or_else(|_| "localhost:9000".into());
    let user = std::env::var("QDB_USER").unwrap_or_else(|_| "admin".into());
    let pass = std::env::var("QDB_PASS").unwrap_or_else(|_| "quest".into());
    let sql = std::env::var("QDB_SQL").unwrap_or_else(|_| "select * from hits".into());
    let compression = std::env::var("QDB_COMPRESSION").unwrap_or_else(|_| "zstd".into());
    let max_batch_rows: u64 = std::env::var("QDB_MAX_BATCH_ROWS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let warmup = env_bool("QDB_WARMUP", true);
    let touch = env_bool("QDB_TOUCH", false);

    let mut conf = format!("qwp::addr={addr};compression={compression};");
    if let Ok(lvl) = std::env::var("QDB_COMPRESSION_LEVEL") {
        conf.push_str(&format!("compression_level={lvl};"));
    }
    if max_batch_rows > 0 {
        conf.push_str(&format!("max_batch_rows={max_batch_rows};"));
    }
    if !user.is_empty() {
        conf.push_str(&format!("username={user};password={pass};"));
    }

    println!("config : {}", redact_pass(&conf));
    println!("sql    : {sql:?}");
    println!("touch  : {touch}");

    let mut reader = Reader::from_conf(&conf).expect("connect to QuestDB");

    if warmup {
        println!();
        println!("=== Warmup (discarded) ===");
        let r = run(&mut reader, &sql, touch);
        report(&r, "warmup");
    }

    println!();
    println!("=== Measurement ===");
    let r = run(&mut reader, &sql, touch);
    report(&r, "measure");

    println!();
    println!("=== Summary ===");
    let secs = r.elapsed.as_secs_f64();
    let wire_mib_per_s = r.wire_bytes as f64 / secs / (1024.0 * 1024.0);
    let body_mib_per_s = r.body_bytes as f64 / secs / (1024.0 * 1024.0);
    let rows_per_s = r.rows as f64 / secs;
    let ratio = r.body_bytes as f64 / r.wire_bytes as f64;
    println!("rows         : {}", r.rows);
    println!("batches      : {}", r.batches);
    println!("columns      : {}", r.columns);
    println!(
        "wire bytes   : {} ({:.2} MiB)",
        r.wire_bytes,
        r.wire_bytes as f64 / (1024.0 * 1024.0),
    );
    println!(
        "body bytes   : {} ({:.2} MiB) — compression ratio {:.2}x",
        r.body_bytes,
        r.body_bytes as f64 / (1024.0 * 1024.0),
        ratio,
    );
    println!("elapsed      : {:.3} s", secs);
    println!("wire MiB/s   : {wire_mib_per_s:.2}   (compressed bytes / elapsed)");
    println!(
        "body MiB/s   : {body_mib_per_s:.2}   (decompressed bytes / elapsed — apples-to-apples)"
    );
    println!("row rate     : {:.0} rows/s", rows_per_s);
    println!(
        "read / dec   : {} ms / {} ms",
        r.read_ns / 1_000_000,
        r.decode_ns / 1_000_000
    );
}

fn run(reader: &mut Reader, sql: &str, touch: bool) -> Run {
    reader.reset_timing();
    let bytes_before = reader.bytes_received();

    let start = Instant::now();
    let mut cursor = reader.prepare(sql).execute().expect("execute SELECT");

    let mut rows: u64 = 0;
    let mut batches: u64 = 0;
    let mut columns: usize = 0;
    let mut body_bytes: u64 = 0;
    let mut sink: u64 = 0;

    while let Some(view) = cursor.next_batch().expect("next_batch") {
        let n = view.row_count();
        rows += n as u64;
        batches += 1;
        columns = view.column_count();
        for c in 0..columns {
            let col = view.column(c).expect("column");
            body_bytes += column_byte_size(&col, n);
            if touch {
                sink ^= touch_column(&col, n);
            }
        }
    }
    let elapsed = start.elapsed();
    drop(cursor);

    // Keep `sink` from being optimised away.
    std::hint::black_box(sink);

    Run {
        elapsed,
        rows,
        batches,
        columns,
        wire_bytes: reader.bytes_received() - bytes_before,
        body_bytes,
        read_ns: reader.read_ns(),
        decode_ns: reader.decode_ns(),
    }
}

/// Approximate post-decompression body size for a single column-batch.
/// Fixed-width columns: `rows * elem_size`. Varlen columns: the data buffer.
/// Validity bitmaps and per-column framing are ignored — close enough for
/// comparing wire vs decompressed throughput at MiB/s granularity.
fn column_byte_size(col: &ColumnView<'_>, n: usize) -> u64 {
    let n = n as u64;
    match col {
        ColumnView::Boolean(_) => n.div_ceil(8),
        ColumnView::Byte(_) | ColumnView::Char(_) => n,
        ColumnView::Short(_) => n * 2,
        ColumnView::Int(_) | ColumnView::Float(_) | ColumnView::Ipv4(_) => n * 4,
        ColumnView::Long(_)
        | ColumnView::Double(_)
        | ColumnView::Date(_)
        | ColumnView::Timestamp(_) => n * 8,
        ColumnView::Uuid(_) => n * 16,
        ColumnView::Long256(_) => n * 32,
        ColumnView::Symbol(c) => n * 4 + c.dict().heap_bytes() as u64,
        ColumnView::Varchar(c) => c.data().len() as u64 + n * 4,
        ColumnView::Binary(c) => c.data().len() as u64 + n * 4,
        // Catch-all for less-common types; underestimates but cheap.
        _ => n * 8,
    }
}

/// Best-effort per-cell touch so callers can measure end-to-end decode +
/// consume cost rather than just the eager next_batch() decode. XORs a
/// cheap value derived from each cell into the sink.
fn touch_column(col: &ColumnView<'_>, n: usize) -> u64 {
    let mut acc: u64 = 0;
    match col {
        ColumnView::Boolean(c) => {
            for r in 0..n {
                acc ^= u64::from(c.value(r));
            }
        }
        ColumnView::Byte(c) => {
            for r in 0..n {
                acc ^= c.value(r) as u8 as u64;
            }
        }
        ColumnView::Short(c) => {
            for r in 0..n {
                acc ^= c.value(r) as u16 as u64;
            }
        }
        ColumnView::Char(c) => {
            for r in 0..n {
                acc ^= u64::from(c.value(r));
            }
        }
        ColumnView::Int(c) => {
            for r in 0..n {
                acc ^= c.value(r) as u32 as u64;
            }
        }
        ColumnView::Long(c) => {
            for r in 0..n {
                acc ^= c.value(r) as u64;
            }
        }
        ColumnView::Date(c) => {
            for r in 0..n {
                acc ^= c.value(r) as u64;
            }
        }
        ColumnView::Timestamp(c) => {
            for r in 0..n {
                acc ^= c.value(r) as u64;
            }
        }
        ColumnView::Float(c) => {
            for r in 0..n {
                acc ^= u64::from(c.value(r).to_bits());
            }
        }
        ColumnView::Double(c) => {
            for r in 0..n {
                acc ^= c.value(r).to_bits();
            }
        }
        ColumnView::Ipv4(c) => {
            for r in 0..n {
                acc ^= u64::from(c.value(r));
            }
        }
        ColumnView::Symbol(c) => {
            let dict = c.dict();
            let codes = c.codes();
            for &code in codes.iter().take(n) {
                acc ^= dict.get(code).map(str::len).unwrap_or(0) as u64;
            }
        }
        ColumnView::Varchar(c) => {
            for r in 0..n {
                acc ^= c.value(r).map(str::len).unwrap_or(0) as u64;
            }
        }
        ColumnView::Binary(c) => {
            for r in 0..n {
                acc ^= c.value(r).map(<[u8]>::len).unwrap_or(0) as u64;
            }
        }
        ColumnView::Uuid(c) => {
            for r in 0..n {
                if !c.is_null(r) {
                    let b = c.value(r);
                    acc ^= u64::from_le_bytes(b[..8].try_into().unwrap());
                }
            }
        }
        // Variants we don't bother specialising for: just consume the
        // raw byte length so decode still has to run.
        _ => {
            acc ^= n as u64;
        }
    }
    acc
}

fn report(r: &Run, phase: &str) {
    let secs = r.elapsed.as_secs_f64();
    let mb_per_s = r.wire_bytes as f64 / secs / 1_000_000.0;
    println!(
        "[{phase}] {} rows in {} batches ({} cols) — {:.3}s — {} bytes — {:.2} MB/s",
        r.rows, r.batches, r.columns, secs, r.wire_bytes, mb_per_s,
    );
}

fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "on"),
        Err(_) => default,
    }
}

fn redact_pass(conf: &str) -> String {
    let mut out = String::with_capacity(conf.len());
    for part in conf.split(';') {
        if part.is_empty() {
            continue;
        }
        if let Some(rest) = part.strip_prefix("password=") {
            out.push_str("password=");
            out.push_str(&"*".repeat(rest.len().min(8)));
        } else {
            out.push_str(part);
        }
        out.push(';');
    }
    out
}
