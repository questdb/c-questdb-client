//! Compare lease overhead and flush size against an existing QWP server.
//! Set QWP_POOL_BENCH_TABLE to a fresh table; warmup rows have negative qty.
use std::hint::black_box;
use std::time::{Duration, Instant};

use questdb::ingress::{AckLevel, Buffer, Sender, SenderBuilder, TimestampNanos};
use questdb::{QuestDb, Result};

const BASE_TS: i64 = 1_700_000_000_000_000_000;

fn env(name: &str, default: &str) -> String {
    std::env::var(format!("QWP_POOL_BENCH_{name}")).unwrap_or_else(|_| default.to_owned())
}

fn number(name: &str, default: &str) -> usize {
    env(name, default)
        .parse()
        .expect("expected a positive integer")
}

#[cfg(unix)]
fn cpu_ms() -> f64 {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    assert_eq!(
        // SAFETY: usage points to writable storage for one rusage.
        unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) },
        0
    );
    // SAFETY: getrusage succeeded and initialized usage.
    let usage = unsafe { usage.assume_init() };
    (usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) as f64 * 1000.0
        + (usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) as f64 / 1000.0
}

#[cfg(not(unix))]
fn cpu_ms() -> f64 {
    f64::NAN
}

fn fill(
    buffer: &mut Buffer,
    table: &str,
    symbols: &[String],
    start: i64,
    rows: usize,
) -> Result<()> {
    for offset in 0..rows {
        let seq = start + offset as i64;
        buffer
            .table(table)?
            .symbol("sym", &symbols[seq.unsigned_abs() as usize % symbols.len()])?
            .column_i64("qty", seq)?
            .column_f64("px", 100.0 + (seq & 1023) as f64)?
            .at(TimestampNanos::new(BASE_TS + seq))?;
    }
    Ok(())
}

struct Measurement {
    publish_ms: f64,
    total_ms: f64,
    publish_cpu_ms: f64,
    total_cpu_ms: f64,
    frames: u64,
}

fn run(
    db: &QuestDb,
    table: &str,
    symbols: &[String],
    mode: &str,
    start: i64,
    rows: usize,
    batch: usize,
) -> Result<Measurement> {
    let mut buffer = db.new_buffer();
    let before = db.borrow_sender()?.published_fsn()?.map_or(0, |v| v + 1);
    let mut held = if mode == "hold" {
        Some(db.borrow_sender()?)
    } else {
        None
    };
    let cpu_start = cpu_ms();
    let started = Instant::now();
    match mode {
        "hold" => {
            let sender = held.as_mut().unwrap();
            for offset in (0..rows).step_by(batch) {
                fill(
                    &mut buffer,
                    table,
                    symbols,
                    start + offset as i64,
                    batch.min(rows - offset),
                )?;
                sender.flush_buffer(&mut buffer)?;
            }
        }
        "per_flush" => {
            for offset in (0..rows).step_by(batch) {
                let mut sender = db.borrow_sender()?;
                fill(
                    &mut buffer,
                    table,
                    symbols,
                    start + offset as i64,
                    batch.min(rows - offset),
                )?;
                sender.flush_buffer(&mut buffer)?;
                // wait() is lease-scoped: retain the final publishing lease for the ACK barrier.
                if offset + batch >= rows {
                    held = Some(sender);
                }
            }
        }
        "borrow_only" => {
            for _ in 0..rows {
                black_box(db.borrow_sender()?);
            }
        }
        _ => panic!("mode must be hold, per_flush, or borrow_only"),
    }
    let publish_ms = started.elapsed().as_secs_f64() * 1000.0;
    let publish_cpu_ms = cpu_ms() - cpu_start;
    let mut sender = match held.take() {
        Some(sender) => sender,
        None => db.borrow_sender()?,
    };
    let after = sender.published_fsn()?.map_or(0, |v| v + 1);
    let frames = after - before;
    assert_eq!(
        frames,
        if mode == "borrow_only" {
            0
        } else {
            rows.div_ceil(batch) as u64
        }
    );
    if env("PAUSE_AFTER_PUBLISH", "off") == "on" {
        use std::io::Write;
        println!("qwp_pool_bench_published rows={rows} publications={frames}");
        std::io::stdout().flush().unwrap();
        // The recovery probe kills this process only after every flush returned.
        loop {
            std::thread::park();
        }
    }
    sender.wait(AckLevel::Ok, Duration::from_secs(60))?;
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;
    let total_cpu_ms = cpu_ms() - cpu_start;
    Ok(Measurement {
        publish_ms,
        total_ms,
        publish_cpu_ms,
        total_cpu_ms,
        frames,
    })
}

fn run_standalone(
    sender: &mut Sender,
    table: &str,
    symbols: &[String],
    start: i64,
    rows: usize,
    batch: usize,
) -> Result<Measurement> {
    let mut buffer = sender.new_buffer();
    let before = sender.published_fsn()?.map_or(0, |v| v + 1);
    let cpu_start = cpu_ms();
    let started = Instant::now();
    for offset in (0..rows).step_by(batch) {
        fill(
            &mut buffer,
            table,
            symbols,
            start + offset as i64,
            batch.min(rows - offset),
        )?;
        sender.flush(&mut buffer)?;
    }
    let publish_ms = started.elapsed().as_secs_f64() * 1000.0;
    let publish_cpu_ms = cpu_ms() - cpu_start;
    let frames = sender.published_fsn()?.map_or(0, |v| v + 1) - before;
    assert_eq!(frames, rows.div_ceil(batch) as u64);
    sender.wait(AckLevel::Ok, Duration::from_secs(60))?;
    Ok(Measurement {
        publish_ms,
        total_ms: started.elapsed().as_secs_f64() * 1000.0,
        publish_cpu_ms,
        total_cpu_ms: cpu_ms() - cpu_start,
        frames,
    })
}

fn main() -> Result<()> {
    let conf = env(
        "CONF",
        "ws::addr=127.0.0.1:9000;sender_pool_min=1;sender_pool_max=1;pool_reap=manual;",
    );
    let table =
        std::env::var("QWP_POOL_BENCH_TABLE").expect("set QWP_POOL_BENCH_TABLE to a fresh table");
    let mode = env("MODE", "hold");
    if mode == "recover" {
        let db = QuestDb::connect(&conf)?;
        drop(db.borrow_sender()?);
        db.close();
        println!("mode=recover table={table}");
        return Ok(());
    }
    let rows = number("ROWS", "1000000");
    let batch = number("BATCH", "1");
    let warmup = number("WARMUP", "10000");
    assert!(env("PAUSE_AFTER_PUBLISH", "off") != "on" || warmup == 0);
    let cardinality = number("SYMBOLS", "1000");
    assert!(rows > 0 && batch > 0 && cardinality > 0);
    assert!(rows < i64::MAX as usize && warmup < i64::MAX as usize);
    let symbols: Vec<_> = (0..cardinality).map(|i| format!("SYM{i:04}")).collect();
    let m = if mode == "standalone" {
        let mut sender = SenderBuilder::from_conf(&conf)?.build()?;
        if warmup > 0 {
            run_standalone(
                &mut sender,
                &table,
                &symbols,
                -(warmup as i64),
                warmup,
                batch,
            )?;
        }
        run_standalone(&mut sender, &table, &symbols, 0, rows, batch)?
    } else {
        let db = QuestDb::connect(&conf)?;
        if warmup > 0 {
            run(
                &db,
                &table,
                &symbols,
                &mode,
                -(warmup as i64),
                warmup,
                batch,
            )?;
        }
        run(&db, &table, &symbols, &mode, 0, rows, batch)?
    };
    println!(
        "mode={mode} rows={rows} batch={batch} warmup={warmup} symbols={cardinality} frames={} \
         publish_ms={:.3} drain_ms={:.3} total_ms={:.3} publish_cpu_ms={:.3} total_cpu_ms={:.3} \
         acked_rows_per_sec={:.0} table={table}",
        m.frames,
        m.publish_ms,
        m.total_ms - m.publish_ms,
        m.total_ms,
        m.publish_cpu_ms,
        m.total_cpu_ms,
        rows as f64 * 1000.0 / m.total_ms,
    );
    Ok(())
}
