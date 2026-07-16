/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 ******************************************************************************/

//! One [`QuestDb`] pool shared by an ingestion thread and a query thread.
//!
//! `QuestDb` is `Send + Sync` but not `Clone`: an application creates one
//! pool and shares it through an [`Arc`]. Each thread takes its own
//! short-lived borrow — a [`BorrowedSender`](questdb::BorrowedSender) here,
//! a [`BorrowedReader`](questdb::BorrowedReader) there — and `Drop` returns
//! the connection to the pool. The borrowed handles are neither `Send` nor
//! `Sync`, so a borrow never crosses a thread boundary; only the pool does.
//!
//! Both threads run against the same table at the same time:
//!
//! * **ingest** publishes trades in batches, blocking for an
//!   [`AckLevel::Ok`] ack per batch, and publishes the acked row count to
//!   `Progress`.
//! * **query** polls the table for rows carrying this run's `run_id` and
//!   prints how far query visibility trails the acked watermark.
//!
//! That gap is the point of the example. An `Ok` ack means the server
//! accepted the frame, not that the rows are queryable: a WAL table applies
//! writes asynchronously, so a row counted here was necessarily acked
//! earlier, and the count converges on the acked total once ingestion stops.
//! Bind the run marker into the query rather than reading a bare `count()`
//! so a leftover table cannot fake progress.
//!
//! The reported lag is an upper bound. Both threads sample a moving system,
//! so the printed figure carries the sampling skew between the query's
//! snapshot and the watermark load (see `query`). Against a local server the
//! true backlog is often zero — WAL apply keeps up with ingestion, and the
//! poll simply observes the count tracking the watermark. The reason to poll
//! is that visibility is not guaranteed at ack time, not that a lag is
//! guaranteed to be observable.
//!
//! Schema (created by this example, dropping any previous run):
//!     timestamp   TIMESTAMP  (designated)
//!     symbol      SYMBOL
//!     run_id      SYMBOL
//!     price       DOUBLE
//!     amount      DOUBLE
//!
//! Run against a local QuestDB instance:
//!     cargo run --release --features sync-sender-qwp-ws,sync-reader-qwp-ws \
//!         --example qwp_ws_shared_pool
//!
//! Positional args:
//!     1: connect string  (default `ws::addr=localhost:9000;` plus pool keys)
//!     2: table name      (default `trades_shared_pool`)
//!     3: row count       (default 200_000)

use std::error::Error;
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use questdb::QuestDb;
use questdb::egress::column::ColumnView;
use questdb::egress::reader::Reader;
use questdb::ingress::{AckLevel, TimestampNanos};

/// `sender_pool_max` / `query_pool_max` are the real pool keys; the
/// ingestion and query pools grow and cap independently. This example holds
/// one sender borrow and one reader borrow at a time, so a cap of 2 each
/// leaves headroom without opening connections it never uses.
const DEFAULT_CONF: &str = "ws::addr=localhost:9000;sender_pool_max=2;query_pool_max=2;";
const DEFAULT_TABLE: &str = "trades_shared_pool";
const DEFAULT_TOTAL_ROWS: usize = 200_000;

/// Rows per publish. Each batch is one `flush_buffer_and_wait`, so this also
/// sets how often the acked watermark advances.
const BATCH_ROWS: usize = 10_000;
/// How long the query thread keeps polling after ingestion has finished and
/// stopped advancing the watermark. Sized for WAL apply, not for ingestion.
const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(60);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

const SYMBOLS: &[&str] = &["ETH-USDT", "BTC-USDT", "SOL-USDT", "ADA-USDT"];

/// Ingestion's acked watermark, read by the query thread.
///
/// `done` is set on every ingestion exit path, success or failure, so the
/// query thread always terminates instead of polling to its deadline.
#[derive(Default)]
struct Progress {
    acked_rows: AtomicU64,
    done: AtomicBool,
}

fn main() -> Result<(), Box<dyn Error>> {
    let conf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_CONF.to_string());
    let table = std::env::args()
        .nth(2)
        .unwrap_or_else(|| DEFAULT_TABLE.to_string());
    let total_rows: usize = std::env::args()
        .nth(3)
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_TOTAL_ROWS);

    // Marks this run's rows so the query thread counts only what this
    // process ingested.
    let run_id = format!(
        "run-{}-{}",
        process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
    );

    println!("Connecting to {conf} ...");
    // One pool for the whole process. `connect` parses the connect string
    // and opens nothing: the pools fill on first borrow, from either thread.
    let db = Arc::new(QuestDb::connect(&conf)?);

    println!("Creating table {table} ...");
    create_table(&db, &table)?;
    println!("Ingesting {total_rows} rows as run_id={run_id}\n");

    let progress = Arc::new(Progress::default());
    let started = Instant::now();

    let ingest_thread = {
        let db = Arc::clone(&db);
        let progress = Arc::clone(&progress);
        let table = table.clone();
        let run_id = run_id.clone();
        thread::spawn(move || -> Result<(), String> {
            let result = ingest(&db, &progress, &table, &run_id, total_rows);
            progress.done.store(true, Ordering::Release);
            result.map_err(|e| format!("ingest: {e}"))
        })
    };

    let query_thread = {
        let db = Arc::clone(&db);
        let progress = Arc::clone(&progress);
        let table = table.clone();
        let run_id = run_id.clone();
        thread::spawn(move || -> Result<(), String> {
            query(&db, &progress, &table, &run_id, total_rows).map_err(|e| format!("query: {e}"))
        })
    };

    // Join both before reporting: an early return would drop `main`'s Arc
    // and exit the process while the other thread is still borrowing.
    let ingest_result = ingest_thread.join().map_err(|_| "ingest thread panicked")?;
    let query_result = query_thread.join().map_err(|_| "query thread panicked")?;
    ingest_result?;
    query_result?;

    println!(
        "\nBoth threads finished in {:.2}s. Verify in QuestDB:",
        started.elapsed().as_secs_f64()
    );
    println!("  SELECT count() FROM {table} WHERE run_id = '{run_id}';");
    Ok(())
}

/// Publishes `total_rows` trades in `BATCH_ROWS` batches, blocking for an
/// `Ok` ack per batch before advancing the watermark the query thread reads.
fn ingest(
    db: &QuestDb,
    progress: &Progress,
    table: &str,
    run_id: &str,
    total_rows: usize,
) -> questdb::Result<()> {
    // Borrowed on this thread and used only here: `BorrowedSender` is not
    // `Send`. The buffer is caller-owned data and is reused across flushes —
    // `flush_buffer_and_wait` clears it but keeps its capacity.
    let mut sender = db.borrow_sender()?;
    let mut buffer = sender.new_buffer();

    let base_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_nanos() as i64;

    let mut sent = 0usize;
    while sent < total_rows {
        let end = (sent + BATCH_ROWS).min(total_rows);
        for i in sent..end {
            buffer
                .table(table)?
                .symbol("symbol", SYMBOLS[i % SYMBOLS.len()])?
                .symbol("run_id", run_id)?
                .column_f64("price", 2615.54 + (i % 1_000) as f64 * 0.01)?
                .column_f64("amount", 0.00044 + (i % 97) as f64 * 0.00001)?
                // Monotonic 1 ms ladder, so the run occupies a predictable
                // window rather than colliding on a single instant.
                .at(TimestampNanos::new(base_ts + i as i64 * 1_000_000))?;
        }

        // Publish, then block until the server acks every frame through this
        // boundary. Highest throughput would be a bare `flush_buffer`, but
        // this example wants an acked watermark to compare against.
        sender.flush_buffer_and_wait(&mut buffer, AckLevel::Ok)?;
        sent = end;
        progress.acked_rows.store(sent as u64, Ordering::Release);
    }
    Ok(())
}

/// Polls for this run's rows until ingestion is done and every acked row is
/// visible, reporting the WAL-apply lag as it converges.
fn query(
    db: &QuestDb,
    progress: &Progress,
    table: &str,
    run_id: &str,
    total_rows: usize,
) -> questdb::Result<()> {
    let sql = format!("SELECT count(), max(price) FROM {table} WHERE run_id = $1");
    let mut deadline = Instant::now() + VISIBILITY_TIMEOUT;
    let mut last_visible = 0u64;

    loop {
        let ingest_done = progress.done.load(Ordering::Acquire);

        // Borrow per poll rather than holding a reader for the whole loop: a
        // borrow occupies its pool slot until `Drop`, including while this
        // thread sleeps.
        let (visible, max_price) = count_run(db, &sql, run_id)?;

        // Sample the watermark *after* the query returns. A row is only
        // visible once it was acked earlier, so an `acked` taken no earlier
        // than the query's snapshot is always >= `visible`. Loading it before
        // the query instead would compare a stale watermark against a newer
        // snapshot and report a negative lag as zero.
        //
        // Ingestion also advances during the query, so the difference is an
        // upper bound on the real backlog, not an exact measurement.
        let acked = progress.acked_rows.load(Ordering::Acquire);

        println!(
            "  acked {acked:>7} | visible {visible:>7} | lag <={:>6} | max(price) {}",
            acked.saturating_sub(visible),
            max_price.map_or_else(|| "-".to_string(), |p| format!("{p:.2}")),
        );

        if ingest_done && visible >= total_rows as u64 {
            return Ok(());
        }
        // Progress refreshes the deadline: it bounds a stall, not the run.
        if visible > last_visible {
            last_visible = visible;
            deadline = Instant::now() + VISIBILITY_TIMEOUT;
        }
        if Instant::now() >= deadline {
            return Err(questdb::Error::new(
                questdb::ErrorCode::SocketError,
                format!(
                    "stalled at {visible}/{total_rows} rows visible after {VISIBILITY_TIMEOUT:?}"
                ),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// Runs the bound count query and drains its cursor. Returns the row count
/// and the highest price seen, which is `None` while the run has no visible
/// rows yet.
fn count_run(db: &QuestDb, sql: &str, run_id: &str) -> questdb::Result<(u64, Option<f64>)> {
    let mut reader = db.borrow_reader()?;
    let mut cursor = reader.prepare(sql).bind_varchar(run_id).execute()?;

    let mut count = 0u64;
    let mut max_price = None;

    // An aggregate over a bound predicate returns a single row, but the
    // cursor contract requires draining every batch (or calling `cancel()`),
    // so this loop is the general idiom rather than an optimistic one-shot.
    while let Some(batch) = cursor.next_batch()? {
        let ColumnView::Long(count_col) = batch.column(0)? else {
            unreachable!("count() is LONG")
        };
        let ColumnView::Double(price_col) = batch.column(1)? else {
            unreachable!("max(price) is DOUBLE")
        };
        for row in 0..batch.row_count() {
            if !count_col.is_null(row) {
                count = count_col.value(row) as u64;
            }
            // `max()` over zero matching rows is NULL. Check before reading:
            // the raw value in a null slot is only a sentinel.
            if !price_col.is_null(row) {
                max_price = Some(price_col.value(row));
            }
        }
    }
    Ok((count, max_price))
}

/// Creates the table over QWP. The reader runs DDL as well as SELECTs, so
/// the example needs no HTTP client alongside the pool.
fn create_table(db: &QuestDb, table: &str) -> questdb::Result<()> {
    let mut reader = db.borrow_reader()?;
    exec(&mut reader, &format!("DROP TABLE IF EXISTS {table}"))?;
    exec(
        &mut reader,
        &format!(
            "CREATE TABLE {table} (\
                 timestamp TIMESTAMP, \
                 symbol SYMBOL, \
                 run_id SYMBOL, \
                 price DOUBLE, \
                 amount DOUBLE\
             ) TIMESTAMP(timestamp) PARTITION BY HOUR WAL"
        ),
    )
}

/// Runs a statement that returns no rows. The cursor still has to be drained;
/// its terminal value reports `ExecDone` rather than a result set.
fn exec(reader: &mut Reader, sql: &str) -> questdb::Result<()> {
    let mut cursor = reader.execute(sql)?;
    while cursor.next_batch()?.is_some() {}
    Ok(())
}
