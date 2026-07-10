//! Egress (reader) leg drivers (§S1).
//!
//! The egress legs exercise the QWP/WebSocket **reader** under sustained query
//! load with server restarts, complementing the ingest legs. They read back a
//! table an ingest leg populated and assert a cheap correctness invariant
//! (every `c_seq` in the scanned range is present — `count == max - min + 1`),
//! so a decode / failover bug shows up as a gap or a query error rather than a
//! silent wrong answer.
//!
//! `rust-egress-whole` full-scans and materialises the whole `c_seq` column;
//! `rust-egress-stream` does the same but is driven batch-by-batch. Both share
//! the scan driver here; the distinction (transparent failover-reset vs an
//! explicit `FailoverWouldDuplicate`) is a follow-up once the legs run against
//! a restart-injecting proxy.

use std::thread::sleep;
use std::time::{Duration, Instant};

use questdb::egress::column::ColumnView;
use questdb::QuestDb;

use crate::legs::LegConfig;
use crate::stats::StatsWriter;

type LegResult = Result<(), Box<dyn std::error::Error>>;

/// Full-scan `c_seq` for `worker_id`, returning (count, min, max) over the
/// non-null values. Exercises the reader transport + batch decode.
fn scan_seq(
    reader: &mut questdb::BorrowedReader<'_>,
    table: &str,
    worker_id: u32,
) -> questdb::egress::error::Result<(u64, i64, i64)> {
    let sql = format!("SELECT c_seq FROM {table} WHERE worker_id = {worker_id}");
    let mut cursor = reader.prepare(&sql).execute()?;
    let mut count: u64 = 0;
    let mut min = i64::MAX;
    let mut max = i64::MIN;
    while let Some(view) = cursor.next_batch()? {
        let n = view.row_count();
        let col = match view.column(0)? {
            ColumnView::Long(c) => c,
            other => {
                return Err(questdb::egress::error::Error::new(
                    questdb::egress::error::ErrorCode::ProtocolError,
                    format!("c_seq not a Long column: {other:?}"),
                ))
            }
        };
        for r in 0..n {
            if !col.is_null(r) {
                let v = col.value(r);
                count += 1;
                min = min.min(v);
                max = max.max(v);
            }
        }
    }
    Ok((count, min, max))
}

/// Drive an egress leg: repeatedly scan the table and assert `c_seq`
/// contiguity, re-borrowing the reader on a transport failure.
pub fn run_egress_leg(cfg: &LegConfig) -> LegResult {
    let conf = crate::legs::build_conf(cfg);
    let db = QuestDb::connect(&conf)?;
    let mut stats = StatsWriter::create(&cfg.stats_path)?;

    let start = Instant::now();
    let mut last_stats = Instant::now();
    let mut queries: u64 = 0;
    let mut rows_read: u64 = 0;
    let mut gaps: u64 = 0;
    let mut stuck: u32 = 0;
    const STUCK_LIMIT: u32 = 500;

    let mut reader = db.borrow_reader()?;

    while start.elapsed() < cfg.duration {
        match scan_seq(&mut reader, &cfg.table, cfg.worker_id) {
            Ok((count, min, max)) => {
                queries += 1;
                rows_read += count;
                stuck = 0;
                // Every seq in [min, max] must be present: a gap means loss.
                if count > 0 && (max - min + 1) as u64 != count {
                    gaps += 1;
                    eprintln!("{}: egress gap: count={count} min={min} max={max}", cfg.leg);
                }
            }
            Err(e) => {
                eprintln!("{}: egress query error: {e}", cfg.leg);
                stuck += 1;
                if stuck > STUCK_LIMIT {
                    return Err(format!(
                        "{}: {STUCK_LIMIT} query failures without progress: {e}",
                        cfg.leg
                    )
                    .into());
                }
                drop(reader);
                sleep(Duration::from_millis(200));
                reader = reborrow_reader(&db, &cfg.leg)?;
                continue;
            }
        }

        // Query cadence: `target_rows_per_sec` is reused as a rough queries/sec
        // knob (÷1000) so egress load tracks the same throughput dial.
        let qps = (cfg.target_rows_per_sec / 1000).max(1);
        sleep(Duration::from_secs_f64(1.0 / qps as f64));

        if last_stats.elapsed() >= Duration::from_secs(5) {
            stats.emit(&db, rows_read, rows_read, Some(queries), Some(gaps))?;
            last_stats = Instant::now();
        }
    }

    stats.emit(&db, rows_read, rows_read, Some(queries), Some(gaps))?;
    if gaps > 0 {
        return Err(format!("{}: {gaps} egress gap(s) detected", cfg.leg).into());
    }
    Ok(())
}

fn reborrow_reader<'a>(
    db: &'a QuestDb,
    leg: &str,
) -> Result<questdb::BorrowedReader<'a>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match db.borrow_reader() {
            Ok(r) => return Ok(r),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("{leg}: reader re-borrow gave up: {e}").into());
                }
                sleep(Duration::from_millis(500));
            }
        }
    }
}
