//! Egress (reader) leg drivers (§S1).
//!
//! The egress legs exercise the QWP/WebSocket **reader** under sustained query
//! load with server restarts, complementing the ingest legs. They read back a
//! table an ingest leg populated and assert a cheap correctness invariant:
//! every `c_seq` in the scanned range is present, i.e. `count >= max - min + 1`.
//! `count < span` means a missing `c_seq` — real loss (fatal). `count > span`
//! is duplicate `c_seq`, expected under Direct-backend failover re-drive (I2;
//! the oracle bounds it at reconcile) and only logged, not fatal. So a decode /
//! loss bug shows up as LOSS or a query error rather than a silent wrong answer.
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

/// Scan only the most recent `SCAN_WINDOW` rows (QuestDB `LIMIT -N` reads the
/// tail). An unbounded full-scan grows with the table and, over a multi-hour
/// run, eventually can't finish between fault episodes — so the reader never
/// completes a query and the leg stalls. A bounded window keeps each scan fast
/// and streaming regardless of table size, while still exercising the reader
/// and catching a gap/dup in the recent tail (table-wide completeness is the
/// oracle's job at reconcile). The QWP egress reader caps an absolute `LIMIT`
/// at 10000, so the window can't exceed that.
const SCAN_WINDOW: u64 = 10_000;

/// Full-scan `c_seq` for `worker_id`, returning (count, min, max) over the
/// non-null values. Exercises the reader transport + batch decode.
fn scan_seq(
    reader: &mut questdb::BorrowedReader<'_>,
    table: &str,
    worker_id: u32,
) -> questdb::Result<(u64, i64, i64)> {
    let sql =
        format!("SELECT c_seq FROM {table} WHERE worker_id = {worker_id} LIMIT -{SCAN_WINDOW}");
    let mut cursor = reader.prepare(&sql).execute()?;
    let mut count: u64 = 0;
    let mut min = i64::MAX;
    let mut max = i64::MIN;
    while let Some(view) = cursor.next_batch()? {
        let n = view.row_count();
        let col = match view.column(0)? {
            ColumnView::Long(c) => c,
            other => {
                return Err(questdb::Error::new(
                    questdb::ErrorCode::ProtocolError,
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
    let mut losses: u64 = 0; // count < span: a missing c_seq => real loss (fatal)
    let mut dup_surplus: u64 = 0; // last-seen count - span (>0 => duplicates)
    let mut max_dup_surplus: u64 = 0; // high-water mark for the end-of-run summary
    let mut last_err: Option<String> = None; // dedupe transient-error logging

    let mut reader = db.borrow_reader()?;

    while !crate::stop_requested() && start.elapsed() < cfg.duration {
        match scan_seq(&mut reader, &cfg.table, cfg.worker_id) {
            Ok((count, min, max)) => {
                queries += 1;
                rows_read += count;
                last_err = None; // a successful scan closes any error streak
                if count > 0 {
                    let span = (max - min + 1) as u64;
                    if count < span {
                        // Fewer rows than the seq range spans => a missing
                        // c_seq => real loss. This is what the egress leg guards.
                        losses += 1;
                        eprintln!(
                            "{}: egress LOSS: count={count} < span={span} (min={min} max={max})",
                            cfg.leg
                        );
                    } else if count > span {
                        // More rows than the range spans => duplicate c_seq,
                        // expected under Direct-backend failover re-drive (I2,
                        // bounded dup; the oracle bounds it at reconcile). Log
                        // only when the surplus changes so we don't flood.
                        let surplus = count - span;
                        if surplus != dup_surplus {
                            eprintln!(
                                "{}: egress dup surplus={surplus} (count={count} span={span}); \
                                 expected under failover re-drive",
                                cfg.leg
                            );
                            dup_surplus = surplus;
                            max_dup_surplus = max_dup_surplus.max(surplus);
                        }
                    } else {
                        // count == span: clean. Reset so a later recurrence logs.
                        dup_surplus = 0;
                    }
                }
            }
            Err(e) => {
                // Transport churn is expected: a server bounce (Broken pipe /
                // reset), or the brief startup window before the ingest leg
                // creates `c_seq` (Invalid column). A large dataset can keep the
                // faulted server down a while during a graceful restart, so
                // retry patiently rather than give up — a slow restart is not
                // the reader's fault. The end-of-run `queries == 0` check still
                // catches a reader that never worked at all. Log once per error
                // streak so the churn doesn't flood the log.
                let msg = e.to_string();
                if last_err.as_deref() != Some(msg.as_str()) {
                    eprintln!("{}: egress query error (retrying): {msg}", cfg.leg);
                    last_err = Some(msg);
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
            stats.emit(&db, rows_read, rows_read, None, None)?;
            last_stats = Instant::now();
        }
    }

    // Release the reader so the final quiesce sample sees the pool drained (I4).
    drop(reader);
    stats.emit(&db, rows_read, rows_read, None, None)?;
    if max_dup_surplus > 0 {
        eprintln!(
            "{}: egress observed max dup surplus={max_dup_surplus} \
             (duplicates are bounded by the oracle's I2 check)",
            cfg.leg
        );
    }
    if losses > 0 {
        return Err(format!("{}: {losses} egress LOSS event(s) detected", cfg.leg).into());
    }
    if queries == 0 {
        return Err(format!(
            "{}: egress never completed a scan (reader unreachable the whole run)",
            cfg.leg
        )
        .into());
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
