//! DataFrame (Polars) leg driver (§S1) — behind the `dataframe` feature.
//!
//! Exercises the `DataFrame -> Arrow -> chunk` ingest path that the Python
//! wrapper uses: builds a Polars [`DataFrame`] per batch from the generator and
//! flushes it via [`QuestDb::flush_polars_dataframe`], advancing the same
//! fsync'd journal as the other legs. Covers a representative column set
//! (i64 / f64 / bool / symbol / designated timestamp) — enough to drive the
//! DataFrame conversion machinery; the full 22-type matrix is the column leg's.

use std::thread::sleep;
use std::time::{Duration, Instant};

use polars::prelude::{
    Column, DataFrame, DataType as PlDataType, IntoColumn, NamedFrom, PlSmallStr, Series, TimeUnit,
};
use questdb::ingress::polars::PolarsIngestOptions;
use questdb::ingress::ColumnName;
use questdb::{ErrorCode, QuestDb};

use crate::gen::{self, Expected, QwpType};
use crate::journal::AckJournal;
use crate::legs::LegConfig;
use crate::stats::StatsWriter;

const TS_BASE_NANOS: i64 = 1_600_000_000_000_000_000;

type LegResult = Result<(), Box<dyn std::error::Error>>;

/// Build one batch's DataFrame for `seq_start .. seq_start + rows`.
fn build_df(
    cfg: &LegConfig,
    seq_start: u64,
    rows: usize,
) -> Result<DataFrame, Box<dyn std::error::Error>> {
    let mut worker = Vec::with_capacity(rows);
    let mut seqs = Vec::with_capacity(rows);
    let mut ts = Vec::with_capacity(rows);
    let mut bools = Vec::with_capacity(rows);
    let mut longs: Vec<Option<i64>> = Vec::with_capacity(rows);
    let mut doubles: Vec<Option<f64>> = Vec::with_capacity(rows);
    let mut syms: Vec<Option<String>> = Vec::with_capacity(rows);

    for i in 0..rows {
        let s = seq_start + i as u64;
        worker.push(i64::from(cfg.worker_id));
        seqs.push(s as i64);
        ts.push(TS_BASE_NANOS + (s as i64) * 1000);
        bools.push(matches!(
            gen::gen_expected(cfg.seed, cfg.worker_id, s, QwpType::Boolean),
            Expected::Bool(true)
        ));
        longs.push(
            match gen::gen_expected(cfg.seed, cfg.worker_id, s, QwpType::Long) {
                Expected::Int(v) => Some(v as i64),
                _ => None,
            },
        );
        doubles.push(
            match gen::gen_expected(cfg.seed, cfg.worker_id, s, QwpType::Double) {
                Expected::Float(v) => Some(v),
                _ => None,
            },
        );
        syms.push(
            match gen::gen_expected(cfg.seed, cfg.worker_id, s, QwpType::Symbol) {
                Expected::Text(t) => Some(t),
                _ => None,
            },
        );
    }

    let sym_refs: Vec<Option<&str>> = syms.iter().map(|o| o.as_deref()).collect();
    let ts_col = Series::new(PlSmallStr::from("timestamp"), &ts)
        .cast(&PlDataType::Datetime(TimeUnit::Nanoseconds, None))?;

    let columns: Vec<Column> = vec![
        Series::new(PlSmallStr::from("worker_id"), &worker).into_column(),
        Series::new(PlSmallStr::from("c_seq"), &seqs).into_column(),
        ts_col.into_column(),
        Series::new(PlSmallStr::from("c_bool"), &bools).into_column(),
        Series::new(PlSmallStr::from("c_long"), longs).into_column(),
        Series::new(PlSmallStr::from("c_double"), doubles).into_column(),
        Series::new(PlSmallStr::from("c_symbol"), sym_refs).into_column(),
    ];
    Ok(DataFrame::new(rows, columns)?)
}

pub fn run_dataframe_leg(cfg: &LegConfig) -> LegResult {
    let conf = crate::legs::build_conf(cfg);
    let db = QuestDb::connect(&conf)?;
    let mut journal = AckJournal::open(&cfg.journal_path)?;
    let mut stats = StatsWriter::create(&cfg.stats_path)?;

    let opts = PolarsIngestOptions::new().timestamp_column(ColumnName::new("timestamp")?);

    let mut seq = journal.resume_seq();
    let mut rows_sent: u64 = 0;
    let start = Instant::now();
    let mut last_stats = Instant::now();
    let mut stuck: u32 = 0;
    const STUCK_LIMIT: u32 = 500;

    while !crate::stop_requested() && start.elapsed() < cfg.duration {
        let batch_start = seq;
        let rows = cfg.batch as usize;
        let df = build_df(cfg, batch_start, rows)?;
        let last_seq = batch_start + rows as u64 - 1;

        match db.flush_polars_dataframe(cfg.table.as_str(), &df, &opts) {
            Ok(()) => {
                journal.record(last_seq)?;
                seq = last_seq + 1;
                stuck = 0;
            }
            Err(e) => {
                let transient = e.code() == ErrorCode::FailoverRetry;
                eprintln!(
                    "{}: dataframe flush error at {batch_start}..={last_seq} \
                     (transient={transient}): {e}",
                    cfg.leg
                );
                stuck += 1;
                if stuck > STUCK_LIMIT {
                    return Err(format!(
                        "{}: {STUCK_LIMIT} re-drives without progress: {e}",
                        cfg.leg
                    )
                    .into());
                }
                sleep(Duration::from_millis(200));
                seq = journal.resume_seq();
                continue;
            }
        }

        rows_sent += rows as u64;
        crate::legs::rate_limit(cfg, rows_sent, start);

        if last_stats.elapsed() >= Duration::from_secs(5) {
            let rows_acked = journal.watermark().map_or(0, |w| w + 1);
            stats.emit(&db, rows_sent, rows_acked, None, None)?;
            last_stats = Instant::now();
        }
    }

    let rows_acked = journal.watermark().map_or(0, |w| w + 1);
    stats.emit(&db, rows_sent, rows_acked, None, None)?;
    Ok(())
}
