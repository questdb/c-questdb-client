//! Ingest / egress leg drivers (§S1).
//!
//! A leg is one workload process: it generates rows from [`crate::gen`], drives
//! them into QuestDB through a pool, advances its fsync'd [`AckJournal`] as acks
//! land, and emits [`StatsWriter`] samples. On a transient failure it re-borrows
//! from the pool and re-drives from the journal watermark (bounded so a terminal
//! error can't spin forever).
//!
//! The Buffer, Chunk, and mixed Buffer/Chunk/Arrow SFA legs all use the unified
//! ingestion pool. The conf string selects default memory, explicitly bounded
//! memory, or disk storage. The DataFrame leg uses direct whole-source delivery;
//! Chunk and DataFrame cover the full 22-type matrix while Buffer covers its
//! expressible subset.

use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};

use questdb::ingress::{AckLevel, Buffer, TimestampNanos};
use questdb::{ErrorCode, QuestDb};

use crate::gen::{self, Expected, QwpType};
use crate::journal::AckJournal;
use crate::stats::StatsWriter;

/// Fixed epoch-nanos base for the designated timestamp: `base + seq * 1000`.
/// Deterministic (no wall-clock), monotonic per worker, and unique per `seq`
/// so `DEDUP UPSERT KEYS(ts, worker_id)` collapses re-sent duplicates.
const TS_BASE_NANOS: i64 = 1_600_000_000_000_000_000; // ~2020-09-13

/// One leg's runtime configuration, parsed from the CLI.
#[derive(Debug, Clone)]
pub struct LegConfig {
    pub leg: String,
    pub seed: u64,
    pub worker_id: u32,
    pub addr: String,
    pub table: String,
    pub journal_path: PathBuf,
    pub stats_path: PathBuf,
    pub target_rows_per_sec: u64,
    pub sf_dir: Option<PathBuf>,
    pub sf_mem_bytes: Option<u64>,
    pub duration: Duration,
    pub batch: u64,
}

type LegResult = Result<(), Box<dyn std::error::Error>>;

/// Dispatch to the leg driver by name.
pub fn run_leg(cfg: &LegConfig) -> LegResult {
    match cfg.leg.as_str() {
        "rust-buffer-saf-default"
        | "rust-buffer-saf-disk"
        | "rust-buffer-saf-mem"
        | "control-buffer-saf-default" => run_buffer_leg(cfg),
        "rust-chunk-saf-default" => crate::chunk_leg::run_chunk_leg(cfg),
        "rust-mixed-saf-disk" | "rust-mixed-saf-mem" => crate::mixed_leg::run_mixed_leg(cfg),
        "rust-egress-whole" | "rust-egress-stream" | "control-egress" => {
            crate::egress_leg::run_egress_leg(cfg)
        }
        #[cfg(feature = "dataframe")]
        "rust-dataframe-direct" => crate::dataframe_leg::run_dataframe_leg(cfg),
        other => Err(format!(
            "leg {other:?} not available (the DataFrame leg needs the \
             `dataframe` cargo feature; see doc/QWP_SOAK_HARNESS.md)"
        )
        .into()),
    }
}

/// Build the pool connect string. A unified sender is memory
/// store-and-forward by default; `sf_dir` selects disk storage and
/// `sf_mem_bytes` sets an explicit memory bound. Shared with the Chunk leg.
pub(crate) fn build_conf(cfg: &LegConfig) -> String {
    let mut c = format!(
        "ws::addr={};auth_timeout=5000;\
         reconnect_max_duration_millis=30000;sender_pool_min=1;sender_pool_max=4;",
        cfg.addr
    );
    if let Some(dir) = &cfg.sf_dir {
        // Disk store-and-forward: pool-minted slots under `sf_dir`.
        c.push_str(&format!("sf_dir={};sender_id={};", dir.display(), cfg.leg));
    }
    if let Some(bytes) = cfg.sf_mem_bytes {
        // In-memory store-and-forward, bounded by `sf_max_bytes`.
        c.push_str(&format!("sf_max_bytes={bytes};"));
    }
    c
}

fn run_buffer_leg(cfg: &LegConfig) -> LegResult {
    let conf = build_conf(cfg);
    let db = QuestDb::connect(&conf)?;
    let mut journal = AckJournal::open(&cfg.journal_path)?;
    let mut stats = StatsWriter::create(&cfg.stats_path)?;

    let mut seq = journal.resume_seq();
    let mut rows_sent: u64 = 0;
    let start = Instant::now();
    let mut last_stats = Instant::now();
    // Consecutive re-drives without the journal advancing: distinguishes a
    // transient (eventually progresses) from a terminal error (never does).
    let mut stuck: u32 = 0;
    const STUCK_LIMIT: u32 = 500;

    let mut sender = db.borrow_sender()?;
    let mut buf = sender.new_buffer();

    while !crate::stop_requested() && start.elapsed() < cfg.duration {
        let batch_start = seq;
        // `flush` (success) and a fresh re-borrow (failure) both leave `buf`
        // empty at the top of each batch, so no explicit clear is needed.
        for _ in 0..cfg.batch {
            build_row(&mut buf, cfg, seq)?;
            seq += 1;
        }
        let last_seq = seq - 1;

        // Flush the batch and block until it is acked, then the journal
        // watermark is durable. On a transient error, re-drive from the
        // journal; the pool re-borrow rotates endpoints / reconnects.
        let outcome = match sender.flush_buffer(&mut buf) {
            Ok(()) => sender.wait(AckLevel::Ok, Duration::from_secs(60)),
            Err(e) => Err(e),
        };

        match outcome {
            Ok(()) => {
                journal.record(last_seq)?;
                stuck = 0;
            }
            Err(e) => {
                let transient = e.code() == ErrorCode::FailoverRetry;
                eprintln!(
                    "{}: flush/wait error at seq {batch_start}..={last_seq} \
                     (transient={transient}): {e}",
                    cfg.leg
                );
                stuck += 1;
                if stuck > STUCK_LIMIT {
                    return Err(format!(
                        "{}: {STUCK_LIMIT} re-drives without progress; last \
                         error: {e}",
                        cfg.leg
                    )
                    .into());
                }
                // Re-borrow a live sender and re-drive from the durable
                // watermark. Back off so a flapping endpoint isn't hammered.
                drop(sender);
                sleep(Duration::from_millis(200));
                sender = reborrow(&db, &cfg.leg)?;
                buf = sender.new_buffer();
                seq = journal.resume_seq();
                continue;
            }
        }

        rows_sent += last_seq - batch_start + 1;
        rate_limit(cfg, rows_sent, start);

        if last_stats.elapsed() >= Duration::from_secs(5) {
            let published = sender.published_fsn().ok().flatten();
            let acked = sender.acked_fsn().ok().flatten();
            let rows_acked = journal.watermark().map_or(0, |w| w + 1);
            stats.emit(&db, rows_sent, rows_acked, published, acked)?;
            last_stats = Instant::now();
        }
    }

    // Release the sender before the final quiesce sample so the oracle sees the
    // pool drained (I4). No blocking final wait here: it does not advance the
    // journal (I1 reads that), and a graceful-stop SIGTERM landing in it would
    // kill the leg before the drop.
    let rows_acked = journal.watermark().map_or(0, |w| w + 1);
    let published = sender.published_fsn().ok().flatten();
    let acked = sender.acked_fsn().ok().flatten();
    drop(sender);
    stats.emit(&db, rows_sent, rows_acked, published, acked)?;
    Ok(())
}

/// Re-borrow a unified sender, retrying with backoff while the endpoint recovers.
fn reborrow<'a>(
    db: &'a QuestDb,
    leg: &str,
) -> Result<questdb::BorrowedSender<'a>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match db.borrow_sender() {
            Ok(s) => return Ok(s),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("{leg}: re-borrow gave up: {e}").into());
                }
                sleep(Duration::from_millis(500));
            }
        }
    }
}

/// Append one full row (table + symbols + fields + designated timestamp) for
/// `seq`. Symbols precede fields (ILP ordering). Covers Buffer's expressible
/// subset of the 22 types; the rest are covered by the Chunk leg.
fn build_row(buf: &mut Buffer, cfg: &LegConfig, seq: u64) -> LegResult {
    buf.table(cfg.table.as_str())?;

    // Symbols first.
    match &expected_of(cfg, seq, QwpType::Symbol) {
        Expected::Text(s) => {
            buf.symbol("c_symbol", s.as_str())?;
        }
        Expected::Null => {
            buf.symbol_opt("c_symbol", None::<&str>)?;
        }
        _ => {}
    }

    // Keys the oracle reconciles on.
    buf.column_i64("worker_id", i64::from(cfg.worker_id))?;
    buf.column_i64("c_seq", seq as i64)?;

    // Fields: every ILP-expressible type except the symbol already emitted.
    for cell in gen::gen_row(cfg.seed, cfg.worker_id, seq) {
        if cell.ty == QwpType::Symbol {
            continue;
        }
        emit_field(buf, cell.ty, &cell.expected)?;
    }

    // DoubleArray needs the raw f64 values (not the canonical hex text), so it
    // is emitted here. Empty arrays ingest as-is; only NULL omits the column.
    match gen::double_array_values(cfg.seed, cfg.worker_id, seq) {
        Some(vals) => {
            buf.column_arr("c_dbl_arr", &vals)?;
        }
        None => {
            buf.column_arr_opt("c_dbl_arr", None::<&Vec<f64>>)?;
        }
    }

    // Geohash (QWP-only) takes the raw bits + pinned precision.
    match gen::geohash_bits(cfg.seed, cfg.worker_id, seq) {
        Some(bits) => {
            buf.column_geohash("c_geohash", bits, gen::GEOHASH_BITS as u8)?;
        }
        None => {
            buf.column_geohash_opt("c_geohash", None)?;
        }
    }

    buf.at(TimestampNanos::new(TS_BASE_NANOS + (seq as i64) * 1000))?;
    Ok(())
}

fn expected_of(cfg: &LegConfig, seq: u64, ty: QwpType) -> Expected {
    gen::gen_expected(cfg.seed, cfg.worker_id, seq, ty)
}

/// Emit one non-symbol cell as a Buffer field, if Buffer can express it.
/// Narrow ints widen to `column_i64`; unsupported types (uuid, long256,
/// geohash, ipv4, binary, timestamps) are skipped here and covered by the
/// Chunk leg.
fn emit_field(buf: &mut Buffer, ty: QwpType, exp: &Expected) -> LegResult {
    let name = ty.col_name();
    match ty {
        QwpType::Boolean => {
            if let Expected::Bool(b) = exp {
                buf.column_bool(name, *b)?;
            }
        }
        QwpType::Byte | QwpType::Short | QwpType::Int | QwpType::Long => match exp {
            Expected::Int(v) => {
                buf.column_i64(name, *v as i64)?;
            }
            Expected::Null => {
                buf.column_i64_opt(name, None)?;
            }
            _ => {}
        },
        QwpType::Float | QwpType::Double => match exp {
            Expected::Float(v) => {
                buf.column_f64(name, *v)?;
            }
            Expected::Null => {
                buf.column_f64_opt(name, None)?;
            }
            _ => {}
        },
        QwpType::Varchar | QwpType::Char => match exp {
            Expected::Text(s) => {
                buf.column_str(name, s.as_str())?;
            }
            Expected::Null => {
                buf.column_str_opt(name, None::<&str>)?;
            }
            _ => {}
        },
        // Decimals: the generator's canonical text feeds `column_dec*`
        // directly. Fixed-width methods pin a stable column type across rows
        // (the generic `column_dec` could infer different widths per value).
        // dec256's value is i64-unscaled so it fits the 128-bit column.
        QwpType::Decimal64 => match exp {
            Expected::Text(s) => {
                buf.column_dec64(name, s.as_str())?;
            }
            Expected::Null => {
                buf.column_dec64_opt(name, None::<&str>)?;
            }
            _ => {}
        },
        QwpType::Decimal128 | QwpType::Decimal256 => match exp {
            Expected::Text(s) => {
                buf.column_dec128(name, s.as_str())?;
            }
            Expected::Null => {
                buf.column_dec128_opt(name, None::<&str>)?;
            }
            _ => {}
        },
        // DoubleArray is emitted in build_row (it needs the raw f64 values);
        // the remaining types (uuid/long256/geohash/ipv4/binary/timestamps)
        // are covered by the Chunk leg.
        _ => {}
    }
    Ok(())
}

/// Batch-granular rate control: sleep so cumulative `rows_sent` tracks
/// `target_rows_per_sec`. `0` means unlimited. Shared with the Chunk leg.
pub(crate) fn rate_limit(cfg: &LegConfig, rows_sent: u64, start: Instant) {
    if cfg.target_rows_per_sec == 0 {
        return;
    }
    let target = Duration::from_secs_f64(rows_sent as f64 / cfg.target_rows_per_sec as f64);
    let actual = start.elapsed();
    if target > actual {
        sleep(target - actual);
    }
}
