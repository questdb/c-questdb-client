//! Column-sender (columnar / QWP-WS) leg drivers (§S1).
//!
//! The columnar path is the Polars/Pandas ingest path and the newer, riskier
//! code, so it gets its own soak legs. Unlike the row leg (ILP `Buffer`,
//! one value at a time), this builds a whole [`Chunk`] per batch: one slice per
//! column, plus validity bitmaps for nullable columns, a symbol dictionary, and
//! Arrow-style varchar/binary offset+byte buffers — then flushes it.
//!
//! Coverage: 15 of the 22 QWP types that have direct `Chunk` methods —
//! bool, byte, short, int, long, float, double, ipv4, timestamp, date,
//! timestamp_nanos, uuid, varchar, binary, symbol. (long256 needs its wire
//! byte-order confirmed; geohash / decimals / arrays / char have no `Chunk`
//! method yet — tracked as follow-ups.) Every ingestible value is derived from
//! the generator's canonical `Expected`, so the same round-trip the oracle
//! checks holds.

use std::collections::HashMap;
use std::thread::sleep;
use std::time::{Duration, Instant};

use questdb::ingress::column_sender::{Chunk, Validity};
use questdb::ingress::{AckLevel, TimestampUnit};
use questdb::{ErrorCode, QuestDb};

use crate::gen::{self, Expected, QwpType};
use crate::journal::AckJournal;
use crate::legs::LegConfig;
use crate::stats::StatsWriter;

const TS_BASE_NANOS: i64 = 1_600_000_000_000_000_000;

type LegResult = Result<(), Box<dyn std::error::Error>>;

/// Set bit `idx` (LSB-first) to `val`, growing `bits` to cover it either way —
/// so after `rc` pushes the bitmap always spans `ceil(rc/8)` bytes even when
/// the trailing rows are 0 (null / false).
fn pack_bit(bits: &mut Vec<u8>, idx: usize, val: bool) {
    let byte = idx / 8;
    while bits.len() <= byte {
        bits.push(0);
    }
    if val {
        bits[byte] |= 1 << (idx % 8);
    }
}

/// Parse the generator's canonical UUID text into QuestDB wire bytes:
/// low 64 bits little-endian followed by high 64 bits little-endian.
fn uuid_bytes(s: &str) -> [u8; 16] {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    let v = u128::from_str_radix(&hex, 16).unwrap_or(0);
    let mut b = [0u8; 16];
    b[0..8].copy_from_slice(&(v as u64).to_le_bytes());
    b[8..16].copy_from_slice(&((v >> 64) as u64).to_le_bytes());
    b
}

/// Per-batch columnar buffers. Cleared and refilled each batch; a `Chunk`
/// borrows these slices only within `flush_batch`, so `reset` is always called
/// after the chunk is dropped.
#[derive(Default)]
struct Batch {
    rc: usize,
    ts_ns: Vec<i64>,
    worker: Vec<i64>,
    seq: Vec<i64>,

    bool_bits: Vec<u8>,
    byte: Vec<i8>,
    short: Vec<i16>,

    int: Vec<i32>,
    int_v: Vec<u8>,
    long: Vec<i64>,
    long_v: Vec<u8>,
    float: Vec<f32>,
    float_v: Vec<u8>,
    double: Vec<f64>,
    double_v: Vec<u8>,
    ipv4: Vec<u32>,
    ipv4_v: Vec<u8>,
    ts: Vec<i64>,
    ts_v: Vec<u8>,
    date: Vec<i64>,
    date_v: Vec<u8>,
    tsn: Vec<i64>,
    tsn_v: Vec<u8>,
    uuid: Vec<[u8; 16]>,
    uuid_v: Vec<u8>,
    long256: Vec<[u8; 32]>,
    long256_v: Vec<u8>,

    vc_offsets: Vec<i32>,
    vc_bytes: Vec<u8>,
    vc_v: Vec<u8>,
    bin_offsets: Vec<i32>,
    bin_bytes: Vec<u8>,
    bin_v: Vec<u8>,

    sym_codes: Vec<i32>,
    sym_v: Vec<u8>,
    sym_order: Vec<String>,
    sym_lookup: HashMap<String, i32>,
    sym_dict_offsets: Vec<i32>,
    sym_dict_bytes: Vec<u8>,
}

impl Batch {
    fn reset(&mut self) {
        self.rc = 0;
        self.ts_ns.clear();
        self.worker.clear();
        self.seq.clear();
        self.bool_bits.clear();
        self.byte.clear();
        self.short.clear();
        self.int.clear();
        self.int_v.clear();
        self.long.clear();
        self.long_v.clear();
        self.float.clear();
        self.float_v.clear();
        self.double.clear();
        self.double_v.clear();
        self.ipv4.clear();
        self.ipv4_v.clear();
        self.ts.clear();
        self.ts_v.clear();
        self.date.clear();
        self.date_v.clear();
        self.tsn.clear();
        self.tsn_v.clear();
        self.uuid.clear();
        self.uuid_v.clear();
        self.long256.clear();
        self.long256_v.clear();
        self.vc_offsets.clear();
        self.vc_offsets.push(0);
        self.vc_bytes.clear();
        self.vc_v.clear();
        self.bin_offsets.clear();
        self.bin_offsets.push(0);
        self.bin_bytes.clear();
        self.bin_v.clear();
        self.sym_codes.clear();
        self.sym_v.clear();
        self.sym_order.clear();
        self.sym_lookup.clear();
        self.sym_dict_offsets.clear();
        self.sym_dict_bytes.clear();
    }

    fn sym_code(&mut self, s: &str) -> i32 {
        if let Some(&c) = self.sym_lookup.get(s) {
            return c;
        }
        let code = self.sym_order.len() as i32;
        self.sym_order.push(s.to_string());
        self.sym_lookup.insert(s.to_string(), code);
        code
    }

    fn push(&mut self, seed: u64, worker: u32, seq: u64) {
        let idx = self.rc;
        self.worker.push(i64::from(worker));
        self.seq.push(seq as i64);
        self.ts_ns.push(TS_BASE_NANOS + (seq as i64) * 1000);

        for cell in gen::gen_row(seed, worker, seq) {
            match cell.ty {
                QwpType::Boolean => {
                    pack_bit(
                        &mut self.bool_bits,
                        idx,
                        matches!(cell.expected, Expected::Bool(true)),
                    );
                }
                QwpType::Byte => {
                    self.byte.push(int_of(&cell.expected) as i8);
                }
                QwpType::Short => {
                    self.short.push(int_of(&cell.expected) as i16);
                }
                QwpType::Int => {
                    let (v, ok) = opt_int(&cell.expected);
                    self.int.push(v as i32);
                    pack_bit(&mut self.int_v, idx, ok);
                }
                QwpType::Long => {
                    let (v, ok) = opt_int(&cell.expected);
                    self.long.push(v as i64);
                    pack_bit(&mut self.long_v, idx, ok);
                }
                QwpType::Float => {
                    let (v, ok) = opt_float(&cell.expected);
                    self.float.push(v as f32);
                    pack_bit(&mut self.float_v, idx, ok);
                }
                QwpType::Double => {
                    let (v, ok) = opt_float(&cell.expected);
                    self.double.push(v);
                    pack_bit(&mut self.double_v, idx, ok);
                }
                QwpType::Ipv4 => {
                    let (v, ok) = opt_int(&cell.expected);
                    self.ipv4.push(v as u32);
                    pack_bit(&mut self.ipv4_v, idx, ok);
                }
                QwpType::Timestamp => {
                    let (v, ok) = opt_int(&cell.expected);
                    self.ts.push(v as i64);
                    pack_bit(&mut self.ts_v, idx, ok);
                }
                QwpType::Date => {
                    let (v, ok) = opt_int(&cell.expected);
                    self.date.push(v as i64);
                    pack_bit(&mut self.date_v, idx, ok);
                }
                QwpType::TimestampNanos => {
                    let (v, ok) = opt_int(&cell.expected);
                    self.tsn.push(v as i64);
                    pack_bit(&mut self.tsn_v, idx, ok);
                }
                QwpType::Uuid => match &cell.expected {
                    Expected::Text(s) => {
                        self.uuid.push(uuid_bytes(s));
                        pack_bit(&mut self.uuid_v, idx, true);
                    }
                    _ => {
                        self.uuid.push([0u8; 16]);
                        pack_bit(&mut self.uuid_v, idx, false);
                    }
                },
                QwpType::Varchar => match &cell.expected {
                    Expected::Text(s) => {
                        self.vc_bytes.extend_from_slice(s.as_bytes());
                        self.vc_offsets.push(self.vc_bytes.len() as i32);
                        pack_bit(&mut self.vc_v, idx, true);
                    }
                    _ => {
                        self.vc_offsets.push(self.vc_bytes.len() as i32);
                        pack_bit(&mut self.vc_v, idx, false);
                    }
                },
                QwpType::Binary => match &cell.expected {
                    Expected::Bytes(b) => {
                        self.bin_bytes.extend_from_slice(b);
                        self.bin_offsets.push(self.bin_bytes.len() as i32);
                        pack_bit(&mut self.bin_v, idx, true);
                    }
                    _ => {
                        self.bin_offsets.push(self.bin_bytes.len() as i32);
                        pack_bit(&mut self.bin_v, idx, false);
                    }
                },
                QwpType::Symbol => match &cell.expected {
                    Expected::Text(s) => {
                        let code = self.sym_code(s);
                        self.sym_codes.push(code);
                        pack_bit(&mut self.sym_v, idx, true);
                    }
                    _ => {
                        self.sym_codes.push(0);
                        pack_bit(&mut self.sym_v, idx, false);
                    }
                },
                // geohash, decimals, arrays, char: row-leg / follow-ups.
                _ => {}
            }
        }

        // long256 needs the raw words (not the canonical hex), packed as
        // [u8; 32] little-endian with word 0 least-significant.
        match gen::long256_words(seed, worker, seq) {
            Some(w) => {
                let mut b = [0u8; 32];
                b[0..8].copy_from_slice(&w[0].to_le_bytes());
                b[8..16].copy_from_slice(&w[1].to_le_bytes());
                b[16..24].copy_from_slice(&w[2].to_le_bytes());
                b[24..32].copy_from_slice(&w[3].to_le_bytes());
                self.long256.push(b);
                pack_bit(&mut self.long256_v, idx, true);
            }
            None => {
                self.long256.push([0u8; 32]);
                pack_bit(&mut self.long256_v, idx, false);
            }
        }

        self.rc += 1;
    }

    /// Finalise the symbol dictionary (Arrow Utf8 offsets + bytes) from the
    /// insertion-ordered entries. Must run before building the chunk.
    fn finish_symbol_dict(&mut self) {
        self.sym_dict_offsets.clear();
        self.sym_dict_bytes.clear();
        self.sym_dict_offsets.push(0);
        for s in &self.sym_order {
            self.sym_dict_bytes.extend_from_slice(s.as_bytes());
            self.sym_dict_offsets.push(self.sym_dict_bytes.len() as i32);
        }
    }
}

fn int_of(e: &Expected) -> i128 {
    match e {
        Expected::Int(v) => *v,
        _ => 0,
    }
}

fn opt_int(e: &Expected) -> (i128, bool) {
    match e {
        Expected::Int(v) => (*v, true),
        _ => (0, false),
    }
}

fn opt_float(e: &Expected) -> (f64, bool) {
    match e {
        Expected::Float(v) => (*v, true),
        _ => (0.0, false),
    }
}

/// Build a `Chunk` from the batch and flush it (blocking until acked). All the
/// `Validity` objects and the chunk borrow `b`'s buffers; everything lives in
/// this one scope, so `b` is free to be reset by the caller afterwards.
fn flush_batch(
    sender: &mut questdb::BorrowedColumnSender<'_>,
    table: &str,
    b: &Batch,
) -> questdb::Result<()> {
    let rc = b.rc;
    let v_int = Validity::from_bitmap(&b.int_v, rc)?;
    let v_long = Validity::from_bitmap(&b.long_v, rc)?;
    let v_float = Validity::from_bitmap(&b.float_v, rc)?;
    let v_double = Validity::from_bitmap(&b.double_v, rc)?;
    let v_ipv4 = Validity::from_bitmap(&b.ipv4_v, rc)?;
    let v_ts = Validity::from_bitmap(&b.ts_v, rc)?;
    let v_date = Validity::from_bitmap(&b.date_v, rc)?;
    let v_tsn = Validity::from_bitmap(&b.tsn_v, rc)?;
    let v_uuid = Validity::from_bitmap(&b.uuid_v, rc)?;
    let v_long256 = Validity::from_bitmap(&b.long256_v, rc)?;
    let v_vc = Validity::from_bitmap(&b.vc_v, rc)?;
    let v_bin = Validity::from_bitmap(&b.bin_v, rc)?;
    let v_sym = Validity::from_bitmap(&b.sym_v, rc)?;

    let mut chunk = Chunk::new(table);
    chunk.column_i64("worker_id", &b.worker, None)?;
    chunk.column_i64("c_seq", &b.seq, None)?;
    chunk.column_bool("c_bool", &b.bool_bits, rc, None)?;
    chunk.column_i8("c_byte", &b.byte, None)?;
    chunk.column_i16("c_short", &b.short, None)?;
    chunk.column_i32("c_int", &b.int, Some(&v_int))?;
    chunk.column_i64("c_long", &b.long, Some(&v_long))?;
    chunk.column_f32("c_float", &b.float, Some(&v_float))?;
    chunk.column_f64("c_double", &b.double, Some(&v_double))?;
    chunk.column_ipv4("c_ipv4", &b.ipv4, Some(&v_ipv4))?;
    chunk.column_ts("c_ts", &b.ts, TimestampUnit::Micros, Some(&v_ts))?;
    chunk.column_date("c_date", &b.date, Some(&v_date))?;
    chunk.column_ts("c_ts_nanos", &b.tsn, TimestampUnit::Nanos, Some(&v_tsn))?;
    chunk.column_uuid("c_uuid", &b.uuid, Some(&v_uuid))?;
    chunk.column_long256("c_long256", &b.long256, Some(&v_long256))?;
    chunk.column_str("c_varchar", &b.vc_offsets, &b.vc_bytes, Some(&v_vc))?;
    chunk.column_binary("c_binary", &b.bin_offsets, &b.bin_bytes, Some(&v_bin))?;
    chunk.symbol_i32(
        "c_symbol",
        &b.sym_codes,
        &b.sym_dict_offsets,
        &b.sym_dict_bytes,
        Some(&v_sym),
    )?;
    chunk.at_nanos(&b.ts_ns)?;
    sender.flush_and_wait(&mut chunk, AckLevel::Ok)
}

/// Drive a column-sender leg: batches of columnar rows through the pool, with
/// the journal watermark advanced on ack and transient re-drive from it.
pub fn run_column_leg(cfg: &LegConfig) -> LegResult {
    let conf = crate::legs::build_conf(cfg);
    let db = QuestDb::connect(&conf)?;
    let mut journal = AckJournal::open(&cfg.journal_path)?;
    let mut stats = StatsWriter::create(&cfg.stats_path)?;

    let mut seq = journal.resume_seq();
    let mut rows_sent: u64 = 0;
    let start = Instant::now();
    let mut last_stats = Instant::now();
    let mut stuck: u32 = 0;
    const STUCK_LIMIT: u32 = 500;

    let mut sender = db.borrow_column_sender()?;
    let mut batch = Batch::default();
    batch.reset();

    while start.elapsed() < cfg.duration {
        let batch_start = seq;
        batch.reset();
        for _ in 0..cfg.batch {
            batch.push(cfg.seed, cfg.worker_id, seq);
            seq += 1;
        }
        batch.finish_symbol_dict();
        let last_seq = seq - 1;

        match flush_batch(&mut sender, &cfg.table, &batch) {
            Ok(()) => {
                journal.record(last_seq)?;
                stuck = 0;
            }
            Err(e) => {
                let transient = e.code() == ErrorCode::FailoverRetry;
                eprintln!(
                    "{}: column flush error at {batch_start}..={last_seq} \
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
                drop(sender);
                sleep(Duration::from_millis(200));
                sender = reborrow(&db, &cfg.leg)?;
                seq = journal.resume_seq();
                continue;
            }
        }

        rows_sent += last_seq - batch_start + 1;
        crate::legs::rate_limit(cfg, rows_sent, start);

        if last_stats.elapsed() >= Duration::from_secs(5) {
            let rows_acked = journal.watermark().map_or(0, |w| w + 1);
            stats.emit(
                &db,
                rows_sent,
                rows_acked,
                sender.published_fsn().ok().flatten(),
                sender.acked_fsn().ok().flatten(),
            )?;
            last_stats = Instant::now();
        }
    }

    let rows_acked = journal.watermark().map_or(0, |w| w + 1);
    stats.emit(
        &db,
        rows_sent,
        rows_acked,
        sender.published_fsn().ok().flatten(),
        sender.acked_fsn().ok().flatten(),
    )?;
    Ok(())
}

fn reborrow<'a>(
    db: &'a QuestDb,
    leg: &str,
) -> Result<questdb::BorrowedColumnSender<'a>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match db.borrow_column_sender() {
            Ok(s) => return Ok(s),
            Err(e) => {
                if Instant::now() >= deadline {
                    return Err(format!("{leg}: column re-borrow gave up: {e}").into());
                }
                sleep(Duration::from_millis(500));
            }
        }
    }
}
