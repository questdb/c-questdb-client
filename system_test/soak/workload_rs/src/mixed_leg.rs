//! Mixed-shape store-and-forward soak leg.
//!
//! One [`questdb::BorrowedSender`] deterministically cycles Arrow, Buffer, and
//! Chunk batches against one table. This is deliberately different from
//! running three independent clients: every shape mutates the same sender
//! dictionary, publishes into the same retained payload allocation, advances
//! one FSN sequence, and recovers through one SFA slot after reconnect or
//! process restart.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::{Duration, Instant};

use arrow::array::{
    ArrayRef, BooleanArray, Float64Array, Int64Array, RecordBatch, StringArray,
    TimestampNanosecondArray,
};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use questdb::ingress::column_sender::{ArrowColumnOverride, Chunk, Validity};
use questdb::ingress::{AckLevel, Buffer, ColumnName, TimestampNanos};
use questdb::{ErrorCode, QuestDb};

use crate::gen::{self, Expected, QwpType};
use crate::journal::AckJournal;
use crate::legs::LegConfig;
use crate::stats::StatsWriter;

const TS_BASE_NANOS: i64 = 1_600_000_000_000_000_000;
const STUCK_LIMIT: u32 = 500;

type LegResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Shape {
    Arrow,
    Buffer,
    Chunk,
}

impl Shape {
    fn for_batch(batch_index: u64) -> Self {
        match batch_index % 3 {
            0 => Self::Arrow,
            1 => Self::Buffer,
            _ => Self::Chunk,
        }
    }
}

#[derive(Default)]
struct MixedBatch {
    row_count: usize,
    worker: Vec<i64>,
    seq: Vec<i64>,
    timestamp: Vec<i64>,

    bool_values: Vec<Option<bool>>,
    bool_bits: Vec<u8>,
    bool_validity: Vec<u8>,
    long_values: Vec<Option<i64>>,
    long_raw: Vec<i64>,
    long_validity: Vec<u8>,
    double_values: Vec<Option<f64>>,
    double_raw: Vec<f64>,
    double_validity: Vec<u8>,

    symbol_values: Vec<Option<String>>,
    symbol_codes: Vec<i32>,
    symbol_validity: Vec<u8>,
    symbol_order: Vec<String>,
    symbol_lookup: HashMap<String, i32>,
    symbol_offsets: Vec<i32>,
    symbol_bytes: Vec<u8>,

    varchar_values: Vec<Option<String>>,
    varchar_offsets: Vec<i32>,
    varchar_bytes: Vec<u8>,
    varchar_validity: Vec<u8>,
}

impl MixedBatch {
    fn reset(&mut self) {
        self.row_count = 0;
        self.worker.clear();
        self.seq.clear();
        self.timestamp.clear();
        self.bool_values.clear();
        self.bool_bits.clear();
        self.bool_validity.clear();
        self.long_values.clear();
        self.long_raw.clear();
        self.long_validity.clear();
        self.double_values.clear();
        self.double_raw.clear();
        self.double_validity.clear();
        self.symbol_values.clear();
        self.symbol_codes.clear();
        self.symbol_validity.clear();
        self.symbol_order.clear();
        self.symbol_lookup.clear();
        self.symbol_offsets.clear();
        self.symbol_bytes.clear();
        self.varchar_values.clear();
        self.varchar_offsets.clear();
        self.varchar_offsets.push(0);
        self.varchar_bytes.clear();
        self.varchar_validity.clear();
    }

    fn push(&mut self, cfg: &LegConfig, seq: u64) {
        let row = self.row_count;
        self.worker.push(i64::from(cfg.worker_id));
        self.seq.push(seq as i64);
        self.timestamp.push(TS_BASE_NANOS + (seq as i64) * 1000);

        let bool_value = match expected(cfg, seq, QwpType::Boolean) {
            Expected::Bool(value) => Some(value),
            _ => None,
        };
        self.bool_values.push(bool_value);
        pack_bit(&mut self.bool_bits, row, bool_value.unwrap_or(false));
        pack_bit(&mut self.bool_validity, row, bool_value.is_some());

        let long_value = match expected(cfg, seq, QwpType::Long) {
            Expected::Int(value) => Some(value as i64),
            _ => None,
        };
        self.long_values.push(long_value);
        self.long_raw.push(long_value.unwrap_or_default());
        pack_bit(&mut self.long_validity, row, long_value.is_some());

        let double_value = match expected(cfg, seq, QwpType::Double) {
            Expected::Float(value) => Some(value),
            _ => None,
        };
        self.double_values.push(double_value);
        self.double_raw.push(double_value.unwrap_or_default());
        pack_bit(&mut self.double_validity, row, double_value.is_some());

        let symbol_value = match expected(cfg, seq, QwpType::Symbol) {
            Expected::Text(value) => Some(value),
            _ => None,
        };
        let symbol_code = symbol_value
            .as_deref()
            .map(|value| self.symbol_code(value))
            .unwrap_or_default();
        self.symbol_codes.push(symbol_code);
        pack_bit(&mut self.symbol_validity, row, symbol_value.is_some());
        self.symbol_values.push(symbol_value);

        let varchar_value = match expected(cfg, seq, QwpType::Varchar) {
            Expected::Text(value) => Some(value),
            _ => None,
        };
        if let Some(value) = &varchar_value {
            self.varchar_bytes.extend_from_slice(value.as_bytes());
        }
        self.varchar_offsets.push(self.varchar_bytes.len() as i32);
        pack_bit(&mut self.varchar_validity, row, varchar_value.is_some());
        self.varchar_values.push(varchar_value);
        self.row_count += 1;
    }

    fn finish(&mut self) {
        self.symbol_offsets.clear();
        self.symbol_offsets.push(0);
        self.symbol_bytes.clear();
        for value in &self.symbol_order {
            self.symbol_bytes.extend_from_slice(value.as_bytes());
            self.symbol_offsets.push(self.symbol_bytes.len() as i32);
        }
    }

    fn symbol_code(&mut self, value: &str) -> i32 {
        if let Some(code) = self.symbol_lookup.get(value) {
            return *code;
        }
        let code = self.symbol_order.len() as i32;
        self.symbol_order.push(value.to_owned());
        self.symbol_lookup.insert(value.to_owned(), code);
        code
    }

    fn to_arrow(&self) -> arrow::error::Result<RecordBatch> {
        let schema = Arc::new(Schema::new(vec![
            Field::new("worker_id", DataType::Int64, false),
            Field::new("c_seq", DataType::Int64, false),
            Field::new("c_bool", DataType::Boolean, true),
            Field::new("c_long", DataType::Int64, true),
            Field::new("c_double", DataType::Float64, true),
            Field::new("c_symbol", DataType::Utf8, true),
            Field::new("c_varchar", DataType::Utf8, true),
            Field::new(
                "timestamp",
                DataType::Timestamp(TimeUnit::Nanosecond, None),
                false,
            ),
        ]));
        let symbol_refs: Vec<Option<&str>> = self
            .symbol_values
            .iter()
            .map(|value| value.as_deref())
            .collect();
        let varchar_refs: Vec<Option<&str>> = self
            .varchar_values
            .iter()
            .map(|value| value.as_deref())
            .collect();
        let arrays: Vec<ArrayRef> = vec![
            Arc::new(Int64Array::from(self.worker.clone())),
            Arc::new(Int64Array::from(self.seq.clone())),
            Arc::new(BooleanArray::from(self.bool_values.clone())),
            Arc::new(Int64Array::from(self.long_values.clone())),
            Arc::new(Float64Array::from(self.double_values.clone())),
            Arc::new(StringArray::from(symbol_refs)),
            Arc::new(StringArray::from(varchar_refs)),
            Arc::new(TimestampNanosecondArray::from(self.timestamp.clone())),
        ];
        RecordBatch::try_new(schema, arrays)
    }
}

fn expected(cfg: &LegConfig, seq: u64, ty: QwpType) -> Expected {
    gen::gen_expected(cfg.seed, cfg.worker_id, seq, ty)
}

fn pack_bit(bits: &mut Vec<u8>, index: usize, value: bool) {
    let byte = index / 8;
    while bits.len() <= byte {
        bits.push(0);
    }
    if value {
        bits[byte] |= 1 << (index % 8);
    }
}

fn flush_buffer(
    sender: &mut questdb::BorrowedSender<'_>,
    buffer: &mut Buffer,
    table: &str,
    batch: &MixedBatch,
) -> questdb::Result<()> {
    for row in 0..batch.row_count {
        buffer.table(table)?;
        buffer.symbol_opt("c_symbol", batch.symbol_values[row].as_deref())?;
        buffer.column_i64("worker_id", batch.worker[row])?;
        buffer.column_i64("c_seq", batch.seq[row])?;
        buffer.column_bool_opt("c_bool", batch.bool_values[row])?;
        buffer.column_i64_opt("c_long", batch.long_values[row])?;
        buffer.column_f64_opt("c_double", batch.double_values[row])?;
        buffer.column_str_opt("c_varchar", batch.varchar_values[row].as_deref())?;
        buffer.at(TimestampNanos::new(batch.timestamp[row]))?;
    }
    sender.flush_buffer(buffer)?;
    sender.wait(AckLevel::Ok, Duration::from_secs(60))
}

fn flush_chunk(
    sender: &mut questdb::BorrowedSender<'_>,
    table: &str,
    batch: &MixedBatch,
) -> questdb::Result<()> {
    let bool_validity = Validity::from_bitmap(&batch.bool_validity, batch.row_count)?;
    let long_validity = Validity::from_bitmap(&batch.long_validity, batch.row_count)?;
    let double_validity = Validity::from_bitmap(&batch.double_validity, batch.row_count)?;
    let symbol_validity = Validity::from_bitmap(&batch.symbol_validity, batch.row_count)?;
    let varchar_validity = Validity::from_bitmap(&batch.varchar_validity, batch.row_count)?;
    let mut chunk = Chunk::new(table);
    chunk.column_i64("worker_id", &batch.worker, None)?;
    chunk.column_i64("c_seq", &batch.seq, None)?;
    chunk.column_bool(
        "c_bool",
        &batch.bool_bits,
        batch.row_count,
        Some(&bool_validity),
    )?;
    chunk.column_i64("c_long", &batch.long_raw, Some(&long_validity))?;
    chunk.column_f64("c_double", &batch.double_raw, Some(&double_validity))?;
    chunk.symbol_i32(
        "c_symbol",
        &batch.symbol_codes,
        &batch.symbol_offsets,
        &batch.symbol_bytes,
        Some(&symbol_validity),
    )?;
    chunk.column_str(
        "c_varchar",
        &batch.varchar_offsets,
        &batch.varchar_bytes,
        Some(&varchar_validity),
    )?;
    chunk.at_nanos(&batch.timestamp)?;
    sender.flush_and_wait(&mut chunk, AckLevel::Ok)
}

fn flush_arrow(
    sender: &mut questdb::BorrowedSender<'_>,
    table: &str,
    batch: &MixedBatch,
) -> questdb::Result<()> {
    let record_batch = batch
        .to_arrow()
        .map_err(|error| questdb::Error::new(ErrorCode::ArrowIngest, error.to_string()))?;
    let timestamp = ColumnName::new("timestamp")?;
    let overrides = [ArrowColumnOverride::Symbol { column: "c_symbol" }];
    sender.flush_arrow_batch_at_column_and_wait(
        table,
        &record_batch,
        timestamp,
        &overrides,
        AckLevel::Ok,
    )
}

pub fn run_mixed_leg(cfg: &LegConfig) -> LegResult {
    let conf = crate::legs::build_conf(cfg);
    let db = QuestDb::connect(&conf)?;
    let mut journal = AckJournal::open(&cfg.journal_path)?;
    let mut stats = StatsWriter::create(&cfg.stats_path)?;
    let mut seq = journal.resume_seq();
    let mut rows_sent = 0_u64;
    let start = Instant::now();
    let mut last_stats = Instant::now();
    let mut stuck = 0_u32;
    let mut sender = db.borrow_sender()?;
    let mut buffer = sender.new_buffer();
    let mut batch = MixedBatch::default();

    while !crate::stop_requested() && start.elapsed() < cfg.duration {
        let batch_start = seq;
        let shape = Shape::for_batch(batch_start / cfg.batch.max(1));
        batch.reset();
        for _ in 0..cfg.batch {
            batch.push(cfg, seq);
            seq += 1;
        }
        batch.finish();
        let last_seq = seq - 1;
        let outcome = match shape {
            Shape::Arrow => flush_arrow(&mut sender, &cfg.table, &batch),
            Shape::Buffer => flush_buffer(&mut sender, &mut buffer, &cfg.table, &batch),
            Shape::Chunk => flush_chunk(&mut sender, &cfg.table, &batch),
        };

        match outcome {
            Ok(()) => {
                journal.record(last_seq)?;
                stuck = 0;
            }
            Err(error) => {
                let transient = error.code() == ErrorCode::FailoverRetry;
                eprintln!(
                    "{}: {shape:?} flush error at {batch_start}..={last_seq} \
                     (transient={transient}): {error}",
                    cfg.leg
                );
                stuck += 1;
                if stuck > STUCK_LIMIT {
                    return Err(format!(
                        "{}: {STUCK_LIMIT} re-drives without progress: {error}",
                        cfg.leg
                    )
                    .into());
                }
                drop(sender);
                sleep(Duration::from_millis(200));
                sender = reborrow(&db, &cfg.leg)?;
                buffer = sender.new_buffer();
                seq = journal.resume_seq();
                continue;
            }
        }

        rows_sent += last_seq - batch_start + 1;
        crate::legs::rate_limit(cfg, rows_sent, start);
        if last_stats.elapsed() >= Duration::from_secs(5) {
            let rows_acked = journal.watermark().map_or(0, |watermark| watermark + 1);
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

    let rows_acked = journal.watermark().map_or(0, |watermark| watermark + 1);
    let published = sender.published_fsn().ok().flatten();
    let acked = sender.acked_fsn().ok().flatten();
    drop(sender);
    stats.emit(&db, rows_sent, rows_acked, published, acked)?;
    Ok(())
}

fn reborrow<'a>(
    db: &'a QuestDb,
    leg: &str,
) -> Result<questdb::BorrowedSender<'a>, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match db.borrow_sender() {
            Ok(sender) => return Ok(sender),
            Err(error) => {
                if Instant::now() >= deadline {
                    return Err(format!("{leg}: mixed re-borrow gave up: {error}").into());
                }
                sleep(Duration::from_millis(500));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Shape;

    #[test]
    fn shape_cycle_is_stable_across_restart() {
        assert_eq!(Shape::for_batch(0), Shape::Arrow);
        assert_eq!(Shape::for_batch(1), Shape::Buffer);
        assert_eq!(Shape::for_batch(2), Shape::Chunk);
        assert_eq!(Shape::for_batch(3), Shape::Arrow);
    }
}
