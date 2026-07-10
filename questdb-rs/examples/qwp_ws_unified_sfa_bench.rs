use std::time::{Duration, Instant};

use questdb::{
    Result,
    ingress::{Sender, TimestampNanos},
};

const DEFAULT_CONF: &str = "ws::addr=127.0.0.1:9000;in_flight_window=128;";
const DEFAULT_TABLE: &str = "qwp_ws_unified_sfa_bench";
const DEFAULT_ROWS: usize = 50_000_000;
const DEFAULT_BATCH_SIZE: usize = 1_000;
const DEFAULT_SYMBOL_CARDINALITY: usize = 1_000;
const BASE_TS_NANOS: i64 = 1_700_000_000_000_000_000;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn fill_batch(
    buffer: &mut questdb::ingress::Buffer,
    table: &str,
    symbols: &[String],
    batch_idx: usize,
    batch_size: usize,
    rows_in_batch: usize,
) -> Result<()> {
    for row_idx in 0..rows_in_batch {
        let seq = (batch_idx * batch_size + row_idx) as i64;
        let sym = symbols[(seq as usize) % symbols.len()].as_str();
        buffer
            .table(table)?
            .symbol("sym", sym)?
            .column_i64("qty", seq)?
            .column_f64("px", 100.0 + (seq & 1023) as f64)?
            .at(TimestampNanos::new(BASE_TS_NANOS + seq))?;
    }
    Ok(())
}

fn millis(duration: Duration) -> u128 {
    duration.as_millis()
}

fn main() -> Result<()> {
    let conf = env_string("QWP_WS_UNIFIED_SFA_BENCH_CONF", DEFAULT_CONF);
    let table = env_string("QWP_WS_UNIFIED_SFA_BENCH_TABLE", DEFAULT_TABLE);
    let label = env_string("QWP_WS_UNIFIED_SFA_BENCH_LABEL", "unlabeled");
    let rows = env_usize("QWP_WS_UNIFIED_SFA_BENCH_ROWS", DEFAULT_ROWS);
    let batch_size = env_usize("QWP_WS_UNIFIED_SFA_BENCH_BATCH_SIZE", DEFAULT_BATCH_SIZE);
    let symbol_cardinality = env_usize(
        "QWP_WS_UNIFIED_SFA_BENCH_SYMBOL_CARDINALITY",
        DEFAULT_SYMBOL_CARDINALITY,
    );
    assert!(rows > 0, "rows must be positive");
    assert!(batch_size > 0, "batch size must be positive");
    assert!(
        symbol_cardinality > 0,
        "symbol cardinality must be positive"
    );

    let symbols = (0..symbol_cardinality)
        .map(|idx| format!("SYM{idx:04}"))
        .collect::<Vec<_>>();

    let total_started = Instant::now();
    let mut sender = Sender::from_conf(conf.as_str())?;
    let mut buffer = sender.new_buffer();
    let publish_started = Instant::now();
    let mut published_rows = 0usize;
    let mut batch_idx = 0usize;

    while published_rows < rows {
        let rows_in_batch = (rows - published_rows).min(batch_size);
        fill_batch(
            &mut buffer,
            table.as_str(),
            symbols.as_slice(),
            batch_idx,
            batch_size,
            rows_in_batch,
        )?;
        sender.flush(&mut buffer)?;
        published_rows += rows_in_batch;
        batch_idx += 1;
    }

    let publish_elapsed = publish_started.elapsed();
    let close_started = Instant::now();
    sender.close_drain()?;
    let close_elapsed = close_started.elapsed();
    let total_elapsed = total_started.elapsed();
    let batches = rows.div_ceil(batch_size);

    eprintln!(
        "qwp_ws_unified_sfa_real_bench label={} table={} rows={} batch_size={} batches={} symbol_cardinality={} publish_ms={} close_ms={} total_ms={} publish_rows_per_sec={:.2} total_rows_per_sec={:.2} batches_per_sec={:.2} conf={}",
        label,
        table,
        rows,
        batch_size,
        batches,
        symbol_cardinality,
        millis(publish_elapsed),
        millis(close_elapsed),
        millis(total_elapsed),
        rows as f64 / publish_elapsed.as_secs_f64(),
        rows as f64 / total_elapsed.as_secs_f64(),
        batches as f64 / publish_elapsed.as_secs_f64(),
        conf,
    );

    Ok(())
}
