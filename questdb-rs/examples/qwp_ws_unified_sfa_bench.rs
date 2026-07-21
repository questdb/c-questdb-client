use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arrow::array::{ArrayRef, Float64Array, Int64Array, RecordBatch, StringArray};
use arrow::datatypes::{DataType, Field, Schema, TimeUnit};
use questdb::ingress::column_sender::{ArrowColumnOverride, Chunk};
use questdb::ingress::{AckLevel, ColumnName, TimestampNanos};
use questdb::{QuestDb, Result};

const DEFAULT_CONF: &str = "ws::addr=127.0.0.1:9000;\
    sf_max_segment_bytes=1073741824;sender_pool_min=1;sender_pool_max=1;in_flight_window=128;";
const DEFAULT_TABLE: &str = "qwp_ws_unified_sfa_bench";
const DEFAULT_ROWS: usize = 1_000_000;
const DEFAULT_BATCH_SIZE: usize = 1_000;
const DEFAULT_SYMBOL_CARDINALITY: usize = 1_000;
const BASE_TS_NANOS: i64 = 1_700_000_000_000_000_000;

struct CountingAllocator;

static ALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static ALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static DEALLOC_CALLS: AtomicU64 = AtomicU64::new(0);
static DEALLOC_BYTES: AtomicU64 = AtomicU64::new(0);
static LIVE_BYTES: AtomicU64 = AtomicU64::new(0);
static PEAK_LIVE_BYTES: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            record_alloc(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        record_dealloc(layout.size());
        unsafe { System.dealloc(ptr, layout) };
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { System.realloc(ptr, layout, new_size) };
        if !new_ptr.is_null() {
            record_dealloc(layout.size());
            record_alloc(new_size);
        }
        new_ptr
    }
}

fn record_alloc(size: usize) {
    let size = size as u64;
    ALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    ALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
    let live = LIVE_BYTES.fetch_add(size, Ordering::Relaxed) + size;
    let mut peak = PEAK_LIVE_BYTES.load(Ordering::Relaxed);
    while live > peak {
        match PEAK_LIVE_BYTES.compare_exchange_weak(
            peak,
            live,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
}

fn record_dealloc(size: usize) {
    let size = size as u64;
    DEALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    DEALLOC_BYTES.fetch_add(size, Ordering::Relaxed);
    LIVE_BYTES.fetch_sub(size, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
enum Mode {
    Buffer,
    Chunk,
    Arrow,
}

impl Mode {
    fn parse(value: &str) -> Self {
        match value {
            "buffer" => Self::Buffer,
            "chunk" => Self::Chunk,
            "arrow" => Self::Arrow,
            other => panic!("unknown benchmark mode {other:?}; expected buffer, chunk, or arrow"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Buffer => "buffer",
            Self::Chunk => "chunk",
            Self::Arrow => "arrow",
        }
    }
}

struct Workload {
    rows: usize,
    batch_size: usize,
    symbols: Vec<String>,
    symbol_offsets: Vec<i32>,
    symbol_bytes: Vec<u8>,
    symbol_codes: Vec<i32>,
    qty: Vec<i64>,
    px: Vec<f64>,
    ts: Vec<i64>,
}

impl Workload {
    fn new(rows: usize, batch_size: usize, symbol_cardinality: usize) -> Self {
        let symbols = (0..symbol_cardinality)
            .map(|idx| format!("SYM{idx:04}"))
            .collect::<Vec<_>>();
        let mut symbol_offsets = Vec::with_capacity(symbol_cardinality + 1);
        let mut symbol_bytes = Vec::with_capacity(symbol_cardinality * 7);
        symbol_offsets.push(0);
        for symbol in &symbols {
            symbol_bytes.extend_from_slice(symbol.as_bytes());
            symbol_offsets.push(symbol_bytes.len() as i32);
        }
        let symbol_codes = (0..batch_size)
            .map(|idx| (idx % symbol_cardinality) as i32)
            .collect();
        let qty = (0..batch_size).map(|idx| idx as i64).collect();
        let px = (0..batch_size)
            .map(|idx| 100.0 + (idx & 1023) as f64)
            .collect();
        let ts = (0..batch_size)
            .map(|idx| BASE_TS_NANOS + idx as i64)
            .collect();
        Self {
            rows,
            batch_size,
            symbols,
            symbol_offsets,
            symbol_bytes,
            symbol_codes,
            qty,
            px,
            ts,
        }
    }

    fn batches(&self) -> usize {
        self.rows.div_ceil(self.batch_size)
    }
}

#[derive(Default)]
struct PublishMetrics {
    latencies_ns: Vec<u64>,
    final_fsn: Option<u64>,
    publish_elapsed: Duration,
    drain_elapsed: Duration,
    allocations: Option<AllocationMetrics>,
}

#[derive(Clone, Copy)]
struct AllocationMetrics {
    alloc_calls: u64,
    alloc_bytes: u64,
    dealloc_calls: u64,
    dealloc_bytes: u64,
    peak_live_growth: u64,
}

fn reset_allocation_metrics() -> u64 {
    let live = LIVE_BYTES.load(Ordering::Relaxed);
    ALLOC_CALLS.store(0, Ordering::Relaxed);
    ALLOC_BYTES.store(0, Ordering::Relaxed);
    DEALLOC_CALLS.store(0, Ordering::Relaxed);
    DEALLOC_BYTES.store(0, Ordering::Relaxed);
    PEAK_LIVE_BYTES.store(live, Ordering::Relaxed);
    live
}

fn settle_before_measurement() {
    let millis = env_usize("QWP_WS_UNIFIED_SFA_BENCH_SETTLE_MILLIS", 0);
    if millis != 0 {
        std::thread::sleep(Duration::from_millis(millis as u64));
    }
}

fn allocation_metrics(baseline_live: u64) -> AllocationMetrics {
    AllocationMetrics {
        alloc_calls: ALLOC_CALLS.load(Ordering::Relaxed),
        alloc_bytes: ALLOC_BYTES.load(Ordering::Relaxed),
        dealloc_calls: DEALLOC_CALLS.load(Ordering::Relaxed),
        dealloc_bytes: DEALLOC_BYTES.load(Ordering::Relaxed),
        peak_live_growth: PEAK_LIVE_BYTES
            .load(Ordering::Relaxed)
            .saturating_sub(baseline_live),
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn fill_buffer_batch(
    buffer: &mut questdb::ingress::Buffer,
    table: &str,
    workload: &Workload,
    batch_idx: usize,
    rows_in_batch: usize,
) -> Result<()> {
    for row_idx in 0..rows_in_batch {
        let seq = batch_idx * workload.batch_size + row_idx;
        let symbol = workload.symbols[seq % workload.symbols.len()].as_str();
        buffer
            .table(table)?
            .symbol("sym", symbol)?
            .column_i64("qty", seq as i64)?
            .column_f64("px", 100.0 + (seq & 1023) as f64)?
            .at(TimestampNanos::new(BASE_TS_NANOS + seq as i64))?;
    }
    Ok(())
}

fn run_buffer(
    db: &QuestDb,
    table: &str,
    workload: &Workload,
    metrics: &mut PublishMetrics,
) -> Result<()> {
    let mut sender = db.borrow_sender()?;
    let mut buffer = db.new_buffer();
    settle_before_measurement();
    let live_baseline = reset_allocation_metrics();
    let publish_started = Instant::now();
    for batch_idx in 0..workload.batches() {
        let row_start = batch_idx * workload.batch_size;
        let rows_in_batch = (workload.rows - row_start).min(workload.batch_size);
        fill_buffer_batch(&mut buffer, table, workload, batch_idx, rows_in_batch)?;
        let started = Instant::now();
        metrics.final_fsn = sender.flush_buffer_and_get_fsn(&mut buffer)?;
        metrics.latencies_ns.push(duration_ns(started.elapsed()));
    }
    metrics.publish_elapsed = publish_started.elapsed();
    metrics.allocations = Some(allocation_metrics(live_baseline));
    let drain_started = Instant::now();
    sender.wait(AckLevel::Ok, Duration::from_secs(60))?;
    metrics.drain_elapsed = drain_started.elapsed();
    Ok(())
}

fn run_chunk(
    db: &QuestDb,
    table: &str,
    workload: &Workload,
    metrics: &mut PublishMetrics,
) -> Result<()> {
    let mut sender = db.borrow_sender()?;
    settle_before_measurement();
    let live_baseline = reset_allocation_metrics();
    let publish_started = Instant::now();
    for batch_idx in 0..workload.batches() {
        let row_start = batch_idx * workload.batch_size;
        let len = (workload.rows - row_start).min(workload.batch_size);
        let mut chunk = Chunk::new(table);
        chunk.symbol_i32(
            "sym",
            &workload.symbol_codes[..len],
            &workload.symbol_offsets,
            &workload.symbol_bytes,
            None,
        )?;
        chunk.column_i64("qty", &workload.qty[..len], None)?;
        chunk.column_f64("px", &workload.px[..len], None)?;
        chunk.at_nanos(&workload.ts[..len])?;
        let started = Instant::now();
        metrics.final_fsn = sender.flush_and_get_fsn(&mut chunk)?;
        metrics.latencies_ns.push(duration_ns(started.elapsed()));
    }
    metrics.publish_elapsed = publish_started.elapsed();
    metrics.allocations = Some(allocation_metrics(live_baseline));
    let drain_started = Instant::now();
    sender.wait(AckLevel::Ok, Duration::from_secs(60))?;
    metrics.drain_elapsed = drain_started.elapsed();
    Ok(())
}

fn arrow_batch(workload: &Workload) -> RecordBatch {
    let symbols: ArrayRef = Arc::new(StringArray::from(
        workload
            .symbol_codes
            .iter()
            .map(|&code| workload.symbols[code as usize].as_str())
            .collect::<Vec<_>>(),
    ));
    let qty: ArrayRef = Arc::new(Int64Array::from(workload.qty.clone()));
    let px: ArrayRef = Arc::new(Float64Array::from(workload.px.clone()));
    let ts: ArrayRef = Arc::new(arrow::array::TimestampNanosecondArray::from(
        workload.ts.clone(),
    ));
    let schema = Arc::new(Schema::new(vec![
        Field::new("sym", DataType::Utf8, false),
        Field::new("qty", DataType::Int64, false),
        Field::new("px", DataType::Float64, false),
        Field::new("ts", DataType::Timestamp(TimeUnit::Nanosecond, None), false),
    ]));
    RecordBatch::try_new(schema, vec![symbols, qty, px, ts])
        .expect("benchmark arrays have equal lengths and a matching schema")
}

fn run_arrow(
    db: &QuestDb,
    table: &str,
    workload: &Workload,
    metrics: &mut PublishMetrics,
) -> Result<()> {
    let mut sender = db.borrow_sender()?;
    let full_batch = arrow_batch(workload);
    let overrides = [ArrowColumnOverride::Symbol { column: "sym" }];
    let ts_column = ColumnName::new("ts")?;
    settle_before_measurement();
    let live_baseline = reset_allocation_metrics();
    let publish_started = Instant::now();
    for batch_idx in 0..workload.batches() {
        let row_start = batch_idx * workload.batch_size;
        let len = (workload.rows - row_start).min(workload.batch_size);
        let batch = if len == workload.batch_size {
            full_batch.clone()
        } else {
            full_batch.slice(0, len)
        };
        let started = Instant::now();
        metrics.final_fsn =
            sender.flush_arrow_batch_at_column_and_get_fsn(table, &batch, ts_column, &overrides)?;
        metrics.latencies_ns.push(duration_ns(started.elapsed()));
    }
    metrics.publish_elapsed = publish_started.elapsed();
    metrics.allocations = Some(allocation_metrics(live_baseline));
    let drain_started = Instant::now();
    sender.wait(AckLevel::Ok, Duration::from_secs(60))?;
    metrics.drain_elapsed = drain_started.elapsed();
    Ok(())
}

fn duration_ns(duration: Duration) -> u64 {
    duration.as_nanos().min(u128::from(u64::MAX)) as u64
}

fn percentile(sorted: &[u64], percentile: usize) -> u64 {
    let idx = (sorted.len() - 1) * percentile / 100;
    sorted[idx]
}

fn main() -> Result<()> {
    let conf = env_string("QWP_WS_UNIFIED_SFA_BENCH_CONF", DEFAULT_CONF);
    let table = env_string("QWP_WS_UNIFIED_SFA_BENCH_TABLE", DEFAULT_TABLE);
    let label = env_string("QWP_WS_UNIFIED_SFA_BENCH_LABEL", "unlabeled");
    let mode = Mode::parse(&env_string("QWP_WS_UNIFIED_SFA_BENCH_MODE", "buffer").to_lowercase());
    let rows = env_usize("QWP_WS_UNIFIED_SFA_BENCH_ROWS", DEFAULT_ROWS);
    let batch_size = env_usize("QWP_WS_UNIFIED_SFA_BENCH_BATCH_SIZE", DEFAULT_BATCH_SIZE);
    let symbol_cardinality = env_usize(
        "QWP_WS_UNIFIED_SFA_BENCH_SYMBOL_CARDINALITY",
        DEFAULT_SYMBOL_CARDINALITY,
    );
    assert!(rows > 0, "rows must be positive");
    assert!(batch_size > 0, "batch size must be positive");
    assert!(
        symbol_cardinality > 0 && symbol_cardinality <= i32::MAX as usize,
        "symbol cardinality must be in 1..=i32::MAX"
    );

    let workload = Workload::new(rows, batch_size, symbol_cardinality);
    let db = QuestDb::connect(&conf)?;
    let mut metrics = PublishMetrics {
        latencies_ns: Vec::with_capacity(workload.batches()),
        final_fsn: None,
        publish_elapsed: Duration::ZERO,
        drain_elapsed: Duration::ZERO,
        allocations: None,
    };
    match mode {
        Mode::Buffer => run_buffer(&db, &table, &workload, &mut metrics)?,
        Mode::Chunk => run_chunk(&db, &table, &workload, &mut metrics)?,
        Mode::Arrow => run_arrow(&db, &table, &workload, &mut metrics)?,
    }
    let allocations = metrics
        .allocations
        .expect("each benchmark mode records allocation metrics");

    let close_started = Instant::now();
    drop(db);
    let close_elapsed = close_started.elapsed();
    metrics.latencies_ns.sort_unstable();

    eprintln!(
        "qwp_ws_unified_sfa_bench label={} mode={} rows={} batch_size={} batches={} \
         symbol_cardinality={} publish_ms={} drain_ms={} close_ms={} rows_per_sec={:.2} \
         queue_latency_p50_ns={} queue_latency_p95_ns={} queue_latency_p99_ns={} \
         alloc_calls={} alloc_bytes={} dealloc_calls={} dealloc_bytes={} \
         peak_live_growth_bytes={} alloc_calls_per_batch={:.4} alloc_bytes_per_row={:.4} \
         final_fsn={:?} conf={}",
        label,
        mode.as_str(),
        rows,
        batch_size,
        workload.batches(),
        symbol_cardinality,
        metrics.publish_elapsed.as_millis(),
        metrics.drain_elapsed.as_millis(),
        close_elapsed.as_millis(),
        rows as f64 / metrics.publish_elapsed.as_secs_f64(),
        percentile(&metrics.latencies_ns, 50),
        percentile(&metrics.latencies_ns, 95),
        percentile(&metrics.latencies_ns, 99),
        allocations.alloc_calls,
        allocations.alloc_bytes,
        allocations.dealloc_calls,
        allocations.dealloc_bytes,
        allocations.peak_live_growth,
        allocations.alloc_calls as f64 / workload.batches() as f64,
        allocations.alloc_bytes as f64 / rows as f64,
        metrics.final_fsn,
        conf,
    );

    Ok(())
}
