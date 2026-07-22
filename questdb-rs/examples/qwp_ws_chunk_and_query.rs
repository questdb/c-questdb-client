//! One `QuestDb` pool shared by two threads over QWP/WebSocket.
//!
//! The pool is created once, wrapped in an `Arc`, and handed to two worker
//! threads. Each worker takes its own short-lived borrow:
//!
//! * The ingestion thread builds column-major batches with the `Chunk` API and
//!   publishes them through a `BorrowedSender`, checkpointing on `AckLevel::Ok`.
//! * The query thread polls the same table through a `BorrowedReader`, watching
//!   rows become visible as the WAL is applied, then reports per-symbol stats.
//!
//! Both directions run concurrently against one pool, which is the intended
//! deployment shape: one pool per process, a borrow per unit of work.
//!
//! Run against a local QuestDB (10.0+):
//!
//! ```sh
//! cargo run --release --example qwp_ws_chunk_and_query \
//!     --features sync-sender-qwp-ws,sync-reader-qwp-ws
//! ```
//!
//! The example recreates its own `rust_shared_pool_trades` table on every run.

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use questdb::{
    Error, ErrorCode, QuestDb,
    egress::column::ColumnView,
    ingress::{AckLevel, TimestampNanos, column_sender::Chunk},
};

/// Separate caps for the two pools: this process holds at most one sender and
/// one reader borrow at a time, plus headroom for the main thread's DDL.
const CONF: &str = "ws::addr=localhost:9000;sender_pool_max=2;query_pool_max=2;";

const TABLE: &str = "rust_shared_pool_trades";

const INSTRUMENTS: [(&str, f64); 4] = [
    ("BTC-USDT", 65432.10),
    ("ETH-USDT", 2615.54),
    ("SOL-USDT", 141.27),
    ("ADA-USDT", 0.38),
];

const BATCHES: usize = 20;
const ROWS_PER_BATCH: usize = 5_000;
const TOTAL_ROWS: usize = BATCHES * ROWS_PER_BATCH;

/// Batches published between `AckLevel::Ok` checkpoints.
const CHECKPOINT_EVERY: usize = 8;

/// Pause between batches, standing in for the arrival rate of a live feed.
const BATCH_INTERVAL: Duration = Duration::from_millis(100);

/// Gap between query-visibility polls.
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// `amount` bind for the final per-symbol query.
const LARGE_TRADE: f64 = 0.005;

const ACK_TIMEOUT: Duration = Duration::from_secs(30);
const VISIBILITY_TIMEOUT: Duration = Duration::from_secs(60);

/// The client's own operations report `questdb::Error`. The visibility
/// deadline below is this example's own policy rather than a client failure, so
/// it needs an application error type; `questdb::Error` converts into this one.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Reports a result column that is not the type this program expects, in the
/// client's error vocabulary rather than as a panic.
fn column_type_error(column: &str, expected: &str) -> Error {
    Error::new(
        ErrorCode::InvalidApiCall,
        format!("result column {column} is not a {expected}"),
    )
}

fn main() -> Result<(), BoxError> {
    let db = Arc::new(QuestDb::connect(CONF)?);

    recreate_table(&db)?;

    let ingest_db = Arc::clone(&db);
    let ingest = thread::spawn(move || ingest_trades(&ingest_db));

    let query_db = Arc::clone(&db);
    let query = thread::spawn(move || follow_trades(&query_db));

    ingest.join().expect("ingest thread panicked")?;
    query.join().expect("query thread panicked")?;

    Ok(())
}

/// Runs DDL through a reader borrow. `execute` drives statements that return no
/// rows, and the cursor is drained to reach its terminal value.
fn recreate_table(db: &QuestDb) -> questdb::Result<()> {
    let mut reader = db.borrow_reader()?;

    for statement in [
        format!("DROP TABLE IF EXISTS {TABLE}"),
        format!(
            "CREATE TABLE {TABLE} (\
                 symbol SYMBOL, \
                 price DOUBLE, \
                 amount DOUBLE, \
                 timestamp TIMESTAMP\
             ) TIMESTAMP(timestamp) PARTITION BY DAY WAL"
        ),
    ] {
        let mut cursor = reader.execute(statement)?;
        while cursor.next_batch()?.is_some() {}
    }

    println!("table {TABLE} is ready");
    Ok(())
}

/// Publishes `TOTAL_ROWS` rows as column-major chunks.
fn ingest_trades(db: &QuestDb) -> questdb::Result<()> {
    let mut sender = db.borrow_sender()?;

    // Arrow-style dictionary shared by every batch: a flat UTF-8 block plus
    // `i32` offsets, where `offsets[i]..offsets[i + 1]` spans entry `i`.
    let mut dict_bytes: Vec<u8> = Vec::new();
    let mut dict_offsets: Vec<i32> = vec![0];
    for (instrument, _) in INSTRUMENTS {
        dict_bytes.extend_from_slice(instrument.as_bytes());
        dict_offsets.push(dict_bytes.len() as i32);
    }

    // Reused across batches: the chunk borrows these slices, so they outlive it.
    let mut symbol_codes: Vec<i8> = Vec::with_capacity(ROWS_PER_BATCH);
    let mut price: Vec<f64> = Vec::with_capacity(ROWS_PER_BATCH);
    let mut amount: Vec<f64> = Vec::with_capacity(ROWS_PER_BATCH);
    let mut timestamp: Vec<i64> = Vec::with_capacity(ROWS_PER_BATCH);

    // `at_nanos` takes raw epoch nanoseconds, which `TimestampNanos` unwraps.
    let mut rng = Rng::new(0x5eed_1234_9abc_def0);
    let mut row_ts = TimestampNanos::now().as_i64();
    let started = Instant::now();

    for batch in 0..BATCHES {
        symbol_codes.clear();
        price.clear();
        amount.clear();
        timestamp.clear();

        for _ in 0..ROWS_PER_BATCH {
            let code = (rng.next() % INSTRUMENTS.len() as u64) as usize;
            let (_, base_price) = INSTRUMENTS[code];

            symbol_codes.push(code as i8);
            price.push(base_price * (1.0 + rng.unit_spread() * 0.001));
            amount.push(0.0001 + rng.unit() * 0.01);
            row_ts += 1_000;
            timestamp.push(row_ts);
        }

        // One chunk per batch, built after its backing buffers and flushed
        // before they are reused.
        let mut chunk = Chunk::new(TABLE);
        chunk.symbol_i8("symbol", &symbol_codes, &dict_offsets, &dict_bytes, None)?;
        chunk.column_f64("price", &price, None)?;
        chunk.column_f64("amount", &amount, None)?;
        chunk.at_nanos(&timestamp)?;

        // Publishes to the local store-and-forward queue; delivery continues in
        // the background.
        sender.flush(&mut chunk)?;

        if (batch + 1) % CHECKPOINT_EVERY == 0 {
            // A bounded no-progress wait for everything published so far.
            sender.wait(AckLevel::Ok, ACK_TIMEOUT)?;
            println!("ingest: {} rows acked", (batch + 1) * ROWS_PER_BATCH);
        }

        // Paces the synthetic feed like a live market data source, so the query
        // thread observes the table growing rather than one finished bulk load.
        thread::sleep(BATCH_INTERVAL);
    }

    sender.wait(AckLevel::Ok, ACK_TIMEOUT)?;
    println!(
        "ingest: all {TOTAL_ROWS} rows acked in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Polls for query visibility, then reports per-symbol stats.
fn follow_trades(db: &QuestDb) -> Result<(), BoxError> {
    let deadline = Instant::now() + VISIBILITY_TIMEOUT;

    loop {
        let visible = count_rows(db)?;
        println!("query: {visible}/{TOTAL_ROWS} rows visible");

        if visible >= TOTAL_ROWS as i64 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(format!("only {visible}/{TOTAL_ROWS} rows became visible").into());
        }
        thread::sleep(POLL_INTERVAL);
    }

    report_large_trades(db)?;
    Ok(())
}

/// An `Ok` ack means the server accepted the frame; a row becomes visible only
/// once the WAL is applied, which happens asynchronously.
fn count_rows(db: &QuestDb) -> questdb::Result<i64> {
    let mut reader = db.borrow_reader()?;
    let mut cursor = reader.execute(format!("SELECT count() FROM {TABLE}"))?;
    let mut count = 0;

    while let Some(batch) = cursor.next_batch()? {
        let ColumnView::Long(counts) = batch.column(0)? else {
            return Err(column_type_error("count()", "LONG"));
        };
        if batch.row_count() > 0 && !counts.is_null(0) {
            count = counts.value(0);
        }
    }

    Ok(count)
}

fn report_large_trades(db: &QuestDb) -> questdb::Result<()> {
    let mut reader = db.borrow_reader()?;
    let mut cursor = reader
        .prepare(format!(
            "SELECT symbol, count() AS trades, avg(price) AS avg_price \
             FROM {TABLE} WHERE amount > $1 ORDER BY symbol"
        ))
        .bind_f64(LARGE_TRADE)
        .execute()?;

    println!("\ntrades with amount > {LARGE_TRADE}:");
    while let Some(batch) = cursor.next_batch()? {
        let ColumnView::Symbol(symbol) = batch.column(0)? else {
            return Err(column_type_error("symbol", "SYMBOL"));
        };
        let ColumnView::Long(trades) = batch.column(1)? else {
            return Err(column_type_error("count()", "LONG"));
        };
        let ColumnView::Double(avg_price) = batch.column(2)? else {
            return Err(column_type_error("avg(price)", "DOUBLE"));
        };

        for row in 0..batch.row_count() {
            let Some(instrument) = symbol.resolve(row) else {
                continue;
            };
            if avg_price.is_null(row) {
                continue;
            }
            println!(
                "  {instrument:<9} {:>6} trades, avg price {:.4}",
                trades.value(row),
                avg_price.value(row),
            );
        }
    }

    Ok(())
}

/// xorshift64*, so the example needs no `rand` dependency.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// Uniform in `[0, 1)`.
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }

    /// Uniform in `[-1, 1)`.
    fn unit_spread(&mut self) -> f64 {
        self.unit() * 2.0 - 1.0
    }
}
