//! Pooled `Db` facade: one cloneable handle that pools both ingest senders
//! and egress readers, so application code never opens or closes a connection.
//!
//! Run (needs a local QuestDB on :9000):
//!     cargo run --example db_pool --features pool
//!
//! Env:
//!     QDB_HOST=localhost  QDB_PORT=9000

use questdb::db::Db;
use questdb::egress::column::ColumnView;
use questdb::ingress::TimestampNanos;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = std::env::var("QDB_HOST").unwrap_or_else(|_| "localhost".into());
    let port: u16 = std::env::var("QDB_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(9000);

    // Build one handle for the whole deployment. Ingest over HTTP, query over
    // WS, with explicit pool sizing. `Db` is `Clone` (cheap, Arc-backed) — clone
    // it into every thread; the pools guarantee mutual exclusion of slots.
    let db = Db::builder()
        .ingest_config(&format!("http::addr={host}:{port};"))
        .query_config(&format!("ws::addr={host}:{port};"))
        .sender_pool_max(8)
        .query_pool_max(4)
        .acquire_timeout(Duration::from_secs(5))
        .idle_timeout(Duration::from_secs(30))
        .build()?;

    // --- Ingest: borrow a sender, build rows, flush. Returns to the pool on
    // drop; no connection lifecycle in user code. ---
    {
        let mut sender = db.borrow_sender()?;
        let mut buf = sender.new_buffer();
        for i in 0..1_000i64 {
            buf.table("db_pool_demo")?
                .symbol("sym", if i % 2 == 0 { "ETH-USD" } else { "BTC-USD" })?
                .column_i64("id", i)?
                .column_f64("price", i as f64 * 1.5)?
                .at(TimestampNanos::now())?;
        }
        sender.flush(&mut buf)?;
        println!(
            "ingested 1000 rows; sender pool size = {}",
            db.sender_pool_size()
        );
    }

    // --- Query: run a SELECT and consume batches. The reader returns to the
    // pool clean once the query reaches its terminal. ---
    let mut total_price = 0.0f64;
    let summary = db.execute_query("select id, price from db_pool_demo", |batch| {
        if let Ok(ColumnView::Double(price)) = batch.column(1) {
            for r in 0..batch.row_count() {
                if !price.is_null(r) {
                    total_price += price.value(r);
                }
            }
        }
        true // keep streaming; return false to stop early (auto-cancels)
    })?;

    println!(
        "queried {} rows in {} batches; price sum = {total_price:.1}; query pool size = {}",
        summary.rows,
        summary.batches,
        db.reader_pool_size()
    );

    // Demonstrate concurrent use from multiple threads sharing the one handle.
    let mut handles = Vec::new();
    for t in 0..4 {
        let db = db.clone();
        handles.push(std::thread::spawn(move || {
            let s = db
                .execute_query("select count() from db_pool_demo", |_b| true)
                .expect("query");
            println!("thread {t}: {} batch(es)", s.batches);
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    db.close();
    Ok(())
}
