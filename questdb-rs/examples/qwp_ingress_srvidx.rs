//! srv-covidx campaign load generator (doc/net_bench/SRV_COVIDX_PLAN.md).
//!
//! Ingests the campaign's narrow 3-column schema (`bench_s3_cov` /
//! `bench_s3_plain`) with zipfian symbols and 1k-row transactions, one WAL
//! txn per flush (row path never defers commits). Unlike the client benches
//! this one measures the **server**: every pass runs against a fresh table
//! and reports both flush-ack wall ("srvidx-flush") and WAL-applied wall
//! ("srvidx-applied", flush + `wal_tables()` drain).
//!
//! Env knobs:
//!   VARIANT=cov|plain        table variant (default cov)
//!   ROWS=10000000            rows per pass
//!   SENDERS=1                connections; round-robin row split (i % n == k)
//!   MAX_BATCH_ROWS=1000      rows per flush == rows per WAL txn
//!   ITERATIONS=5  WARMUPS=2  CHECKPOINT_BATCHES=64
//!   RUN_MODE=e2e|selftest    selftest = generator invariants only, no server
//!   QDB_HOST=127.0.0.1  QDB_PORT=9000  QDB_CONF_EXTRA=
//!   SEED_BASE=42             pass p uses seed SEED_BASE + p

use std::error::Error;

mod bench_json;
mod bench_srvidx;

fn main() -> Result<(), Box<dyn Error>> {
    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "e2e".into());
    if run_mode == "selftest" {
        bench_srvidx::selftest().map_err(|e| format!("selftest FAILED: {e}"))?;
        println!("{{\"selftest\":\"ok\"}}");
        return Ok(());
    }
    Err("e2e mode not implemented yet (Task 2)".into())
}
