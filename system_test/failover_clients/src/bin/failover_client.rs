//! Test helper for `system_test/test_egress_failover.py`. NOT a documentation
//! example — it exists purely to give the Python failover test a
//! deterministic synchronization point for killing the upstream server
//! mid-stream.
//!
//! Differs from `questdb-rs/examples/qwp_egress_failover.rs` in two
//! ways:
//!
//!   1. After the first `RESULT_BATCH` arrives, prints
//!      `BATCH_RECEIVED\n` to STDOUT and flushes, then blocks waiting
//!      for a line on STDIN. The test harness reads stdout to know the
//!      cursor has actually started streaming, kills server #1, then
//!      writes a line to stdin to release this binary.
//!   2. Sets `initial_credit` to 4 KiB so the server can't outpace the
//!      pause: after the first batch (the row floor lets it ship one
//!      batch beyond the budget) the server stops emitting until the
//!      cursor's auto-replenish CREDIT lands. With the cursor blocked
//!      on stdin, that CREDIT is delayed too — so even on a tiny
//!      result set the kill is guaranteed to land mid-stream.
//!
//! Build & run:
//!     cd system_test/failover_clients
//!     cargo build --release
//!     ./target/release/failover_client \
//!         "qwp::addr=h1:p1,h2:p2;target=primary" "SELECT ..."
//!
//! Final stderr line is the same `completed: batches=N rows=M
//! failover_resets=K final_endpoint=...` summary `qwp_egress_failover`
//! produces, so the Python test parses both identically.

use std::io::{BufRead, Write};
use std::sync::{Arc, Mutex};

use questdb::egress::{FailoverEvent, Reader};

/// Initial byte-credit window. The server pauses streaming after this
/// budget is exhausted, modulo the row floor (one extra batch
/// permitted). 4 KiB is below QuestDB's per-batch wire size, so the
/// pause kicks in on batch boundaries.
const INITIAL_CREDIT_BYTES: u64 = 4 * 1024;

fn main() {
    let conf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "qwp::addr=localhost:9000".into());
    let sql: String = std::env::args().nth(2).unwrap_or_else(|| "SELECT 1".into());

    let mut reader = Reader::from_conf(&conf).expect("connect");
    eprintln!(
        "connected to {} (cluster role: {:?})",
        reader.current_addr(),
        reader.server_info().map(|i| i.role)
    );

    let rows_received: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let rows_for_cb = Arc::clone(&rows_received);

    let mut cursor = reader
        .query(&sql)
        .initial_credit(INITIAL_CREDIT_BYTES)
        .on_failover_reset(move |ev: &FailoverEvent| {
            eprintln!(
                "[failover] {} -> {} attempts={} elapsed={:?} trigger={:?}: {}",
                ev.failed_addr,
                ev.new_addr,
                ev.attempts,
                ev.elapsed,
                ev.trigger.code(),
                ev.trigger.msg(),
            );
            *rows_for_cb.lock().unwrap() = 0;
        })
        .execute()
        .expect("execute");

    let mut total_batches = 0u64;

    // Phase 1: drain exactly one batch so the test harness has a
    // deterministic "the cursor is mid-stream" anchor.
    if let Some(batch) = cursor.next_batch().expect("next (first batch)") {
        total_batches += 1;
        *rows_received.lock().unwrap() += batch.row_count() as u64;
    } else {
        // Empty result set — no batches at all. The test relies on
        // the table having data; this is a configuration error.
        eprintln!("WARN: cursor terminated before first batch arrived");
    }

    // Phase 2: signal the harness, then block waiting for the kill +
    // green light. STDOUT is reserved for this signal; everything else
    // goes to STDERR so the test parser doesn't trip over log spam.
    println!("BATCH_RECEIVED");
    std::io::stdout().flush().expect("flush stdout");

    let mut line = String::new();
    let stdin = std::io::stdin();
    stdin
        .lock()
        .read_line(&mut line)
        .expect("read stdin signal");

    // Phase 3: drain the remaining batches. The auto-replenish CREDIT
    // frame queued during Phase 1's `next_batch` call may have failed
    // to send if server #1 is already dead; in that case the cursor's
    // mid-query failover machinery will reconnect to the next endpoint
    // and replay the QUERY_REQUEST transparently.
    while let Some(batch) = cursor.next_batch().expect("next (post-kill)") {
        total_batches += 1;
        *rows_received.lock().unwrap() += batch.row_count() as u64;
    }
    let resets = cursor.failover_resets();
    drop(cursor);

    eprintln!(
        "completed: batches={} rows={} failover_resets={} final_endpoint={}",
        total_batches,
        *rows_received.lock().unwrap(),
        resets,
        reader.current_addr(),
    );
}
