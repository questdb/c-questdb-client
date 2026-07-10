//! Demonstrates mid-query failover for the QWP egress reader.
//!
//! Configure a cluster with multiple endpoints and a failover handler
//! that prints whenever the cursor's underlying connection is replaced.
//!
//! Run with:
//!     cargo run --release --example qwp_egress_failover \
//!         --features sync-reader-qwp-ws \
//!         -- "ws::addr=db-a:9000,db-b:9000,db-c:9000;target=primary" "SELECT 1"
//!
//! When ANY of the endpoints in the address list dies mid-query (peer
//! reset, TLS reset, server bounce), the cursor automatically reconnects
//! to the next live endpoint that satisfies the `target` filter, replays
//! the same SQL with a fresh `request_id`, and resumes streaming.
//!
//! The user-supplied callback is the place to discard whatever rows the
//! handler had accumulated from the previous (now-dead) connection — the
//! query restarts from `batch_seq=0`, so anything you'd already buffered
//! will be re-delivered. For idempotent point-in-time queries (e.g.
//! `SELECT … WHERE ts < '2026-04-27'`) failover is fully transparent.
//! For "now"-bounded or streaming-style queries, the replayed rows may
//! differ slightly from what was being delivered before the failure.

use std::sync::{Arc, Mutex};

use questdb::egress::{FailoverResetEvent, Reader};

fn main() {
    // The default is single-endpoint so `cargo run --example` works
    // out of the box against a local server. To actually exercise
    // mid-query failover, pass a multi-endpoint conf string as
    // argv[1], e.g.
    //   `ws::addr=db-a:9000,db-b:9000,db-c:9000;target=primary`.
    let conf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "ws::addr=localhost:9000".into());
    let sql: String = std::env::args().nth(2).unwrap_or_else(|| "SELECT 1".into());

    let mut reader = Reader::from_conf(&conf).expect("connect");
    eprintln!(
        "connected to {} (cluster role: {:?})",
        reader.current_addr(),
        reader.server_info().map(|i| i.role)
    );

    // Shared row counter: the callback resets it on failover so the
    // replayed batches don't double-count. Real handlers would buffer
    // the actual row data here and dispatch on `batch.schema()`.
    let rows_received: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let rows_for_cb = Arc::clone(&rows_received);

    let mut cursor = reader
        .prepare(&sql)
        .on_failover_reset(move |ev: &FailoverResetEvent| {
            // `ev.trigger` carries the full error of the previous
            // connection's death — code (for routing/metrics) and
            // message (for log diagnostics). Print both.
            eprintln!(
                "[failover] {:>21} → {:<21}  attempts={} elapsed={:?} trigger={:?}: {}",
                ev.failed_addr.to_string(),
                ev.new_addr.to_string(),
                ev.attempts,
                ev.elapsed,
                ev.trigger.code(),
                ev.trigger.msg(),
            );
            // Discard whatever the previous connection delivered — the
            // server will resend from `batch_seq=0` on the new endpoint.
            *rows_for_cb.lock().unwrap() = 0;
        })
        .execute()
        .expect("execute");

    let mut total_batches = 0u64;
    while let Some(batch) = cursor.next_batch().expect("next") {
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
