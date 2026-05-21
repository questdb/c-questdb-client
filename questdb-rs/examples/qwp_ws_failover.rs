//! QWP/WebSocket multi-host failover with store-and-forward.
//!
//! Demonstrates a production-style connect string with:
//!
//!   - Multiple `addr=` entries (the driver walks the list to find a
//!     healthy peer when the current connection breaks).
//!   - `sf_dir=...` so unacknowledged frames spill to disk and are
//!     replayed after reconnects and process restarts. Replay is
//!     at-least-once, so target tables should declare
//!     `DEDUP UPSERT KEYS(...)`.
//!   - `sender_id=...` identifying this sender's slot under `sf_dir`.
//!     Use a distinct id per sender process when several share the
//!     same directory.
//!   - `reconnect_max_duration_millis=...` to bound the per-outage
//!     reconnect budget.
//!
//! Replace the address list with hosts on your network and ensure the
//! `sf_dir` path is writable.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example qwp_ws_failover --features sync-sender-qwp-ws
//! ```

use std::thread;
use std::time::Duration;

use questdb::{
    Result,
    ingress::{Sender, TimestampNanos},
};

fn main() -> Result<()> {
    let sf_dir = std::env::temp_dir().join("myapp-qdb-sf");
    let conf = format!(
        "ws::addr=db-primary:9000,db-replica-1:9000,db-replica-2:9000;\
         sf_dir={};\
         sender_id=ingest-1;\
         reconnect_max_duration_millis=300000;",
        sf_dir.display()
    );

    let mut sender = Sender::from_conf(conf)?;
    let mut buffer = sender.new_buffer();

    // Publish ten rows, one per second. In a real ingest service this
    // loop would be driven by your data source instead.
    for _ in 0..10 {
        buffer
            .table("trades")?
            .symbol("symbol", "ETH-USD")?
            .symbol("side", "sell")?
            .column_f64("price", 2615.54)?
            .column_f64("amount", 0.00044)?
            .at(TimestampNanos::now())?;

        // For QWP/WebSocket, a successful flush publishes the batch
        // to the local replay queue or Store-and-Forward storage.
        // Delivery, ACKs, reconnect, and replay happen asynchronously.
        // If flush returns an error, the buffer is still intact; do
        // not append more rows until you have retried, cleared, or
        // dropped it.
        if let Err(e) = sender.flush(&mut buffer) {
            eprintln!("flush error: {e}");
            if sender.must_close() {
                eprintln!("sender is terminal; aborting");
            }
            return Err(e);
        }

        thread::sleep(Duration::from_secs(1));
    }

    sender.close_drain()?;
    Ok(())
}
