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
    let conf = "ws::addr=db-primary:9000,db-replica-1:9000,db-replica-2:9000;\
                sf_dir=/tmp/myapp-qdb-sf;\
                sender_id=ingest-1;\
                reconnect_max_duration_millis=300000;";

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

        // On flush failure, the buffer is retained so the next
        // iteration retries the same payload. must_close() reports
        // whether the sender has latched into a terminal state and
        // must be dropped and recreated (e.g. auth failure, reconnect
        // budget exhausted).
        if let Err(e) = sender.flush(&mut buffer) {
            eprintln!("flush error: {e}");
            if sender.must_close() {
                eprintln!("sender is terminal; aborting");
                return Err(e);
            }
        }

        thread::sleep(Duration::from_secs(1));
    }

    sender.close_drain()?;
    Ok(())
}
