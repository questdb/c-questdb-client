//! Minimal QWP/WebSocket ingestion.
//!
//! Publishes one trades row to a QuestDB server reachable on
//! `ws::addr=localhost:9000;` (override host and port via command-line
//! arguments) and waits for in-flight frames to be acknowledged before
//! the sender is dropped.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example qwp_ws_basic --features sync-sender-qwp-ws
//! cargo run --example qwp_ws_basic --features sync-sender-qwp-ws -- db.example.com 9000
//! ```

use questdb::{
    Result,
    ingress::{Sender, TimestampNanos},
};

fn main() -> Result<()> {
    let host = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "localhost".to_string());
    let port = std::env::args().nth(2).unwrap_or_else(|| "9000".to_string());
    let conf = format!("ws::addr={host}:{port};");

    let mut sender = Sender::from_conf(conf.as_str())?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(TimestampNanos::now())?;

    sender.flush(&mut buffer)?;

    // close_drain stops accepting new publications and waits up to
    // close_flush_timeout_millis (default 5000) for already-published
    // frames to be acknowledged by the server. Skip it (or rely on
    // Sender::drop) only if delivery is not delivery-sensitive --
    // without close_drain, in-flight frames may not reach the server
    // and any delivery failure is silent.
    sender.close_drain()?;

    Ok(())
}
