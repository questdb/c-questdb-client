//! QWP/WebSocket asynchronous error handling.
//!
//! Server errors (schema mismatch, parse error, security error, etc.)
//! arrive asynchronously after `flush` has returned. There are two
//! ways to observe them:
//!
//!   - Poll for them with `Sender::poll_qwp_ws_error`. The diagnostic
//!     log is bounded; if the caller polls too slowly, older
//!     diagnostics are dropped and the dropped count is available via
//!     `Sender::qwp_ws_errors_dropped`.
//!   - Install a callback at construction time via
//!     `SenderBuilder::qwp_ws_error_handler`. The callback runs
//!     synchronously from sender API calls such as `flush` and must
//!     not call methods on the same sender.
//!
//! This example shows both styles back-to-back.
//!
//! Run with:
//!
//! ```sh
//! cargo run --example qwp_ws_error_handling --features sync-sender-qwp-ws
//! ```

use questdb::{
    Result,
    ingress::{Sender, SenderBuilder, TimestampNanos},
};
use std::time::Duration;

fn polling_style() -> Result<()> {
    let mut sender = Sender::from_conf("ws::addr=localhost:9000;")?;
    let mut buffer = sender.new_buffer();

    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .column_f64("price", 2615.54)?
        .at(TimestampNanos::now())?;
    let published_fsn = sender.flush_and_get_fsn(&mut buffer)?;

    let wait_result = if let Some(fsn) = published_fsn {
        match sender.await_acked_fsn(fsn, Duration::from_secs(5)) {
            Ok(true) => Ok(()),
            Ok(false) => {
                eprintln!("timed out waiting for QWP/WebSocket frame {fsn} to complete");
                Ok(())
            }
            Err(err) => Err(err),
        }
    } else {
        Ok(())
    };

    // Drain server-side diagnostics observed for completed frames.
    while let Some(err) = sender.poll_qwp_ws_error()? {
        eprintln!(
            "qwp error (poll): category={:?} policy={:?} fsn=[{}..={}] msg={:?}",
            err.category, err.applied_policy, err.from_fsn, err.to_fsn, err.message
        );
    }

    let dropped = sender.qwp_ws_errors_dropped()?;
    if dropped > 0 {
        eprintln!("note: {dropped} diagnostic(s) were dropped from the log");
    }

    sender.close_drain()?;
    wait_result
}

fn callback_style() -> Result<()> {
    let mut sender = SenderBuilder::from_conf("ws::addr=localhost:9000;")?
        .qwp_ws_error_handler(|err| {
            eprintln!(
                "qwp error (callback): category={:?} policy={:?} fsn=[{}..={}] msg={:?}",
                err.category, err.applied_policy, err.from_fsn, err.to_fsn, err.message
            );
        })?
        .build()?;

    let mut buffer = sender.new_buffer();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .column_f64("price", 2615.54)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;

    sender.close_drain()?;
    Ok(())
}

fn main() -> Result<()> {
    println!("polling style:");
    polling_style()?;
    println!("\ncallback style:");
    callback_style()?;
    Ok(())
}
