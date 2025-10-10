use chrono::{TimeZone, Utc};
use ndarray::arr1;
use questdb::{
    ingress::{Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let host: String = std::env::args().nth(1).unwrap_or("localhost".to_string());
    let port: &str = &std::env::args().nth(2).unwrap_or("9009".to_string());
    let mut sender = Sender::from_conf(format!("tcp::addr={host}:{port};protocol_version=2;"))?;
    let mut buffer = sender.new_buffer();
    let designated_timestamp =
        TimestampNanos::from_datetime(Utc.with_ymd_and_hms(1997, 7, 4, 4, 56, 55).unwrap())?;
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_decimal("price", "2615.54")?
        .column_f64("amount", 0.00044)?
        // QuestDB server version 9.0.0 or later is required for array support.
        .column_arr("location", &arr1(&[100.0, 100.1, 100.2]).view())?
        .at(designated_timestamp)?;

    //// If you want to pass the current system timestamp, replace with:
    // .at(TimestampNanos::now())?;

    // You can add multiple rows before flushing.
    // It's recommended to keep a timer and/or a buffer size before flushing.
    sender.flush(&mut buffer)?;

    // The buffer is now reusable. No need to reallocate a new one.
    Ok(())
}
