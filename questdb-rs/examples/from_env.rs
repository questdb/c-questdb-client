use questdb::{
    ingress::{Buffer, Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    // Read configuration string from the `QDB_CLIENT_CONF` environment variable.
    let mut sender = Sender::from_env()?;
    let mut buffer = Buffer::new();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    Ok(())
}
