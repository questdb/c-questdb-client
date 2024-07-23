use questdb::{
    ingress::{Buffer, Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let mut sender = Sender::from_conf("https::addr=localhost:9000;username=foo;password=bar;")?;
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
