use ndarray::arr1;
use questdb::{
    ingress::{Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let mut sender = Sender::from_conf("https::addr=localhost:9000;username=foo;password=bar;")?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        // QuestDB server version 8.4.0 or later is required for array support.
        .column_arr("location", &arr1(&[100.0, 100.1, 100.2]).view())?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    Ok(())
}
