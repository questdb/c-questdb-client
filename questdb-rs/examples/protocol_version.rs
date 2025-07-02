use ndarray::arr1;
use questdb::{
    ingress::{Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let mut sender = Sender::from_conf(
        "https::addr=localhost:9000;username=foo;password=bar;protocol_version=1;",
    )?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("trades_ilp_v1")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;

    // QuestDB server version 9.0.0 or later is required for `protocol_version=2` support.
    let mut sender2 = Sender::from_conf(
        "https::addr=localhost:9000;username=foo;password=bar;protocol_version=2;",
    )?;
    let mut buffer2 = sender.new_buffer();
    buffer2
        .table("trades_ilp_v2")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .column_arr("location", &arr1(&[100.0, 100.1, 100.2]).view())?
        .at(TimestampNanos::now())?;
    sender2.flush(&mut buffer2)?;
    Ok(())
}
