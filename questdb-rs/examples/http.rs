use std::str::FromStr;

use ndarray::arr1;
use questdb::{
    ingress::{Sender, TimestampNanos},
    Result,
};
use rust_decimal::Decimal;

fn main() -> Result<()> {
    let mut sender = Sender::from_conf(
        "https::addr=localhost:9000;username=foo;password=bar;protocol_version=3;",
    )?;
    let mut buffer = sender.new_buffer();
    let price = Decimal::from_str("2615.54").unwrap();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_dec("price", &price)?
        .column_f64("amount", 0.00044)?
        // QuestDB server version 9.0.0 or later is required for array support.
        .column_arr("location", &arr1(&[100.0, 100.1, 100.2]).view())?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    Ok(())
}
