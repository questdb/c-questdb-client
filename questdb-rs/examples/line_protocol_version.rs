use ndarray::arr1;
use questdb::ingress::LineProtocolVersion;
use questdb::{
    ingress::{Buffer, Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let mut sender = Sender::from_conf("https::addr=localhost:9000;username=foo;password=bar;")?;
    let mut buffer = Buffer::new().with_line_proto_version(LineProtocolVersion::V1)?;
    buffer
        .table("trades_ilp_v1")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;

    let mut sender2 = Sender::from_conf("https::addr=localhost:9000;username=foo;password=bar;")?;
    let mut buffer2 =
        Buffer::new().with_line_proto_version(sender2.default_line_protocol_version())?;
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
