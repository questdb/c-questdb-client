use questdb::ingress::SenderProtocol;
use questdb::{
    ingress::{Buffer, SenderBuilder, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let mut sender = SenderBuilder::new("localhost", 9000)
        .protocol(SenderProtocol::IlpOverHttp)
        .connect()?;
    let mut buffer = Buffer::new();
    buffer
        .table("sensors")?
        .symbol("id", "toronto1")?
        //        .column_f64("temperature", 20.0)?
        .symbol("temperature", "w00t")?
        .column_i64("humidity", 50)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    Ok(())
}
