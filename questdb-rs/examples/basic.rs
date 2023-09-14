use questdb::{
    ingress::{Buffer, SenderBuilder},
    Result,
};

fn main() -> Result<()> {
    let host: String = std::env::args().nth(1).unwrap_or("localhost".to_string());
    let port: u16 = std::env::args()
        .nth(2)
        .unwrap_or("9009".to_string())
        .parse()
        .unwrap();
    let mut sender = SenderBuilder::new(host, port).connect()?;
    let mut buffer = Buffer::new();
    buffer
        .table("sensors")?
        .symbol("id", "toronto1")?
        .column_f64("temperature", 20.0)?
        .column_i64("humidity", 50)?
        .at_now()?;
    sender.flush(&mut buffer)?;
    Ok(())
}
