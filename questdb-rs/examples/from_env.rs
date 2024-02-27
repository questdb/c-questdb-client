use questdb::{
    ingress::{Buffer, Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    // Read connection string from the `QDB_CLIENT_CONF` environment variable.
    let mut sender = Sender::from_env()?;
    let mut buffer = Buffer::new();
    buffer
        .table("sensors")?
        .symbol("id", "toronto1")?
        .column_f64("temperature", 20.0)?
        .column_i64("humidity", 50)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    Ok(())
}
