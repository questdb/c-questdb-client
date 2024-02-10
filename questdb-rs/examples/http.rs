use questdb::ingress::{CertificateAuthority, Tls};
use questdb::{
    ingress::{Buffer, SenderBuilder, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let mut sender = SenderBuilder::new_tcp("localhost", 9000)
        .http()
        .tls(Tls::Enabled(CertificateAuthority::WebpkiRoots))
        .basic_auth("foo", "bar")
        .connect()?;
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
