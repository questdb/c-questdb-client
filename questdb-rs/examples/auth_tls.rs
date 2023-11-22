use chrono::{TimeZone, Utc};
use questdb::{
    ingress::{Buffer, CertificateAuthority, SenderBuilder, TimestampNanos, Tls},
    Result,
};

fn main() -> Result<()> {
    let host: String = std::env::args().nth(1).unwrap_or("localhost".to_string());
    let port: u16 = std::env::args()
        .nth(2)
        .unwrap_or("9009".to_string())
        .parse()
        .unwrap();
    let mut sender = SenderBuilder::new(host, port)
        .auth(
            "testUser1",                                   // kid
            "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48", // d
            "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // x
            "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac", // y
        )
        .tls(Tls::Enabled(CertificateAuthority::WebpkiRoots))
        // Alternatively: .tls(Tls::Enabled(CertificateAuthority::OsRoots))
        .connect()?;
    let mut buffer = Buffer::new();
    let designated_timestamp =
        TimestampNanos::from_datetime(Utc.with_ymd_and_hms(1997, 7, 4, 4, 56, 55).unwrap())?;
    buffer
        .table("sensors")?
        .symbol("id", "toronto1")?
        .column_f64("temperature", 20.0)?
        .column_i64("humidity", 50)?
        .at(designated_timestamp)?;

    //// If you want to pass the current system timestamp, replace with:
    // .at(TimestampNanos::now())?;

    // You can add multiple rows before flushing.
    // It's recommended to keep a timer and/or a buffer size before flushing.
    sender.flush(&mut buffer)?;

    // The buffer is now reusable. No need to reallocate a new one.
    Ok(())
}
