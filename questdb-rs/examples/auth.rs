use chrono::{TimeZone, Utc};
use questdb::{
    ingress::{Sender, TimestampNanos},
    Result,
};

fn main() -> Result<()> {
    let host: String = std::env::args().nth(1).unwrap_or("localhost".to_string());
    let port: &str = &std::env::args().nth(2).unwrap_or("9009".to_string());
    let mut sender = Sender::from_conf(format!(
        concat!(
            "tcp::addr={}:{};",
            "username=admin;",
            "token=5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48;",
            "token_x=fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU;",
            "token_y=Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac;"
        ),
        host, port
    ))?;
    let mut buffer = sender.new_buffer();
    let designated_timestamp =
        TimestampNanos::from_datetime(Utc.with_ymd_and_hms(1997, 7, 4, 4, 56, 55).unwrap())?;
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(designated_timestamp)?;

    //// If you want to pass the current system timestamp, replace with:
    // .at(TimestampNanos::now())?;

    // You can add multiple rows before flushing.
    // It's recommended to keep a timer and/or a buffer size before flushing.
    sender.flush(&mut buffer)?;

    // The buffer is now reusable. No need to reallocate a new one.
    Ok(())
}
