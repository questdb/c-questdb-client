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
    let mut sender = SenderBuilder::new(host, port)
        .auth(
            "testUser1",                                   // kid
            "5UjEMuA0Pj5pjK8a-fa24dyIf-Es5mYny3oE_Wmus48", // d
            "fLKYEaoEb9lrn3nkwLDA-M_xnuFOdSt9y0Z7_vWSHLU", // x
            "Dt5tbS1dEDMSYfym3fgMv0B99szno-dFc1rYF9t0aac",
        ) // y
        .connect()?;
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
