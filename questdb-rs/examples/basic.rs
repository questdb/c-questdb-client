use questdb::{
    Result,
    ingress::{
        Buffer,
        SenderBuilder}};
use clap::Parser;

/// ILP Connection Arguments
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Database hostname.
    #[clap(long, value_parser, default_value = "localhost")]
    host: String,

    /// ILP Port.
    #[clap(long, value_parser, default_value_t = 9009)]
    port: u16,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let mut sender = SenderBuilder::new(args.host, args.port).connect()?;
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
