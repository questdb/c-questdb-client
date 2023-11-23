# QuestDB Client Library for Rust

## Getting Started

To start using `questdb-rs` add it to your `Cargo.toml`:

```toml
[dependencies]
questdb-rs = "3.1.0"
```

## Docs

See documentation for the [`ingress`](https://docs.rs/questdb-rs/3.1.0/questdb/ingress/) module to insert data into QuestDB via the ILP protocol.

* Latest API docs: [https://docs.rs/questdb-rs/latest/](https://docs.rs/questdb-rs/latest/)

## Example

```rust no_run
use questdb::{
    Result,
    ingress::{
        Sender,
        Buffer,
        SenderBuilder,
        TimestampNanos}};

fn main() -> Result<()> {
   let mut sender = SenderBuilder::new("localhost", 9009).connect()?;
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
```

## C, C++ and Python APIs

This crate is also exposed as a C and C++ API and in turn exposed to Python.

* This project's [GitHub page](https://github.com/questdb/c-questdb-client)
  for the C and C++ API.
* [Python bindings](https://github.com/questdb/py-questdb-client).

## Community

If you need help, have additional questions or want to provide feedback, you
may find us on [Slack](https://slack.questdb.io/).

You can also sign up to our [mailing list](https://questdb.io/community/) to
get notified of new releases.
