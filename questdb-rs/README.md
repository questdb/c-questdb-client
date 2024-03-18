# QuestDB Client Library for Rust

Official Rust client for [QuestDB](https://questdb.io/), an open-source SQL database designed to process time-series data, faster.

The client library is designed for fast ingestion of data into QuestDB via the InfluxDB Line Protocol (ILP).

* [QuestDB Database docs](https://questdb.io/docs/)
* [ILP docs](https://questdb.io/docs/reference/api/ilp/overview/)

## Getting Started

To start using `questdb-rs` add it to your `Cargo.toml`:

```toml
[dependencies]
questdb-rs = "4.0.0"
```

## Docs

See documentation for the [`ingress`](https://docs.rs/questdb-rs/4.0.0/questdb/ingress/) module to insert data into QuestDB via the ILP protocol.

* Latest API docs: [https://docs.rs/questdb-rs/latest/](https://docs.rs/questdb-rs/latest/)

## Example

```rust no_run
use questdb::{
    Result,
    ingress::{
        Sender,
        Buffer,
        TimestampNanos}};

fn main() -> Result<()> {
   let mut sender = Sender::from_conf("http::addr=localhost:9000;")?;
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

## Crate features

This Rust crate supports a number of optional features.

For example, if you want to work with ILP/HTTP and work with Chrono timestamps,
use:

```bash
cargo add questdb-rs --features ilp-over-http chrono
```

### Default-enabled features

* `tls-webpki-certs`: Use the `webpki-roots` crate for TLS cert verification.

### Optional features

These features are opt-in as they bring in additional downstream dependencies.

* `ilp-over-http`: Enables ILP/HTTP support via the `ureq` crate.
* `tls-native-certs`: Supports validating TLS certificates against the OS's
  certificates store.
* `insecure-skip-verify`: Allows skipping TLS validation.
* `chrono_timestamp`: Allows specifying timestamps as `chrono::Datetime` objects.

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
