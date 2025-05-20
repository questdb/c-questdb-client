# QuestDB Client Library for Rust

Official Rust client for [QuestDB](https://questdb.io/), an open-source SQL
database designed to process time-series data, faster.

The client library is designed for fast ingestion of data into QuestDB via the
Ingestion Line Protocol (ILP) over either HTTP (recommended) or TCP.

* [QuestDB Database docs](https://questdb.io/docs/)
* [Docs on Ingestion Line Protocol](https://questdb.io/docs/reference/api/ilp/overview/)

When connecting to QuestDB over HTTP, the library will auto-detect the server's
latest supported version and use it. Version 1 is compatible with
the [InfluxDB Line Protocol](https://docs.influxdata.com/influxdb/v2/reference/syntax/line-protocol/).

## Quick Start

To start using `questdb-rs`, add it as a dependency of your project:

```bash
cargo add questdb-rs
```

Then you can try out this quick example, which connects to a QuestDB server
running on your local machine:

```rust no_run
use questdb::{
    Result,
    ingress::{
        Sender,
        Buffer,
        TimestampNanos}};

fn main() -> Result<()> {
   let mut sender = Sender::from_conf("http::addr=localhost:9000;")?;
  let mut buffer = sender.new_buffer();
   buffer
       .table("trades")?
       .symbol("symbol", "ETH-USD")?
       .symbol("side", "sell")?
       .column_f64("price", 2615.54)?
       .column_f64("amount", 0.00044)?
       .at(TimestampNanos::now())?;
   sender.flush(&mut buffer)?;
   Ok(())
}
```

## Docs

Most of the client documentation is on the
[`ingress`](https://docs.rs/questdb-rs/5.0.0-rc1/questdb/ingress/) module page.

## Crate features

This Rust crate supports a number of optional features, in most cases linked
to additional library dependencies.

For example, if you want to work with Chrono timestamps, use:

```bash
cargo add questdb-rs --features chrono_timestamp
```

### Default-enabled features

* `ilp-over-http`: Enables ILP/HTTP support via the `ureq` crate.
* `tls-webpki-certs`: Supports using the `webpki-roots` crate for TLS
  certificate verification.

### Optional features

These features are opt-in:

* `chrono_timestamp`: Allows specifying timestamps as `chrono::Datetime` objects.
* `tls-native-certs`: Supports validating TLS certificates against the OS's
  certificates store.
* `insecure-skip-verify`: Allows skipping server certificate validation in TLS
  (this compromises security).

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
