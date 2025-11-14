# QuestDB Client Library for Rust

Official Rust client for [QuestDB](https://questdb.io/), an open-source SQL
database designed to process time-series data, faster.

The client library is designed for fast ingestion of data into QuestDB via the
InfluxDB Line Protocol (ILP) over either HTTP (recommended) or TCP.

* [QuestDB Database docs](https://questdb.io/docs/)
* [Docs on InfluxDB Line Protocol](https://questdb.io/docs/reference/api/ilp/overview/)

## Protocol Versions

The library supports the following ILP protocol versions.

These protocol versions are supported over both HTTP and TCP.

* If you use HTTP and `protocol_version=auto` or unset, the library will
  automatically detect the server's
  latest supported protocol version and use it (recommended).
* If you use TCP, you can specify the
  `protocol_version=N` parameter when constructing the `Sender` object
  (TCP defaults to `protocol_version=1`).

| Version | Description                                             | Server Compatibility   |
| ------- | ------------------------------------------------------- | --------------------- |
| **1**   | Over HTTP it's compatible InfluxDB Line Protocol (ILP)  | All QuestDB versions  |
| **2**   | 64-bit floats sent as binary, adds n-dimentional arrays | 9.0.0+ (2023-10-30)   |

**Note**: QuestDB server version 9.0.0 or later is required for `protocol_version=2` support.

## Quick Start

To start using `questdb-rs`, add it as a dependency of your project:

```bash
cargo add questdb-rs
```

Then you can try out this quick example, which connects to a QuestDB server
running on your local machine:

```rust ignore
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

       // Array ingestion (QuestDB 9.0.0+). Slices and ndarray supported through trait
       .column_arr("price_history", &[2615.54f64, 2615.10, 2614.80])?
       .column_arr("volatility", &ndarray::arr1(&[0.012f64, 0.011, 0.013]).view())?
       .at(TimestampNanos::now())?;
   sender.flush(&mut buffer)?;
   Ok(())
}
```

## Docs

Most of the client documentation is on the
[`ingress`](https://docs.rs/questdb-rs/6.1.0/questdb/ingress/) module page.

## Examples

A selection of usage examples is available in the [examples directory](https://github.com/questdb/c-questdb-client/tree/6.1.0/questdb-rs/examples):

| Example | Description |
|---------|-------------|
| [`basic.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/basic.rs) | Minimal TCP ingestion example; shows basic row and array ingestion. |
| [`auth.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/auth.rs) | Adds authentication (user/password, token) to basic ingestion. |
| [`auth_tls.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/auth_tls.rs) | Like `auth.rs`, but uses TLS for encrypted TCP connections. |
| [`from_conf.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/from_conf.rs) | Configures client via connection string instead of builder pattern. |
| [`from_env.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/from_env.rs) | Reads config from `QDB_CLIENT_CONF` environment variable. |
| [`http.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/http.rs) | Uses HTTP transport and demonstrates array ingestion with `ndarray`. |
| [`protocol_version.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/protocol_version.rs) | Shows protocol version selection and feature differences (e.g. arrays). |

## Crate features

The crate provides several optional features to enable additional functionality. You can enable features using Cargo's `--features` flag or in your `Cargo.toml`.

### Default features
- **sync-sender**: Enables both `sync-sender-tcp` and `sync-sender-http`.
- **sync-sender-tcp**: Enables ILP/TCP (legacy). Depends on the `socket2` crate.
- **sync-sender-http**: Enables ILP/HTTP support. Depends on the `ureq` crate.
- **tls-webpki-certs**: Uses a snapshot of the [Common CA Database](https://www.ccadb.org/) as root TLS certificates. Depends on the `webpki-roots` crate.
- **ring-crypto**: Uses the `ring` crate as the cryptography backend for TLS (default crypto backend).

### Optional features

- **chrono_timestamp**: Allows specifying timestamps as `chrono::DateTime` objects. Depends on the `chrono` crate.
- **tls-native-certs**: Uses OS-provided root TLS certificates for secure connections. Depends on the `rustls-native-certs` crate.
- **insecure-skip-verify**: Allows skipping verification of insecure certificates (not recommended for production).
- **ndarray**: Enables integration with the `ndarray` crate for working with n-dimensional arrays. Without this feature, you can still send slices or implement custom array types via the `NdArrayView` trait.
- **aws-lc-crypto**: Uses `aws-lc-rs` as the cryptography backend for TLS. Mutually exclusive with the `ring-crypto` feature.

- **almost-all-features**: Convenience feature for development and testing. Enables most features except mutually exclusive crypto backends.

> See the `Cargo.toml` for the full list and details on feature interactions.

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
