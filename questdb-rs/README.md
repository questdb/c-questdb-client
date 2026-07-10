# QuestDB Client Library for Rust

Official Rust client for [QuestDB](https://questdb.io/), an open-source SQL
database designed to process time-series data, faster.

The client library is designed for fast ingestion of data into QuestDB, and
for querying it back out.

Its centrepiece is the **QuestDB Wire Protocol (QWP)** over WebSocket:
QuestDB's native binary columnar protocol, covering both directions. Writes
are acknowledged per flush and go through [`QuestDb`] — a thread-safe
connection pool with automatic reconnect and failover — as rows, columns,
Apache Arrow `RecordBatch`es or Polars `DataFrame`s. Queries stream SQL
result sets back over the same protocol as columnar batches, `RecordBatch`es
or `DataFrame`s.

The InfluxDB Line Protocol (ILP) over HTTP or TCP, and QWP over UDP, are
also supported for ingestion.

[`QuestDb`]: https://docs.rs/questdb-rs/latest/questdb/struct.QuestDb.html

* [QuestDB Database docs](https://questdb.io/docs/)
* [Docs on InfluxDB Line Protocol](https://questdb.io/docs/reference/api/ilp/overview/)

## Transports

The transport is selected by the scheme in the configuration string:

* `ws::addr=...` / `wss::addr=...` (also `ws::` / `wss::`) — QWP over
  WebSocket, in both directions. For ingestion (`QuestDb::connect`): binary
  columnar frames with per-flush acknowledgements, a thread-safe connection
  pool with automatic reconnect/failover, and row, column, Arrow
  `RecordBatch` and Polars `DataFrame` input. For queries
  (`Reader::from_conf` or `QuestDb::borrow_reader`): SQL execution with
  results streamed back as columnar batches. Requires QuestDB 9.4.3+.
* `http::addr=...` / `https::addr=...` — ILP request-response, errors
  returned to the client, supports authentication and TLS.
* `tcp::addr=...` / `tcps::addr=...` — ILP streaming, legacy; errors cause
  server-side disconnect and surface only in server logs.
* `qwpudp::addr=...` — best-effort UDP datagrams (IPv4-only); no
  acknowledgements, no authentication, no TLS, no transactional guarantees.
  See the [`ingress`](https://docs.rs/questdb-rs/latest/questdb/ingress/)
  module docs (in particular `Protocol::QwpUdp`) for semantics and
  configuration parameters.

## ILP Protocol Versions

The library supports the following ILP protocol versions. These apply to
ILP/HTTP and ILP/TCP only — QWP uses its own wire format and is not
versioned through this mechanism.

* If you use HTTP and `protocol_version=auto` or unset, the library will
  automatically detect the server's
  latest supported protocol version and use it (recommended).
* If you use TCP, you can specify the
  `protocol_version=N` parameter when constructing the `Sender` object
  (TCP defaults to `protocol_version=1`).

| Version | Description                                             | Server Compatibility   |
| ------- | ------------------------------------------------------- | --------------------- |
| **1**   | Over HTTP it's compatible with InfluxDB Line Protocol (ILP)  | All QuestDB versions  |
| **2**   | 64-bit floats sent as binary, adds n-dimensional arrays      | 9.0.0+ (2025-07-11)   |

**Note**: QuestDB server version 9.0.0 or later is required for `protocol_version=2` support.

## Quick Start

To start using `questdb-rs`, add it as a dependency of your project:

```bash
cargo add questdb-rs
```

### QWP: the `QuestDb` connection pool

`QuestDb` is the entry point for QWP/WebSocket (QuestDB 9.4.3+): one
thread-safe pool covering both writes and reads. A Polars round trip (with
the `polars` feature):

```rust ignore
use questdb::{QuestDb, ingress::polars::PolarsIngestOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = QuestDb::connect("ws::addr=localhost:9000;")?;

    // One call: stream the DataFrame in columnar batches, wait for the ack.
    db.flush_polars_dataframe("trades", &df, &PolarsIngestOptions::new())?;

    // Query it back over the same pool.
    let back = db
        .borrow_reader()?
        .execute("SELECT * FROM trades WHERE amount > 0.001")?
        .fetch_all_polars()?;
    println!("{back}");
    Ok(())
}
```

The pool's main handles:

* `db.flush_polars_dataframe(table, &df, &options)` — one-call `DataFrame`
  ingestion (`polars` feature).
* `db.flush_arrow_batch(table, &batch, ts_column, overrides, ack)` —
  one-call Arrow `RecordBatch` ingestion (`arrow` feature).
* `db.borrow_column_sender()` — columnar streaming: fill a `Chunk` column by
  column, `flush` it, reuse the allocation.
* `db.borrow_row_sender()` — row-by-row ingestion with the familiar
  `Buffer` API (`table(..).symbol(..).column_f64(..).at(..)`).
* `db.borrow_reader()` — run SQL and stream the result set back.

Handles return to the pool on drop; the pool reconnects and fails over
across `addr=host-a:9000,host-b:9000` endpoint lists transparently.

A standalone `Reader::from_conf("ws::addr=...")` gives the query side
without a pool (`sync-reader-qwp-ws` feature), yielding results as native
columnar batches, Arrow `RecordBatch`es (`cursor.next_arrow_batch()`) or
Polars `DataFrame`s (`cursor.fetch_all_polars()`).

### ILP over HTTP

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
[`ingress`](https://docs.rs/questdb-rs/7.0.0/questdb/ingress/) module page
for writing data, and the
[`egress`](https://docs.rs/questdb-rs/7.0.0/questdb/egress/) module page for
querying it back.

## Examples

A selection of usage examples is available in the [examples directory](https://github.com/questdb/c-questdb-client/tree/7.0.0/questdb-rs/examples):

| Example | Description |
|---------|-------------|
| [`basic.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/basic.rs) | Minimal TCP ingestion example; shows basic row and array ingestion. |
| [`auth.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/auth.rs) | Adds authentication (user/password, token) to basic ingestion. |
| [`auth_tls.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/auth_tls.rs) | Like `auth.rs`, but uses TLS for encrypted TCP connections. |
| [`from_conf.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/from_conf.rs) | Configures client via connection string instead of builder pattern. |
| [`from_env.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/from_env.rs) | Reads config from `QDB_CLIENT_CONF` environment variable. |
| [`http.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/http.rs) | Uses HTTP transport and demonstrates array ingestion with `ndarray`. |
| [`protocol_version.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/protocol_version.rs) | Shows protocol version selection and feature differences (e.g. arrays). |
| [`qwp_ws_l1_quotes.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/qwp_ws_l1_quotes.rs) | Columnar ingestion over QWP/WebSocket via the `QuestDb` connection pool. |
| [`qwp_egress_read.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/qwp_egress_read.rs) | Runs a SQL query and streams the result set over QWP/WebSocket. |
| [`polars.rs`](https://github.com/questdb/c-questdb-client/blob/7.0.0/questdb-rs/examples/polars.rs) | Round trip: ingests a Polars `DataFrame` and queries it back as one. |

## Crate features

The crate provides several optional features to enable additional functionality. You can enable features using Cargo's `--features` flag or in your `Cargo.toml`.

### Default features
- **sync-sender**: Enables `sync-sender-tcp`, `sync-sender-http` and `sync-sender-qwp-ws` (ingestion).
- **sync-reader**: Enables `sync-reader-qwp-ws` and `sync-reader-zstd` (queries). Querying is first-class, on by default.
- **sync-sender-tcp**: Enables ILP/TCP (legacy). Depends on the `socket2` crate.
- **sync-sender-http**: Enables ILP/HTTP support. Depends on the `ureq` crate.
- **sync-sender-qwp-ws**: Enables QWP/WebSocket ingestion (`QuestDb` pool, row and column senders).
- **sync-reader-qwp-ws**: Enables QWP/WebSocket queries (`Reader` / `Cursor`).
- **sync-reader-zstd**: Enables zstd decompression of query result batches.
- **tls-webpki-certs**: Uses a snapshot of the [Common CA Database](https://www.ccadb.org/) as root TLS certificates. Depends on the `webpki-roots` crate.
- **ring-crypto**: Uses the `ring` crate as the cryptography backend for TLS (default crypto backend).

### Optional features

- **arrow**: Apache Arrow integration in both directions — ingest `RecordBatch`es, read query results as `RecordBatch`es. Also available as the single-direction `arrow-ingress` / `arrow-egress` features.
- **polars**: Polars integration in both directions — ingest `DataFrame`s, read query results as `DataFrame`s. Also available as `polars-ingress` / `polars-egress`.
- **chrono-timestamp**: Allows specifying timestamps as `chrono::DateTime` objects. Depends on the `chrono` crate.
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
