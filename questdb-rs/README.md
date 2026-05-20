# QuestDB Client Library for Rust

Official Rust client for [QuestDB](https://questdb.io/), an open-source SQL
database designed to process time-series data, faster.

The client library is designed for fast ingestion of data into QuestDB. The
recommended transport is the
**QuestDB Wire Protocol over WebSocket (QWP/WebSocket)**: a columnar binary
protocol with explicit asynchronous server acknowledgements, multi-host
failover, optional on-disk durability, and a structured error model.

Legacy InfluxDB Line Protocol (ILP) transports — over HTTP or TCP — remain
supported for backwards compatibility but are not recommended for new code.

* [Rust client documentation](https://questdb.com/docs/connect/clients/rust/) —
  the full guide on the QuestDB documentation site.
* [`ingress` module docs](https://docs.rs/questdb-rs/6.1.0/questdb/ingress/) —
  this crate's API reference: protocol details, configuration parameters,
  and patterns.
* [QuestDB Database docs](https://questdb.com/docs/) — the wider
  documentation site (SQL reference, deployment, operations).

## Transports

The transport is selected by the scheme in the configuration string:

* `ws::addr=...` / `wss::addr=...` — **QWP/WebSocket**, the recommended
  transport. Columnar binary frames, asynchronous server ACKs with explicit
  frame-sequence-number watermarks, multi-host failover, optional
  store-and-forward durability. Supports HTTP basic and bearer-token auth,
  plus TLS via `wss::`. The long-form aliases `qwpws::` / `qwpwss::` are
  also accepted.
* `http::addr=...` / `https::addr=...` — **ILP/HTTP** (legacy).
  Request-response with error returns and per-request retry, no
  asynchronous ACKs or multi-host failover. Suitable for existing
  deployments and one-shot batches.
* `tcp::addr=...` / `tcps::addr=...` — **ILP/TCP** (legacy). Streaming with
  no error reporting to the client; the server logs failures and silently
  disconnects. Lowest overhead, lowest observability.

See the [`ingress` module docs](https://docs.rs/questdb-rs/6.1.0/questdb/ingress/)
for the full configuration-parameter reference, including the
QWP-specific keys (`sf_dir`, `sender_id`, `reconnect_*`,
`request_durable_ack`, `qwp_ws_progress`, `max_in_flight`).

## Quick Start

Add `questdb-rs` to your project:

```bash
cargo add questdb-rs
```

A minimal ingest using QWP/WebSocket:

```rust ignore
use questdb::{
    Result,
    ingress::{Sender, TimestampNanos}};

fn main() -> Result<()> {
    let mut sender = Sender::from_conf("ws::addr=localhost:9000;")?;
    let mut buffer = sender.new_buffer();
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .symbol("side", "sell")?
        .column_f64("price", 2615.54)?
        .column_f64("amount", 0.00044)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    sender.close_drain()?;
    Ok(())
}
```

`flush` returns once the frame has been appended to the local publication
log. `close_drain` waits for already-published frames to be acknowledged
by the server (bounded by `close_flush_timeout_millis`, default 5s) before
the sender is dropped.

## Docs

This crate's API reference is on the
[`ingress`](https://docs.rs/questdb-rs/6.1.0/questdb/ingress/) module
page: configuration keys, the QWP error model, FSN-based completion,
progress modes, multi-host failover, store-and-forward, authentication,
TLS, the `Buffer` API, and the legacy ILP transports.

For the full Rust client guide — failover, store-and-forward operations,
migration from ILP, worked examples — see the
[Rust client documentation](https://questdb.com/docs/connect/clients/rust/)
on the QuestDB documentation site.

## Examples

QWP/WebSocket examples in the
[examples directory](https://github.com/questdb/c-questdb-client/tree/6.1.0/questdb-rs/examples):

| Example | Description |
|---------|-------------|
| [`qwp_ws_basic.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/qwp_ws_basic.rs) | Minimal QWP/WebSocket ingestion: build a sender, flush a row, `close_drain`. |
| [`qwp_ws_failover.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/qwp_ws_failover.rs) | Multi-host `addr=` list with on-disk store-and-forward and `sender_id`. |
| [`qwp_ws_error_handling.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/qwp_ws_error_handling.rs) | Server-error handling via `poll_qwp_ws_error` and via the `qwp_ws_error_handler` callback. |
| [`qwp_ws_unified_sfa_bench.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/qwp_ws_unified_sfa_bench.rs) | Throughput benchmark with store-and-forward. |

Build and run any of these with, for example:

```sh
cargo run --example qwp_ws_basic --features sync-sender-qwp-ws
```

## Crate features

The crate provides optional features. Enable them via Cargo's
`--features` flag or in your `Cargo.toml`.

### Default features

* **sync-sender** — umbrella for the synchronous sender transports.
* **sync-sender-qwp-ws** — QWP over WebSocket. Recommended transport.
* **sync-sender-http** — ILP over HTTP (legacy).
* **sync-sender-tcp** — ILP over TCP (legacy).
* **tls-webpki-certs** — bundled TLS roots from the
  [Common CA Database](https://www.ccadb.org/) via
  [`webpki-roots`](https://crates.io/crates/webpki-roots).
* **ring-crypto** — default TLS crypto backend, via the `ring` crate.

### Optional features

* **chrono_timestamp** — accept timestamps as `chrono::DateTime`.
* **tls-native-certs** — OS-provided root TLS certificates via
  `rustls-native-certs`.
* **insecure-skip-verify** — disable TLS verification (test-only,
  not for production).
* **ndarray** — integrate with the `ndarray` crate for N-dimensional
  arrays. Without this feature, slices and custom types via the
  `NdArrayView` trait still work.
* **aws-lc-crypto** — alternative TLS backend via `aws-lc-rs`. Mutually
  exclusive with `ring-crypto`.
* **almost-all-features** — dev/test convenience: enables most features
  except mutually exclusive crypto backends.

> See `Cargo.toml` for the full list and feature interactions.

## C, C++ and Python APIs

This crate is also exposed as a C and C++ API and in turn exposed to
Python.

* [c-questdb-client](https://github.com/questdb/c-questdb-client) — the C
  and C++ API.
* [py-questdb-client](https://github.com/questdb/py-questdb-client) —
  Python bindings.

## Community

If you need help, have questions, or want to provide feedback,
[join us on Slack](https://slack.questdb.io/). You can also sign up to
the [mailing list](https://questdb.io/community/) to get notified of new
releases.
