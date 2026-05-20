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

* [QuestDB Database docs](https://questdb.com/docs/)
* [`ingress` module docs](https://docs.rs/questdb-rs/6.1.0/questdb/ingress/) —
  protocol details, configuration parameters, and patterns.

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

## Protocol Versions

QWP/WebSocket negotiates its protocol version during the WebSocket upgrade;
the client requires no `protocol_version` configuration. Arrays
(`column_arr`) and decimals (`column_dec`) work natively over QWP.

The ILP transports use a separate, ILP-specific protocol-version mechanism
that gates array and decimal ingestion. Over ILP/HTTP, `protocol_version`
defaults to `auto` (server-negotiated). Over ILP/TCP, the default is `1`
and you must set `protocol_version=2` (arrays) or `=3` (decimals)
explicitly in the configuration string.

| Version | Description                                                | Server Compatibility |
| ------- | ---------------------------------------------------------- | -------------------- |
| **1**   | Compatible InfluxDB Line Protocol over ILP transports      | All QuestDB versions |
| **2**   | 64-bit floats as binary, n-dimensional arrays              | 9.0.0+               |
| **3**   | Adds DECIMAL64/DECIMAL128/DECIMAL256                       | 9.2.0+               |

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

A selection of usage examples is available in the
[examples directory](https://github.com/questdb/c-questdb-client/tree/6.1.0/questdb-rs/examples):

| Example | Description |
|---------|-------------|
| [`basic.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/basic.rs) | Minimal ILP/TCP ingestion (legacy transport). |
| [`auth.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/auth.rs) | ILP/TCP with ECDSA authentication. |
| [`auth_tls.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/auth_tls.rs) | ILP/TCP with TLS plus ECDSA auth. |
| [`http.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/http.rs) | ILP/HTTP transport with array ingestion. |
| [`from_conf.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/from_conf.rs) | Configures a sender from a connection string. |
| [`from_env.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/from_env.rs) | Reads configuration from `QDB_CLIENT_CONF`. |
| [`protocol_version.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/protocol_version.rs) | ILP protocol-version selection. |
| [`qwp_ws_unified_sfa_bench.rs`](https://github.com/questdb/c-questdb-client/blob/6.1.0/questdb-rs/examples/qwp_ws_unified_sfa_bench.rs) | QWP/WebSocket throughput benchmark with store-and-forward. |

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
