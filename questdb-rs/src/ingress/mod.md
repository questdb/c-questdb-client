# Fast Ingestion of Data into QuestDB

The `ingress` module sends rows of time-series data to a QuestDB server. The
recommended transport is the
**QuestDB Wire Protocol over WebSocket (QWP/WebSocket)**: a columnar binary
protocol with asynchronous server acknowledgements, multi-host failover, and
optional on-disk durability.

Legacy InfluxDB Line Protocol (ILP) transports — over HTTP and TCP — remain
supported but are not recommended for new code; see
[Legacy ILP Transports](#legacy-ilp-transports) below.

To get started:

* Use [`Sender::from_conf()`] to build a [`Sender`].
* Populate a [`Buffer`] with one or more rows.
* Call [`sender.flush()`](Sender::flush) to publish.
* Call [`sender.close_drain()`](Sender::close_drain) before dropping the
  sender so already-published frames complete on the wire.

```rust no_run
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

# Configuration String

A sender is configured with a single string:

```plain
<transport>::addr=host:port;key1=val1;key2=val2;...
```

For QWP/WebSocket the transport is `ws` (plain) or `wss` (TLS). The
long-form aliases `qwpws` / `qwpwss` are also accepted. The default port
is `9000` for both `ws` and `wss`.

```plain
ws::addr=localhost:9000;
wss::addr=db.example.com:9000;username=admin;password=secret;
ws::addr=node-a:9000,node-b:9000;sf_dir=/var/lib/myapp/qdb-sf;sender_id=ingest-1;
```

For the full key reference (TLS, auth, failover, store-and-forward,
durable ACK, progress modes), see the
[connect-string reference](https://questdb.io/docs/connect/clients/connect-string/)
on the QuestDB documentation site. [`SenderBuilder`] exposes the same
options programmatically.

# Don't Forget to Flush

The sender and the buffer are decoupled: a buffer accumulates rows
locally and the sender does not see them until you call
[`sender.flush(&mut buffer)`](Sender::flush) (or
[`sender.flush_and_keep(&mut buffer)`](Sender::flush_and_keep) to retain
the buffer contents).

**This client does not auto-flush, regardless of transport.** The
configuration keys `auto_flush_rows`, `auto_flush_bytes`, and
`auto_flush_interval` are rejected; `auto_flush=off` is accepted as a
no-op for compatibility with older connect strings. A common pattern is
to flush periodically on a timer and/or once the buffer size
([`buffer.len()`](Buffer::len)) exceeds a threshold.

On QWP/WebSocket, `flush` returns once the frame has been appended to the
local publication log. A successful flush clears the buffer; a failed
flush retains the rows so you can retry. A typical ingest loop reuses one
sender and one buffer:

```rust no_run
# use questdb::{Result, ingress::{Sender, TimestampNanos}};
# fn main() -> Result<()> {
# let mut sender = Sender::from_conf("ws::addr=localhost:9000;")?;
# let mut buffer = sender.new_buffer();
# let running = true;
while running {
    buffer
        .table("trades")?
        .symbol("symbol", "ETH-USD")?
        .column_f64("price", 2615.54)?
        .at(TimestampNanos::now())?;
    sender.flush(&mut buffer)?;
    if buffer.len() > 64 * 1024 {
        // also flush on size if you batch multiple rows per iteration
    }
    // sleep until the next tick
#   break;
}
# Ok(()) }
```

# Error Handling on QWP/WebSocket

QWP/WebSocket is a reliable, in-order transport. Transient socket errors
and reconnects are absorbed by the driver and do not surface to the
caller. Two error surfaces are visible to user code:

1. **Synchronous errors from `flush` and related calls** — local
   failures or a terminal sender state. Returned as `Result::Err`.
2. **Asynchronous server errors** — protocol or schema errors reported
   by the server *after* `flush` has returned. Drain them with
   [`sender.poll_qwp_ws_error()`](Sender::poll_qwp_ws_error) or install a
   callback via
   [`SenderBuilder::qwp_ws_error_handler`](SenderBuilder::qwp_ws_error_handler).

```rust no_run
# use questdb::{Result, ingress::Sender};
# fn main() -> Result<()> {
# let mut sender = Sender::from_conf("ws::addr=localhost:9000;")?;
while let Some(err) = sender.poll_qwp_ws_error()? {
    eprintln!("qwp error: {:?}", err);
}
# Ok(()) }
```

Server errors are classified by
[`QwpWsErrorPolicy`]: `DropAndContinue` rejects only the affected
frame, `Halt` latches the sender into a permanently-unusable state
([`must_close()`](Sender::must_close) returns `true`). See
[`QwpWsSenderError`] for the diagnostic fields and
[`QwpWsErrorCategory`] for the categorisation. The
[QuestDB documentation site](https://questdb.io/docs/connect/clients/c-and-cpp/#asynchronous-error-handling)
has the full protocol-level error model.

# Completion Tracking, Progress Modes, Failover, Durability

These are QWP/WebSocket features whose protocol-level details live in the
QuestDB documentation; the Rust API entry points are summarised here.

* **FSN-based completion** — every published frame is assigned a frame
  sequence number. Use [`flush_and_get_fsn`](Sender::flush_and_get_fsn)
  to capture it, then
  [`await_acked_fsn`](Sender::await_acked_fsn) (or
  [`published_fsn`](Sender::published_fsn) /
  [`acked_fsn`](Sender::acked_fsn) non-blocking) to wait for server
  acknowledgement.
* **Progress modes** — `background` (default) runs a sender-owned thread
  that drives the transport; `manual` requires the caller to drive
  progress with [`drive_once`](Sender::drive_once) or any sender method
  that progresses the loop. Select via the configuration string
  (`qwp_ws_progress=manual`) or
  [`SenderBuilder::qwp_ws_progress`](SenderBuilder::qwp_ws_progress).
* **Multi-host failover** — pass a comma-separated address list
  (`addr=a:9000,b:9000`) and tune `reconnect_max_duration_millis`,
  `reconnect_initial_backoff_millis`, `reconnect_max_backoff_millis`.
  Auth failures are terminal across all endpoints; transport errors are
  retried.
* **Store-and-forward** — set `sf_dir` to a writable directory and
  `sender_id` to a stable identifier per sender process. Unacknowledged
  frames are persisted and replayed across reconnects and process
  restarts. Replay is at-least-once, so target tables should declare
  `DEDUP UPSERT KEYS(...)`.
* **Durable acknowledgement** — set `request_durable_ack=on` (QuestDB
  Enterprise with primary replication) so `acked_fsn` advances only
  after durable upload to object storage.

See [QuestDB high-availability docs](https://questdb.io/docs/high-availability/overview/)
for the full failover/SF/durable-ACK story and
[delivery semantics](https://questdb.io/docs/concepts/delivery-semantics/)
for the at-least-once/exactly-once model.

# Authentication

QWP/WebSocket authenticates at the HTTP layer during the WebSocket
upgrade. Credentials are sent once per connection and reused across
reconnects.

```rust no_run
# use questdb::{Result, ingress::Sender};
# fn main() -> Result<()> {
// Bearer token (recommended for Enterprise)
let _s = Sender::from_conf(
    "wss::addr=db.example.com:9000;token=Yfym3fgMv0B9;")?;

// HTTP basic auth
let _s = Sender::from_conf(
    "wss::addr=db.example.com:9000;username=admin;password=Yfym3fgMv0B9;")?;
# Ok(()) }
```

`auth_timeout` (milliseconds, default `15000`) bounds the handshake.
`auth_timeout_ms` is accepted as a Java-compatible spelling.

**Not supported by this client:** OIDC token acquisition / in-band
refresh, mutual TLS (client certificates), token rotation mid-session.
QuestDB itself supports OIDC server-side — see
[OpenID Connect](https://questdb.io/docs/security/oidc/); acquire a
token out-of-band from your IdP, pass it via `token=...`, and rebuild
the sender when it nears expiry. mTLS is not negotiated by the
QuestDB server regardless of client.

# TLS

Use the `wss` schema (or the alias `qwpwss`). Configuration parameters:

* `tls_ca=webpki_roots` — bundled webpki roots (default).
* `tls_ca=os_roots` — OS certificate store (requires the
  `tls-native-certs` feature).
* `tls_ca=webpki_and_os_roots` — both.
* `tls_roots=/path/to/root-ca.pem` — load roots from a PEM file.
  Implies `tls_ca=pem_file`.
* `tls_verify=unsafe_off` — disable verification entirely. Requires
  the `insecure-skip-verify` feature. **Never use in production.**

See the notes on
[how to generate a self-signed certificate](https://github.com/questdb/c-questdb-client/tree/6.1.0/tls_certs).

# Closing the Sender

For delivery-sensitive shutdown, call
[`close_drain`](Sender::close_drain) before dropping the sender:

```rust no_run
# use questdb::{Result, ingress::Sender};
# fn main() -> Result<()> {
# let mut sender = Sender::from_conf("ws::addr=localhost:9000;")?;
sender.close_drain()?;
# Ok(()) }
```

`close_drain` stops accepting new publications and waits up to
`close_flush_timeout_millis` (default `5000`) for already-published
frames to be acknowledged. With `sf_dir`, anything still un-acked is
persisted to disk so a later sender can replay it. Dropping a sender
without `close_drain` is best-effort: in-flight frames may not reach the
server, and any delivery failure is silent.

# Health Check

The QuestDB server exposes a `/ping` endpoint on the same port as
QWP/WebSocket (the HTTP listener; default `9000`):

```shell
curl -I http://localhost:9000/ping
```

# Sequential Coupling in the Buffer API

The fluent API of [`Buffer`] has sequential coupling: there's a certain
order in which you are expected to call the methods. You must write the
symbols before the columns, and you must terminate each row by calling
either [`at`](Buffer::at) or [`at_now`](Buffer::at_now). Refer to the
[`Buffer`] doc for the full rules and a flowchart.

# Optimization: Avoid Revalidating Names

The client validates every name you provide. To avoid re-validating the
same names on every row, create pre-validated [`ColumnName`] and
[`TableName`] values once:

```rust no_run
# use questdb::Result;
use questdb::ingress::{TableName, ColumnName, Sender, TimestampNanos};
# fn main() -> Result<()> {
let mut sender = Sender::from_conf("ws::addr=localhost:9000;")?;
let mut buffer = sender.new_buffer();
let table_name = TableName::new("trades")?;
let price_name = ColumnName::new("price")?;
buffer.table(table_name)?.column_f64(price_name, 2615.54)?.at(TimestampNanos::now())?;
buffer.table(table_name)?.column_f64(price_name, 39269.98)?.at(TimestampNanos::now())?;
# Ok(()) }
```

# Handling Optional Data (NULLs)

In QuestDB, `NULL` values are represented by simply omitting the column
for that specific row.

To make working with Rust's `Option<T>` ergonomic and keep the fluent
builder chain unbroken, the [`Buffer`] API provides `_opt` variants for
all column methods (e.g.
[`column_str_opt`](Buffer::column_str_opt),
[`column_f64_opt`](Buffer::column_f64_opt)).

If the provided value is `Some(v)`, the column is written normally. If
the value is `None`, the method acts as a no-op and skips the column.

**Note on ownership:** for types that implement `Copy` (like `i64`,
`f64`, `bool`), you can pass the `Option` directly. For heap-allocated
types like `String` or `Vec`, use `.as_ref()` or `.as_deref()` to pass a
reference without consuming the original value.

```rust no_run
# use questdb::Result;
use questdb::ingress::{Sender, TimestampNanos};
# fn main() -> Result<()> {
let mut sender = Sender::from_conf("ws::addr=localhost:9000;")?;
let mut buffer = sender.new_buffer();
let humidity: Option<f64> = None;
buffer
    .table("sensors")?
    .symbol("location", "factory-1")?
    .column_f64("temperature", 22.5)?
    // Silently skips the humidity column (stored as NULL).
    .column_f64_opt("humidity", humidity)?
    .at(TimestampNanos::now())?;
# Ok(()) }
```

# Array Datatype

[`Buffer::column_arr`](Buffer::column_arr) supports efficient ingestion
of N-dimensional arrays using:

* native Rust arrays and slices (up to 3-dimensional)
* native Rust vectors (up to 3-dimensional)
* arrays from the [`ndarray`](https://docs.rs/ndarray) crate

QWP/WebSocket carries array types natively in the wire format and does
not require a `protocol_version` setting. Requires QuestDB server
9.0.0 or later.

# Decimal Datatype

[`Buffer::column_dec`](Buffer::column_dec) accepts:

* native Rust string slices
* decimals from the [`rust_decimal`](https://docs.rs/rust_decimal) crate
* decimals from the [`bigdecimal`](https://docs.rs/bigdecimal) crate

QWP/WebSocket carries `DECIMAL64`, `DECIMAL128`, and `DECIMAL256`
natively and does not require a `protocol_version` setting. Requires
QuestDB server 9.2.0 or later. Pre-create decimal columns with
`DECIMAL(precision, scale)` so the server enforces the expected
precision.

# Timestamp Column Name

The QuestDB ingest protocols do not give a name to the designated
timestamp, so if you let this client auto-create the table, it will have
the default `timestamp` name. To use a custom name, issue a
`CREATE TABLE` in advance:

```sql
CREATE TABLE IF NOT EXISTS 'trades' (
  symbol SYMBOL capacity 256 CACHE,
  side SYMBOL capacity 256 CACHE,
  price DOUBLE,
  amount DOUBLE,
  my_ts TIMESTAMP
) timestamp (my_ts) PARTITION BY DAY WAL;
```

# Transactional Flush

[`flush_and_keep_with_flags`](Sender::flush_and_keep_with_flags) with
`transactional = true` refuses to flush a buffer that would span
multiple tables, ensuring QuestDB treats the flush as a single
transaction. The function is gated on the `sync-sender-http` Cargo
feature; building with QWP/WebSocket only does not expose it.

# Check out the CONSIDERATIONS Document

The
[library considerations](https://github.com/questdb/c-questdb-client/blob/6.1.0/doc/CONSIDERATIONS.md)
covers threading, data quality, server errors, flushing, and
disconnections.

# Troubleshooting

If data doesn't appear in the database in a timely manner, you may not
be calling [`flush`](Sender::flush) often enough — this client has no
auto-flush on any transport.

For QWP/WebSocket, drain
[`poll_qwp_ws_error`](Sender::poll_qwp_ws_error) (or install a callback
via
[`qwp_ws_error_handler`](SenderBuilder::qwp_ws_error_handler)) to see
structured server diagnostics. The
[server log](https://questdb.io/docs/troubleshooting/log/) carries
additional context.

To inspect the bytes of an ILP buffer before sending, call
[`buffer.as_bytes()`](Buffer::as_bytes). QWP buffers are encoded into
frames during [`flush`](Sender::flush) and `as_bytes()` is not useful
there.

# Legacy ILP Transports

> **Legacy.** The ILP transports (`http`, `https`, `tcp`, `tcps`) remain
> supported for backwards compatibility but are not recommended for new
> code. Use QWP/WebSocket
> ([top of this page](#fast-ingestion-of-data-into-questdb)) instead.

The same [`Sender`] / [`Buffer`] API works across all transports — the
difference is the configuration string and the error model.

## ILP/HTTP

Configuration: `http::` or `https::`. Request-response. Recoverable
errors are retried with exponential backoff and surface only after the
retry budget is exhausted; the sender remains usable on signalled
errors.

```rust no_run
# use questdb::{Result, ingress::{Sender, TimestampNanos}};
# fn main() -> Result<()> {
let mut sender = Sender::from_conf("http::addr=localhost:9000;")?;
# let mut buffer = sender.new_buffer();
# buffer.table("trades")?.column_f64("price", 1.0)?.at(TimestampNanos::now())?;
# sender.flush(&mut buffer)?;
# Ok(()) }
```

HTTP-specific tuning: `request_min_throughput` (bytes/sec, default
100 KiB/s), `request_timeout` (default 10 s), `retry_timeout` (default
10 s). HTTP also supports
[transactional flushes](#transactional-flush).

For arrays and decimals on HTTP, `protocol_version=auto` (the default)
negotiates the right version with the server.

## ILP/TCP

Configuration: `tcp::` or `tcps::`. Streaming. Does not report errors to
the sender — the server silently disconnects on error and the failure
appears only in the server log. The sender transitions into a terminal
state which you can detect via
[`must_close`](Sender::must_close). TCP also has lower overhead than
HTTP, which suits very high steady-state throughput on a high-latency
network, at the cost of all observability.

TCP supports ECDSA authentication:

```rust no_run
# use questdb::{Result, ingress::Sender};
# fn main() -> Result<()> {
let _s = Sender::from_conf(
    "tcps::addr=localhost:9009;username=testUser1;token=5UjEA0;token_x=fLKYa9;token_y=bS1dEfy;")?;
# Ok(()) }
```

TCP defaults to `protocol_version=1`. To send arrays or decimals over
TCP you must specify `protocol_version=2` (or `=3`) explicitly.
