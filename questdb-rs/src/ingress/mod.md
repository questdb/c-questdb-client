# Fast Ingestion of Data into QuestDB

The `ingress` module implements QuestDB's variant of the
[InfluxDB Line Protocol](https://questdb.io/docs/reference/api/ilp/overview/)
(ILP).

To get started:

* Use [`Sender::from_conf()`] to get the [`Sender`] object
* Populate a [`Buffer`] with one or more rows of data
* Send the buffer using [`sender.flush()`](Sender::flush)

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

# Configuration String

The easiest way to configure all the available parameters on a line sender is
the configuration string. The general structure is:

```plain
<transport>::addr=host:port;param1=val1;param2=val2;...
```

`transport` can be `http`, `https`, `tcp`, or `tcps`. See the full details on
supported parameters in a dedicated section below.

# Don't Forget to Flush

The sender and buffer objects are entirely decoupled. This means that the sender
won't get access to the data in the buffer until you explicitly call
[`sender.flush(&mut buffer)`](Sender::flush) or a variant. This may lead to a
pitfall where you drop a buffer that still has some data in it, resulting in
permanent data loss.

A common technique is to flush periodically on a timer and/or once the buffer
exceeds a certain size. You can check the buffer's size by the calling
[`buffer.len()`](Buffer::len).

The default `flush()` method clears the buffer after sending its data. If you
want to preserve its contents (for example, to send the same data to multiple
QuestDB instances), call
[`sender.flush_and_keep(&mut buffer)`](Sender::flush_and_keep) instead.

# Error Handling

The two supported transport modes, HTTP and TCP, handle errors very differently.
In a nutshell, HTTP is much better at error handling.

## TCP

TCP doesn't report errors at all to the sender; instead, the server quietly
disconnects and you'll have to inspect the server logs to get more information
on the reason. When this has happened, the sender transitions into an error
state, and it is permanently unusable. You must drop it and create a new sender.
You can inspect the sender's error state by calling
[`sender.must_close()`](Sender::must_close).

## HTTP

HTTP distinguishes between recoverable and non-recoverable errors. For
recoverable ones, it enters a retry loop with exponential backoff, and reports
the error to the caller only after it has exhausted the retry time budget
(configuration parameter: `retry_timeout`).

`sender.flush()` and variant methods communicate the error in the `Result`
return value. The category of the error is signalled through the
[`ErrorCode`](crate::error::ErrorCode) enum, and it's accompanied with an error
message.

After the sender has signalled an error, it remains usable. You can handle the
error as appropriate and continue using it.

# Health Check

The QuestDB server has a "ping" endpoint you can access to see if it's alive,
and confirm the version of the InfluxDB that it is compatible with at a protocol
level.

```shell
curl -I http://localhost:9000/ping
```

Example of the expected response:

```plain
HTTP/1.1 204 OK
Server: questDB/1.0
Date: Fri, 2 Feb 2024 17:09:38 GMT
Transfer-Encoding: chunked
Content-Type: text/plain; charset=utf-8
X-Influxdb-Version: v2.7.4
```

# Configuration Parameters

In the examples below, we'll use configuration strings. We also provide the
[`SenderBuilder`] to programmatically configure the sender. The methods on
[`SenderBuilder`] match one-for-one with the keys in the configuration string.

## Authentication

To establish an
[authenticated](https://questdb.io/docs/reference/api/ilp/overview/#authentication)
and TLS-encrypted connection, use the `https` or `tcps` protocol, and use the
configuration options appropriate for the authentication method.

Here are quick examples of configuration strings for each authentication method
we support:

### HTTP Token Bearer Authentication

```no_run
# use questdb::{Result, ingress::Sender};
# fn main() -> Result<()> {
let mut sender = Sender::from_conf(
    "https::addr=localhost:9000;token=Yfym3fgMv0B9;"
)?;
# Ok(())
# }
```

* `token`: the authentication token

### HTTP Basic Authentication

```no_run
# use questdb::{Result, ingress::Sender};
# fn main() -> Result<()> {
let mut sender = Sender::from_conf(
    "https::addr=localhost:9000;username=testUser1;password=Yfym3fgMv0B9;"
)?;
# Ok(())
# }
```

* `username`: the username
* `password`: the password

### TCP Elliptic Curve Digital Signature Algorithm (ECDSA)

```no_run
# use questdb::{Result, ingress::Sender};
# fn main() -> Result<()> {
let mut sender = Sender::from_conf(
    "tcps::addr=localhost:9009;username=testUser1;token=5UjEA0;token_x=fLKYa9;token_y=bS1dEfy;"
)?;
# Ok(())
# }
```

The four ECDSA components are:

* `username`, aka. _kid_
* `token`, aka. _d_
* `token_x`, aka. _x_
* `token_y`, aka. _y_

### Authentication Timeout

You can specify how long the client should wait for the authentication request
to resolve. The configuration parameter is:

* `auth_timeout` (milliseconds, default 15 seconds)

## Encryption on the Wire: TLS

To enable TLS on the QuestDB Enterprise server, refer to the [QuestDB Enterprise
TLS documentation](https://questdb.io/docs/operations/tls/).

*Note*: QuestDB Open Source does not support TLS natively. To use TLS with
QuestDB Open Source, use a TLS proxy such as
[HAProxy](http://www.haproxy.org/).

We support several certification authorities (sources of PKI root certificates).
To select one, use the `tls_ca` config option. These are the supported variants:

* `tls_ca=webpki_roots;` use the roots provided in the standard Rust crate
  [webpki-roots](https://crates.io/crates/webpki-roots)

* `tls_ca=os_roots;` use the OS-provided certificate store

* `tls_ca=webpki_and_os_roots;` combine both of the above

* `tls_roots=/path/to/root-ca.pem;` get the root certificates from the specified
  file. Main purpose is for testing with self-signed certificates. _Note:_ this
  automatically sets `tls_ca=pem_file`.

See our notes on [how to generate a self-signed
certificate](https://github.com/questdb/c-questdb-client/tree/main/tls_certs).

* `tls_verify=unsafe_off;` tells the QuestDB client to ignore all CA roots and
  accept any server certificate without checking. You can use it as a last
  resort, when you weren't able to apply the above approach with a self-signed
  certificate. You should **never use it in production** as it defeats security
  and allows a man-in-the middle attack.

## HTTP Timeouts

Instead of a fixed timeout value, we use a flexible timeout that depends on the
size of the HTTP request payload (how much data is in the buffer that you're
flushing). You can configure it using two options:

* `request_min_throughput` (bytes per second, default 100 KiB/s): divide the
  payload size by this number to determine for how long to keep sending the
  payload before timing out.
* `request_timeout` (milliseconds, default 10 seconds): additional time
  allowance to account for the fixed latency of the request-response roundtrip.

Finally, the client will keep retrying the request if it experiences errors. You
can configure the total time budget for retrying:

* `retry_timeout` (milliseconds, default 10 seconds)

# Usage Considerations

## Transactional Flush

When using HTTP, you can arrange that each `flush()` call happens within its own
transaction. For this to work, your buffer must contain data that targets only
one table. This is because QuestDB doesn't support multi-table transactions.

In order to ensure in advance that a flush will be transactional, call
[`sender.flush_and_keep_with_flags(&mut buffer, true)`](Sender::flush_and_keep_with_flags).
This call will refuse to flush a buffer if the flush wouldn't be transactional.

## When to Choose the TCP Transport?

As discussed above, the TCP transport mode is raw and simplistic: it doesn't
report any errors to the caller (the server just disconnects), has no automatic
retries, requires manual handling of connection failures, and doesn't support
transactional flushing.

However, TCP has a lower overhead than HTTP and it's worthwhile to try out as an
alternative in a scenario where you have a constantly high data rate and/or deal
with a high-latency network connection.

## Array Datatype

The [`Buffer::column_arr`](Buffer::column_arr) method supports efficient ingestion of N-dimensional
arrays using several convenient types:

- native Rust arrays and slices (up to 3-dimensional)
- native Rust vectors (up to 3-dimensional)
- arrays from the [`ndarray`](https://docs.rs/ndarray) crate

You must use protocol version 2 to ingest arrays. HTTP transport will
automatically enable it as long as you're connecting to an up-to-date QuestDB
server (version 9.0.0 or later), but with TCP you must explicitly specify it in
the configuration string: `protocol_version=2;`.

**Note**: QuestDB server version 9.0.0 or later is required for array support.

## Timestamp Column Name

The InfluxDB Line Protocol (ILP) does not give a name to the designated timestamp,
so if you let this client auto-create the table, it will have the default `timestamp` name.
To use a custom name, say `my_ts`, pre-create the table with the desired
timestamp column name:

To address this, issue a `CREATE TABLE` statement to create the table in advance.
Note the `timestamp(my_ts)` clause at the end specifies the designated timestamp.

```sql
CREATE TABLE IF NOT EXISTS 'trades' (
  symbol SYMBOL capacity 256 CACHE,
  side SYMBOL capacity 256 CACHE,
  price DOUBLE,
  amount DOUBLE,
  my_ts TIMESTAMP
) timestamp (my_ts) PARTITION BY DAY WAL;
```

You can use the `CREATE TABLE IF NOT EXISTS` construct to make sure the table is
created, but without raising an error if the table already exists.

## Sequential Coupling in the Buffer API

The fluent API of [`Buffer`] has sequential coupling: there's a certain order in
which you are expected to call the methods. For example, you must write the
symbols before the columns, and you must terminate each row by calling either
[`at`](Buffer::at) or [`at_now`](Buffer::at_now). Refer to the [`Buffer`] doc
for the full rules and a flowchart.

## Optimization: Avoid Revalidating Names

The client validates every name you provide. To avoid the redundant CPU work of
re-validating the same names on every row, create pre-validated [`ColumnName`]
and [`TableName`] values:

```no_run
# use questdb::Result;
use questdb::ingress::{
    TableName,
    ColumnName,
    Buffer,
    SenderBuilder,
    TimestampNanos};
# fn main() -> Result<()> {
let mut sender = SenderBuilder::from_conf("https::addr=localhost:9000;")?.build()?;
let mut buffer = sender.new_buffer();
let table_name = TableName::new("trades")?;
let price_name = ColumnName::new("price")?;
buffer.table(table_name)?.column_f64(price_name, 2615.54)?.at(TimestampNanos::now())?;
buffer.table(table_name)?.column_f64(price_name, 39269.98)?.at(TimestampNanos::now())?;
# Ok(())
# }
```

## Check out the CONSIDERATIONS Document

The [Library
considerations](https://github.com/questdb/c-questdb-client/blob/main/doc/CONSIDERATIONS.md)
document covers these topics:

* Threading
* Differences between the InfluxDB Line Protocol and QuestDB Data Types
* Data Quality
* Client-side checks and server errors
* Flushing
* Disconnections, data errors and troubleshooting

# Troubleshooting Common Issues

## Infrequent Flushing

If the data doesn't appear in the database in a timely manner, you may not be
calling [`flush()`](Sender::flush) often enough.

## Debug disconnects and inspect errors

If you're using ILP-over-TCP, it doesn't report any errors to the client.
Instead, on error, the server terminates the connection, and logs any error
messages in [server logs](https://questdb.io/docs/troubleshooting/log/).

To inspect or log a buffer's contents before you send it, call
[`buffer.as_bytes()`](Buffer::as_bytes).
