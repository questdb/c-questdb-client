# c-questdb-client
**QuestDB - Client Library for Rust, C and C++**

This library makes it easy to insert data into [QuestDB](https://questdb.io/),
and to query it back out.

Its centrepiece is the **QuestDB Wire Protocol (QWP)** over WebSocket:
QuestDB's native binary columnar protocol, covering both directions. All
QWP traffic goes through a thread-safe connection pool (`QuestDb` in Rust,
`questdb_db` in C/C++) with per-flush acknowledgements and automatic
reconnect/failover across multiple endpoints. Data is written as rows,
columns, Apache Arrow record batches or Polars DataFrames (Rust), and SQL
result sets stream back over the same pool as columnar batches, Arrow
record batches or Polars DataFrames.

The library also implements QuestDB's variant of the
[InfluxDB Line Protocol](https://questdb.io/docs/reference/api/ilp/overview/)
(ILP) over HTTP and TCP, and QWP over UDP, for ingestion.

When connecting to QuestDB over HTTP, the library will auto-detect the server's
latest supported version and use it. Version 1 is compatible with
the [InfluxDB Database](https://docs.influxdata.com/influxdb/v2/reference/syntax/line-protocol/).

* Implementation is in Rust, with no additional
  [run-time or link-time dependencies](doc/BUILD.md#pre-requisites-and-dependencies)
  on the C++ standard library or other libraries.
* We ship both a static and a dynamic library.
* The library exposes Rust, C11 and C++17 APIs.
* The C++ API is a header-only wrapper over the C API.
* This library also has separate Python bindings.

## Insertion Protocols Overview

Inserting data into QuestDB can be done in several ways.

This library supports four ingestion transports:

* **QWP/WebSocket** (recommended, QuestDB 9.4.3+): QuestDB's native binary
  columnar protocol with per-flush acknowledgements, authentication and TLS.
  Ingests rows, columns, Arrow record batches and Polars DataFrames through
  the thread-safe connection pool (`QuestDb` / `questdb_db`) with automatic
  reconnect/failover. The only transport that also runs queries.
* **ILP/HTTP**: request-response, server errors returned to the client,
  supports authentication and TLS.
* **ILP/TCP**: streaming, legacy; errors cause disconnect and surface only in
  server logs.
* **QWP/UDP**: best-effort datagram transport for high-throughput ingestion on
  trusted networks; no acknowledgements, no authentication, no TLS.

| Protocol | Record Insertion Reporting | Data Insertion Performance |
| -------- | -------------------------- | -------------------------- |
| **QWP/WebSocket** | Per-flush acknowledgements (configurable ack level) | **Best** (binary columnar) |
| [ILP/HTTP](https://questdb.io/docs/reference/api/ilp/overview/) | Transaction-level (on flush) | **Excellent** |
| [ILP/TCP](https://questdb.io/docs/reference/api/ilp/overview/) | Errors in logs; Disconnect on error | **Best** (tolerates higher-latency networks) |
| QWP/UDP | None (best-effort, unacknowledged) | **Best** (lowest overhead; datagrams may be dropped) |
| [CSV Upload via HTTP](https://questdb.io/docs/reference/api/rest/#imp---import-data) | Configurable | Very Good |
| [PostgreSQL](https://questdb.io/docs/reference/api/postgres/) | Transaction-level | Good |

Server errors are reported back to the client for ILP/HTTP and QWP/WebSocket.
ILP/TCP surfaces errors via server-side disconnect; QWP/UDP has no
error-reporting path at all. See the [flush troubleshooting](doc/CONSIDERATIONS.md)
docs for more details on how to debug ILP/TCP and QWP/UDP.

For an overview and code examples, see the
[Ingestion overview page of the developer docs](https://questdb.io/docs/ingestion-overview/). 

To understand the protocol in more depth, consult the
[protocol reference docs](https://questdb.io/docs/reference/api/ilp/overview/).

## The QWP Connection Pool: Writing and Querying

One pool handle covers both directions (QuestDB 9.4.3+). In Rust:

```rust ignore
let db = QuestDb::connect("ws::addr=localhost:9000;")?;

// Write: one call streams the whole DataFrame and waits for the ack.
db.flush_polars_dataframe("trades", &df, &PolarsIngestOptions::new())?;

// Read: borrow a reader from the same pool, run SQL, stream the result.
let back = db
    .borrow_reader()?
    .execute("SELECT * FROM trades WHERE amount > 0.001")?
    .fetch_all_polars()?;
```

Alongside `flush_polars_dataframe` and `flush_arrow_batch`, the pool hands
out `borrow_column_sender()` (columnar streaming), `borrow_row_sender()`
(row-by-row `Buffer` API) and `borrow_reader()` (SQL queries); handles
return to the pool on drop. A standalone `Reader::from_conf` covers the
query side without a pool, yielding native columnar batches, Arrow
`RecordBatch`es or Polars `DataFrame`s.

The C and C++ APIs expose the pool via
[`questdb/ingress/column_sender.h`](include/questdb/ingress/column_sender.h)
(`questdb_db_connect`, `questdb_db_borrow_*`) and the reader via
[`questdb/egress/reader.h`](include/questdb/egress/reader.h) /
[`questdb/egress/reader.hpp`](include/questdb/egress/reader.hpp), handing
data across the Arrow C Data Interface. In Rust, QWP ingestion is gated
behind the `sync-sender-qwp-ws` feature and queries behind
`sync-reader-qwp-ws`; Arrow and Polars conversions behind the `arrow` and
`polars` features.

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

| Version | Description                                                  | Server Compatibility  |
| ------- | ------------------------------------------------------------ | --------------------- |
| **1**   | Over HTTP it's compatible with InfluxDB Line Protocol (ILP)  | All QuestDB versions  |
| **2**   | 64-bit floats sent as binary, adds n-dimensional arrays      | 9.0.0+ (2025-07-11)   |

## Getting Started

To get started, read the language-specific guides.

**C**
* [Getting started with C](doc/C.md)
* [`.h` header file](include/questdb/ingress/line_sender.h) (ingestion)
* [`.h` header file](include/questdb/egress/reader.h) (queries)

**C++**
* [Getting started with C++](doc/CPP.md)
* [`.hpp` header file](include/questdb/ingress/line_sender.hpp) (ingestion)
* [`.hpp` header file](include/questdb/egress/reader.hpp) (queries)

**Rust**
* [Getting started with Rust](questdb-rs/README.md)
* [`questdb-rs` crate on crates.io](https://crates.io/crates/questdb-rs)
* [API docs on docs.rs](https://docs.rs/questdb-rs/latest/)
* [`questdb-rs` source code](questdb-rs)
* [`questdb-rs-ffi` source code](questdb-rs-ffi) - C bindings code

**Python**
* [Python GitHub Repo](https://github.com/questdb/py-questdb-client/)
* [`questdb` package on PyPI](https://pypi.org/project/questdb/)
* [Documentation](https://py-questdb-client.readthedocs.io/en/latest/)

## Further Topics

* [Data quality and threading considerations](doc/CONSIDERATIONS.md)
* [Authentication and TLS encryption](doc/SECURITY.md)

## Community

If you need help, have additional questions or want to provide feedback, you
may find us on our [Community Forum](https://community.questdb.io/).

You can also [sign up to our mailing list](https://questdb.io/contributors/)
to get notified of new releases.

## License

The code is released under the [Apache License](LICENSE).
