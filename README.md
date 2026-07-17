# c-questdb-client
**QuestDB - Client Library for Rust, C and C++**

This library inserts data into [QuestDB](https://questdb.io/) and queries it
back out.

The primary protocol is the **QuestDB Wire Protocol (QWP)** over WebSocket,
QuestDB's native binary columnar format, used for both ingestion and queries.
QWP traffic runs over a thread-safe connection pool (`QuestDb` in Rust,
`questdb_db` in C/C++) with per-flush acknowledgements and automatic reconnect.
Multi-endpoint failover requires QuestDB Enterprise. You send rows, columns,
Apache Arrow record batches or Polars DataFrames (Rust); SQL results stream
back over the same pool in the same formats. QWP over WebSocket requires
QuestDB 10.0 or newer.

QWP also has a best-effort **UDP** transport for low-latency ingestion on
trusted networks (batching is MTU-bounded).

* Written in Rust, with no additional
  [run-time or link-time dependencies](doc/BUILD.md#pre-requisites-and-dependencies)
  on the C++ standard library or other libraries.
* Ships as a static and a dynamic library.
* Exposes Rust, C11 and C++17 APIs; the C++ API is a header-only wrapper over
  the C API.
* Python bindings are available separately.

## Compatibility

The Rust and native clients require Rust 1.91.1 to build. The C and C++
surfaces target C11 and C++17, with CMake 3.15 or newer. See the
[compatibility matrix](doc/COMPATIBILITY.md) for server, toolchain, platform,
Arrow, and Polars support.

## Inserting Data

QWP/WebSocket is the main path, covered below. For cross-language code
and production configuration, see the
[client documentation](https://questdb.com/docs/ingestion/overview/).
QuestDB also accepts
[CSV uploads](https://questdb.io/docs/reference/api/rest/#imp---import-data)
and [PostgreSQL-wire](https://questdb.io/docs/reference/api/postgres/) inserts.

<details>
<summary>Legacy ILP transports (InfluxDB compatibility)</summary>

For InfluxDB-compatible ingestion the library still supports the legacy **ILP**
transports: **ILP/HTTP** (request-response; server errors returned to the
client; auth and TLS) and **ILP/TCP** (streaming; errors cause disconnect and
surface only in server logs). Over HTTP the protocol version is auto-detected;
over TCP it defaults to version 1 (InfluxDB-compatible) and can be raised with
`protocol_version=N`.

See the [flush troubleshooting](doc/CONSIDERATIONS.md) docs for debugging
ILP/TCP disconnects, and the
[ILP protocol reference](https://questdb.io/docs/reference/api/ilp/overview/)
for the wire format.

</details>

## Writing and Querying

One pool handle covers both directions. In Rust:

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

Besides `flush_polars_dataframe` and `flush_arrow_batch`, the pool hands out
`borrow_sender()` for both row-built `Buffer` payloads and columnar `Chunk` /
Arrow payloads, plus `borrow_reader()` for SQL queries. Handles return to the
pool on drop. `Reader::from_conf` runs queries without a pool, yielding native
columnar batches, Arrow `RecordBatch`es or Polars `DataFrame`s.

The C and C++ APIs expose the pool via
[`questdb/ingress/column_sender.h`](include/questdb/ingress/column_sender.h)
(`questdb_db_connect`, `questdb_db_borrow_*`) and the reader via
[`questdb/egress/reader.h`](include/questdb/egress/reader.h) /
[`questdb/egress/reader.hpp`](include/questdb/egress/reader.hpp), handing
data across the Arrow C Data Interface. In Rust, QWP ingestion
(`sync-sender-qwp-ws`) and queries (`sync-reader-qwp-ws`) are both on by
default; Arrow and Polars conversions sit behind the `arrow` and `polars`
features.

## Getting Started

Read the language-specific guides:

**C**
* [Getting started with C](doc/C.md)
* [Shared-pool ingestion and query example](examples/qwp_ws_chunk_and_query_c_example.c)
* [`.h` header file](include/questdb/ingress/column_sender.h) (ingestion)
* [`.h` header file](include/questdb/egress/reader.h) (queries)

**C++**
* [Getting started with C++](doc/CPP.md)
* [Shared-pool ingestion and query example](examples/qwp_ws_chunk_and_query_cpp_example.cpp)
* [`.hpp` header file](include/questdb/ingress/column_sender.hpp) (ingestion)
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

* [Documentation index](doc/README.md)
* [Data quality and threading considerations](doc/CONSIDERATIONS.md)
* [Authentication and TLS encryption](doc/SECURITY.md)
* [QWP ingress and egress soak harness](doc/QWP_SOAK_HARNESS.md)

## Community

Questions or feedback? Reach us on the
[Community Forum](https://community.questdb.io/). To hear about new releases,
[sign up to the mailing list](https://questdb.io/contributors/).

## License

The code is released under the [Apache License](LICENSE).
