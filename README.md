# c-questdb-client
**QuestDB - Client Library for Rust, C and C++**

This library makes it easy to insert data into [QuestDB](https://questdb.io/).

This client library implements the QuestDB's variant of the [InfluxDB Line Protocol](
https://questdb.io/docs/reference/api/ilp/overview/) (ILP) over HTTP and TCP.

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

This library supports ILP/HTTP (default-recommended) and ILP/TCP (specific
streaming use cases).

| Protocol | Record Insertion Reporting | Data Insertion Performance |
| -------- | -------------------------- | -------------------------- |
| **[ILP/HTTP](https://questdb.io/docs/reference/api/ilp/overview/)** | Transaction-level (on flush) | **Excellent** |
| [ILP/TCP](https://questdb.io/docs/reference/api/ilp/overview/)| Errors in logs; Disconnect on error | **Best** (tolerates higher-latency networks) |
| [CSV Upload via HTTP](https://questdb.io/docs/reference/api/rest/#imp---import-data) | Configurable | Very Good |
| [PostgreSQL](https://questdb.io/docs/reference/api/postgres/) | Transaction-level | Good |

Server errors are only reported back to the client for ILP/HTTP.
See the [flush troubleshooting](doc/CONSIDERATIONS.md) docs for more details on
how to debug ILP/TCP.

For an overview and code examples, see the
[Ingestion overview page of the developer docs](https://questdb.io/docs/ingestion-overview/). 

To understand the protocol in more depth, consult the
[protocol reference docs](https://questdb.io/docs/reference/api/ilp/overview/).

## Protocol Versions

The library supports the following ILP protocol versions.

These protocol versions are supported over both HTTP and TCP.

* If you use HTTP and `protocol_version=auto` or unset, the library will
  automatically detect the server's
  latest supported protocol version and use it (recommended).
* If you use TCP, you can specify the
  `protocol_version=N` parameter when constructing the `Sender` object
  (TCP defaults to `protocol_version=1`).

| Version | Description                                             | Server Comatibility   |
| ------- | ------------------------------------------------------- | --------------------- |
| **1**   | Over HTTP it's compatible InfluxDB Line Protocol (ILP)  | All QuestDB versions  |
| **2**   | 64-bit floats sent as binary, adds n-dimentional arrays | 8.4.0+ (2023-10-30)   |

## Getting Started

To get started, read the language-specific guides.

**C**
* [Getting started with C](doc/C.md)
* [`.h` header file](include/questdb/ingress/line_sender.h)

**C++**
* [Getting started with C++](doc/CPP.md)
* [`.hpp` header file](include/questdb/ingress/line_sender.hpp)

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
