# c-questdb-client
**QuestDB - Client Library for Rust, C and C++**

This library makes it easy to insert data into [QuestDB](https://questdb.io/).

This client library implements the [InfluxDB Line Protocol](
https://questdb.io/docs/reference/api/ilp/overview/) (ILP) over TCP.

* Implementation is in Rust, with no additional
  [run-time or link-time dependencies](doc/BUILD.md#pre-requisites-and-dependencies)
  on the C++ standard library or other libraries.
* We ship both a static and a dynamic library.
* The library exposes Rust, C11 and C++17 APIs.
* The C++ API is a header-only wrapper over the C API.
* This library also has separate Python bindings.

## Insertion Protocols Overview

Inserting data into QuestDB can be done via one of three protocols.

| Protocol | Record Insertion Reporting | Data Insertion Performance |
| -------- | -------------------------- | -------------------------- |
| [ILP](https://questdb.io/docs/reference/api/ilp/overview/)| Errors in logs; Disconnect on error | **Best** |
| [CSV Upload via HTTP](https://questdb.io/docs/reference/api/rest/#imp---import-data) | Configurable | Very Good |
| [PostgreSQL](https://questdb.io/docs/reference/api/postgres/) | Transaction-level | Good |

This library implements the **ILP protocol** and mitigates the lack of confirmation
and error reporting by validating data ahead of time before any data is sent
to the database instance.

For example, the client library will report that a supplied string isn't encoded
in UTF-8. Some issues unfortunately can't be caught by the library and require
some [care and diligence to avoid data problems](doc/CONSIDERATIONS.md).

For an overview and code examples, see the
[ILP page of the developer docs](https://questdb.io/docs/develop/insert-data/#influxdb-line-protocol).

To understand the protocol in more depth, consult the
[protocol reference docs](https://questdb.io/docs/reference/api/ilp/overview/).

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
may find us on [Slack](https://slack.questdb.io).

You can also [sign up to our mailing list](https://questdb.io/community/)
to get notified of new releases.

## License

The code is released under the [Apache License](LICENSE).
