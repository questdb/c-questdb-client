# Getting Started with C++

## Building and depending on this library
* To begin with, we suggest first building the library to ensure you have all
  the tooling and build dependencies set up just right by following the
  [build instructions](BUILD.md)
* Then read the guide for including this library as a
  [dependency from your project](DEPENDENCY.md).

## Complete Examples

* [Basic example in C++](../examples/line_sender_cpp_example.cpp).
* [With authentication](../examples/line_sender_cpp_example_auth.cpp).
* [With authentication and TLS](../examples/line_sender_cpp_example_auth_tls.cpp).
* [Custom certificate authority file](../examples/line_sender_c_example_tls_ca.c).

## API Overview

### Header

* [`.hpp` header file](../include/questdb/ingress/line_sender.hpp)

### Connnecting

```cpp
#include <questdb/ingress/line_sender.hpp>

...

auto sender = questdb::ingress::line_sender::from_conf(
    "http::addr=localhost:9000;");

```

See the main [client libraries](https://questdb.io/docs/reference/clients/overview/)
documentation for the full config string params, including authentication, tls, etc.

You can also connect programmatically using the `questdb::ingress::opts` object.

### Building Messages

The `line_sender` object is responsible for connecting to the network and
sending data.

Use the `line_sender_buffer` type to construct messages (aka rows, aka records,
aka lines).

To avoid malformed messages, the `line_sender_buffer` object's methods
must be called in a specific order.

For each row, you need to specify a table name and at least one symbol or
column. Symbols must be specified before columns.

You can accumulate multiple lines (rows) with a given buffer and a buffer is
re-usable, but a buffer may only be flushed via the sender after a call to
`buffer.at(..)` (preferred) or `buffer.at_now()`.

```cpp
questdb::ingress::line_sender_buffer buffer;
buffer
    .table("trades")
    .symbol("symbol", "ETH-USD")
    .column("price", 2615.54)
    .at(timestamp_nanos::now());

// To insert more records, call `buffer.table(..)...` again.

sender.flush(buffer);
```

Diagram of valid call order of the buffer API.

![Sequential Coupling](../api_seq/seq.svg)

## Error handling

Note that most methods in C++ may throw `questdb::ingress::line_sender_error`
exceptions. The C++ `line_sender_error` type inherits from `std::runtime_error`
and you can obtain an error message description by calling `.what()` and an
error code calling `.code()`.

## Further Topics

* [Data quality and threading considerations](CONSIDERATIONS.md)
* [Authentication and TLS encryption](SECURITY.md)
