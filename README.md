# c-questdb-client
**QuestDB - InfluxDB Line Protocol - Ingestion Client Library for C and C++**

This library makes it easy to insert data into [QuestDB](https://questdb.io/).

This client library implements the [InfluxDB Line Protocol](
https://questdb.io/docs/reference/api/ilp/overview/) (ILP) over TCP.

* Implementation is in Rust, with no additional
  [run-time or link-time dependencies](BUILD.md#pre-requisites-and-dependencies)
  on the C++ standard library or other libraries.
* We ship both a static and a dynamic library.
* The library exposes both a C and a C++17 API.
* The C++ API is a header-only wrapper over the C API.

## Protocol

Inserting data into QuestDB can be done via one of three protocols.

| Protocol | Record Insertion Reporting | Data Insertion Performance |
| -------- | -------------------------- | -------------------------- |
| [ILP](https://questdb.io/docs/reference/api/ilp/overview/)| Errors in logs; Disconnect on error | **Best** |
| [CSV Upload via HTTP](https://questdb.io/docs/reference/api/rest/#imp---import-data) | Configurable | Very Good |
| [PostgreSQL](https://questdb.io/docs/reference/api/postgres/) | Transaction-level | Good |

This library mitigates the lack of confirmation and error reporting by
validating data ahead of time before any data is sent to the database instance.

For example, the client library will report that a supplied string isn't encoded
in UTF-8. Some issues unfortunately can't be caught by the library and require
some [care and diligence to avoid data problems](#data-quality-considerations).

For an overview and code examples, see the
[ILP page of the developer docs](https://questdb.io/docs/develop/insert-data/#influxdb-line-protocol).

To understand the protocol in more depth, consult the
[protocol reference docs](https://questdb.io/docs/reference/api/ilp/overview/).

## Using this Library

Start with the [build instructions](BUILD.md), then read the guide for including
this library as a [dependency from your project](DEPENDENCY.md).

Once you've all set up, you can take a look at our examples:

### From a C program

```c
#include <questdb/ilp/line_sender.h>

...

line_sender_error* err = NULL;
line_sender_opts* opts = NULL;
line_sender* sender = NULL;

line_sender_utf8 host = QDB_UTF8_LITERAL("localhost");
opts = line_sender_opts_new(host, 9009, &err);
if (!opts) {
    /* ... handle error ... */
}

sender = line_sender_connect(opts, &err);
line_sender_opts_free(opts);
opts = NULL;
if (!sender) {
    /* ... handle error ... */
}

```

The `opts` object can additionally take parameters for the outbound interface,
authentication, full-connection encryption via TLS and more.

Examples:
* [Basic example in C](examples/line_sender_c_example.c).
* [With authentication](examples/line_sender_c_example_auth.c).
* [With authentication and TLS](examples/line_sender_c_example_tls.c).

### From a C++ program

```cpp
#include <questdb/ilp/line_sender.hpp>

...

// Automatically connects on object construction.
questdb::ilp::line_sender sender{
    "localhost",  // QuestDB hostname
    9009};        // QuestDB port

```

For more advanced use cases, such as those requiring authentication or
full-connection encryption via TLS, first, create an `opts` object then call its
methods to populate its options and then pass the `opts` object to the
`line_sender` constructor.

Examples:
* [Basic example in C++](examples/line_sender_cpp_example.cpp).
* [With authentication](examples/line_sender_cpp_example_auth.cpp).
* [With authentication and TLS](examples/line_sender_cpp_example_tls.cpp).

See a [complete example in C++](examples/line_sender_cpp_example.cpp).

### How to use the API
The API is sequentially coupled, meaning that methods need to be called in a
specific order.

For each row, you need to specify a table name and at least one symbol or
column. Symbols must be specified before columns.
Once you're done with a row you must add a timestamp calling `at` or `at_now`.

This ordering of operations is documented for both the C and C++ APIs below.

#### Buffer API

The `line_sender` object is responsible for connecting to the network and
sending data.

The buffer it sends is constructed separately through a `line_sender_buffer`
object.

To avoid malformed messages, this object's methods (`line_sender_buffer_*`
functions in C) must be called in a specific order.

You can accumulate multiple lines (rows) with a given buffer and a buffer is
re-usable, but a buffer may only be flushed via the sender after a `.at()` or
`.at_now()` method call (or equivalent C function).

![Sequential Coupling](api_seq/seq.svg)

#### Threading Considerations

By design, the sender and buffer objects perform all operations on the current
thread. The library will not spawn any threads internally.

By constructing multiple buffers you can design your application to build ILP
messages on multiple threads whilst handling network connectivity in a separate
part of your application on a different thread (for example by passing buffers
that need sending over a concurrent queue and sending flushed buffers back over
another queue).

Buffer and sender objects don't use any locks, so it's down to you to ensure
that a single thread owns a buffer or sender at any given point in time.

#### Error handling in the C API

In the C API, functions that can result in errors take a `line_sender_error**`
parameter as the last argument. When calling such functions you must check the
return value for errors. Functions that return `bool` use `false` to indicate
a failure, whilst functions that return a pointer use NULL as the failure
sentinel value.

You may then call `line_sender_error_msg(err)` and
`line_sender_error_get_code(err)` to extract error details.

Once handled, the error object *must* be disposed of by calling
`line_sender_error_free(err)`.

On error, you must also call `line_sender_close(sender)`.

Here's a complete example of how to handle an error without leaks:

```c
line_sender* sender = ...;
line_sender_error* err = NULL;
if (!line_sender_flush(sender, &err))
{
  size_t msg_len = 0;
  const char* msg = line_sender_error_msg(err, &msg_len);
  fprintf(stderr, "Could not set table name: %.*s", (int)msg_len, msg);

  // Clean-up
  line_sender_error_free(err);
  line_sender_close(sender);
  return;
}
```

This type of error handling can get error-prone and verbose,
so you may want to use a `goto` to simplify handling
(see [example](examples/line_sender_c_example.c)).

#### Error handling in the C++ API

Note that most methods in C++ may throw `questdb::ilp::line_sender_error`
exceptions. The C++ `line_sender_error` type inherits from `std::runtime_error`
and you can obtain an error message description by calling `.what()` and an
error code calling `.code()`.

### Data types

The ILP protocol has its own set of data types which is smaller
that the set supported by QuestDB.
We map these types into QuestDB types and perform conversions
as necessary wherever possible.

Strings may be recorded as either the `STRING` type or the `SYMBOL` type.

`SYMBOL`s are strings with which are automatically
[interned](https://en.wikipedia.org/wiki/String_interning) by the database on a
per-column basis.
You should use this type if you expect the string to be re-used over and over.
This is common for identifiers, etc.

For one-off strings use `STRING` columns which aren't interned.

For more details see our
[datatypes](https://questdb.io/docs/reference/sql/datatypes) page.

## Data quality considerations

When inserting data through the API, you must follow a set of considerations.

### Library-validated considerations

* Strings and symbols must be passed in as valid UTF-8 which
  need not be nul-terminated.
* Table names and column names must conform to valid names as accepted by the
  database (see `isValidTableName` and `isValidColumnName` in the QuestDB java
  [codebase](https://github.com/questdb/questdb) for details).
* Each row should contain, *in order*:
  * table name
  * at least one of:
    * symbols, zero or more
    * columns, zero or more
  * timestamp, optionally

Breaking these rules above will result in an error in the client library.

### Additional considerations

Additionally you should also ensure that:

* For a given row, a column name should not be repeated.
  If it's repeated, only the first value will be kept.
  This also applies to symbols.
* Values for a given column should always have the same type.
  If changing types the whole row will be dropped (unless we can cast).
* If supplying timestamps these need to be at least equal to
  previous ones in the same table, unless using the out of order
  feature. Out of order rows would be dropped.
* The timestamp column should be written out through the provided
  `line_sender_at` function (in C) or or `.at()` method in (C++).
  It is also possible to write out additional timestamps values
  as columns.

The client library will not check any of these types of data issues.

To debug these issues you may consult the QuestDB instance logs.

#### Resuming after an error

If you intend to retry, you must create a new sender object: The same sender
object can't be reused.

## Connection Security

You may choose to enable authentication and/or TLS encryption by setting the
appropriate properties on the `opts` object used for connecting.

### Authentication

We support QuestDB's ECDSA P256 SHA256 signing-based authentication.

To create your own keys, follow the QuestDB's [authentication documentation](https://questdb.io/docs/reference/api/ilp/authenticate/).

Authentication can be used independently of TLS encryption.

### TLS Encryption

As of writing, whilst QuestDB itself can't be configured to support TLS natively
it is recommended that you use `haproxy` or other to secure the connection
for any public-facing servers.

TLS can be used independently and provides no authentication itself.

The `tls_certs` directory of this project contains tests certificates, its
[README](tls_certs/README.md) page describes generating your own certs.

For API usage, see the C and C++ auth examples:
* [examples/line_sender_c_example_auth.c](examples/line_sender_c_example_auth.c)
* [examples/line_sender_cpp_example_auth.cpp](examples/line_sender_cpp_example_auth.cpp)

## If you don't see any data

You may be experiencing one of these issues:

### QuestDB configuration

If you can't initially see your data through a `select` query straight away,
this is normal: by default the database will only commit data it receives
though the line protocol periodically to maximize throughput.

For dev/testing you may want to tune the following database configuration
parameters as so:

```ini
# server.conf
cairo.max.uncommitted.rows=1
line.tcp.maintenance.job.interval=100
```

The defaults are more applicable for a production environment.

For these and more configuration parameters refer to [database configuration
](https://questdb.io/docs/reference/configuration/)documentation.

### API usage
The API doesn't send any data over the network until the `line_sender_flush`
function (if using the C API) or `.flush()` method (if using the C++ API API)
is called.

*Closing the connection will not auto-flush.*

## Community

If you need help, have additional questions or want to provide feedback, you
may find us on [Slack](https://slack.questdb.io).

You can also [sign up to our mailing list](https://questdb.io/community/)
to get notified of new releases.

## License

The code is released under the [Apache License](LICENSE).
