# QuestDB - Line Protocol - Ingestion Client Library for C and C++

* Implementation is in C11, with no dependency on the C++ standard library
  for simpler inclusion into other projects.
* The C++ API is a header-only wrapper written in C++17.

## Protocol

This client library implements the input line protocol over TCP.

* Reference docs: https://questdb.io/docs/reference/api/ilp/overview/

Whilst this library performs as much validation ahead of time as possible,
the protocol does not report errors or report progress.

As such, due to error in the database or crashes, not all the data may end up
being written. You can however expect well-formed data to be written so long as
it has been received by the database.

Data will be written in the order it is sent, unless the
[out-of-order feature](https://questdb.io/docs/guides/out-of-order-commit-lag/#how-to-configure-out-of-order-ingestion)
is used in QuestDB which will reorder records based on timestamp.

The protocol does not implement authentication and does not resume in case
of a client-side crash. If you want to be certain that your data has been
written you will need to:

* Wait for your data to be written, as per the
  [Load balancing](https://questdb.io/docs/reference/configuration/#load-balancing)
  configuration section.

* Execute a `select` SQL query to check for the presence of your data.

## Rules for well-formed data

When inserting data through the API, you must follow a set of rules.
Some are validated by the client library, others will cause the engine to fail silently.

### Library-validated rules

* Strings and symbols must be passed in as valid UTF-8 which
  need not be nul-terminated.
* Table names, symbol and column names can't contain the characters `?`, `.`,
  `,`, `'`, `"`, `\`, `/`, `:`, `(`, `)`, `+`, `-`, `*`, `%`, `~`,
  `' '` (space), `\0` (nul terminator),
  [ZERO WIDTH NO-BREAK SPACE](https://unicode-explorer.com/c/FEFF).

### Non-validated rules

TODO: document me.

## Building

Prepare your system with:
  * A C/C++ compiler which supports C11 and C++17.
  * CMake 3.15.0 or greater.

Then follow the [build instructions](BUILD.md).

If you happen to also use CMake in your own project, you can include it as an
[external cmake dependency](CMAKE_DEPENDENCY.md).
  
## Usage

### From a C program

```c
#include <questdb/line_sender.h>

...

line_sender_error* err = NULL;
line_sender* sender = line_sender_connect(
  "0.0.0.0",   // bind to all interfaces
  "127.0.0.1", // QuestDB hostname
  "9009",      // QuestDB port
  &err);
```

See a [complete example in C](examples/line_sender_c_example.c).

### From a C++ program

```cpp
#include <questdb/line_sender.hpp>

...

// Automatically connects on object construction.
questdb::line_sender sender{
  "127.0.0.1",  // QuestDB hostname
  "9009"};      // QuestDB port

```

See a [complete example in C++](examples/line_sender_cpp_example.cpp).

### How to use the API
The API is sequentially coupled, meaning that methods need to be called in a
specific order.

For each row you need to specify a table name and at least one symbol or
column. Symbols must be specified before columns.
Once you're done with a row you must add a timestamp calling `at` or `at_now`.

This ordering of operations is documented for both the C and C++ APIs below.

#### C function calling order

![C API Sequential Coupling](api_seq/c.svg)

Note that this diagram excludes error handling paths: One can call `line_sender_close(sender)` after any operation.

The `line_sender_close(sender)` function will release memory and therefore must be called
exactly once per created object.

Error handling with the C api works by providing a `line_sender_error**` parameter as last argument and check the return value of functions that can go wrong.

You may then call `line_sender_error_msg(err)` and `line_sender_error_get_code(err)`
to extract error details.

Once handled, the error object must be disposed by calling
`line_sender_error_free(err)`.

Here's a complete example on how to handle an error:

```c
line_sender* sender = ...;
line_sender_error* err = NULL;
if (!line_sender_table(
      sender,
      10,
      "table_name",
      &err))
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

This type of error handling can get verbose, so you may want to use a `goto`
to simplify handling (see [example](examples/line_sender_c_example.c)).

#### C++ method calling order

![C++ API Sequential Coupling](api_seq/cpp.svg)

Note how if you're using C++, `.close()` can be called multiple times and will
also be called automatically on object destruction.

Note that most methods in C++ may throw `questdb::line_sender_error`
exceptions. The C++ `line_sender_error` type inherits from `std::runtime_error` and you can obtain an error message description by calling `.what()`.

#### Resuming after an error

If you intend to retry, you must create a new sender object: The same sender object can't be reused.

## If you don't see any data

You may be experiencing one of these three issues.

### QuestDB configuration
QuestDB (as of writing) defaults to a rather long timeout and high row count for
when data is committed and can by processed by SQL `select` queries.
These settings can be changed. Tune the `cairo.max.uncommitted.rows`,
`line.tcp.commit.timeout` and `line.tcp.maintenance.job.interval`
[Load balancing](https://questdb.io/docs/reference/configuration/#load-balancing)
settings.

### API usage
The API doesn't send any data over the network until the `line_sender_flush`
function (if using the C API) or `.flush()` method (if using the C++ API API)
is called.

*Closing the connection will not auto-flush.*

## Windows Dynamic Library Linkage Issues

If you depend on this library as a dynamic library on Windows you need to
define `LINESENDER_DYN_LIB` as compiler argument when compiling your code.

If you're depending on the cmake infrastructure, this should be added for you
automatically.

The `LINESENDER_DYN_LIB` define is to allow the header to mark all public APIs
as `__declspec(dllimport)` and have symbols resolve correctly at runtime.

*Don't do any of this if you're linking the library statically.*

## License

The code is released under the [Apache License](LICENSE).
