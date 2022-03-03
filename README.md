# QuestDB - Influx DB Line Protocol - Ingestion Client Library for C and C++

* Implementation is in C11, with no dependency on the C++ standard library
  for simpler inclusion into other projects.
* The C++ API is a header-only wrapper written in C++17.

## Protocol

* Reference docs: https://questdb.io/docs/reference/api/ilp/overview/


## Building

Prepare your system with:
  * A C/C++ compiler which supports C11 and C++17.
  * CMake 3.10.0 or greater.

Then follow the [build instructions](BUILD.md).

If you happen to also use CMake in your own project, you can include it as an
[external cmake dependency](CMAKE_DEPENDENCY.md).
  
## Usage

### From a C program

```c
#include <questdb/linesender.h>

...

linesender_error* err = NULL;
linesender* sender = linesender_connect(
  linesender_tcp,
  "0.0.0.0",   // bind to all interfaces
  "127.0.0.1", // QuestDB hostname
  "9009",      // QuestDB port
  0,  // ignored for TCP
  &err);
```

See a [complete example in C](examples/linesender_example.c).

### From a C++ program

```cpp
#include <questdb/linesender.hpp>

...

// Automatically connects on object construction.
auto sender = questdb::proto::line::sender{
  questdb::proto::line::transport::tcp,
  "127.0.0.1",  // QuestDB hostname
  "9009"};      // QuestDB port

```

See a [complete example in C++](examples/linesender_example.c).

### How to use the API
The API is sequentially coupled, meaning that methods need to be called in a
specific order.



This may be summaried as follows:

```
Grammar:

    // C                              // C++
    linesender_connect,               sender::sender
    (                                 (
        linesender_metric,                sender::metric,
        linesender_tag*,                  sender::tag*
        linesender_field...+              sender::field+,
        linesender_end_line...,           sender::end_line,
        linesender_flush?                 sender::flush?
    )*,                               )*,
    linesender_close                  sender::close*,
                                      sender::~sender

Legend:

    Syntax          Description
    -------------------------------------
    <no suffix>     Call exactly once.
    ?               Call 0 or 1 times.
    *               Call 0 or more times.
    +               Call 1 or more times.
    ()              Repeating group.
    ,               Separator.
```

Note how if you're using C++, `.close()` can be called multiple times and will
also be called automatically on object destruction whilst in C,
`linesender_close(sender)` will release memory and therefore must be called
exactly once.


### Error handling

#### C++

Most methods in C++ may throw `questdb::proto::line::sender_error`
exceptions. The `sender_error` type inherits from `std::runtime_error`.

#### C

In C you must provide a pointer to a pointer to a `linesender_error` and check
the return value of functions that can go wrong.

You may call `linesender_error_errnum(err)` and `linesender_error_errnum(err)`
to extract error details.

Once handled, the error object must be disposed by calling
`linesender_error_free(err)`.

Here's a complete example on how to handle errors:

```c
linesender* sender = ...;
linesender_error* err = NULL;
if (!linesender_metric(
      sender,
      10,
      "table_name",
      &err))
{
  size_t msg_len = 0;
  const char* msg = linesender_error_msg(err, &msg_len);
  fprintf(stderr, "Could not set metric: %.*s", (int)msg_len, msg);

  // Clean-up
  linesender_error_free(err);
  linesender_close(sender);
  return;
}
```

#### Resuming after an error

If you intend to retry, you must call close the existing sender object and
create a new one. The same sender object can't be reused.

### TCP or UDP reliability and performance

Data send over TCP is going to be written reliably.

The UDP protocol should provide higher throughput, but by contrast,
makes no such guarantees and may result in dropped packets.
The line protocol does *not* verify if data has been written
and does *not* resend dropped lines. When using UDP you should also be aware
that `linesender_flush(..)` will fail if
`linesender_pending_size(sender) > 64000`. This logic is in place to avoid
corrupting lines. In other words, when using UDP you may end up with missing
data, but not corrupt data.

## If you don't see any data

You may be experiencing one of these three issues.

### QuestDB configuration
QuestDB (as of writing) defaults to a rather long timeout and high row count for
when data is committed and can by processed by SQL `select` queries.
These settings can be changed. Tune the `cairo.max.uncommitted.rows`,
`line.tcp.commit.timeout` and `line.tcp.maintenance.job.interval`
[Load balancing](https://questdb.io/docs/reference/configuration/#load-balancing)
settings.

### Ingestion protocol behaviour
If you're still not succeeding, note that the same port is used for both TCP
and UDP and once data is sent using once transport the other transport will be
ignored.

### API usage
The API doesn't send any data over the network until the `linesender_flush`
function (if using the C API) or `.flush()` method (if using the C++ API API)
is called.

*Closing the connection will not auto-flush.*

## License

The code is released under the [Apache License](LICENSE).
