# QuestDB - Influx DB Line Protocol - Ingestion Client Library for C and C++

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
  "0.0.0.0",   // bind to all
  "127.0.0.1",
  "9009",
  0,  // ignored for TCP
  &err);
```

See a (complete example in C)[examples/linesender_example.c].

### From a C++ program

```cpp
#include <questdb/linesender.hpp>

...

auto sender = questdb::proto::line::sender{

};
```

See a (complete example in C++)[examples/linesender_example.c].

## If you don't see any data

QuestDB (as of writing) has a rather long timeout and high row count for when
data is committed and appears can by processed by SQL select queries.
These settings can be changed. See `cairo.max.uncommitted.rows`,
`line.tcp.commit.timeout` and `line.tcp.maintenance.job.interval` in the
(Load balancing)[https://questdb.io/docs/reference/configuration/#load-balancing]
section of our documentation.

If you're still not succeeding, note that the same port is used for both TCP
and UDP and once data is sent using once transport the other transport will be
ignored.

Also, did you call `flush()` function before disconnecting?

## License

The code is released under the [Apache License](LICENSE).
