# Getting started with C++

The C++17 client is a header-only RAII wrapper over the C ABI. Its primary
entry point is `questdb::pool`, one thread-safe QWP/WebSocket pool for both
ingestion and queries. QWP over WebSocket requires QuestDB 10.0 or newer; the
native library is built with Rust 1.91.1.

See the repository [compatibility matrix](COMPATIBILITY.md), then follow the
[build](BUILD.md) and [dependency](DEPENDENCY.md) instructions.

## Build and run the shared-pool example

Start QuestDB 10.0+ on `localhost:9000`, then build the examples:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DQUESTDB_TESTS_AND_EXAMPLES=ON
cmake --build build --target qwp_ws_chunk_and_query_cpp_example
./build/qwp_ws_chunk_and_query_cpp_example
```

Multi-configuration generators may place the executable under
`build/Release/`.

The complete, compiled source is
[`examples/qwp_ws_chunk_and_query_cpp_example.cpp`](../examples/qwp_ws_chunk_and_query_cpp_example.cpp).
It shares one pool between ingestion and query workers. Each worker owns its
short-lived borrow, and RAII returns readers and senders to the pool.

The essential ownership shape is:

```cpp
#include <questdb/ingress/qwp_sender.hpp>
#include <questdb/egress/qwp_reader.hpp>

questdb::pool db{"ws::addr=localhost:9000;"};

{
    auto sender = db.borrow_sender();
    questdb::ingress::column_chunk chunk{"trades"};
    // Append columns and a designated timestamp, then publish and wait.
    sender.flush_and_wait(chunk, questdb::ingress::qwpws_ack_level::ok);
}

{
    auto reader = db.borrow_reader();
    auto cursor = reader.prepare("SELECT * FROM trades WHERE amount > $1")
                      .bind_f64(0.001)
                      .execute();
    while (auto batch = cursor.next_batch()) {
        // Read typed column views from *batch.
    }
}
```

The full example contains error handling and valid backing buffers. A
`column_chunk` borrows its column memory until `flush` returns, so those buffers
must remain alive and unchanged across the call.

## Threading, acknowledgement, and errors

- `questdb::pool` is thread-safe for borrow, return, and reap operations while
  its owner remains alive.
- `borrowed_sender`, `reader`, query, cursor, and `column_chunk` handles are
  single-threaded. Give each worker its own borrow.
- Returning a healthy sender parks it for reuse. A terminal or in-doubt sender
  must be force-dropped as described by the API contract.
- An `ok` acknowledgement means that the server accepted the frame. WAL apply
  and query visibility occur asynchronously.
- Fallible C++ calls throw `questdb::error`; `.code()` returns the unified
  client error category and `.what()` returns the diagnostic.

See [threading and delivery considerations](CONSIDERATIONS.md) for the complete
protocol matrix and [authentication and TLS](SECURITY.md) for production
connections.

## More examples

- [Query with bind variables](../examples/reader_cpp_example_with_binds.cpp)
- [Read typed columns](../examples/reader_cpp_example_columns.cpp)
- [Read through Arrow](../examples/reader_cpp_example_arrow.cpp)
- [Ingest an Arrow batch](../examples/line_sender_cpp_example_arrow.cpp)
- [Load a connection string](../examples/reader_cpp_example_from_conf.cpp)
- [ILP authentication](../examples/line_sender_cpp_example_auth.cpp)
- [ILP authentication with TLS](../examples/line_sender_cpp_example_auth_tls.cpp)
- [Custom certificate authority](../examples/line_sender_cpp_example_tls_ca.cpp)
- [QWP/UDP](../examples/line_sender_cpp_example_udp.cpp)

The committed headers are the authoritative native API reference:

- [`client.hpp`](../include/questdb/client.hpp) — `questdb::pool`
- [`qwp_sender.hpp`](../include/questdb/ingress/qwp_sender.hpp) — `pool::borrow_sender()`
- [`qwp_reader.hpp`](../include/questdb/egress/qwp_reader.hpp) — `pool::borrow_reader()`
- [`line_sender.hpp`](../include/questdb/ingress/line_sender.hpp)

For connection-string keys, QuestDB Enterprise multi-host failover,
store-and-forward, and deployment guidance, use the public
[C and C++ client guide](https://questdb.com/docs/ingestion/clients/c-and-cpp/).
