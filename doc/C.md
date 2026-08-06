# Getting started with C

The C client exposes QuestDB Wire Protocol (QWP) ingestion and queries through
one shared connection pool. QWP over WebSocket requires QuestDB 10.0 or newer.
The library itself is built with Rust 1.91.1 and exposes a C11 ABI.

See the repository [compatibility matrix](COMPATIBILITY.md), then follow the
[build](BUILD.md) and [dependency](DEPENDENCY.md) instructions.

## Build and run the shared-pool example

Start QuestDB 10.0+ on `localhost:9000`, then build the examples:

```bash
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DQUESTDB_TESTS_AND_EXAMPLES=ON
cmake --build build --target qwp_ws_chunk_and_query_c_example
./build/qwp_ws_chunk_and_query_c_example
```

Multi-configuration generators may place the executable under
`build/Release/`.

The complete, compiled source is
[`examples/qwp_ws_chunk_and_query_c_example.c`](../examples/qwp_ws_chunk_and_query_c_example.c).
It demonstrates the intended lifecycle:

1. Open one process-wide `questdb_db` using a `ws::` or `wss::` connection
   string.
2. Borrow a `qwp_sender`, fill a column-major `qwp_chunk`, publish
   it, and wait for an `OK` acknowledgement.
3. Return the sender, borrow a `qwp_reader` from the same pool, bind and execute a
   SQL query, and stream result batches.
4. Close the reader before finally closing the pool.

Pool borrow and return operations are thread-safe. A borrowed sender, reader,
query, cursor, or chunk is single-threaded and must not be used concurrently.
Use one short-lived borrow per unit of work rather than sharing a borrowed
handle.

## API map

Include both headers when using one pool for ingestion and queries:

```c
#include <questdb/ingress/qwp_sender.h>
#include <questdb/egress/qwp_reader.h>
```

The principal entry points are:

| Task | C API |
| --- | --- |
| Open/close the pool | `questdb_db_connect`, `questdb_db_close` |
| Borrow/return an ingestion lease | `questdb_db_borrow_sender`, `questdb_db_return_sender` |
| Build a columnar batch | `qwp_chunk_new`, `qwp_chunk_*` |
| Publish and observe an acknowledgement | `qwp_sender_flush_chunk`, `qwp_sender_wait` |
| Borrow/return a query lease | `questdb_db_borrow_reader`, `qwp_reader_close` |
| Prepare, bind, and execute SQL | `qwp_reader_prepare`, `qwp_reader_query_bind_*`, `qwp_reader_query_execute` |
| Stream results | `qwp_reader_cursor_next_batch`, `qwp_reader_batch_column_data` |

Every fallible call returns a status or nullable handle and optionally writes a
new `questdb_error`/`line_sender_error`. Check the return value, inspect the
error, free it exactly once, and release any live cursor or query before
closing its reader. The two error names are aliases of the same C ABI type.

An `OK` acknowledgement means the server accepted a QWP frame. On a WAL table,
query visibility follows asynchronously; applications that must read their own
writes should poll with a bounded deadline or use their own WAL-apply policy.
Durable acknowledgement requires QuestDB Enterprise. Enable
`request_durable_ack=on` and wait for the durable level. See
[threading and delivery considerations](CONSIDERATIONS.md).

## More examples

- [Query with bind variables](../examples/reader_c_example_with_binds.c)
- [Read typed columns](../examples/reader_c_example_columns.c)
- [Read through the Arrow C Data Interface](../examples/reader_c_example_arrow.c)
- [Load a connection string](../examples/reader_c_example_from_conf.c)
- [ILP authentication](../examples/line_sender_c_example_auth.c)
- [ILP authentication with TLS](../examples/line_sender_c_example_auth_tls.c)
- [Custom certificate authority](../examples/line_sender_c_example_tls_ca.c)
- [QWP/UDP](../examples/line_sender_c_example_udp.c)

QWP/UDP is best effort and provides no acknowledgement, authentication, or
TLS. ILP/HTTP and ILP/TCP remain available for compatibility, but they do not
share QWP's ingestion/query pool.

The committed headers are the authoritative native API reference:

- [`client.h`](../include/questdb/client.h) — `questdb_db`
- [`qwp_sender.h`](../include/questdb/ingress/qwp_sender.h) — `questdb_db_borrow_sender`
- [`qwp_reader.h`](../include/questdb/egress/qwp_reader.h) — `questdb_db_borrow_reader`
- [`line_sender.h`](../include/questdb/ingress/line_sender.h)

For connection-string keys, Enterprise multi-host failover, store-and-forward,
and deployment guidance, use the public
[C and C++ client guide](https://questdb.com/docs/ingestion/clients/c-and-cpp/).
