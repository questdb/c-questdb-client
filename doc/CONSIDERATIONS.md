# Operational considerations

The client supports ILP over TCP/HTTP and QWP over UDP/WebSocket. Their
delivery, threading, and error contracts differ; choose a transport based on
the guarantee your application needs.

## Threading and ownership

| Object | Concurrent-use contract |
| --- | --- |
| `questdb_db` / C++ `questdb::pool` / Rust `QuestDb` | Thread-safe for borrow, return, and reap while the owning pool remains open |
| Borrowed QWP sender | Single-threaded; keep it on the borrowing thread until it is returned or dropped |
| Reader, query, cursor, or batch handle | One thread at a time; a reader may move between threads when no operation overlaps |
| Row sender and buffer | One thread at a time |
| Column chunk | One thread at a time; referenced column arrays must remain valid until the flush call returns |

Use one long-lived pool per process or service and take short-lived sender or
reader borrows per unit of work. Do not close the pool while another thread is
borrowing, returning, reaping, or otherwise using the owner handle. Existing
borrows become detached leases after close and must still be returned or
dropped, but cannot start new operations.

The pool does create internal threads by default:

- each active QWP/WebSocket store-and-forward sender may drive delivery in the
  background;
- `pool_reap=auto` runs a reaper for idle pooled connections; and
- configured connection/rejection callbacks are dispatched outside the
  caller's critical path.

Applications that cannot host those threads can select manual QWP progress and
`pool_reap=manual`, then call the documented drive and reap APIs regularly.
Manual progress changes when connection failures and server rejections become
observable, so it must be integrated into the application's event loop.

## Delivery semantics

| Transport | What a successful flush means | Server feedback |
| --- | --- | --- |
| ILP/HTTP(S) | The HTTP write request succeeded | HTTP status and response body report ingestion errors |
| ILP/TCP(S) | Bytes were written to the connection | No per-batch acknowledgement; inspect server logs after disconnects |
| QWP/UDP | Datagrams were handed to the local socket | No acknowledgement; datagrams may be lost, reordered, or partly delivered |
| QWP/WebSocket | The frame was published to the local store-and-forward queue | FSN progress, `ok` ACK barriers, Enterprise `durable` ACK barriers, and structured rejection events |

For QWP/WebSocket, `flush` is a local publication boundary, not a server
acknowledgement. Use `flush_and_wait` or `wait` when the caller needs a barrier:

- `ok` waits until the server accepts every frame published through that
  sender up to the captured frame-sequence boundary;
- `durable` requires QuestDB Enterprise, waits for the server's durable
  watermark, and requires the pool to be configured with
  `request_durable_ack=on`; and
- neither ACK guarantees that a WAL table row is immediately query-visible.
  WAL application remains asynchronous, so read-after-write workflows should
  poll or otherwise wait for visibility.

ACK timeouts are no-progress deadlines. Published frames remain owned by the
store-and-forward queue and may continue through reconnect and replay.
Transient connection failures and retriable server states are retried;
terminal schema, parse, security, or protocol rejections make that sender
unusable and must be handled explicitly.

Returning a borrowed QWP sender does not discard already-published frames. For
in-memory store-and-forward, pool shutdown drains best-effort within
`close_flush_timeout`; call `wait` before close when delivery must be confirmed,
or configure `sf_dir` for crash-recoverable disk-backed replay. Never assume
that destroying an unflushed row buffer or column chunk publishes its contents.

## Buffering and backpressure

Batch rows and flush periodically based on elapsed time and data volume.
Flushing every row increases overhead, while unbounded buffers increase memory
use and recovery time.

For ILP, the buffer length is the exact pending encoded byte length. For
QWP/UDP it is a size hint rather than an eventual datagram size. QWP/WebSocket
column and row senders encode frames at publication time and apply their own
store-and-forward limits.

Pool limits (`sender_pool_max`, `query_pool_max`) bound concurrent connections.
At capacity, borrow operations wait up to `acquire_timeout_ms` or fail
immediately when it is zero. Keep borrows short and size these limits against
both application concurrency and server connection capacity.

## Data types and validation

Names and string values must be valid UTF-8; C APIs take explicit lengths and
do not require NUL termination. Table and column names must satisfy QuestDB's
naming rules. Keep a column's type consistent across rows.

For ILP row ingestion, symbols must be added before fields and the designated
timestamp ends a row. Prefer `SYMBOL` for frequently repeated categorical
values and `STRING`/`VARCHAR` for free-form text. The QWP column APIs support a
broader native type set, dictionary-encoded symbols, arrays, and Arrow/Polars
paths; validate equal row counts and keep all borrowed input arrays alive until
the flush returns.

Client-side validation failures are returned as Rust `Result` errors, C error
out-pointers, or C++ exceptions. Server-side data errors follow the transport
contracts above. See the [QuestDB data type reference](https://questdb.com/docs/reference/sql/datatypes/)
and [server logs](https://questdb.com/docs/troubleshooting/log/) when diagnosing
rejected or disconnected writes.
