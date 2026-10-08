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
  watermark, and requires the sender or pool to be opened with
  `request_durable_ack=on`; and
- neither ACK guarantees that a WAL table row is immediately query-visible.
  WAL application remains asynchronous, so read-after-write workflows should
  poll or otherwise wait for visibility.

ACK timeouts are no-progress deadlines. Published frames remain owned by the
store-and-forward queue and may continue through reconnect and replay.
Transient connection failures and retriable server states are retried;
terminal schema, parse, security, or protocol rejections make that sender
unusable and must be handled explicitly.

With `sf_dir`, the QWP/WebSocket publication log can be recovered after a
producer-process restart. The default `sf_durability=memory` mode relies on the
OS page cache, so it does not protect the newest published frames from host
power loss. Configure
`sf_durability=periodic;sf_sync_interval_millis=5000;` for background
memory-map/file-sync checkpoints. The interval defaults to 5000 ms and is a
target cadence, not a hard upper bound: sender scheduling and storage latency
extend the actual recovery window. If a segment fills before its published
data is durable, rotation waits for a requested checkpoint and publication
sees the normal store-and-forward backpressure response.

In manual QWP progress mode, periodic checkpoints advance only when the
application calls a progress-driving API such as `drive_once` or `wait`.

A periodic checkpoint protects only the client's local replay log.
`request_durable_ack=on` is orthogonal: it requests QuestDB Enterprise
server-side durable ACKs. Use periodic local durability together with durable
ACK waits when both sides of the delivery path must cross a durability
barrier.

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
the flush returns. QWP rows allow symbol and non-symbol columns in any order
before the designated timestamp.

Client-side validation failures are returned as Rust `Result` errors, C error
out-pointers, or C++ exceptions. Server-side data errors follow the transport
contracts above. See the [QuestDB data type reference](https://questdb.com/docs/reference/sql/datatypes/)
and [server logs](https://questdb.com/docs/troubleshooting/log/) when diagnosing
rejected or disconnected writes.

## QWP/WebSocket symbol dictionary recycling

Store-and-forward senders automatically recycle their connection-scoped symbol
namespace at a safe publication boundary. The connect-string settings are:

| Setting | Default | Range |
| --- | --- | --- |
| `symbol_dict_reset` | `on` | `on`, `off` |
| `symbol_dict_reset_threshold` | `100000` | `1`–`1000000` distinct symbols |
| `symbol_dict_reset_max_wait_millis` | `2000` | `0`–`9223372036854` milliseconds |

A successful publication reaching the threshold arms recycling; a later nonempty
flush can execute it after all pending frames have reached the required ACK and
there is no open deferred-commit group. Appending a symbol does not reset the
dictionary. After a reset, the automatic rearm floor is at least twice the old
namespace's size, capped at one million; the configured threshold still applies.
This hysteresis reduces repeated work, but live sets of one million or more can
recycle repeatedly. `symbol_dict_reset=off` may suit a bounded set below two
million symbols, provided it also fits the UTF-8 heap cap.

Once an arm has aged by `symbol_dict_reset_max_wait_millis`, an eligible live
flush may wait for progress for at most that duration, once per arm. Zero disables
that wait, not recycling. An outage or deferred group postpones recycling. Armed
age survives pool return and reborrow, so the next borrower may pay the one bounded
wait. Retained queue bytes and SF side-files are not a new hard dictionary-memory
budget: the existing two-million-entry and 256 MiB cumulative UTF-8 limits still
apply, and a large individual publication can hit either before a reset is safe.

Rust `Sender::reset_symbol_dictionary` and the corresponding borrowed sender
advisory method coalesce requests for a later safe boundary. They do not flush,
wait, reconnect, or guarantee completion; disabled recycling is a no-op. C and C++
inherit automatic settings through their existing connect strings; there is no
new C manual-reset API. Public FSNs remain continuous across recycling within one
sender lifetime. They are not a persisted, cross-process epoch sequence.

This applies to memory and disk SF, background and manual progress, standalone
and pooled senders, and their Buffer, Chunk, Arrow, and Polars-to-Arrow ingestion
paths. The direct whole-source backend (`BorrowedDirectColumnSender`, including
`QuestDb::flush_polars_dataframe`) is excluded: it keeps its `spent` /
`SymbolDictFull`, commit, and reborrow behavior. A pool can expose both kinds of
sender. Recycling does not strengthen ordinary write durability or delivery
certainty; replay plus server deduplication establishes logical no-loss, not wire
exactly-once delivery.
