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
| QWP/WebSocket | The frame was published to the local store-and-forward queue | FSN progress, `ok`, local-durable, and replicated-durable ACK barriers, plus structured rejection events |

For QWP/WebSocket, `flush` is a local publication boundary, not a server
acknowledgement. Use `flush_and_wait` or `wait` when the caller needs a barrier:

- `ok` waits until the server accepts every frame published through that
  sender up to the captured frame-sequence boundary;
- `local_durable` waits until the server has flushed the frames to its own
  disk. It requires a server running `cairo.commit.mode=adaptive` and
  `request_durable_ack=local`. It survives a server power loss, not the loss
  of that disk or a failover to another node;
- `durable` requires QuestDB Enterprise and `request_durable_ack=on`,
  `replicated`, or `local,replicated` (which also needs a server running
  `cairo.commit.mode=adaptive`), and waits until the frames reached
  replication storage, so they survive the loss of the server; and
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
data is durable, the flush that needs the next segment syncs it first. While
a checkpoint is already under way it waits for that one, and publication sees
the normal store-and-forward backpressure response.

In manual QWP progress mode, periodic checkpoints advance only when the
application calls a progress-driving API such as `drive_once` or `wait`.

A periodic checkpoint protects only the client's local replay log.
`request_durable_ack` is orthogonal. It accepts `off` (default), `local`,
`replicated`, `local,replicated`, and `on`. The server must grant the whole
requested set or the connection fails, so `local,replicated` needs both
QuestDB Enterprise and `cairo.commit.mode=adaptive`, which a replicating
Enterprise primary runs only when the mode is set explicitly. With `local` the
sender trims its replay log on the local acknowledgement; with any set that
contains `replicated` it trims only on the replicated one, and
`local_durable` waits are refused. `on` is the original name of the
replicated level: it sends the request every QuestDB Enterprise release
understands, while servers that do not know the explicit names refuse them, so
keep `on` for older servers.

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
QWP/UDP it is a size hint rather than an eventual datagram size. For a
QWP/WebSocket row buffer it is at least the size of the frame a flush encodes,
unless store-and-forward has fallen back to full symbol dictionaries, so a
buffer whose length is within the frame limit fits in one frame.
QWP/WebSocket column and row senders encode frames at publication time and
apply their own store-and-forward limits.

Pool limits (`sender_pool_max`, `query_pool_max`) bound concurrent connections.
At capacity, borrow operations wait up to `acquire_timeout_ms` or fail
immediately when it is zero. Keep borrows short and size these limits against
both application concurrency and server connection capacity.

## Row buffers larger than one frame

A QWP/WebSocket frame cannot be larger than the per-frame cap: the smallest of
`max_buf_size`, the limit the server advertises (2 MiB by default) and what
one store-and-forward segment holds. `effective_frame_cap` returns it.

A sender connected to a server that advertised its frame limit sends a row
buffer above the cap in several frames. All but the last tell the server to
hold their rows, and the last one commits them. So one flush is one commit per
table, for a buffer of any size up to `max_buf_size` (100 MiB by default).
This holds with the queue in memory and with `sf_dir`, for the row sender in
both progress modes and for a sender borrowed from the pool, in Rust, C and
C++. The frame number that such a flush returns is the one of its last frame,
and a `wait` covers the whole flush.

This is about row buffers. A chunk of the column sender that is too large for
one frame is split as well, and with `sf_dir` each of its frames still commits
by itself.

A buffer whose frame fits the cap is never refused for its size. One that does
not is refused with `batch_too_large`, nothing of it is sent and it keeps its
rows, when:

- the server did not advertise a frame limit, because it is too old to commit
  several frames together, or the sender has not connected yet;
- the sender could not write the symbol file of its `sf_dir` slot. The error
  says so: flush smaller buffers, or close the sender, see to the disk of
  `sf_dir` and create a new sender;
- the buffer is larger than `max_buf_size`, or one of its rows fits no frame;
  or
- the queue (`sf_max_total_bytes`, by default 128 MiB in memory and 10 GiB
  with `sf_dir`) can never hold the frames of the flush together. The error
  names the value that would.

The last two go by the buffer's `len()` and the frame sizes planned from it,
which count more than the frames take for symbols: each symbol value at the
widest symbol id, and the text of every symbol, also of one that the
connection already knows. So a buffer that needs several frames is held
against `max_buf_size` by its `len()`, and against `sf_max_total_bytes` by
those planned sizes.

Before its first frame, a flush in several frames waits until the queue has
room for all of them, for up to `sf_append_deadline_millis`. When the room
does not come, the flush fails and nothing of it was sent.

### What one flush guarantees

- **One commit per table, not one for the flush.** A flush with rows of
  several tables commits each table by itself.
- **At least once.** After a reconnect the sender sends again what the server
  has not confirmed. A commit whose confirmation was lost is sent again, and
  its rows are stored twice unless the table has `DEDUP` keys.
- **The server's row limit.** A server commits a table by itself once it holds
  `qwp.max.uncommitted.rows` uncommitted rows of it (1,000,000 by default).
  One flush with more rows of one table than that is committed in parts:
  2,500,000 rows are three transactions, with every row stored once. If such
  a flush fails after a part was committed, that part stays, and sending the
  buffer again stores it twice. A reconnect during such a flush stores
  nothing twice when the flush has rows of one table only: the server
  confirms what it committed, and the sender sends the rest. With rows of
  several tables the server confirms nothing before the end, the sender
  sends the whole flush again, and the part that was committed is stored
  twice. Keep the rows of a table in one flush below the limit, raise the
  limit on the server, or use `DEDUP`. The client does not check the limit.
- **Rows without a timestamp.** The server gives the rows added with
  `at_now()` the time at which it takes their frame, so the rows of a flush in
  several frames carry one timestamp per frame.

### Memory

A flush in several frames needs two to three times the buffer's length in
memory. The buffer itself takes 1.2 to 2 times its `len()` for ordinary rows,
and the queue holds every frame of the flush until the server has confirmed
the last one. With a server on the same machine, one flush of 100 MiB peaked
at 230 to 330 MiB of resident memory, depending on its rows, where the same
rows flushed a frame at a time needed 20 to 75 MiB. The flush took no longer.

A connection also keeps every symbol it has sent, about 200 bytes for a symbol
of 40 to 50 bytes, and takes at most 2,000,000 symbols or 256 MiB of symbol
text over its life. A
server creates a symbol column with room for 256 symbols; when one flush
brings hundreds of thousands of new symbols, the rows show in the table
seconds later than their confirmation, unless the table was created with a
symbol capacity to match.

### A flush that stops part way

A flush that has queued some of its frames and cannot queue the rest, for
example because the connection has no room for more symbols, fails with
`flush_aborted`. The frame that commits the flush was never sent, so nothing
of the flush is committed (below the server's row limit, see above), the
buffer keeps its rows, and the error is not in doubt. The sender takes no more
flushes and reports `must_close`, but it still delivers the flushes before the
failed one. To lose none of them, call `close_drain` and check that it
succeeded; then close the sender, create a new one and flush the buffer again.
The holder of a pooled sender calls `wait` instead and returns the sender,
which the pool closes instead of lending it again. With `sf_dir` a
`close_drain` that waits (a `close_flush_timeout` above 0) and succeeds leaves
the sender's slot empty, nothing of the failed flush and no symbols, and so
does the pool when its wait for the sender succeeds.

A frame that the server rejects takes the whole flush with it: the server
drops the rows it holds for the connection and commits nothing of the flush.
The rejection usually arrives while `flush` is still queuing frames, and
`flush` then fails with it while the buffer keeps its rows. Otherwise the next
`wait`, `flush` or `close_drain` reports it. A rejection names a range of frame
numbers; it belongs to the flush whose returned frame number is the first at
or above the end of that range.

### With `sf_dir`

The frames of a flush stay in the files of the sender's slot until the server
has confirmed the flush. A sender that opens a slot again, after the process
was killed or the sender before it was closed, finds one of two things at its
end:

- **A flush with its last frame** is sent whole, unless the server has
  confirmed it. When the server committed it and the confirmation was lost, it
  is committed again (at least once).
- **A flush without its last frame** is removed. The process was killed inside
  `flush`, or the flush failed with `flush_aborted` and the sender was closed
  without a `close_drain` that waited and succeeded. Nothing of it was
  committed (below the server's row limit, see above) and nothing of it is
  sent, so flush the buffer again. The flushes before it are sent as usual.

A pool that opens a slot does the same, and so does the drainer of a slot that
no sender owns. A segment file that the process was killed while creating is
removed as well. Opening a slot that held 100 MiB took about 40 ms.

**Older clients.** Releases 7.0.0 to 7.3.0 do not remove a flush without its
last frame. One of them that opens such a slot sends the frames, and its next
flush would commit their rows, a part of a flush. Before a slot goes back to
one of these releases after a kill inside a flush or a `flush_aborted`, open
it once with this release: build a sender with the same `sf_dir` and
`sender_id`, or the pool, and close it. Or delete the slot's folder when its
rows are not needed. The format of a slot is the same: one whose flushes all
have their last frame is read by every release.

**Speed.** With `sf_dir` a sender pays for every segment file it fills, not
for the bytes: about 20 ms a file on an NVMe disk with ext4, and 26 ms with
`sf_durability=periodic`. Small flushes pay the same for each file. With the
default `sf_max_segment_bytes` of 4 MiB, one flush of 100 MiB returned after
0.54 s (0.66 s with `periodic`), where a sender with its queue in memory took
0.07 s. For large flushes raise `sf_max_segment_bytes`: with 64 MiB the same
flush returned after 0.07 s (0.09 s). The per-frame cap stays what the server
advertises. Larger segments give disk space back in larger steps, and
`sf_max_total_bytes` must hold the segments that one flush fills and one more.

### Waiting and closing

- The `wait` timeout counts the time without a new confirmation, and the
  server confirms a flush in several frames once, at its end. Pass a timeout
  that covers sending and committing the whole flush, or zero to wait without
  a limit. A timeout is not a failure: the frames stay queued, so call `wait`
  again and do not flush the same rows again. `flush_buffer_and_wait` of a
  pooled sender uses `request_timeout` in the same way.
- "Flush, then close" can lose a large flush. `close_drain` waits for
  `close_flush_timeout_millis` in total (5 seconds by default), closing or
  dropping a sender without it does not wait at all, and without `sf_dir` the
  frames that are not confirmed by then are dropped with the sender. The
  timeout error of `close_drain` says how many those are. Call `wait` before
  closing, or raise `close_flush_timeout_millis`.
- One flush must reach the server and be committed within the life of one
  connection: after a reconnect the sender sends it again from its first
  frame. When the server ends the connection with a WebSocket close frame
  other than a normal or going-away close four times in a row
  (`max_frame_rejections`) without confirming anything in between, and
  `poison_min_escalation_window_millis` has passed, the sender stops for good.
  A connection that just drops is never counted. Raise the two settings for
  flushes that take long.

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
