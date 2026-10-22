# Pool commit batching

**Status:** proposal

**Scope:** QWP/WebSocket ingestion through the `QuestDb` pool
(`borrow_sender()`), in Rust, C and C++. Neither the protocol nor the server
changes.

## 1. The problem

A common way to use the pool is one lease per message:

```rust
for msg in queue {
    let mut s = db.borrow_sender()?;
    buf.table("trades")?.symbol("sym", &msg.sym)?.column_f64("px", msg.px)?.at(msg.ts)?;
    s.flush_buffer(&mut buf)?;
}
```

Today every flush becomes one frame on the wire, and the server commits
every frame on its own. A million messages mean a million frames and a
million commits, and that, not the data, is what limits throughput.

Users work in one of two modes:

| Mode | Calls | When rows commit |
|---|---|---|
| Streaming | borrow, add, flush, return | Soon. The client decides when |
| Transaction control | borrow, add, flush, **commit**, add, flush, **commit**, return | When the user calls `commit()` |

Requirements:

1. **A flush is durable.** When a flush returns `Ok`, its frame is in the
   store-and-forward (SF) queue, exactly as today. Nothing is left in any
   client buffer after a lease is returned.
2. **Fewer frames and fewer commits.** Small flushes are sent together.
3. **Nothing changes on the server.** Messages use the protocol as it is.

## 2. The idea

Flush stays exactly as it is: each flush writes one frame into SF, and SF
holds the only copy of the data.

What changes is sending. Each slot already has an I/O thread that reads
frames from SF and sends them. Now it waits a little, collects the small
frames that have queued up, and turns them into **one** message. It decodes
them, puts each table's rows together, and encodes the result once. The
server receives one frame and commits once.

```text
flush ──► SF queue ─────────────────────► I/O thread ──────────────► server
          one frame per flush,            decode the queued frames,   1 message,
          durable, unchanged              one block per table,        1 commit
                                          encode once
```

With `commit_interval_ms=100`, one slot sees this:

```text
time     event                          SF queue (unsent)       wire
0 ms     lease A flushes 1 row          frame 1
1 ms     lease B flushes 1 row          frames 1-2
...
99 ms    lease X flushes 1 row          frames 1-500
100 ms   frame 1 is 100 ms old          (sent)                  1 message, 500 rows, 1 commit
```

## 3. Why it is safe

Four rules hold at all times. Each one is what keeps an existing guarantee
intact.

1. **Every row that is sent is already in SF.** Batching never holds data
   anywhere else. So a crash or restart loses nothing, and recovery stays
   exactly as it is.
2. **A merged message is just another way to put SF frames on the wire.**
   Each frame (identified by its FSN, its position in SF) is sent once, inside
   exactly one message. So acks still tell SF exactly which frames it can
   drop.
3. **Frames go out in FSN order.** So rows reach the server in the order
   they were flushed.
4. **Each table appears at most once in a message, and a frame is never
   split.** So the server sees an ordinary message, and the rows of one
   flush always commit together.

## 4. How it works

### 4.1 Configuration

| Key | Default | Meaning |
|---|---|---|
| `commit_interval_ms` | unset (off) | Turns batching on. Rows are sent at the latest this long after they were flushed |
| `commit_rows` | off | Also send once this many rows are waiting |

- Setting `commit_rows` alone turns batching on with
  `commit_interval_ms=100`.
- The pool reads both keys and removes them before opening each slot's
  sender. A standalone `Sender` rejects them.
- With batching off, every frame is sent as soon as it is queued, as today.

### 4.2 When frames are sent

All unsent frames become due as soon as any of these is true:

1. the oldest one has waited `commit_interval_ms`;
2. together they hold `commit_rows` rows;
3. together they reach the frame cap (the smallest of `max_buf_size`, the
   server's advertised max batch size, and the SF segment payload cap);
4. someone called `commit()` or a wait (§4.5);
5. the sender is closing or draining.

- **Waiting.** The I/O thread sleeps until the oldest unsent frame is due,
  using the `wait_timeout` it already has (`ingress/sender/qwp_ws.rs:1010`).
- **Bookkeeping.** Each frame's enqueue time and row count are kept in
  memory only.
- **After a restart or reconnect.** Replayed frames are due at once.

### 4.3 From due frames to messages

Due frames are taken in FSN order. Each frame goes one of three ways.

**Merged (the normal case).** Consecutive small frames are merged into one
message (§4.4). The message keeps the frames' header flags. Its
`FLAG_DEFER_COMMIT` is the last frame's, so a chunk split that is still
open stays open.

A message ends, and a new one starts, before a frame that:

- would push the message over the frame cap;
- has different header flags (version, Gorilla, delta dictionary), ignoring
  `FLAG_DEFER_COMMIT`;
- writes a column with a different type, or a different type parameter
  (decimal scale, geohash precision, array element type), than the same
  column already in the message;
- writes a table with a different timestamp shape: an explicit designated
  timestamp versus server-assigned (`at_now`);
- does not continue the message's symbol dictionary range, for example a
  dictionary that restarts at 0.

**As is.** These frames are sent unchanged, each as its own message:

- frames of 64 KiB or more. They are big enough already, so merging gains
  nothing. Big buffers, chunks and Arrow batches usually land here.
- frames without a delta dictionary (the degraded full-dictionary mode).

**Backlog.** If more than two frame caps of unsent data have queued up, the
I/O thread is falling behind. It stops merging and sends the frames
unchanged, which is cheap. To keep the commit count low, it sets
`FLAG_DEFER_COMMIT` on the wire on every frame of the group but the last,
so the server commits the group once. Flags already stored on a frame are
kept. The added flags are never written to SF. Merging resumes once the
backlog has cleared.

### 4.4 The merger

The merger lives in a new module, `ingress/sender/qwp_ws_merge.rs`. It does
not invent a new way to merge rows: it reuses the one the row API already
uses.

1. **Decode into a `Buffer`.** Each frame's table blocks are decoded into a
   reused `QwpWsColumnarBuffer`, the buffer the row API fills. That buffer
   already keeps one table per name, represents missing columns as nulls,
   and keeps a dictionary per symbol column. The decoder covers every QWP
   wire type: fixed width, booleans, varchar and binary, symbols,
   Gorilla-encoded timestamps, decimals, geohash, UUID, long256 and arrays.
   A new bulk append adds the decoded columns without going row by row.
2. **Resolve symbols.** Symbol IDs in a frame are connection-wide. The I/O
   thread keeps a copy of the connection dictionary (`SymbolGlobalDict`),
   fed from every frame's dictionary section in FSN order, and resolves
   each ID to its string.
3. **Encode once.** The existing encoder writes the message
   (`encode_ws_replay_message_with_defer`, `buffer/qwp.rs:3802`).
   - **IDs stay the same.** Every symbol is already in the dictionary, so
     encoding gives back the IDs the server knows.
   - **New: an explicit dictionary start.** The message must carry exactly
     the entries its frames introduced, from the first frame's
     `delta_start` onwards. Today the encoder always starts at the
     dictionary's current end.

### 4.5 The API

| Call | With batching on |
|---|---|
| `flush_buffer`, `flush_buffer_and_keep`, `flush_chunk`, `flush_arrow_batch_*`, `*_and_get_fsn` | Unchanged. `Ok` means the frame is in SF, and the FSN is known |
| **`commit()`** (new) | Every unsent frame up to this lease's last flush becomes due now. Returns at once, without waiting for the server |
| `wait`, `*_and_wait` | Do what `commit()` does, then wait as today |
| Return or drop of a lease | Unchanged. No I/O; the rows are already in SF |

- **Rust:** `BorrowedSender::commit(&mut self) -> Result<()>`
- **C:** `qwp_sender_commit(qwp_sender*, line_sender_error**)`
- **C++:** `borrowed_sender::commit()`

With batching off, `commit()` does nothing, since every frame is already
sent at once.

**A transaction is one `Buffer`.** Add the rows, `flush_buffer`, then
`commit()`. One buffer is one frame, and a frame is never split, so its rows
commit together (per table, up to the frame cap).

### 4.6 Acks and rejections

Today `InFlightRun` (`ingress/sender/qwp_ws_driver.rs:2828`) assumes one
frame per message and maps FSNs to wire sequence numbers with arithmetic.
It becomes a small queue with one entry per message:
`(wire_seq, first_fsn, last_fsn)`.

- **Ack.** An ack (OK or durable) of a message covers all its frames. SF
  trims through `last_fsn`, as today. On the backlog path, the last frame's
  ack covers the deferred frames before it.
- **Rejection.** The existing rejection policy applies to the message's
  whole FSN range, and the error handler receives the range.
- **Dictionary checks.** `dict_mirror.accumulate` and
  `guard_dict_not_torn` run on every message sent.

### 4.7 What does not change

- The publish path, the SF format, recovery, replay and the reconnect
  catch-up. Replayed frames are merged like any others.
- Return, drop, reaping, close and drain.
- `SymbolDictFull` handling and the `Buffer` contract.

## 5. Costs and limits

- **Visibility.** In streaming mode, rows become visible up to
  `commit_interval_ms` after the flush. Call `commit()` to see them sooner.
- **Rejections.** One bad frame fails the whole message, so every flush
  merged into it fails together.
- **Partial commits.** These can happen exactly as they do today with
  multi-table frames. The server commits a table early once it reaches
  `maxUncommittedRows`. If a later table in the same message then fails,
  the tables before it may already be committed.
- **I/O thread CPU.** The I/O thread now decodes and re-encodes small
  frames. Each slot has its own I/O thread, so the work spreads across
  `sender_pool_max` threads and runs alongside the callers' encoding. Big
  frames skip the merge, and a backlog switches to the cheap path.

## 6. Code

- **`ingress/sender/qwp_ws_merge.rs` (new):** the frame decoder, grouping
  frames, and the rules that end a message.
- **`ingress/buffer/qwp.rs`:** bulk append of decoded columns; an explicit
  dictionary start for the encoder.
- **`ingress/sender/qwp_ws_driver.rs`:**
  - when frames are due, including the `commit()` mark;
  - the three paths;
  - the per-message in-flight queue;
  - the I/O-side `SymbolGlobalDict`.
- **`ingress/sender/qwp_ws.rs`:** per-frame enqueue time and row count; the
  timed wake.
- **`ingress/column_sender/sender.rs` (`PooledSenderCore`):** `commit()`;
  `wait` and `*_and_wait` set the mark. The C FFI calls this type directly,
  so C and C++ get it too.
- **`db.rs`:** `BorrowedSender::commit`.
- **`db/conf.rs`:** the two keys.
- **`include/questdb/ingress/qwp_sender.h` / `.hpp`, `client.h`:**
  `qwp_sender_commit`, `borrowed_sender::commit()`, the conf-key table.

## 7. Tests

**Decoder and merger**

- Round trip: encode a `Buffer`, decode it, encode it again. The bytes must
  be identical. Cover every column kind, sparse columns, nulls, symbols,
  `at_now` and Gorilla.
- Merging the frames of several buffers gives the same bytes as writing all
  their rows into one buffer.
- Each rule that ends a message: cap, flags, type or type parameter,
  timestamp shape, dictionary gap or restart.
- `FLAG_DEFER_COMMIT` on a merged message follows its last frame.

**Driver** (`QwpWsCoreTestHarness`, fake server)

- Due frames go out as one message with one block per table, and its ack
  trims the whole range.
- A frame of 64 KiB or more goes out unchanged, in order.
- The backlog path makes the server commit once per group. Stored flags are
  kept.
- After a reconnect, frames are replayed and merged again.
- A rejection covers the whole range.
- The interval, `commit_rows`, `commit()` and close each make frames due.

**Pool** (`tests/qwp_sender_pool.rs`)

- One lease per message: about one message per interval.
- `commit()` sends now.
- A returned lease leaves nothing behind.
- With `sf_dir`, frames flushed before a kill arrive after a restart.

**Config**

- Defaults.
- `commit_rows` alone turns batching on.
- A standalone `Sender` rejects the keys.

**C/C++:** `commit` exists and the keys are accepted.

## 8. Plan

1. Decoder and bulk append, with the round-trip tests.
2. Merger and the explicit dictionary start, with the merge tests.
3. Driver: when frames are due, the three paths, the in-flight queue and the
   I/O-side dictionary.
4. `commit()` in Rust, C and C++; the config keys.
5. Pool, C and C++ tests.
