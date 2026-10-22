# Pool commit batching

**Status:** proposal

**Scope:** QWP/WebSocket ingestion through the `QuestDb` pool
(`borrow_sender()`), in Rust, C and C++. Neither the protocol nor the server
changes.

## 1. Goal

| Mode | Calls | Who decides when rows commit |
|---|---|---|
| Streaming | borrow, add, flush, return | The client, within `commit_interval_ms` |
| Transaction control | borrow, add, flush, **commit**, add, flush, **commit**, return | The user: `commit()` sends now |

Requirements:

1. **Durable on flush.** When a flush returns `Ok`, its frame is in the
   store-and-forward (SF) queue, exactly as today. Nothing stays in a
   client buffer after a lease is returned.
2. **Fewer frames and fewer commits.** One lease per message must not mean
   one frame and one commit per message.
3. **Protocol unchanged.** A table appears at most once in a message. The
   only flag used is the existing `FLAG_DEFER_COMMIT`.

## 2. Design

The publish path does not change: each flush encodes one frame into SF. All
batching happens in each slot's I/O thread. When unsent frames are due, the
I/O thread decodes them and merges each table's rows into one block. It
then encodes the result as one message: one frame on the wire and one
commit on the server.

```text
flush ──► SF queue (frame per flush, durable) ──► I/O thread ──► server
          unchanged                                decode, merge    1 message,
                                                   per table,       1 commit
                                                   encode
```

SF is the only source of truth. A merged message is derived from SF frames
and replaces them on the wire. Recovery, replay and the SF format are
unchanged.

Each SF sender already has its own I/O thread (`ingress/sender/qwp_ws.rs:644`,
`:698`). Merging therefore scales with `sender_pool_max`, and per slot it
runs in parallel with the caller's encoding.

### 2.1 Configuration

| Key | Default | Meaning |
|---|---|---|
| `commit_interval_ms` | unset (off) | Turns batching on. Frames are sent at the latest this long after the oldest unsent one was flushed |
| `commit_rows` | off | Also send when the unsent frames hold this many rows |

- Setting `commit_rows` alone turns batching on with
  `commit_interval_ms=100`.
- The pool parses both keys and strips them before opening each slot's
  sender. A standalone `Sender` rejects them.
- With batching off, every frame is sent as soon as it is queued, as today.

### 2.2 When the I/O thread sends

All unsent frames are due as soon as any of these holds:

1. The oldest unsent frame has waited `commit_interval_ms`.
2. The unsent frames hold `commit_rows` rows.
3. The unsent frames reach the frame cap: the smallest of `max_buf_size`,
   the server's advertised max batch size, and the SF segment payload cap.
4. `commit()` or a wait asked for it (§2.5).
5. The sender is closing or draining.

- The I/O thread sleeps until the oldest unsent frame is due, using the
  existing `wait_timeout` (`qwp_ws.rs:1010`).
- Each frame's enqueue time and row count are kept in memory only. Frames
  replayed after a reconnect or restart are due at once.

### 2.3 From due frames to messages

Due frames are taken in FSN order and grouped. Each group becomes one
message.

**Merge path (normal).** Frames are merged with the merger in §2.4. The
message's header flags are the frames' flags. Its `FLAG_DEFER_COMMIT` is
the last frame's, so a chunk split that is still open stays deferred.

A group ends before the next frame when that frame:

- would push the message over the frame cap;
- has different header flags, ignoring `FLAG_DEFER_COMMIT` (version,
  Gorilla, delta-dictionary mode);
- has a column whose type, or type parameter (decimal scale, geohash
  precision, array element type), differs from the same column already in
  the group;
- has a different designated-timestamp shape for the same table: the
  timestamp column versus server-assigned (`at_now`);
- does not continue the group's symbol dictionary range. This includes a
  dictionary that restarts at 0.

**As-is path.** These frames are sent unchanged, each as its own message:

- frames of at least 64 KiB, because merging no longer saves anything. Big
  row buffers, chunks and Arrow batches usually land here;
- frames without the delta-dictionary flag (the degraded full-dictionary
  mode).

**Backlog path.** If more than two frame caps of unsent bytes are queued
when a group is due, the I/O thread is falling behind. It then stops
merging and sends that group's frames unchanged. On the wire, each frame
carries its stored `FLAG_DEFER_COMMIT`. Every frame but the last also gets
the flag, so the server commits the group once. These extra flags are never
written to SF. Merging resumes once the backlog drains.

### 2.4 The merger

The merger lives in a new module, `ingress/sender/qwp_ws_merge.rs`.

1. **Decode.** Read each frame's table blocks into a reused
   `QwpWsColumnarBuffer`, the same buffer type that the row API fills. The
   buffer already keeps one table buffer per table name, sparse cells for
   missing columns, and per-column symbol dictionaries. Decoding covers
   every QWP wire type: fixed width, booleans, varchar and binary,
   symbols, Gorilla-encoded timestamps, decimals, geohash, UUID, long256
   and arrays.
2. **Symbols.** Each symbol ID is resolved to its string through the I/O
   thread's copy of the connection dictionary. That copy is a
   `SymbolGlobalDict`, updated from every frame's delta section in FSN
   order.
3. **Encode.** Use the existing encoder
   (`encode_ws_replay_message_with_defer`, `buffer/qwp.rs:3802`). Interning
   returns the same IDs, because every symbol is already in the
   dictionary. The encoder gains an explicit dictionary start: the delta
   section must carry exactly the entries the group's frames introduced,
   starting at the first frame's `delta_start`.
4. **Bulk append.** `QwpWsColumnarBuffer` gains a bulk append for decoded
   columns, so decoding does not go through the per-row API.

### 2.5 API

| Call | With batching on |
|---|---|
| `flush_buffer`, `flush_buffer_and_keep`, `flush_chunk`, `flush_arrow_batch_*`, `*_and_get_fsn` | Unchanged. `Ok` means the frame is in SF, and the FSN is known |
| **`commit()`** (new) | Makes every unsent frame up to this lease's last flushed frame due now. Returns without waiting |
| `wait`, `*_and_wait` | `commit()`, then wait as today |
| Return or drop of a lease | Unchanged. No I/O |

- **Rust:** `BorrowedSender::commit(&mut self) -> Result<()>`
- **C:** `qwp_sender_commit(qwp_sender*, line_sender_error**)`
- **C++:** `borrowed_sender::commit()`

`commit()` sets a per-connection "due through FSN" mark. With batching off,
it does nothing.

A transaction is one `Buffer`: add rows, `flush_buffer`, `commit()`. One
buffer is one frame, and a frame is never split across messages, so its
rows commit together, per table, up to the frame cap.

### 2.6 Acks and rejections

`InFlightRun` (`ingress/sender/qwp_ws_driver.rs:2828`) maps FSNs to wire
sequences with fixed arithmetic, assuming one frame per message. It becomes
a queue of `(wire_seq, first_fsn, last_fsn)`, one entry per message.

- **Ack.** An ack (OK or durable) of a message acks through its
  `last_fsn`. The SF queue trims as today. Deferred frames on the backlog
  path are covered by the ack of the group's last frame.
- **Rejection.** A rejected message applies the existing rejection policy to
  its whole FSN range. The error handler receives the range.
- **Symbol dictionary.** `dict_mirror.accumulate` and `guard_dict_not_torn`
  run on every message sent.

### 2.7 Unchanged

- The publish path, the SF format, recovery, replay and the reconnect
  catch-up. Replayed frames go through the same merging.
- Return, drop, reaping, close and drain.
- `SymbolDictFull` handling and the `Buffer` contract.

## 3. Invariants

1. Every row sent is already in SF. Nothing is held outside SF.
2. Each FSN is sent at most once per connection, inside exactly one
   message.
3. Wire order is FSN order.
4. A table appears at most once in a message.
5. A frame is never split across messages.

## 4. Limits

- **Visibility.** In streaming mode, rows become visible up to
  `commit_interval_ms` after the flush. Call `commit()` to send sooner.
- **Rejections.** A rejection covers the whole message, so every flush
  merged into it fails together.
- **Partial commits.** These are possible exactly as today with multi-table
  frames. The server commits a table as soon as it reaches
  `maxUncommittedRows`, so if a later table's block in the same message
  fails, the earlier tables may already be committed.
- **I/O thread CPU.** The I/O thread decodes and re-encodes small frames.
  Frames of 64 KiB or more skip the merge, and a backlog switches to the
  backlog path.

## 5. Code

- **`ingress/sender/qwp_ws_merge.rs` (new):** the frame decoder, grouping
  and the rules that end a group.
- **`ingress/buffer/qwp.rs`:**
  - bulk append of decoded columns into `QwpWsColumnarBuffer`;
  - an explicit dictionary start for the replay encoder.
- **`ingress/sender/qwp_ws_driver.rs`:**
  - the due rules and the "due through FSN" mark;
  - merging, the as-is path and the backlog path;
  - the in-flight message queue;
  - the I/O-side `SymbolGlobalDict`.
- **`ingress/sender/qwp_ws.rs`:** per-frame enqueue time and row count, and
  the timed wake.
- **`ingress/column_sender/sender.rs` (`PooledSenderCore`):**
  - `commit()`;
  - `wait` and `*_and_wait` set the mark.

  The C FFI calls this directly, so this also covers C and C++.
- **`db.rs`:** `BorrowedSender::commit`.
- **`db/conf.rs`:** the two keys.
- **`include/questdb/ingress/qwp_sender.h` / `.hpp`, `client.h`:**
  `qwp_sender_commit`, `borrowed_sender::commit()`, and the conf-key table.

## 6. Tests

**Decoder and merger**

- Round trip: encode a `Buffer`, decode it, encode it again. The two encodings
  must be byte for byte equal. Cover every column kind, sparse columns,
  nulls, symbols, the designated timestamp and `at_now`, and Gorilla.
- Merge: frames from several buffers, once merged, encode exactly like the
  same rows written into one buffer.
- Each rule that ends a group: cap, flag mismatch, type or type-parameter
  clash, timestamp shape, dictionary gap or restart.
- `FLAG_DEFER_COMMIT` on a merged message follows the last frame. On the
  backlog path, a stored flag is kept.

**Driver** (`QwpWsCoreTestHarness`, fake server)

- A group goes out as one message with one block per table, and its ack
  trims the whole range.
- A frame of 64 KiB or more goes out as-is, in order.
- The backlog path sends the group deferred except the last frame, so the
  server sees one commit.
- Reconnect replays and merges again. A rejection covers the whole range.
- The interval, `commit_rows`, `commit()` and close each make frames due.

**Pool** (`tests/qwp_sender_pool.rs`)

- One lease per message: about one message per interval.
- `commit()` sends now.
- Returning a lease leaves nothing behind.
- With `sf_dir`, frames flushed before a kill are delivered after a
  restart.

**Config**

- Defaults.
- `commit_rows` alone enables batching.
- A standalone `Sender` rejects the keys.

**C/C++:** `commit` exists, and the keys are accepted.

## 7. Plan

1. Decoder and bulk append, with round-trip tests.
2. Merger, with merge tests and the explicit dictionary start.
3. Driver: due rules, the three paths, the in-flight message queue, the
   I/O-side dictionary.
4. `commit()` in Rust, C and C++; the config keys.
5. Pool, C and C++ tests.
