# Pool Auto-Flush: Batching Rows Across Leases

**Status:** proposal

**Audience:** Rust core, C FFI and C++ wrapper reviewers

**Scope:** row `Buffer` ingestion through `QuestDb::borrow_sender()` (the
store-and-forward pool). Not covered: the standalone `Sender`, the direct
DataFrame sender, batching of chunks or Arrow batches, transactions or an
explicit `commit()`, and the Python client.

---

## 1. Summary

With `auto_flush=on`, the pool collects small flushes from many leases into
one frame, so the server commits once per batch instead of once per
message. Nothing changes for users who don't turn it on, and no new
functions are added in Rust, C or C++.

## 2. The problem

A common way to use the pool is one lease per message: read a message from
a queue, borrow a sender, write a few rows, flush, return.

```rust
for msg in queue {
    let mut s = db.borrow_sender()?;
    buf.table("trades")?.symbol("sym", &msg.sym)?.column_f64("px", msg.px)?.at(msg.ts)?;
    s.flush_buffer(&mut buf)?;
}
```

Each `flush_buffer` sends one frame, and the server commits each frame on
its own. One million messages mean one million WAL commits. Commits are the
expensive part, so the server's commit rate becomes the limit.

The rows written between borrow and return are not a transaction. The user
just wants them visible soon. Rows from many leases can therefore share one
commit without the user knowing or caring. Only the pool sees all the
leases, so the pool has to do the batching.

## 3. The idea

### 3.1 Terms

- **Slot**: one pooled connection and its store-and-forward (SF) queue.
- **Lease**: one `borrow_sender()`, from borrow to return.
- **Batch**: rows that callers handed to a slot but that are not encoded
  yet. It is a plain `Buffer` owned by the slot.
- **Send** (a batch): encode it into one frame and put the frame into the
  slot's SF queue. The existing SF machinery delivers it from there.

### 3.2 The picture

Each slot keeps one batch. `flush_buffer` copies the caller's rows into the
batch of the slot it is using, and returns. The batch goes out as one frame
when it is full or old enough.

```text
 caller buf ──flush_buffer──► slot batch ──send──► SF queue ──► server
   (copied, then cleared)     (one Buffer)  (1 frame,   (unchanged)
                                             1 commit)
```

With the default settings, one slot sees this:

```text
time     event                              batch on the slot
0 ms     lease A flushes 1 row              1 row
1 ms     lease B flushes 1 row              2 rows
...      ...                                ...
40 ms    lease X flushes the 1000th row     1000 rows -> sent: 1 frame, 1 commit
41 ms    lease Y flushes 1 row              1 row
         (traffic stops)
141 ms   background thread: batch is 100 ms old -> sent
```

### 3.3 Five rules

Every behaviour in §4 follows from these five rules:

1. **Rows from different callers meet only after each caller's buffer has
   passed every check.** So a caller's own mistakes are reported to that
   caller, right away.
2. **The batch can always be sent.** If adding a buffer would break the
   batch (too big, or a column type clash), the batch is sent first. So
   rows that other callers were told are accepted are never dropped because
   of someone else.
3. **A batch belongs to no connection until it is encoded.** So if its
   connection dies, the batch can move to another one.
4. **Any call that promises something about delivery sends the batch
   first.** So FSNs, acks and `wait` keep their current meaning.
5. **Returning a lease never blocks.** Leftover batches are sent by a
   background thread. So returns stay cheap, and the C++ destructor stays
   non-blocking.

## 4. How it works

### 4.1 Configuration

| Key | Default | Meaning |
|---|---|---|
| `auto_flush` | `off` | `on` turns on batching for the pool |
| `auto_flush_rows` | `1000` | Send when the batch holds this many rows. `off` removes this trigger |
| `auto_flush_interval` | `100` (ms) | Send when the oldest row in the batch has waited this long. Must be > 0 |
| `auto_flush_bytes` | 90% of the frame cap | Send when the batch's size estimate reaches this. Larger values are clamped to 90% of the cap. `off` removes this trigger; the cap itself still applies |

- **Frame cap.** This is the existing hard limit for one SF frame: the
  smallest of `max_buf_size`, the max batch size the server advertises, and
  the SF segment payload cap. Until the server's cap is known (async
  connect), 8 MiB is used. Stopping at 90% leaves room if the cap shrinks a
  little after a failover.
- **A threshold key alone turns batching on.** Combining a threshold key with
  `auto_flush=off` is a `ConfigError`.
- **`auto_flush_interval=off` is rejected.** Without an interval, an idle
  slot could hold its rows forever.
- **Only the pool accepts these keys.** The standalone `Sender` and the
  direct sender keep rejecting them, as today.

### 4.2 Handing rows over: `flush_buffer`

With `auto_flush=on`, `flush_buffer(&mut buf)` does this, in the caller's
thread:

```text
1. check buf (no row in progress, not over the frame cap, ...)
       fails -> error to the caller; nothing else changes          (rule 1)

2. if buf alone reaches a threshold:
       send the batch, then send buf as its own frame; clear buf
       -> big buffers are never copied; this is today's path

3. if batch + buf would pass the frame cap, or their column types clash:
       send the batch first                                          (rule 2)

4. copy buf's rows into the batch; clear buf (buf keeps its capacity)

5. if the batch now reaches a threshold, or its oldest row is
   at least auto_flush_interval old:
       send the batch
```

- `flush_buffer_and_keep` does the same, but does not clear `buf`.
- An empty `buf` does nothing, as today.

### 4.3 When a batch is sent

A batch is sent at the first of:

1. a `flush_buffer` that makes it reach a threshold (§4.2);
2. a forced commit (§4.4);
3. the background thread finding it due (§4.5);
4. its slot being dropped, retired or closed (§4.6).

### 4.4 Forcing a commit

Batching is automatic, but the user can always force a commit when they
choose to. Row frames are never deferred, so sending a frame commits it.
"Force a commit" therefore means "send the batch now". These calls do that
(rule 4):

| To ... | Rust | C |
|---|---|---|
| Commit now, without waiting | `flush_buffer_and_get_fsn`, `flush_buffer_and_keep_and_get_fsn` | `qwp_sender_flush_buffer_and_get_fsn`, `qwp_sender_flush_buffer_and_keep_and_get_fsn` |
| Commit now and wait for the server's ack | `flush_buffer_and_wait` | `qwp_sender_flush_buffer_and_wait` |
| Commit what is pending on the slot, and wait | `wait` | `qwp_sender_wait` |

- `buf` joins the slot's batch, and the whole batch is sent now, as one
  frame. The commit includes rows that other leases left on the same slot.
  That keeps the rows on the slot in order.
- With an empty `buf`, these calls still send the batch. `*_and_get_fsn`
  returns that frame's FSN, or `None` if there was nothing to send.
- The FSN and the ack refer to that frame. `wait` covers it because the
  frame was sent through this lease.
- Chunk and Arrow flushes (`flush_chunk*`, `flush_arrow_batch_*`) also send
  the batch first, then the chunk, so rows on the slot stay in order.

`published_fsn()` and `acked_fsn()` describe the connection, so they move
only when the batch is sent.

### 4.5 The background thread

A returned slot can still hold a batch. Nobody may block on return
(rule 5), so a background thread sends it:

- **When it wakes.** The pool already wakes this thread on every return. It
  looks at the idle slots (at most `sender_pool_max` of them), finds the
  earliest batch due time, and sleeps until then. Rows on an idle slot
  therefore wait about `auto_flush_interval`, not twice that.
- **How it sends.** It takes one idle slot off the free list, as a borrower
  would, sends the batch outside the pool lock, and puts the slot back.
- **It never waits for queue space.** It publishes with a zero append
  deadline. If the SF queue is full, it puts the slot back and tries again
  on the next wake, so one stuck slot cannot hold up the others. If the SFA
  publisher has no non-blocking mode, this work adds one.
- **It also runs with `pool_reap=manual`.** It runs whenever `auto_flush=on`.
  Reaping still follows `pool_reap`.

### 4.6 Return, drop, reaping and close

| Event | Today | With `auto_flush=on` |
|---|---|---|
| Healthy lease returned (Rust drop, `questdb_db_return_sender`, C++ destructor) | Back to the free list, no I/O | Same. The batch stays on the slot (rule 5) |
| Idle slot reaped | When idle and fully delivered | A batch counts as undelivered: it is sent first, and the slot is reaped later |
| `drop_on_return()` / `questdb_db_drop_sender`, or a terminal slot returned | Bounded drain, then drop | Send the batch into the slot's **own** SF queue, then the same bounded drain. If that fails, hand the batch off (§4.7) |
| Pool closed (`QuestDb` drop, `questdb_db_close`) | Stop the reaper, drain idle slots under one shared deadline | Stop the thread, send every idle batch, try the handed-off batches, then drain as today |
| Lease returned after close (C only) | Treated as a drop | Same as a drop above |

Why a dropped slot sends its batch into its own queue first: once there,
the batch is just more queued frames, and queued frames already have rules.
In memory mode they are delivered within the bounded drain or lost. In disk
mode they stay in the slot directory and are replayed later. So a batch is
never treated worse than frames that were already queued.

### 4.7 When a connection can't send its batch

Sometimes a slot cannot send its own batch:

- the connection hit a terminal error (including `StoreResendRequired`);
- its symbol dictionary is full (`SymbolDictFull`). This one is common:
  long-lived connections with many distinct symbols do fill up.

The batch is not encoded yet, so it does not belong to that connection
(rule 3). It moves to a short list on the pool instead of being lost. The
background thread sends each one through the next healthy idle slot, as its
own frame. At close, these batches get one try within the close deadline;
rows still left are logged at ERROR with their count.

One case is not covered. A batch built for one server's frame cap can be
sent, after a failover, to a server with a much smaller cap. The 90% margin
absorbs small differences. If the cap shrinks more than that, the batch is
dropped and logged at ERROR.

## 5. What each call means, and who hears about errors

### 5.1 Calls

| Call | `auto_flush=off` (default) | `auto_flush=on` |
|---|---|---|
| `flush_buffer` | Encode into the SF queue, clear `buf` | Copy into the slot's batch and clear `buf`. A big `buf` is sent on its own, right after the batch |
| `flush_buffer_and_keep` | As today | As above, without clearing `buf` |
| `*_and_get_fsn`, `*_and_wait` | As today | `buf` joins the batch, which is sent now; the FSN and ack refer to that frame |
| `flush_chunk*`, `flush_arrow_batch_*` | As today | Send the batch, then as today |
| `wait` | As today | Send the batch, then wait |
| Healthy lease returned or dropped | No I/O | No I/O; the batch stays on the slot |
| Force-drop, or terminal lease returned | Bounded drain | Send the batch into its own queue, then bounded drain; hand it off if that fails |
| Pool closed | Drain idle slots | Send all batches, then drain |

### 5.2 Errors

| What went wrong | Who is told | Rows lost |
|---|---|---|
| The caller's buffer is invalid (row in progress, etc.) | The caller, immediately. `buf` untouched | None |
| The caller's buffer alone is over the frame cap | The caller, immediately (`BatchTooLarge`). `buf` untouched | None |
| The caller's buffer clashes with the batch (types, size) | Nobody. The batch is sent first | None |
| The SF queue is full while the caller's flush sends the batch | The caller, same back-pressure error as today. `buf` untouched, batch kept | None |
| The connection turned terminal | The caller, same error as today. The batch is handed off | None |
| The server rejects a batch frame | The error handler, later, as today | **The whole batch** |
| A batch cannot be sent anywhere by close | ERROR log with the row count | That batch |

Only the "server rejects a batch frame" row is new. Batching makes one bad
row fail its whole frame, which now holds rows from many leases.

## 6. What users give up

The user docs must say these plainly.

1. **`Ok` means "in the batch".** It no longer means "in the SF queue". With
   `sf_dir`, `Ok` used to mean the frame was written to the SF files and
   would survive a process crash. With batching, up to about one
   `auto_flush_interval` of rows lives only in memory. For per-message
   durability, keep `auto_flush=off`, or force a commit (§4.4) for those
   messages.
2. **One bad row fails its batch.** The server rejects the whole frame, so
   rows from every lease in that batch fail. The error handler sees one
   rejection, possibly after those leases have returned.
3. **Order across connections loosens.** Rows on one slot keep their order.
   Rows on different slots were never ordered, but they used to land about
   one round trip apart. Now they can land up to about
   `auto_flush_interval` apart, in either order. On dedup/upsert tables,
   write a stream through one lease, or force a commit, when order
   matters.
4. **`flush_buffer` may not commit right away.** Force a commit (§4.4)
   when you need one.
5. **A lease that keeps a slot holds that slot's batch back.** The
   background thread only touches idle slots. If a lease keeps a slot for a
   long time without flushing, rows that earlier leases left there wait
   until its next `flush_buffer` or forced commit.

## 7. Implementation

### 7.1 Where the code goes

- **`ingress/column_sender/sender.rs` (`PooledSenderCore`, SFA backend):**
  the batch, `flush_buffer` and the forced-commit calls. The C FFI calls
  `PooledSenderCore` directly (through `OwnedSender`, not
  `BorrowedSender`), so this one place covers Rust, C and C++.
- **`db.rs`:** the hooks for return, drop, reaping and close; the
  background thread (it reuses the reaper thread and the pool condvar,
  `db.rs:3103-3124`); the list of handed-off batches in `DbInner`.
- **`db/conf.rs`:** parse the four keys and remove them from the string
  passed to `SenderBuilder::from_conf` (`db.rs:828`), which keeps rejecting
  them for standalone senders.
- **`ingress/buffer/qwp.rs`:** `append_from` (§7.2).

Sending always goes through the existing publish path,
`SfaForegroundPublisher::encode_persist_publish`. It encodes, checks the
size, writes the symbols ahead and appends the frame in one step, and it
rolls the symbol dictionary back if the append fails.

### 7.2 Merging buffers

```rust
impl QwpWsColumnarBuffer {
    /// Checks first, then copies; a failed check changes nothing.
    pub(crate) fn append_from(&mut self, other: &Self) -> Result<()>;
}
```

The columnar buffer stores each column as sparse cells,
`QwpWsCell { row_idx, value }`. Merging is mostly bookkeeping:

1. For each table in `other`, find or create the table in `self`.
2. For each column, find it in `self` (case-insensitive, like
   `lookup_column`) or create it. A different `ColumnKind`, including for
   the designated timestamp, is a clash: the check fails and nothing is
   touched.
3. Append `other`'s cells with `row_idx + self.row_count`.
4. Re-add symbol values to `self`'s per-column dictionary.
5. Update the row count and the size estimate.

Connection-wide symbol IDs are assigned only when a frame is encoded. So
merging never touches the connection's symbol state, which is what makes
rule 3 possible.

Two existing buffer behaviours matter here:

- **`clear()` keeps each table's columns** (`qwp.rs:3941-3950`). After a
  type clash, a cleared batch would clash again, so the batch starts from a
  fresh buffer instead.
- **The encoder writes every known column** of a table that has rows. A
  column used by an earlier batch but not by this one goes out as all-null.
  This is accepted for now; skipping such columns is a follow-up.

### 7.3 Cost

Each small message's rows are copied one extra time, into the batch. In
return, encoding, the SF append, the WebSocket frame, the server parse and
the commit happen once per batch instead of once per message. Big buffers
are not copied at all (§4.2 step 2). The benchmark in §9 measures the copy.

## 8. C and C++

**API.** No new functions. `qwp_sender_flush_buffer*`, `qwp_sender_wait`,
`questdb_db_return_sender` and `questdb_db_drop_sender` behave as in §5.1.
The conf-key table in `include/questdb/client.h:82-110` gains the four
`auto_flush*` keys.

**Errors at close.** `questdb_db_close` returns `void`, and the C++ `pool`
destructor is `noexcept`. Errors while sending the last batches go to the
log and, for server rejections, to the error handler. Close-time drain
errors work the same way today.

**Doc comments to update.** Each one gets a short "with `auto_flush=on`"
note:

- `qwp_sender.h:86-89`: "the store-and-forward queue owns delivery".
- `qwp_sender.h:192-200` (return): "Returning is safe". Still true; the pool
  sends the batch.
- `qwp_sender.h:215-225` (drop): a later borrower sending earlier rows
  together with its own is now intended. The warning about lost frames
  also covers the batch.
- `qwp_sender.h:365`, `qwp_sender.h:1521-1522`: "after local
  store-and-forward acceptance" becomes "accepted into the batch".
- `qwp_sender.h:1661-1664` (`wait`): `wait` sends the batch before its
  "published nothing" check.
- `qwp_sender.h:876-895` (symbol dictionary full): retiring the connection
  hands the batch off.
- `qwp_sender.hpp:1152-1154`, `1232`, `1486-1492`: the same points on
  `borrowed_sender`.
- `client.h:132-135` (close): batches on slots still leased at close are
  sent when those leases return.

**Examples.** Add one Rust and one C example of a one-lease-per-message
consumer with `auto_flush=on`. Register them in `questdb-rs/Cargo.toml` and
`CMakeLists.txt`.

**Docs.**

- `doc/CONSIDERATIONS.md:43-46` and `:83-93`: point to `auto_flush=on` for
  the one-lease-per-message pattern.
- `README.md` and `questdb-rs/README.md`: mention it in the pool snippet.
- Update the external conf-key docs linked from `doc/C.md` and `doc/CPP.md`.

## 9. Tests, benchmark and plan

**Buffer merge (Rust unit tests)**

- Merged buffers encode byte for byte like the same rows written into one
  buffer. Cover every column kind, sparse columns, symbols, the designated
  timestamp and `at_now`.
- A failed check leaves both buffers unchanged.

**Pool (`tests/qwp_sender_pool.rs`, mock server)**

- One lease per message, 10k rows: about rows / 1000 frames.
- An idle slot sends its batch about `auto_flush_interval` after the last
  return.
- Forced commits: `*_and_get_fsn` sends at once and FSNs stay in order;
  an empty `buf` still sends the batch;
  `wait` covers batched rows; a chunk after batched rows keeps row order.
- A type clash sends the batch and the caller's flush succeeds. An
  oversized caller buffer fails and leaves the batch intact. No batch
  exceeds the cap.
- Lifecycle: a dropped or terminal slot sends into its own queue;
  `SymbolDictFull` and terminal slots hand the batch off, and it arrives
  through another slot; the reaper skips slots with batches; close sends
  everything.
- The background thread does not wait when an SF queue is full.

**Config (`db/conf.rs` tests)**

- Defaults.
- A threshold key implies `on`.
- A threshold key with `off` is an error.
- `auto_flush_interval=off` is rejected.
- `Sender::from_conf` still rejects the keys.

**C/C++ (`cpp_test/test_column_sender.cpp`)**

- The config is accepted.
- Batching shows in the mock's frame count.
- The `borrowed_sender` destructor stays non-blocking.
- Close sends everything.

**System test.** One lease per row against a real server: every row lands,
and the WAL commit count is about rows / 1000.

**Benchmark.** 1M rows, one lease per row, `auto_flush` off vs on, with the
default and `sync` commit modes. Profile the share of client CPU spent on
the copy.

**Plan**

1. Buffer merge: `append_from` and its equivalence tests.
2. Pool batching: config, `flush_buffer`, forced commits, background
   thread, return/drop/reap/close hooks, handoff; Rust tests.
3. C/C++: header docs, the conf-key table, C++ tests, the C example.
4. Benchmark and system test; update the docs listed in §8.

**Follow-ups (not in the first version)**

- Skip all-null columns when encoding (§7.2).
- Report client-side drops through the error handler, not only the log.
- An owned-buffer `flush_buffer` variant, only if the benchmark shows the
  copy matters.
