# Pool auto-flush

**Problem:** one lease per message means one frame and one WAL commit per
message. The server's commit rate becomes the bottleneck.

**Fix:** `auto_flush=on` (off by default). The pool batches small flushes
from many leases into one frame and one commit.

## Behaviour

- `flush_buffer(&mut buf)` copies the rows into the slot's batch and clears
  `buf`.
- The batch is sent at 1000 rows, after 100 ms, or at 90% of the frame cap
  (`auto_flush_rows` / `_interval` / `_bytes`).
- If `buf` alone reaches a threshold, it is sent directly, without a copy.
- If `buf` would overflow the batch or clash with it on column types, the
  batch is sent first.
- A bad `buf` is an error for that caller only. The batch is untouched.
- **Force a commit:** `flush_buffer_and_get_fsn` (no wait),
  `flush_buffer_and_wait`, or `wait`. Each sends the batch now, even when
  `buf` is empty.
- Chunk and Arrow flushes send the batch first.
- **Return** does nothing. A background thread sends batches on idle slots
  when they are due, and never blocks on a full SF queue.
- **Drop or terminal error:** the batch goes into the slot's own SF queue
  first. If that slot can't take it (terminal, `SymbolDictFull`), another
  slot sends it.
- The reaper skips slots that hold a batch. Close sends all batches.

## Trade-offs (to document for users)

- `Ok` means "in the batch", in memory. With `sf_dir`, a crash loses up to
  about one interval of rows.
- A server rejection fails the whole batch.
- Rows on different slots can land up to about one interval apart, in
  either order.
- A lease that holds a slot without flushing holds back that slot's batch.

## Config

- Only the pool accepts these keys. Standalone and direct senders still
  reject them.
- A threshold key alone turns batching on. A threshold with
  `auto_flush=off` is an error. `auto_flush_interval=off` is rejected.

## Code

- `PooledSenderCore` (`column_sender/sender.rs`): the batch, flush and
  forced commits. FFI calls it directly, so this covers Rust, C and C++.
- `db.rs`: return, drop, reap and close hooks; background sending; the
  handoff list.
- `db/conf.rs`: parse the keys and strip them before
  `SenderBuilder::from_conf`.
- `buffer/qwp.rs`: `QwpWsColumnarBuffer::append_from`. It checks first, then
  copies. Symbol IDs are assigned at encode time, so merging never touches
  connection state.

## C/C++

No new functions. Update the doc comments in `qwp_sender.h` / `.hpp` and the
conf-key table in `client.h`. Add a Rust example and a C example.

## Steps

1. `append_from`, plus tests that a merged buffer encodes exactly like the
   same rows written directly.
2. Pool batching, plus Rust tests.
3. C/C++ docs, tests and example.
4. Benchmark: 1M rows, one lease per row, off vs on.
