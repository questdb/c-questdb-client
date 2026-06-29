# Column Sender ACK Boundary Flush Design

**Status:** draft
**Audience:** Rust core, C FFI, C++ wrapper, Python dataframe integration
engineers
**Scope:** move common ACK boundaries closer to column-sender `flush*` calls
without breaking the existing pipelined publish-only APIs

---

## 1. Problem

The column sender currently exposes two separate operations:

- `flush*`: encode and publish a QWP/WebSocket frame.
- `sync(AckLevel)`: create or observe a server-side completion boundary and
  wait for the requested ACK level.

This split is efficient, but it is easy to misuse. A caller can successfully
flush data, return the borrowed sender, and never ask for a server completion
boundary. That is especially surprising for dataframe-shaped APIs where the
natural user model is "send this batch and return when it is committed".

The proposed improvement is to let callers attach an ACK wait to a flush call
when the flushed batch is the intended boundary.

---

## 2. Current Behavior

### 2.1 Direct QWP/WebSocket mode

Direct mode is backed by `ColumnConn`.

- The first frame on a physical connection is non-deferred.
- Later no-wait flushes are sent with QWP's `FLAG_DEFER_COMMIT`.
- `sync(AckLevel)` sends an empty non-deferred commit frame, then waits until
  all in-flight frames reach the requested ACK level.
- The connection keeps one in-flight slot reserved for the later `sync()`
  commit frame.

This gives high throughput because callers can pipeline many data frames and
pay one blocking wait.

### 2.2 Store-and-forward mode

Store-and-forward mode is backed by the QWP/WebSocket SFA queue and background
sender.

- Every columnar frame is already non-deferred.
- `flush*` success means local queue acceptance, not server commitment.
- `sync(AckLevel)` waits until the queue boundary observed at sync entry
  reaches the requested OK or durable watermark.

### 2.3 High-level dataframe APIs

Two dataframe helpers already behave as completion-owning APIs: they flush one
or more batches, then call `sync(AckLevel::Ok)` before returning.

- The Rust polars helper checkpoints on sync: it advances its committed marker
  only after a successful `sync(Ok)` and replays from that marker on failover.
- The Python `Client.dataframe` helper (separate `py-questdb-client` repo)
  flushes batches and ends with one `sync(Ok)`, but does *not* checkpoint: on
  failover it replays the whole frame. Its mid-stream `sync(Ok)` (every N
  deferred Arrow frames) is backpressure, not a replay boundary.

So "sync as a replay boundary" describes the Rust helper; the Python helper uses
sync only as a completion/backpressure wait.

---

## 3. Goals

- Make the common safe API shape one call: publish this batch and wait for
  the requested completion level.
- Preserve the current publish-only fast path for users that intentionally
  pipeline many batches.
- Keep `AckLevel` focused on ACK strength: `Ok` versus `Durable`.
- Avoid a new `AckLevel::None`; "wait or do not wait" is a separate policy.
- Avoid ABI breaks in C.
- Apply the model consistently to manual chunks and Arrow RecordBatch flushes.
- Keep `sync(AckLevel)` as a first-class operation for draining already
  published work.
- Make the failure contract explicit enough that callers can reason about
  retry and duplicate-delivery risk.

---

## 4. Non-goals

- No change to the default behavior of existing `flush*` functions.
- No exactly-once guarantee. ACK wait failures can leave delivery uncertain.
- No new wire protocol.
- No removal of `sync()`.
- No per-call timeout knob in this design. The existing `request_timeout`
  remains the wait/no-progress bound.

---

## 5. Proposed API Model

The conceptual model is:

```text
flush(batch)                      -> publish only
flush_and_wait(batch, AckLevel)   -> publish batch as a boundary, then wait
sync(AckLevel)                    -> wait/commit already-published work
```

### 5.1 Rust

Add explicit methods instead of optional arguments:

```rust
sender.flush(&mut chunk)?;
sender.flush_and_wait(&mut chunk, AckLevel::Ok)?;
sender.flush_and_wait(&mut chunk, AckLevel::Durable)?;

sender.flush_arrow_batch_at_now(table, &batch, overrides)?;
sender.flush_arrow_batch_at_now_and_wait(
    table,
    &batch,
    overrides,
    AckLevel::Ok,
)?;

sender.flush_arrow_batch_at_column(table, &batch, ts_col, overrides)?;
sender.flush_arrow_batch_at_column_and_wait(
    table,
    &batch,
    ts_col,
    overrides,
    AckLevel::Ok,
)?;
```

Rationale: Rust has no optional arguments, and explicit method names keep the
blocking behavior visible.

### 5.2 C ABI

Add new entry points. Do not change existing function signatures:

```c
bool column_sender_flush_and_wait(
    column_sender* conn,
    column_sender_chunk* chunk,
    uint32_t ack_level,
    line_sender_error** err_out);

bool column_sender_flush_arrow_batch_at_now_and_wait(
    column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    uint32_t ack_level,
    line_sender_error** err_out);

bool column_sender_flush_arrow_batch_at_column_and_wait(
    column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    line_sender_column_name ts_column,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    uint32_t ack_level,
    line_sender_error** err_out);
```

The `uint32_t` ACK level follows the existing `column_sender_sync` pattern so
out-of-range values can return `line_sender_error_invalid_api_call`.

### 5.3 C++

Mirror the Rust naming with an `_and_wait` suffix rather than overloading the
publish-only names:

```cpp
conn.flush(chunk);                                   // publish only
conn.flush_and_wait(chunk, column_sender_ack_level::ok);
conn.flush_and_wait(chunk, column_sender_ack_level::durable);

conn.flush_arrow_batch_at_now(table, array, schema, overrides, n);
conn.flush_arrow_batch_at_now_and_wait(
    table, array, schema, column_sender_ack_level::ok, overrides, n);

conn.flush_arrow_batch(table, array, schema, ts_column, overrides, n);
conn.flush_arrow_batch_and_wait(
    table, array, schema, ts_column, column_sender_ack_level::ok, overrides, n);
```

The new methods call the new C ABI functions; existing methods remain
publish-only. Distinct names (not an extra argument on the existing methods)
keep the blocking behavior visible in every language and avoid a silent
downgrade: with overloads, dropping `ack_level` from an Arrow call would still
compile as a publish-only flush, because the enum and the trailing `overrides`
pointer do not collide. The `_and_wait` suffix makes that a compile error
instead.

---

## 6. Semantics

### 6.1 Boundary scope

An ACKing flush waits through all work published before or by that call on the
same borrowed sender.

Example:

```text
flush(A)
flush(B)
flush_and_wait(C, Ok)
```

The successful `flush_and_wait(C, Ok)` boundary covers `A`, `B`, and `C`.

This is intentional. QWP ACKs are ordered/cumulative at the connection level,
and SFA waits by frame sequence boundary.

### 6.2 ACK validation preflight

Every ACKing flush must validate the requested ACK level before doing anything
that can consume caller-owned input or publish a frame.

This includes:

- parsing the C ABI `uint32_t` ACK level and rejecting out-of-range values;
- validating `AckLevel::Durable` against the connection's durable-ACK opt-in;
- doing both checks before Arrow C Data Interface import consumes
  `array->release`;
- doing both checks before chunk/batch encode can mutate sender-side symbol
  state;
- doing both checks before direct socket write or SFA local queue append.

If ACK validation fails, the failure is always pre-publication:

- no frame is published;
- manual chunks remain untouched;
- Arrow `ArrowArray` / `ArrowSchema` ownership remains with the caller exactly
  as it was on entry;
- the error is `invalid_api_call`.

This mirrors the current `sync()` ordering, where durable opt-in is validated
before the empty commit frame is sent.

The preflight dispatches per backend, not as one shared call: direct mode
already has a standalone gate (`validate_ack_level`), but the SFA durable check
currently lives *inside* `sync()` and must be lifted ahead of encode/import for
`_and_wait`. If it is not, the Arrow import consumes `array->release` before the
ACK level is rejected — exactly the ordering this section forbids.

### 6.3 Direct mode

For direct mode, an ACKing flush should publish the data-bearing frame as
non-deferred and then wait for ACKs:

```text
validate ack_level and durable opt-in
encode chunk/batch with defer_commit = false
publish frame
push pending FSN
wait with sync_all_acks(ack_level)
```

This avoids the extra empty non-deferred commit frame that `sync()` uses today
when the caller already has a final data-bearing batch.

No-wait `flush*` keeps the current deferred behavior and the current
`first_frame_sent` behavior.

### 6.4 Store-and-forward mode

For SFA mode, an ACKing flush should:

```text
validate ack_level and durable opt-in
encode replay payload
append/publish payload to local SFA queue
capture the resulting local published FSN boundary
wait until OK or durable watermark reaches that boundary
```

`flush_and_wait(..., Ok)` in SFA mode therefore means server OK ACK, not merely
local queue acceptance.

The per-frame FSN needed for the boundary is already returned by the local
publish call (today the `Ok` value is discarded); `_and_wait` must capture it.
On success, write the satisfied boundary back to the cached sync watermark so a
trailing `sync(level)` short-circuits instead of re-polling.

### 6.5 `sync()` and `flush_and_wait()` together

`sync(AckLevel)` remains necessary because callers can have no current batch
to attach a boundary to:

- final drain after many no-wait flushes;
- empty dataframe / no yielded batches;
- compatibility with existing direct and C callers;
- explicit "wait for whatever is already published" workflows.

Two interactions are defined explicitly:

- **Empty chunk:** `flush_and_wait(empty_chunk, level)` behaves exactly like
  `sync(level)`. An empty chunk already encodes a header-only frame, which is
  what `sync()` sends, so the two collapse to the same operation rather than
  being rejected.
- **`sync()` after `flush_and_wait`:** still valid and still safe. In direct
  mode it publishes a fresh empty commit frame and waits again (a redundant
  round-trip, not a no-op); in SFA mode it is a cheap re-check. Callers that
  always end with `sync()` therefore stay correct, just slightly less efficient
  than ending on the ACKing flush.

### 6.6 Best-effort commit on drop / pool return

Dropping a borrowed or owned sender (directly or via a C++ RAII destructor)
that still holds un-sync'd deferred frames runs a single best-effort
`sync(AckLevel::Ok)` so the common "loop `flush()`, then drop" path does not
silently lose its tail. This is best-effort only and **not** a substitute for
an explicit `sync()` / `flush_and_wait()`:

- it can block the dropping thread up to `request_timeout` while the commit
  round-trip completes;
- on failure (or an already-dead transport) the connection is discarded rather
  than recycled, the deferred data is lost, and the loss is logged at `warn`.

Failover (`reborrow_from_pool`) does not run this commit — it discards the dead
connection's un-sync'd window and logs it; re-drive from the last successful
`sync()`.

---

## 7. Failure Contract

ACKing flush has two phases:

```text
phase 1: encode/publish
phase 2: wait for ACK level
```

The public contract must distinguish these cases conservatively.

### 7.1 Current input versus boundary state

"Not published" is scoped only to the current input passed to the ACKing flush.
It does not say that the whole boundary is clean.

An ACKing flush waits through all prior no-wait frames on the same borrowed
sender. It may also inspect prior work before publishing the current input:

- direct mode drains/checks already-ready ACKs before encode/publish;
- SFA mode checks background sender errors before local queue append.

Therefore a not-delivered failure can still report a problem with earlier frames
in the boundary. The current chunk or Arrow batch remains retryable according to
the rules below, but prior frames may already be committed, rejected, or
delivery-unknown. Low-level `_and_wait` must not imply an all-boundary rollback.

In particular, when the not-delivered failure is a transport error (the
connection is now `must_close`), the current input is safe to retry but the
whole borrow is dead: the caller must drop/reborrow and re-drive its entire
uncommitted tail, not just resend the one input.

### 7.2 Current input not delivered

If the call fails before any byte of the current frame can have reached the
server, the failure is provably pre-transmission:

- manual chunk remains untouched;
- caller can inspect, clear, free, or retry the chunk;
- Arrow ownership follows the existing pre-import/import failure rules;
- if an Arrow `RecordBatch` was imported and the failure is retryable, the C ABI
  may re-export the batch back into the caller's `ArrowArray` so the caller can
  retry with a fresh connection.

Examples:

- invalid chunk;
- invalid ACK level or durable ACK requested without opt-in;
- unsupported Arrow type;
- payload too large;
- prior-frame rejection or transport failure observed before the current input
  is encoded or written;
- SFA local append failure that is known not to have accepted the current
  frame.

### 7.3 Current input delivery unknown

If the current frame's bytes may have reached the server — whether the write
fully succeeded, partially succeeded, or the ACK wait failed afterwards:

- manual chunk is cleared once publication succeeds; a *partial write* that
  fails mid-frame returns before the chunk is cleared and so leaves it
  populated (per the publish-only clearing rule, §7.4) — but the data is still
  delivery-unknown, so chunk state is not a "safe to retry" signal;
- Arrow array has already been consumed according to the flush contract;
- delivery is uncertain; the failure flags the error `in_doubt` (surfaced via
  `Error::in_doubt` / `line_sender_error_in_doubt`) so publish-only callers can
  detect it without inspecting the error code;
- C Arrow functions (both `_and_wait` and publish-only) must not re-export the
  input `ArrowArray`, even if the failure is reported as `FailoverRetry`;
- retry can duplicate rows unless table-level dedup/upsert keys make replay
  safe;
- the borrowed sender should be treated according to the error class
  (`must_close`, drop/reborrow, or terminal rejection).

Examples:

- a direct socket write or flush that fails mid-frame (bytes may already be on
  the wire, the connection is latched `must_close`);
- direct socket read timeout while waiting for ACK;
- direct transport death after the write succeeded;
- SFA no-progress timeout waiting for the boundary;
- server-side error observed for the boundary.

The first example is the important one: a direct-mode partial write returns the
same `FailoverRetry` class as a clean pre-write failure, but the current input
is *not* safe to retry. Delivery certainty — not "did `publish` return `Err`" —
is what decides re-exportability (see 7.5).

Pool-safety invariant: a delivery-unknown failure must leave the connection
latched (`in_flight > 0` / `must_close`) so that pool return and reborrow discard
it rather than recycle a half-committed connection to the next borrower. A
successful ACKing flush drains in-flight to zero and recycles cleanly. Do not
"tidy up" in-flight state on the error path.

The error text should make the phase clear. The API should not promise that a
failed ACKing flush leaves the input retryable once delivery is unknown.

### 7.4 Chunk clearing rule

For manual chunks:

- publish-only `flush()` keeps today's rule: clear only on successful publish.
- ACKing `flush_and_wait()` clears once publish succeeds, even if the later ACK
  wait fails.

This is the least surprising memory-lifetime rule: after bytes have been put
on the wire or accepted into SFA, the caller buffers should no longer be
required for completion or replay.

### 7.5 Phase-aware Arrow ownership

The C Arrow `_and_wait` implementation must not decide re-exportability from
`ErrorCode::FailoverRetry` alone.

Today, `arrow_batch_impl` re-exports the imported `RecordBatch` back into the
caller's `ArrowArray` for any `FailoverRetry`, because existing
publish-only Arrow flushes treat that code as "retry on another connection".
That rule is not safe for ACKing flushes: a direct ACK timeout or SFA
no-progress timeout can also be `FailoverRetry` after the frame has already
been published locally or written to the socket. Re-exporting then would invite
the caller to retry a delivery-unknown batch.

The fix is to have the Rust flush primitive tell the FFI layer whether the
current input was delivered, instead of letting the FFI infer it from the error
code:

```rust
enum FlushFailure {
    /// The current input was provably NOT transmitted (validation, encode,
    /// size check, or a transport error before any byte was written).
    NotDelivered(crate::Error),
    /// The current input may have reached the server: write succeeded,
    /// partially succeeded, or the post-write ACK wait failed.
    DeliveryUnknown(crate::Error),
}
```

The distinction is delivery certainty of the *current input*, not "did the
publish call return `Err`". A direct-mode `write_all`/`flush` error is
`DeliveryUnknown`, not `NotDelivered`, because bytes may already be on the wire.

The FFI rule is then simple and does not inspect the error code:

- `NotDelivered`: re-export Arrow input if the existing Arrow ownership rules
  allow it. This does not imply prior frames in the boundary are retryable or
  uncommitted.
- `DeliveryUnknown`: never re-export; set the error and document delivery as
  unknown.

This signal is required for both direct and SFA backends. SFA local append is
atomic (accepted or not), so it maps cleanly; direct mode must classify its
write/flush failures as `DeliveryUnknown` even when they look like ordinary
retryable transport errors.

---

## 8. Internal Integration

Use one internal implementation shape instead of duplicating logic:

```rust
enum WaitForAck {
    No,
    Yes(AckLevel),
}
```

or equivalently `Option<AckLevel>`.

For `WaitForAck::Yes(level)`, ACK validation is a preflight step. It must run
before manual chunk encode and before Arrow import. In the C ABI path, that
means `_and_wait` entry points parse the integer ACK level and validate durable
opt-in before calling the shared Arrow import helper that can consume
`ArrowArray.release`. The durable check is per backend: direct mode reuses its
existing `validate_ack_level` gate, while SFA's check must be lifted out of
`sync()` so it runs before encode/import.

Manual chunk path:

```rust
ColumnSender::flush_inner(chunk, WaitForAck::No)
ColumnSender::flush_inner(chunk, WaitForAck::Yes(level))
```

Arrow path:

```rust
ColumnSender::flush_arrow_batch_inner(..., WaitForAck::No)
ColumnSender::flush_arrow_batch_inner(..., WaitForAck::Yes(level))
```

Direct backend:

- `WaitForAck::No`: current behavior.
- `WaitForAck::Yes(level)`: validate ACK preflight, publish with
  `defer_commit = false`, then `sync_all_acks(level)`.
- classify a write/flush failure as `DeliveryUnknown` (bytes may be on the
  wire), and a `sync_all_acks(level)` failure after a successful publish as
  `DeliveryUnknown`; only pre-write failures are `NotDelivered`.

SFA backend:

- `WaitForAck::No`: current behavior.
- `WaitForAck::Yes(level)`: validate ACK preflight, publish to local queue,
  capture the returned FSN, then wait to that boundary.
- local append is atomic: a failed append is `NotDelivered`; any failure after a
  successful append (including the boundary wait) is `DeliveryUnknown`.

FFI layer:

- keep `column_sender_flush` and `column_sender_flush_arrow_batch_*` as wrappers
  passing `WaitForAck::No`;
- add `_and_wait` functions passing `WaitForAck::Yes(level)`;
- parse the C ACK level and validate durable opt-in before Arrow import,
  manual chunk encode, or publication;
- re-export Arrow input only when the flush primitive reports `NotDelivered`;
- keep `column_sender_sync` unchanged.

---

## 9. Dataframe Integration

The dataframe helpers can use ACKing flushes for checkpoint boundaries.

Today:

```text
for each batch:
  flush_arrow_batch_*(batch)
  every N batches:
    sync(Ok)
final sync(Ok)
```

Possible migration:

```text
for each batch:
  if this batch is a checkpoint boundary:
    flush_arrow_batch_*_and_wait(batch, Ok)
    mark checkpoint committed
  else:
    flush_arrow_batch_*(batch)
after loop:
  sync(Ok) if the last batch was not an ACKing boundary
```

For the Rust helper this preserves checkpoint-on-sync replay (the committed
marker still advances only after a successful boundary). For the Python
`Client.dataframe` helper, which replays the whole frame on failover rather than
checkpointing, the win is different: folding the periodic backpressure
`sync(Ok)` into the boundary flush removes one empty commit frame per checkpoint
and, because the boundary flush drains in-flight to zero, can retire the
separate "deferred capacity exhausted" retry path entirely.

The throughput effect is modest (one fewer empty frame per checkpoint interval),
so treat this migration as a clarity/robustness change, not a performance one.

For empty dataframes or iterators that yield no batches, the helper still needs
`sync(Ok)` or a no-op completion path, because there is no batch to attach a
boundary to.

---

## 10. Testing Plan

The Rust direct/SFA cases apply to both manual chunks and Arrow RecordBatch
ACKing flushes. Chunk untouched/cleared assertions are manual-chunk-specific;
Arrow ownership is covered by the C ABI contract below.

### 10.1 Rust direct mode

- `flush_and_wait(chunk, Ok)` publishes a non-deferred data frame and returns
  only after OK ACK.
- `flush_and_wait(chunk, Durable)` rejects unless durable ACK was negotiated.
- durable-without-opt-in publishes no frame and leaves the chunk untouched.
- `flush(A); flush_and_wait(B, Ok)` waits for both frames.
- `flush_and_wait` needs no separate commit frame: it publishes one
  non-deferred data frame and drains all in-flight to zero. It never trips the
  reserved-slot guard, which only gates deferred flushes.
- ACK wait timeout after publication clears the chunk and returns
  `FailoverRetry`.

### 10.2 Rust SFA mode

- `flush_and_wait(chunk, Ok)` waits for the local SFA boundary to reach the OK
  watermark.
- `flush_and_wait(chunk, Durable)` waits for durable watermark and rejects
  without `request_durable_ack=on`.
- durable-without-opt-in appends no local SFA frame and leaves the chunk
  untouched.
- Timeout after local queue acceptance leaves queued frames replayable and
  clears the chunk.
- Server rejection inside the waited range is surfaced by the ACKing flush.

### 10.3 C ABI

- NULL conn/chunk and invalid ACK level return `invalid_api_call`.
- Existing `column_sender_flush` ABI and behavior remain unchanged.
- New `_and_wait` functions use the same `err_out` conventions as `sync()`.
- invalid integer ACK level is rejected before Arrow import and leaves
  `array->release` unchanged.
- durable-without-opt-in is rejected before Arrow import and leaves
  `array->release` unchanged.
- Arrow `_and_wait` functions re-export on retryable pre-publication failures
  only.
- Arrow `_and_wait` functions do not re-export on ACK wait timeout,
  SFA no-progress timeout, or any other post-publication `FailoverRetry`.
- Arrow `_and_wait` does not re-export on a direct partial write/flush failure
  (`DeliveryUnknown`), distinguishing it from a clean pre-write failure
  (`NotDelivered`, which does re-export).
- The delivery-certainty distinction (`NotDelivered` vs `DeliveryUnknown`) is
  part of the ABI contract, not just an internal error classification detail.

### 10.4 C++

- Overloads route to the correct C ABI function.
- Existing no-ACK overloads remain source-compatible.
- Exceptions preserve the underlying `line_sender_error` code and message.

### 10.5 Dataframe helpers

- Checkpoint advancement still happens only after a successful ACK boundary.
- Transient failure after an ACKing checkpoint re-drives only the uncommitted
  tail.
- Empty dataframe behavior remains unchanged.

---

## 11. Documentation Updates

If implemented, update:

- `doc/COLUMN_SENDER_FFI_ABI.md` section 13;
- `include/questdb/ingress/column_sender.h` flush/sync comments;
- `include/questdb/ingress/column_sender.hpp` C++ overload docs;
- Rust rustdoc in `questdb-rs/src/ingress/column_sender`;
- Python: the `_and_wait` functions are not yet declared in the
  `py-questdb-client` Cython binding. Adopting them inside `Client.dataframe`
  would touch `line_sender.pxd` (extern decls) and `ingress.pyx` (flush/sync
  wrappers); no public Python surface changes, since the column sender exposes
  no user-facing flush/sync. Python can also keep its current `flush` +
  `sync(Ok)` and stay correct.

The docs should consistently use:

- "publish-only flush" for existing `flush*`;
- "ACKing flush" or "boundary flush" for `flush*_and_wait`;
- "delivery unknown" for ACK-phase failures.

---

## 12. Decisions

1. **C ABI / C++ names: `_and_wait`.** Explicit about blocking behavior, does not
   overload "sync", and used consistently in Rust, C, and C++ (see 5.3).

2. **C++ shape: distinct `_and_wait` methods, not overloads.** Resolved by
   decision 1. Because the names differ, the `ack_level` parameter-ordering
   question is moot, and dropping `ack_level` can no longer silently downgrade an
   Arrow call to publish-only.

3. **ACKing direct flush updates `first_frame_sent`: yes.** It published a real
   frame, so later no-wait flushes should keep deferring. This is for consistency
   only, not correctness: `sync_all_acks` drains in-flight to zero, so the slot
   budget resets regardless.

4. **Boundary covers all prior frames plus the new frame.** Matches ordered QWP
   ACK semantics and SFA cumulative watermarks; avoids a misleading per-frame
   guarantee (see 6.1).

5. **No internal failover retry in `flush_and_wait`.** Keep retry orchestration
   in dataframe helpers or caller code, where source data and duplicate policy
   are known.

6. **SFA `flush_and_wait` writes back the satisfied sync watermark** so a
   trailing `sync(level)` short-circuits (see 6.4).

---

## 13. Recommended Rollout

1. Add internal `WaitForAck` plumbing in Rust manual chunk and Arrow paths.
2. Add Rust public `*_and_wait` APIs.
3. Add C ABI `_and_wait` functions.
4. Add C++ overloads.
5. Add direct-mode and SFA-mode tests for success, durable rejection, timeout,
   and boundary coverage.
6. Migrate dataframe checkpoint boundaries to ACKing Arrow flush where it
   simplifies the loop.
7. Update docs and examples.

This order keeps the behavior additive and testable at each layer.
