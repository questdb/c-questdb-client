# Column Sender Store-and-Forward Design

**Status:** draft
**Audience:** Rust core, C FFI, C++ wrapper, and Python dataframe ingestion
engineers
**Scope:** first implementation of store-and-forward for
`questdb-rs/src/ingress/column_sender`

---

## 1. Problem

The column sender currently has one transport mode: a direct QWP/WebSocket
connection owned by `ColumnConn`.

That path is optimized for dataframe throughput:

- it writes encoded QWP payloads directly to the socket;
- it keeps a connection-local `SymbolGlobalDict`;
- after the first frame on a physical connection, `flush()` publishes frames
  with `FLAG_DEFER_COMMIT`;
- `sync()` sends a non-deferred commit frame and waits for server ACKs.

This is fast, but it does not provide store-and-forward. If the process or
network fails after user data has been encoded but before the server commits
it, the direct path has no local replay log.

The row QWP/WebSocket sender already has a store-and-forward stack:

- `SfaSlotQueue` for slot ownership and queue persistence;
- `QwpWsPublicationStore` for publication state and events;
- `QwpWsSendCore` for send, receive, reconnect, and ACK interpretation;
- `SyncQwpWsRunner` for a background progress runner.

The goal is to add a column-sender mode that uses this store-and-forward
machinery without changing the default dataframe path.

---

## 2. Goals

- Support opt-in store-and-forward for columnar ingestion.
- Keep direct columnar mode as the default for dataframe ingestion.
- Reuse the existing row QWP/WebSocket store-and-forward queue, slot locking,
  reconnect, background progress, and error-policy machinery where possible.
- Keep the first version simple: each stored columnar frame is independently
  commit-triggering.
- Preserve the column sender's bulk encode paths for `Chunk`, Arrow, Polars,
  pandas, and C ABI callers.
- Make error behavior explicit enough that users can reason about whether data
  is only locally stored, sent, committed, or failed.

---

## 3. Non-goals

- No deferred commits in store-and-forward v1.
- No commit groups, commit barriers, or "ACKed but not pruneable" tracking in
  v1.
- No implicit `sync()` in `Drop` or C++ RAII destructors.
- No change to direct columnar mode's current pipelined/deferred behavior.
- No automatic store-and-forward for Python dataframe ingestion unless the user
  opts in through store-and-forward configuration.
- No Python-only replay layer. Replay belongs below the C ABI, in the Rust
  column-sender transport layer.
- No server wire-protocol changes.
- No exactly-once guarantee beyond the existing row QWP/WebSocket SFA
  semantics. Replay after an unpersisted ACK can resend a frame.
- No cross-slot ordering guarantee.
- No fsync/power-loss durability beyond what the existing row SFA stack
  supports today. `sf_dir` gives file-backed replay after process restart, but
  `sf_durability=memory` does not promise that queued bytes or completion
  watermarks survive host power loss.
- No support for `pool_max > 1` in v1 SFA mode. Multi-slot columnar SFA can be
  added later with explicit sender-id sharding.

---

## 4. Terminology

**Direct mode**
: The existing column-sender path backed by `ColumnConn`. It writes to the
socket directly and has no replay queue.

**Store-and-forward mode / SFA mode**
: The new opt-in column-sender path backed by the existing QWP/WebSocket SFA
queue and progress runner.

**Deferred frame**
: A QWP frame with `FLAG_DEFER_COMMIT`. The server can accept it, but it does
not trigger commit by itself.

**Non-deferred frame**
: A QWP frame without `FLAG_DEFER_COMMIT`. In this design, every SFA v1
columnar data frame is non-deferred and therefore acts as its own commit
trigger.

**Replay-safe symbol payload**
: A QWP payload that does not depend on a previous live connection's symbol
cache. For SFA v1 this means the encoded frame must include enough symbol
dictionary entries for replay after reconnect or process restart.

---

## 5. Decisions

### 5.1 Two explicit backend modes

`ColumnSender` should become a facade over two backend implementations:

```rust
enum ColumnSenderBackend {
    Direct(DirectColumnBackend),
    StoreAndForward(SfaColumnBackend),
}
```

Direct mode keeps the current `ColumnConn`, `first_frame_sent`, deferred flush,
and `sync()` behavior.

SFA mode uses a queue-backed backend. It does not use `ColumnConn` for publish.
It may reuse QWP/WebSocket connection setup, transport, response parsing, and
SFA runner code from `sender/qwp_ws.rs` and `sender/qwp_ws_driver.rs`.

### 5.2 Direct remains the dataframe default

The default configuration stays direct:

```text
qwpws::addr=localhost:9000;
```

Dataframe helpers must not silently enable SFA. They use SFA only when the
configuration explicitly opts in, for example with `sf_dir`.

### 5.3 SFA opt-in uses existing QWP/WebSocket SFA keys

The column-sender config parser currently refuses `sf_*` and `sender_id`.
This should change, but the opt-in boundary must stay explicit:

- direct mode still ignores SFA machinery when `sf_dir` is absent;
- SFA mode is selected when `sf_dir` is present;
- `sender_id` and `sf_*` without `sf_dir` are rejected rather than ignored;
- `sender_id` defaults to the row QWP/WebSocket default when `sf_dir` is
  present and the user does not specify it;
- `sender_id` and `sf_*` follow row QWP/WebSocket validation rules;
- unsupported durability values should fail with the same class of error as
  row QWP/WebSocket.

For v1, SFA mode should reject pool configurations that imply multiple
concurrent SFA slots:

```text
sf_dir present and explicit pool_size > 1 -> ConfigError
sf_dir present and explicit pool_max > 1 -> ConfigError
```

When `sf_dir` is present and `pool_max` is not explicitly specified, the
effective SFA `pool_max` is `1` even though the direct-mode default is larger.
This keeps the common opt-in string usable:

```text
qwpws::addr=localhost:9000;sf_dir=/var/lib/questdb-client/sfa;
```

The single-slot v1 decision keeps slot ownership, replay order, and
`sender_id` semantics simple.

### 5.4 SFA v1 frames are never deferred

In SFA mode, every `flush*` method must encode with:

```rust
defer_commit = false
```

This applies to:

- `flush(&mut Chunk)`;
- `flush_arrow_batch_server_stamped`;
- `flush_arrow_batch_at_column`;
- dataframe routes that call through the C ABI.

`first_frame_sent` is direct-mode state only. It must not affect SFA mode.

### 5.5 `sync()` in SFA mode waits, it does not create a commit barrier

Because SFA v1 frames are all non-deferred, `sync(AckLevel::Ok)` does not need
to publish an empty commit frame.

SFA `sync()` should:

- validate the requested `AckLevel`;
- wait until all frames published by this sender up to the call boundary are
  complete at that level;
- surface terminal send errors and server rejections according to the existing
  QWP/WebSocket SFA error policy.

The row QWP/WebSocket sender exposes one cumulative completion watermark:
`acked_fsn()`. In durable-ACK mode that watermark advances only after durable
coverage; ordinary OK responses merely release send-window pressure. Column SFA
cannot reuse only that watermark for all `AckLevel`s because the column API
already distinguishes `AckLevel::Ok` from `AckLevel::Durable`.

Required adapter behavior:

- keep the row SFA durable-aware completion watermark as the prune/replay
  watermark;
- additionally expose an in-memory OK watermark for frames whose basic OK has
  arrived;
- `sync(AckLevel::Ok)` waits for the OK watermark for the call boundary;
- `sync(AckLevel::Durable)` waits for the durable-aware completion watermark
  and requires `request_durable_ack=on`;
- if durable ACK mode is enabled, `sync(AckLevel::Ok)` may return before SFA
  can prune the frames, so later flushes can still hit SFA byte/in-flight
  backpressure until durable completion arrives.

The OK watermark is not persisted and is not used to skip replay after restart.
After restart, unresolved frames replay according to the persisted SFA
completion watermark.

However, the OK watermark helper must still treat the persisted completed-FSN
watermark as a lower bound. A frame that is already completed according to the
durable-aware SFA queue is also complete for `AckLevel::Ok`. If the in-memory
OK watermark starts at zero after reopening a slot while the queue has already
completed frames, `sync(AckLevel::Ok)` can wait forever for ACKs that will never
arrive. The adapter should therefore initialize the OK watermark from recovered
completion state, or have `ok_fsn()` return:

```text
max(in_memory_ok_fsn, durable_aware_completed_fsn)
```

This lower bound is only a wait optimization/correctness guard. It must not be
used as a prune or replay watermark.

### 5.6 SFA v1 stores encoded QWP payloads, not source data

The queue should store the encoded QWP payload bytes, matching the row sender's
SFA model.

It should not store:

- raw Arrow arrays;
- borrowed dataframe buffers;
- `Chunk` descriptors;
- C ABI pointers;
- Python objects.

This keeps replay independent from caller memory lifetimes. Once `flush()`
returns success in SFA mode, the caller's borrowed buffers are released just as
they are in direct mode.

### 5.7 SFA columnar symbol encoding must be replay-safe

The current direct column encoder writes delta-symbol-dictionary payloads that
are efficient for a live connection-local cache. That is not sufficient for SFA
replay after reconnect or restart.

SFA columnar encoding must use replay-safe symbol dictionary semantics. The row
SFA replay encoder provides the model: encode payloads so a replayed frame has
the symbol entries it needs without assuming the server still has the previous
client connection's symbol cache.

The required replay-safe invariant is the row replay encoder's dense-prefix
shape:

```text
delta_start = 0
dense_count = highest referenced symbol id + 1
payload contains dictionary entries for every id in 0..dense_count
```

This is intentionally stronger than "include new symbols." A later unresolved
frame must be replayable even if an earlier frame that introduced a symbol has
already completed and been pruned from the local SFA queue.

Implementation options:

- add a replay-safe mode to `column_sender::encoder` and
  `column_sender::arrow_batch`;
- or factor the shared replay-symbol logic from the row QWP/WebSocket encoder.

The first option is likely smaller. The implementation must not reuse the row
publisher's current encode-then-publish boundary directly, because that boundary
commits symbol state before local queue acceptance is known.

Column SFA needs a transactional encode-plus-append API with three outcomes:

- **Definitely not appended:** rollback symbol state, leave retryable inputs
  untouched, keep the backend usable when the error is local/backpressure.
- **Definitely appended with FSN:** commit symbol state, clear retryable inputs,
  and return the published FSN.
- **Unknown append state:** mark the backend terminal. Later frames must not be
  allowed to depend on symbol state that may or may not be represented in the
  replay log.

Tests must inject failures before append, during/torn append before the frame is
published, and after publish-before-return.

### 5.8 SFA follows row sender local-publication semantics

SFA `flush*` methods follow the row QWP/WebSocket sender's store-and-forward
contract: success means local publication to the replay queue, not server
completion.

Frame completion, reject-and-continue, halt, reconnect, orphan draining, and
close-drain should use the existing row QWP/WebSocket driver model unless this
document names a column-specific exception.

The main column-specific exceptions are:

- `sync(AckLevel::Ok)` needs the OK watermark described above;
- dataframe APIs call `sync(AckLevel::Ok)` before returning;
- reject-and-continue inside an explicit `sync()`/dataframe boundary must be
  surfaced to that boundary, not hidden as success.

### 5.9 Dataframe APIs keep completion-on-return

Python `Client.dataframe()` and equivalent dataframe helpers currently flush
one or more chunks and then call column-sender `sync(AckLevel::Ok)` before
returning.

That behavior must remain true in SFA mode. Only low-level columnar `flush*`
APIs return after local queue acceptance. Dataframe helpers return after their
published frames have reached the requested server-side boundary, or they return
an error.

Because SFA v1 does not use deferred commits, every dataframe chunk is a
commit-triggering QWP frame. A dataframe split into multiple SFA frames is not
all-or-nothing: earlier chunks can commit before a later chunk fails.

### 5.10 Reuse boundaries

Column SFA should share the row QWP/WebSocket store-and-forward engine, but not
the row-oriented buffer encoder or public row `Sender` API.

| Category | Scope |
| --- | --- |
| Reuse directly | `SfaSlotQueue` / `SfaFrameQueue`, slot locking, segment files, storage cleanup, orphan scanning/draining, reconnect policy, `QwpWsPublicationStore`, `QwpWsSendCore`, `BlockingQwpWsTransport`, server error classification, durable ACK tracking, backpressure, append deadline, and sender-error diagnostics. |
| Expose through a narrow adapter | Queue construction from parsed QWP/WebSocket config, append of a pre-encoded QWP payload, published-FSN reads, durable-aware completed-FSN reads, OK watermark reads, wait helpers, close-drain, and structured error polling for a waited FSN range. |
| Implement in column sender | Replay-safe column encoding for `Chunk` and Arrow/Polars/dataframe inputs, symbol-dictionary transaction handling around encode-plus-append, direct-vs-SFA backend dispatch, pool/drop behavior, and C/C++/Python-facing ownership/completion semantics. |
| Do not reuse | `QwpWsColumnarBuffer` row-building, `QwpWsReplayEncoder` as a callable encoder for column chunks, direct `ColumnConn` publish for SFA mode, and direct-mode deferred-commit state (`first_frame_sent`) in SFA mode. |

This boundary avoids two implementation traps:

- duplicating the row SFA driver in `column_sender`;
- trying to force column chunks through the row replay encoder even though their
  source representation and ownership model are different.

---

## 6. User-visible behavior

### 6.1 Direct mode

No behavior change.

```text
flush #1 on a cold direct connection:
  non-deferred, commit-triggering

flush #2..N on the same direct connection:
  deferred

sync():
  sends an empty non-deferred commit frame and waits
```

### 6.2 SFA mode

```text
flush #1:
  encode replay-safe non-deferred QWP payload
  append payload to local SFA queue
  return after local acceptance

flush #2..N:
  same

background runner:
  sends queued frames
  reconnects/replays as needed
  marks frames complete when server ACK policy is satisfied

sync():
  waits for frames published up to the sync boundary
```

In SFA mode, `flush()` success means the frame is locally accepted for
store-and-forward. It does not mean the server has already committed it.

`sync()` is the API that gives the caller a server-side completion boundary.
Dataframe helpers keep their existing stronger contract by calling
`sync(AckLevel::Ok)` before returning.

---

## 7. Error paths

### 7.1 Encode and validation failure

Examples:

- invalid table or column name;
- unsupported Arrow type;
- invalid timestamp column;
- string, symbol, or varchar encoding error;
- frame exceeds `max_buf_size`.

Required behavior:

- return the error from `flush*`;
- do not append anything to SFA;
- leave the `Chunk` untouched for `flush(&mut Chunk)`;
- roll back symbol dictionary changes;
- keep the backend usable if the error is local and deterministic.

### 7.2 Local SFA queue backpressure

Examples:

- queue byte capacity reached;
- `max_in_flight` reached;
- storage spare segment not ready;
- append deadline reached.

Required behavior:

- wait/retry according to the existing SFA append-deadline behavior;
- if the deadline expires before append succeeds, return an error;
- roll back symbol dictionary state for the frame that was not appended;
- leave `Chunk` untouched;
- keep the backend usable unless the queue reports a terminal state.

### 7.3 SFA queue open failure

Examples:

- invalid `sender_id`;
- slot lock already held;
- `sf_dir` cannot be created;
- unsupported `sf_durability`;
- corrupt queue state that cannot be recovered.

Required behavior:

- fail `QuestDb::connect` / builder construction;
- do not fall back silently to direct mode;
- include enough path/config context in the error for users to identify the
  bad slot or setting.

### 7.4 Transport failure after local append

Examples:

- server unavailable;
- TCP reset;
- TLS failure;
- reconnect budget exhausted.

Required behavior:

- keep the frame in the SFA queue until it is completed or policy-dropped;
- reconnect and replay through the existing QWP/WebSocket SFA driver;
- surface terminal transport errors through `sync()`, close/drain, or sender
  error polling, matching row SFA behavior.

`flush()` must not report success as server durability. It reports local queue
acceptance.

### 7.5 Server rejection

Use the row QWP/WebSocket error-policy model:

- schema mismatch and write errors are `DropAndContinue`;
- parse, security, protocol, internal, and unknown errors halt the sender.

Required behavior:

- for `DropAndContinue`, complete/drop the affected frame from the SFA sender's
  perspective and record a structured sender error;
- for `Halt`, terminalize the backend and retain diagnostics;
- make the error observable through the same surfaces used by row SFA.

Columnar SFA v1 has one QWP frame per flushed chunk or dataframe batch, so the
affected range for a server rejection should normally be one FSN.

Additional column-specific boundary rule:

- if a rejected frame is inside the FSN range that a `sync()` call is waiting
  for, `sync()` must return an error after the frame has been resolved for SFA
  replay purposes;
- dataframe helpers call `sync(AckLevel::Ok)`, so they must also return an
  error for rejected frames inside the dataframe's published range;
- low-level callers that only call `flush()` can observe later rejections via
  row-like structured diagnostics or the next `sync()`/backend error check.

This prevents `DropAndContinue` from looking like successful dataframe
ingestion while still allowing the SFA queue to move past policy-droppable
frames.

The sync-side error reporting must be one-shot for a given observed range. Once
`sync()` has surfaced a nonterminal `DropAndContinue` sender error, later
`sync()` calls or later dataframe publishes must not be poisoned forever by the
same already-resolved frame. The implementation needs either:

- an observed sender-error watermark/sequence, equivalent to row SFA polling;
- or sync-boundary advancement that records "this rejected range was reported"
  before returning the error.

It is not sufficient to run a non-consuming "find overlapping error in
`from_fsn..=boundary`" query on every `sync()` attempt. That shape can keep
returning the same historical schema/write rejection even after the SFA queue
has moved past it and later valid frames have completed.

### 7.6 Durable ACK requested but not enabled

If `sync(AckLevel::Durable)` is requested without durable ACK support negotiated
or configured, return the same validation error as direct columnar and row
QWP/WebSocket.

Do not silently downgrade `Durable` to `Ok`.

### 7.7 Drop/close with queued frames

Dropping or returning a borrowed SFA-backed `ColumnSender` must not delete
queued, unresolved frames.

Required behavior for a borrowed sender returned to `QuestDb`:

- return the backend to the single-slot pool if it is still usable;
- do not mark it `must_close` merely because frames are unresolved;
- allow the background runner to continue making progress while the sender is
  idle in the pool;
- keep later borrows on the same ordered SFA slot.

Required behavior for dropping the owning `QuestDb` / owned C handle:

- stop/join the background runner in an orderly way;
- close the queue handle and release the slot lock;
- leave unresolved frames in the SFA slot for replay by the next owner;
- surface close-drain timeout only from explicit close/drain APIs, not from
  `Drop`.

Required behavior for an explicit close-drain API, if exposed:

- reject new `flush*` calls after close begins;
- wait only for frames already published to the local queue;
- on timeout, return an error without deleting unresolved frames;
- release the slot lock when the owner is dropped.

This differs from direct mode, where in-flight un-synced frames live only in the
socket connection and are not replayable.

Explicit force-drop APIs need a defined SFA meaning. The C
`questdb_db_drop_column_sender` and C++ `borrowed_column_sender::drop_on_return()` contracts say
"do not recycle this borrowed handle." In SFA mode, honoring that contract must
not delete queued frames. The preferred behavior is:

- remove this backend from the pool instead of recycling it;
- stop/join its background runner and release the slot lock;
- leave unresolved frames in `<sf_dir>/<sender_id>/`;
- let a later owner open the same slot and replay unresolved frames.

If the implementation chooses not to support force-drop for SFA, the public
C/C++ docs must state that exception explicitly. A silent no-op is not
acceptable because recovery code relies on `drop_on_return()` to discard a
possibly tainted handle.

### 7.8 API ownership and retryability

SFA must preserve each API surface's existing input ownership rules.

| API surface | On local encode/append failure | On local append success |
| --- | --- | --- |
| `flush(&mut Chunk)` | `Chunk` remains intact and retryable when the failure is definitely-not-appended. Unknown append state terminalizes the backend. | `Chunk` is cleared; caller buffers may be released. |
| Arrow batch Rust API | Borrowed `RecordBatch` remains caller-owned. Retrying is safe after definitely-not-appended failures. | Batch may be dropped after return. |
| C Arrow FFI | Follow the existing C ABI release contract exactly. Do not promise retryability if the ABI consumes an `ArrowArray.release` callback on failure. | Caller may release according to existing ABI docs. |
| Polars / Python dataframe | The helper owns chunking and must call `sync(AckLevel::Ok)` before returning. A failure can leave earlier chunks committed. | Caller dataframe memory may be released after return. |

---

## 8. Corner cases

### 8.1 Empty chunks

Direct `sync()` uses an empty non-deferred frame as a commit trigger. SFA v1 has
no deferred frames, so it should not need to enqueue empty commit frames.

`flush(empty_chunk)` should keep the current public behavior, whatever direct
mode already exposes. The SFA backend must not invent a new commit barrier for
it.

### 8.2 Process restart after local append but before send

The payload remains in the SFA slot. On next open with the same `sf_dir` and
`sender_id`, the sender replays unresolved frames.

This is the primary SFA use case.

### 8.3 Process restart after send but before ACK persistence

The client may replay a frame that the server already accepted but the local
queue did not mark complete.

This is the standard store-and-forward duplicate boundary. The design inherits
the row QWP/WebSocket behavior and server-side sequence semantics. The column
sender must not add a separate deduplication layer.

Crash-window expectations:

| Window | Expected behavior |
| --- | --- |
| Before local append starts | No frame exists in SFA; caller gets an error if the process survives. |
| Torn append before publish/CRC visibility | Recovery treats the torn frame as absent or corrupt according to existing SFA segment recovery rules; no later frame may depend on uncommitted symbol state from it. |
| After local append, before send | Frame replays from SFA. |
| After send, before basic OK | Frame may replay; at-least-once boundary. |
| Basic OK before durable ACK | `sync(Ok)` may have completed, but durable-aware prune/completion has not; restart may replay. |
| ACK/reject before completed-FSN watermark persistence | Frame may replay or rejection may be observed again; this is inherited row SFA behavior. |
| Completed-FSN watermark persisted | Reopen skips completed frames through the persisted watermark. |
| Halt rejection before caller observes error | Reopen must not silently treat the slot as healthy if the persisted queue still contains unresolved frames; the next owner replays or reaches terminal state according to row SFA recovery. |
| Close-drain timeout | Unresolved frames remain in the slot for the next owner. |

### 8.4 Reconnect with symbol columns

Replay must not depend on the old WebSocket connection's symbol cache. This is
why SFA mode needs replay-safe symbol payloads.

Tests must cover at least:

- symbol-only frames replayed after reconnect;
- a later frame whose symbols were first observed in an earlier unresolved
  frame;
- a restart where the sender opens from disk and replays unresolved symbol
  frames.

### 8.5 Queue append failure after symbol dictionary mutation

This is the easiest data-corruption trap.

If a frame is encoded, mutates the sender symbol dictionary, and then fails to
append to the local SFA queue, later frames must not be allowed to reference
that missing frame's symbol state.

Required behavior:

- rollback dictionary state if the append did not happen;
- or mark the backend terminal if the code cannot prove whether append
  happened.

Replay-prefix construction is part of the same transaction. If the encoder
resolves/interns symbols and then fails while building the dense replay prefix,
it must roll back the symbol dictionary just like later frame-body failures do.
The production caller may also keep an outer rollback guard, but the replay
encoder helper itself should have a consistent transactional contract so future
call sites cannot accidentally retain symbols for a frame that was never
published.

### 8.6 Multiple borrowers

V1 SFA mode should reject multiple pool slots. A single SFA slot maps cleanly to
one ordered queue and one `sender_id`.

Future multi-slot SFA can shard by generated sender IDs, but it must document
that ordering is per slot only.

Concurrent v1 behavior should match the current pool's fail-fast style rather
than silently serializing:

- one active borrowed SFA sender at a time;
- a second concurrent borrow fails with a targeted error such as
  `column sender store-and-forward supports one active borrower in v1`;
- Python dataframe calls that overlap on the same `Client` see that targeted
  error rather than silently moving to direct mode or opening another SFA slot.

### 8.7 Orphan slots

Columnar SFA should reuse row SFA orphan-slot policy where applicable.

Do not invent a separate directory layout. The expected layout remains:

```text
<sf_dir>/<sender_id>/
```

with slot locking owned by `SfaSlotQueue`.

The row SFA namespace is shared: row and column senders both store QWP payloads
under `<sf_dir>/<sender_id>/`. A column sender must therefore not assume it owns
the whole `sf_dir`.

If `drain_orphans` is enabled:

- exclude the current `sender_id` from orphan draining;
- skip locked orphan slots as diagnostics, not startup-fatal errors;
- mark corrupt orphan slots according to row orphan-drainer behavior;
- allow mixed row/column orphan slots because the stored replay unit is an
  encoded QWP payload.

---

## 9. Suggested implementation shape

### 9.1 Config

- Stop refusing `sf_*` and `sender_id` unconditionally in
  `column_sender/conf.rs`.
- Parse column-sender pool keys as today.
- Pass SFA keys through to the shared QWP/WebSocket config parser.
- Select SFA backend mode only when `sf_dir` is present.
- Reject `sender_id`/`sf_*` without `sf_dir`, except for defaulted internal
  settings.
- In SFA mode, reject explicit `pool_size > 1` or explicit `pool_max > 1`;
  default unspecified `pool_max` to `1`.
- Branch on `sf_dir` before constructing row SFA queue pieces. The row sender
  opens an in-memory SFA queue when `sf_dir` is absent; column direct mode must
  not accidentally take that path.

### 9.2 Backend split

Introduce internal backends:

```rust
struct DirectColumnBackend {
    conn: ColumnConn,
    symbol_dict: SymbolGlobalDict,
    scratch: EncodeScratch,
    first_frame_sent: bool,
}

struct SfaColumnBackend {
    runner: SyncQwpWsRunner<SfaSlotQueue>,
    symbol_dict: SymbolGlobalDict,
    scratch: EncodeScratch,
    configured_max_buf_size: usize,
    server_max_batch_size: Arc<AtomicUsize>,
}
```

The public `ColumnSender` methods dispatch to the active backend.

The existing row runner has useful internals, but some methods are currently
module-private to `sender/qwp_ws.rs`. The implementation should expose a narrow
`pub(crate)` adapter rather than duplicate queue driving logic in
`column_sender`.

That adapter is mandatory. It must provide at least:

- queue construction from an already-parsed QWP/WebSocket config;
- append of a pre-encoded QWP payload with the three-state append outcome;
- published-FSN and durable-aware completed-FSN watermarks;
- the in-memory OK watermark needed by `sync(AckLevel::Ok)`;
- close-drain and structured sender-error polling equivalent to row SFA.

The SFA backend must use the effective maximum batch size:

```text
min(configured_max_buf_size, server_max_batch_size_when_known)
```

matching row QWP/WebSocket behavior.

### 9.3 Encoding

Add an encode mode:

```rust
enum ColumnEncodeMode {
    Direct { defer_commit: bool },
    StoreAndForward,
}
```

`StoreAndForward` means:

- no `FLAG_DEFER_COMMIT`;
- replay-safe symbol dictionary payload;
- rollback support around local failures.

### 9.4 Publishing

Direct mode keeps `ColumnConn::publish_qwp`.

SFA mode should:

1. encode into scratch;
2. validate the effective maximum batch size;
3. append the encoded payload through the SFA adapter's transactional publish
   API;
4. on append success, clear the `Chunk`;
5. on append failure, roll back dictionary state and keep the `Chunk`
   untouched unless terminalization is required.

The payload written to SFA is the QWP message body, not a WebSocket frame. The
existing SFA transport layer owns WebSocket framing and masking.

### 9.5 Sync

SFA `sync()` needs a boundary. It should record the highest locally published
FSN at the start of the call and wait for that FSN to become completed at the
requested level.

If no frame has been published, `sync()` should be a no-op after ack-level
validation.

If the existing runner does not expose these wait primitives, add crate-private
helpers in the row QWP/WebSocket SFA adapter rather than implementing a separate
columnar queue driver.

For `AckLevel::Ok`, the helper waits on the adapter's in-memory OK watermark.
For `AckLevel::Durable`, it waits on the row-style durable-aware completed-FSN
watermark. Both waits must also surface any structured sender errors for frames
inside the waited FSN range according to section 7.5.

Additional sync invariants:

- the OK wait watermark is lower-bounded by the recovered completed-FSN
  watermark, as described in section 5.5;
- a nonterminal sender error reported by `sync()` is marked observed before
  returning, so the same historical rejection does not poison future sync
  ranges;
- terminal sender errors may remain sticky because later use of the backend is
  invalid anyway;
- if a wait loop observes no progress, it must continue to check the runner's
  terminal/error state rather than sleeping forever.

The adapter API should expose a consuming or sequence-aware sender-error
primitive for sync. A raw non-consuming "find any overlapping error" helper is
useful for diagnostics, but it is not sufficient as the only sync error
boundary.

### 9.6 Public API documentation updates

The implementation must update every public surface that describes the old
direct-only behavior:

- C `questdb_db_connect`: `sf_dir` now opts the column sender into SFA mode;
  `sender_id` and `sf_*` are accepted only with explicit `sf_dir`.
- C/C++ pool borrow docs: SFA v1 has one active borrower and an effective
  `pool_max=1` unless the user explicitly sets an invalid larger value.
- C/C++ `sync()` docs: direct mode sends a commit-triggering frame; SFA mode
  does not. SFA `sync()` waits for the already-published local queue boundary.
- C `questdb_db_drop_column_sender` and C++ `drop_on_return()`: document and implement
  the SFA force-drop semantics from section 7.7.
- Python `Client.from_conf()` / `Client.dataframe()` docs or release notes:
  `sf_dir` affects dataframe ingestion through the Rust column-sender backend,
  and dataframe calls still call `sync(AckLevel::Ok)` before returning.

---

## 10. Trade-offs

### Simplicity over batching

SFA v1 commits every flushed columnar frame independently. This is slower than
direct deferred batching, but it avoids commit-group state and replay ambiguity.

This is acceptable because direct mode remains the default for dataframe
throughput.

### One SFA slot over pooled concurrency

Rejecting multi-slot SFA in v1 limits concurrency, but keeps replay order and
slot ownership obvious.

The direct path remains pooled and is still the right default for high-throughput
dataframes.

### Encoded payload storage over source-data storage

Storing encoded QWP payloads avoids retaining Arrow/dataframe memory and keeps
the queue language-independent.

The cost is that local encode work is not retried after restart; replay sends
the already encoded bytes.

### Replay-safe symbols over minimum payload size

Replay-safe symbol payloads may be larger than direct delta payloads.

The benefit is correctness across reconnect and restart. SFA is a reliability
feature; payload compactness is secondary.

---

## 11. Future work

Deferred commit support can be added later as an SFA v2 feature.

That version needs commit-group metadata:

```text
deferred frame A
deferred frame B
non-deferred commit barrier C
```

The queue must not prune A or B until C completes at the requested ACK level.
Recovery must define what happens when A and B exist but C was never appended.

This is intentionally outside v1.

Other future work:

- multi-slot SFA with explicit sender-id sharding;
- manual progress mode for columnar SFA;
- persistent queue durability modes beyond the existing row SFA support;
- public metrics for queued, sent, completed, rejected, and replayed columnar
  frames;
- shared columnar/row replay-symbol encoder utilities.

---

## 12. Minimum test plan

### 12.1 Config and mode selection

- `qwpws::addr=...` selects direct mode.
- `qwpws::addr=...;sf_dir=...` selects SFA mode with effective
  `pool_size=1`, `pool_max=1`.
- Explicit `pool_size > 1` or `pool_max > 1` with `sf_dir` fails with a
  targeted `ConfigError`.
- `sender_id`/`sf_*` without `sf_dir` fails as "requires sf_dir" rather than
  becoming a no-op.
- Unsupported `sf_durability` values fail exactly like row QWP/WebSocket.
- Direct dataframe config still selects direct mode and never opens the row
  memory SFA queue.

### 12.2 Encoding and publish

- SFA `flush()` encodes frames without `FLAG_DEFER_COMMIT`.
- SFA encoding uses dense-prefix replay-safe symbol payloads.
- SFA payload size validation uses the effective max of configured and
  negotiated server limits.
- SFA `sync()` does not enqueue an empty commit frame.
- SFA `flush()` success allows caller buffers to be dropped before replay.

### 12.3 Transactional append fault injection

- Encode failure leaves `Chunk` intact and rolls back symbol dictionary state.
- Failure before queue append leaves `Chunk` intact and rolls back symbol state.
- Torn append before publish/CRC visibility does not commit symbol state for
  later frames.
- Failure after publish-before-return terminalizes or returns a definite FSN;
  it never allows later frames to depend on a missing symbol frame.
- Queue append timeout/backpressure leaves retryable inputs intact when the
  frame is definitely not appended.

### 12.4 Sync and ACK levels

- `sync(AckLevel::Ok)` waits for basic OK on the call boundary.
- Reopening a slot with already-completed frames makes `sync(AckLevel::Ok)` a
  no-op for those frames rather than waiting forever on an empty in-memory OK
  watermark.
- With durable ACK enabled, `sync(AckLevel::Ok)` may return before frames are
  pruned from SFA.
- `sync(AckLevel::Durable)` validates `request_durable_ack=on` and waits for
  durable-aware completion.
- `sync(AckLevel::Durable)` never silently downgrades to `Ok`.
- Basic OK delayed, durable ACK delayed, and completed-FSN watermark persistence
  are tested independently.

### 12.5 Server rejection policy

- Schema mismatch / write error on FSN 0 resolves replay state but makes
  `sync()` or `Client.dataframe()` return an error for that boundary.
- A valid FSN after a drop-and-continue rejection can still complete.
- After a drop-and-continue rejection has been reported once, a later
  `sync()`/dataframe call covering only newer frames does not re-surface the
  old rejection.
- Returning a sender to the pool after a nonterminal rejection does not poison
  the next borrower with the same already-reported error.
- Parse/internal/security rejection latches terminal and blocks later flushes.
- Rejection diagnostics are available through the row-like structured error
  path.

### 12.6 Recovery and replay

- Transport failure after append leaves the frame replayable.
- Restart replays unresolved frames from `sf_dir`.
- Restart after ACK but before completed-FSN watermark persistence may replay.
- Restart after completed-FSN watermark persistence skips completed frames.
- Symbol replay works when the earlier frame that introduced a symbol has been
  pruned and a later unresolved frame references that symbol.
- Drop with unresolved SFA frames leaves them in the queue for the next owner.

### 12.7 Close, concurrency, and orphans

- Borrowed sender drop returns a usable SFA backend to the pool without
  discarding unresolved frames.
- `questdb_db_drop_column_sender` / C++ `drop_on_return()` remove the current SFA
  backend from the pool, release the slot lock, and leave unresolved frames
  replayable for the next owner.
- Owning `QuestDb`/C handle drop releases the slot lock and leaves unresolved
  frames.
- Explicit close-drain timeout returns an error without deleting unresolved
  frames.
- A second concurrent SFA borrower fails with the targeted v1 single-borrower
  error.
- `drain_orphans=on/off`, locked orphan skip, corrupt orphan diagnostics, and
  mixed row/column orphan replay are covered.

### 12.8 Entry routes

Run representative coverage through every entry route:

- Rust `flush(&mut Chunk)`;
- Rust Arrow batch;
- Rust Arrow-at-column;
- C ABI chunk and Arrow entry points;
- C++ wrappers;
- Polars/dataframe helpers;
- Python `Client.dataframe()`.

### 12.9 Public contract checks

- C headers no longer claim `sf_*` / `sender_id` are refused by column sender.
- C/C++ docs explain that SFA v1 is single-borrower/single-slot.
- C/C++ `sync()` docs distinguish direct commit-frame behavior from SFA
  wait-only behavior.
- C/C++ force-drop docs match the implemented SFA behavior.
- Python docs or release notes mention that `sf_dir` opt-in also applies to
  dataframe ingestion through `Client.from_conf()`.
