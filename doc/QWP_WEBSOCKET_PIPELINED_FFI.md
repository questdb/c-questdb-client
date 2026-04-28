# QWP/WebSocket pipelined Store-and-Forward design for Rust and FFI

Status: **draft**, target implementation is the Rust client plus C/C++/Python FFI layers.

Java reference point:
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/design/qwp-cursor-durability.md`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`

Rust code touched by this design:
- `questdb-rs/src/ingress/buffer/qwp.rs`
- `questdb-rs/src/ingress/sender/qwp_ws.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_async.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_codec.rs`
- `include/questdb/ingress/line_sender.h`
- `include/questdb/ingress/line_sender_core.hpp`

Validation plan:
- `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`

## Context

The current Rust client already has QWP/UDP buffers, synchronous QWP/WebSocket,
and a Tokio-based async QWP/WebSocket sender.

That is not the target shape for durable pipelined FFI:

- Rust, C, and C++ historically keep `Sender` and `Buffer` separate.
- C and C++ callers should not need to understand Tokio or Rust futures.
- Python can build blocking, future, or asyncio wrappers, but the C ABI should remain runtime-neutral.
- The low-level API must not silently start a background thread.
- The steady-state hot path should not allocate after warm-up and sizing.
- Store-and-Forward means a submitted batch must survive reconnect, process restart, and caller buffer reuse.

The Java client is useful as a reference for durability and reconnect semantics, not as an API shape to copy directly.

## Goals

- Support pipelined QWP over WebSocket.
- Add Store-and-Forward durability for submitted batches.
- Preserve `Sender` / `Buffer` separation.
- Let callers reuse or clear a `Buffer` immediately after successful submission.
- Expose deterministic delivery state through receipts, outcomes, and events.
- Keep the core API threadless by default.
- Provide optional blocking-thread and Tokio adapters explicitly.
- Keep the C ABI simple and stable enough for C++, Python, and other FFI consumers.
- Avoid heap allocation on steady-state submit, drive, ACK, and replay paths.
- Preserve submission order: later batches cannot jump an earlier unresolved batch.
- Avoid infinite replay of deterministic bad batches.
- Avoid silent data loss: "skip" must mean "quarantine and report".

## Non-goals

- Replacing the existing synchronous `line_sender` ABI.
- Making QWP/UDP use this WebSocket pipelining API.
- Exposing Tokio handles through C.
- Starting orphan drainers automatically.
- Row-level recovery inside a rejected QWP batch.
- Exactly-once delivery without server-side idempotency or deduplication.

## Current Rust behavior

The sync QWP/WebSocket sender sends one frame and waits for its matching response before returning.

The async QWP/WebSocket sender is already pipelined. It uses Tokio tasks, an unbounded writer channel, an in-flight `BTreeMap`, `oneshot` completions, and cloned `Buffer` values for replay. That is workable for a Rust async API, but it conflicts with the FFI and hot-path constraints:

- Tokio is mandatory for that path.
- Construction and reconnect spawn tasks.
- Submission allocates for channels, maps, frames, and completion state.
- In-flight replay stores cloned buffers rather than durable self-sufficient frames.
- `flush()` waits for completion rather than returning a submission receipt.

The durable Rust design should reuse the protocol codec and tests where useful, but should introduce a new core rather than layering FFI over the current Tokio sender.

## Design principle

Split the sender into three layers:

```text
Buffer API
  User-owned row accumulation. Not thread-safe. Reusable after submit succeeds.

QWP/WebSocket SF core
  Threadless state machine. Owns the durable queue, connection state,
  in-flight slots, event ring, and preallocated scratch buffers.

Adapters
  Blocking convenience API, explicit background runner, Tokio integration,
  C ABI, C++ RAII, Python wrappers.
```

The core is the contract. Adapters must not change delivery semantics.

## Public Rust shape

Low-level Rust API:

```rust
pub struct QwpWsSender { /* threadless core */ }

pub struct QwpReceipt {
    pub fsn: u64,
}

pub enum QwpDeliveryOutcome {
    Acked,
    Poisoned {
        status: QwpStatus,
        message_truncated: bool,
        poison_path: Option<PathBuf>,
    },
    Timeout,
}

impl QwpWsSender {
    pub fn open(opts: QwpWsOptions) -> Result<Self>;

    pub fn new_buffer(&self) -> Buffer;

    pub fn submit(&mut self, buffer: &mut Buffer) -> Result<QwpReceipt>;
    pub fn submit_and_keep(&mut self, buffer: &Buffer) -> Result<QwpReceipt>;

    pub fn drive_once(&mut self, timeout: Duration) -> Result<Option<QwpEvent>>;
    pub fn poll_event(&mut self) -> Option<QwpEvent>;
    pub fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus;
    pub fn wait(&mut self, receipt: QwpReceipt, timeout: Duration) -> Result<QwpDeliveryOutcome>;

    pub fn close_drain(&mut self, timeout: Duration) -> Result<CloseOutcome>;
    pub fn close_fast(&mut self);
}
```

Properties:

- `open()` always performs local setup. With `open_mode=connected` it also performs bounded initial TCP/TLS/WebSocket/auth work. With `open_mode=lazy` it performs local setup only.
- `submit()` publishes to the local engine and returns a receipt. It does not wait for server ACK.
- `submit()` clears the caller buffer only after successful publication.
- `submit_and_keep()` publishes the same data without clearing the caller buffer.
- `drive_once()` is the low-level progress primitive. It performs bounded I/O, reconnect, replay, ACK handling, poison handling, and event production.
- `wait()` is a convenience loop over `drive_once()` plus receipt-status checks.

The low-level type should prefer `&mut self` methods. That gives Rust callers a clear single-driver ownership model and avoids internal locks on the hot path.

## Open and initial connection

There is one constructor. `open_mode` controls whether it performs initial network work.

With `open_mode=connected` (the default), `open()` is allowed to do real connection setup:

- DNS resolution,
- TCP connect,
- TLS handshake,
- WebSocket upgrade,
- protocol negotiation,
- authentication failure detection.

All of that work must be bounded by configured connect/request timeouts. `open()` still must not start a background thread, spawn a Tokio task, or continue sending/replaying after it returns.

With `open_mode=lazy`, `open()` performs only local setup: config parsing, allocation, queue initialization, SF slot locking, and SF recovery. A lazy sender can accept `submit()` calls before the first successful connection as long as local queue capacity is available. The first `drive_once()`, `wait()`, or `close_drain()` may then perform initial connection work.

The default `open_mode=connected` matches user expectations for a sender constructor: bad host, bad TLS, bad auth, and incompatible server versions fail early. `open_mode=lazy` is the explicit escape hatch for applications that want to buffer locally while QuestDB is unavailable.

## Optional adapters

### Blocking adapter

```rust
pub struct BlockingQwpWsSender {
    inner: QwpWsSender,
}
```

This is still threadless. Calls like `flush()` or `wait()` drive the connection synchronously on the caller's thread.

### Explicit background runner

```rust
let (sender, runner) = QwpWsSender::open_with_runner(opts)?;
let handle = std::thread::spawn(move || runner.run());
```

Rules:

- The method name and type make the thread explicit.
- The user owns the thread.
- Dropping the sender does not spawn a drainer.
- The runner uses the same core event and receipt semantics.

### Tokio adapter

```rust
let (sender, driver) = QwpWsTokioSender::open(opts).await?;
tokio::spawn(driver.run());
```

Rules:

- Tokio support is optional and feature-gated.
- Tokio integration is an adapter, not the core implementation.
- The caller chooses whether and where to spawn the driver.
- Async multi-producer ergonomics may allocate in the adapter, but the core steady-state hot path remains allocation-free after warm-up.

## Buffer and submit contract

The `Buffer` remains user-owned and separate from the sender.

Submit pipeline:

```text
validate buffer
reserve/locate an engine slot
encode a self-sufficient QWP message into that slot
publish the slot by advancing the durable cursor
return QwpReceipt { fsn }
clear the caller buffer only for submit()
```

If submission fails before publication, the buffer is not cleared.

If submission succeeds, the caller can immediately reuse the buffer. Server ACK or rejection is reported later through the receipt and event APIs.

This means the sender cannot hold references into the caller buffer. It must copy encoded bytes into sender-owned memory or SF storage. The steady-state no-allocation requirement is met by sizing and reusing that storage, not by borrowing the caller buffer.

## Self-sufficient replay frames

The first version follows the Java cursor-SF approach: every data frame
published by the new pipelined sender is self-sufficient.

The v1 dictionary strategy is deliberately dense and Java-compatible. If a
frame references symbol id `N`, the frame carries the connection-global
dictionary entries from id `0` through `N`, even if the frame only uses a small
subset of those ids. This is the simplest correctness-first replay contract and
matches the Java cursor-SF approach, but it is not the final scalability target.

This is not a user-selectable durability encoding mode. It is the invariant for
the new pipelined core in both `volatile` and `sf` queue modes, because both
modes may need to replay unresolved frames after reconnect and both let the
caller reuse the source `Buffer` immediately after successful submission.

Each published frame must:

- emit full schema definitions for every table block,
- avoid schema-id reference mode,
- emit the complete connection symbol-dictionary prefix from id `0` through
  the highest symbol id referenced by the frame,
- avoid incremental "new symbols only" dictionary deltas,
- be valid when sent as the first QWP data frame on a fresh WebSocket
  connection.

For the current QWP wire shape, this means the new core always encodes
replayable frames as if the server has no prior client-side QWP state:

```text
confirmedMaxId = -1   # symbol delta
useSchemaRef = false
```

The sender may still keep a dense connection-global symbol dictionary
internally and use those ids in row payloads. The Java-style rule is that every
replayable frame repeats the dictionary prefix needed to define those ids on a
fresh server connection. It does not require a frame-local symbol id space in
the first version.

This costs more bytes than connection-delta encoding, especially for
long-running high-cardinality symbol workloads. In the worst case, a frame that
uses one old high-numbered symbol id still repeats every lower dictionary entry.
That scalability limit is accepted for v1 so the end-to-end replay contract can
be validated before optimizing it.

Future optimization should preserve the same replay invariant by adding
explicit protocol support for sparse referenced-entry dictionaries, state-only
QWP messages, and durable state checkpoints. It should not make correctness
depend on whether a user selected a durability mode.

### Encoder work item

The current QWP/WebSocket encoder is connection-scoped:

- symbols are tracked in `SymbolGlobalDict` for the WebSocket connection,
- schema IDs use `SchemaRegistry` and later batches can emit reference mode,
- existing QWP/WS tests assert that repeated symbols/schemas are omitted after the first message.

The new pipelined core needs an encoder entry point that always emits the
Java-style self-sufficient replay form described above. It can share machinery
with the existing connection-delta encoder, but the new core must not expose or
select between connection-delta and self-sufficient replay encoding.

Tests must store a later frame from a repeated-schema/repeated-symbol workload
and replay that frame alone against a fresh mock connection. That replay must
succeed without having sent the earlier frame.

## Store-and-Forward engine

The engine assigns an FSN when it publishes a frame.

Core cursors:

```text
published_fsn       highest frame published into the engine
server_acked_fsn    highest contiguous frame accepted by the server
completed_fsn       highest contiguous frame ACKed or quarantined
```

Do not count quarantined frames as server ACKed.

### Volatile queue mode

Volatile queue mode uses a preallocated in-memory ring of frame slots.

Properties:

- survives transient reconnect,
- does not survive process exit,
- still uses receipts, in-flight slots, and event semantics,
- applies the same backpressure behavior as SF mode.

### File-backed SF queue mode

File-backed Store-and-Forward mode stores frames in segment files under a sender slot:

```text
<sf_dir>/<sender_id>/
  .lock
  segment-0000000000000001.qwpws
  segment-0000000000000002.qwpws
  .poison/
```

Segment record shape:

```text
record_header {
    magic
    header_version
    fsn
    payload_len
    checksum
    flags
}
payload bytes
commit marker / published cursor
```

Publication must be crash-recoverable:

1. Write header as not committed.
2. Write payload.
3. Write checksum.
4. Publish the record with one ordered cursor or commit marker update.

Recovery ignores partial or checksum-invalid tail records.

Queue mode and durability are separate concepts:

| Queue mode | Storage | Survives process crash | Survives OS crash |
|---|---|---|---|
| `volatile` | preallocated RAM ring | No | No |
| `sf` | segment files under `sf_dir` | Yes, after publication | Depends on `sf_durability` |

`sf_durability` only applies when `queue_mode=sf`:

| SF durability | Submit returns after | Survives process crash | Survives OS crash |
|---|---|---|---|
| `page_cache` | record copied into mmap/page cache and published | Yes | Not guaranteed |
| `flush` | published bytes flushed on explicit flush/drain boundary | Yes | Yes after flush boundary |
| `append` | each published frame is flushed before receipt returns | Yes | Yes per receipt |

This deliberately avoids overloading "memory". `volatile` means no files. `page_cache` means file-backed SF without fsync on every submit.

Names can align with Java where useful, but Rust should document the exact fsync boundary for each mode.

## Pipelining model

`max_in_flight` bounds frames sent but not yet completed.

The driver sends frames in FSN order. It may send up to `max_in_flight` unresolved frames on one connection.

Each wire connection has a wire sequence counter. On reconnect:

```text
wire_seq = 0
replay starts at first unresolved FSN
connection-scoped encoder state is reset
```

The server processes submitted WebSocket frames strictly in wire-sequence order. Responses do not complete arbitrary later frames ahead of earlier frames.

The server may coalesce successful ACKs by sending only the highest successful wire sequence. An `OK(sequence=N)` response means every unresolved successful frame up to `N` is accepted. The client maps that cumulative wire sequence to the corresponding FSN and advances `server_acked_fsn` through that FSN.

If the server sends an error for sequence `N`, prior unresolved frames below `N` are treated as ACKed if they were covered by the server's ordering guarantee. Frame `N` follows the server-error classification and poison policy. Later frames remain unresolved until a later cumulative OK or error response resolves them.

The in-flight table must be preallocated:

```rust
struct InFlightSlot {
    wire_seq: u64,
    fsn: u64,
    state: InFlightState,
}
```

Use a fixed-capacity ordered ring sized by `max_in_flight`. Do not use `BTreeMap`, `HashMap`, or per-submit heap nodes in the steady-state hot path. The ring advances from the oldest unresolved slot when cumulative ACKs arrive.

## WebSocket framing without steady-state hot-path allocation

Client-to-server WebSocket payloads must be masked. Durable QWP payload bytes must not be modified in place.

Use one of these steady-state allocation-free approaches:

1. Preallocate a per-driver send scratch buffer sized to `max_frame_bytes + websocket_header`.
2. Stream masked chunks through a fixed-size scratch buffer.

The chunked approach avoids reserving a full max-frame scratch buffer:

```text
write websocket header
for each payload chunk:
    copy + xor into fixed scratch
    write scratch
```

The random mask is stack data. The WebSocket header is stack data. No `Vec` growth is allowed during steady-state sends.

Inbound responses are small. Preallocate:

```text
read_header_scratch
response_payload_scratch
max_error_message_bytes
```

If the server error message exceeds the configured buffer, truncate it and set `message_truncated=true` in the event/outcome.

## Error and event model

Submission errors are local:

- invalid buffer,
- incomplete row,
- frame too large,
- SF slot/cap failure,
- sender already terminal,
- timeout waiting for local capacity.

Delivery outcomes are asynchronous:

- server ACK,
- server data rejection,
- transport retry and eventual success,
- reconnect budget exhaustion,
- security or upgrade failure.

Events:

```rust
pub enum QwpEvent {
    Published { fsn: u64 },
    Sent { fsn: u64, wire_seq: u64 },
    AckedThrough { fsn: u64 },
    DurableAck { /* per-table durable details, if requested */ },
    Retrying { attempt: u32, elapsed: Duration, error: QwpErrorSummary },
    Reconnected { replay_from_fsn: u64, attempts: u32, elapsed: Duration },
    Poisoned { fsn: u64, status: QwpStatus, message_truncated: bool },
    Backpressure { duration: Duration, reason: BackpressureReason },
    Terminal { error: QwpErrorSummary },
}
```

The event ring is preallocated. On overflow, increment `events_dropped_total` and retain the latest terminal/poison state in direct accessors.

## Server error classification

Current QWP response statuses include:

| Status | Meaning | Default disposition |
|---|---|---|
| `OK` | Batch accepted | ACK |
| `DURABLE_ACK` | Per-table durability notification | Event, not batch completion |
| `PARSE_ERROR` | Bad payload | Poison candidate |
| `SCHEMA_MISMATCH` | Bad schema/data for table | Poison candidate |
| `SECURITY_ERROR` | Auth/authorization | Terminal |
| `INTERNAL_ERROR` | Server internal error | Retryable until budget exhausts |
| `WRITE_ERROR` | Server write failure | Retryable until budget exhausts |
| unknown | Unknown | Terminal |

The preferred wire contract is stronger:

```text
status
sequence
message
disposition = RETRYABLE | POISON | TERMINAL
```

Without `disposition`, clients are guessing. The fallback above is conservative: ambiguous server errors stall and eventually become terminal, but they are not silently quarantined as bad data.

## Poison policy

Expose poison handling explicitly:

```rust
pub enum PoisonPolicy {
    Stop,
    QuarantineAndContinue,
}
```

### Stop

Low-level default.

Behavior:

- rejected frame remains in the main queue,
- sender becomes terminal,
- next checkpoint surfaces the rejection,
- user decides whether to inspect, delete, repair, or replay.

Trade-off:

- no implicit skip,
- one bad frame can stop the sender indefinitely.

### QuarantineAndContinue

Operational liveness mode.

Behavior:

- copy the rejected frame to `.poison`,
- write metadata,
- advance `completed_fsn`,
- emit a poison event,
- continue with later frames.

Suggested poison layout:

```text
<sf_dir>/<sender_id>/.poison/<fsn>.qwp
<sf_dir>/<sender_id>/.poison/<fsn>.json
```

Suggested metadata:

```json
{
  "fsn": 42,
  "wireSequence": 7,
  "status": "SCHEMA_MISMATCH",
  "statusCode": 3,
  "message": "server message, maybe truncated in event",
  "payloadBytes": 1024,
  "checksum": "..."
}
```

In volatile queue mode, quarantine can only be in-memory unless the user provides a poison directory. The API must report that poison data is not durable in that configuration.

## Reconnect and replay

Retryable transport failures:

- preserve order,
- reconnect with bounded backoff,
- reset wire sequence,
- replay from the first unresolved FSN,
- keep receipts valid.

Reconnect budget exhaustion:

- terminal error,
- all unresolved receipts become terminal,
- future submit calls fail until the sender is recreated.

Security/upgrade failures:

- terminal immediately,
- do not burn retry budget with unchanged credentials.

## Close behavior

No close path starts a background thread.

```rust
close_drain(timeout)
```

- stops accepting new submissions,
- drives until all published frames are completed or timeout expires,
- returns whether everything was ACKed/quarantined,
- leaves uncompleted SF frames recoverable.

```rust
close_fast()
```

- stops accepting new submissions,
- closes the connection,
- leaves unresolved SF frames in the slot,
- loses unresolved volatile-queue frames.

Dropping a sender should be equivalent to fast close. It should not attempt surprise draining.

## C ABI shape

Use value receipts, not heap-allocated completion handles. This avoids per-submit allocation and makes ownership simple.

```c
typedef struct line_sender_qwpws line_sender_qwpws;

typedef struct {
    uint64_t fsn;
} line_sender_qwpws_receipt;

typedef enum {
    LINE_SENDER_QWPWS_EVENT_NONE = 0,
    LINE_SENDER_QWPWS_EVENT_PUBLISHED,
    LINE_SENDER_QWPWS_EVENT_SENT,
    LINE_SENDER_QWPWS_EVENT_ACKED,
    LINE_SENDER_QWPWS_EVENT_DURABLE_ACK,
    LINE_SENDER_QWPWS_EVENT_RETRYING,
    LINE_SENDER_QWPWS_EVENT_RECONNECTED,
    LINE_SENDER_QWPWS_EVENT_POISONED,
    LINE_SENDER_QWPWS_EVENT_BACKPRESSURE,
    LINE_SENDER_QWPWS_EVENT_TERMINAL
} line_sender_qwpws_event_kind;

typedef struct {
    line_sender_qwpws_event_kind kind;
    uint64_t fsn;
    uint64_t wire_sequence;
    uint8_t qwp_status;
    bool message_truncated;
} line_sender_qwpws_event;

typedef enum {
    LINE_SENDER_QWPWS_RECEIPT_INVALID = 0,
    LINE_SENDER_QWPWS_RECEIPT_PENDING,
    LINE_SENDER_QWPWS_RECEIPT_ACKED,
    LINE_SENDER_QWPWS_RECEIPT_POISONED,
    LINE_SENDER_QWPWS_RECEIPT_TERMINAL
} line_sender_qwpws_receipt_status_kind;

typedef struct {
    line_sender_qwpws_receipt_status_kind kind;
    uint64_t fsn;
    uint8_t qwp_status;
} line_sender_qwpws_receipt_status;

typedef enum {
    LINE_SENDER_QWPWS_DELIVERY_ACKED = 0,
    LINE_SENDER_QWPWS_DELIVERY_POISONED,
    LINE_SENDER_QWPWS_DELIVERY_TIMEOUT,
    LINE_SENDER_QWPWS_DELIVERY_TERMINAL,
    LINE_SENDER_QWPWS_DELIVERY_INVALID_RECEIPT
} line_sender_qwpws_delivery_kind;

typedef struct {
    line_sender_qwpws_delivery_kind kind;
    uint64_t fsn;
    uint8_t qwp_status;
    bool message_truncated;
} line_sender_qwpws_delivery;

typedef enum {
    LINE_SENDER_QWPWS_CLOSE_DRAINED = 0,
    LINE_SENDER_QWPWS_CLOSE_TIMEOUT,
    LINE_SENDER_QWPWS_CLOSE_TERMINAL
} line_sender_qwpws_close_kind;

typedef struct {
    line_sender_qwpws_close_kind kind;
    uint64_t published_fsn;
    uint64_t completed_fsn;
} line_sender_qwpws_close_outcome;
```

For `LINE_SENDER_QWPWS_EVENT_ACKED`, `fsn` is the highest cumulatively ACKed FSN, not necessarily a single-frame ACK. `wire_sequence` is the highest cumulatively ACKed wire sequence on the current connection.

Construction:

```c
line_sender_qwpws* line_sender_qwpws_new(
    line_sender_utf8 config,
    line_sender_error** err_out);

void line_sender_qwpws_free(line_sender_qwpws* sender);
```

Buffer:

```c
line_sender_buffer* line_sender_qwpws_new_buffer(
    const line_sender_qwpws* sender,
    line_sender_error** err_out);
```

Submit and drive:

```c
bool line_sender_qwpws_submit(
    line_sender_qwpws* sender,
    line_sender_buffer* buffer,
    line_sender_qwpws_receipt* receipt_out,
    line_sender_error** err_out);

bool line_sender_qwpws_submit_and_keep(
    line_sender_qwpws* sender,
    const line_sender_buffer* buffer,
    line_sender_qwpws_receipt* receipt_out,
    line_sender_error** err_out);

bool line_sender_qwpws_drive_once(
    line_sender_qwpws* sender,
    uint64_t timeout_millis,
    line_sender_qwpws_event* event_out,
    char* message_buf,
    size_t message_buf_len,
    size_t* message_len_out,
    line_sender_error** err_out);

bool line_sender_qwpws_poll_event(
    line_sender_qwpws* sender,
    line_sender_qwpws_event* event_out,
    char* message_buf,
    size_t message_buf_len,
    size_t* message_len_out,
    line_sender_error** err_out);
```

Receipt wait/status:

```c
bool line_sender_qwpws_wait(
    line_sender_qwpws* sender,
    line_sender_qwpws_receipt receipt,
    uint64_t timeout_millis,
    line_sender_qwpws_delivery* outcome_out,
    char* message_buf,
    size_t message_buf_len,
    size_t* message_len_out,
    line_sender_error** err_out);

bool line_sender_qwpws_receipt_status(
    const line_sender_qwpws* sender,
    line_sender_qwpws_receipt receipt,
    line_sender_qwpws_receipt_status* status_out,
    line_sender_error** err_out);
```

Close:

```c
bool line_sender_qwpws_close_drain(
    line_sender_qwpws* sender,
    uint64_t timeout_millis,
    line_sender_qwpws_close_outcome* outcome_out,
    line_sender_error** err_out);

void line_sender_qwpws_close_fast(line_sender_qwpws* sender);
```

Rules:

- No C call starts a thread unless its name says so explicitly.
- `line_sender_qwpws_new` follows `open_mode`: `connected` may perform bounded initial connection work, while `lazy` performs local setup only.
- `submit` returns a receipt only after local publication.
- `submit` clears the buffer only after successful publication.
- `submit_and_keep` never clears the buffer.
- `drive_once` progresses network I/O on the caller thread when no runner owns progress.
- `wait` progresses network I/O only when no runner owns progress; while a runner is active, `wait` is passive and observes receipt state driven by the runner.
- Message text is copied into caller-provided storage.
- `line_sender_error` allocation is allowed only on error paths.

Pointer contract:

- Input handles are required to be non-NULL unless the function is documented as a free/close no-op.
- `err_out` is optional. Passing NULL discards error details.
- `receipt_out`, `event_out`, `status_out`, `outcome_out`, `runner_out`, and close `outcome_out` are required. Passing NULL returns `false` and sets `err_out` if provided.
- `message_len_out` is optional. When non-NULL, it receives the full message length before truncation.
- `message_buf` may be NULL only when `message_buf_len == 0`.
- If `message_buf` is too small, the copied message is truncated and the returned event/outcome sets `message_truncated=true`.
- On success, required output structs are always initialized, including `NONE`, `TIMEOUT`, and other non-error states.
- Timeout, pending, not-drained, and no-event states are not reported through `err_out`; they are normal outcomes.
- For `wait`, `receipt_status`, and `close_drain`, the boolean return reports whether the API call itself succeeded and initialized the output. Delivery state is reported only through the output enum.

Optional explicit runner:

```c
typedef struct line_sender_qwpws_runner line_sender_qwpws_runner;

bool line_sender_qwpws_runner_start(
    line_sender_qwpws* sender,
    line_sender_qwpws_runner** runner_out,
    line_sender_error** err_out);

void line_sender_qwpws_runner_stop(line_sender_qwpws_runner* runner);
```

This is the only C API that may start a thread.

Runner ownership and legal operations:

- `runner_start` does not consume `sender`; it creates a runner handle that owns the single progress driver until stopped.
- The runner holds its own internal reference to the sender state, so `line_sender_qwpws_free(sender)` must not create a use-after-free. Freeing the sender handle while a runner exists closes the user handle, but the runner remains responsible for stopping and releasing its reference.
- The caller must eventually call `line_sender_qwpws_runner_stop(runner)`.
- While a runner is active, `line_sender_qwpws_drive_once` rejects with an error because progress is runner-owned.
- While a runner is active, `line_sender_qwpws_wait` is passive: it blocks on condition variables/state changes and never performs socket I/O.
- While a runner is active, `submit`, `submit_and_keep`, `receipt_status`, `poll_event`, `close_drain`, and `close_fast` remain legal if the implementation provides the synchronization for them.
- `close_drain` while a runner is active stops accepting new submissions and passively waits for the runner to complete or time out.
- `close_fast` asks the runner to stop promptly and marks unresolved volatile frames lost / unresolved SF frames recoverable.

## C++ wrapper shape

```cpp
questdb::ingress::qwpws_sender sender{
    questdb::ingress::qwpws_opts::from_conf(
        "qwpws::addr=localhost:9000;sf_dir=/var/lib/qdb-sf;")};

auto buffer = sender.new_buffer();

auto receipt = sender.submit(buffer);        // clears buffer on success
auto receipt2 = sender.submit_and_keep(buffer);

while (auto event = sender.drive_once(10ms)) {
    if (event.kind() == event_kind::poisoned) {
        // inspect status/message/path
    }
}

auto outcome = sender.wait(receipt, 30s);
```

C++ can offer RAII and exceptions over the C ABI. It should not hide a background thread unless the user chooses a runner type.

## Python wrapper shape

Python can expose:

- blocking `submit`, `drive_once`, `wait`,
- an iterator over events,
- an optional background runner,
- optional asyncio integration built above the runner or a dedicated async extension.

The C ABI remains the stable base. Python object allocation is acceptable in the Python layer; it must not force allocation into the Rust core steady-state hot path.

## Steady-state allocation rule

The allocation target is steady state, not first use. After `open()`, warm-up, and buffer/queue sizing, the following paths should not allocate for workloads within configured bounds:

- `submit` for frames within configured bounds,
- `drive_once` send of already-published frames,
- ACK response parsing,
- receipt status checks,
- successful replay after reconnect.

Pre-size or reuse:

- frame/journal storage,
- in-flight table sized by `max_in_flight`,
- event ring sized by `event_capacity`,
- WebSocket send chunk scratch,
- response scratch,
- bounded server-message scratch,
- schema/symbol encode scratch and registries,
- receipt/status bookkeeping.

Allowed allocations:

- construction/open,
- user-requested buffer growth/reserve,
- first use of a table/schema/symbol shape if the caller has not prewarmed or reserved enough state,
- configured capacity growth outside the steady-state envelope,
- error object creation,
- poison metadata file writing,
- recovery path setup,
- reconnect setup if it rebuilds non-hot state,
- optional high-level adapters that document allocation.

Forbidden in the steady-state hot path:

- cloning the whole `Buffer` for replay,
- heap-allocating completion handles per submit,
- unbounded MPSC queues,
- `BTreeMap` or `HashMap` insertion per submitted frame,
- growing `Vec` while sending or parsing normal responses within configured bounds.

## Thread-safety model

Rust core:

- `QwpWsSender` is single-owner and driven through `&mut self`.
- `Buffer` is single-owner and not thread-safe.

C ABI:

- Without a runner, callers must serialize access to the sender handle.
- Exactly one driver may own network progress at a time.
- With a runner active, the runner owns progress. Synchronous `drive_once` is illegal; `wait` and `close_drain` become passive waiters.
- Functions that remain legal while the runner is active must be internally synchronized by the implementation.

Future multi-producer support should be a wrapper over the core with a bounded preallocated submission ring. It should not be the v1 low-level primitive.

## Configuration knobs

Candidate config keys:

| Key | Default | Meaning |
|---|---|---|
| `max_in_flight` | 128 | Sent but unresolved frames per connection. |
| `max_frame_bytes` | existing QWP cap | Maximum encoded QWP frame. |
| `queue_mode` | `volatile` | `volatile` RAM ring or file-backed `sf`. |
| `sf_dir` | unset | Required when `queue_mode=sf`; parent for sender slots. |
| `sender_id` | `default` | Slot name under `sf_dir`. |
| `sf_max_total_bytes` | TBD | Total queued bytes before submit backpressure. |
| `sf_segment_bytes` | TBD | Segment file size. |
| `sf_durability` | `page_cache` | `page_cache`, `flush`, or `append`; only valid with `queue_mode=sf`. |
| `poison_policy` | `stop` | `stop` or `quarantine`. |
| `event_capacity` | 1024 | Preallocated event ring size. |
| `max_error_message_bytes` | 1024 | Bounded server message storage. |
| `reconnect_max_duration_millis` | 300000 | Per-outage retry budget. |
| `reconnect_initial_backoff_millis` | 100 | Initial reconnect backoff. |
| `reconnect_max_backoff_millis` | 5000 | Backoff cap. |
| `open_mode` | `connected` | `connected` validates network/auth during construction; `lazy` performs local setup only. |
| `close_flush_timeout_millis` | 5000 | Default high-level close drain timeout. |

## First implementation slice

1. Add the threadless `QwpWsSender` core with `queue_mode=volatile` only.
2. Return value receipts from `submit`; no completion handles.
3. Implement fixed-capacity in-flight table and event ring.
4. Implement `drive_once`, `wait`, and close semantics.
5. Add the Java-style self-sufficient replay encoder path and tests proving a later frame replays alone on a fresh connection.
6. Encode all frames published by the new core in self-sufficient replay form.
7. Add C ABI for construct, new buffer, submit, drive, poll event, wait, receipt status, close.
8. Add mock-server tests for pipelining, cumulative ACKs, ordered server errors, close, and no buffer clear on failed submit.
9. Add file-backed `queue_mode=sf` segment storage and recovery.
10. Add poison policy and poison files.
11. Add explicit background runner with passive wait semantics.
12. Add Tokio adapter.
13. Add C++ and Python wrappers after the C ABI is stable.

## Tests

Rust core tests:

- submit returns before ACK,
- connected `open()` validates initial connection without starting a thread,
- `open_mode=lazy` accepts local submissions before first connection,
- successful submit clears buffer,
- failed submit preserves buffer,
- `submit_and_keep` preserves buffer,
- `max_in_flight` applies backpressure without steady-state allocation,
- cumulative ACK completes all covered receipts,
- ordered server errors leave later receipts unresolved until a later response resolves them,
- server parse/schema rejection follows poison policy,
- retryable transport failure replays from first unresolved FSN,
- reconnect exhaustion marks unresolved receipts terminal,
- close drain waits for published receipts,
- close fast leaves SF frames recoverable,
- event ring overflow increments dropped counter,
- self-sufficient replay encoder emits full schema and the required symbol dictionary prefix for every frame,
- a stored later frame from a repeated-schema/repeated-symbol workload can be sent alone on a fresh connection.

C ABI tests:

- construct from config,
- `open_mode=lazy` construct performs no network I/O,
- new QWP buffer for sender,
- submit/drive/wait happy path,
- caller-provided message buffer truncates safely,
- no hidden thread before runner start,
- explicit runner starts/stops cleanly,
- `drive_once` rejects while a runner owns progress,
- `wait` is passive while a runner owns progress,
- NULL required output pointers fail cleanly and optional `err_out` may be NULL,
- C++ RAII wrappers free exactly once.

System tests:

- live QuestDB QWP/WebSocket ingestion,
- many in-flight batches,
- schema expansion across batches,
- arrays, decimals, timestamps, UTF-8, sparse columns,
- process kill and SF recovery,
- poison file creation for deterministic bad batch.

## Open questions

1. Is `Stop` the right default for every low-level API, with `QuarantineAndContinue` opt-in?
2. Should high-level Python default to quarantine for operational liveness, or inherit low-level `Stop`?
3. Should volatile queue mode support poison persistence through an explicit `poison_dir`?
4. Can the server add `disposition = RETRYABLE | POISON | TERMINAL` before the FFI ABI is frozen?
5. What are the initial defaults for `sf_segment_bytes` and `sf_max_total_bytes`?
