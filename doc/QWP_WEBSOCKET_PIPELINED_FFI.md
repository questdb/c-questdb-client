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

The Java client is the reference for durable WebSocket feature set,
configuration names, and reconnect semantics. Rust can keep a smaller manual
core internally, but public knobs should match Java unless a language boundary
requires a different shape.

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
- Avoid silent data loss: server rejections must be observable through receipts,
  events, or error handlers.

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
    Rejected {
        status: QwpStatus,
        message_truncated: bool,
    },
    Timeout,
}

pub enum QwpDriveOutcome {
    Idle,
    Progress,
    Terminal,
}

impl QwpWsSender {
    pub fn open(opts: QwpWsOptions) -> Result<Self>;

    pub fn new_buffer(&self) -> Buffer;

    pub fn submit(&mut self, buffer: &mut Buffer) -> Result<QwpReceipt>;
    pub fn submit_and_keep(&mut self, buffer: &Buffer) -> Result<QwpReceipt>;

    pub fn drive_once(&mut self, timeout: Duration) -> Result<QwpDriveOutcome>;
    pub fn poll_event(&mut self) -> Option<QwpEvent>;
    pub fn receipt_status(&self, receipt: QwpReceipt) -> QwpReceiptStatus;
    pub fn wait(&mut self, receipt: QwpReceipt, timeout: Duration) -> Result<QwpDeliveryOutcome>;

    pub fn close_drain(&mut self, timeout: Duration) -> Result<CloseOutcome>;
    pub fn close_fast(&mut self);
}
```

Properties:

- `open()` performs local setup and initial TCP/TLS/WebSocket/auth work by
  default. `initial_connect_retry` controls whether initial connection failures
  retry with the reconnect policy or fail fast.
- `submit()` publishes to the local engine and returns a receipt. It does not wait for server ACK.
- `submit()` clears the caller buffer only after successful publication.
- `submit_and_keep()` publishes the same data without clearing the caller buffer.
- `drive_once()` is the low-level progress primitive. It performs bounded I/O,
  reconnect, replay, ACK handling, server-rejection handling, and event
  production, but it does not consume events. `poll_event()` is the only event
  consumer.
- For blocking transports, `drive_once()` should prefer sending already
  published frames while the in-flight window has room before performing a
  blocking response poll. A blocking read must only happen when there is
  in-flight work to observe and no immediately sendable frame, or when a
  higher-level wait/close loop is explicitly waiting for delivery progress.
- `wait()` is a convenience loop over `drive_once()` plus receipt-status checks.

The low-level type should prefer `&mut self` methods. That gives Rust callers a clear single-driver ownership model and avoids internal locks on the hot path.

## Open and initial connection

There is one constructor. It follows the Java sender model:

- local setup always happens,
- initial connection is attempted by default,
- initial failures fail fast unless `initial_connect_retry=true`,
- `initial_connect_retry=true` uses the same bounded backoff policy as
  reconnect,
- authentication, authorization, and protocol/upgrade failures are terminal
  even when initial retry is enabled.

Initial connection work may include:

- DNS resolution,
- TCP connect,
- TLS handshake,
- WebSocket upgrade,
- protocol negotiation,
- authentication failure detection.

All of that work must be bounded by configured connect/request timeouts. The
manual core still must not start a background thread, spawn a Tokio task, or
continue sending/replaying after `open()` returns. There is no public lazy
constructor mode in v1; applications that want to tolerate startup ordering use
`initial_connect_retry=true`, matching Java.

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
let sender = QwpWsSender::open(opts)?;
let threaded = QwpWsThreadedSender::start(sender)?;
```

Rules:

- The method name and type make the thread explicit.
- Starting the threaded adapter consumes the manual sender.
- Once consumed, the original sender cannot also call `drive_once()` or `wait()`
  as a progress owner.
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

### Commit-point invariant

Fallible work must not advance externally observable state before its commit
point:

- encoding failure must not consume a QWP/WebSocket wire sequence,
- failed payload materialization must not assign an FSN or return a receipt,
- failed local publication must not clear the caller buffer,
- failed SF append must not advance the published cursor,
- failed transport write/flush must not mark a frame `Sent`,
- failed ACK-driven segment trim must not delete partially ACKed frames or invent
  a durable completion marker.

This invariant is more important than the internal helper boundaries. The core
may refactor encoding, queue, and transport code, but the observable state
transitions must remain commit-after-success.

`SymbolGlobalDict` is not part of this external commit boundary. It is
append-only sender encoding state, like the Java cursor-SF global dictionary.
A failed encode or failed queue publication may reserve symbol IDs internally.
That must not return a receipt, assign an FSN, enqueue bytes, consume a wire
sequence, or clear the caller buffer. Because v1 replay frames carry the dense
dictionary prefix needed by their row payloads, reserved-but-unused lower IDs are
valid. They may make later frames larger, but they do not require dictionary
checkpoint/rollback for correctness.

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

The dictionary is intentionally simple and append-only in v1. A symbol ID
reserved by a failed submission attempt may appear later as part of the dense
prefix even if no published frame references that symbol. This mirrors the
state model of the Java sender, where symbol IDs are assigned before cursor
publication and only the sent watermark is commit-after-success.

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

The replay encoder does not need transactional dictionary rollback. Tests should
instead lock down the public boundary: failed materialization/publication returns
no receipt and publishes no bytes, while a later successful frame remains
self-sufficient even if earlier failed attempts reserved dictionary IDs.

Tests must store a later frame from a repeated-schema/repeated-symbol workload
and replay that frame alone against a fresh mock connection. That replay must
succeed without having sent the earlier frame.

## Java/Rust compatibility drift risks

The Java client is the closest working reference for cursor-style
Store-and-Forward, but it should not become an implicit, untested dependency.
Rust v1 should copy the Java-way replay invariant deliberately, then validate
the shared protocol behavior with fixtures and real-server probes.

The main drift risks are:

- Wire constants, status codes, feature/version negotiation, and close/error
  codes can diverge if Rust copies stale Java constants instead of the protocol
  source of truth.
- ACK identity can drift. Java maps connection-local `wireSeq` to durable FSN
  through `fsnAtZero + wireSeq`; Rust must keep the same separation between
  durable FSN and per-connection wire sequence, especially after reconnect.
- Self-sufficient replay can drift in small details: `confirmedMaxId = -1`,
  full schema mode, no schema references, and dense symbol dictionary prefix
  from id `0` through the highest referenced id.
- The v1 dense dictionary rule is intentionally Java-compatible, not a protocol
  ideal. If Rust later supports sparse referenced-entry dictionaries or durable
  state checkpoints, that is a new protocol/design step rather than a local
  encoder tweak.
- WebSocket masking can make byte comparisons misleading. Java/Rust golden tests
  should compare unmasked QWP application payload bytes, not WebSocket frames,
  because client mask keys are intentionally fresh on every send.
- Store-and-Forward disk format can drift if Rust invents its own journal. The
  product file-backed format must be Java's `.sfa` segment format, not a
  Rust-specific log with ACK or rejection records.
- Error policy can drift if Rust invents a richer rejection/dead-letter model.
  Match Java's default server-rejection categories first, preserve raw
  status/message, and add new policy only if Java grows the same surface.
- Durability naming can drift if Rust exposes internal queue names. Public
  configuration should follow Java: `sf_dir` unset means memory mode, `sf_dir`
  set means SF mode, and `sf_durability` uses Java's `memory` / `flush` /
  `append` labels.
- Close semantics can drift because Java has a background I/O loop while Rust's
  low-level API is threadless by default. Shared behavior should be defined in
  terms of submitted, ACKed, rejected, and recoverable frames, not Java thread
  lifecycle.
- Encoding edge cases can drift across clients even when the happy path matches:
  arrays, decimals, timestamps, UTF-8, sparse columns, table/schema evolution,
  and symbol reuse need fixture coverage.

Validation should include Java/Rust golden cases at two layers. For the same
logical batches, Java and Rust should emit equivalent unmasked QWP payloads for
v1 replay mode. For file-backed SF, Java and Rust should read and write the same
`.sfa` segment files. When exact payload byte equality is not practical because
an agreed non-semantic field differs, the fixture should document the field and
the real-server probe should verify that both payloads ingest to the same rows.

## Store-and-Forward engine

The engine assigns an FSN when it publishes a frame.

Core cursors:

```text
published_fsn       highest frame published into the engine
server_acked_fsn    highest contiguous frame accepted by the server
completed_fsn       highest contiguous frame ACKed or server-rejected
```

Do not count rejected frames as server ACKed.

A frame is *resolved* when its receipt reaches a final delivery state:
ACKed, server-rejected, or terminal. `completed_fsn` advances through contiguous
resolved frames. `server_acked_fsn` advances only through contiguous ACKed frames
and can therefore lag behind `completed_fsn` across rejection gaps.

Durable state is deliberately smaller than runtime state. The queue stores only
retained publication data:

- Java-compatible `.sfa` segment files,
- each segment's base FSN,
- self-sufficient QWP payload bytes per frame,
- CRC32C enough to recover through torn tails.

The queue does not store ACK-through records, rejection records, receipt handles,
or server status payloads. ACK and rejection outcomes are runtime facts. Their
only durable effect is indirect: fully ACKed sealed segments may be trimmed from
the slot. After a process crash, retained frames may be replayed even if the
previous process had already received an ACK for them but had not durably trimmed
the containing segment. This is the Java-compatible at-least-once model.

The queue does not store connection-local state:

- `Sent` receipt status,
- WebSocket wire sequence,
- in-flight table contents,
- WebSocket mask keys,
- WebSocket headers or masked payload bytes.

After process recovery, every retained frame is `Published`, not `Sent`.
The next connection rebuilds its in-flight table from scratch, maps the lowest
retained FSN to wire sequence `0`, and replays from there. This is the same
model as reconnect replay, except process restart may replay retained frames
whose previous runtime ACK state was lost before segment trim.

### Volatile queue mode

Volatile queue mode uses a preallocated in-memory ring of frame slots.

Properties:

- survives transient reconnect,
- does not survive process exit,
- still uses receipts, in-flight slots, and event semantics,
- applies the same backpressure behavior as SF mode.

### File-backed SF queue mode

File-backed Store-and-Forward mode stores frames in Java-compatible segment files
under a sender slot:

```text
<sf_dir>/<sender_id>/
  .lock
  sf-initial.sfa
  sf-0000000000000001.sfa
  sf-0000000000000002.sfa
```

The disk format is the Java client `.sfa` format. Rust must match the bytes Java
writes; on supported little-endian platforms that means the layout below. Golden
fixtures protect this contract.

```text
segment_header {
    u32 magic        // 'SF01'
    u8  version      // 1
    u8  flags        // 0
    u16 reserved     // 0
    u64 base_seq     // FSN of first frame in this segment
    u64 created_us
}

frame {
    u32 crc32c       // over payload_len followed by payload bytes
    u32 payload_len
    u8  payload[payload_len]
}
```

There are no Rust-specific record tags, no WebSocket frame headers, and no
WebSocket mask bytes in the segment. The stored frame payload is the unmasked QWP
application payload sent as one WebSocket binary message.

Publication follows the Java segment invariant:

1. Reserve the frame header and write `payload_len` at frame offset `+4`.
2. Write payload bytes after the frame header.
3. Compute CRC32C over `payload_len || payload` and write it at frame offset `0`.
4. Advance the in-process published cursor only after the complete frame is in
   the segment mapping.

Recovery scans each `.sfa` file from the segment header through valid frames.
The first frame with a negative length, a length past the file end, or a CRC32C
mismatch is a torn tail. The recovered append cursor is positioned at that frame
so the next append overwrites it. Segment files are sorted by `base_seq`; the
recovered ranges must be contiguous. The highest-base segment becomes active and
older segments become sealed.

The `.lock` file is part of the slot contract. A sender must hold an exclusive
slot lock before it recovers, appends, rotates, or trims `.sfa` files. Two live
writers in one slot would corrupt the FSN sequence and must fail at startup.

ACK handling follows Java's segment-trim model. Runtime ACKs advance an in-memory
ACK cursor. Fully ACKed sealed segments may be closed and unlinked. Active
segments are not rewritten to remove individual ACKed frames. Server
drop-and-continue rejection advances the same ACK cursor for the rejected FSN and
reports the rejection to the user; halt/terminal rejection leaves bytes in place.
No rejection marker is written to disk.

Public mode selection follows Java:

| Public mode | Trigger | Storage | Survives process crash | Survives OS crash |
|---|---|---|---|---|
| Memory | `sf_dir` unset | preallocated RAM ring | No | No |
| Store-and-Forward | `sf_dir` set | segment files under `<sf_dir>/<sender_id>/` | Yes, after publication | Not guaranteed in v1 |

`sf_durability` is a Java-compatible knob for SF mode. The public values are
`memory`, `flush`, and `append`. v1 supports only `memory`, meaning copied to
the mmap/page cache and published without an fsync guarantee. `flush` and
`append` are reserved and should fail loudly until implemented, matching Java's
current behavior.

| SF durability | Submit returns after | Survives process crash | Survives OS crash |
|---|---|---|---|
| `memory` | record copied into mmap/page cache and published | Yes | Not guaranteed |
| `flush` | reserved; fail until implemented | Yes | Yes after flush boundary |
| `append` | reserved; fail until implemented | Yes | Yes per receipt |

Internally the Rust code may still call these volatile and SF queues. The public
configuration should not expose a separate mode flag; the presence of `sf_dir`
is the mode switch.

## Pipelining model

`max_in_flight` bounds frames sent but not yet completed.

The driver sends frames in FSN order. It may send up to `max_in_flight` unresolved frames on one connection.

Each wire connection has a wire sequence counter. On reconnect:

```text
wire_seq = 0
replay starts at first unresolved FSN
connection-scoped encoder state is reset
```

The same reset happens after process recovery from file-backed SF state. Durable
FSN remains stable, but wire sequence is always per connection. Therefore an
ACK for `wire_seq = 0` on a recovered connection maps to the oldest unresolved
FSN, not necessarily FSN `0`.

The server processes submitted WebSocket frames strictly in wire-sequence order. Responses do not complete arbitrary later frames ahead of earlier frames.

The server may coalesce successful ACKs by sending only the highest successful wire sequence. An `OK(sequence=N)` response means every unresolved successful frame up to `N` is accepted unless a prior rejection gap prevents contiguous server ACK advancement. The client maps that cumulative wire sequence to the corresponding FSN, marks covered successful receipts ACKed, and advances `server_acked_fsn` only through contiguous ACKed FSNs.

If the server sends an error for sequence `N`, prior unresolved frames below `N`
are treated as ACKed if they were covered by the server's ordering guarantee.
Frame `N` follows the Java-compatible server-rejection policy. Later frames
remain unresolved until a later cumulative OK or error response resolves them.

Responses resolve frames. Rejection policy only decides whether the sender keeps
sending after the already-sent in-flight window is resolved. The driver must not
stop reading immediately on a deterministic server error because the server can
still accept and later ACK frames that were already in flight.

Example:

```text
OK(0), Error(1), OK(2)

receipt 0      ACKed
receipt 1      Rejected
receipt 2      ACKed
server_acked   0
completed      2
```

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

The durable queue stores QWP application payload bytes, not WebSocket frames.
WebSocket headers, mask keys, and masked payload bytes are transport artifacts.
They must not be part of the durable frame identity, segment CRC, receipt state,
or replay comparison.

Client-to-server WebSocket payloads must be masked. Apply masking fresh on every
send or replay after reading the stored QWP payload. The same stored FSN may be
sent multiple times with different WebSocket mask keys; the server must observe
the same unmasked QWP payload each time.

Durable QWP payload bytes must not be modified in place. If masking is done by
copy-and-XOR, copy from the stored payload into send scratch and mask the copy.
If masking is streamed, XOR only the outbound chunks.

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

Client-originated control frames, such as close, ping, and pong, follow the same
transport rule: mask them at the WebSocket layer and keep that state out of the
QWP/SF engine.

Inbound responses are small. Preallocate:

```text
read_header_scratch
response_payload_scratch
max_error_message_bytes
```

Server-to-client WebSocket frames are expected to be unmasked. A masked server
response is a WebSocket protocol error, not a QWP delivery outcome.

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
    Rejected { fsn: u64, status: QwpStatus, message_truncated: bool },
    Backpressure { duration: Duration, reason: BackpressureReason },
    Terminal { error: QwpErrorSummary },
}
```

The event ring is preallocated. On overflow, increment `events_dropped_total` and retain the latest terminal/rejection state in direct accessors.

Events are transition notifications, not authoritative state. `receipt_status()`,
`wait()`, and `close_drain()` remain the state surfaces. Calls that drive
progress may produce events, but they should not consume them; `poll_event()`
is the consumer API.

Message text used by `wait()` and receipt/outcome queries must not depend on the
event ring. A rejection or terminal event may be dropped or already polled, so
the core must retain bounded diagnostic details with the affected receipt or
sender state for as long as that state remains observable.

## Server error classification

Current QWP response statuses include:

| Status | Meaning | Default disposition |
|---|---|---|
| `OK` | Batch accepted | ACK |
| `DURABLE_ACK` | Per-table durability notification | Event, not batch completion |
| `SCHEMA_MISMATCH` | Bad schema/data for table | Drop-and-continue / rejected receipt |
| `SECURITY_ERROR` | Auth/authorization | Terminal |
| `PARSE_ERROR` | Bad payload | Terminal |
| `INTERNAL_ERROR` | Server internal error | Terminal |
| `WRITE_ERROR` | Non-critical write failure | Drop-and-continue / rejected receipt |
| unknown | Unknown | Terminal |

The preferred wire contract is stronger:

```text
status
sequence
message
disposition = RETRYABLE | DROP_AND_CONTINUE | TERMINAL
```

Without `disposition`, clients are still applying policy rather than receiving a
server guarantee. The fallback above follows Java's current defaults: schema and
write rejections are frame-local and reportable; parse, internal, security,
protocol, and unknown errors halt the sender.

A real-server probe after the server taxonomy fix showed that a deterministic
string-to-DOUBLE failure is reported as `SCHEMA_MISMATCH`, not `WRITE_ERROR`,
while still being sequence-specific: the bad frame is reported with its sequence
and a later valid frame can still be ACKed. This keeps bad-data handling in the
frame-local rejection path and narrows `WRITE_ERROR` back toward operational
write failures.

## Server rejection reporting

Do not add a Rust-only dead-letter file subsystem in v1. Match Java's model:

- preserve raw server status, wire sequence, message, affected FSN span, and
  table attribution when available,
- expose the rejected frame through receipt status / wait outcome,
- publish a transition event or call the configured handler,
- drop-and-continue only for the Java-compatible categories,
- latch terminal categories so the next producer call reports the error.

The Java client has no client-owned dead-letter file format for rejected
batches. Its drop-and-continue path advances the acknowledged FSN so the
existing Store-and-Forward trim path can forget the rejected bytes, and it
delivers a structured `SenderError` to user code. Java's `.corrupt` files are a
different mechanism: recovery quarantine for damaged `.sfa` segment files, not
dead-letter storage for server-rejected batches.

Users that need durable dead-letter storage can implement it in the error
handler by joining the reported FSN span to their own producer-side log. The
client should not create dead-letter files or expose a rejection-policy knob
unless Java grows that feature too.

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

For file-backed SF mode, terminalizing the current sender's receipts does not
ACK, reject, or delete unresolved retained SF frames. Those frames remain in the
slot and can be recovered by a newly created sender after the operator fixes
configuration, credentials, or server availability. ACK and server-rejection
outcomes do not append durable completion records; they only affect runtime
receipt state and, for ACK/drop-and-continue, ACK-driven segment trim.

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
- returns whether everything was ACKed or server-rejected,
- leaves uncompleted SF frames recoverable.

If `close_drain()` times out, the current sender remains closing: new
submissions fail, but existing receipts remain observable and unresolved SF
frames remain recoverable by a newly created sender. If progress becomes
terminal during close drain, the close outcome is terminal rather than timeout.

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

C callers allocate the output structs, so the first ABI shape should be treated
as frozen once released. Do not add speculative reserved fields to every struct;
if later server features need more detail, add explicit v2 structs/functions or
detail accessors.

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
    LINE_SENDER_QWPWS_EVENT_REJECTED,
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
    LINE_SENDER_QWPWS_DRIVE_IDLE = 0,
    LINE_SENDER_QWPWS_DRIVE_PROGRESS,
    LINE_SENDER_QWPWS_DRIVE_TERMINAL
} line_sender_qwpws_drive_kind;

typedef struct {
    line_sender_qwpws_drive_kind kind;
} line_sender_qwpws_drive_outcome;

typedef enum {
    LINE_SENDER_QWPWS_RECEIPT_INVALID = 0,
    LINE_SENDER_QWPWS_RECEIPT_PENDING,
    LINE_SENDER_QWPWS_RECEIPT_ACKED,
    LINE_SENDER_QWPWS_RECEIPT_REJECTED,
    LINE_SENDER_QWPWS_RECEIPT_TERMINAL
} line_sender_qwpws_receipt_status_kind;

typedef struct {
    line_sender_qwpws_receipt_status_kind kind;
    uint64_t fsn;
    uint8_t qwp_status;
} line_sender_qwpws_receipt_status;

typedef enum {
    LINE_SENDER_QWPWS_DELIVERY_ACKED = 0,
    LINE_SENDER_QWPWS_DELIVERY_REJECTED,
    LINE_SENDER_QWPWS_DELIVERY_TIMEOUT,
    LINE_SENDER_QWPWS_DELIVERY_TERMINAL
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
    bool has_published_fsn;
    uint64_t published_fsn;
    bool has_server_acked_fsn;
    uint64_t server_acked_fsn;
    bool has_completed_fsn;
    uint64_t completed_fsn;
} line_sender_qwpws_close_outcome;
```

For `LINE_SENDER_QWPWS_EVENT_ACKED`, `fsn` is the highest cumulatively ACKed FSN, not necessarily a single-frame ACK. `wire_sequence` is the highest cumulatively ACKed wire sequence on the current connection. ACKed-through and completed-through are intentionally different across rejection gaps: `completed_fsn` can advance past a rejected frame while `server_acked_fsn` cannot.

`LINE_SENDER_QWPWS_EVENT_DURABLE_ACK` is intentionally only a notification in
the first ABI shape. Per-table durable ACK detail should be added later through a
separate detail accessor or v2 event struct if callers need it.

Client-managed dead-letter file paths are not part of the first C ABI
shape. The low-level C outcome carries status and bounded message text. Add a
separate detail accessor later only if Java grows an equivalent durable
dead-letter feature.

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
    line_sender_qwpws_drive_outcome* outcome_out,
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

bool line_sender_qwpws_get_receipt_status(
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
- `line_sender_qwpws_new` follows Java connection semantics: it performs local
  setup and initial connection work by default; `initial_connect_retry` controls
  bounded startup retry.
- `submit` returns a receipt only after local publication.
- `submit` clears the buffer only after successful publication.
- `submit_and_keep` never clears the buffer.
- Core submit calls require `receipt_out`. A no-receipt convenience can be added
  later as a thin wrapper that discards the value receipt, but it should not
  change local publication semantics.
- `drive_once` progresses network I/O on the caller thread and writes only a
  drive outcome. It may produce events internally, but callers observe those
  events only through `poll_event`.
- `wait` is a manual-sender convenience loop over `drive_once()` plus receipt
  status checks.
- Starting the threaded adapter consumes the manual sender handle. There is no
  runtime "runner active" mode on a manual sender.
- Message text is copied into caller-provided storage.
- `line_sender_error` allocation is allowed only on error paths.
- New QWP/WS FFI functions catch Rust panics and convert them to API failures.
  Rust panics must not cross the C ABI boundary.

Pointer contract:

- Input handles are required to be non-NULL unless the function is documented as a free/close no-op.
- `err_out` is optional. Passing NULL discards error details.
- `receipt_out`, `event_out`, `status_out`, `outcome_out`, `threaded_out`, and close `outcome_out` are required for functions that declare them. Passing NULL returns `false` and sets `err_out` if provided.
- `message_len_out` is optional. When non-NULL, it receives the full message length before truncation.
- `message_buf` may be NULL only when `message_buf_len == 0`.
- If `message_buf` is too small, the copied message is truncated and the returned event/outcome sets `message_truncated=true`.
- On success, required output structs are always initialized, including `NONE`, `TIMEOUT`, and other non-error states.
- Timeout, pending, not-drained, idle, and no-event states are not reported through `err_out`; they are normal outcomes.
- For `drive_once`, `wait`, `receipt_status`, and `close_drain`, the boolean
  return reports whether the API call itself succeeded and initialized the
  output. Progress, delivery, status, and close state are reported only through
  the output enum/struct.
- `receipt_status` can report `LINE_SENDER_QWPWS_RECEIPT_INVALID` as a normal
  status query result. `wait` on an invalid or unknown receipt is an API failure:
  it returns `false` and sets `err_out` when provided.
- Close outcome FSN fields are valid only when their matching `has_*` field is
  true. This avoids sentinel values when a sender has not published, ACKed, or
  completed any frame.

Optional explicit threaded adapter:

```c
typedef struct line_sender_qwpws_threaded line_sender_qwpws_threaded;

bool line_sender_qwpws_threaded_start(
    line_sender_qwpws** sender,
    line_sender_qwpws_threaded** threaded_out,
    line_sender_error** err_out);

void line_sender_qwpws_threaded_stop(line_sender_qwpws_threaded* threaded);
```

This is the only C API that may start a thread.

Threaded ownership and legal operations:

- `threaded_start` consumes the manual sender handle on success.
- The caller passes `&sender`; on success, `*sender` is set to `NULL` and the
  returned threaded handle owns the core.
- On failure, `*sender` remains unchanged and the caller still owns it.
- Passing a NULL `sender` pointer, a NULL `*sender`, or a NULL `threaded_out`
  returns `false` and sets `err_out` if provided.
- The caller must eventually call `line_sender_qwpws_threaded_stop(threaded)`.
- Manual operations such as `line_sender_qwpws_drive_once` and
  `line_sender_qwpws_wait` are no longer available through the consumed sender.
- The threaded API should expose its own synchronized submit, wait, poll, drain,
  and close calls rather than reusing the manual handle with runtime
  "runner active" checks.
- Stopping the runner returns no manual sender. If the application wants manual
  control again, it should close the threaded sender and create or recover a new
  manual sender from the same SF slot.

## C++ wrapper shape

```cpp
questdb::ingress::qwpws_sender sender{
    questdb::ingress::qwpws_opts::from_conf(
        "qwpws::addr=localhost:9000;sf_dir=/var/lib/qdb-sf;")};

auto buffer = sender.new_buffer();

auto receipt = sender.submit(buffer);        // clears buffer on success
auto receipt2 = sender.submit_and_keep(buffer);

while (sender.receipt_status(receipt).is_pending()) {
    sender.drive_once(10ms);
    while (auto event = sender.poll_event()) {
        if (event.kind() == event_kind::rejected) {
            // inspect status/message
        }
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
- user error-handler/dead-letter file writing outside the core,
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
- The manual sender is the progress owner until it is consumed by a threaded or
  async adapter.
- After a threaded adapter consumes the manual sender, callers use only the
  threaded handle's synchronized API.
- The manual API does not contain a runtime "runner active" state.

Future multi-producer support should be a wrapper over the core with a bounded preallocated submission ring. It should not be the v1 low-level primitive.

## Configuration knobs

Candidate config keys:

| Key | Default | Meaning |
|---|---|---|
| `max_in_flight` | 128 | Sent but unresolved frames per connection. |
| `max_frame_bytes` | existing QWP cap | Maximum encoded QWP frame. |
| `sf_dir` | unset | Enables file-backed SF when set; otherwise memory mode. |
| `sender_id` | `default` | Slot name under `sf_dir`. |
| `sf_max_bytes` | 4 MiB | Segment size, matching Java naming. |
| `sf_max_total_bytes` | 128 MiB memory / 10 GiB SF | Total queued bytes before submit backpressure. |
| `sf_durability` | `memory` | Java-compatible values are `memory`, `flush`, `append`; v1 supports only `memory` and fails loudly for the reserved values. |
| `sf_append_deadline_millis` | 30000 | Deadline for submit/flush waiting on local capacity. |
| `event_capacity` | 1024 | Preallocated event ring size. |
| `max_error_message_bytes` | 1024 | Bounded server message storage. |
| `reconnect_max_duration_millis` | 300000 | Per-outage retry budget. |
| `reconnect_initial_backoff_millis` | 100 | Initial reconnect backoff. |
| `reconnect_max_backoff_millis` | 5000 | Backoff cap. |
| `initial_connect_retry` | `false` | Retry initial connect with reconnect policy. |
| `close_flush_timeout_millis` | 5000 | Default high-level close drain timeout. |
| `drain_orphans` | `false` | Adopt sibling SF slots on startup. |
| `max_background_drainers` | 4 | Cap concurrent orphan drainers. |

Rust currently parses and validates the Java-compatible `sf_*` / `sender_id`
config keys, including Java's size suffixes (`k`, `m`, `g`, `t` with optional
trailing `b`) and reserved `sf_durability=flush|append` values. Until the
public sender is moved onto the new pipelined queue/driver core, SF runtime
knobs such as `sf_dir` and `sf_max_bytes` must fail before connecting rather
than being silently ignored.

## First implementation slice

1. Add the Java-style self-sufficient replay encoder path and tests proving a later frame replays alone on a fresh connection.
2. Add Java/Rust golden payload fixtures for replay-mode QWP bytes.
3. Add the threadless `QwpWsSender` core with Java-style memory mode
   (`sf_dir` unset) only.
4. Wire `submit` through `Buffer -> replay payload -> queue publication`; return value receipts only after publication.
5. Implement fixed-capacity in-flight table and event ring.
6. Implement `drive_once`, `wait`, and close semantics.
7. Validate the full Rust-only path against real QWP/WebSocket: replay payload publication, manual driver transport, ACK, and reconnect replay.
8. Add C ABI for construct, new buffer, submit, drive, poll event, wait, receipt status, close.
9. Add mock-server tests for pipelining, cumulative ACKs, ordered server errors, close, and no buffer clear on failed submit.
10. Add Java-compatible `.sfa` file-backed SF segment storage, recovery, slot
    locking, rotation, and ACK-driven trim behind `sf_dir`.
11. Add Java/Rust `.sfa` golden fixtures before treating the disk format as a
    product contract.
12. Add Java-compatible server rejection reporting and handler plumbing.
13. Add explicit background runner as an ownership-consuming adapter.
14. Add Tokio adapter.
15. Add C++ and Python wrappers after the C ABI is stable.

## Tests

Rust core tests:

- submit returns before ACK,
- connected `open()` validates initial connection without starting a thread,
- `initial_connect_retry=true` retries startup connection with the reconnect
  policy,
- successful submit clears buffer,
- failed submit preserves buffer,
- `submit_and_keep` preserves buffer,
- `max_in_flight` applies backpressure without steady-state allocation,
- cumulative ACK completes all covered receipts,
- ordered server errors leave later receipts unresolved until a later response resolves them,
- server rejection follows Java-compatible defaults and preserves raw
  status/message,
- retryable transport failure replays from first unresolved FSN,
- reconnect exhaustion marks unresolved receipts terminal,
- close drain waits for published receipts,
- close fast leaves SF frames recoverable,
- event ring overflow increments dropped counter,
- self-sufficient replay encoder emits full schema and the required symbol dictionary prefix for every frame,
- Java/Rust replay-mode fixtures agree on unmasked QWP payload bytes, or document
  any agreed non-semantic byte differences and validate them against a real
  server,
- a stored later frame from a repeated-schema/repeated-symbol workload can be sent alone on a fresh connection,
- Java/Rust `.sfa` header golden fixture agrees on magic `SF01`, version `1`,
  flags/reserved zero, `base_seq`, and `created_us` field placement,
- Java/Rust `.sfa` frame golden fixture agrees on
  `[crc32c][payload_len][payload]`, including CRC32C over
  `payload_len || payload`,
- a Java-written SF slot can be opened by Rust and replayed in FSN order,
- a Rust-written SF slot can be opened by Java and replayed in FSN order,
- recovery ignores a torn tail in the same way as Java and appends at the first
  invalid frame offset,
- ACK/drop-and-continue rejection does not create Rust-only disk records; only
  ACK-driven segment trim changes the retained `.sfa` set,
- SF segment frames store unmasked QWP payload bytes, not WebSocket headers or masked payloads,
- replaying the same stored frame can use a fresh WebSocket mask key without changing the stored bytes,
- masked server-to-client WebSocket frames are rejected as protocol errors.

C ABI tests:

- construct from config,
- `initial_connect_retry` is parsed and bounded by reconnect configuration,
- new QWP buffer for sender,
- submit/drive/wait happy path,
- `drive_once` reports idle/progress/terminal without consuming events,
- `poll_event` is the only event consumer,
- `receipt_status` can report invalid receipts while `wait` rejects them as API
  failures,
- close outcome initializes `has_*` flags correctly when no frame has been
  published, ACKed, or completed,
- caller-provided message buffer truncates safely,
- no hidden thread before runner start,
- explicit runner starts/stops cleanly,
- threaded start consumes the manual handle so manual `drive_once`/`wait` cannot
  race the runner through normal API use,
- NULL required output pointers fail cleanly and optional `err_out` may be NULL,
- C++ RAII wrappers free exactly once.

System tests:

- live QuestDB QWP/WebSocket ingestion,
- many in-flight batches,
- schema expansion across batches,
- arrays, decimals, timestamps, UTF-8, sparse columns,
- process kill and SF recovery,
- Java-compatible server rejection reporting.

## Open questions

1. Can the server add `disposition = RETRYABLE | DROP_AND_CONTINUE | TERMINAL`
   before the FFI ABI is frozen?
2. Are Java's `SCHEMA_MISMATCH` / `WRITE_ERROR` drop-and-continue defaults the
   right defaults for all FFI users, or should Rust expose only the raw
   rejection and let wrappers choose?
3. Should `flush` and `append` values for `sf_durability` remain parse-and-fail
   until implemented, exactly like Java, or be omitted from C constants until
   they work?
4. Should per-table durable ACK details be v2 C ABI accessors, or are they
   important enough for v1?
