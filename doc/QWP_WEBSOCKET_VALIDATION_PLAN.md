# QWP/WebSocket pipelined design validation plan

Status: **active draft**. This document is a validation plan for
`doc/QWP_WEBSOCKET_PIPELINED_FFI.md`, not an implementation schedule.

The goal is to validate the main design decisions for pipelined QWP over
WebSocket with Store-and-Forward in Rust and the C/C++/Python FFI layers.

The plan is intentionally iterative. Each step should validate one design bet,
then stop for reflection before adding the next layer.

## Current progress

As of 2026-04-29:

- Step 1 has a sketch in `doc/QWP_WEBSOCKET_API_SKETCH.md`.
- Step 2 has a type-only ownership prototype and reflection in
  `doc/QWP_WEBSOCKET_PROGRESS_OWNERSHIP_PROTOTYPE.md`; the live Rust manual
  sender has since been simplified so it only represents a real connected
  progress owner.
- Step 3 has a Rust encoder-only byte-shape spike and reflection in
  `doc/QWP_WEBSOCKET_REPLAY_ENCODER_SPIKE.md`.
- Step 3 has a Java/Rust replay payload golden fixture and reflection in
  `doc/QWP_WEBSOCKET_JAVA_RUST_GOLDEN_PAYLOADS.md`.
- Step 4 has a passing real-server self-sufficient replay probe in
  `doc/QWP_WEBSOCKET_SELF_SUFFICIENT_REPLAY_PROBE.md`.
- Step 4 also corrected the client-side wire-sequence assumption: the first
  QWP/WebSocket frame on a fresh connection is ACKed as sequence `0`.
- Step 5 has a transport-free volatile queue and receipt prototype with
  reflection in `doc/QWP_WEBSOCKET_VOLATILE_QUEUE_PROTOTYPE.md`.
- Step 6 has a manual-driver prototype over a fake ordered server with
  reflection in `doc/QWP_WEBSOCKET_MANUAL_DRIVER_PROTOTYPE.md`.
- Step 7 has a passing real-server ACK/order/reject probe in
  `doc/QWP_WEBSOCKET_ACK_ORDER_REJECT_PROBE.md`.
- Step 8 has a minimal file-backed SF queue prototype and reflection in
  `doc/QWP_WEBSOCKET_SF_QUEUE_PROTOTYPE.md`. That prototype validated recovery
  mechanics but is not the product disk format and is no longer wired into the
  driver seam. The product SF store must use the Java-compatible `.sfa` segment
  format.
- Step 9 has driver/error seam coverage for server rejection, terminal,
  close-drain, retry-budget behaviour, and event polling agreement in
  `doc/QWP_WEBSOCKET_ERROR_POLICY_PROTOTYPE.md`.
- Step 10 has a first real-server error taxonomy probe for parse error,
  schema mismatch, and deterministic value/type coercion in
  `doc/QWP_WEBSOCKET_ERROR_TAXONOMY_PROBE.md`; auth/upgrade rejection and
  deterministic internal/retryable write failure remain deferred.
- Step 11 has C ABI shape stubs for value receipts, progress-only drive,
  event polling, receipt status, wait, close outcomes, and threaded ownership.
  The public C header parses as C and C++; receipt status uses
  `line_sender_qwpws_get_receipt_status` to avoid the C typedef/function
  namespace collision.
- Step 12 has a first real blocking WS/WSS transport adapter behind
  `ManualDriverTransport`, with reflection in
  `doc/QWP_WEBSOCKET_REAL_TRANSPORT_PROTOTYPE.md`. The adapter reuses the
  existing sync connection and frame helpers, keeps stored payload identity as
  unmasked QWP bytes, preserves the two-phase send rule, and handles cumulative
  ACK after multiple sends.
- Step 12 also has a Rust-only publication shell with reflection in
  `doc/QWP_WEBSOCKET_PUBLICATION_SHELL_PROTOTYPE.md`. The shell owns replay
  encoder state and publishes `Buffer -> replay payload -> queue` bytes through
  the manual driver.
- Step 12 now has real QuestDB publication and reconnect e2e probes with
  reflection in `doc/QWP_WEBSOCKET_PUBLICATION_E2E_PROBE.md`. They validate
  `Buffer -> replay payload -> volatile queue -> manual driver ->
  BlockingQwpWsTransport -> QuestDB -> queryable row`, including a fault-proxy
  reconnect case where an already-ACKed frame is not duplicated and an
  unresolved frame is replayed after reconnect.
- Extended Java/Rust fixtures for arrays, decimals, UTF-8 strings, sparse
  columns, and schema evolution remain recommended before hardening the full
  product surface.
- The 2026-04-30 design adjustment is that the ordinary Rust `Sender` should
  converge on Java's high-level model: `flush()` publishes into bounded local
  memory/SFA storage and returns without waiting for the submitted frame's
  server ACK, while a sender-owned runner advances WebSocket I/O. `flush()` may
  still wait for local capacity or the current reconnect critical section. The
  latest runner slice already moves ordinary socket send and non-blocking
  receive polling outside the publication mutex; reconnect/backoff remains the
  next coupling to remove. The manual `QwpWsSender` remains the threadless
  progress-owner API.

## Validation discipline

Work one step at a time.

After each step, write a short note with exactly these headings:

```text
Local reflection
- How does this particular step feel?
- What was simpler or more awkward than expected?
- Did the API or implementation shape create accidental complexity?

Global reflection
- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?
- Did this step strengthen or weaken the core assumptions?
- Should the next step proceed, or should the design be adjusted first?
```

If either reflection feels bad, stop and adjust the design before continuing.

This is the main value of the plan: it should reveal weak assumptions while the
cost of changing them is still small.

## Mock and real-server split

Use mocks and real-server probes for different jobs:

```text
Mocks validate client design.
Real-server probes validate protocol truth.
Full integration validates the product.
```

Mocks are the right tool for queue invariants, receipt state, crash recovery,
progress ownership, and FFI shape. They are not enough for protocol assumptions.

Real-server probes should be narrow gates, not full integration work. A probe
can be a throwaway harness or a focused ignored test. Its job is to invalidate
bad assumptions early.

Each real-server probe should record:

- QuestDB build/version used
- relevant server configuration
- exact client-side scenario
- observed server response, close behavior, or table result
- whether the design can proceed unchanged

If a real-server probe fails, do not patch the mock to match the design. Update
the design to match the protocol truth, then adjust the mock.

## Java compatibility gates

Java is a reference implementation for the v1 dense replay shape, not a
substitute for validation.

The Rust encoder spike may start with Rust-only byte-shape tests. Before queue
work turns replay payloads into product state, add the core Java/Rust fixture
below or explicitly record that real-server semantic validation, not
byte-for-byte Java parity, is the compatibility gate for v1.

Before implementation depends on Java-compatible behavior, add small golden
fixtures at two layers.

QWP payload fixtures compare Java and Rust at the application-payload layer:

- Compare unmasked QWP payload bytes, not WebSocket frames. Client mask keys are
  intentionally fresh per send, so masked frame bytes should differ.
- The first queue-blocking fixture should cover full schema mode, disabled
  schema references, repeated table/schema use, repeated symbols, high symbol
  ids, timestamps, and a later replay batch.
- Extended fixtures should later cover arrays, decimals, UTF-8, sparse columns,
  and schema evolution across batches.
- Include at least one fixture where a later batch is stored and replayed alone
  on a fresh connection.
- Record whether any byte difference is semantically intentional. If so, validate
  both payloads against a real server and document the observed rows.

Store-and-Forward disk fixtures compare Java and Rust at the `.sfa` segment
layer:

- Compare the 24-byte segment header: magic `SF01`, version `1`, zero
  flags/reserved, `baseSeq`, and `createdMicros` field placement.
- Compare frame envelopes: `[u32 crc32c][u32 payloadLen][payload]`, with CRC32C
  computed over `payloadLen || payload`.
- Include a Java-written slot that Rust opens and replays, and a Rust-written
  slot that Java opens and replays.
- Include recovery of a torn tail: the reader must stop at the first invalid
  frame and append from that offset, matching Java behavior.
- Verify there are no Rust-only ACK or rejection records on disk. ACK/rejection
  state is represented only by retained vs trimmed segment files.

These fixtures should not lock Rust into Java's public API or Java's threading
model. They lock down the wire behavior and disk contract that both clients rely
on.

## Step 1: API sketch first

Write the intended end-user code as if the implementation already existed.

Cover at least:

- Rust manual/synchronous use
- Rust threaded adapter use
- Rust async adapter use
- C use
- C++ RAII use
- Python blocking use
- Python asyncio use, if planned

Validation target:

- `Sender` and `Buffer` remain separate.
- There is no silent background thread in the low-level API.
- Submission, delivery, timeout, and close semantics are visible from names.
- Receipts are easy to understand as value IDs.
- The API does not make FFI users model Rust futures or a specific async runtime.
- The native Rust API is pipelined too. C/FFI should wrap Rust's manual sender,
  not be the only pipelined surface.

Design pressure to watch:

- `flush()` may be familiar, but can hide whether it means local acceptance or
  server delivery.
- `submit()` is more precise, but may feel less compatible with current
  `Sender::flush()` usage.
- Receipt-returning and non-receipt convenience methods should not duplicate too
  much surface area.

Local reflection:

- Does the API feel simpler than the current `Sender` + `Buffer` shape, or did
  pipelining add too much ceremony?

Global reflection:

- Does the sketch preserve the core principles: Buffer/Sender segregation,
  explicit progress ownership, runtime-neutral FFI, and observable delivery?

Current validated slice:

- `SenderBuilder::build_qwp_ws()` and `QwpWsSender::from_conf(...)` create the
  native Rust manual sender from the same config validation used by
  `Sender::from_conf`.
- `QwpWsSender::submit()` / `submit_and_keep()` return value receipts after
  local publication and do not wait for server ACK.
- `drive_once`, `receipt_status`, `wait` / `wait_steps`, and `close_drain` /
  `close_drain_steps` expose manual progress without a hidden runner.
- A behavioral mock-server test proves two submitted buffers can be sent before
  waiting, then resolved by one cumulative ACK.
- A behavioral mock-server test proves per-receipt rejection diagnostics are not
  overwritten when receipts are waited out of rejection order.
- A gated real-server probe verifies public manual `submit` / `wait_steps`
  writes a queryable row through a local QuestDB server.
- The live Rust API exposes only the real manual sender path; threaded and async
  adapters remain design targets until their progress behavior exists.

## Step 2: Progress ownership prototype

Model only the type ownership transitions. Do not implement real networking.

Prototype shapes such as:

```rust
pub struct QwpWsSender;
pub struct QwpWsThreadedSender;
pub struct QwpWsAsyncSender;

impl QwpWsThreadedSender {
    pub fn start(sender: QwpWsSender) -> Result<Self>;
}

impl QwpWsAsyncSender {
    pub fn from_sender(sender: QwpWsSender) -> Result<Self>;
}
```

For FFI, model consuming ownership explicitly:

```c
bool line_sender_qwpws_threaded_start(
        line_sender_qwpws_sender **sender,
        line_sender_qwpws_threaded **threaded_out,
        line_sender_error **err_out);
```

On success, `*sender` is set to `NULL`.

Validation target:

- A sender core has exactly one progress owner.
- Future manual, threaded, and async modes are represented by ownership, not
  mode flags.
- No API allows `drive_once()` and a background runner to race on the same core.
- FFI handle ownership cannot produce use-after-free through normal API use.

Design pressure to watch:

- If too many methods need "driver already active" errors, the ownership model is
  leaking.
- If adapters need to borrow rather than own the sender, progress ownership is
  probably unclear.

Local reflection:

- Is it obvious who drives progress at every point?

Global reflection:

- Did the type model avoid stateful magic, or are we recreating runtime mode
  switches under different names?

## Step 3: Self-sufficient QWP frame spike

Implement the Java-style v1 replay encoding path behind focused tests first.

Every frame stored by the new pipelined sender must be valid as the first QWP
data frame on a fresh WebSocket connection.

This step has two layers:

- Rust byte-shape tests for the replay encoder.
- Java/Rust replay payload fixtures, or documented real-server-validated
  semantic equivalence.

The Rust-only encoder layer is enough to proceed to Step 4. It is not enough to
proceed to Step 5 unless Step 4 passes and the Java parity question is either
resolved or deliberately deferred with rationale.

Validation target:

- Stored frames contain enough schema information for independent replay.
- Stored frames contain the dense symbol dictionary prefix from id `0` through
  the highest symbol id referenced by the frame.
- Stored frames are unmasked QWP payload bytes. WebSocket headers, mask keys,
  and masked payload bytes are not stored and are not part of durable identity.
- Replaying a later stored frame alone after reconnect/restart succeeds.
- The public API does not expose a durability-dependent encoding choice.
- Java and Rust replay-mode fixtures agree on unmasked QWP payload bytes for the
  v1 dense cases, or document a real-server-validated semantic equivalence.

Design pressure to watch:

- The encoder should not infect normal row-building ergonomics.
- WebSocket masking should stay below the QWP/SF layer. If masking leaks into
  stored frame identity, replay and CRC semantics are wrong.
- The cost of repeated schema/symbol material should be visible in benchmarks,
  but should not block the correctness-first v1.
- The v1 dense dictionary rule is intentionally not scalable for long-running
  high-cardinality symbol workloads. Treat sparse referenced-entry dictionaries
  as a later optimization, not a v1 requirement.

Local reflection:

- Is the encoder change localized, or does it make the buffer model harder to
  understand?

Global reflection:

- Does this provide a correct Store-and-Forward baseline before optimizing with
  state-only QWP messages or checkpoints?

## Step 4: Real-server protocol probe: self-sufficient replay

Before building the queue around the encoder assumption, validate it against a
real QuestDB server.

This is a hard gate before Step 5. The harness should exercise the replay
encoder directly; it should not require the volatile queue, disk
Store-and-Forward, receipts, or the new sender state machine.

Use the smallest harness that can:

- open a real QWP/WebSocket connection
- send one self-sufficient frame
- build a later frame that repeats schema/symbol usage
- reconnect
- send that later frame alone as the first QWP data frame on the new connection
- verify the expected rows are visible in QuestDB
- capture the unmasked QWP payload bytes and relevant QWP header fields for the
  first and replayed frames

Validation target:

- A Java-style self-sufficient later frame is accepted as the first data frame
  on a fresh WebSocket connection.
- The server does not require hidden connection-local schema or symbol state
  beyond what the frame carries.
- The rows are not merely ACKed; they are queryable with the expected values.
- The probe records the byte-size overhead of the dense dictionary prefix for at
  least one repeated-symbol and one higher-cardinality scenario.
- If Java-generated and Rust-generated fixture payloads differ, both variants
  ingest to the same table contents or the design stops for protocol review.
- If Java fixtures are not available yet, the probe validates Rust-vs-server
  protocol truth only. It must not be described as Java compatibility proof.

Design pressure to watch:

- If the server accepts the frame but data is wrong, the encoder contract is
  still invalid.
- If a later frame cannot stand alone, Store-and-Forward needs a different v1
  replay contract before queue work proceeds.

Local reflection:

- Did the real server confirm the encoder assumption cleanly, or did the probe
  require special setup that should become part of the design?

Global reflection:

- Can the rest of the validation ladder safely treat self-sufficient stored
  frames as protocol truth?

## Step 5: Volatile queue and receipts

Build an in-memory bounded queue with monotonically increasing 64-bit frame
sequence numbers. Do not add disk durability yet.

Use a fake server that can produce cumulative ACKs.

Validation target:

- Submission produces value receipts.
- Receipt status is derivable from queue state.
- Backpressure is observable and deterministic.
- ACK coalescing works with strictly in-order server processing.
- Later frames never jump earlier unresolved frames.

Design pressure to watch:

- Receipt APIs should feel like value IDs, not heap completion handles.
- Queue full behavior must be clear for both blocking and non-blocking calls.

Local reflection:

- Do receipts, status polling, and backpressure feel natural in Rust?

Global reflection:

- Does the pipeline model remain understandable without durability and reconnect
  noise?

## Step 6: Manual synchronous driver

Add `drive_once`, blocking submit convenience, and `wait` against a fake ordered
server.

The fake server should support:

- cumulative ACKs
- response coalescing
- disconnects
- retryable transport failures
- deterministic frame rejection

Validation target:

- Manual `QwpWsSender` is the sole progress owner.
- Blocking calls drive progress only while they own the sender mutably.
- `submit()` blocks only until local queue/store acceptance.
- `wait()` observes server delivery outcome for a receipt.
- Timeouts are outcomes where appropriate, not confused with protocol errors.

Design pressure to watch:

- If `submit()` and `wait()` have surprising blocking behavior, rename or split
  the methods before implementing real transport.
- If `flush()` is kept as an alias, its local-acceptance semantics must be
  impossible to miss.

Local reflection:

- Are blocking calls easy to reason about from a caller's point of view?

Global reflection:

- Does the "one progress owner" model survive real control flow?

## Step 7: Real-server protocol probe: ACK, order, and close

Before relying on the fake ordered server too heavily, validate the response
contract against a real QuestDB server.

Use a narrow harness that can send multiple QWP/WebSocket frames without waiting
for each response before sending the next.

Cover:

- strictly in-order server processing
- cumulative ACKs for the highest successful frame
- response coalescing, if observable
- disconnect or close while frames are in flight
- reconnect after a clean or abrupt close

Validation target:

- The server never reports success for a later frame while an earlier frame has
  no response. A server error counts as resolving that earlier frame.
- A cumulative ACK can be treated as ACK for all lower unresolved frame sequence
  numbers until a rejection gap prevents contiguous server-ACK advancement.
- Close and EOF behavior map cleanly into retryable, terminal, or drained
  outcomes.

Design pressure to watch:

- If the server can produce out-of-order application outcomes, the receipt and
  queue model must change before disk durability is added.
- If close behavior is ambiguous, do not harden public close semantics yet.

Local reflection:

- Did the server behavior match the fake ordered server closely enough?

Global reflection:

- Are the ordering and ACK assumptions strong enough to build durable replay on
  top?

## Step 8: Java-compatible Store-and-Forward disk queue

Replace the volatile queue with a file-backed queue. Keep the fake server.

The first prototype used a Rust-specific journal. Do not evolve that journal into
the product disk format. The product queue must use the Java client `.sfa`
segment layout so a slot written by one client can be recovered by the other.
The Rust-specific journal prototype is now test-only and must not be used as the
driver integration substrate.

Start with the smallest Java-compatible durability surface that can validate
replay:

- create and lock `<sf_dir>/<sender_id>/`,
- create `sf-initial.sfa` with the Java segment header,
- append frames as `[crc32c][payloadLen][payload]`,
- publish receipt only after the complete frame is visible to the queue,
- recover `.sfa` files after restart by scanning valid frames,
- replay from the lowest retained FSN,
- rotate to `sf-<generation>.sfa`,
- trim fully ACKed sealed segments.

Do not add durable ACK-through, rejection, or dead-letter records. The only
durable evidence that earlier frames were acknowledged is that fully ACKed sealed
segments may have been removed. If a crash happens before trim, retained frames
may replay again. That is the Java-compatible at-least-once model.

Do not confuse Java's `.corrupt` recovery quarantine with dead-letter storage.
`.corrupt` files preserve damaged segment files for postmortem recovery; they
are not created for server-rejected batches.

Validation target:

- Durability mode is orthogonal to public API semantics.
- Caller buffers can be cleared after local publication.
- Process restart does not lose published frames.
- Replay preserves submission order.
- The design distinguishes volatile memory mode from file-backed page-cache
  durability.
- Java can recover a Rust-written `.sfa` slot.
- Rust can recover a Java-written `.sfa` slot.
- Torn-tail recovery matches Java: stop at the first invalid frame and append
  from that offset.
- ACK/drop-and-continue rejection leaves no Rust-only completion marker on disk.
- The public sync `Sender` path, not only the manual driver shell, can publish
  into `sf_dir`, survive a disconnect before ACK, recover retained work from the
  same `<sf_dir>/<sender_id>/` slot on a new sender, deliver it before follow-up
  work, and later remove retained `.sfa` files once high-level close/drain is
  implemented.
- DROP_AND_CONTINUE does not create client-owned dead-letter files; the
  observable artifact is the structured rejection event/error plus normal
  resolved-frame segment trim.

Design pressure to watch:

- If disk durability changes user-facing encoding or receipt behavior, the
  abstraction is too leaky.
- If cleanup rules require durable per-frame completion records, the design has
  drifted away from Java and should stop.
- If the `.sfa` format cannot be described as a small mechanical segment reader
  and writer, implementation is probably carrying too much product policy.

Local reflection:

- Is the disk queue small and mechanical, or is it driving API design?
- Can each retained byte be explained as either Java segment metadata or QWP
  payload bytes?

Global reflection:

- Can crash/restart behavior be explained without special cases?
- Can a user move a Store-and-Forward slot between Java and Rust and still
  recover it?

## Step 9: Error policy validation

Use the fake server and disk queue to validate the error model.

Cover:

- retryable transport errors
- reconnect budget exhaustion
- auth or upgrade rejection
- parse/schema server rejection
- write/internal server error
- cumulative ACK followed by error
- close while frames are unresolved

Validation target:

- Retryable failures preserve ordering and keep retrying within policy.
- Terminal failures are surfaced to the caller.
- Java-compatible drop-and-continue server rejections are reported with raw
  status/message and affected FSN instead of being silently lost.
- Drop-and-continue has Java's dead-letter boundary: the client reports the
  structured rejection and does not persist a rejected-batch file. Users that
  need durable dead letters implement them in their error handler or producer
  log.
- A deterministic bad frame does not brick the sender forever.
- `receipt_status`, `wait`, and event polling agree.

Design pressure to watch:

- If one enum is forced to represent events, receipt status, wait outcomes, and
  close outcomes, split it before the C ABI hardens.
- If rejection handling requires row-level information the server does not
  provide, keep v1 at frame-level reporting.

Local reflection:

- Are errors surfaced at the right time and at the right API layer?

Global reflection:

- Does the model avoid both silent data loss and permanent sender bricking?

## Step 10: Real-server protocol probe: error taxonomy

Before hardening the FFI outcome enums, validate server error behavior with a
real QuestDB server where practical.

Cover reproducible cases such as:

- schema mismatch
- parse error or malformed frame
- auth or upgrade rejection
- write failure, if a reliable server-side setup exists
- internal error, only if there is a deterministic test hook

Validation target:

- Server statuses map cleanly into retryable, terminal, rejected, or unknown.
- Rejected frames are identified at frame granularity.
- ACK-before-error behavior matches the cumulative ACK model.
- The connection state after each error is understood.

Design pressure to watch:

- If the server does not expose enough information to classify an error, the
  client API must surface `Unknown` rather than guessing.
- If schema/parse failures close the connection before a useful status arrives,
  rejection handling may need to be conservative.

Local reflection:

- Did the real server provide enough information for a stable error contract?

Global reflection:

- Can the FFI expose durable error semantics without inventing details the
  server does not provide?

## Step 11: FFI shape pass

Add C ABI stubs and tests for ownership and output-pointer contracts before full
implementation is wired through.

If Step 2 already introduced type-only ownership stubs, extend those stubs rather
than adding a parallel C surface. Keep those stubs out of the live Rust manual
sender once the real sender exists; until the C ABI is wired through, FFI-only
shape state should stay local to the FFI crate.

This step validates ABI shape, pointer contracts, and state vocabulary only. It
should not wire real WebSocket transport or durable storage into the C ABI.

Cover:

- sender construction and free
- buffer creation
- submit and submit-and-keep with required value receipts
- receipt status
- wait outcome
- event polling
- close outcome
- threaded adapter ownership conversion, if included

Validation target:

- Every output pointer is documented as required or optional.
- Null handling is explicit and tested.
- Rust panics cannot cross the FFI boundary.
- C distinguishes API failure from non-error states such as pending, timeout,
  drained, and not drained.
- The core C submit calls keep receipt outputs required. A no-receipt
  convenience can be added later as a wrapper if examples prove it useful, but
  it should not weaken the core publication contract.
- `drive_once` is progress-only and does not consume events; `poll_event` is the
  only C event consumer.
- `receipt_status` may report an invalid receipt, but `wait` on an invalid or
  unknown receipt is an API failure.
- Threaded adapter start consumes the manual sender handle on success, leaves it
  unchanged on failure, and does not require runtime "runner active" checks on
  the manual API.
- C++ and Python wrappers do not need extra semantic inventions.

Design pressure to watch:

- If C callers need to pass too many pointers for common cases, add convenience
  calls rather than weakening the core contract.
- If Python needs behavior that C cannot observe, the ABI is incomplete.

Local reflection:

- Are ownership, lifetime, null, and timeout rules unambiguous?

Global reflection:

- Can all language layers expose the same semantics without pretending to be
  Rust?

## Step 12: Real WebSocket integration

Replace the fake transport with real QWP/WebSocket transport while keeping the
validated queue and public API shape.

Validation target:

- A Rust-only publication shell encodes a caller `Buffer` into a
  self-sufficient replay payload before queue publication.
- The publication shell owns append-only replay encoder state:
  `QwpWsEncodeScratch`, `SymbolGlobalDict`, and the negotiated QWP version.
- Real connection setup follows Java semantics: initial connect is attempted by
  default, and `initial_connect_retry` opts into bounded startup retry.
- Client-to-server frames are masked on the wire, but durable/SF records remain
  unmasked QWP payloads.
- Replaying the same stored QWP payload applies a fresh WebSocket mask without
  mutating durable bytes.
- Masked server-to-client frames are treated as WebSocket protocol errors.
- Real cumulative ACK handling matches the fake-server model.
- Reconnect and replay do not require public API changes.
- Real-server submit/wait and reconnect replay use the same publication path
  intended for the product core, not opaque test payload bytes.
- The public sync `Sender` path uses the same publication driver and
  config-derived queue selection as the validated manual core.
- The native Rust manual `QwpWsSender` path uses the same publication driver and
  config-derived queue selection as the public sync compatibility path.
- The public sync `Sender` path has a live QuestDB SFA recovery probe for runner
  semantics: local publication succeeds, a proxy drops the unACKed frame, the
  next sender reopens the same Java-style slot, replay happens before follow-up
  work. Cleanup remains part of the high-level close/drain gap.
- The old Tokio `build_async()` path is removed rather than maintained as a
  second QWP/WebSocket implementation. Future async support should be an adapter
  over the same queue/driver core.
- Authentication, WebSocket upgrade, and close behavior map into the existing
  error/outcome model.
- Failed encode or queue publication may reserve internal symbol IDs, but must
  not assign an FSN, return a receipt, enqueue bytes, consume a wire sequence,
  or clear the caller buffer.
- A successful frame after a failed submit remains self-sufficient when replayed
  on a fresh connection, even if the dense dictionary prefix includes
  reserved-but-unused lower IDs.

Design pressure to watch:

- If the publication shell makes `submit()` allocate or mutate caller buffers
  before successful publication, revisit the commit points before adding FFI.
- Do not add `SymbolGlobalDict` checkpoint/rollback unless a stronger public
  "failed submit has no internal side effects" contract is deliberately chosen,
  or dictionary bloat is proven material.
- If networking forces public API changes, revisit the fake-server assumptions.
- If the real protocol requires hidden tasks to make progress, the low-level
  contract has been violated.
- If the public sync compatibility API needs a second parallel transport path,
  the old path has not really been removed.

Local reflection:

- Did the real transport fit the state machine, or did it expose missing states?

Global reflection:

- Were the earlier fake-server validation and real-server probes predictive
  enough?

## Step 13: Java-like high-level Sender runner

Validate the product API shift to Java behavior:

```text
Sender::flush(&mut Buffer)
  -> local publication into bounded memory/SFA cursor
  -> buffer cleared on success
  -> background runner sends, reconnects, replays, ACKs, rejects, trims
```

This step should start by re-reading Java's `QwpWebSocketSender.flush()`,
`CursorSendEngine.appendBlocking()`, `SegmentRing`, and current Rust
`flush_qwp_ws()` / queue code. If Java changed again, update the design before
coding.

First runner slice status: high-level `flush()` and `flush_and_keep()` now
return after local publication, and a sender-owned runner advances WebSocket
I/O. Mock-server coverage proves delayed-ACK `flush()`, delayed-ACK
`flush_and_keep()`, and two high-level `flush()` calls before the first ACK.
The manual driver now uses a `PublicationLog` boundary: local publication owns
FSNs and retained payloads, while the driver owns connection-local wire
sequencing, in-flight state, ACK mapping, and reconnect replay cursor. The
latest runner slice performs ordinary socket send and non-blocking receive poll
outside the publication mutex, with behavioral coverage proving that a blocked
send does not block another local publication. The remaining architectural work
in this step is to make the high-level runner a direct Java-shaped I/O loop over
the publication store instead of growing the manual driver as its center, and
then finish reconnect/backoff decoupling, local-capacity backpressure/deadline,
close/drain, and async rejection observability.

Validation target:

- High-level `Sender::flush()` returns after local publication and before the
  server ACK for the newly published frame. The target contract allows waiting
  for local capacity, terminal state checks, or explicit close/shutdown
  coordination, not for ordinary socket send/poll or reconnect backoff.
- High-level `Sender::flush_and_keep()` has the same delivery semantics while
  preserving the caller buffer.
- Two `flush()` calls can publish and be sent before the first ACK, bounded by
  `max_in_flight`.
- The foreground path clears the caller buffer only after successful local
  publication.
- A full local cursor blocks until resolved-frame trim frees space, or returns an
  append-deadline error after `sf_append_deadline_millis`. Current Rust
  recognizes and rejects that Java key; the runner slice must accept it only
  after validating that the stored value actually controls local-publication
  backpressure.
- Server rejection observed after `flush()` returns is observable through a
  bounded pollable error/event path. Terminal categories are latched so a later
  producer call fails. Do not require callbacks for the first runner slice.
- Drop/void close remains best-effort; explicit drain APIs are the only
  portable way to report close-time delivery failures.
- Manual `QwpWsSender::drive_once()` and the high-level background runner cannot
  drive the same core at the same time.
- The manual driver remains a threadless manual-progress API. The high-level
  runner should converge on a direct publication-store plus I/O-loop ownership
  model, not a growing permanent `detach_*` surface on the manual driver.
- Memory mode and SFA mode share the same publication and error semantics; only
  process-crash recovery differs.

Behavioral tests should include:

- delayed-ACK mock server proving `flush()` returns before ACK,
- `flush_and_keep()` mock-server coverage proving local publication without
  clearing the buffer,
- cumulative-ACK mock server proving multiple flushes pipeline,
- blocked-send runner fixture proving ordinary transport send does not block
  another local publication while capacity remains,
- blocked-reconnect runner fixture proving reconnect/backoff does not block
  another local publication while capacity remains,
- capacity/backpressure fixture proving wait-for-trim and deadline expiry,
- server-rejection fixture proving pollable async observability without
  dead-letter files or I/O-thread callbacks,
- SFA recovery fixture proving a locally published but unACKed frame survives
  process-style sender rebuild.

Real-server gates should be narrow:

- publish two frames without waiting for the first ACK and verify rows,
- force a reconnect after local publication and verify replay,
- verify a schema/write rejection is reported through the high-level pollable
  observer while later valid data can still be accepted.

Design pressure to watch:

- If the runner requires an unbounded payload channel, the design is drifting
  away from Java's bounded cursor model.
- If the runner gains more detach/finish operations for each new behavior, stop
  and extract the Java-shaped store/runner ownership boundary instead.
- If `flush()` waits for the server ACK except under test-only timing, the
  product semantics did not change.
- If high-level rejection reporting requires user callbacks inside the I/O
  thread, add a bounded dispatcher/queue instead.
- If close behavior becomes hard to explain across Rust/C/C++/Python, keep
  destructor/void close best-effort and make drain explicit.

Local reflection:

- Did the background runner make the common API simpler, or did it leak too
  much receipt/manual machinery into `Sender`?

Global reflection:

- Are we now closer to Java's product model while preserving Rust's explicit
  manual/FFI escape hatch?

## Step 14: Ergonomics and design review

Re-read the original API sketches and compare them with the implemented shape.

Exercise real examples:

- single-threaded Rust ingestion
- high-throughput Rust ingestion with explicit progress
- C producer loop
- C++ RAII wrapper
- Python blocking wrapper
- crash/restart Store-and-Forward recovery demo
- server-rejection demo

Validation target:

- Common use remains short and understandable.
- Advanced use does not require undocumented sequencing.
- Naming matches actual blocking and delivery semantics.
- The v1 design is still a small correctness-first design.

Design pressure to watch:

- If examples need long explanations, simplify the API before optimizing.
- If the implementation already assumes state-only messages or checkpoints,
  the v1 scope has drifted.

Local reflection:

- What feels awkward only after using the API end to end?

Global reflection:

- Are we still building the intended v1, or did validation reveal a better
  design?

## Stop conditions

Stop and redesign before continuing if any of these happen:

- Progress ownership depends on runtime flags instead of ownership.
- Durable and volatile modes require different public encoding semantics.
- The C ABI cannot express Rust outcomes without lossy mapping.
- `submit()`, `flush()`, or `wait()` names do not match their blocking behavior.
- Store-and-Forward can silently drop data.
- A rejected frame can permanently brick recovery without a documented operator
  path.
- A real-server probe invalidates the self-sufficient-frame, ACK-ordering, or
  error-taxonomy assumptions.
- Java/Rust golden payload fixtures disagree in a way that is not explained by a
  documented non-semantic field and validated against a real server.
- Java/Rust `.sfa` golden fixtures disagree in segment header, frame envelope,
  CRC, recovery cursor, or replay order.
- Real WebSocket integration requires a hidden background thread in the low-level
  API.

## Expected output of each step

Each step should leave behind:

- the smallest useful prototype or test artifact
- a short `Local reflection`
- a short `Global reflection`
- a decision: proceed, adjust, or abandon that design branch

The reflections are not optional. They are the feedback loop that keeps this
from becoming a large unvalidated implementation.
