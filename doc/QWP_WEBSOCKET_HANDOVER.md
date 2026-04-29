# QWP/WebSocket pipelined Store-and-Forward handover

Date: 2026-04-29

Status: active validation branch for the Rust client plus C FFI shape.

This is no longer only a design discussion. Steps 1-11 are validated by docs,
Rust prototypes, real-server probes, and C ABI shape stubs. Step 12 now has a
first Rust-only blocking WS/WSS transport adapter and a Rust-only publication
shell behind the manual driver seam. The publication path has passed real
QuestDB submit/wait, reconnect/replay, and Java-compatible `.sfa` recovery e2e
probes, but the new pipelined Store-and-Forward core is not wired into the
public product API or C ABI yet.

Do not read this as production readiness. The existing `qwpws` sync/async sender
paths still exist separately. The new pipelined/SF sender core is being built
behind prototypes before product API integration.

## Read first

- `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md` - active validation ladder and current
  progress.
- `doc/QWP_WEBSOCKET_PIPELINED_FFI.md` - parent design proposal.
- `doc/QWP_WEBSOCKET_API_SKETCH.md` - Step 1 end-user API sketch.
- `doc/QWP_WEBSOCKET_ERROR_POLICY_PROTOTYPE.md` - current driver/SF error
  policy notes.
- `doc/QWP_WEBSOCKET_ERROR_TAXONOMY_PROBE.md` - latest real-server error
  taxonomy results.
- `doc/QWP_WEBSOCKET_REAL_TRANSPORT_PROTOTYPE.md` - first real blocking WS/WSS
  transport slice for the manual driver.
- `doc/QWP_WEBSOCKET_PUBLICATION_SHELL_PROTOTYPE.md` - Rust-only
  `Buffer -> replay payload -> queue` publication slice for the manual driver.
- `doc/QWP_WEBSOCKET_PUBLICATION_E2E_PROBE.md` - real QuestDB e2e publication
  and reconnect probes through the manual driver and blocking transport.
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs` - current manual driver
  prototype and transport seam.
- `questdb-rs/src/ingress/sender/qwp_ws_publisher.rs` - replay publication
  shell above the manual driver.
- `questdb-rs/src/ingress/sender/qwp_ws_queue.rs` - volatile queue prototype.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs` - Java-compatible
  `.sfa` segment codec spike.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs` - Java-compatible
  `.sfa` queue adapter behind the manual driver seam.
- `questdb-rs/src/ingress/sender/qwp_ws_sf_queue.rs` - retired Rust-only
  file-backed SF queue prototype, now compiled only for tests and no longer
  wired into the driver seam.
- `questdb-rs-ffi/src/lib.rs` and `include/questdb/ingress/line_sender.h` -
  shape-only C ABI stubs.

Useful Java/server references:

- Java client design:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/design/qwp-cursor-durability.md`
- Java client sender:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
- Java SF send loop:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
- Java SF segment format:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java`
- Java SF segment ring and slot lock:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java`
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SlotLock.java`
- Server source used for taxonomy checks:
  `/home/jara/devel/oss/questdb-arrays`

## Current branch state

Current branch:

```text
ia_qwp_ws
```

Most recent committed checkpoint:

```text
6a49e5c Add QWP WebSocket SFA recovery probe
```

Recent validation after the Step 12 publication-shell, reconnect-probe, and
`.sfa` recovery slices:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
cargo test --manifest-path questdb-rs/Cargo.toml \
    --no-default-features \
    --features _sender-qwp-ws,tls-webpki-certs,ring-crypto \
    qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml \
    --features async-sender-qwp-ws \
    qwp_ws_async
QDB_QWP_WS_PUBLICATION_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_publication_driver_submit_waits_and_row_is_queryable \
    -- --ignored --nocapture
QDB_QWP_WS_RECONNECT_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_publication_driver_reconnect_replays_only_unacked_rows \
    -- --ignored --nocapture
cargo test --manifest-path questdb-rs/Cargo.toml --lib qwp_ws_sfa
QDB_QWP_WS_SFA_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml --lib \
    qwp_ws_sfa_recovered_frame_is_delivered_and_cleaned_up \
    -- --ignored --nocapture
cargo test --manifest-path questdb-rs/Cargo.toml --lib
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Observed result:

```text
qwp_ws_driver: 47 passed
qwp_ws: 126 passed, 6 ignored
minimal _sender-qwp-ws driver filter: 43 passed, with existing unused-code warnings
qwp_ws_async with async-sender-qwp-ws: 8 passed
real QuestDB publication probe: 1 passed
real QuestDB reconnect probe: 1 passed
qwp_ws_sfa: 22 passed, 3 ignored
real QuestDB .sfa recovery probe: 1 passed
cargo test --lib: 475 passed, 10 ignored
format and whitespace checks passed
```

The ignored tests are real-server probes gated by environment variables.

## What is implemented

### API and ownership shape

- `doc/QWP_WEBSOCKET_API_SKETCH.md` commits to `submit()` as the primary verb.
- `submit()` means local publication and returns a value receipt.
- `wait(receipt, timeout)` means delivery observation and may drive progress.
- `flush()` is intentionally not the primary low-level verb.
- Manual, threaded, and async ownership are modeled by consuming adapters, not
  runtime "runner active" flags.
- `questdb-rs/src/ingress/sender/qwp_ws_ownership.rs` validates the Rust
  type-only ownership shape.

### Replay payload shape

- `questdb-rs` has a replay encoder path for self-sufficient QWP/WebSocket
  payloads.
- Store/replay identity is the unmasked QWP application payload, not the
  WebSocket frame bytes.
- Replay frames use full schema mode and dense global symbol dictionary prefix
  from id `0` through the highest referenced symbol id.
- Java/Rust golden fixture exists for the core dense replay payload case:
  `tests::qwp_ws_java_golden::qwp_ws_replay_payloads_match_java_golden_bytes`.
- Current golden fixture covers symbols, long, double, and timestamp nanos; it
  does not yet cover arrays, decimals, UTF-8 strings, sparse columns, or schema
  evolution.

### Real-server protocol gates

Real-server probes have validated:

- A later self-sufficient replay payload can be sent alone as the first data
  frame on a fresh connection and rows are queryable.
- The first QWP/WebSocket frame on a fresh connection is ACKed with wire
  sequence `0`.
- Successful ACKs can be coalesced; `OK(sequence=N)` is cumulative for lower
  unresolved successful frames on the same connection.
- A malformed frame or schema mismatch reports the rejected sequence without
  making all later in-flight frames terminal.
- A later valid frame can still be ACKed after a deterministic frame-local
  error.
- After the server fix in `questdb-arrays`, deterministic string-to-DOUBLE
  coercion failure is surfaced as `SCHEMA_MISMATCH`, not `WRITE_ERROR`.
- The publication driver can reconnect through the real blocking transport after
  an abrupt close, avoid replaying an already-ACKed frame, replay an unresolved
  frame on a fresh QuestDB connection, and make both expected rows queryable.

Still not validated by real server:

- auth/upgrade rejection taxonomy,
- deterministic internal/retryable write failure taxonomy,
- broader close/EOF behavior with multiple unresolved in-flight frames,
- full product integration using the new queue/driver core.

### Queue and receipt prototypes

`questdb-rs/src/ingress/sender/qwp_ws_queue.rs` implements the volatile queue
prototype:

- monotonically increasing FSNs starting at `0`,
- value receipts,
- `Published`, `Sent`, `Acked`, `Rejected`, `Terminal`, and `Unknown` status
  vocabulary,
- bounded frame and byte capacity,
- fixed in-flight ring,
- zero-based per-connection wire sequence,
- cumulative ACK handling,
- ordered rejection gaps,
- reconnect replay from the oldest unresolved FSN.

The queue now has a two-phase send boundary for the driver:

```text
next_outbound_frame() -> borrowed payload candidate
transport accepts write
commit_sent() -> receipt becomes Sent
```

This is deliberate. A local transport write failure must not create a fake
`Sent` receipt or emit a `Sent` event.

### Store-and-Forward prototype

`questdb-rs/src/ingress/sender/qwp_ws_sf_queue.rs` is a retired Rust-only
file-backed SF queue prototype:

- append-only journal,
- frame publication records,
- ACK-through completion records,
- server-rejection completion records,
- recovery from incomplete tails,
- malformed-log rejection,
- ACK and rejection state surviving restart.

This prototype is no longer the product disk design and is no longer wired into
`ManualDriverPrototype`. It is compiled only for tests so its recovery coverage
can remain available while product SF moves to byte-compatible
Store-and-Forward with the Java client. Product SF must use Java `.sfa` segment
files under
`<sf_dir>/<sender_id>/`, using the Java header, frame envelope, CRC32C,
recovery scan, slot lock, rotation, and ACK-driven segment trim model.

The product `.sfa` store must also avoid connection-local facts:

- `Sent` receipt status,
- wire sequence,
- in-flight ring contents,
- WebSocket mask keys,
- masked WebSocket bytes.

After process recovery, retained frames are `Published`; replay rebuilds
connection-local state from scratch. Previous receipt handles and runtime
ACK/rejection status are gone.

`questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs` is the product-format
segment codec spike. It currently validates:

- Java `SF01` header bytes,
- Java frame envelope `[crc32c][payloadLen][payload]`,
- CRC32C using Java's known `123456789` vector,
- `sf-initial.sfa` and `sf-<generation:016x>.sfa` naming,
- clean zero-tail recovery,
- torn-tail detection on CRC mismatch,
- create/open/append cursor behavior for one segment.
- ignored cross-client fixture where Java writes a segment Rust opens, Rust
  writes a segment Java opens, and torn-tail recovery agrees in both directions.

Normal Rust tests use committed hex fixtures under
`questdb-rs/src/tests/interop/qwp-ws-sfa/`. The ignored cross-client fixture is
the regeneration/proof tool for those bytes.

`questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs` is the Java-compatible
queue adapter behind the manual driver seam. It currently validates:

- open/create of Java-compatible `.sfa` segments,
- frame publication only after durable append succeeds,
- restart recovery as `Published` frames,
- replay from the oldest retained FSN with zero-based wire sequence,
- segment rotation and recovery in FSN order,
- ACK-driven trimming of fully ACKed sealed segments,
- clean close removing fully drained `.sfa` files,
- close timeout retaining recoverable frames,
- manual-driver replay of recovered `.sfa` frames,
- real QuestDB replay of a recovered `.sfa` frame through
  `BlockingQwpWsTransport`.

It does not yet implement product slot layout, slot locking, `sf_dir` /
`sender_id` config wiring, orphan draining, or a non-ignored CI fixture. The
cross-client fixture compiles a small Java helper into `/tmp` and uses the local
Java client checkout from `QDB_JAVA_CLIENT_CORE` or
`/home/jara/devel/oss/questdb-arrays/java-questdb-client/core`.

### Manual driver and transport seam

`questdb-rs/src/ingress/sender/qwp_ws_driver.rs` contains the manual driver
prototype. It currently supports both volatile and SF queue implementations via
`ManualDriverQueue`.

The fake ordered server is now behind `ManualDriverTransport`. The driver seam
is intentionally transport-shaped before real I/O is wired:

- `poll_response()` returns `Result<Option<TransportResponse>, TransportFailure>`.
- `send_frame()` receives an `OutboundFrame` containing the unmasked QWP payload.
- accepted send results can be `NoResponse`, immediate response, or structured
  failure.
- read-side and write-side transport failures enter the same reconnect/terminal
  policy.
- write failure before commit leaves the receipt `Published`.
- accepted send followed by reconnect failure leaves the receipt observably
  `Sent`.

This seam was refined because the first transport split had two problems:

- it passed only `SentFrame` metadata, not payload bytes;
- it marked frames `Sent` before transport write success.

Both are fixed in the current branch.

The first real transport adapter now exists as `BlockingQwpWsTransport` behind
the same seam. It reuses the current sync QWP/WebSocket TCP/TLS/upgrade/frame
helpers, writes masked client frames, parses real QWP/WebSocket response frames,
handles cumulative ACK after multiple sends, and is covered by local in-process
plain WS and WSS tests. This is still a manual-driver prototype path, not public
product API integration.

### Publication shell

`questdb-rs/src/ingress/sender/qwp_ws_publisher.rs` is the first Rust-only
publication owner above the manual driver. It owns:

- `QwpWsEncodeScratch`,
- `SymbolGlobalDict`,
- negotiated QWP version,
- `ManualDriverPrototype<Q, T>`.

Its submit path is:

```text
QwpBuffer -> encode_ws_replay_message -> ManualDriverPrototype::try_submit
```

The driver remains payload-opaque. The shell returns a receipt only after queue
publication succeeds. Failed queue publication may reserve internal symbol IDs,
but it does not enqueue bytes, assign an FSN, return a receipt, consume a wire
sequence, or clear the caller buffer.

Focused coverage now verifies:

- exact replay payload bytes reach the driver transport,
- empty buffers are rejected before encoding and publication,
- failed queue publication does not consume an FSN,
- `BlockingQwpWsTransport` can submit/wait through this publication path against
  the local in-process WS harness,
- a real QuestDB submit/wait probe makes the row queryable,
- a real QuestDB reconnect probe does not duplicate the ACKed row and does
  replay the unresolved row.

This is still not public product API integration and not yet a real QuestDB
`.sfa` Store-and-Forward integration.

### Real publication and reconnect e2e

`questdb-rs/src/tests/qwp_ws_publication_probe.rs` validates the current
publication path against a real QuestDB server:

```text
Buffer -> replay payload -> volatile queue -> manual driver -> BlockingQwpWsTransport -> QuestDB
```

The probes are ignored by default and gated by
`QDB_QWP_WS_PUBLICATION_PROBE=1` or `QDB_QWP_WS_RECONNECT_PROBE=1`. The
submit/wait probe submits a QWP buffer through `QwpWsPublicationDriver`, waits
for the receipt, then queries QuestDB over HTTP and verifies the inserted
symbol, long, and double values.

The reconnect probe uses a fault proxy in front of real QuestDB. It forwards and
ACKs the first frame, drops the second frame before QuestDB receives it, closes
the client connection, accepts the reconnect, forwards the replayed second
frame, then verifies both receipts and exactly two queryable rows. It asserts
user-visible behavior only; it does not lock in internal driver state, event
order, or private queue fields.

### C ABI shape stubs

The public C header and Rust FFI crate contain shape-only QWP/WebSocket stubs:

- `line_sender_qwpws_new`,
- `line_sender_qwpws_new_buffer`,
- `line_sender_qwpws_submit`,
- `line_sender_qwpws_submit_and_keep`,
- `line_sender_qwpws_drive_once`,
- `line_sender_qwpws_poll_event`,
- `line_sender_qwpws_get_receipt_status`,
- `line_sender_qwpws_wait`,
- `line_sender_qwpws_close_drain`,
- `line_sender_qwpws_close_fast`,
- `line_sender_qwpws_free`,
- `line_sender_qwpws_threaded_start`,
- `line_sender_qwpws_threaded_stop`.

Important constraints already represented:

- receipts are value structs containing FSN,
- submit receipt outputs are required,
- `drive_once` is progress-only and does not consume events,
- `poll_event` owns event consumption and bounded message copying,
- invalid receipt status is queryable without API failure,
- `wait` on invalid receipt is API failure,
- timeout, drained, rejected, terminal, and pending are normal outcomes where
  appropriate, not overloaded `err_out` failures,
- threaded start consumes the manual handle on success and sets `*sender = NULL`.

These stubs are not the final product implementation. The current FFI fake state
validates ABI shape, pointer/null handling, output contracts, and ownership
conversion before the real driver is wired through.

## Settled design decisions

- New pipelined SF core should be Rust-first and FFI-friendly.
- Low-level core is threadless by default.
- Background thread and Tokio integration are explicit adapters.
- Exactly one progress owner exists at a time.
- `submit()` means local publication, not server ACK.
- `wait()` means server delivery observation.
- Store-and-Forward is at-least-once, not exactly-once.
- Deduplication is a server-side/message-sequence mechanism, not a client-side
  guarantee.
- Durable/SF records store unmasked QWP payloads only.
- WebSocket masking is transport-local and regenerated for each send/replay.
- Process recovery discards volatile connection state and replays unresolved
  frames from the oldest unresolved FSN.
- Frame-local deterministic server errors should resolve the affected FSN using
  Java-compatible rejection policy, not terminalize all later in-flight frames by
  default.
- Events are observability notifications, not authoritative state; receipt
  status and wait/close outcomes are authoritative.
- Fallible work must not advance externally visible state before its commit
  point: encode failure does not consume wire sequence; failed payload
  materialization does not return a receipt; failed local/SF publication does
  not clear the caller buffer; failed transport write does not mark `Sent`.
- `SymbolGlobalDict` is append-only internal encoder state, not part of the
  externally visible commit boundary. Failed materialization/publication may
  reserve symbol IDs, but must not publish bytes, assign an FSN, return a
  receipt, consume a wire sequence, or clear the caller buffer.
- Blocking real transports may need send-before-poll progress so coalesced ACKs
  cannot stall the in-flight window. Fake transports can remain poll-first for
  protocol-error fixtures.

## Known gaps and risks

- Java-compatible initial connection configuration (`initial_connect_retry`)
  still has design text but no real new-core implementation.
- The FFI shape stubs are not connected to the real queue/driver prototypes.
- Active queue/driver/FFI prototype vocabulary now uses Java-compatible
  `Rejected` naming before ABI hardening.
- No C++ or Python wrapper implementation has been added for the new QWP/WS
  shape.
- Java-compatible `.sfa` queue integration exists behind the manual driver seam,
  but product slot wiring is missing. The remaining product work is
  `<sf_dir>/<sender_id>/` layout, slot locking, config parsing, public core
  integration, orphan draining, and Java-compatible `sf_durability`
  parse-and-fail behavior for reserved `flush`/`append` modes.
- Cross-client `.sfa` golden fixture is present but ignored by default because it
  depends on the local Java client checkout, `javac`, and Maven classpath
  discovery.
- Extended Java/Rust golden fixtures are still missing arrays, decimals, UTF-8,
  sparse columns, and schema evolution.
- Close/EOF semantics beyond the single forced-disconnect replay probe are not
  yet proven by a real-server probe.
- Auth/upgrade rejection and ambiguous operational write/internal errors still
  need taxonomy validation.
- The real transport adapter and publication shell have real QuestDB submit/wait,
  reconnect replay, and recovered `.sfa` replay probes, but not yet product
  config or public API wiring.
- Java has no client-owned dead-letter file format for rejected batches. Rust v1
  should not add one. Java's `.corrupt` files are recovery quarantine for
  damaged `.sfa` segments, not server-rejection dead letters; rejected batches
  are reported through structured errors/events and forgotten via the normal
  ACK/trim path.
- The v1 dense dictionary replay shape is correctness-first and can be expensive
  for long-running high-cardinality symbol workloads.
- Reserved-but-unused symbol IDs from failed submit attempts are acceptable in
  v1 because every replay frame carries the dense prefix needed by the symbols it
  references. Avoid adding dictionary checkpoint/rollback unless that public
  contract changes or the bloat is measured as material.

## Recommended next step

Move to the product slot/config boundary, but keep it narrow.

The Java-compatible `.sfa` queue now fits the publication/driver seam and has a
real QuestDB recovery probe. The next slice should make the queue open like the
product will open it, rather than adding FFI, threaded adapters, or wrapper
APIs.

Suggested slice:

1. Add the smallest product slot wrapper over `SfaFrameQueue`: derive
   `<sf_dir>/<sender_id>/`, create the slot directory, and keep `sf_dir` as the
   only Store-and-Forward on-switch.
2. Add Java-compatible exclusive slot locking and behavior tests for
   same-slot contention.
3. Add config parsing/validation for `sf_dir`, `sender_id`, `sf_max_bytes`,
   `sf_max_total_bytes`, and `sf_durability`, including parse-and-fail behavior
   for reserved `flush`/`append` values.
4. Preserve the simple durable model: `.sfa` segment files and QWP payload bytes
   only. Do not add Rust-only ACK, rejection, receipt, wire-sequence, in-flight,
   or dead-letter records.
5. Re-run the `.sfa` recovery real-server probe through the product slot wrapper
   before wiring public API or C ABI.

Do not start with threaded adapters, C++/Python wrappers, orphan draining, SF
compaction, or performance optimization. The main de-risking question is now
whether Java-compatible slot ownership and config fit the current manual core
without public API changes.

## Commands worth re-running

General QWP validation:

```bash
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
git diff --check
```

Focused driver seam:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
```

FFI shape tests:

```bash
cargo test --manifest-path questdb-rs-ffi/Cargo.toml qwpws
```

Real-server probes, when a compatible QuestDB server is running:

```bash
env QDB_QWP_WS_REPLAY_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_replay_frame_is_self_sufficient_on_fresh_connection \
    -- --ignored --nocapture

env QDB_QWP_WS_PROTOCOL_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_real_server_ack_order_and_reject_probe \
    -- --ignored --nocapture

env QDB_QWP_WS_ERROR_TAXONOMY_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_real_server_error_taxonomy_probe \
    -- --ignored --nocapture

env QDB_QWP_WS_PUBLICATION_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_publication_driver_submit_waits_and_row_is_queryable \
    -- --ignored --nocapture

env QDB_QWP_WS_RECONNECT_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_publication_driver_reconnect_replays_only_unacked_rows \
    -- --ignored --nocapture

env QDB_QWP_WS_SFA_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml --lib \
    qwp_ws_sfa_recovered_frame_is_delivered_and_cleaned_up \
    -- --ignored --nocapture
```

## How to think about the fake server

The fake ordered server is a client state-machine tool, not protocol truth.

Use it for:

- queue invariants,
- receipt status,
- event ordering,
- retry/reconnect policy,
- close-drain and timeout behavior,
- SF recovery interactions.

Do not use it as evidence for:

- exact QuestDB status taxonomy,
- close/EOF semantics,
- auth/upgrade behavior,
- server-side ordering beyond what real probes have already established.

When fake behavior and real-server behavior differ, update the design and fake
tests to match the server.
