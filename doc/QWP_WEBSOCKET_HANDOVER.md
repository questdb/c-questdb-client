# QWP/WebSocket pipelined Store-and-Forward handover

Date: 2026-04-29

Status: active validation branch for the Rust client plus C FFI shape.

This is no longer only a design discussion. Steps 1-11 are validated by docs,
Rust prototypes, real-server probes, and C ABI shape stubs. Step 12 has a first
Rust-only blocking WS/WSS transport adapter behind the manual driver seam, but
the new pipelined Store-and-Forward core is not wired into the public product
API or C ABI yet.

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
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs` - current manual driver
  prototype and transport seam.
- `questdb-rs/src/ingress/sender/qwp_ws_queue.rs` - volatile queue prototype.
- `questdb-rs/src/ingress/sender/qwp_ws_sf_queue.rs` - file-backed SF queue
  prototype.
- `questdb-rs-ffi/src/lib.rs` and `include/questdb/ingress/line_sender.h` -
  shape-only C ABI stubs.

Useful Java/server references:

- Java client design:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/design/qwp-cursor-durability.md`
- Java client sender:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
- Java SF send loop:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
- Server source used for taxonomy checks:
  `/home/jara/devel/oss/questdb-arrays`

## Current branch state

Current branch:

```text
ia_qwp_ws
```

Most recent code checkpoint before the 2026-04-29 working-copy changes:

```text
2ef1d4c Refine QWP WebSocket transport seam
```

Recent validation after the Step 12 blocking transport slice:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml encode_failure_does_not_consume_sequence
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml blocking_real_
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
cargo test --manifest-path questdb-rs/Cargo.toml --features async-sender-qwp-ws qwp_ws_async
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Observed result:

```text
encode failure regression: 1 passed
qwp_ws_driver: 43 passed
blocking real transport mock tests: 3 passed
qwp_ws: 113 passed, 3 ignored
qwp_ws_async with async-sender-qwp-ws: 8 passed
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

Still not validated by real server:

- auth/upgrade rejection taxonomy,
- deterministic internal/retryable write failure taxonomy,
- close/EOF behavior while frames are in flight,
- full product integration using the new queue/driver core.

### Queue and receipt prototypes

`questdb-rs/src/ingress/sender/qwp_ws_queue.rs` implements the volatile queue
prototype:

- monotonically increasing FSNs starting at `0`,
- value receipts,
- `Published`, `Sent`, `Acked`, `Poisoned`, `Terminal`, and `Unknown` status
  vocabulary,
- bounded frame and byte capacity,
- fixed in-flight ring,
- zero-based per-connection wire sequence,
- cumulative ACK handling,
- ordered rejection/poison gaps,
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

`questdb-rs/src/ingress/sender/qwp_ws_sf_queue.rs` implements the file-backed SF
queue prototype:

- append-only journal,
- frame publication records,
- ACK-through completion records,
- poison completion records,
- recovery from incomplete tails,
- malformed-log rejection,
- ACK and poison state surviving restart.

The SF journal deliberately does not persist connection-local facts:

- `Sent` receipt status,
- wire sequence,
- in-flight ring contents,
- WebSocket mask keys,
- masked WebSocket bytes.

After process recovery, unresolved frames are `Published`; replay rebuilds
connection-local state from scratch.

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

The next architectural seam is above the queue: product submission must encode a
caller `Buffer` into a self-sufficient replay payload, then publish those bytes
to the queue. The current driver tests still submit opaque payload bytes
directly, which is correct for transport validation but not sufficient for the
next real-server product-path gate.

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
- timeout, drained, poisoned, terminal, and pending are normal outcomes where
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
- Frame-local deterministic server errors should poison/quarantine the affected
  FSN, not terminalize all later in-flight frames by default.
- Events are observability notifications, not authoritative state; receipt
  status and wait/close outcomes are authoritative.
- Fallible work must not advance externally visible state before its commit
  point: encode failure does not consume wire sequence; failed payload
  materialization does not return a receipt; failed local/SF publication does
  not clear the caller buffer; failed transport write does not mark `Sent`.
- Blocking real transports may need send-before-poll progress so coalesced ACKs
  cannot stall the in-flight window. Fake transports can remain poll-first for
  protocol-error fixtures.

## Known gaps and risks

- A Rust-only `Buffer -> replay payload -> queue` publication shell has not been
  wired into the manual driver/core path yet.
- Real-server validation through the new manual driver transport is still
  missing for the full publication path.
- `open_mode=connected` vs `open_mode=lazy` has design text but no real new-core
  implementation.
- The FFI shape stubs are not connected to the real queue/driver prototypes.
- No C++ or Python wrapper implementation has been added for the new QWP/WS
  shape.
- Durable SF prototype lacks segment rotation, compaction, checksums, and
  selectable fsync durability modes.
- Extended Java/Rust golden fixtures are still missing arrays, decimals, UTF-8,
  sparse columns, and schema evolution.
- Close/EOF semantics with unresolved in-flight frames are not yet proven by a
  real-server probe.
- Auth/upgrade rejection and ambiguous operational write/internal errors still
  need taxonomy validation.
- The real transport adapter has local mock WS/WSS coverage, but not yet a real
  QuestDB submit/wait or reconnect replay probe through
  `Buffer -> replay payload -> queue -> BlockingQwpWsTransport`.
- The v1 dense dictionary replay shape is correctness-first and can be expensive
  for long-running high-cardinality symbol workloads.

## Recommended next step

Continue Step 12, but keep it narrow.

Add a Rust-only publication shell first, then one real-server integration/probe
that uses `BlockingQwpWsTransport` through the manual driver seam, not the old
sync sender path.

Suggested slice:

1. Add a narrow Rust-only owner for replay encoding state:
   `QwpWsEncodeScratch`, `SymbolGlobalDict`, negotiated QWP version, and queue.
2. Make its submit path perform `Buffer -> encode_ws_replay_message -> queue
   publication`, returning a receipt only after successful publication.
3. Verify failed encoding/publication does not clear the caller buffer or
   consume externally visible sequence/receipt state.
4. Run valid submit/wait against a real QuestDB QWP/WebSocket endpoint through
   that publication path and `BlockingQwpWsTransport`.
5. Add a reconnect replay case through the same path.
6. Keep this as an ignored/gated probe until the required QuestDB server setup is
   explicit and cheap to reproduce.
7. Record observed ACK, close, and error behavior in a short reflection note.

Do not start with threaded adapters, C++/Python wrappers, SF compaction, or
performance optimization. The main de-risking question is whether real blocking
WebSocket I/O fits the current manual driver state machine without public API
changes.

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
