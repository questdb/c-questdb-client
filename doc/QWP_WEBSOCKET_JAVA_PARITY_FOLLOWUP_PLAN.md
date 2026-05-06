# QWP/WebSocket Java parity follow-up plan

Date: 2026-04-30
Last updated: 2026-05-05

Status: active planning tracker.

Parent architecture and validation docs:

- `doc/QWP_WEBSOCKET_PIPELINED_FFI.md` - global Rust/FFI architecture and
  design principles.
- `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md` - staged validation ladder and
  behavioral gates.
- `doc/QWP_WEBSOCKET_HANDOVER.md` - current implementation state and recent
  validation evidence.

This document tracks follow-up work after refreshing the Java client source at:

```text
/home/jara/devel/oss/questdb-arrays/java-questdb-client
```

It is intentionally a plan, not a locked implementation recipe. Each slice must
start by validating its assumptions against current Java source, current Rust
source, and, when behavior is observable, a real QuestDB server or a focused
behavioral fixture. If validation changes the design pressure, adjust the slice
before coding.

## Source Snapshot

Java branch checked:

```text
vi_sf...origin/vi_sf
```

Relevant Java commits observed since 2026-04-29:

| Commit | Meaning for Rust |
| --- | --- |
| `12049d8` | Adds `initial_connect_retry=async` and the `OFF/SYNC/ASYNC` initial-connect model. |
| `052f6ee` | Makes `close()` rethrow latched terminal and close-drain errors. |
| `13ea8a2` | Preserves close-path errors across cleanup and hardens `awaitAckedFsn(0)` style polling. |
| `9e298e7` | Moves error-dispatch delivered counter before handler invocation. Mostly Java test/observability alignment. |
| `9be35cb` | Test fixture cleanup for async initial connect. |
| `a6b45c3` | Moves slot-lock holder PID to `.lock.pid`, adjusts drainer shutdown, and quiets server-error stack logs. |

Current Rust branch checked:

```text
ia_qwp_ws
```

Rust currently has:

- public sync `qwpws` cut over to the queue/publication driver,
- high-level `Sender::flush()` / `flush_and_keep()` local-publication semantics
  with a sender-owned runner advancing WebSocket I/O,
- ordinary socket send, non-blocking receive polling, and reconnect/backoff
  outside the publication mutex,
- volatile queue when `sf_dir` is unset,
- Java-style `.sfa` slot queue when `sf_dir` is set,
- `initial_connect_retry=sync` as an alias for current blocking startup retry,
- explicit rejection for unsupported `initial_connect_retry=async`,
- explicit rejection for Java's `close_flush_timeout_millis` key until Rust
  wires Java-compatible configurable close-drain timeout semantics,
- a single public `Sender` surface for QWP/WebSocket: background progress is the
  default, and `qwp_ws_progress=manual` lets callers avoid a background thread
  while using `flush_and_get_fsn`, `published_fsn`, `acked_fsn`, `drive_once`,
  and `await_acked_fsn`,
- Java-style `.lock` ownership plus diagnostic `.lock.pid` holder sidecar,
- Java-compatible public sync handling for frame-local schema/write rejection
  policy,
- Java-compatible CRC-last `.sfa` frame append order,
- best-effort skip for bad `.sfa` side files while preserving fatal
  recovered-FSN gap checks,
- structured SFA recovery diagnostics for non-empty torn tails,
- Java `in_flight_window` accepted as an alias for Rust `max_in_flight` while
  preserving Java's `in_flight_window > 1` validation,
- explicit rejection for enabled or behavior-bearing Java QWP/WebSocket config
  keys Rust cannot honor yet, including schema cap, orphan draining, and async
  error inbox sizing; durable ACK opt-in and durable-ACK keepalive, including
  Java's signed `<= 0` disable values, are supported; background-drainer knobs,
  using Java's signed int parsing and `< 0` rejection, are accepted as no-ops
  while orphan draining is disabled,
- Java/spec-style clamping for OK response wire sequences beyond the highest
  sent frame, while rejection/error response wire sequences remain strict
  protocol errors,
- strict empty-payload rejection for live and recovered QWP/WebSocket replay
  payloads,
- strict cleanup error propagation from Rust close/ACK-trim paths,
- no background orphan drainer implementation,
- no Java-style `initial_connect_retry=async` behavior.

## External Agent Fix Handoff (2026-05-05)

This section is the starting context for an external agent continuing the
Java/Rust parity work. Treat it as a handoff, not as a substitute for re-reading
source. Java source is the behavioral reference when Java docs disagree with
code.

### Repositories And Main Source Paths

Rust workspace:

```text
/home/jara/devel/oss/c-questdb-client
```

Java workspace:

```text
/home/jara/devel/oss/questdb-arrays/java-questdb-client
```

Primary Java files:

- `core/src/main/java/io/questdb/client/Sender.java` - public builder,
  configuration parser, WebSocket/SFA option names and defaults.
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
  - high-level sender lifecycle, close drain, durable-ack connect check, orphan
  drainer entry point.
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java`
  - local publication into Store-and-Forward and ACK trimming.
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
  - I/O loop, reconnect, replay, ACK/NACK handling, durable ACK handling, error
  dispatch.
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/MmapSegment.java`
  - `.sfa` segment byte format, append write order, recovery scan, torn-tail
  diagnostics.
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java`
  - recovery policy, segment ordering, empty segment cleanup, trimmable segment
  unlinking.
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SlotLock.java`
  - `.lock` / `.lock.pid` slot ownership.
- `core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/OrphanScanner.java`
  and `BackgroundDrainer*.java` - Java-only orphan slot draining.

Primary Rust files:

- `questdb-rs/src/ingress.rs` - public builder and configuration parser.
- `questdb-rs/src/ingress/conf.rs` - QWP/WebSocket defaults.
- `questdb-rs/src/ingress/buffer/qwp.rs` - QWP encoder and schema ID
  allocation.
- `questdb-rs/src/ingress/sender.rs` - public sender flush, close, drain, and
  diagnostic surface.
- `questdb-rs/src/ingress/sender/qwp_ws_codec.rs` - WebSocket/QWP frame codec
  and upgrade headers.
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs` - transport driver, replay,
  ACK/reject handling, durable-ack parse outcome.
- `questdb-rs/src/ingress/sender/qwp_ws_queue.rs` - volatile queue and
  publication log.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs` - Rust `.sfa` segment
  byte format and recovery scan.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs` - Rust SFA queue,
  recovery, capacity checks, cleanup.
- `questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs` - Rust slot ownership.

Do not use the untracked `doc/QWP_WEBSOCKET_ARCHITECTURE.md` as source of
truth unless the user explicitly asks to work on it. The tracked handoff and
parity documents are the stable coordination points.

### Current Rust State From The Latest Local Work

- The lock-free volatile publication path was simplified under the product
  invariant that `Sender` is single-producer / single-thread owned. Rust no
  longer needs to support concurrent producer calls into the same `Sender`.
- Empty `.sfa` recovery now matches the Java empty-segment policy:
  clean empty segments are removed, and empty torn segments are quarantined as
  `.corrupt` and skipped. The completed Rust fix is in
  `questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs`.
- The following validation passed after that SFA recovery fix:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_queue --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa --lib
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

### Fix Order

1. Done: fix the SFA frame commit-marker write order.
2. Done: implement durable ACK opt-in with Java-compatible durable trimming.
3. Done: align SFA recovery error policy for per-file scan failures while
   keeping recovered-FSN gaps fatal.
4. Done: add diagnostics for recovered non-empty torn tails.
5. Done: audit Java configuration keys and reject unimplemented behavior keys.
6. Done: record OK ACK clamping plus still-strict rejection/error choices and
   cover future response-sequence tests.
7. Defer large operational features, especially orphan drainers and Java-style
   async initial connect, unless the user explicitly prioritizes them.

### Confirmed Parity Gaps

#### J10: SFA Frame Commit Marker Write Order

Java writes the CRC last. In `MmapSegment.tryAppend`, Java writes
`payloadLen`, copies the payload, computes CRC32C over `(payloadLen, payload)`,
then writes the CRC field at the start of the frame. Current reference lines:
`MmapSegment.java:365-385`.

Before this slice, Rust computed CRC first and wrote the full 8-byte frame
header before the payload. Historical reference lines:
`qwp_ws_sfa_segment.rs:169-177`.

Why it matters: Java makes the CRC field the effective commit marker. A crash
before the CRC write leaves a frame that recovery will not accept as committed.
Rust currently writes the CRC before the payload, so a crash after header write
but before payload write can leave a committed-looking header for uncommitted
payload bytes. CRC validation catches ordinary mismatches, but the write order
still does not match the Java crash-safety contract.

Implemented fix shape:

- Change Rust append to write payload length first, then payload, then CRC last.
- Keep the on-disk frame layout unchanged: `[u32 crc32c][u32 payloadLen][payload]`.
- Add regression coverage for partial/torn new frame recovery. At minimum,
  simulate a frame with length/payload bytes but no CRC commit and assert
  recovery treats it as torn/uncommitted.
- Re-run SFA segment and SFA queue tests.

Result: done. `SfaSegment::try_append` writes `payloadLen`, payload, and then
CRC. `scan_treats_length_and_payload_without_crc_commit_as_torn` covers the
crash-safety regression.

#### J11: Durable ACK Lifecycle

Java fails connection when the user requested durable ACKs but the server did
not confirm support in the WebSocket upgrade. Current reference lines:
`QwpWebSocketSender.java:1864-1875`.

In Java durable mode, ordinary OK frames do not trim the SFA store. The send
loop enqueues OK-acked batches and trims only after `STATUS_DURABLE_ACK`
watermarks cover those batches. Current reference lines:
`CursorWebSocketSendLoop.java:1088-1220`, especially the success branch that
calls `enqueuePendingOk` / `drainPendingDurable` in durable mode.

Rust now accepts `request_durable_ack=off|on`, sends
`X-QWP-Request-Durable-Ack` when requested, requires the server durable-ACK echo,
parses durable OK table coverage and `STATUS_DURABLE_ACK` watermarks, and in
durable mode completes frames only after matching durable watermarks cover all
prior pending OKs.

Expected fix shape:

- Full parity option chosen: store OK-acked batches with their per-table seqTxn
  coverage, parse durable ACK table watermarks, trim only when all prior OK
  entries are durably covered, and keep ordinary non-durable ACK behavior
  unchanged.
- Test both server upgrade without durable ACK confirmation and delayed durable
  ACK after OK.

Result: done. `request_durable_ack=off|on` is accepted, server upgrade echo is
validated, and durable mode waits for durable ACK watermarks before completing
frames.

#### J12: SFA Recovery Error Policy

Java recovery opens each `.sfa` file inside `SegmentRing.openExisting`, and
per-file recovery failures are logged/skipped before the contiguous recovered
range is validated. Current reference lines: `SegmentRing.java:152-221` and
`SegmentRing.java:242-264`.

Before this slice, Rust recovery called `scan_file(&path)?` for each candidate,
so one bad `.sfa` file could abort queue open before other files were
considered. Historical reference lines: `qwp_ws_sfa_queue.rs:548` and the later
capacity/contiguity checks around `qwp_ws_sfa_queue.rs:590-678`.

Expected fix shape:

- Match Java's per-file failure policy where safe: skip bad-header or unreadable
  `.sfa` files without renaming them and continue scanning other candidates.
- Preserve Rust's contiguous recovered FSN check after skipped files. If a
  skipped file creates a real gap in the valid sequence, recovery should still
  fail rather than silently lose middle data.
- Add tests with one corrupt side file and one valid contiguous file, plus a
  corrupt middle segment that should still fail due to an FSN gap.

Result: done. Rust now best-effort skips scan-failed `.sfa` files without
renaming them, continues recovery, and still fails a real recovered FSN gap.

#### J13: Non-empty Torn Tail Diagnostics

Both clients recover the valid prefix when a segment has committed frames
followed by torn bytes. Java logs a warning with torn byte count, offset, file
size, and recovered frame count. Current reference lines:
`MmapSegment.java:247-258`.

Before this slice, Rust recorded `torn_tail_bytes` in the segment scan, but the
queue only branched specially for empty torn segments. Non-empty torn tails were
accepted without a structured diagnostic. Historical reference lines:
`qwp_ws_sfa_segment.rs:247-282` and `qwp_ws_sfa_queue.rs:548-562`.

Expected fix shape:

- Add a warning or structured diagnostic for non-empty torn tails.
- Do not make non-empty torn tails fatal if Java recovers the prefix.
- Cover the diagnostic in a focused unit test if the logging/diagnostic path is
  testable without brittle log capture.

Result: done. `SfaRecoveryDiagnostic::NonEmptyTornTail` records path, torn byte
count, append offset, file size, and recovered frame count.

#### J14: Recovery Capacity And Memory Policy

Java recovers segments by mmap and segment metadata; it does not materialize all
recovered payloads into heap memory during recovery. Current reference areas:
`MmapSegment.openExisting`, `SegmentRing.openExisting`, and
`SegmentManager`.

Rust scans files and stores recovered payload bytes in memory before replay.
Current reference lines: `qwp_ws_sfa_segment.rs:247-274` and
`qwp_ws_sfa_queue.rs:594-606`.

Rust also rejects recovered backlog that exceeds current configured frame,
byte, or segment capacity. Current reference lines:
`qwp_ws_sfa_queue.rs:590-678`. Java is more tolerant of already-recovered disk
state and applies capacity mostly to future publication/spare provisioning.

Expected fix shape:

- Treat this as a design decision, not a small local patch.
- If matching Java, recover existing disk state even when current config shrank,
  then apply caps only to new publication/backpressure.
- If keeping Rust strict, document that Rust may fail startup after a config
  shrink where Java would replay first.
- Consider a future mmap/streaming replay design before loading large recovered
  payloads into memory.

Decision: keep Rust strict for v1. Startup may fail after a config shrink that
would leave Java able to replay first; this is preferable to adding a larger
mmap/streaming recovery design inside this follow-up.

#### J15: Empty Payload Frames

Java segment append rejects negative payload lengths but permits
`payloadLen == 0`. Current reference lines: `MmapSegment.java:365-379`.

Rust rejects empty new submissions and empty recovered frames. Current reference
areas: queue publication validation and `qwp_ws_sfa_queue.rs:650-658`.

Expected fix shape:

- First verify whether a valid QWP replay payload can ever be empty.
- If empty QWP payloads are impossible by higher-level contract, document the
  invariant and keep Rust stricter.
- If Java-readable zero-payload segments must be replayable, allow empty
  recovered frames and add compatibility tests.

Decision: keep Rust strict for v1. A valid Rust QWP/WebSocket replay payload is
produced only from a non-empty QWP buffer; public `Sender` flush returns without
publication for an empty buffer, the QWP replay encoder rejects empty buffers,
and both volatile and SFA queues reject empty payloads. Recovered zero-length
`.sfa` frames therefore remain corrupt in Rust rather than replayable
compatibility frames. Tests cover both live SFA submission rejection without FSN
consumption and recovered empty-frame rejection.

#### J16: Cleanup Error Policy

Java cleanup of fully drained SFA files is best effort and logs unlink failures.
Rust propagates non-`NotFound` unlink errors from queue cleanup. Current Rust
reference areas: `qwp_ws_sfa_queue.rs:216-226`, `qwp_ws_sfa_queue.rs:420-427`,
and `qwp_ws_sfa_queue.rs:740-747`.

Expected fix shape:

- Decide whether Rust `close()` / ACK trimming should be strict about cleanup
  failures or Java-compatible best effort.
- If changing behavior, preserve diagnostics so operators can still see leaked
  files.

Decision: keep Rust strict for v1. Java can log and continue because cleanup
failure is reported through its logger and background lifecycle. Rust's SFA
queue close and ACK-trim APIs are already fallible, so propagating unexpected
unlink failures is the clearer operator signal than silently leaving durable
store files behind. Best-effort cleanup remains limited to Java-compatible
empty-torn-segment quarantine paths.

#### J17: Over-large OK ACK and Rejection Handling

Java clamps ACK/NACK wire sequence values to the highest sent sequence before
trimming or rejecting. Current reference lines:
`CursorWebSocketSendLoop.java:1094-1108` and
`CursorWebSocketSendLoop.java:1131-1141`.

Rust intentionally splits the behavior: OK responses, including durable-mode
OKs, clamp unknown future wire sequence values to the highest sent sequence
before completing or enqueueing frames; rejection/error responses remain strict
protocol errors.
Current reference areas: `QwpWsPublicationStore::apply_response`,
`QwpWsPublicationStore::complete_ack_through`,
`QwpWsPublicationStore::apply_durable_ok`, `SendCursor::ack_fsn_for_wire_seq`,
and strict rejection handling through `SendCursor::fsn_for_wire_seq`.

Validation shape:

- Test over-large non-durable OK ACK and durable-mode OK responses clamp to the
  highest sent sequence.
- Test over-large rejection frames remain protocol errors.
- Confirm no trim can advance past sent/published data.

Decision: match Java/spec for ordinary OK ACKs and keep Rust strict for future
rejection/error frames. Tests cover future OK ACK clamping, durable-mode OK
clamping, and future rejection protocol errors, and assert no receipt is
resolved past what was sent.

#### J18: Configuration Surface Differences

Java parses these QWP/WebSocket options in `Sender.java`:

- `in_flight_window`
- `request_durable_ack`
- `max_schemas_per_connection`
- `sf_dir`
- `sender_id`
- `sf_max_bytes`
- `sf_max_total_bytes`
- `sf_durability`
- `close_flush_timeout_millis`
- `durable_ack_keepalive_interval_millis`
- `reconnect_max_duration_millis`
- `reconnect_initial_backoff_millis`
- `initial_connect_retry`
- `sf_append_deadline_millis`
- `drain_orphans`
- `max_background_drainers`
- `error_inbox_capacity`
- `reconnect_max_backoff_millis`

Current Java parser reference lines: `Sender.java:2607-2738`.

Rust now accepts Java spelling `in_flight_window` as an alias for
`max_in_flight` while rejecting `in_flight_window <= 1`, keeps SFA and reconnect
keys, explicitly rejects `sf_append_deadline_millis`,
`close_flush_timeout_millis`, `initial_connect_retry=async`, accepts
`request_durable_ack=off|on` and `drain_orphans=off|false`, applies
`durable_ack_keepalive_interval_millis`, accepts Java's signed `<= 0` keepalive
disable values and signed-int background-drainer parsing, and rejects
unimplemented Java behavior keys or enabled values:
`max_schemas_per_connection`, `drain_orphans=on|true`, and
`error_inbox_capacity`. Unknown non-QWPWS keys remain ignored for cross-client
compatibility.

Expected fix shape:

- Do not silently ignore Java QWP/WebSocket keys that Rust does not implement.
- Prefer explicit rejection for unimplemented behavior-bearing enabled values or
  keys: `max_schemas_per_connection`, `drain_orphans=on|true`, and
  `error_inbox_capacity`.
- Java spelling `in_flight_window` is accepted as an alias for Rust
  `max_in_flight`, with Java's `> 1` validation preserved.
- Keep existing explicit rejections for `sf_append_deadline_millis`,
  `close_flush_timeout_millis`, and `initial_connect_retry=async` until their
  runtime behavior exists.

Result: done.

#### J19: Larger Operational Parity Backlog

These are known differences but should not be mixed into the first crash-safety
and durability fixes:

- Java supports `initial_connect_retry=async`; Rust rejects it until a real
  background initial-connect lifecycle exists.
- Java has orphan slot scanning and background drainers; Rust opens exactly the
  configured `<sf_dir>/<sender_id>` slot.
- Java `SlotLock` documents `flock` / `LockFileEx`; Rust uses Unix `flock` and
  returns `SlotLockUnsupported` on non-Unix targets.
- Java requires WebSocket `in_flight_window` greater than 1; Rust accepts
  `max_in_flight=1` only through the Rust spelling.
- Java has a configurable `max_schemas_per_connection`; Rust schema IDs are
  allocated from a `u64` counter in `qwp.rs`.
- Java has async error/progress observer hooks; Rust exposes bounded pollable
  diagnostics from the sender surface.

### Suggested Validation Commands

Use the smallest test filter that covers the changed slice, then run formatting
and whitespace checks.

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_segment --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sfa_queue --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_from_conf --lib
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_sync --lib
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Run broader tests only when the changed behavior crosses the driver/public
sender boundary. For disk-format changes, include at least the segment and SFA
queue tests.

## Working Assumptions

These are assumptions, not permanent facts. Re-check them at the beginning of
each slice.

1. Java source and tests are the parity source of truth when Java markdown docs
   are stale.
2. Rust should match Java public configuration names and observable behavior
   unless Rust's ownership/FFI boundary makes that shape misleading.
3. The on-disk Store-and-Forward contract includes the slot directory layout and
   lock sidecar files, not only the `.sfa` segment bytes.
4. Simplicity wins over feature symmetry when parity would require permanent
   machinery that the Rust product surface is not ready to expose.
5. The old Tokio sender is not a foundation for new work. Future async behavior
   should be an adapter over the single queue/driver core.
6. Behavioral tests are preferred. Unit tests are appropriate for filesystem
   layout and parser boundaries, but transport and recovery claims should be
   backed by real-server probes when feasible.
7. Do not add Rust-only durable dead-letter, quarantine, rollback, or completion
   records unless a fresh Java comparison shows that Java has equivalent product
   semantics.
8. The ordinary Rust `Sender` API should stay the single product surface:
   `flush()` and `flush_and_keep()` publish into bounded local memory/SFA
   storage and return without waiting for the newly published frame's ACK.
   Rust's explicit-progress exception is a `qwp_ws_progress=manual` mode on the
   same `Sender`, not a separate public sender type.

## Iteration Rule

Every implementation iteration starts with this gate:

1. **Validate assumptions**
   - Re-read the current Java files for the feature.
   - Re-read the current Rust files that would change.
   - Check whether Java design docs are stale relative to source.
   - Identify the behavior that a user can observe.
2. **Reflect on design**
   - Is this a public contract, disk-format contract, or implementation detail?
   - Can the behavior be matched with less permanent machinery?
   - Would matching Java exactly make Rust less idiomatic or less honest?
   - Does this belong in the sync sender, a lower-level API, or a future adapter?
3. **Choose the next globally coherent move**
   - Re-check the grand plan before narrowing scope.
   - Choose a slice size that preserves architectural simplicity. Sometimes
     that is a small local fix; sometimes it is a broader adjustment that removes
     a misleading split or avoids carrying temporary complexity forward.
   - Add tests that would still be valid after an internal rewrite.
   - Update docs when they clarify the product contract, design direction, or a
     known Java/Rust gap.
4. **Record outcome**
   - Update the tracker row.
   - Add a short decision-log entry with evidence and validation commands.

## Progress Tracker

Status values:

- `todo` - not started.
- `validating` - assumption validation or design reflection is in progress.
- `implementing` - code/docs are being changed.
- `done` - implementation and validation are complete.
- `deferred` - deliberately not doing now, with reason recorded.

| ID | Status | Architecture layer | Slice | Why it matters | Required first validation | Completion signal |
| --- | --- | --- | --- | --- | --- | --- |
| J1 | done | SFA slot / disk contract | Slot lock `.lock.pid` parity | Java moved holder PID out of `.lock`; on-disk slot layout should match. | Re-read Java `SlotLock.java`; re-read Rust `qwp_ws_sfa_slot.rs`; confirm whether `.lock.pid` is only diagnostic and stale-safe. | Rust creates `.lock` plus `.lock.pid`, reads holder from `.lock.pid`, and existing lock behavior remains unchanged. |
| J2 | done | Public config surface | `initial_connect_retry` parser surface | Java now accepts `off/false/on/true/sync/async`; Rust should match supported names without pretending to support Java's async lifecycle. | Re-read Java `Sender.java` parsing and Rust config parser; confirm the unsupported-mode error text. | `sync` is accepted as an alias for the existing retry behavior, and `async` is rejected clearly until the behavior exists. |
| J3 | deferred | Adapter / lifecycle boundary | Initial-connect mode design | Java's `ASYNC` returns before any socket exists; Rust currently rejects that spelling. High-level Rust `Sender` may later own a runner, but async initial connect is still a distinct lifecycle mode. | Before resuming, trace Java `InitialConnectMode.ASYNC`, Rust open/flush semantics, and the high-level runner design. | Not implemented now. `initial_connect_retry=async` stays rejected until the behavior exists. |
| J4 | done | Driver / error surface | Reconnect budget exhaustion classification | Java distinguishes never-connected config-likely failures from connection-lost transient failures. | Re-read Java `hasEverConnected` handling; inspect Rust driver/transport reconnect state and current error messages. | Decision recorded: Rust keeps the simpler current transport error surface until a public product need justifies a stable classification. |
| J5 | done | Public close / FFI boundary | Close-drain and terminal close semantics | Java now treats close-drain timeout and latched terminal errors as observable close failures. | Compare Java `close()` with Rust public close, FFI `close_drain`, and existing `CloseOutcome`; decide which public surfaces need parity. | Rust keeps drop/void-close fast, exposes explicit `Sender::close_drain()`, and rejects `close_flush_timeout_millis` until configurable timeout parity is wired. |
| J6 | done | Operational recovery / adapter layer | Orphan drainer scope check | Java now has real background orphan drainers and `.failed` sentinel behavior; Rust intentionally does not. | Re-read Java orphan scanner/drainer code and Rust SFA recovery scope; validate whether this is needed before public release. | Decision recorded; Rust accepts disabled `drain_orphans=off|false` and inert `max_background_drainers`, rejects enabled `drain_orphans`, and does not add partial drainer behavior. |
| J7 | done | Documentation architecture | Docs sync after code slices | Handover, validation plan, and design proposal should not contradict the implemented contract. | Cross-read changed docs plus `QWP_WEBSOCKET_HANDOVER.md`, `QWP_WEBSOCKET_VALIDATION_PLAN.md`, and `QWP_WEBSOCKET_PIPELINED_FFI.md`. | Docs name current behavior, known gaps, and validation evidence without promising unimplemented Java features. |
| J8 | done | Public sync error surface | Frame-local server rejection behavior | Java treats schema/write rejections as drop-and-continue and exposes the server message. Rust should report the rejection without making the sender terminal. | Re-read Java `CursorWebSocketSendLoop` and `SenderError`; inspect Rust codec/driver/public flush path and existing coverage. | Public mock-server test rejects the first flush with schema mismatch, verifies the server message and error category, then successfully flushes a second frame on the same sender. |
| J9 | partial | Public `Sender` semantics | Java-like local-publication flush | Java `Sender.flush()` publishes into the cursor engine and returns before ACK; Rust now has the local-publication runner slice and bounded post-flush diagnostics, but still rejects Java-configurable append-deadline backpressure. | Re-read Java `QwpWebSocketSender.flush()`, `CursorSendEngine.appendBlocking()`, Rust `flush_qwp_ws()`, `flush_and_keep()`, config parsing, and queue capacity semantics. | High-level Rust `Sender::flush()` / `flush_and_keep()` locally publish, pipeline before ACK, apply the current bounded append backpressure, and report later QWP/server-close diagnostics through a bounded pollable observer path. |
| J10 | done | SFA disk format / crash recovery | CRC-last frame commit marker | Java writes SFA CRC last; Rust previously wrote CRC in the header before payload. | Re-read Java `MmapSegment.tryAppend` and Rust `qwp_ws_sfa_segment::append`. | Rust append order matches Java and recovery tests prove partial new frames are not committed. |
| J11 | done | Durable ACK / trim semantics | `request_durable_ack` behavior | Java trims SFA only after durable ACK watermarks in durable mode. | Re-read Java durable ACK connect check and send-loop durable tracking; re-read Rust codec/driver response handling. | Rust accepts `request_durable_ack=off|on`, validates durable ACK upgrade echo, and completes durable-mode frames only after durable ACK watermarks cover prior pending OKs. |
| J12 | done | SFA recovery policy | Java-compatible recovery skip/quarantine | Empty clean/torn segment handling is aligned; Rust now also skips per-file scan errors Java skips. | Re-read Java `SegmentRing.openExisting`, Java `MmapSegment.openExisting`, and Rust `recover_segments`. | Bad side files are skipped without renaming where Java skips them, while real recovered FSN gaps remain fatal. |
| J13 | done | SFA diagnostics | Non-empty torn-tail warning | Java warns when valid recovered frames are followed by torn bytes; Rust now records a structured recovery diagnostic. | Re-read Java `MmapSegment.openExisting` torn-tail logging and Rust scan result handling. | Rust exposes a structured diagnostic without making valid-prefix recovery fatal. |
| J14 | done | SFA recovery capacity / memory | Recover existing disk state under current caps | Java mmap recovery is more tolerant of already-existing disk state; Rust materializes payloads and applies current caps during startup. | Compare Java segment manager recovery with Rust recovered frame validation. | Decision recorded: Rust keeps strict v1 recovery caps until a larger mmap/streaming design is justified. |
| J15 | done | Public config / protocol surface | Unsupported Java keys | Java parses more QWP/WebSocket behavior keys than Rust implements. | Re-read Java parser key list and Rust `ingress.rs` parser branches. | Rust explicitly rejects behavior-bearing Java keys it cannot honor, accepts no-op dependent knobs, and accepts `in_flight_window` as a Java-validated alias. |
| J16 | done | Protocol response policy | Over-large OK/rejection handling | OK responses clamp over-large wire sequences to highest sent; rejection/error policy remains strict in Rust until Java/spec behavior is re-checked. | Re-read Java clamp branches and Rust `SendCursor` response resolution. | Rust clamps future non-durable and durable OK responses to highest sent, keeps future rejection frames as protocol errors, and tests both paths. |
| J17 | deferred | Operational parity | Async initial connect and orphan drainers | These are large lifecycle features, not local bug fixes. | Re-read Java async startup and orphan drainer code before any implementation. | No partial implementation without a product scenario and behavioral tests. |

## Slice Notes

### J1: Slot Lock `.lock.pid` Parity

Current hypothesis: this is the best first slice. It is small, mechanical, and
part of the disk layout. It does not force background threads, new public API,
or async behavior.

Design pressure:

- The PID sidecar is diagnostic-only.
- A stale `.lock.pid` is acceptable because the next successful acquirer
  overwrites it.
- The lock itself remains `<slot>/.lock`.
- Tests should assert behavior, not internals: lock contention reports a holder,
  lock release permits reuse, and the slot contains Java-compatible sidecar
  files after acquisition.

Validation candidates:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --lib qwp_ws_sfa_slot
git diff --check
```

### J2/J3: Initial Connect Modes

Current hypothesis: split parser compatibility from behavior design.

`sync` is likely a parser alias for the existing `true` behavior. `async` is not
just a parser value. In Java it changes the sender lifecycle: construction
returns before a socket exists, the I/O loop connects in the background, and
terminal startup failures are delivered asynchronously.

Rust's current public sync sender has a different observable contract:

- `build()` connects,
- `flush()` publishes locally and returns before the newly submitted frame's
  ACK,
- the background runner starts only after the blocking initial connection
  succeeds.

Do not paper over that mismatch. Until Rust has a real implementation for the
async lifecycle, `initial_connect_retry=async` must be rejected clearly. It must
not be accepted as a no-op, as an alias for `sync`, or as a promise that the
sender cannot keep.

The broader architecture has since moved toward a Java-like high-level
`Sender` runner, but that does not automatically implement Java's async initial
connect mode. Blocking startup retry and background initial connect are separate
observable contracts. When async startup is needed, design it explicitly over
the same cursor/runner core.

Validation candidates:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --lib qwp_ws_from_conf
cargo test --manifest-path questdb-rs/Cargo.toml --lib qwp_ws_sync_initial_connect_retry
```

### J4: Reconnect Budget Classification

Current hypothesis: useful, but lower priority than disk layout and config
surface. Classification is mostly error quality, not recovery correctness.

Questions to answer first:

- Does Rust already know whether the transport ever completed a WebSocket
  upgrade?
- Would the classification be visible as a stable API, an error message only, or
  a structured event later?
- Can the same tests cover never-connected and previously-connected failures
  without depending on internal driver counters?

### J5: Close Semantics

Decision: Rust should not accept Java's `close_flush_timeout_millis` until there
is a Rust API path that can report close-drain failures.

Java owns row buffers inside the sender, has a background I/O loop, and can make
`close()` flush user-thread state, wait for ACKs, and throw on timeout or
latched terminal errors. Rust's public API has external buffers and `Drop`,
C `line_sender_close()`, and C++ destructors do not have a reliable error return
channel. Even after the high-level `Sender` moves to Java-like local-publication
`flush()`, blocking and failing from drop would be surprising and still would
not flush an external `Buffer`.

Therefore:

- `close_flush_timeout_millis` must not be accepted as a no-op.
- The current sync sender rejects that Java config key with an explicit message
  pointing users at `Sender::close_drain()` for fallible drain behavior.
- The explicit close-drain shape remains the right Rust/FFI model for pipelined
  QWPWS APIs where submitted frames can be pending after a call returns. The
  remaining gap is configurable Java-compatible timeout wiring, not the
  existence of a fallible drain path.

Questions to answer first:

- When wiring the real QWPWS FFI sender, should `close_drain(timeout)` return a
  value outcome only, or also expose the terminal/drain error text directly?
- Should wrappers offer Java-style close behavior as convenience over explicit
  `flush()` / `close_drain()`, or keep the Rust/C boundary explicit?

### J6: Orphan Drainers

Current hypothesis: defer until the foreground slot path is stable. Java's
orphan drainer is real product behavior, but implementing it in Rust adds
background execution, slot adoption, failure sentinels, and shutdown policy.

Before starting:

- prove the user scenario that needs it,
- inspect Java's current `.failed` behavior,
- decide whether Rust v1 can instead document manual recovery,
- design tests around slots being drained or skipped, not around thread-pool
  internals.

## Decision Log

Append entries in this format:

```text
YYYY-MM-DD - Jx - decision
Evidence:
- Java:
- Rust:
- Validation:
Result:
- done/deferred/follow-up
```

2026-04-30 - J1 - match Java `.lock.pid` slot holder sidecar
Evidence:
- Java: `SlotLock` keeps `.lock` as the actual lock file, writes holder PID to
  `.lock.pid`, reads holder diagnostics from `.lock.pid`, and treats PID writes
  as best-effort.
- Rust: `qwp_ws_sfa_slot.rs` now keeps flock ownership on `.lock`, writes the
  holder PID sidecar to `.lock.pid`, reads contention diagnostics from that
  sidecar, and leaves both files behind for slot reuse.
- Validation: `cargo test --manifest-path questdb-rs/Cargo.toml --lib
  qwp_ws_sfa_slot`; `cargo test --manifest-path questdb-rs/Cargo.toml --lib
  qwp_ws_sfa`.
Result:
- done.

2026-04-30 - J2/J3 - reject `initial_connect_retry=async` until implemented
Evidence:
- Java: `initial_connect_retry=async` is a real lifecycle mode, not just a
  parser synonym; it returns a sender before a socket exists and reports
  startup terminal failures asynchronously.
- Rust: current sync `qwpws` still connects during `build()`. Its high-level
  `flush()` now publishes locally, but accepting `async` without changing
  construction and startup-error delivery would still be misleading.
- Validation: source comparison only; implementation slice still needs parser
  tests.
Result:
- follow-up: accept `sync` as an alias for existing retry behavior, reject
  `async` with an explicit unsupported-mode error until the real behavior
  exists.

2026-04-30 - J2 - parser surface aligned for supported modes
Evidence:
- Java: config parsing accepts `on` / `true` / `sync` as `SYNC`, `off` /
  `false` as `OFF`, and `async` as the real background `ASYNC` lifecycle mode.
- Rust: `initial_connect_retry=sync` now aliases the existing blocking startup
  retry behavior; `initial_connect_retry=async` fails during config parsing with
  an explicit unsupported-mode error.
- Validation: `cargo test --manifest-path questdb-rs/Cargo.toml --lib
  qwp_ws_from_conf_parses_java_reconnect_keys`; `cargo test --manifest-path
  questdb-rs/Cargo.toml --lib
  qwp_ws_sync_initial_connect_retry_survives_dropped_upgrade`.
Result:
- done.

2026-04-30 - J3 - defer Java-style async initial connect
Evidence:
- Architecture: the manual core remains threadless; the high-level `Sender`
  design may own a Java-like runner, but background initial connect is still a
  separate lifecycle contract from blocking startup retry.
- Rust: accepting `initial_connect_retry=async` before the behavior exists would
  make build, flush, close, and FFI error timing misleading.
- Validation: design-level decision; no code validation needed until the
  adapter is planned.
Result:
- deferred: do not implement Java-style `ASYNC` initial connect in the sync
  sender now. Revisit only as part of the high-level runner / explicit adapter
  lifecycle design.

2026-04-30 - J8 - validate public sync frame-local rejection behavior
Evidence:
- Java: `CursorWebSocketSendLoop` classifies schema mismatch and write errors as
  drop-and-continue server rejections and exposes structured `SenderError`
  details including category, policy, raw status, server message, and affected
  sequence range.
- Rust: `qwp_ws_codec.rs` maps schema mismatch/write statuses to non-terminal
  transport responses; `qwp_ws_driver.rs` resolves the affected frame, stores
  the server error, and lets the sender continue. After the Java-like
  local-publication `flush()` cutover, rejected frames are not synchronously
  reported by the publishing `flush()` call.
- Validation: `cargo test qwp_ws_schema_rejection_drops_and_sender_continues`;
  `cargo test qwp_ws_server_error_response_is_surfaced`; `cargo test raw_qwp`.
Result:
- done for drop-and-continue behavior on the public sync sender surface. Future
  public/FFI work still needs a simple diagnostic path for server rejections so
  rejection details do not depend on private driver state.

2026-04-30 - J5 - keep sync close explicit and reject Java close timeout key
Evidence:
- Java: `QwpWebSocketSender.close()` flushes sender-owned pending rows, drains up
  to `closeFlushTimeoutMillis`, and rethrows close-drain or latched terminal
  errors after cleanup. Java config exposes `close_flush_timeout_millis` for that
  behavior.
- Rust: public `Sender` uses external buffers, and dropping `Sender` has no
  error return channel. `Sender::close_drain()` is the explicit fallible close
  path; Java's close timeout key should remain rejected until that timeout is
  configurable with Java-compatible semantics.
- Validation: `cargo test qwpws_store_and_forward_config_rejects_invalid_java_keys`;
  `cargo test qwpws_store_and_forward_config_is_websocket_only`.
Result:
- done for the public sync config surface: `close_flush_timeout_millis` is now a
  known unsupported Java key, not a silently ignored no-op. Public
  `Sender::close_drain()` exists with the current built-in timeout; configurable
  Java-compatible timeout wiring remains a follow-up.

2026-04-30 - J9 - adjust target toward Java-like high-level Sender
Evidence:
- Java: `QwpWebSocketSender.flush()` publishes into the cursor engine and does
  not wait for server ACK; local backpressure is bounded by
  `sf_max_total_bytes` and `sf_append_deadline_millis`.
- Rust: high-level `flush_qwp_ws()` now encodes a replay-safe payload, publishes
  locally into memory/SFA storage, clears the caller buffer only after local
  publication, and returns before ACK while a sender-owned runner advances
  transport progress. The latest runner slices move ordinary send,
  non-blocking receive polling, and reconnect/backoff outside the publication
  mutex. Rust still recognizes and rejects `sf_append_deadline_millis` until
  the current sender can use it for Java-compatible local-publication
  backpressure.
- Validation: behavioral mock tests cover delayed ACK, pipelined `flush()` /
  `flush_and_keep()`, schema/write rejection drop-and-continue, reconnect
  replay, and a blocked transport send that does not block another local
  publication. They now also cover blocked reconnect not blocking another local
  publication. Remaining validation starts with append backpressure,
  append-deadline config acceptance, and FFI exposure for pollable async
  diagnostics.
Result:
- partial: local-publication `flush()` and the first runner ownership slices are
  in place. Append-deadline config remains rejected until it affects runtime
  backpressure. Continue converging toward the Java-shaped store/runner split
  rather than growing the manual driver as the permanent high-level runner core.

2026-05-05 - J12 - match Java empty `.sfa` recovery policy
Evidence:
- Java: `SegmentRing.openExisting` removes genuinely empty clean segments, but
  renames empty torn segments to `.corrupt` and continues recovery.
- Rust: `qwp_ws_sfa_queue.rs` now removes clean empty segments and
  best-effort quarantines empty torn segments as `.corrupt`, replacing any stale
  `.corrupt` file first.
- Validation: `cargo test --manifest-path questdb-rs/Cargo.toml
  qwp_ws_sfa_queue --lib`; `cargo test --manifest-path questdb-rs/Cargo.toml
  qwp_ws_sfa --lib`; `cargo fmt --manifest-path questdb-rs/Cargo.toml
  --check`; `git diff --check`.
Result:
- done for empty clean/torn segment recovery. Later slices completed
  non-destructive scan-failure skips and non-empty torn-tail diagnostics.

2026-05-05 - J10-J17 - record external-agent parity handoff
Evidence:
- Java: source comparison covered `Sender.java`, `QwpWebSocketSender.java`,
  `CursorWebSocketSendLoop.java`, `MmapSegment.java`, `SegmentRing.java`, and
  `SlotLock.java`.
- Rust: source comparison covered `ingress.rs`, `qwp_ws_codec.rs`,
  `qwp_ws_driver.rs`, `qwp_ws_sfa_segment.rs`, `qwp_ws_sfa_queue.rs`,
  `qwp_ws_sfa_slot.rs`, and `buffer/qwp.rs`.
- Validation: documentation-only update; run `git diff --check`.
Result:
- superseded by later 2026-05-05 implementation slices below; J10 was the next
  slice and is now complete.

2026-05-05 - J11/J18 - validate durable-ACK and config-surface assumptions
Evidence:
- Java: `Sender.java` parses `request_durable_ack`, `in_flight_window`,
  `error_inbox_capacity`, and the other WebSocket/SFA keys listed in J18.
  `QwpWebSocketSender` rejects durable-ACK opt-in when the server does not
  confirm support during upgrade.
- Rust at this checkpoint: `QwpWsConfig` contains `request_durable_ack` and the
  upgrade path passes it to the codec, but `ingress.rs` has no public
  `request_durable_ack` parser branch. Unknown keys are ignored unless
  explicitly matched.
- Validation: source comparison only; documentation corrected to distinguish
  internal durable-ACK plumbing from public config support.
Result:
- superseded by later implementation slices below; durable ACK opt-in is now
  accepted with durable trimming, and Java `in_flight_window` is accepted as a
  Java-validated alias.

2026-05-05 - J10/J12/J13 - finish SFA crash-safety and recovery policy slice
Evidence:
- Java: `MmapSegment.tryAppend` writes payload length, payload, then CRC last;
  `SegmentRing.openExisting` skips per-file recovery failures while preserving
  the contiguous recovered range check; `MmapSegment.openExisting` logs
  non-empty torn tails.
- Rust: `SfaSegment::try_append` now writes CRC last without changing the
  on-disk `[crc32c][payloadLen][payload]` layout. `SfaFrameQueue` now
  best-effort skips scan-failed `.sfa` files without renaming them, continues
  scanning sibling files, keeps recovered-FSN gaps fatal, and records
  `SfaRecoveryDiagnostic::NonEmptyTornTail` for valid-prefix recovery with torn
  bytes.
- Validation: `cargo test --manifest-path questdb-rs/Cargo.toml
  qwp_ws_sfa_segment --lib`; `cargo test --manifest-path questdb-rs/Cargo.toml
  qwp_ws_sfa_queue --lib`.
Result:
- done. Partial length+payload-without-CRC frames recover as torn/uncommitted;
  corrupt side files are skipped without dropping contiguous valid data; corrupt
  middle files still fail as FSN gaps without being renamed; non-empty torn tails
  are non-fatal but diagnosed.

2026-05-05 - J11/J15 - reject unsupported Java QWP/WebSocket behavior keys
Evidence:
- Java: `Sender.java` parses `in_flight_window`, `request_durable_ack`,
  `max_schemas_per_connection`, `durable_ack_keepalive_interval_millis`,
  `drain_orphans`, `max_background_drainers`, and `error_inbox_capacity`.
- Rust: `SenderBuilder::from_conf` now accepts `in_flight_window` as a
  Java-validated alias for `max_in_flight`, accepts `request_durable_ack=off|on`
  and `drain_orphans=off|false`, applies durable ACK keepalive settings, parses
  dependent orphan-drainer no-op knobs, and rejects the unimplemented Java
  behavior keys above instead of silently ignoring them.
- Validation: `cargo test --manifest-path questdb-rs/Cargo.toml qwpws --lib`.
Result:
- done for the safe public config surface. Durable ACK behavior is now present;
  configurable schema caps, orphan drainers, and Java-style async error inbox
  remain future features.

2026-05-05 - J4/J6/J14/J16 - record deliberate strict/deferred decisions
Evidence:
- Java: `CursorWebSocketSendLoop` tracks `hasEverConnected` for reconnect
  budget classification and clamps future ACK/NACK wire sequences to the
  highest sent. Java also has orphan scanning/background drainers with a
  `.failed` sentinel, and mmap-based SFA recovery that is more tolerant of
  config shrink than Rust's materialized recovery.
- Rust: current reconnect errors surface the underlying transport/config error
  without a stable never-connected vs connection-lost classification; enabled
  `drain_orphans` is rejected while `max_background_drainers` is parsed as an
  inert dependent knob; SFA recovery keeps current configured frame/byte/segment
  caps; OK responses use `SendCursor::ack_fsn_for_wire_seq` to clamp future
  wire sequences, while rejection/error responses still use strict
  `SendCursor::fsn_for_wire_seq` resolution.
- Validation: `cargo test --manifest-path questdb-rs/Cargo.toml future_ --lib`;
  source validation for reconnect classification, orphan drainers, and recovery
  capacity policy.
Result:
- done as decisions. Keep Rust strict/simple for v1 and revisit only with a
  product scenario plus behavioral tests.

2026-05-05 - J15-detail/J16-detail - close empty-payload and cleanup-policy decisions
Evidence:
- Java: `MmapSegment.tryAppend` accepts zero-length payloads at the segment
  layer, and cleanup of fully drained files is best effort with logging.
- Rust: public QWP/WebSocket flush does not publish empty QWP buffers, the replay
  encoder rejects empty buffers, SFA live submit rejects empty payloads without
  consuming FSN, and recovered zero-length `.sfa` frames are corrupt. Rust
  `close()` and ACK trimming retain their fallible unlink behavior.
- Validation: `cargo test --manifest-path questdb-rs/Cargo.toml
  qwp_ws_sfa_queue --lib`.
Result:
- done as decisions plus focused SFA tests. Empty replay payloads remain invalid
  in Rust, and cleanup failures remain visible through fallible queue operations.

## Open Questions

- What should the eventual explicit threaded/async adapter API look like if we
  decide to support Java-style async initial connect?
- Should reconnect budget classification become structured state later if the
  public API exposes richer progress events?
- What concrete operational scenario would justify Rust orphan drainers instead
  of explicit rejection for `drain_orphans`?
- Should wrappers expose a Java-style close convenience after the explicit
  QWPWS close-drain API is wired?
- Should callbacks be added later as a convenience over the bounded pollable
  error/event path, and if so how should overflow/dropped-notification counters
  be exposed across Rust/C/C++/Python?
