# QWP/WebSocket Store-and-Forward Spec Alignment Design

Status: design handoff

Date: 2026-05-12

Repository: `/home/jara/devel/oss/c-questdb-client`

Server and Java reference repository: `/home/jara/devel/oss/questdb-arrays`

## Goal

Bring the Rust QWP/WebSocket store-and-forward implementation closer to the
current store-and-forward client spec and the Java client, without introducing a
new architecture.

The recommended first implementation slice is deliberately small:

1. Add spec-compatible `.ack-watermark` recovery support.
2. Switch newly created disk SFA segments to generation naming
   `sf-0000000000000000.sfa`, while continuing to read legacy
   `sf-initial.sfa` for current Java interoperability.

`.ack-watermark` is optional in the protocol, but it is in scope for this Rust
implementation slice. Do not defer it.

Do not implement failover, async initial connect, Windows locking, schema-limit
rotation, configurable error inboxes, or a new diagnostics subsystem in this
slice.

## Sources Checked

Spec:

- Store-and-forward client spec:
  `/home/jara/devel/oss/questdb-arrays/docs/qwp/sf-client.md`
  - Options and defaults: lines 128-149.
  - Slot files and `.ack-watermark`: lines 193-329.
  - Segment file format and append recovery: lines 331-452.
  - FSN model: lines 452-495.
  - Durable ACK semantics: lines 573-626.
  - Self-sufficient replay frames: lines 649-670.
  - Reconnect and failover: lines 672-865.
  - Errors, close, and backpressure: lines 865-1014.
  - Recovery, orphan handling, and interoperability: lines 1014-1111.
  - Observability: lines 1120-1138.

Java reference:

- Builder/config surface:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/Sender.java`
  - Initial connect mode: lines 544-564, 2140-2161.
  - WebSocket construction and default dispatcher capacities: lines 1087-1202.
  - `maxSchemasPerConnection`: lines 1667-1679.
  - `errorInboxCapacity`: lines 1871-1878, 2860.
  - `sender_id`: lines 1921-1951.
  - `close_flush_timeout_millis`: lines 2006-2010.
  - reconnect options: lines 2075-2114.
  - orphan options: lines 2184-2223.

- WebSocket sender:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
  - Config passed to sender: lines 459-599.
  - Close drain behavior: lines 892-898, 2206-2235.
  - Initial connect mode handling: lines 2291-2339.
  - Self-sufficient framing: lines 2390-2442.
  - `maxSchemasPerConnection` check: lines 2458-2460.

- Store-and-forward engine:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java`
  - Recovery seeds `ackedFsn` from the lowest recovered segment: lines 167-188.
  - Fresh Java slot still creates `sf-initial.sfa`: line 196.
  - `ackedFsn()` and `acknowledge(long)`: lines 247-261.
  - Clean shutdown removes segment files: lines 373-401, 496-502.

- Segment management:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentManager.java`
  - Generation segment naming and legacy initial-file handling: around lines
    200-245.
  - New spare segment path generation: around line 438.

- Segment ring:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java`
  - `ackedFsn` field: line 86.
  - Recovery contiguity checks: lines 252-274.
  - `ackedFsn()` and `acknowledge(long)`: lines 312-340.
  - Trimming: around line 444.

- WebSocket send loop:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java`
  - Durable OK mode: lines 103-119, 164, 251.
  - Replay starts at `engine.ackedFsn() + 1`: lines 486, 519.
  - OK acknowledgement: line 1139.
  - reject/drop-and-continue handling: lines 1198-1281.
  - durable ACK drain loop: lines 1341-1396.
  - progress dispatch: lines 1428-1436.

- Error dispatcher:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SenderErrorDispatcher.java`
  - Bounded non-blocking error inbox, default 256: lines 39-69.

Rust implementation:

- Config defaults and parser:
  `/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/conf.rs`
  - QWP/WS defaults: lines 119-130, 159-227.
  - `sender_id` validation: lines 152-157.
  - `sf_max_total_bytes` defaulting: lines 233-243.

  `/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress.rs`
  - QWP/WS config parser: lines 527-590.
  - `initial_connect_retry=async` rejected: lines 2018-2037.
  - QWP/WS build rejects non-memory durability: lines 2130-2139.
  - QWP/WS auth supports Basic/Bearer and rejects ECDSA: lines 2143-2155.

- SFA queue and segment files:
  `/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs`
  - Segment format constants and legacy initial file name: lines 42-46.
  - Create/write header: lines 192-241.
  - Append protocol: lines 276-311.
  - Recovery scan and CRC/torn-tail checks: lines 596-719.
  - Initial and generation path helpers: lines 519-525.

  `/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs`
  - Disk queue open/recovery: lines 270-351.
  - `complete_through_fsn`: lines 843-857.
  - Recovery scan: lines 1350-1447.
  - Generation scanner and `.sfa` classifier: lines 1518-1553.
  - Full SFA cleanup removes only `.sfa` files today: lines 1575-1595.

- Driver and ACK/reject behavior:
  `/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws_driver.rs`
  - Driver event/error rings use fixed default capacity 1024: line 65.
  - Response handling and reject guard: lines 291-357.
  - ACK/completion event emission: lines 361-465.
  - Reject-gap protection: lines 604-629.
  - Wire sequence clamping: lines 1788-1814.
  - Durable pending FIFO: lines 2384-2529.
  - Existing event-capacity constructor for tests: lines 998-1005.

- WebSocket connection/reconnect/close:
  `/home/jara/devel/oss/c-questdb-client/questdb-rs/src/ingress/sender/qwp_ws.rs`
  - Queue open and memory-only durability validation: lines 919-960.
  - Connect and upgrade path: lines 1760-1815.
  - Initial connect retry: lines 1931-1998.
  - Close drain behavior: lines 364-402, 2131-2163.

## Validated Assumptions

- The local Java client tree does not contain `AckWatermark.java`. The spec
  describes `.ack-watermark`, but the checked Java implementation still derives
  `ackedFsn` from recovered segment state.

- Java still creates `sf-initial.sfa` for a fresh slot in
  `CursorSendEngine`, but `SegmentManager` already treats `sf-initial.sfa` as
  legacy and uses generation names for managed segments. The Rust reader must
  keep accepting `sf-initial.sfa`; new Rust writers can move to generation
  zero.

- Rust already has the important Java-like ACK/reject model:
  - Queue state is cumulative completion, not per-FSN rejection state.
  - Server reject is surfaced through driver events and sender errors.
  - Durable rejects are held behind prior durable OKs by the durable FIFO.
  - Non-durable rejects must be oldest unresolved, otherwise the driver treats
    the sequence as a protocol violation.

- Rust replay frames are already self-sufficient. `QwpWsReplayEncoder` writes
  schema and symbol dictionaries into each replay frame, matching the spec and
  Java design. Do not redesign replay in this slice.

- Rust close drain is already configurable and intentionally Java-like: timeout
  is reported as an error instead of silently continuing. This diverges from
  the current spec text, which says to log and proceed, but matches the checked
  Java implementation. Do not reopen close semantics in this SFA recovery
  design.

## Design Principles

- Keep the current queue/driver split. Do not introduce a new completion
  manager, ACK service, or replay scheduler.

- Keep the producer hot path allocation-free after queue open. Publishing must
  not allocate for `.ack-watermark` or config compatibility.

- Keep the producer hot path lock-free. `.ack-watermark` writes happen on
  completion, not on publish. The change must not add locks to `try_submit` or
  replay encoding.

- Prefer actual file-backed tests and small fake servers over tests coupled to
  private fields. The interesting behavior is recovery, replay start FSN,
  and documented event/error surface, not the exact helper layout.

- Treat spec-forward work and Java parity separately. If the current Java
  client lacks a feature described by the spec, say so in code comments/tests
  and implement only the smallest compatible behavior.

## Implementation Slice 1: `.ack-watermark`

### Spec Contract

The spec defines a sidecar file named `.ack-watermark` in each sender slot. It
stores the durable cumulative acknowledged FSN so recovery can resume from the
first unresolved frame even when older frames still exist in segment files.

Relevant spec points:

- Slot layout includes `.ack-watermark`: `sf-client.md` lines 247-329.
- The file is 16 bytes:
  - offset 0: magic `0x31574B41` (`AKW1`)
  - offset 4: reserved `0`
  - offset 8: little-endian signed 64-bit acknowledged FSN
- Writers update the mmap when the in-memory cumulative acknowledged FSN
  advances.
- Recovery may use the file only when the stored FSN is plausible for the
  recovered segments. If it is missing or invalid, fall back to segment-derived
  recovery.
- A clean fully drained close removes SFA files. The Rust cleanup path must
  also remove `.ack-watermark`.

### Current Rust Gap

Rust persists only SFA segment files. On restart, recovery derives
`completed_upper` from the first recovered segment, so frames that were already
acknowledged but not yet trimmed can be replayed again.

That behavior is safe for idempotent replay, but it is weaker than the spec and
can create unnecessary replay after process restart. The sidecar is best-effort
for host crashes because the spec does not require fsync; after a host crash,
the implementation may still fall back to segment-derived recovery.
This slice does not change Rust's `sf_durability` support or turn QWP/WebSocket
into a full fsync-backed durability mode.

### Proposed Rust Shape

Add a small private helper for the sidecar. Do not add a public API, trait, or
cross-module abstraction unless the implementation gets materially simpler.

Recommended placement:

- Prefer keeping the helper private inside `qwp_ws_sfa_queue.rs` unless the file
  becomes hard to read.
- If moved out, use a narrow module such as `qwp_ws_sfa_watermark.rs`; do not
  create a generic persistence layer.

Suggested helper responsibilities:

- `open_if_available(slot_dir) -> SfaAckWatermarkOpen`
  - Use a private return struct or tuple. Do not make this a public type or a
    generic sidecar abstraction.
  - Try to open or create `<slot>/.ack-watermark`.
  - Ensure the file is at least 16 bytes before mmap. If an existing file is
    shorter, extend it to 16 bytes. If it is longer, leave it in place and
    read/write only the first 16 bytes.
  - mmap the file when possible.
  - Return two pieces of state:
    - an optional writable handle, present when the file was opened and mapped,
    - an optional recovered FSN, present only when magic, reserved, and FSN
      bounds are valid.
  - Bad or zero magic, bad reserved, and future FSN are invalid only for the
    recovery seed. If the mmap handle exists, the next completion may overwrite
    the file with a valid FSN and stamp magic.
  - Open/map failure means there is no writable handle for this session. Still
    fall back to segment-derived recovery and do not fail queue open only
    because the optional sidecar is unavailable.

- `recover_completed_upper(published_upper, segment_completed_upper) -> u64`
  - Read the stored FSN.
  - Convert inclusive FSN to upper-exclusive completion: `stored_fsn + 1`.
  - Use it only when:
    - magic is valid,
    - reserved field is zero,
    - stored FSN is non-negative,
    - `stored_fsn <= published_fsn`, where `published_fsn` is
      `published_upper - 1` when any frame is present.
      If `published_upper == 0`, any non-negative stored FSN is above the
      recovered frame ceiling and must be ignored.
  - Return `max(segment_completed_upper, stored_fsn + 1)`.
  - If the watermark is missing, invalid, or above `published_fsn`, return
    `segment_completed_upper`. A stale lower watermark is normal after a crash
    where trimming reached disk before the sidecar update; do not diagnose that
    case as corruption.

- `persist_completed_fsn(fsn)`
  - Called only when `complete_through_fsn` advances.
  - Write the inclusive completed FSN at offset 8.
  - On the first valid write for a fresh or previously invalid mapped sidecar,
    write the FSN first, write reserved zero, then stamp magic last. This
    preserves the spec's rule that bad or zero magic means "no usable
    watermark" if the first write is torn.
  - Do not allocate.
  - Do not fsync.
  - Do not write on publish.

Do not add an extra `last_persisted` cache. `complete_through_fsn` already
detects no-op completions before it stores `completed_upper`; persist the
sidecar only from the same branch that advances completion.

Implementation points:

- Store the optional writable watermark handle on `SfaFrameQueue`, not in
  `SfaEngineState`. `SfaEngineState` is mutex-protected, and watermark writes
  must not add a completion-path lock. Memory queues hold no handle.
- In both `SfaFrameQueue::open` and `SfaFrameQueue::open_replay_only`:
  - recover segments as today,
  - compute `published_upper` from recovered `next_fsn`,
  - open/recover `.ack-watermark`,
  - seed `completed_upper` from the valid watermark if it moves completion
    forward safely.
  - use one private recovery helper for both paths. The foreground sender and
    orphan drainer must not diverge.
- In `SfaFrameQueue::complete_through_fsn`:
  - keep the current `Result<(), SfaQueueError>` API,
  - compare completion before/after, as the driver already does for event
    emission,
  - call the existing engine completion logic,
  - persist `.ack-watermark` only when completion actually advanced and a
    writable sidecar handle exists,
  - avoid introducing a new completion result type.
- In `record_all_sfa_cleanup`:
  - also remove `<slot>/.ack-watermark`.
  - Keep `.lock` and `.lock.pid` behavior unchanged.

Failure behavior:

- Missing, invalid, or map-failed `.ack-watermark` is not fatal. Recover from
  segments exactly as a legacy client would.
- Invalid file contents mean "invalid for recovery seed", not necessarily
  "unusable for writes". If the file was mapped successfully, later completion
  may rewrite the FSN and stamp valid magic/reserved bytes.
- If the sidecar contains a future FSN above the recovered published FSN,
  ignore it. Trusting it could skip unacked frames. Do not add a new diagnostics
  surface for this slice.
- After a successful mmap open, normal completion should not have a fallible I/O
  path. Do not change `complete_through_fsn` into a broad fallible API only for
  this sidecar.

Performance constraints:

- No allocations in `try_submit`.
- No locks in `try_submit`.
- No syscalls on publish.
- Watermark writes are completion-path writes only. They may touch an mmap page
  but should not allocate or fsync.

### Behavioral Tests

Use real temporary directories and the real queue. Avoid tests that only assert
private helper methods.

Required tests:

- `ack_watermark_skips_completed_frames_after_restart`
  - Open a disk-backed queue.
  - Publish at least two frames.
  - Complete only FSN 0.
  - Close without draining all frames.
  - Reopen the same slot.
  - Assert the oldest unresolved FSN is 1 and replay starts at FSN 1.

- `ack_watermark_bounds_are_safe`
  - Cover both edge cases in one file-backed test:
    - future watermark above `published_fsn` falls back to segment-derived
      recovery,
    - stale lower watermark below the segment floor starts at the lowest
      surviving FSN.
  - Assert neither case fails queue open.

- `ack_watermark_invalid_contents_are_ignored_and_repaired`
  - Open slots with bad magic and bad reserved bytes.
  - Assert recovery falls back to the segment-derived unresolved FSN and does
    not fail queue open.
  - Complete a later FSN through the queue.
  - Reopen and assert the sidecar is now valid and affects recovery.

- `ack_watermark_applies_to_replay_only_orphan_open`
  - Create a disk slot with completed and unresolved frames plus a valid
    `.ack-watermark`.
  - Open it through `SfaSlotQueue::open_replay_only_existing`.
  - Assert replay starts at the same FSN as foreground recovery.

- `ack_watermark_removed_on_fully_drained_close`
  - Publish and complete all frames.
  - Close the queue.
  - Assert `.ack-watermark` and `.sfa` files are removed, while lock files are
    not part of this cleanup assertion.

- `missing_ack_watermark_keeps_legacy_recovery`
  - Recover a slot with only legacy segment files and no sidecar.
  - Assert behavior matches current recovery.

## Implementation Slice 2: Fresh Segment Naming

### Spec and Java Context

The spec standardizes segment names as `sf-%016x.sfa` and treats
`sf-initial.sfa` as a legacy file accepted by scanners but skipped for max
generation computation.

Relevant spec points:

- Segment filename pattern: `sf-client.md` lines 232-242.
- Interoperability invariant: `sf-client.md` lines 1081-1082.

Java context:

- The current Java sender still creates `sf-initial.sfa` for a fresh slot in
  `CursorSendEngine`.
- Java `SegmentManager` already knows generation names and treats
  `sf-initial.sfa` as legacy.

Rust context:

- Rust creates `sf-initial.sfa` for fresh queues in
  `qwp_ws_sfa_segment.rs`.
- Rust already has `spare_segment_path(slot_dir, generation)` and
  `scan_next_generation`.
- Rust recovery already skips `sf-initial.sfa` for generation scanning.
- Current Java still writes `sf-initial.sfa`, so accepting that name is current
  Java interoperability, not a Rust backward-compatibility migration.

### Proposed Rust Shape

Change only new-slot creation:

- For a fresh disk slot, create `sf-0000000000000000.sfa` as the active
  segment.
- Set next generation to 1 after creation.
- Continue to accept and recover `sf-initial.sfa`.
- Continue to ignore `sf-initial.sfa` when computing the next generation.
- Do not rename existing `sf-initial.sfa` files during recovery.
- Do not introduce a migration step.

This keeps Rust compatible with current Java-created slots and makes new
Rust-created slots match the spec.

### Behavioral Tests

Required tests:

- `fresh_disk_queue_uses_generation_zero_segment_name`
  - Open a new disk queue in a temporary slot.
  - Assert `sf-0000000000000000.sfa` exists.
  - Assert `sf-initial.sfa` is not created.

- `java_current_initial_segment_still_recovers`
  - Create a slot with `sf-initial.sfa`, matching the checked Java writer.
  - Reopen.
  - Assert frames can be replayed and completed.

- `rotation_after_generation_zero_uses_generation_one`
  - Use a small segment size.
  - Publish enough frames to rotate.
  - Assert `sf-0000000000000001.sfa` is promoted into a real segment, not only
    pre-created as a hot spare. Check its header base sequence and replayed
    payload order after reopening.

These filename tests are acceptable because the file naming is a documented
interop contract, not a private implementation detail.

## Deferred Gaps

These are real differences from the spec and/or Java, but they should not be
folded into the first patch.

### Multi-Endpoint Failover

Spec and Java support multi-endpoint connection attempts and failover behavior.
Rust currently parses `addr` as a single host/port and reconnects the same
transport.

Why defer:

- It requires host-list parsing, endpoint state, server role handling, and
  reconnect policy changes.
- A partial implementation would be easy to test poorly.
- It is not necessary for `.ack-watermark` or segment naming.

When implemented, use live behavior tests with multiple local endpoints rather
than tests that only inspect parser output.

### Async Initial Connect

Java has explicit initial connect modes. Rust currently supports synchronous
retry and rejects `initial_connect_retry=async`.

Why defer:

- Async initial connect changes open semantics and API expectations.
- It should be designed with the Rust sender lifecycle, not added as a hidden
  background task.

### Windows Slot Locking

The spec says `flock` on Unix and `LockFileEx` on Windows. Rust currently uses
Unix `flock` and reports unsupported locking on non-Unix.

Why defer:

- This needs Windows-specific implementation and testing.
- It should not block Unix/Linux correctness work.

### `max_schemas_per_connection`

Java supports a connection-scoped schema count limit. Rust rejects
`max_schemas_per_connection`.

Why defer:

- Rust replay frames are already self-sufficient, but schema-count limiting
  interacts with connection lifetime and schema registry behavior.
- Implementing the parser alone would be misleading.

### Backpressure Diagnostics

The spec asks for explicit backpressure diagnostics while waiting for reconnect
or when persistent send failures hold back replay.

Why defer:

- Rust already has sender errors, terminal errors, dropped error accounting,
  and reconnect logic.
- The right user-facing diagnostic should be designed from observed failure
  paths. Do not add a broad state machine only to satisfy wording in the spec.

### `error_inbox_capacity`

The spec, Java, and Rust are not identical here:

- The spec says default 256, minimum `>=16`, overflow drops oldest.
- Java says default 256, accepts `>=1`, and drops the new notification when the
  dispatcher queue is full.
- Rust already uses bounded drop-oldest rings, but the current constructor
  applies one capacity to driver events, stored sender errors, and sender error
  notifications.

Why defer:

- This setting is not required for `.ack-watermark` or segment naming.
- A simple implementation should not let an "error inbox" knob silently change
  progress/event capacity.
- If implemented later, design it as a focused error-surface change with one
  explicit Rust contract. Because QWP/WebSocket is new code, there is no need
  to preserve the current rejected-config behavior.

### Close Drain Timeout

The spec says a positive close-drain timeout logs a warning and proceeds; the
checked Java implementation logs and throws from `close()`. Rust already follows
the Java shape.

Why defer:

- This design is about SFA disk recovery and naming.
- Close semantics should be handled in a separate API/behavior decision, not as
  incidental fallout from watermark work.

## Implementation Order

Recommended order:

1. Implement `.ack-watermark`.
2. Add the `.ack-watermark` behavioral recovery tests.
3. Switch fresh segment naming to generation zero.
4. Update filename/recovery tests.
5. Run focused Rust validation.

Suggested validation:

```bash
cargo fmt --check --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_sfa_queue
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws
cargo check --manifest-path questdb-rs/Cargo.toml --no-default-features --features _sender-qwp-ws,ring-crypto,tls-webpki-certs
```

If the system-test suite is in scope for the implementation owner, add one
QWP/WebSocket restart/replay test that uses the real QuestDB server from:

`/home/jara/devel/oss/questdb-arrays`

Do not make that system test depend on private SFA file internals unless the
test is specifically checking the documented on-disk interoperability contract.

## Non-Goals

- No new public Rust API for ACK watermarks.
- No public config flag for `.ack-watermark`.
- No SFA queue rewrite.
- No generic durable-state abstraction.
- No fsync-backed crash-durability guarantee.
- No mocking-heavy test suite for private queue internals.
- No failover implementation in the same patch.
- No schema-rotation implementation in the same patch.
- No Windows lock implementation in the same patch.
- No `error_inbox_capacity` implementation in the same patch.

## Acceptance Criteria

The first implementation slice is complete when:

- Rust-created fresh disk slots use `sf-0000000000000000.sfa`.
- Rust still recovers legacy `sf-initial.sfa`.
- Rust creates and updates `.ack-watermark` for disk-backed queues.
- Restart recovery uses a valid `.ack-watermark` to skip completed frames still
  present in segment files.
- Missing, invalid, map-failed, or future `.ack-watermark` state does not
  corrupt recovery and does not fail queue open by itself.
- Foreground recovery and replay-only orphan recovery use the same watermark
  floor.
- Fully drained cleanup removes `.ack-watermark` as well as segment files.
- Memory-backed queues are unchanged.
- The publish hot path still performs no allocations and takes no new locks.
- Watermark persistence does not add a `SfaEngineState` lock to completion.
- Tests exercise observable recovery/replay behavior rather than only helper
  functions or private fields.
