# QWP/WebSocket Simplification Opportunities

Date: 2026-05-13

Status: review handoff. This document records follow-up simplification ideas
found after the SFA send-path cleanup. It is not a replacement for the failover,
SFA, or validation design documents.

Repository: `/home/jara/devel/oss/c-questdb-client`

Java/spec reference repository: `/home/jara/devel/oss/questdb-arrays`

## Goal

Keep the Rust QWP/WebSocket implementation moving toward the Java client shape:
small queue/store primitives, protocol policy in the driver/connect layer, and
test-only machinery out of the production API surface.

The target is deletion-focused simplification. Do not add a new abstraction
unless it removes more complexity than it introduces, or unless the spec cannot
be represented cleanly with the current Rust pieces.

The hot path constraints remain:

- steady-state publish/send/ACK processing must not add heap allocations;
- steady-state publish/send/ACK processing must not add locks;
- SFA outbound selection must keep borrowing mapped payload bytes for the
  synchronous send call;
- diagnostics, fake transports, and rich test inspection must stay off the
  production steady-state path.

## Sources Checked

Rust:

- [qwp_ws_queue.rs](../questdb-rs/src/ingress/sender/qwp_ws_queue.rs)
  defines `OutboundFrame` over `SfaMappedPayload`.
- [qwp_ws_driver.rs](../questdb-rs/src/ingress/sender/qwp_ws_driver.rs)
  owns `ManualDriverPrototype`, `QwpWsSendCore`, test transports, send cursor,
  durable ACK tracking, and driver events.
- [qwp_ws_sfa_queue.rs](../questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs)
  owns SFA queue publication/completion state and exposes `len()` /
  `bytes_used()` helpers.
- [qwp_ws_sfa_slot.rs](../questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs)
  wraps `SfaFrameQueue` with slot locking and forwards the publication-log
  surface.
- [qwp_ws_sfa_segment.rs](../questdb-rs/src/ingress/sender/qwp_ws_sfa_segment.rs)
  owns SFA segment files and mapped segment state.
- [qwp_ws.rs](../questdb-rs/src/ingress/sender/qwp_ws.rs)
  owns the sync/background QWP/WebSocket publisher and initial-connect paths.
- [qwp_ws_codec.rs](../questdb-rs/src/ingress/sender/qwp_ws_codec.rs)
  validates WebSocket upgrade responses and QWP response payloads.
- [qwp_ws_orphan.rs](../questdb-rs/src/ingress/sender/qwp_ws_orphan.rs)
  owns orphan-slot discovery and draining.

Java:

- [QwpWebSocketSender.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java)
  owns endpoint walking, upgrade classification, durable-ACK capability checks,
  and foreground/orphan connection factory behavior.
- [CursorWebSocketSendLoop.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java)
  owns the shared connect/reconnect loop and replay after reconnect.
- [CursorSendEngine.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java)
  owns the Java cursor engine setup.
- [SlotLock.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SlotLock.java)
  documents the Java slot-lock contract, including Windows `LockFileEx`.
- [QwpVersionMismatchException.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpVersionMismatchException.java)
  classifies upgrade-time QWP version mismatch as an outage-budget failure.

Specs:

- [sf-client.md](../../questdb-arrays/docs/qwp/sf-client.md)
  defines QWP/WebSocket SFA config, durable ACK negotiation, initial-connect
  retry, reconnect-loop behavior, and orphan adoption.
- [failover.md](../../questdb-arrays/docs/qwp/failover.md)
  defines endpoint error classification, role/topology rejects, transient
  upgrade failures, backoff, and failover defaults.

Related local docs:

- [QWP_WEBSOCKET_JAVA_LIKE_SFA_SIMPLIFICATION.md](QWP_WEBSOCKET_JAVA_LIKE_SFA_SIMPLIFICATION.md)
- [QWP_WEBSOCKET_FAILOVER_ALIGNMENT_DESIGN.md](QWP_WEBSOCKET_FAILOVER_ALIGNMENT_DESIGN.md)
- [QWP_WEBSOCKET_WINDOWS_SFA_SUPPORT.md](QWP_WEBSOCKET_WINDOWS_SFA_SUPPORT.md)
- [QWP_WEBSOCKET_SELF_REVIEW_TODOS.md](QWP_WEBSOCKET_SELF_REVIEW_TODOS.md)

## Working Rules

- Prefer removing Rust-only concepts over wrapping them.
- Keep Java behavior as the reference when Rust and docs disagree.
- Validate every behavior-affecting change against the current spec and Java
  source before implementation.
- Tests should verify behavior visible through the driver/sender or on-disk SFA
  contract, not private layout details.
- Do not use broad refactors as a way to land small simplifications.
- Do not widen public API surface for in-progress QWP/WebSocket internals.

## Recommended Queue

| ID | Status | Priority | Area | Recommendation | Why now |
| --- | --- | --- | --- | --- | --- |
| S1 | done | high | Payload model | Inline `PendingPayload` into `OutboundFrame`. | Smallest deletion; removes a wrapper that no longer abstracts anything. |
| S2 | done | high | Test surface | Move fake transports behind `#[cfg(test)]` and remove fake defaults from production generics. | Keeps production driver shape honest and Java-like. |
| S3 | done | high | Test surface | Remove the test-only `sent_frames()` hook from the production transport trait. | Prevents test inspection from becoming production API. |
| S4 | todo | medium | Queue diagnostics | Delete or cfg-test misleading queue counters, especially constant-zero `bytes_used()`. | Avoids stale diagnostics and broad `allow(dead_code)`. |
| S5 | todo | medium | Feature hygiene | Replace file-level `#![allow(dead_code)]` with targeted cfgs/removals after S1-S4. | Makes stale Rust-only surface visible again. |
| C1 | todo | high | Upgrade classification | Validate `X-QWP-Version` before durable-ACK echo. | Spec/Java alignment; avoids misclassifying future-version peers. |
| C2 | todo | high | Connect/retry | Unify connect/retry plumbing, including orphan initial connect. | Spec alignment; current Java only partially shares this orphan behavior. |
| C3 | todo | low | Windows coverage | Broaden orphan locked-slot tests to Windows. | Verifies the already-implemented cross-platform lock contract. |

`S*` items are simplification-only. `C*` items are correctness/spec-alignment
cleanups that also simplify policy placement.

## S1: Inline `PendingPayload`

Previous shape:

- `PendingPayload` is a one-field wrapper around `SfaMappedPayload`.
- `OutboundFrame` stores `PendingPayload`.
- `OutboundFrame::with_view()` delegates to the wrapper to expose borrowed bytes.
- `OutboundFrame` is a short-lived synchronous-send object: the runner selects
  it, immediately calls transport `send_frame()`, and then drops it before later
  storage cleanup work.

Implemented shape:

- Store `SfaMappedPayload` directly in `OutboundFrame`.
- Keep `OutboundFrame::with_view()` as the external borrowed-view helper if it
  still improves call sites.
- Remove `PendingPayload` entirely from this synchronous send path.
- Do not add a `Mapped | Owned` payload enum for `OutboundFrame` unless the
  production contract changes to return payload objects that can outlive the
  send call.

Rationale:

The earlier retained-payload API has been removed from the production send path.
The remaining wrapper no longer protects a real choice between owned and mapped
payloads for outbound sending. Keeping it suggests a future abstraction that the
current code does not need.

Windows note:

`QWP_WEBSOCKET_WINDOWS_SFA_SUPPORT.md` previously called for owned Windows
replay payloads because a retained payload object could keep a mapped segment
alive after trim, making `remove_file()` fail on Windows. That concern applies
to any future long-lived replay-payload API. It does not apply to the current
`OutboundFrame` contract because the frame is consumed synchronously by
`send_frame()` and is dropped before storage maintenance performs cleanup.

Performance requirement:

This must remain a pure type/layout cleanup. The send path must still borrow
mapped bytes for the synchronous WebSocket send call and must not copy payload
bytes into an owned buffer. Do not reintroduce per-frame owned payload copies on
Windows for this synchronous send path.

Validation:

- `cargo fmt --check --manifest-path questdb-rs/Cargo.toml`
- `cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_sfa_queue`
- `cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_driver`
- Run the ignored zero-allocation send-cursor/SFA test if it still exists after
  the cleanup.
- Re-check that no production API returns an outbound payload that can be held
  beyond the synchronous `send_frame()` call. If such an API is introduced, it
  needs a separate Windows-owned payload design.

## S2/S3: Gate Fake Transports And Test Inspection

Intent:

Remove fake transport machinery from the production driver shape while keeping
the deterministic tests that make the driver state machine cheap to exercise.
This is a production-surface cleanup, not a test-quality downgrade.

Status:

Implemented. The remaining fake transport fixture is test-only.

Previous shape:

- `ManualDriverPrototype<Q = SfaFrameQueue, T = FakeOrderedServer>` and
  `QwpWsSendCore<T = FakeOrderedServer>` default production generic parameters
  to a fake transport.
- `qwp_ws_driver` is compiled by `_sender-qwp-ws`, so these fakes are
  production-compiled when QWP/WebSocket support is enabled.
- `FakeServerResponse`, `FakeOrderedServer`, `FakeSendResult`,
  `DelayedPollAckServer`, `fake_transport_error()`, and similar helpers live in
  the production module instead of behind `#[cfg(test)]`.
- `ManualDriverTransport` exposes `sent_frames()` even though only tests need
  it.
- Driver wrappers forward `sent_frames()` through production-visible methods.
- `QwpWsPublicationDriver::sent_frames()` is already `#[cfg(test)]`, but it
  still depends on the production driver hook.

Previous production code points:

- [qwp_ws_driver.rs](../questdb-rs/src/ingress/sender/qwp_ws_driver.rs)
  contains the default fake generic parameters, `ManualDriverTransport`,
  fake server types, and driver-level `sent_frames()` forwarding.
- [qwp_ws_publisher.rs](../questdb-rs/src/ingress/sender/qwp_ws_publisher.rs)
  exposes a test-only publication-driver `sent_frames()` wrapper that still
  relies on the production hook below it.
- [qwp_ws_sfa_queue.rs](../questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs)
  has sibling tests that import `FakeOrderedServer`.
- [qwp_ws.rs](../questdb-rs/src/ingress/sender/qwp_ws.rs)
  has runner tests with custom in-memory transports that currently implement
  `sent_frames()` only because the production trait offers it.

Validated scope:

- The dependency is concentrated. Most uses are in `qwp_ws_driver` tests, with
  small sibling-test use from `qwp_ws_sfa_queue` and `qwp_ws`.
- No FFI/C++/Python code depends on these fake driver helpers; those tests use
  public QWP/WebSocket APIs or loopback/mock servers.
- The deterministic fake transport is useful for driver state-machine tests:
  ACK/reject ordering, durable-ACK interleavings, event rings, receipt
  accounting, reconnect outcomes, and backpressure.
- The fake transport should not shape production generics, production trait
  methods, or production constructors.

Java comparison:

- Java production `Sender` exposes real transports only; QWP/WebSocket creates a
  real `WebSocketClient` through the factory, then connects and upgrades.
- Java QWP/WebSocket connect/retry/failover tests primarily use loopback fake
  servers and raw socket fixtures, not a production-exposed in-memory fake
  transport.
- Java still has targeted test hooks and stub factories where unit tests are
  cheaper, so deleting every Rust unit fake would be overcorrection.
- Java memory mode is production queue backing, not fake transport. Do not treat
  Rust memory SFA queues as test fake infrastructure.

Implemented boundary:

Production-visible:

- `ManualDriverTransport` describes only what the real driver needs from a
  transport: poll, optional durable-ACK keepalive, synchronous frame send, and
  reconnect.
- `QwpWsSendCore<T>` and `ManualDriverPrototype<Q, T>` require their transport
  type explicitly. No production type default names a fake.
- Real production constructors still take a generic `T:
  ManualDriverTransport` because Rust tests and internal runners use that
  extension point, but the default type and trait contract are
  real-transport-shaped.

Test-only:

- `FakeOrderedServer`, `FakeSendResult`, `FakeServerResponse`, and fake
  transport errors.
- `DelayedPollAckServer` is local to `qwp_ws_driver` tests.
- Any retained sent-frame log used to prove a fake observed a frame.
- Any helper constructor that creates a memory queue plus `FakeOrderedServer`.

Implemented shape:

- Fake transports and fake send-result enums are under `#[cfg(test)]`.
- Fake default type parameters are removed from production structs.
- `sent_frames()` is removed from `ManualDriverTransport`.
- `sent_frames()` forwarding is removed from `QwpWsSendCore`,
  `ManualDriverPrototype`, and `QwpWsPublicationDriver`.
- Deterministic driver tests remain, but test inspection is test-owned:
  - prefer `DriveOutcome::Sent(SentFrame)` when the drive operation already
    returns the sent frame;
  - prefer `DriverEvent::Sent { fsn, wire_seq }` for cross-module tests that
    only need FSN/wire-sequence evidence;
  - use direct fake/test-transport inspection only inside local driver tests
    when outcome/event assertions do not express the behavior, and only through
    test-owned helpers.
- Avoid adding a broad test-only inspection trait unless implementation churn
  becomes materially worse without it.

Test migration rules:

- If the test only needs to prove a send happened, assert
  `DriveOutcome::Sent(SentFrame { .. })`.
- If the test needs to prove the driver published an observable notification,
  assert `DriverEvent::Sent { fsn, wire_seq }`.
- If the test needs to prove a receipt moved, assert `receipt_status()`,
  `acked_fsn()`, `published_fsn()`, or the relevant sender error.
- If the test needs frame payload bytes, prefer a loopback/WebSocket-level test
  unless the behavior is purely driver-internal.
- Do not add a production `SentFrameRecorder`, `TransportObserver`, or
  inspection side channel for this slice.
- Do not move public sender, FFI, TLS, auth, handshake, close-frame, or timeout
  behavior onto in-memory fakes. Those belong in loopback/system tests.

Rationale:

Java's production send loop does not expose fake transport inspection as part of
its real transport contract. Rust should keep the same boundary: production
driver code sends frames and handles responses; tests own their fake server
state.

The goal is not to remove deterministic unit tests. It is to stop fake
transports from being a production default, production trait obligation, or
production constructor shape.

Tradeoff:

This may touch many tests because existing tests rely on default generic
inference and `driver.sent_frames()`. The change is still worth doing because it
removes test machinery from the production surface without altering sender
behavior.

Reflection after implementation:

The first S2/S3 slice is a real simplification, but mostly at the API boundary:
production types no longer default to `FakeOrderedServer`, and
`ManualDriverTransport` no longer requires a test inspection hook. It is not a
large code-size reduction because deterministic driver tests still need a cheap
in-memory transport.

Keeping `FakeOrderedServer` as a module-level `#[cfg(test)]` fixture is the
right compromise for now. It is used by local driver tests and small sibling
tests that need deterministic ACK/reject/reconnect behavior without sockets.
Moving it into production again would be wrong; deleting it outright would cause
test churn without making the production contract simpler.

Possible later simplification:

- If S4/S5 expose more stale test-only surface, consider replacing
  `FakeOrderedServer` with a smaller local `TestTransport` inside
  `qwp_ws_driver` tests and moving sibling tests fully to `DriveOutcome` /
  `DriverEvent` assertions.
- Do this only if it removes meaningful duplication. Do not add a new
  `SentFrameRecorder`, observer trait, or shared test-inspection abstraction to
  replace `FakeOrderedServer`; that would recreate the leak in a different
  shape.

Risk controls:

- Keep the first implementation slice mechanical. Do not change ACK/reject,
  durable-ACK, reconnect, SFA completion, or close-drain behavior.
- Prefer changing one assertion style at a time. The easiest sequence is:
  compile after removing fake defaults, then compile after removing
  `sent_frames()`, then move fake types behind `#[cfg(test)]`.
- If a test becomes hard to express without `sent_frames()`, classify it before
  adding new helpers:
  - driver state-machine test: use `DriveOutcome` or `DriverEvent`;
  - transport/framing test: move to loopback;
  - payload-byte test: keep only if it is proving queue/storage replay, and use
    an existing queue payload accessor where possible.
- A small local helper inside `#[cfg(test)] mod tests` is acceptable. A new
  production trait method or generic observer is not.

Implemented order:

1. Remove fake default type parameters from `ManualDriverPrototype` and
   `QwpWsSendCore`; make test helper return types explicit where needed.
2. Replace `driver.sent_frames()` assertions with `DriveOutcome::Sent`,
   `DriverEvent::Sent`, or direct local fake inspection.
3. Remove `sent_frames()` from `ManualDriverTransport`, `QwpWsSendCore`,
   `ManualDriverPrototype`, and `QwpWsPublicationDriver`.
4. Move `FakeOrderedServer`, `FakeSendResult`, `FakeServerResponse`, and
   fake-only helpers behind `#[cfg(test)]` at module scope. Keep them outside
   `mod tests` if sibling test modules still need to import them.
5. Move `DelayedPollAckServer` directly into `qwp_ws_driver` tests.
6. Keep `from_queue_with_reconnect_policy` production-visible because real
   background/manual open paths and orphan drainers use it.

Expected non-changes:

- `ManualDriverTransport` remains the internal driver transport trait.
- `DriveOutcome::Sent` and `DriverEvent::Sent` remain production-visible inside
  the crate because they are normal driver outputs, not test inspection hooks.
- Memory SFA queues remain production-capable queue backing. They should not be
  cfg-tested as fake infrastructure.
- Loopback tests remain responsible for protocol-visible behavior.

Prefer loopback tests over fake-driver tests for public sender behavior,
WebSocket framing/control frames, handshake, role/auth headers, TLS, socket
timeouts, close/reconnect timing, FFI behavior, and benchmarks. Existing
loopback tests already cover much of that surface; do not migrate deterministic
driver state-machine cases to sockets just for purity.

Validation:

- Focus on driver tests first:
  `cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_driver`
- Then run the broader QWP/WebSocket lib filter:
  `cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws`
- Run the hidden-feature check to ensure cfg boundaries are correct:
  `cargo check --manifest-path questdb-rs/Cargo.toml --no-default-features --features _sender-qwp-ws,ring-crypto,tls-webpki-certs`

## S4: Remove Misleading Queue Counters

Current shape:

- `SfaFrameQueue::len()` is production-visible but appears test-oriented.
- `SfaFrameQueue::bytes_used()` returns a constant zero.

Target shape:

- Delete `bytes_used()` unless production diagnostics need it now.
- If diagnostics do need it, implement the real value instead of keeping a
  placeholder.
- Move `len()` behind `#[cfg(test)]` if it is only used by tests.

Rationale:

A constant-zero byte counter is worse than no counter because it looks like an
implemented production metric. The SFA queue should expose only real state that
callers use.

Validation:

- Search all call sites with `rg "bytes_used|\\.len\\("` before editing.
- Prefer deleting dead call sites over replacing them with another wrapper.
- Run SFA queue tests after the cleanup.

## S5: Remove Broad Dead-Code Suppression

Current shape:

Several QWP/WebSocket files still use file-level `#![allow(dead_code)]`,
including driver, queue, SFA queue, SFA slot, and SFA segment modules.

Target shape:

- After S1-S4, remove file-level `allow(dead_code)`.
- Use targeted `#[cfg(test)]`, feature cfg, or local `allow(dead_code)` only
  where the item is intentionally compiled but not always reachable.
- Treat newly exposed warnings as a cleanup queue, not as noise to suppress.

Rationale:

Broad suppression hides the exact Rust-only surface we are trying to remove. It
also makes feature-gating mistakes harder to see.

Validation:

- `cargo check --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib`
- `cargo check --manifest-path questdb-rs/Cargo.toml --no-default-features --features _sender-qwp-ws,ring-crypto,tls-webpki-certs`

## C1: Validate QWP Version Before Durable-ACK Echo

Current Rust risk:

`validate_upgrade_response()` checks the durable-ACK echo before parsing and
validating `X-QWP-Version`. If a future-version server does not echo durable
ACK, Rust can classify the failure as durable-ACK mismatch before noticing the
version mismatch.

Spec/Java context:

- `failover.md` classifies upgrade-time QWP version mismatch as transient and
  per-endpoint because rolling upgrades can leave some nodes compatible and
  others incompatible.
- Java classifies upgrade failures during `QwpWebSocketSender.buildAndConnect()`
  and checks durable-ACK capability only after a compatible WebSocket client has
  upgraded successfully.
- Java's `QwpVersionMismatchException` documents the version-mismatch category.

Target shape:

- Parse and validate `X-QWP-Version` first.
- Only after the version is compatible, require durable-ACK echo when
  `request_durable_ack=true`.
- Keep durable-ACK mismatch terminal for a compatible 101 response that simply
  did not enable requested durable ACK.
- Preserve the current Rust classification split: invalid or unsupported
  `X-QWP-Version` stays on the transport/transient path (`SocketError` today),
  while missing durable-ACK echo after a compatible 101 remains the terminal
  durable-ACK mismatch path (`ProtocolVersionError` today).
- Rename any test that currently implies this is a generic protocol-version
  path if it is really durable-ACK mismatch-specific.

Rationale:

This is not just cleanup. It is a small ordering fix that keeps Rust's upgrade
classification aligned with the spec and Java's connect behavior.

Validation:

- Add/update codec tests for future-version plus missing durable-ACK echo.
- Ensure future-version remains a version/transport-classified failure, not a
  durable-ACK mismatch and not a terminal protocol-version error.
- Run QWP/WebSocket codec and driver tests.

## C2: Unify Connect/Retry Plumbing

Current Rust shape:

- Sync initial connect, async initial connect, reconnect, and orphan drainer
  connect paths carry separate retry behavior.
- The orphan drainer currently opens the SFA slot and then calls
  `BlockingQwpWsTransport::connect(...)` once. On connect error it marks the
  orphan `.failed`.

Spec/Java context:

- `sf-client.md` reconnect pseudocode uses one loop for initial-connect retry,
  reconnect, host walking, backoff, and replay.
- Java's `CursorWebSocketSendLoop.connectLoop(...)` is shared by reconnect and
  async initial connect.
- Java's `QwpWebSocketSender.buildAndConnect(...)` centralizes endpoint walking
  and upgrade classification.
- Java orphan drainers reuse the sender connection factory, but current
  `BackgroundDrainer` only retries durable-ACK mismatch during orphan initial
  connect. Other initial-connect exceptions still mark the slot `.failed`.
  Therefore broad orphan transient-connect retry is a spec-alignment target, not
  current Java orphan-drainer parity.

Target shape:

- Extract one internal helper for:
  - round walk;
  - per-endpoint connect/upgrade classification;
  - role-reject versus transport failure handling;
  - outage budget and backoff;
  - stop/sleep callback differences between foreground, background, and orphan
    callers.
- Preserve caller-owned `previousIdx` / active-endpoint context for mid-stream
  reconnect.
- Decide explicitly whether Rust is matching current Java or advancing to the
  broader spec target:
  - Java-parity scope: retry durable-ACK mismatch specially for orphan initial
    connect, but keep other orphan initial-connect errors terminal for the
    drainer.
  - Spec-alignment scope: reuse the helper for orphan drainers so a transient
    first connect failure consumes the configured outage budget before the slot
    is marked `.failed`.

Rationale:

This removes duplicated retry policy and makes it harder for future failover
fixes to land in one path but not another. For orphan initial connect, be clear
whether the implementation is matching current Java's narrower behavior or
intentionally moving Rust to the broader spec-aligned retry contract.

Tradeoff:

This is the largest item in this document. Do not combine it with S1-S5. If the
chosen scope is broad orphan retry, start with a failing or behavior-pinning
test around orphan transient connect failure before refactoring.

Validation:

- Existing failover and reconnect unit tests.
- Orphan drainer tests covering transient connect failure versus terminal
  give-up.
- A real-server/system test only if the helper changes externally visible
  initial-connect or reconnect behavior.

## C3: Broaden Orphan Lock Tests To Windows

Current shape:

- Slot locking has Windows support via `LockFileEx`.
- Slot-lock tests already use `any(unix, windows)`.
- Some orphan locked-slot tests remain Unix-only.

Spec/Java context:

- `sf-client.md` requires Windows clients to participate in the mandatory
  `LockFileEx` lock contract.
- Java's `SlotLock` documents `flock` / `LockFileEx` as the cross-platform slot
  lock model.

Target shape:

- Change orphan locked-slot helper/test cfgs from Unix-only to
  `any(unix, windows)` where the helper does not depend on Unix-only APIs.
- Keep platform-specific implementation details inside the lock helper, not the
  orphan test.

Rationale:

This is test simplification by contract: orphan code should not care whether the
slot lock is implemented by POSIX `flock` or Windows `LockFileEx`.

Validation:

- Linux: run the orphan and slot-lock test filters.
- Windows: rely on CI or a Windows local run; if the test is timing-sensitive,
  fix the helper rather than weakening the contract.

## Deferred Ideas

### D1: Do Not Collapse `SfaSlotQueue` Into `SfaFrameQueue` Now

`SfaSlotQueue` is mostly a lock-owning wrapper around `SfaFrameQueue`, so a
collapse would remove forwarding. Defer it anyway.

Reason:

The wrapper keeps slot-lock lifetime separate from frame queue mechanics. Moving
lock ownership into `SfaFrameQueue` would touch queue ownership and recovery
paths for limited immediate value.

Revisit only if a later queue-ownership refactor already touches both files.

### D2: Defer SFA Open Constructor Deduplication

`SfaFrameQueue::open`, `open_memory`, and `open_replay_only` repeat setup work.
Java's cursor engine has a more unified construction path.

Reason to defer:

Open/recovery code has high blast radius. A helper may be useful later, but only
when a behavior change or bug fix already requires touching recovery setup.

### D3: Do Not Split Durable ACK Tracking Yet

The durable ACK tracker could become a tiny module with table-driven tests, but
the current driver-level tests protect important Java/spec parity behavior:
queued OKs, rejected placeholders, durable watermarks, and FIFO-head drain.

Reason to defer:

Moving the tracker now risks replacing useful behavioral coverage with tests
that are too coupled to the implementation shape.

### D4: Do Not Merge Driver Send Cursor And SFA Segment Cursor

The two cursors represent different domains:

- the driver cursor maps replayed frames to connection-local wire sequences and
  in-flight state;
- the SFA cursor maps FSNs to segment offsets and mapped bytes.

Reason to defer:

Merging them would make the code look smaller but would mix wire-protocol state
with storage-position state. That is not Java-like and is not simpler.

## Remaining Implementation Order

Recommended order:

1. S2/S3: gate fake transports and remove production `sent_frames()`.
2. S4: remove or cfg-test dead/misleading queue counters.
3. S5: remove broad dead-code suppressions exposed by the previous steps.
4. C1: fix upgrade validation ordering.
5. C3: broaden orphan lock tests.
6. C2: unify connect/retry plumbing as its own slice.

Do not combine C2 with the smaller deletion cleanups. The connect/retry helper
is a policy refactor and deserves its own tests and review.

## Completion Criteria

The simplification work is successful when:

- production QWP/WebSocket structs do not default to fake transports;
- production transport traits do not expose test inspection hooks;
- `OutboundFrame` borrows mapped SFA payloads without an unnecessary wrapper
  (done by S1);
- no production SFA queue metric returns a placeholder value;
- broad dead-code suppressions are gone or reduced to justified local cases;
- upgrade-time version mismatch is classified before durable-ACK mismatch;
- orphan drainers use the same retry policy family as the foreground sender;
- no steady-state publish/send/ACK path gains allocations or locks.

Minimum validation for the full queue:

```text
cargo fmt --check --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_sfa_queue
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws_orphan
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws
cargo check --manifest-path questdb-rs/Cargo.toml --no-default-features --features _sender-qwp-ws,ring-crypto,tls-webpki-certs
```
