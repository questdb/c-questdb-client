# QWP/WebSocket Java parity follow-up plan

Date: 2026-04-30

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
- volatile queue when `sf_dir` is unset,
- Java-style `.sfa` slot queue when `sf_dir` is set,
- `initial_connect_retry=sync` as an alias for current blocking startup retry,
- explicit rejection for unsupported `initial_connect_retry=async`,
- explicit rejection for Java's `close_flush_timeout_millis` key until Rust has
  a public close path that can report drain failures,
- Java-style `.lock` ownership plus diagnostic `.lock.pid` holder sidecar,
- Java-compatible public sync handling for frame-local schema/write rejection
  policy,
- no background orphan drainer implementation,
- no Java-style `initial_connect_retry=async` behavior.

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
| J3 | deferred | Adapter / lifecycle boundary | Initial-connect mode design | Java's `ASYNC` returns before any socket exists; Rust sync sender currently connects before `build()` returns and `flush()` waits for ACK. | Before resuming, trace Rust open/flush semantics and compare to Java async flush semantics. | Not implemented now. Java-style background initial connect is deferred to a future explicit adapter design; the sync sender must not silently start a background connector. |
| J4 | todo | Driver / error surface | Reconnect budget exhaustion classification | Java distinguishes never-connected config-likely failures from connection-lost transient failures. | Re-read Java `hasEverConnected` handling; inspect Rust driver/transport reconnect state and current error messages. | Rust either reports equivalent classification or records why the current public error surface should stay simpler for now. |
| J5 | done | Public close / FFI boundary | Close-drain and terminal close semantics | Java now treats close-drain timeout and latched terminal errors as observable close failures. | Compare Java `close()` with Rust public sync close, FFI `close_drain`, and existing `CloseOutcome`; decide which public surfaces need parity. | Rust public sync `Sender` keeps fast-drop semantics and rejects `close_flush_timeout_millis` explicitly; real drain reporting remains an explicit QWPWS close-drain API to wire with the FFI/manual sender. |
| J6 | todo | Operational recovery / adapter layer | Orphan drainer scope check | Java now has real background orphan drainers and `.failed` sentinel behavior; Rust intentionally does not. | Re-read Java orphan scanner/drainer code and Rust SFA recovery scope; validate whether this is needed before public release. | Decision recorded; no partial drainer implementation without a real recovery scenario and behavioral test. |
| J7 | todo | Documentation architecture | Docs sync after code slices | Handover, validation plan, and design proposal should not contradict the implemented contract. | Cross-read changed docs plus `QWP_WEBSOCKET_HANDOVER.md`, `QWP_WEBSOCKET_VALIDATION_PLAN.md`, and `QWP_WEBSOCKET_PIPELINED_FFI.md`. | Docs name current behavior, known gaps, and validation evidence without promising unimplemented Java features. |
| J8 | done | Public sync error surface | Frame-local server rejection behavior | Java treats schema/write rejections as drop-and-continue and exposes the server message. Rust should report the rejection without making the sender terminal. | Re-read Java `CursorWebSocketSendLoop` and `SenderError`; inspect Rust codec/driver/public flush path and existing coverage. | Public mock-server test rejects the first flush with schema mismatch, verifies the server message and error category, then successfully flushes a second frame on the same sender. |

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
- `flush()` publishes and waits for the server outcome,
- no background thread is started implicitly.

Do not paper over that mismatch. Until Rust has a real implementation for the
async lifecycle, `initial_connect_retry=async` must be rejected clearly. It must
not be accepted as a no-op, as an alias for `sync`, or as a promise that the
sync sender cannot keep.

We do not have to implement Java-style async initial connect now. The current
architecture should keep the sync sender honest: it should not silently start a
background connector. When this behavior is needed, design it as an explicit
threaded/async adapter over the same queue/driver core, with explicit lifecycle
and error/event semantics.

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

Decision: Rust should not mimic Java's `close()` shape on the public sync
`Sender`.

Java owns row buffers inside the sender, has a background I/O loop, and can make
`close()` flush user-thread state, wait for ACKs, and throw on timeout or
latched terminal errors. Rust's current public sync API is different: buffers are
external, `flush()` waits for the submitted batch's server outcome, and dropping
the sender has no return channel for drain failures. Blocking and failing from
drop would be surprising and would still not flush an external `Buffer`.

Therefore:

- `close_flush_timeout_millis` must not be accepted as a no-op.
- The current sync sender rejects that Java config key with an explicit message
  telling users to flush before dropping the sender.
- The explicit `close_drain(timeout)` / `close_fast()` shape remains the right
  Rust/FFI model for future pipelined QWPWS APIs where submitted receipts can be
  pending after a call returns.

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
- Rust: current sync `qwpws` connects during `build()` and `flush()` waits for
  the submitted frame's server outcome; accepting `async` without changing that
  lifecycle would be misleading.
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
- Architecture: the global design keeps the core threadless and makes
  background behavior an explicit adapter concern.
- Rust: the sync sender is a blocking convenience surface; hidden background
  connector ownership would make build, flush, close, and FFI error timing less
  clear.
- Validation: design-level decision; no code validation needed until the
  adapter is planned.
Result:
- deferred: do not implement Java-style `ASYNC` initial connect in the sync
  sender now. Revisit only as part of an explicit threaded/async adapter design.

2026-04-30 - J8 - validate public sync frame-local rejection behavior
Evidence:
- Java: `CursorWebSocketSendLoop` classifies schema mismatch and write errors as
  drop-and-continue server rejections and exposes structured `SenderError`
  details including category, policy, raw status, server message, and affected
  sequence range.
- Rust: `qwp_ws_codec.rs` maps schema mismatch/write statuses to non-terminal
  transport responses; `qwp_ws_driver.rs` resolves the affected receipt and
  stores the server error; `flush_qwp_ws()` returns that server-derived error for
  the rejected flush.
- Validation: `cargo test qwp_ws_schema_rejection_surfaces_error_and_sender_continues`;
  `cargo test qwp_ws_server_error_response_is_surfaced`; `cargo test raw_qwp`.
Result:
- done for the public sync sender surface. Future pipelined FFI work still needs
  per-receipt diagnostic accessors so rejection details do not depend on the
  event ring or a single last-error slot.

2026-04-30 - J5 - keep sync close explicit and reject Java close timeout key
Evidence:
- Java: `QwpWebSocketSender.close()` flushes sender-owned pending rows, drains up
  to `closeFlushTimeoutMillis`, and rethrows close-drain or latched terminal
  errors after cleanup. Java config exposes `close_flush_timeout_millis` for that
  behavior.
- Rust: public sync `Sender` uses external buffers and each `flush()` waits for
  the submitted frame's server outcome. Dropping `Sender` has no error return
  channel. The manual driver already has `close_drain_steps()` / `CloseOutcome`
  for the future QWPWS API shape.
- Validation: `cargo test qwpws_store_and_forward_config_rejects_invalid_java_keys`;
  `cargo test qwpws_store_and_forward_config_is_websocket_only`.
Result:
- done for the public sync config surface: `close_flush_timeout_millis` is now a
  known unsupported Java key, not a silently ignored no-op. Real close-drain
  behavior remains an explicit QWPWS FFI/manual sender follow-up.

## Open Questions

- What should the eventual explicit threaded/async adapter API look like if we
  decide to support Java-style async initial connect?
- Should reconnect budget classification become structured state now, or wait
  for the public event/error API?
- Is orphan draining required for the first public SFA release, or can it remain
  a documented Java gap while single-slot recovery ships?
- Should wrappers expose a Java-style close convenience after the explicit
  QWPWS close-drain API is wired?
