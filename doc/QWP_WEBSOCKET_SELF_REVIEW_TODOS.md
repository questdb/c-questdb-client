# QWP/WebSocket self-review TODOs

Date: 2026-04-30

Status: active TODO ledger from the latest Rust QWP/WebSocket self-review.

Parent context:

- `doc/QWP_WEBSOCKET_PIPELINED_FFI.md` - global Rust/FFI design.
- `doc/QWP_WEBSOCKET_VALIDATION_PLAN.md` - validation ladder.
- `doc/QWP_WEBSOCKET_HANDOVER.md` - current implementation state.
- `doc/QWP_WEBSOCKET_JAVA_PARITY_FOLLOWUP_PLAN.md` - broader Java parity
  tracker.

This file is deliberately narrower than the global parity tracker. It captures
the concrete issues found in the latest self-review so the next implementation
turns have a clear queue. It is not a locked recipe: every TODO starts with
assumption validation against current Java source, current Rust source, and, when
observable, a behavioral fixture or real QuestDB server.

## Working Rules

- Keep Java public behavior and disk-format parity as the default target.
- Prefer removing Rust-only complexity over carrying permanent compatibility
  shims.
- Tests should prove externally visible behavior, not the current Rust internal
  layout.
- Do not add durable dead-letter, quarantine, dictionary rollback, or receipt
  sidecar formats unless a fresh Java comparison shows equivalent product
  semantics.
- Keep `sf_durability=flush|append`, `sf_append_deadline_millis`,
  `close_flush_timeout_millis`, and `initial_connect_retry=async` rejected until
  the corresponding behavior exists.

## TODO Tracker

| ID | Status | Priority | Area | TODO | First validation | Completion signal |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | todo | high | Protocol parser | Make Rust QWP/WebSocket response parsing match Java/server framing. | Re-read Java `WebSocketResponse.java`; re-read Rust `qwp_ws_codec.rs`; confirm real server emits `tableCount` for OK and durable ACK frames. | Rust rejects truncated/trailing-garbage OK, durable ACK, and error frames; mock-server helpers emit realistic frames; tests show malformed responses do not advance ACK state. |
| R2 | todo | medium | Rejection observability | Bound rejection state and avoid queue-owned rejection history. | Re-read Java `SenderErrorDispatcher`; inspect which Rust APIs need post-resolution rejection details. | Rejection details live in a bounded driver/event surface; volatile and SFA queues only own publication, retention, completion, and trim state. |
| R3 | todo | medium | ACK/NACK defense | Align ACK/NACK beyond highest sent with Java clamping unless validation finds a stronger Rust reason to fail fast. | Re-read Java `CursorWebSocketSendLoop` ACK/NACK clamp; inspect current Rust error paths and tests. | A too-large ACK/NACK cannot complete unsent frames; behavior matches Java or the divergence is documented with a concrete reason. |
| R4 | done | high | Runner architecture | Decouple high-level publication from blocking transport/reconnect progress. | Re-read Java `CursorSendEngine.appendBlocking`, `CursorWebSocketSendLoop`, and Rust `SyncQwpWsRunner`; decide the smallest globally coherent step toward an explicit store/runner split, not a larger manual-driver detach API. | `Sender::flush()` can publish locally while the runner is reconnecting or doing blocking I/O, subject only to local capacity/backpressure and terminal error checks. |
| R5 | todo | high | Shutdown / close | Make runner shutdown and close/drain behavior explicit and Java-compatible. | Compare Java `close()` / `drainOnClose()` with Rust `Drop`, manual `close_drain`, and rejected `close_flush_timeout_millis`. | Background runner stop is not hostage to the full reconnect budget; explicit close-drain can report timeout/terminal errors before `close_flush_timeout_millis` is accepted. |
| R6 | todo | low | Docs | Remove stale wording and sync docs after each code slice. | Search docs and Rust comments for old async/Tokio/manual-driver wording. | Docs describe current behavior, known gaps, and rejected config values without promising unimplemented features. |

## Slice Notes

### R1: Response Parser Parity

Current Rust parser accepts short response frames that Java rejects. This is a
small correctness fix and should be first.

Expected behavior:

- `OK` requires `status + sequence + tableCount + table entries`.
- `DURABLE_ACK` requires `status + tableCount + table entries`.
- Error responses require exactly `status + sequence + msgLen + msg`.
- Table entries can be parsed and ignored for now, but structure must be
  validated.
- A malformed response is terminal protocol failure and must not advance ACK
  state.

Test shape:

- codec unit tests for minimum valid and malformed OK/durable/error responses,
- one driver or public mock-server test proving truncated OK does not ACK a
  receipt,
- update mock helpers to write tableCount `0` for success frames.

### R2: Bounded Rejection State

The current queues remember rejected FSNs, and the driver remembers full rejected
frames. That duplicates responsibility and can grow without bound.

Preferred design direction:

- queues expose `reject_fsn()` as "complete/drop through rejected FSN";
- queues do not retain rejection history;
- driver/event layer owns bounded rejection details;
- receipt status overlays recent rejection details from the driver, like `Sent`
  is already overlaid from `SendCursor`;
- old rejection details can age out after the bounded observer capacity is
  exceeded.

Open decision: how much rejection history does the manual receipt API promise?
If it needs indefinite post-resolution lookup, that is a new storage contract and
should be challenged before implementation.

### R3: ACK/NACK Clamp

Java clamps malformed high sequence responses to the highest sent wire sequence.
Rust currently treats the same condition as protocol error.

Preferred design direction:

- clamp ACK beyond highest sent to highest sent;
- clamp NACK beyond highest sent to highest sent;
- ignore ACK before any send;
- preserve monotonic completion and never mark unsent frames resolved.

This is defensive parity, not a new feature.

### R4: Runner Decoupling

The high-level runner is useful but still transitional. It is implemented by
layering a background runner around the manual driver, while the Java design has
a cleaner split between `CursorSendEngine` and `CursorWebSocketSendLoop`.
Ordinary socket send/receive I/O and reconnect/backoff now run outside the
publication mutex on the high-level runner path.

First slice completed: replay encoding and symbol dictionary state were moved
out of the runner-owned publisher for the high-level sync sender. Foreground
`flush()` now builds the replay payload before it enters the runner mutex, while
the manual sender keeps the same one-object publication driver for explicit
drive/wait use.

Second slice completed: outbound frames now carry a shared payload handle instead
of borrowing payload bytes from the publication log. This does not by itself
release the high-level runner mutex around socket I/O, but it removes the payload
lifetime blocker for doing so.

Third slice completed: the high-level runner now detaches a send-ready frame or
receive-ready transport from the publication driver, performs the transport
`send_frame()` / `try_poll_response()` call outside the publication mutex, and
reattaches the transport to commit the result. A focused runner test proves a
second local publication can be accepted while the first transport send is
blocked.

Fourth slice completed: detached transport failures now return an owned
reconnect action to the runner. The runner sleeps, retries, and calls
`restart_connection()` outside the publication mutex, then briefly re-enters the
driver to reset wire state on reconnect success or latch terminal failure on
budget exhaustion. A behavioral runner test proves a second local publication
can be accepted while reconnect is blocked.

Current Java primitive findings, validated against current
`java-questdb-client` source:

- Java uses one cursor architecture for both modes: `sfDir == null` is
  malloc-backed memory mode, and `sfDir != null` is mmap-backed
  store-and-forward mode.
- Producer-side `flush()` appends encoded QWP bytes into the cursor engine and
  returns once the frame is locally published. It does not wait for server ACK.
- The I/O loop owns socket, reconnect, wire-sequence mapping, and replay. It
  reads published cursor bytes and sends at most one frame per loop iteration.
- The hot path is mostly lock-free, but not lock-free everywhere: Java uses
  volatile publication cursors and also uses narrow `synchronized` sections for
  sealed-segment snapshots, hot-spare install, close, and manager registration.

Global architecture decision: do not let the high-level threaded path accumulate
a permanent family of `detach_*` operations on the manual driver. The manual
driver can stay monolithic because it is an explicit `&mut self` progress owner.
The product `Sender` runner should converge on Java's ownership model: short
publication-store critical sections, plus runner-owned transport,
wire-sequence mapping, reconnect/backoff, and replay cursor.

Remaining architectural debt: the high-level runner still uses private
`detach_*` / `finish_detached_*` operations on the manual driver. That is an
acceptable transition after R4 because the observable publication boundary is in
place, but it should not become the final architecture. The next runner work
should either make close/backpressure behavior explicit or replace the
transitional detach surface with a clearer store/runner split.

Design candidates to validate:

- extract or introduce a high-level runner core whose owned fields are
  transport, `SendCursor`, reconnect policy, and replay cursor state;
- keep queue/SFA publication, ACK/rejection application, segment trim, and
  terminal observation behind short synchronized store access;
- run reconnect sleep and `restart_connection()` outside the store lock, with
  stop-aware sleeps matching Java's `running` checks;
- commit reconnect success with a short store lock: restore transport, reset
  wire mapping from the first unresolved FSN, and publish `Reconnected`;
- commit reconnect exhaustion or terminal upgrade/auth failure with a short
  store lock: latch terminal error and mark currently published unresolved
  receipts terminal;
- treat a lock-free or lock-light producer publication path as a real target,
  but validate each primitive against Rust ownership, memory ordering, and SFA
  durability before copying Java internals mechanically;
- make append/backpressure wait on local capacity, not on transport progress
  critical sections.

Completion should be judged by observable behavior: `flush()` returns after local
publication, pipelines before ACK, and only blocks for local capacity, terminal
error checks, or documented close/shutdown coordination. In particular, a blocked
reconnect/backoff loop must not prevent another local publication while capacity
remains.

### R5: Shutdown And Close

Rust `Drop` cannot report errors, so Java's `close()` behavior should not be
copied blindly. The product needs an explicit close/drain path before accepting
Java's `close_flush_timeout_millis` key.

Design pressure:

- `Drop` should be best-effort and should not wait out a long reconnect budget.
- Manual `close_drain` already has a result shape; the high-level `Sender` needs
  an explicit surface before close-drain config is accepted.
- Terminal errors observed by the runner should be latched and surfaced by later
  public operations.
- SF users can recover unACKed frames by reopening the same slot; memory users
  cannot.

### R6: Documentation Cleanup

Known stale areas:

- Rust comments that still say "async QWP/WebSocket" for the sync sender path,
- `flush().await` wording under sync config,
- docs that imply local-publication backpressure or close-drain config is already
  implemented,
- docs that mention removed Tokio sender behavior as if it were still live.

Docs should be updated in the same slice as behavior changes, not batched far
behind the code.
