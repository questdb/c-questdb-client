# QWP/WebSocket self-review TODOs

Date: 2026-05-13

Status: current review ledger. Items R1-R5 have been revalidated against the
current Rust code, the Java client/server code, and `docs/qwp/sf-client.md`.
Only R6 and R7 remain active TODOs.

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
- Keep `sf_durability=flush|append` rejected. The Java spec still reserves
  those modes and both Java and Rust fail fast instead of silently downgrading to
  memory durability.
- Do not treat `sf_append_deadline_millis`, `close_flush_timeout_millis`, or
  `initial_connect_retry=async` as blanket rejected keys. Current Rust parses and
  wires those settings. `initial_connect_retry=async` is valid for background
  QWP/WebSocket progress and is rejected only with manual progress, where there
  is no background runner to own the pending connect lifecycle.

## TODO Tracker

| ID | Status | Priority | Area | TODO | First validation | Completion signal |
| --- | --- | --- | --- | --- | --- | --- |
| R1 | done | high | Protocol parser | Make Rust QWP/WebSocket response parsing match Java/server framing. | Re-read Java `WebSocketResponse.java`; re-read Rust `qwp_ws_codec.rs`; confirm real server emits `tableCount` for OK and durable ACK frames. | Rust now rejects truncated/trailing-garbage OK, durable ACK, and error frames. Decode failures are retryable transport failures per the spec; they do not advance ACK state. |
| R2 | done | medium | Rejection observability | Bound rejection state and avoid queue-owned rejection history. | Re-read Java `SenderErrorDispatcher`; inspect which Rust APIs need post-resolution rejection details. | Rejection details live in bounded driver/event surfaces. Volatile and SFA queues own publication, retention, completion, and trim state, not rejection history. |
| R3 | done | medium | ACK/NACK defense | Align ACK/NACK beyond highest sent with Java clamping unless validation finds a stronger Rust reason to fail fast. | Re-read Java `CursorWebSocketSendLoop` ACK/NACK clamp; inspect current Rust error paths and tests. | Too-large ACK/NACK responses are clamped to the highest sent wire sequence and cannot complete unsent frames. |
| R4 | done | high | Runner architecture | Decouple high-level publication from blocking transport/reconnect progress. | Re-read Java `CursorSendEngine.appendBlocking`, `CursorWebSocketSendLoop`, and Rust `SyncQwpWsRunner`; decide the smallest globally coherent step toward an explicit store/runner split, not a larger manual-driver detach API. | `Sender::flush()` can publish locally while the runner is reconnecting or doing blocking I/O, subject only to local capacity/backpressure and terminal error checks. |
| R5 | done | high | Shutdown / close | Make runner shutdown and close/drain behavior explicit and Java-compatible for the Rust public API shape. | Compare Java `close()` / `drainOnClose()` with Rust `Drop`, manual `close_drain`, and `close_flush_timeout_millis`. | Rust exposes explicit fallible `Sender::close_drain()` bounded by `close_flush_timeout_millis`; zero and negative timeout values skip the wait. `Drop` remains best-effort. |
| R6 | todo | low | Docs | Remove stale wording and sync docs after each code slice. | Search docs and Rust comments for old async/Tokio/manual-driver wording. | Docs describe current behavior, known gaps, and rejected config values without promising unimplemented features. |
| R7 | todo | medium | Feature gates | Split or re-gate QWP/WebSocket codec modules so unreachable upgrade validation is not compiled in `_sender-qwp-ws`-only builds. | Inspect `Cargo.toml` feature relationships and current `sender.rs` cfg gates; verify which helpers are frame/status codec versus sync transport upgrade code. | `cargo check --no-default-features --features _sender-qwp-ws,ring-crypto,tls-webpki-certs --lib` does not need local `allow(dead_code)` for sync-only upgrade helpers, and the cfg boundary matches actual reachability. |

## Slice Notes

### R1: Response Parser Parity

Current state: done.

Validated source:

- Java `WebSocketResponse.isStructurallyValid()` rejects short OK,
  durable-ACK, and error frames, validates table entries, and requires exact
  error-frame length.
- The QuestDB server writes `tableCount` for OK frames at payload offset 9 and
  durable ACK frames at payload offset 1.
- The spec defines generic frame-decode errors as transient/retry-budget
  failures, not immediate terminal failures.
- Rust `qwp_ws_codec` now validates table-entry structure and rejects trailing
  bytes for OK, durable ACK, and error frames.
- Rust driver decode wraps parser failures as retryable transport failures, so
  malformed responses do not advance ACK state.

Validation already covered:

- codec unit tests for minimum valid and malformed OK/durable/error responses;
- driver tests that parser failures are retryable and do not resolve receipts;
- mock helpers that emit success frames with realistic `tableCount` fields.

### R2: Bounded Rejection State

Current state: done.

Validated source:

- Java `SenderErrorDispatcher.offer()` is bounded and drops with a counter when
  its inbox is full.
- Rust `QwpWsPublicationStore` owns bounded event and sender-error rings plus a
  bounded `rejected_frames` side surface.
- `record_rejected_frame()` pushes sender errors and drops the oldest rejected
  frame when bounded observer capacity is exceeded.
- The volatile and SFA queue APIs do not own durable rejection history; they own
  publication, completion, and trim state.

The manual receipt API exposes recent rejection details through bounded driver
state. It does not promise indefinite post-resolution lookup.

### R3: ACK/NACK Clamp

Current state: done.

Validated source:

- The Java client clamps ACK and NACK wire sequences above the highest sent
  sequence and ignores pre-send ACK/rejection watermark advancement.
- Rust `SendCursor` now applies the same clamp for ACK and rejection mapping.
- Regression tests cover future ACK and future rejection responses.

This is defensive parity, not a new feature.

### R4: Runner Decoupling

Current state: done.

Current Rust structure:

- `QwpWsPublicationStore` owns publication, lifecycle, completion, events,
  bounded sender errors, durable ACK state, and bounded rejection details.
- `QwpWsSendCore` owns connection-local transport, `SendCursor`, and reconnect
  policy. It does not own publication state.
- The threaded runner takes short store locks to publish, select outbound work,
  and commit outcomes. Socket send/receive and reconnect/backoff progress run
  outside those locks.
- There are no remaining `detach_*` / `finish_detached_*` helper operations in
  the current QWP/WebSocket Rust sources.

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

Completion should be judged by observable behavior: `flush()` returns after local
publication, pipelines before ACK, and only blocks for local capacity, terminal
error checks, or documented close/shutdown coordination. In particular, a blocked
reconnect/backoff loop must not prevent another local publication while capacity
remains.

### R5: Shutdown And Close

Current state: done for the Rust public API shape.

Validated source:

- The Java spec makes `close_flush_timeout_millis` a bounded close wait, with
  `0` and `-1` skipping the server-ACK wait.
- Rust now exposes explicit fallible `Sender::close_drain()` for QWP/WebSocket
  senders.
- The background runner close path begins closing, wakes blocked publishers, and
  waits only until the configured close-drain timeout expires.
- The manual close path drives ready work until all published receipts resolve,
  terminal failure is observed, or the configured timeout expires.
- `close_flush_timeout_millis` is parsed, stored, and passed to both background
  and manual close-drain paths. Tests cover `-1` skipping the wait.

Design decision:

- `Drop` should be best-effort and should not wait out a long reconnect budget.
- `close_drain()` is the explicit surface that reports timeout and terminal
  errors.
- Terminal errors observed by the runner should be latched and surfaced by later
  public operations.
- SF users can recover unACKed frames by reopening the same slot; memory users
  cannot.

### R6: Documentation Cleanup

Known stale areas:

- docs that still say `initial_connect_retry=async` is unsupported or rejected;
- docs that still say `sf_append_deadline_millis` is recognized and rejected
  instead of accepted and wired into append/backpressure waiting;
- docs that still say `close_flush_timeout_millis` is rejected instead of
  accepted and wired into `Sender::close_drain()`;
- docs that imply local-publication backpressure or close-drain config is not yet
  implemented;
- docs that mention removed Tokio sender behavior as if it were still live.

Docs should be updated in the same slice as behavior changes, not batched far
behind the code.

Current examples found stale during the 2026-05-13 review:

- `doc/QWP_WEBSOCKET_PIPELINED_FFI.md`
- `doc/QWP_WEBSOCKET_HANDOVER.md`
- `doc/QWP_WEBSOCKET_JAVA_PARITY_FOLLOWUP_PLAN.md`

### R7: QWP/WebSocket Feature Gates

Current feature split:

- `qwp_ws_codec` is compiled under `_sender-qwp-ws`.
- the sync WebSocket sender module `qwp_ws`, which calls HTTP upgrade
  validation, is compiled only under `sync-sender-qwp-ws`.
- `sync-sender-qwp-ws` implies `_sender-qwp-ws`, but `_sender-qwp-ws` alone does
  not imply `sync-sender-qwp-ws`.

That means `_sender-qwp-ws`-only builds compile shared codec code but not the
sync transport caller, making HTTP upgrade validation unreachable in that build
matrix. The 2026-05-13 `_sender-qwp-ws`-only check passed, but still emitted 69
dead-code warnings, including sync-only HTTP upgrade helpers that are compiled
through `qwp_ws_codec`.

Preferred design direction:

- keep pure QWP frame/status parsing under `_sender-qwp-ws`;
- move or `cfg(feature = "sync-sender-qwp-ws")` HTTP upgrade request/response
  helpers that are only used by the sync transport;
- avoid broad `allow(dead_code)` annotations for helpers that are unreachable
  only because of feature-gating shape;
- validate with the `_sender-qwp-ws` no-default feature check and the full
  `sync-sender-qwp-ws` QWP/WebSocket test filter.
