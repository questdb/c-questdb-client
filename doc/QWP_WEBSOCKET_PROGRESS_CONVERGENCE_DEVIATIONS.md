# QWP/WebSocket Progress Convergence Deviations Journal

This file records deliberate deviations from
`doc/QWP_WEBSOCKET_PROGRESS_CONVERGENCE_DESIGN.md` discovered while validating
the proposal against live source. Each entry should explain the source-backed
reason, the implementation choice, and whether follow-up work remains.

## 2026-05-14: Connected Parts Builder Excludes Async Initial Connect

The design asks for one `open_qwp_ws_parts(...)` path that captures the
negotiated QWP protocol version once and returns encoder, producer, store, send
core, and orphan candidates.

Source validation found that this is only correct for already-connected
construction paths. With `initial_connect_retry=async`, background mode opens
the SFA queue, starts a pending-connect runner, and connects on the background
thread later. At handler construction time there is no negotiated version
available. The current public contract also rejects `initial_connect_retry=async`
for manual progress, so this exception is background-only.

Decision: phase 1 uses a connected-parts builder for synchronous connected
background/manual paths only. Async initial connect remains a separate
pending-connect construction path and keeps the existing version-1 encoder
assumption while the live protocol max remains 1.

Follow-up: if QWP/WebSocket supports a negotiated version above 1, async initial
connect must gain an explicit post-connect encoder-version update or defer
publication until version negotiation is visible to the sender-facing encoder.

## 2026-05-14: Background Runner Keeps Lock-Split Scheduling

The design target is for background and manual progress to call the same
`QwpWsSendCore`-based progress path. The first migration of manual progress
into `QwpWsSendCore` uses a `&mut QwpWsPublicationStore` entry point, which is
correct for manual mode because the caller owns progress and publication on the
same sender object.

Source validation found that directly reusing that entry point in the
background runner would hold the shared publication-store mutex across
transport send/receive and reconnect work. Existing runner tests require
publication to remain possible while transport send or reconnect is blocked, so
that would regress a deliberate background-mode concurrency property.

Decision: background mode keeps the lock-split scheduler path. The runner
extracts/finishes store state while holding the mutex, but performs transport
send/receive, reconnect sleeps, durable keepalive I/O, and storage maintenance
file work outside the shared-store lock. The per-phase protocol operations are
still delegated through `QwpWsSendCore` primitives, so this is a scheduler
shape difference rather than a separate protocol implementation.

Follow-up: if a later design step introduces an owned background store or a
non-blocking reconnect state machine, the runner can collapse closer to the
manual `drive_once` shape without regressing publication concurrency or stop
responsiveness.

## 2026-05-14: SFA Send-Cursor Mechanics Use a Detached SFA View

The design says wire send cursors and durable acknowledgment trackers belong to
`QwpWsSendCore`, and that `SfaFrameQueue` should be the queue/log view used by
progress code rather than the owner of progress-local resend policy.

Source validation found that the stateful resend cursor now lives under
`QwpWsSendCore` via `SendCursor`, including the optional `SfaSendCursor`.
`SfaFrameQueue` no longer owns the runner's outbound progress lookup directly.
Both production SFA queue types now provide a required detached
`SfaProgressView`, and the background runner hands that view to
`QwpWsSendCore::next_outbound_sfa_frame` instead of falling back to the shared
publication-store mutex.

Decision: keep low-level segment lookup and mapped-payload cursor advancement
inside the SFA storage module, but attach it to `SfaProgressView` rather than to
the shared publication store. `QwpWsSendCore` owns the cursor state,
restart/reset policy, resend decisions, and ACK/durable-ACK application.

Follow-up: if a non-SFA publication log is introduced, it must provide the same
detached progress contract explicitly; there is no background-runner fallback to
the shared store.

## 2026-05-14: Server Reject Handling Remains a Cold Diagnostic Path

The Step 9 wording originally grouped ACK and reject application together as hot
response progress. Source validation found that ordinary ACK, `DurableOk`, and
`DurableAck` can advance through `QwpWsSendCore` plus `SfaProgressView`, but
server rejection handling also updates rejected-frame history, sender-error
diagnostic log, last server error state, and sometimes terminal state.

Decision: keep background reject handling on the store-backed `finish_response`
path and make the runner branch explicit for `TransportResponse::Reject`.
This preserves the Java-like hot/cold boundary without introducing a deferred
reject-diagnostic API just to avoid a cold-path lock.

Follow-up: if rejects need to be optimized later, split only the proven hot
completion effect from diagnostic materialization. Do not add a new generic
response-hook or scheduler callback family.

## 2026-05-14: Manual Close Does Not Wait for Orphan Drainers

The design says orphan drainers are best-effort post-drop work and that the
orphan scheduler owns grace, stop, detach, and abandon policy. Source validation
found that background mode has an `OrphanDrainerPool` with bounded close
semantics, while manual mode has `ManualOrphanDrainers` that are progressed only
when the caller invokes manual progress.

Decision: keep manual `close_drain` scoped to the foreground sender's own slot.
It does not wait for sibling orphan slots. Making manual close drain orphan work
would turn unrelated best-effort recovery into foreground close policy and could
block close on a stalled orphan transport. Manual callers that want orphan
progress can continue calling manual progress before close.

Follow-up: if a public contract later promises that manual close also advances
orphan cleanup, add an explicit bounded manual orphan-close policy rather than
folding stop or sleep hooks into `QwpWsSendCore`.

## 2026-05-14: Segment-Boundary Optimization Is Deferred

The updated Step 9 guidance says Java lock-free parity does not mean all segment
topology must be lock-free. Java keeps volatile-style hot facts for active
payload visibility and published/acked watermarks, but still synchronizes
sealed-list transitions, sealed-list lookups, trim/cleanup, hot-spare install,
close, recovery, and reconnect positioning.

Source validation found the current Rust background hot path already follows
that boundary. Publication uses the detached `SfaProducer` and writes payload
bytes before publishing active-segment and queue watermarks through atomics.
Background next-frame lookup, send-result completion, ACK application,
`DurableOk`, `DurableAck`, and non-terminal published/acked reads use
`QwpWsSendCore` plus `SfaProgressView`, not the shared
`QwpWsPublicationStore` mutex.

The remaining locks are either cold store locks or storage-local topology locks:
`QwpWsPublicationStore` is still used for terminal/error diagnostics, sender
error polling, rejected-frame history, close, storage maintenance handoff,
reconnect success bookkeeping, and opportunistic cold-event flushing. The
`SfaEngine` mutex still protects active/sealed/hot-spare topology: active
rotation, finding a segment by FSN, moving to the next segment, trim/cleanup,
hot-spare install, close, recovery diagnostics, and slot lifetime. Those map to
Java's synchronized topology/lifecycle paths rather than Java's volatile hot
facts.

Decision: do not add a lock-free segment topology layer, epoch scheme, or new
cursor abstraction for label 6. Treat Segment-boundary optimization as
deferred/optional until source evidence shows a broad shared-store lock or
storage-local topology lock blocking healthy progress in a way the current
`SfaProgressView` split cannot handle.

Follow-up: if profiling or a failing behavioral/concurrency test shows
segment-boundary contention on a healthy path, optimize the concrete SFA
topology operation directly. Do not generalize beyond the active/sealed/hot-spare
boundary that is actually blocking progress.
