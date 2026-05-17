# QWP/WebSocket Progress Convergence Design

Status: proposal, not implemented.

This document captures the simplification direction for QWP/WebSocket progress:
make background progress and manual progress use the same concurrency
protocol. The intended difference between the two modes is who owns the driving
thread, not which publication and transport path the code takes.

## Reference Sources

The protocol specifications are the normative contract for wire behavior,
on-disk state, failover, error classification, and progress semantics:

- [QWP Store-and-Forward Client Specification](../../questdb-arrays/docs/qwp/sf-client.md)
- [QWP Client Failover Spec](../../questdb-arrays/docs/qwp/failover.md)

The Java client is the reference implementation for ambiguous implementation
questions and for the desired hot-path shape:

- [Java QWP client package](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/)
- [Java cursor/SF package](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/)

Key Java files to compare against when the Rust design is unclear:

- `QwpWebSocketSender.java`
- `CursorSendEngine.java`
- `CursorWebSocketSendLoop.java`
- `SegmentRing.java`
- `SegmentManager.java`
- `MmapSegment.java`

If the Rust design, Java client, and protocol specs appear to disagree, do not
guess. Resolve the disagreement against the specs, use the Java client as the
implementation reference when the specs are silent, and update this document
before coding.

## Goal

Today the Rust QWP/WebSocket sender has two substantially different paths:

- background progress, where the sender thread submits payloads and a
  library-owned runner thread drives transport progress;
- manual progress, where the caller alternates between sender operations and
  explicit progress calls.

That split makes the implementation harder to reason about because publication,
transport progress, error propagation, close/drain behavior, and store-and-forward
state are shaped differently in the two modes.

The simplification goal is to converge on one semantic model using the existing
Rust vocabulary:

- `QwpWsReplayEncoder` and `SfaProducer` publish encoded payloads;
- `QwpWsSendCore` owns transport progress, resend cursors, durable
  acknowledgments, reconnect state, and server response handling;
- `QwpWsPublicationStore`, `SfaFrameQueue`, and `SfaEngine` connect publication
  and progress with explicit ownership and ordering rules;
- background mode schedules `QwpWsSendCore` through `SyncQwpWsRunner` on a
  library-owned thread;
- manual mode lets caller code own scheduling and call the same
  `QwpWsSendCore` mechanics explicitly.

In this model, manual mode is no longer special because it is single-threaded.
It is special only because the application supplies the progress executor.

## Required Mode Contract

The public API must keep exactly two progress modes:

- background mode: the client starts and owns a background progress
  thread that drives WebSocket I/O, ACKs, reconnect, replay, and storage
  maintenance;
- manual mode: the client does not start a background progress thread. Progress
  happens only when caller code invokes an explicit progress API.

Rust names this mode `QwpWsProgress::Background`, and the configuration spelling
is `background`. This document uses "background" consistently; it does not
propose a third public mode or a config rename.

Manual mode may still use the same internal `QwpWsSendCore` mechanics as
background mode. The constraint is scheduler ownership: in manual mode, the
library must not call `thread::spawn` or otherwise create a client-owned
progress thread for that sender.

If a future manual API exposes a separate progress handle, moving that handle to
a different thread must remain caller-owned. The caller may create that thread;
the client must not create it implicitly.

## Non-Goals

This design is not a lock-free-first rewrite. The first step is to make the
manual and background modes share one protocol.

The final state should still be lock-free in every path where the Java client is
lock-free. Temporary locks are acceptable during migration, and locks are
acceptable on cold paths where Java also synchronizes, such as rotation, sealed
segment snapshots, trim/cleanup, spare installation, close, and reconnect.

This design does not require public API changes as the first step. The existing
manual API can remain while its internals are replaced by the unified model.

This design does not introduce a third Java-style segment-manager thread. The
Rust simplification target remains two logical roles: publication and
`QwpWsSendCore` progress.

This design does not change durable acknowledgment, reconnect, server reject, or
close/drain protocol semantics. QWP-specific internal error types, payload
shape, and notification timing may change where that makes the sender simpler
and more coherent, but status-byte categories, default DROP/HALT policy, WebSocket
close routing, and failover classification remain bound to the reference specs.

This design does not collapse manual and background progress into one
public mode.

## Compatibility Policy

Only the end-user API and documented sender behavior need compatibility.

The compatibility boundary is:

- `Sender` public methods;
- public builder/configuration surface, including `QwpWsProgress::Background`
  and `QwpWsProgress::Manual`;
- documented behavior of background and manual progress;
- released non-QWP behavior.

QWP/WebSocket has no released client version yet. Do not preserve current
QWP-specific error categories, exact messages, notification timing, or internal
error payload shapes just for compatibility. Keep the `Sender` API shape stable,
but simplify QWP error behavior where the current split forces extra concepts or
mode-specific paths.

Internal Rust types, module boundaries, test helpers, private constructors, and
private progress/store APIs are not compatibility surfaces.

Do not keep compatibility shims, legacy internal paths, or duplicate old/new
implementations after a slice is complete. A temporary adapter is acceptable only
as scaffolding inside a slice; the completed slice should leave one canonical
path for the behavior it touched.

If a new shared publication or progress path replaces an old mode-specific path,
delete the old path in the same slice. Do not preserve it only to keep old
internal tests compiling.

## Java Lock-Free Baseline

The Java cursor client establishes the target boundary for Rust's final state.

`SegmentRing` documents the core contract: one producer thread appends, one I/O
thread reads and acknowledges, and the segment manager handles spare provisioning
and trim work. Its cross-thread publication state is `publishedFsn`, `ackedFsn`,
`active`, and `hotSpare`, all carried by `volatile` fields.

The Java steady-state lock-free paths are:

- append to the active segment: `MmapSegment.tryAppend` writes the frame bytes,
  increments the single-writer frame count, and publishes the new cursor with a
  final volatile store;
- publish a frame sequence number: `SegmentRing.appendOrFsn` assigns `nextSeq`
  and writes `publishedFsn` after the payload is visible;
- read publication progress: `SegmentRing.publishedFsn` is a volatile read;
- read ACK progress: `SegmentRing.ackedFsn` is a volatile read;
- apply an ACK: `SegmentRing.acknowledge` clamps to `publishedFsn` and advances
  `ackedFsn` with a volatile single-writer store;
- I/O loop steady-state send/receive: `CursorWebSocketSendLoop` polls published
  payloads, sends frames, receives ACKs, and calls `engine.acknowledge` without a
  shared publication mutex.

The Java paths that still synchronize are not the steady-state target:

- active-segment rotation adds the old active segment to the sealed list;
- sealed-list snapshots and next-sealed lookups coordinate with rotation;
- trim/cleanup drains acknowledged sealed segments;
- hot-spare installation coordinates with close;
- close and recovery/reconnect paths may take locks.

Java also keeps scheduling concerns outside the cursor engine. The send loop owns
its `running` flag, wakeup, reconnect sleep, and shutdown latch. Background
drainers own their own stop request and pool grace/detach policy. The cursor
engine and ring do not carry generic reconnect hooks for those scheduler cases.

Rust should aim for the same boundary after the protocol convergence is done:
lock-free publication, lock-free progress watermarks, lock-free ACK application,
and no shared publication mutex in the healthy send/receive loop. Locks should
remain only where they represent real cold-path ownership or lifecycle
coordination. This does not require a fully lock-free segment-topology
implementation: Java's active segment and watermarks are hot, while sealed-list
mutation, sealed-list lookup, hot-spare install, trim, close, recovery, and
reconnect positioning are topology/lifecycle boundaries that may synchronize.
Step 9 translates this Java hot/cold boundary into Rust implementation guidance.

## Current Divergence

The current implementation has separate state shapes for the two modes.
Background progress keeps an encoder and runner in the background
handler state. Manual progress keeps a publication driver in the manual handler
state.

In current Rust terms:

- `SyncQwpWsHandlerState` owns the background encoder and `SyncQwpWsRunner`;
- `ManualQwpWsHandlerState` owns a `QwpWsPublicationDriver`;
- `flush_qwp_ws` and `flush_qwp_ws_manual` submit through different paths;
- manual progress calls into `qwp_ws_drive_once` through the sender state;
- `SfaFrameQueue` still carries runner-local send cursor state, even though
  cursor policy belongs to `QwpWsSendCore`.

That causes the two paths to grow their own answers to the same questions:

- how encoded payloads become published frames;
- which object owns the send cursor;
- which object owns durable acknowledgment tracking;
- where close/drain timeout handling lives;
- which thread observes terminal errors;
- where SFA slot lock lifetime is maintained;
- which path handles reconnect and resend.

The result is not just implementation duplication. It is a protocol split.
The same sender state transition can be expressed through different objects and
different thread assumptions depending on the selected progress mode.

## Design Guidance

This refactor should reduce the number of core concepts. Do not introduce a new
layer unless it replaces or deletes an existing one.

The primary implementation goal is simple code. The implementer should prefer
existing Rust names and ownership boundaries, delete obsolete mode-specific
paths, and avoid new abstractions unless there is a strong reason.

A new helper, type, trait, or state machine is justified only when it does at
least one of the following:

- deletes an older concept in the same slice;
- removes real duplication between manual and background paths;
- makes a protocol invariant from the reference specs explicit;
- matches a proven Java client boundary more closely than the current Rust code.

It is not enough for an abstraction to make a local patch look tidy. If the
choice is between a small direct change using `QwpWsSendCore`,
`QwpWsPublicationStore`, `SfaProducer`, `SfaFrameQueue`, or `SfaEngine` and a
new layer whose only job is delegation, use the direct change.

Scheduling policy is not a `QwpWsSendCore` abstraction. Do not add parallel
`*_with_reconnect_hooks`, generic stop/sleep callback variants, or other
shadow progress methods just to serve one close or orphan-drain path. If a
hook-based API is truly needed, it must become the single progress API used by
all schedulers and must delete more complexity than it adds. Otherwise, keep
stop flags, sleep interruption, thread ownership, close wait policy, and
orphan-pool shutdown in the scheduler layer that owns them.

When an implementation detail is uncertain, check the Java client before
inventing Rust-only behavior. When protocol behavior is uncertain, check the
specification documents first.

The target shape should be close to Java's conceptual shape, but expressed in
Rust terms:

```text
Sender-facing publication (`QwpWsReplayEncoder`, `SfaProducer`)
  -> shared publication/log state
     (`QwpWsPublicationStore`, `SfaFrameQueue`, `SfaEngine`)
  -> shared send/progress core (`QwpWsSendCore`)
  -> transport/server responses
```

Background and manual mode should build the same internal pieces.
The mode choice should only decide how `QwpWsSendCore` progress is scheduled.

### Current Concepts to Retire or Narrow

The following current Rust concepts should not all survive as separate core
concepts:

- `QwpWsPublicationDriver` currently combines replay encoding with manual driver
  operations. Target: split this into `QwpWsReplayEncoder`/`SfaProducer`
  publication and `QwpWsSendCore` progress. It should disappear or become a
  short-lived construction helper.
- `ManualDriverPrototype` is not really manual-only: background mode
  constructs it and then tears it into runner parts. Target: move the real
  progress behavior into `QwpWsSendCore` and remove the manual-specific wrapper
  once the common parts builder exists.
- `SyncQwpWsRunnerCore` is effectively the background progress loop.
  Target: make this a thin `QwpWsSendCore` scheduler helper, so manual mode calls
  the same progress implementation.
- `QwpWsPublicationStore` currently bundles queue state, lifecycle, terminal
  errors, event rings, sender-error rings, rejected-frame history, and durable
  ACK tracking. Target: shrink it into the shared publication/lifecycle boundary.
  Runner-local policy should move to `QwpWsSendCore`.
- `SfaFrameQueue` should represent the SFA/log view. It should not own
  progress-local cursor policy such as `SfaSendCursor`.

The concepts that should remain clear are:

- `QwpWsReplayEncoder`: publication encoding scratch and symbol dictionary.
- `SfaProducer`: publication append handle.
- `SfaEngine`: shared SFA/log engine, similar in role to Java's `SegmentRing`.
- `SfaFrameQueue`: queue/log view over `SfaEngine`, without progress-local cursor
  policy.
- `QwpWsPublicationStore`: shared lifecycle, publication status, terminal error,
  sender-error notification state, backpressure, and slot-lifetime state.
- `QwpWsSendCore`: transport, send cursor, reconnect policy, durable ACK tracker,
  server-response application, and storage maintenance progress.
- `SyncQwpWsRunner`: scheduler only, owning a thread and a `QwpWsSendCore`-based
  progress loop.
- `ManualQwpWsHandlerState`: scheduler entry point only, owning or referencing
  a `QwpWsSendCore`-based progress path without spawning a thread.

### Test Policy

The current test suite is allowed to shrink during this refactor. Tests are
useful only if they protect behavior or a load-bearing invariant.

Tests are evidence, not the compatibility contract. The contract is the public
`Sender` API, documented sender behavior, and the QWP specification documents.
If a test asserts a private shape or an obsolete mode split, change or delete
the test instead of preserving the old implementation around it.

Keep or add tests for:

- public `Sender` behavior;
- cross-mode behavior where background and manual should produce the
  same result;
- manual-mode scheduling behavior: publication alone must not make background
  progress, and progress must happen only through caller-driven APIs;
- background scheduling behavior: progress continues without caller
  `drive_once` calls;
- SFA/log invariants that are not obvious from public sender behavior, such as
  publish-before-visible ordering, ACK monotonicity, recovery, rotation, trim,
  and slot locking;
- public FFI/C/C++/Python behavior only when the Rust change can affect those
  surfaces.

Delete or rewrite tests that:

- assert private helper names, private struct shapes, or exact internal call
  sequencing;
- exist only to protect `QwpWsPublicationDriver`, `ManualDriverPrototype`,
  `SyncQwpWsRunnerCore`, or other concepts being removed;
- duplicate the same scenario separately for old manual and background
  internals when one cross-mode behavioral test would cover it;
- require keeping a legacy path or compatibility shim alive;
- test implementation details more narrowly than the behavior they are meant to
  protect.

High-level behavioral tests deserve more care, but they are not untouchable. If
such a test encodes behavior that is not required by the QWP specs, or that is a
side effect of today's split implementation, the implementer may change it. The
replacement must still prove spec-compliant behavior through observable sender,
transport, ACK, failover, or SFA/log outcomes.

Decision: use a small cross-mode behavioral matrix. Do not parameterize every
existing manual/background test, and do not preserve duplicate tests that only
pin the old internal split. The matrix should exercise public `Sender` behavior
through both `QwpWsProgress::Background` and `QwpWsProgress::Manual`, with a
small mode adapter that waits for background progress or calls `drive_once` for
manual progress.

Good shared scenarios are:

- publish and observe ACK/completion;
- DROP rejection advances completion and reports the sender error;
- HALT rejection records terminal state and rejects later publications;
- reconnect replays unacknowledged frames;
- durable ACK mode completes only after durable confirmation;
- close/drain waits for the same completion condition in both modes.

Keep separate mode-specific tests only for intentional scheduler differences:

- manual mode does not progress unless caller code drives it;
- background mode progresses without caller `drive_once` calls;
- `initial_connect_retry=async` remains background-only;
- orphan-drainer tests may stay mode-specific where manual and background have
  genuinely different scheduling or shutdown ownership.

Avoid "fake tests" that merely assert a wrapper delegates to another wrapper.
If a test would still pass when the protocol is broken, remove it or rewrite it
around observable, spec-relevant behavior.

### Target Internal Object Graph

Names are current Rust names where possible. The important part is ownership;
some field names below are still illustrative.

```text
Sender-facing publication path
    encoder: QwpWsReplayEncoder
    producer/shared append handle: SfaProducer
    lifecycle/error status handles needed by sender calls

QwpWsSendCore<T>
    transport: T
    send cursor
    durable ACK tracker
    reconnect policy/state
    storage-maintenance progress
    response application

QwpWsPublicationStore
    queue/log view: SfaFrameQueue over SfaEngine
    lifecycle
    terminal error latch
    sender error/event notification state
    backpressure notification state
    slot-lock lifetime owner
```

The handler states should become simple mode shells:

```text
Background:
    SyncQwpWsHandlerState { encoder, runner, orphan_pool }
    SyncQwpWsRunner { store, producer, send_core, stop, thread }

Manual:
    ManualQwpWsHandlerState {
        encoder,
        producer,
        store,
        send_core,
        orphan_drainers,
    }
```

The manual handler may initially keep the existing `&mut Sender` API. A later
split manual handle can move `QwpWsSendCore` progress out to caller-owned code,
but that is an API step, not a prerequisite for internal convergence.

### Construction Rule

There should be one core builder path that creates the encoder, producer,
publication store, send core, and orphan-drainer candidates. Avoid one builder
for background and a different builder for manual.

Conceptually:

```text
open_qwp_ws_parts(...) -> QwpWsParts {
    encoder,
    producer,
    store,
    send_core,
    orphan_candidates,
}
```

Then mode selection wraps those parts:

```text
background:
    runner = SyncQwpWsRunner::start(parts.store, parts.producer, parts.send_core)
    handler = SyncQwpWsHandlerState { encoder: parts.encoder, runner, ... }

manual:
    handler = ManualQwpWsHandlerState {
        encoder: parts.encoder,
        producer: parts.producer,
        store: parts.store,
        send_core: parts.send_core,
        ...
    }
```

The background wrapper may spawn. The manual wrapper must not spawn.

Pending initial connect, reconnect, durable ACK mode, and SFA configuration
should be configured in the common parts. Mode-specific code should not rebuild
those policies separately.

`close_flush_timeout` is different. Following the Java client, it is sender
close policy: close orchestration keeps the configured timeout, then passes it
to the shared close/drain operation. `QwpWsPublicationStore` should expose close
lifecycle and published/acked facts, and `QwpWsSendCore` should expose progress
needed to reach the close condition, but neither should own the configured
timeout as durable state.

### Error Simplification Guidance

QWP-specific errors are not a released compatibility surface. Prefer the
simplest error model that gives users actionable failures and keeps the two
progress modes aligned.

Guidance:

- keep protocol semantics, such as DROP versus HALT and durable ACK completion;
- keep the status-byte category mapping, default DROP/HALT policies, WebSocket
  close-code routing, and failover classification defined by the reference
  specs;
- keep `Sender` methods returning `crate::Result` through the existing public
  API shape;
- collapse duplicated error rings, notification rings, and terminal error latches
  if one shared delivery model can express the behavior;
- avoid separate manual and background error conversion paths;
- prefer one representation for a server rejection and derive any public error
  view from it;
- do not keep old Rust QWP error variants or exact message text solely because
  tests assert them;
- update tests to assert the intended user outcome: publication rejected,
  terminal state recorded, DROP reported while progress continues, HALT stops
  later publication, close reports an undrained terminal failure.

Decision: error notification state belongs in `QwpWsPublicationStore`, but
error notification delivery belongs to the sender/API layer. Java uses
`SenderErrorDispatcher` and a daemon callback thread; Rust should not add that
thread in this convergence work. `QwpWsSendCore` should record or offer
structured diagnostics, `QwpWsPublicationStore` should retain diagnostics and
dropped-notification counters, and `Sender` should remain responsible for
draining notifications and invoking `QwpWsErrorHandler`.

Target model for sender errors:

- keep one store-owned source of truth for QWP sender diagnostics;
- keep a terminal sender-error latch only if stable non-consuming terminal lookup
  needs it;
- remove the public pollable diagnostic API and use callback notification plus
  terminal-error payloads as the public model;
- do not keep two cloned bounded rings, or independent poll and notification
  cursors, merely to preserve post-hoc diagnostic polling;
- define `qwp_ws_errors_dropped` as dropped callback-notification count.

The focused design is
[`.md`](QWP_WEBSOCKET_NOTIFICATION_ONLY_ERROR_DELIVERY.md).

No store, core, runner, or progress-thread code should call user callbacks.
If Rust later adds Java-style asynchronous error dispatch, it should be an
explicit later API decision, not hidden inside manual mode or this
simplification pass.

Error changes should still be deliberate. If a change affects what a user can
observe through `Sender`, document the new contract in the same slice and test
that contract behaviorally.

## Proposed Model

Split the implementation into three ownership areas using current Rust
terminology.

### Publication Path

The publication path is owned by the user-facing sender. It is responsible for:

- line protocol encoding;
- appending encoded payloads through `SfaProducer`;
- publishing a monotonically increasing upper frame sequence number;
- observing terminal submission errors;
- initiating user-facing close or flush operations.

The publication path uses `QwpWsReplayEncoder` for encoding and `SfaProducer`
for append ownership. It does not own transport state, reconnect state, or
wire-order durable acknowledgment tracking. It must be possible to run it while
`QwpWsSendCore` is concurrently making progress.

### QwpWsSendCore Mechanics and Progress

`QwpWsSendCore` progress is owned by exactly one progress executor. It is
responsible for:

- opening, closing, and reconnecting the WebSocket transport;
- owning the resend/send cursor;
- reading published payloads from `QwpWsPublicationStore` / `SfaFrameQueue`;
- sending payloads to the server;
- receiving and applying server responses;
- advancing completed or durably acknowledged frame sequence numbers;
- recording terminal transport or server errors.

`QwpWsSendCore` should own connection-local mechanics and protocol state. It
should not own scheduler policy:

- it does not decide whether a background thread exists;
- it does not own stop flags or cancellation predicates;
- it does not own idle parking or reconnect-sleep interruption policy;
- it does not own when a scheduler drops store locks around transport or file
  I/O;
- it does not own close timeout loops or orphan-drainer pool grace/detach
  policy.

The core may expose simple progress primitives and a direct `drive_once` for
manual use. It should not grow a second family of hook-parameterized progress
methods for a single scheduler. If reconnect waiting needs to be interruptible,
that belongs to the scheduler that is doing the waiting.

In background mode, the library owns the progress executor thread.

In manual mode, caller code owns the progress executor. The executor may be the
same thread as the sender for compatibility, or a separate caller-managed thread
if the manual API exposes a separate progress handle. In either case, the client
does not start a background thread.

`QwpWsSendCore` should be `Send` if it is exposed through a separate manual
handle, but it should not be implicitly multi-consumer. Only one progress
executor may call progress methods for a sender instance.

### QwpWsPublicationStore and SFA State

`QwpWsPublicationStore` and the SFA types connect publication and progress. They
are responsible for:

- storing published payloads until they are no longer needed;
- making payload visibility happen before publication visibility;
- tracking published and completed upper frame sequence numbers;
- holding lifecycle state shared by publication and progress;
- carrying terminal error state with the same behavior in both modes;
- carrying backpressure notifications;
- carrying structured sender-error notification state for sender/API-layer
  delivery;
- preserving SFA slot lock lifetime until both sides are done with the slot.

`QwpWsPublicationStore` must not invoke user callbacks. It may own diagnostic
queues, notification cursors, terminal sender-error payloads, and dropped-error
counters as data. The sender/API layer owns when and how `QwpWsErrorHandler` is
called.

`SfaEngine` should own shared durable-log state. `SfaProducer` should own the
append cursor. `SfaFrameQueue` should be the queue/log view used by progress
code, not the owner of progress-local resend policy. The first simplification
should be structural convergence, not replacing every lock or store type.

## Concurrency Protocol

The unified protocol should be explicit about the following invariants.

### Single Publication Producer

For one sender instance, there is one publication producer. In SFA mode that is
`SfaProducer`, reached through the public sender API. The public API already
serializes calls through mutable sender access. The design does not require
supporting multiple concurrent user threads submitting through the same sender.

### Single Progress Executor

For one sender instance, there is one `QwpWsSendCore` progress executor.
Background mode and manual mode differ only in who owns the thread or
event loop that calls progress methods.

### Scheduler Ownership

Background, manual, and orphan-drainer execution should be schedulers over the
same core mechanics, not separate protocol implementations.

The background scheduler owns the library thread, stop flag, idle parking,
stop-aware reconnect sleeps, panic/poison handling if still needed, and the
lock-split rules needed to keep publication concurrent with transport and file
I/O.

The manual scheduler calls progress directly from caller-owned code. It must not
spawn a background thread and it should not require stop hooks for the normal
manual hot path.

The orphan-drainer scheduler owns best-effort post-drop draining. It may own its
own core, transport, and store handle, but pool-level shutdown remains an outer
scheduler concern: give drainers a grace window, request stop, then detach or
abandon according to the configured policy. Do not push that policy through
every `QwpWsSendCore` helper as generic hooks.

### Publish Ordering

`SfaProducer` must fully write a payload before making its frame sequence number
visible as published.

`QwpWsSendCore` progress may read only payloads whose frame sequence numbers are
visible as published.

### Completion Ordering

Only `QwpWsSendCore` progress advances completed or durably acknowledged frame
sequence numbers.

Completion is cumulative and monotonic. The completed upper bound must never
advance past the published upper bound.

### Cursor Ownership

Wire send cursors and durable acknowledgment trackers belong to `QwpWsSendCore`,
not to `SfaProducer` and not to a general shared queue object.

This keeps resend, reconnect, and ACK application in one place.

### Payload Borrowing

The transport path must not retain borrowed payload slices after a
`QwpWsSendCore` progress call returns unless the borrowing lifetime is explicit
and owned by that progress path.

This keeps `SfaProducer` free to continue publishing and lets
`QwpWsPublicationStore` / `SfaEngine` make clear reclamation decisions.

### Terminal Error Ordering

Terminal errors must be observed consistently by both progress modes.

If publication, status reads, or close/drain operations currently fail after a
terminal store error, replacing that path with direct atomics must preserve the
same behavior. Faster watermarks are only valid if they do not bypass terminal
error checks.

### Slot Lock Lifetime

The SFA slot lock is a semantic ownership guard, not incidental locking.
Any split between publication and `QwpWsSendCore` progress must preserve the rule
that the slot remains owned until neither side can publish, read, resend, or
clean up state for that slot.

### Close and Drop

Close must prevent new publications, let `QwpWsSendCore` progress drain
according to the configured timeout, and then release shared resources in a
defined order.

Drop must also have a defined ownership handoff:

- dropping the publication path stops new payloads;
- dropping or stopping `QwpWsSendCore` progress stops transport progress;
- the slot lock is released only after both sides have relinquished the shared
  slot state.

## Public API Direction

The safest migration is internal convergence first.

Decision: use the existing `&mut Sender` manual progress API in the first
implementation phase. The internal ownership model should make a later split
manual progress handle possible, but adding that handle is not part of the first
convergence step.

Phase 1 should keep the existing public modes:

- background progress continues to spawn a library-owned progress
  thread;
- manual progress continues to start no library-owned progress thread and expose
  explicit progress calls through the sender.

Internally, both modes should use the same publication path, `QwpWsSendCore`
progress path, and `QwpWsPublicationStore` / SFA state model. The existing
manual API can call into the same progress path while holding exclusive sender
access, preserving current behavior.

Phase 2 may add a split manual-progress API if it is still useful after the old
manual-specific path is gone. That API would still be manual mode, not a third
mode. It would return separate handles, for example conceptually:

```text
(Sender, manual progress handle)
```

The exact names are not part of this proposal.

The important property is that progress calls would no longer require mutable
access to the sender handle. Caller code could then choose to do this:

```text
user thread:    sender.flush(...)
caller thread:  manual_progress.drive_once(...)
```

This still satisfies manual mode because caller code owns the progress handle and
any thread that runs it. Background mode would create and own the
progress thread internally.

## Migration Plan

Each slice should either remove a mode-specific concept, move state to its real
owner, or make both modes call the same implementation. A slice that only adds a
wrapper without deleting or narrowing an existing concept is probably moving in
the wrong direction.

Internal backward compatibility is not required. The implementing agent should
clean up old internals as it goes:

- no permanent compatibility shims;
- no legacy manual path beside a new shared manual path;
- no legacy background path beside a new shared runner path;
- no test-only preservation of old private APIs.

When a slice changes an internal concept, update or remove the tests that pinned
the old concept. Preserve behavior coverage, not private API coverage.

### 1. Defer Lock-Free Work Until the Protocol Boundary Is Correct

Do not start by chasing individual locks while the two progress modes still use
different protocols.

The first step is to make the two progress modes share the same logical objects
and invariants.

### 2. Add a Neutral Core Parts Builder

Introduce one internal construction path for the QWP/WebSocket core. This should
replace the current pattern where background mode opens a publication
driver, extracts runner parts, and then creates a separate encoder, while manual
mode keeps the publication driver whole.

Target:

```text
open_qwp_ws_parts(...) -> QwpWsParts {
    encoder,
    producer,
    store,
    send_core,
    orphan_candidates,
}
```

Immediate acceptance criteria:

- background and manual setup both call this builder;
- negotiated protocol version is captured once and used by `QwpWsReplayEncoder`;
- durable ACK mode, reconnect policy, append deadline, SFA options, and slot
  ownership are configured in this common path;
- mode-specific code only decides whether to put `QwpWsSendCore` progress into a
  runner thread or keep it in the manual handler.

This slice should not change public behavior. It may freely change private
constructors, private type names, and private test helpers.

### 3. Normalize Internal Types Around Existing Rust Names

Extract internal types along these ownership lines:

- `QwpWsReplayEncoder` and `SfaProducer`: encoding and publication;
- `QwpWsSendCore`: transport progress, resend cursor, reconnect, durable ACK
  wire-order policy, and server response handling;
- `QwpWsPublicationStore`, `SfaFrameQueue`, and `SfaEngine`: publication status,
  lifecycle, completion/error propagation, backpressure, durable-log state, and
  slot ownership.

This should initially be an ownership refactor with public behavior preserved.
The types should replace current concepts rather than sit permanently beside
them:

- `QwpWsPublicationDriver` should disappear or become construction-local once
  encoding and publication are owned by `QwpWsReplayEncoder` and `SfaProducer`.
- `ManualDriverPrototype` should disappear once its progress behavior is owned
  by `QwpWsSendCore` and its publication state is owned by
  `QwpWsPublicationStore`.
- `SyncQwpWsRunnerCore` should become a scheduler helper around
  `QwpWsSendCore`, not another driver implementation.

### 4. Share the Publication Path

Make background and manual flush use the same encode-and-submit helper.

The helper should produce the same publication outcome regardless of whether
`QwpWsSendCore` progress is run by the library or by caller code.

Backpressure waiting may remain scheduler-specific at first:

- background mode may wait on a notifier while the runner thread makes
  progress;
- current manual API may drive progress while waiting, because no background
  thread exists.

That difference should be expressed as a small wait/progress strategy around the
same publication operation, not as separate encoding and publication paths.

Behavior tests should compare outcomes, not implementation shape:

- same encoded-size limit behavior in both modes;
- same FSN returned for the first successful publish from a fresh sender;
- same local backpressure timeout category when progress cannot free capacity;
- same terminal error after `QwpWsPublicationStore` is halted.

### 5. Make QwpWsSendCore Mechanics Shared

Make manual `drive_once` and the background runner use the same
`QwpWsSendCore` mechanics and state transitions. The goal is one protocol, not
necessarily one monolithic function that hides scheduler responsibilities.

Target:

```text
manual scheduler -> QwpWsSendCore::drive_once(...) -> DriveOutcome
background scheduler -> QwpWsSendCore progress primitives -> DriveOutcome
```

The background runner loop should add only scheduler-owned behavior:

- stop flag handling;
- idle parking/sleeping;
- stop-aware reconnect sleeps;
- thread lifecycle;
- store-lock splitting around transport and file I/O;
- panic/poison handling if still needed.

Manual mode should call the direct `QwpWsSendCore` progress path and must not
spawn.

Do not replace the old manual/background split with a new split between plain
progress methods and `_with_reconnect_hooks` methods. A hook-parametric helper
family is only acceptable if it is the one shared API used by all schedulers and
it removes existing code. A hook family used by one orphan close path is the
same accidental complexity in a different form.

Behavior tests should exercise both modes against equivalent fake transport
scripts:

- one publish followed by one OK ACK;
- a server rejection with DROP policy;
- a server rejection with HALT policy;
- reconnect and replay after a transport failure;
- durable ACK mode advancing completion only after durable confirmation.

These tests should assert visible sender behavior and FSN/ACK outcomes. They
should not assert that a specific private helper was called.

### 6. Treat Cursor Ownership as a Step 9 Boundary

The old standalone goal was to move runner-only cursor state, such as the SFA
send cursor, out of queue/store objects. That goal is now part of Step 9's hot
SFA/log boundary. Do not create a separate "move cursor helpers" slice unless it
removes a current hot store dependency or deletes real duplication.

`QwpWsSendCore` / `SendCursor` should own protocol cursor state and policy:
wire-sequence mapping, in-flight window accounting, replay reset, ACK/reject
mapping, and resend decisions. The SFA/log view should own storage-local payload
lookup and segment/offset cursor positioning needed to satisfy the next-frame
request.

Durable ACK tracking should also be treated as `QwpWsSendCore` policy. The
shared store/log should expose enough information to complete or retain frames,
but it should not own wire-order durable ACK bookkeeping if only the progress
executor mutates it.

Acceptance criteria:

- reconnect resets send cursors without asking the SFA queue to own resend
  policy;
- ACK and durable ACK application still advance the same completed FSN;
- queue APIs describe storage/log operations, not wire-progress policy;
- any remaining cursor follow-up is routed through Step 9's hot/cold boundary,
  not tracked as an independent cursor-cleanup project.

### 7. Simplify QWP Errors and Preserve Close Semantics

During the migration, close/drain behavior should be treated as a public behavior
requirement. QWP-specific error classification and delivery can be simplified if
the new behavior is clearer and consistent across both modes.

Tests should assert behavior, not implementation shape:

- after a terminal transport or store error, both modes reject later
  publications through the same public error contract;
- close waits for the same completion condition in both modes;
- server reject and reconnect behavior remain `QwpWsSendCore` responsibilities;
- background and manual progress expose the same user-visible QWP
  error contract;
- dropping one side releases resources only when the other side no longer needs
  them.

If this slice changes QWP error categories, messages, or notification timing,
delete the old tests and replace them with tests for the new intended contract.
Do not keep adapters that translate new internal errors back into old unreleased
QWP shapes.

Close/drain should have one core implementation. Mode-specific code should only
decide who repeatedly calls progress while waiting:

- background close can wait while the runner drives progress;
- manual close or `await_acked_fsn` can drive progress on the caller thread;
- split manual handle, if added later, can require caller-owned progress.

The configured `close_flush_timeout` should not live in
`QwpWsPublicationStore` or become persistent `QwpWsSendCore` state. The sender's
close orchestration owns that wait policy and passes it into the shared
close/drain operation. The shared operation should use store/core facts such as
published FSN, completed or ACKed FSN, terminal error state, and progress
availability to decide whether close has drained, timed out, or failed.

Orphan drainers should follow the Java shape: the drainer owns its own
drain-time core/transport loop, polls completion against the target FSN, and
lets the pool own graceful shutdown versus stop/detach policy. If an orphan path
needs a stop-aware retry or reconnect wait, keep that special case in the
orphan scheduler or reconnect wait call site. Do not make every
`QwpWsSendCore` progress helper carry orphan-drainer hooks.

### 8. Keep Manual Progress Caller-Owned

A separate caller-owned progress handle is useful only once the internal split is
real. Do not add it in the first convergence phase. Adding the API first would
make the existing divergence public.

If added, the API should remain part of manual mode and make ownership
constraints explicit:

- one sender/publication handle;
- one progress handle;
- progress handle may move to a caller-owned thread;
- progress calls are serialized by the caller;
- sender calls remain serialized through the sender API;
- the client does not spawn a progress thread for manual mode.

Do not add this API until the existing manual mode is already a wrapper around
the same `QwpWsSendCore` progress path as background mode.

### 9. Reach Java Lock-Free Parity

After convergence, remove hot-path locks until Rust matches Java's lock-free
boundary:

- publication to the active segment must not take the shared publication mutex;
- published and completed/acked progress reads must be direct atomic reads;
- ACK application in the healthy I/O path must not take the shared publication
  mutex;
- the `QwpWsSendCore` loop must not take a shared publication mutex merely to
  find the next healthy outbound frame;
- queue/store decomposition should remove locks from these paths where the
  current ownership shape makes atomic watermarks insufficient.

Locks that remain should be limited to paths analogous to Java's synchronized
paths: rotation into the sealed list, sealed-list snapshots or next-segment
lookups, trim/cleanup, spare installation, close, recovery, and reconnect
positioning. A lock that protects a small SFA topology boundary is acceptable; a
lock that gates publication visibility, ordinary active-segment send progress,
ACK application, or non-terminal status reads is not Java-like.

#### Target Boundary

Lock-free parity means matching Java's hot/cold boundary, not deleting every
lock. The hot path is:

- one producer appends and publishes frames;
- one `QwpWsSendCore` progress executor reads published frames, sends them,
  receives responses, applies ACKs, and advances completion;
- published and completed/acked watermarks are atomic-style visibility
  boundaries;
- healthy send/receive progress does not take the shared publication mutex.

Cold-path locks are still acceptable when they represent real lifecycle or
topology ownership. Do not chase a fully lock-free implementation for sealed-list
coordination, trim/cleanup, spare installation, close, recovery, reconnect
positioning, terminal-error materialization, sender-error polling, or slot-lock
lifetime. The Java-like rule is narrower: locks must not be required for the
hot facts Java reads through volatile/atomic-style boundaries, namely published
progress, completed/acked progress, active payload visibility, ACK advancement,
and non-terminal status.

Do not use raw `shared.lock()` call-site count as the Step 9 success metric.
Once the runner is split into explicit phases, a higher number of short,
per-phase lock touches can be better than fewer coarse locks. Judge progress by
which healthy paths can make forward progress without blocking on the shared
`QwpWsPublicationStore` mutex: publication, next-frame lookup, send-result
completion, ACK/durable-response application, and non-terminal status reads.
Server rejection handling is protocol behavior, but it is an error/diagnostic
path; it may remain store-backed when it materializes rejected-frame history,
sender errors, or terminal state. Cold-effect flushing may still touch the store
in short critical sections, preferably opportunistically, when it only records
diagnostic events, terminal/error state, or other cold bookkeeping.

#### Current Rust State

The first Step 9 slices have moved the background healthy path away from
`Arc<Mutex<QwpWsPublicationStore<_>>>` for the operations that determine steady
send/ACK progress. Background progress now uses `QwpWsSendCore` plus a detached
SFA/log view for:

- finding the next outbound frame;
- recording send completion;
- applying ACK, `DurableOk`, and `DurableAck` progress;
- reading published/completed progress.

The remaining store-backed response path is server rejection handling. Keep that
explicitly cold unless a later source-backed change can split completion from
diagnostic/error materialization without adding another scheduler-facing protocol
API.

The SFA send-cursor follow-up belongs here. Do not treat it as a standalone
"move helpers because Java does" cleanup. The useful Java-like split is the one
that lets `QwpWsSendCore` drive healthy progress through a narrow SFA/log view
without taking the cold publication-store mutex.

#### First Step 9 Slice

Start Step 9 by carving the hot progress/log boundary.

Target shape:

```text
QwpWsSendCore + &mut SendCursor + SFA/log view
  -> next published payload
  -> transport send
  -> response classification
  -> completion/ACK progress
```

The SFA/log view should expose storage facts, not scheduler or diagnostic state:
published/completed watermarks, oldest unresolved FSN, and payload lookup by
FSN/cursor. Prefer a concrete narrow handle over a new generic trait. If a trait
is necessary, it should replace the old hot `PublicationLog` boundary instead of
coexisting with it as another layer.

This slice should not expose arbitrary segment internals just to move methods
around. Keep storage-specific segment lookup, active/sealed/hot-spare topology,
slot-lock ownership, and segment/offset cursor positioning in the SFA module.
`QwpWsSendCore` / `SendCursor` should own protocol cursor state and policy:
FSN-to-wire-sequence mapping, in-flight window accounting, replay reset,
ACK/reject mapping, and the decision that the protocol is ready to request the
next frame. The SFA/log view may advance its own storage-local cursor while
satisfying that request.

Treat detached next-frame lookup as the first milestone, not as Step 9
completion. Step 9 remains incomplete until these healthy paths no longer depend
on the shared `QwpWsPublicationStore` mutex:

- next-frame lookup;
- send-result completion;
- response classification and ACK/durable-response application;
- non-terminal published/acked status reads.

ACK-watermark persistence, trim, cleanup, reject diagnostics, and terminal-error
materialization may move in later sub-slices or remain cold-path work if moving
them would blur the ownership boundary. Do not leave a temporary next-frame-only
API in place as the final state; follow with completion, ACK/status, and status
read splitting.

#### Implementation Direction

Prefer a small phased split over a generic lock-free framework. Refer to these
follow-ups by label rather than item number; the ordering may change as slices
land:

1. **Hot/cold state split.** Hot state should expose lifecycle,
   published/completed watermarks, and SFA/log access. Cold state can keep
   terminal error payloads, sender-error diagnostics, rejected-frame history,
   event rings, and other diagnostic material behind ordinary locks.
2. **Next-frame hot lookup.** Change progress-facing log APIs so healthy
   next-frame lookup uses an immutable SFA/log view plus `&mut SendCursor`, not
   mutable access to the whole `QwpWsPublicationStore`. Resolve cursor ownership
   here only where it removes that hot store dependency; storage-local segment
   cursor movement can stay inside the SFA view.
3. **Atomic completion.** Make completion advance atomic-first. Updating the
   in-memory completed watermark should not require the shared publication mutex.
   ACK-watermark persistence and cleanup can remain progress-owned cold work.
4. **Healthy runner lock removal.** Remove the runner's shared-store mutex from
   healthy `next_outbound_frame`, send-result completion, and ACK/response
   application.
5. **Atomic status reads.** Make background `published_fsn()` and `acked_fsn()`
   use direct atomic reads on the non-terminal path. If lifecycle is terminal,
   fall back to the cold error state so public `Sender` behavior remains
   explicit.
6. **Segment-boundary optimization.** Java reads active payload progress and
   watermarks lock-free, but it still synchronizes sealed-list transitions and
   lookups. Optimize Rust segment-boundary lookup only if it blocks healthy
   progress on a broad store mutex or removes real complexity. It is acceptable
   for active/sealed/hot-spare topology to keep a small storage-local lock. Do
   not build a generic lock-free topology layer solely for parity.

Do not introduce a generic MPSC queue, epoch reclamation, callback scheduler, or
new public progress API unless it deletes existing complexity and preserves this
Java boundary. The existing one-producer / one-progress-executor model should be
enough.

#### Invariants

The lock-free work must preserve these invariants:

- one publication producer per sender;
- one progress executor per sender;
- payload bytes are fully visible before the published FSN becomes visible;
- published FSN is monotonic;
- completed/acked FSN is monotonic and never advances beyond published FSN;
- `QwpWsSendCore` owns send cursor state, wire-sequence mapping, durable ACK
  tracking, reconnect mechanics, and server-response application;
- durable ACK mode does not complete frames on ordinary OK alone; durable
  completion remains driven by durable ACK readiness;
- DROP versus HALT classification remains protocol behavior, not scheduler
  behavior;
- reject gaps remain terminal/protocol errors unless durable FIFO state proves
  the prefix is resolved;
- terminal errors remain observable by public `Sender` APIs; faster atomic reads
  must not silently bypass terminal state;
- borrowed outbound payloads must not outlive the progress/send call that
  created their view;
- close/drain preserves the same completion condition and resource release
  behavior;
- ACK-watermark persistence and trim must not outrun recoverable completion
  state;
- SFA slot lock lifetime remains semantic: the slot is held until neither
  publication nor progress can publish, read, resend, or clean up that slot;
- locks that remain must correspond to Java-like cold paths, not healthy
  send/receive progress.

#### Proof Tests

Tests should prove behavior and lock-boundary changes, not private helper shape:

- background publication can proceed while cold publication-store state is held;
- background send and ACK progress can proceed without the cold store lock on the
  healthy path;
- published/acked status reads use the atomic path when non-terminal but still
  surface terminal errors;
- background and manual modes still agree for publish+ACK, DROP, HALT,
  reconnect replay, and durable ACK completion;
- durable ACK ordering survives reordered OK/ACK responses and reconnect;
- close succeeds after all published frames are resolved, times out without
  deleting recoverable SFA state, and releases resources in the same order as
  before;
- storage maintenance, recovery, and orphan draining continue to use locks only
  at the cold boundaries they own.

## Expected Simplification

The main simplification is that there is one QWP/WebSocket sender protocol:

```text
QwpWsReplayEncoder/SfaProducer
  -> QwpWsPublicationStore/SfaEngine
  -> QwpWsSendCore
  -> server responses
```

Background mode:

```text
Sender owns publication.
Library thread owns QwpWsSendCore progress.
```

Manual mode:

```text
Sender owns publication.
Caller owns QwpWsSendCore progress scheduling.
```

That makes the implementation closer without pretending that all synchronization
can disappear. The code can still use synchronization where it represents real
shared ownership, while removing the larger conceptual split between manual and
background execution.
