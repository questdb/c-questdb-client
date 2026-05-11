# QWP/WebSocket Java-like SFA Completion Simplification

Status: proposal.

This note proposes simplifying the Rust QWP/WebSocket Store-and-Forward (SFA)
queue and receipt model to match the Java cursor implementation more closely.
The motivating decision is that the Rust API is still in progress, so it does
not need to expose more per-receipt outcome detail than Java exposes.

## Review Sources

Rust current implementation:

- [qwp_ws_queue.rs](../questdb-rs/src/ingress/sender/qwp_ws_queue.rs#L79-L100)
  defines `QwpReceipt` and the current `QwpReceiptStatus` variants, including
  `Acked` and `Rejected`.
- [qwp_ws_sfa_queue.rs](../questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs#L255-L256)
  currently stores `completed_upper` and `rejected_fsns`; the current
  completion/rejection logic is in
  [qwp_ws_sfa_queue.rs](../questdb-rs/src/ingress/sender/qwp_ws_sfa_queue.rs#L851-L897).
- [qwp_ws_driver.rs](../questdb-rs/src/ingress/sender/qwp_ws_driver.rs#L313-L344)
  maps WebSocket rejection responses to queue rejection, send-cursor advancement,
  events, and sender errors. It also currently overlays driver-owned
  `rejected_frames` onto receipt status in
  [qwp_ws_driver.rs](../questdb-rs/src/ingress/sender/qwp_ws_driver.rs#L494-L525)
  and appends rejected-frame diagnostics in
  [qwp_ws_driver.rs](../questdb-rs/src/ingress/sender/qwp_ws_driver.rs#L572-L587).
- [qwp_ws_sfa_slot.rs](../questdb-rs/src/ingress/sender/qwp_ws_sfa_slot.rs)
  wraps disk SFA with slot locking and forwards publication-log calls.
- [sender.rs](../questdb-rs/src/ingress/sender.rs#L535-L540) already documents
  public `acked_fsn()` as completion by server ACK or reject-and-continue.

Java reference implementation:

- [SegmentRing.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java#L286-L324)
  owns the append-only FSN log, the cumulative `ackedFsn` cursor, and ACK-driven
  cursor advancement; trimming uses the same cursor in
  [SegmentRing.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/SegmentRing.java#L424-L443).
- [CursorSendEngine.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorSendEngine.java#L247-L261)
  exposes `acknowledge(seq)` as the cursor advancement API.
- [CursorWebSocketSendLoop.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java#L48-L62)
  owns protocol response classification, rejection dispatch, durable-ack FIFO
  gating, reconnect, and progress callbacks; the DROP_AND_CONTINUE rejection
  path is in
  [CursorWebSocketSendLoop.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java#L1185-L1268),
  and durable FIFO draining is in
  [CursorWebSocketSendLoop.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/sf/cursor/CursorWebSocketSendLoop.java#L1326-L1387).
- [WebSocketResponse.java](../../questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/WebSocketResponse.java#L40-L62)
  documents the Java parser's OK, durable-ack, and error response frames.

QuestDB server implementation:

- [QwpWebSocketUpgradeProcessor.java](../../questdb-http2/core/src/main/java/io/questdb/cutlass/qwp/server/QwpWebSocketUpgradeProcessor.java#L756-L827)
  parses WebSocket frames from the receive buffer in order and calls
  `handleWebSocketFrame()` synchronously for each complete frame before moving
  on to the next frame.
- [QwpWebSocketUpgradeProcessor.java](../../questdb-http2/core/src/main/java/io/questdb/cutlass/qwp/server/QwpWebSocketUpgradeProcessor.java#L533-L605)
  assigns each binary QWP message a monotonic connection-local sequence,
  processes and commits it synchronously, advances the cumulative OK sequence
  only after success, and sends pending OK ACKs before an error response.
- [QwpWebSocketUpgradeProcessor.java](../../questdb-http2/core/src/main/java/io/questdb/cutlass/qwp/server/QwpWebSocketUpgradeProcessor.java#L995-L1028)
  writes OK responses as cumulative ACKs for `highestProcessedSequence`.
- [QwpProcessorState.java](../../questdb-http2/core/src/main/java/io/questdb/cutlass/qwp/server/QwpProcessorState.java#L431-L448)
  preserves ACK-before-error ordering under send backpressure by converting an
  in-flight ACK plus blocked error into `SEND_STATE_RESUME_ACK_THEN_ERROR`.
- [QwpWebSocketUpgradeProcessor.java](../../questdb-http2/core/src/main/java/io/questdb/cutlass/qwp/server/QwpWebSocketUpgradeProcessor.java#L446-L452)
  resumes the blocked ACK first, then sends the deferred error.
- [QwpProcessorStateTest.java](../../questdb-http2/core/src/test/java/io/questdb/test/cutlass/qwp/QwpProcessorStateTest.java#L1950-L1966)
  covers the ACK-in-flight then deferred-error state lifecycle.

Specs and local design notes:

- [QWP_SPECIFICATION.md](../../questdb-http2/docs/QWP_SPECIFICATION.md#L686-L779)
  describes OK/error response sequence numbers and durable-ack watermarks.
- [QWP_WEBSOCKET_ACK_ORDER_REJECT_PROBE.md](QWP_WEBSOCKET_ACK_ORDER_REJECT_PROBE.md#L54-L108)
  records the real-server ACK/error ordering probe.
- [QWP_WEBSOCKET_ARCHITECTURE.md](QWP_WEBSOCKET_ARCHITECTURE.md) describes the
  current Rust send-loop and SFA cursor shape.
- [QWP_WEBSOCKET_API_SKETCH.md](QWP_WEBSOCKET_API_SKETCH.md) currently sketches
  richer receipt outcomes, including rejection.
- [QWP_WEBSOCKET_ERROR_POLICY_PROTOTYPE.md](QWP_WEBSOCKET_ERROR_POLICY_PROTOTYPE.md)
  includes older expectations around persisted ordered rejection.

## Current Rust Shape

The Rust SFA queue currently mixes two models:

1. A Java-like cumulative completion cursor:
   `published_upper` is the first unpublished FSN and `completed_upper` is the
   first unresolved FSN.
2. A sparse outcome overlay:
   `rejected_fsns: Mutex<Vec<u64>>` records specific FSNs that were rejected so
   `receipt_status()` can return `QwpReceiptStatus::Rejected`.

That hybrid is fragile. `SfaEngine::reject_fsn(rejected_fsn)` currently records
only `rejected_fsn` in `rejected_fsns`, then stores
`completed_upper = rejected_fsn + 1`. If `rejected_fsn` is not the oldest
unresolved FSN, any gap below it becomes completed but is not in
`rejected_fsns`; `receipt_status()` then reports those gap FSNs as `Acked`.

The narrow invariant fix would be to require
`rejected_fsn == completed_upper`. That keeps the richer Rust status model, but
it also preserves a concept Java does not have: queue-owned per-FSN rejection
state.

## Java Shape

Java keeps the cursor store simpler.

`SegmentRing` owns retained frames and a single cumulative `ackedFsn` cursor.
`SegmentRing.acknowledge(seq)` clamps the requested cursor to `publishedFsn`,
then moves `ackedFsn` forward if `seq` is newer. The ring does not store a
separate rejected-FSN set and does not answer "was this exact FSN rejected?".
It answers "is this FSN still retained and replayable?".

`CursorWebSocketSendLoop` owns protocol meaning. On OK, it maps the response
wire sequence to an FSN and advances the cursor. On a DROP_AND_CONTINUE
rejection, it builds and dispatches a `SenderError`, then advances the same
cursor past the rejected FSN. In durable-ack mode, it queues OKs and rejected
placeholders in FIFO order and only advances the cursor when the head entries
are durable-covered. Rejected placeholders are not store state; they are durable
FIFO gates for the send loop.

This division is the key Java boundary:

- The cursor store tracks replayability and trim safety.
- The send loop tracks server outcome, error policy, progress callbacks, and
  user-visible rejection details.

## Proposed Rust Target

Make Rust use the same boundary.

`SfaFrameQueue`, `SfaSlotQueue`, and the queue-side `PublicationLog` should own
only cumulative publication/completion state:

- `published_upper`
- `completed_upper`
- retained segment metadata
- segment rotation, recovery, trim, and close-drain

They should not own protocol outcome state:

- no `rejected_fsns`
- no queue-level `QwpReceiptStatus::Rejected`
- no queue-level dead-letter metadata

The driver should own protocol outcome state:

- response classification
- `DriverEvent::Rejected`
- sender error construction and dispatch
- any temporary rejected-frame detail needed for callbacks or diagnostics
- durable-ack FIFO gating
- terminal sender error state

Any remaining rejected-frame buffer must be diagnostic only. It must not be used
as an authoritative receipt-status overlay. Otherwise the refactor merely moves
per-FSN rejection state from the queue into the driver instead of removing it.
Prefer bounded event/error rings for user-visible rejection details.

The resulting queue contract becomes:

```text
publish(payload) -> QwpReceipt { fsn }
next_outbound_frame() -> frame view for the next retained unsent FSN
complete_through_fsn(fsn) -> mark every FSN <= fsn as no longer replayable
receipt_status(receipt) -> Unknown | Published | Sent | Completed | Terminal
oldest_unresolved_fsn() -> completed_upper when completed_upper < published_upper
```

If `reject_fsn(fsn)` remains during migration, make it a thin compatibility
wrapper around `complete_through_fsn(fsn)` and keep the rejection event/error in
the driver. The final shape should remove it from the queue trait.

## Simplicity and Performance Constraints

This must be a deletion-focused simplification. The target should be smaller and
easier to reason about than the current hybrid cursor plus rejected-FSN overlay.
Do not add a completion manager, sparse completion map, status composer, queue
diagnostic store, or any other new abstraction unless it replaces more
complexity than it introduces.

Steady-state OK response handling must remain allocation-free and lock-free on
the hot path. Mapping a response wire sequence to an FSN, advancing the
send-side cursor, and calling `complete_through_fsn()` should use existing
cursor/atomic state. It must not allocate, take a mutex, scan a rejection list,
or consult a driver diagnostic map.

Receipt polling must stay queue-local. `receipt_status(receipt)` should be
derived from queue-owned publication/completion/terminal state and retained slot
metadata. It must not consult driver-owned rejected-frame diagnostics or
user-visible error rings.

DROP_AND_CONTINUE rejection handling is a cold path. It may construct and enqueue
the user-visible `DriverEvent::Rejected` / sender error for that rejected frame,
but normal OK completion must not pay for rejection diagnostics. Any
driver-owned rejected-frame detail must be bounded and must not become an
authoritative receipt-status data structure.

The reject-gap guard must also stay small and cold-path. It should check the
current oldest unresolved FSN, or an equivalent already-completed predicate, and
terminalize/reconnect on violation. Do not implement the guard by adding sparse
per-FSN tracking to the queue.

Durable-ack mode must preserve the existing FIFO-head drain shape. Rejected
placeholders may remain in the existing pending durable queue, but this refactor
should not add per-OK heap churn or locks to the durable steady state.

## Status Naming

Do not keep returning internal `QwpReceiptStatus::Acked` for a frame that may
have been dropped by DROP_AND_CONTINUE. Java can call the cursor `ackedFsn`
internally, but Rust's internal status names are visible in types and tests.

Preferred Rust wording:

- `Completed`
- `Resolved`
- `Drained`

`Completed` is the most direct fit for the queue contract: the frame is no
longer retained for replay. It does not claim that the server accepted the
frame. Server acceptance or rejection is reported through driver events and
sender errors.

Keep this rename internal to the in-progress QWP/WebSocket receipt/status model.
Do not rename or redesign public `acked_fsn()` / `await_acked_fsn()` in this
slice; the public Rust docs already define that watermark as completion by
server ACK or server-side reject-and-continue.

## Non-durable Rejection Flow

Target flow:

```text
TransportResponse::Reject { wire_seq, error }
  -> driver maps wire_seq to fsn
  -> driver classifies policy
  -> HALT:
       latch terminal sender error
       terminalize sender
       do not trim as a successful completion
  -> DROP_AND_CONTINUE:
       queue.complete_through_fsn(fsn)
       send_cursor.ack_through(fsn)
       notify progress/backpressure with CompletedThrough
       record/dispatch rejected event and SenderError for fsn
```

The queue does not need to know this was a rejection. It only needs to know that
the frame, and all earlier frames covered by the cumulative response, should no
longer be replayed.

## Durable Rejection Flow

Keep the Java-like FIFO durable gate. The important invariant is "do not trim
past an earlier OK until that OK is durable-covered."

Target durable structures can stay close to current Rust:

```text
PendingDurableFrame::Ok {
    wire_seq,
    fsn,
    table_seq_txns,
}

PendingDurableFrame::Rejected {
    wire_seq,
    fsn,
}
```

But `PendingDurableFrame::Rejected` should mean only:

```text
This rejected frame needs no durable-ack of its own, but it must wait behind
earlier pending OK entries before the completion cursor can advance past it.
```

When a rejected entry reaches the head, the driver calls
`queue.complete_through_fsn(fsn)`, not `queue.reject_fsn(fsn)`.
If that advances the cursor, emit the completion/progress event before the
rejection event so durable and non-durable DROP_AND_CONTINUE follow the same
Java-shaped order: progress first, error second.

## Out-of-order Responses

This simplification intentionally avoids sparse completion. It does not make
out-of-order rejection safe by itself.

The current spec text says OK and error responses include a sequence number that
correlates the response with the original request. It explicitly describes
durable-ack responses as cumulative, but it does not clearly specify whether
regular error responses may be delivered out of order with respect to earlier
unresolved requests.

The local real-server probe observed behavior compatible with:

- OK sequence `N` can be treated as cumulative for successful lower unresolved
  frames.
- Error sequence `N` resolves its own frame.
- Later frames can still be accepted after an earlier error.
- Later receipts remain unresolved until a later OK or error resolves them.

The current QuestDB server implementation strengthens that probe result for
normal binary QWP application messages on one WebSocket connection:

- The receive loop parses frames in buffer order and handles each complete frame
  synchronously before the next frame.
- A message receives its wire sequence immediately before processing.
- A successful message updates `highestProcessedSequence`; OK responses report
  that cumulative sequence.
- An error response reports the failed message's own sequence, but before
  sending it the server flushes any pending cumulative OK ACK for earlier
  successes.
- If the earlier OK ACK blocks, the server stores the error as deferred state
  and resumes the ACK before emitting the error.

Therefore this server should not emit a regular error for sequence `N` while a
lower binary-message sequence is still unresolved in a way that the client must
preserve for replay. If Rust sees such a gap, either the server implementation
has changed, the peer is not this server, the response stream is corrupt, or the
client cursor bookkeeping is wrong.

Required implementation rule:

- Keep the queue Java-like and cumulative; do not add sparse completion or
  queue-owned rejection state.
- Add a small driver guard before applying DROP_AND_CONTINUE for a reject FSN:
  require that the reject target is the queue's current
  `oldest_unresolved_fsn()`, or that every lower FSN has already been completed
  by an earlier OK/durable resolution.
- If the guard fails, treat the response as protocol-invalid for this cursor
  model and reconnect or terminalize; do not call `complete_through_fsn(fsn)`.
- If the QWP spec is later tightened to codify the current server behavior, keep
  the guard as a cheap defensive assertion/error path unless it becomes
  demonstrably redundant.

Do not solve this by putting `rejected_fsns` back into the queue. That recreates
the hybrid model and still does not provide a full sparse-completion design.

## Implementation Plan

Suggested order:

1. Rename receipt terminal wording from `Acked` to `Completed` or `Resolved` in
   internal Rust APIs and tests.
2. Remove `QwpReceiptStatus::Rejected` from queue-owned status.
3. Remove `rejected_fsns` and `lock_rejected_fsns()` from `SfaEngine`.
4. Add the driver-side reject-gap guard described above. It should be cold-path
   defensive code against behavior the current QuestDB server should not
   produce for normal binary QWP responses.
5. Replace `SfaFrameQueue::reject_fsn()` with `complete_through_fsn()` at driver
   call sites. Keep a short-lived wrapper only if it reduces patch size.
6. Update `PublicationLog` so queue implementations expose completion, not
   rejection.
7. Keep `DriverEvent::Rejected` and sender error reporting in `qwp_ws_driver.rs`.
8. Stop using driver `rejected_frames` as an authoritative receipt-status
   overlay. Keep only bounded diagnostic/error/event state if needed.
9. Update durable-ack tracker resolution so rejected pending entries call
   completion, not queue rejection.
10. Update docs that currently promise per-receipt rejected status or persisted
   ordered rejection.

## Tests to Rewrite or Add

Rewrite:

- Queue tests that expect `QwpReceiptStatus::Rejected`.
- Driver tests that use receipt status as the proof of server rejection.

Add or preserve:

- Non-durable DROP_AND_CONTINUE records `DriverEvent::Rejected` and sender error
  detail, then the receipt becomes `Completed`.
- A later successful OK after an earlier DROP_AND_CONTINUE advances completion
  cumulatively without requiring sparse state.
- Reject-gap guard refuses or terminalizes a DROP_AND_CONTINUE error response
  that targets a later FSN while an earlier FSN is still unresolved.
- Durable rejected placeholder behind an earlier pending OK does not advance
  completion until the earlier OK is durable-covered.
- Reconnect starts from `oldest_unresolved_fsn()` after completion cursor
  movement.
- Close-drain treats completed rejected frames as drained, but terminal HALT
  remains terminal rather than drained.

Validation commands for the implementation slice should include at least:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib qwp_ws
cargo check --manifest-path questdb-rs/Cargo.toml --no-default-features --features _sender-qwp-ws,ring-crypto,tls-webpki-certs
cargo fmt --check --manifest-path questdb-rs/Cargo.toml
```

## Expected Deletions

The simplification should delete more code than it adds:

- `SfaEngine::rejected_fsns`
- `SfaEngine::lock_rejected_fsns`
- queue-level `reject_fsn`
- queue-level `QwpReceiptStatus::Rejected`
- tests that assert rejected status via queue state

The driver may still keep a small rejected-frame diagnostic map while the Rust
API is in flux. That map should be considered protocol/error-channel state, not
SFA storage state.

## Open Decisions

- Final status name: `Completed` vs `Resolved`.
- Whether `Terminal` remains a per-receipt status or becomes purely sender-level
  terminal state plus pending/complete receipt status.
- Whether to tighten the QWP spec around regular response ordering before this
  Rust simplification, or keep the driver guard as the implementation rule.
- Whether to preserve `rejected_frame(receipt)` as a temporary driver diagnostic
  API while making it non-authoritative for receipt status.

## Review Checklist

A reviewer should check:

- Does the queue answer only retention/replay questions?
- Does every user-visible rejection still surface through event/error paths?
- Does steady-state OK handling remain allocation-free and lock-free?
- Does receipt polling avoid driver diagnostic/error structures?
- Does durable-ack mode still drain only from the FIFO head?
- Does non-durable DROP_AND_CONTINUE reject handling reject or terminalize a gap
  instead of completing over it?
- Did any code path continue to call a queue-level `reject_fsn`?
- Did any docs still promise that receipt polling can distinguish ACKed from
  rejected frames after the fact?
- Did the implementation avoid introducing sparse completion maps or sets?
