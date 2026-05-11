# QWP/WebSocket Step 9 error policy prototype

Date: 2026-04-28

Status: mock-side validation note for Step 9 of
`doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Prototype scope

This slice keeps the prototype transport-free and validates the error model at
the manual-driver boundary.

Implemented:

- a private `ManualDriverQueue` seam used by the manual driver prototype
- `ManualDriverQueue` implementations for the volatile queue and file-backed SF
  queue
- driver-level terminal state distinct from queue and storage state
- `QwpReceiptStatus::Terminal` and `DeliveryOutcome::Terminal`
- close-drain outcomes: drained, timeout, terminal
- retry-budget exhaustion that terminalizes the current sender without
  completing durable SF records
- a bounded driver event ring and `poll_event()` for transition notifications
- `DriverError::Storage` and `DriverError::CorruptLog` so storage failures do
  not collapse into delivery outcomes

The important behavioural distinction is that terminal failure belongs to the
current sender instance. In file-backed SF mode, terminalizing current receipts
does not append completion records. A newly created sender can
recover the still-unresolved SF frames and replay them.

Events are not authoritative state. They are ordered transition notifications
for observability. `receipt_status()`, `wait()`, and `close_drain()` remain the
state surfaces; event overflow increments a drop counter and must not corrupt
receipt or delivery outcomes.

Not implemented in this slice:

- auth or upgrade rejection detail
- write/internal server error classification
- real-server error taxonomy probing
- durable rejection/dead-letter files

## Validation checks

Rust unit tests cover:

- the volatile manual driver still returns before ACK and preserves existing
  queue/receipt behaviour through the new seam
- retryable failure resets connection state without completing the receipt
- terminal failure marks unresolved receipts terminal and rejects future
  submissions on the current driver
- terminal failure does not complete recovered SF frames; a recreated SF driver can
  replay and ACK the still-unresolved frame
- close drain rejects new submissions, drives existing receipts to drained,
  returns timeout while preserving existing receipt observability, and returns
  terminal when terminal failure occurs during drain
- close-drain timeout in SF mode leaves unresolved frames recoverable by a newly
  created sender
- retry-budget exhaustion terminalizes current unresolved receipts and rejects
  future submissions
- retry-budget exhaustion in SF mode leaves unresolved frames recoverable by a
  newly created sender
- successful submit queues a `Published` event, while failed submit queues no
  event
- send, cumulative ACK, rejection, reconnect, and terminal events agree with
  `receipt_status()` and `wait()`
- terminal transition queues one `Terminal` event; sticky terminal progress does
  not duplicate it
- event ring overflow drops old events and increments a counter without
  corrupting receipt status
- `close_drain()` is irreversible once started, including if progress returns a
  protocol/API error
- an SF-backed driver reopens and replays from the first unresolved FSN with
  wire sequence `0`
- DROP_AND_CONTINUE records a rejection event/error, completes the rejected
  frame for replay purposes, and does not persist queue-owned rejection state

Targeted validation commands:

```bash
cargo fmt --check --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
```

Result:

- manual driver filter: 37 passed
- widened QWP filter: 106 passed, 2 ignored

## Local reflection

- How does this particular step feel?

  The queue seam is small and mechanical. Adding events at existing transition
  points did not require a second state machine, which is the important result:
  events can stay observational rather than authoritative.

- What was simpler or more awkward than expected?

  Terminal and closing state are cleaner as driver-layer overlays than as
  durable queue completion records. Event overflow was simpler than expected
  once direct accessors remained authoritative. The useful simplification is
  that `receipt_status()` no longer carries queue-owned rejection detail:
  rejection remains an event/error concern.

- Did the API or implementation shape create accidental complexity?

  The main complexity is status composition. Queue state, closing state,
  terminal state, and event history are related but not the same. The core
  should probably expose a small status composer rather than scattering these
  checks across adapters.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It strengthens the distinction between durable facts and current-driver
  outcomes. ACK and completion are durable queue facts. Terminal failure,
  retry-budget exhaustion, close timeout, and event loss can affect the current
  sender or observability surface without destroying recoverable SF data.

- Did this step strengthen or weaken the core assumptions?

  It strengthened them. The same manual driver now exercises volatile and SF
  queues for rejection, close, retry, and event-observation outcomes. The SF
  queue can survive terminal sender failure or close timeout without being
  converted into rejection metadata or data loss, and receipt state remains valid
  even when events overflow.

- Should the next step proceed, or should the design be adjusted first?

  Proceed to Step 10. The remaining uncertainty is protocol truth: real-server
  error taxonomy and error payload shape should be validated before any FFI
  outcome enum hardens.
