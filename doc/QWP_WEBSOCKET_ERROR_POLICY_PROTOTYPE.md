# QWP/WebSocket Step 9 error policy prototype

Date: 2026-04-28

Status: partial validation note for Step 9 of
`doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Prototype scope

This slice keeps the prototype transport-free and validates the error model at
the manual-driver boundary.

Implemented:

- a private `ManualDriverQueue` seam used by the manual driver prototype
- `ManualDriverQueue` implementations for the volatile queue and file-backed SF
  queue
- driver-level terminal state distinct from queue, storage, and poison state
- `QwpReceiptStatus::Terminal` and `DeliveryOutcome::Terminal`
- close-drain outcomes: drained, timeout, terminal
- retry-budget exhaustion that terminalizes the current sender without
  completing durable SF records
- `DriverError::Storage` and `DriverError::CorruptLog` so storage failures do
  not collapse into delivery outcomes

The important behavioural distinction is that terminal failure belongs to the
current sender instance. In file-backed SF mode, terminalizing current receipts
does not append ACK or poison completion records. A newly created sender can
recover the still-unresolved SF frames and replay them.

Not implemented in this slice:

- auth or upgrade rejection detail
- write/internal server error classification
- event polling agreement
- real-server error taxonomy probing
- durable poison files

## Validation checks

Rust unit tests cover:

- the volatile manual driver still returns before ACK and preserves existing
  queue/receipt behaviour through the new seam
- retryable failure resets connection state without completing the receipt
- terminal failure marks unresolved receipts terminal and rejects future
  submissions on the current driver
- terminal failure does not poison recovered SF frames; a recreated SF driver can
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
- an SF-backed driver reopens and replays from the first unresolved FSN with
  wire sequence `0`
- an SF-backed driver persists an ordered reject, poison gap, and later ACK
  across reopen

Targeted validation commands:

```bash
cargo fmt --check --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
```

Result:

- manual driver filter: 28 passed
- widened QWP filter: 97 passed, 2 ignored

## Local reflection

- How does this particular step feel?

  The queue seam is small and mechanical. Running close-drain and retry-budget
  behaviour through the same volatile/SF driver path is the right pressure point
  before adding a real event ring or FFI outcomes.

- What was simpler or more awkward than expected?

  Terminal and closing state are cleaner as driver-layer overlays than as
  durable queue completion records. The awkward part is that `receipt_status()`
  now combines queue state with driver lifecycle state; the production API
  should make that layering explicit so storage recovery, close outcomes, and
  current-sender delivery outcomes do not blur together.

- Did the API or implementation shape create accidental complexity?

  The main complexity is status composition. Queue state, closing state,
  terminal state, and future event-ring state are related but not the same. The
  core should probably expose a small status composer rather than scattering
  these checks across adapters.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It strengthens the distinction between durable facts and current-driver
  outcomes. ACK and poison are durable completion facts. Terminal failure,
  retry-budget exhaustion, and close timeout can affect the current sender
  without destroying recoverable SF data.

- Did this step strengthen or weaken the core assumptions?

  It strengthened them. The same manual driver now exercises volatile and SF
  queues for poison, close, and retry outcomes, and the SF queue can survive
  terminal sender failure or close timeout without being converted into poison
  or data loss.

- Should the next step proceed, or should the design be adjusted first?

  Continue Step 9 only far enough to add event polling agreement. After that,
  Step 10 should validate real-server error taxonomy before any FFI outcome enum
  hardens.
