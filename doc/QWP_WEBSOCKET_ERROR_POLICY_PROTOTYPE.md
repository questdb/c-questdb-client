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
- `DriverError::Storage` and `DriverError::CorruptLog` so storage failures do
  not collapse into delivery outcomes

The important behavioural distinction is that terminal failure belongs to the
current sender instance. In file-backed SF mode, terminalizing current receipts
does not append ACK or poison completion records. A newly created sender can
recover the still-unresolved SF frames and replay them.

Not implemented in this slice:

- close-drain semantics
- reconnect budget counters
- auth or upgrade rejection detail
- write/internal server error classification
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
- an SF-backed driver reopens and replays from the first unresolved FSN with
  wire sequence `0`
- an SF-backed driver persists an ordered reject, poison gap, and later ACK
  across reopen

Targeted validation commands:

```bash
cargo fmt --manifest-path questdb-rs/Cargo.toml
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
```

Result:

- manual driver filter: 22 passed
- widened QWP filter: 91 passed, 2 ignored

## Local reflection

- How does this particular step feel?

  The queue seam is small and mechanical. Running the same driver against the
  SF queue is the right pressure point before adding more policy states.

- What was simpler or more awkward than expected?

  Terminal state is cleaner as a driver-layer overlay than as a durable queue
  completion record. The awkward part is that `receipt_status()` now combines
  queue state with driver terminal state; the production API should make that
  layering explicit so storage recovery and current-sender delivery outcomes do
  not blur together.

- Did the API or implementation shape create accidental complexity?

  Not yet, but terminal handling is the first sign that queue state and sender
  lifecycle state must remain separate. If later close-drain or reconnect-budget
  work needs more overlays, the core should probably expose a small status
  composer rather than scattering these checks across adapters.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It strengthens the distinction between durable facts and current-driver
  outcomes. ACK and poison are durable completion facts. Terminal failure can
  end the current sender and current receipts without destroying recoverable SF
  data.

- Did this step strengthen or weaken the core assumptions?

  It strengthened them. The same manual driver can now exercise volatile and SF
  queues, and the SF queue can survive terminal sender failure without being
  converted into poison or data loss.

- Should the next step proceed, or should the design be adjusted first?

  Continue Step 9 before moving to Step 10. The next slice should add close-drain
  and reconnect-budget behaviour through the same queue seam, then Step 10
  should validate real-server error taxonomy before any FFI outcome enum hardens.
