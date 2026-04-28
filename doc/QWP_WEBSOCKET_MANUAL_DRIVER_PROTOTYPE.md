# QWP/WebSocket Step 6 manual driver prototype

Date: 2026-04-28

Status: validation note for Step 6 of
`doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Prototype scope

Implemented a manual driver prototype in:

```text
questdb-rs/src/ingress/sender/qwp_ws_driver.rs
```

The prototype composes the Step 5 volatile queue with a fake ordered server. It
intentionally does not use real WebSocket I/O, C FFI, threaded adapters, Tokio,
durable Store-and-Forward files, close drain, or real wall-clock timers.

The driver validates:

- `try_submit()` returns after local queue publication only
- blocking submit can drive progress only to make local queue capacity
- `drive_once()` takes `&mut self` and performs at most one progress unit
- `wait_steps()` drives progress until a receipt is ACKed, poisoned, or times out
- cumulative and coalesced ACKs complete covered receipts
- disconnects and retryable transport failures restart replay from the oldest
  unresolved FSN
- deterministic ordered rejection ACKs prior frames, poisons the rejected frame,
  and leaves later frames unresolved

The queue was extended with an in-memory `Poisoned` receipt state so the fake
driver can model deterministic server rejection. This is not a durable poison
policy and does not add poison files.

## Validation checks

Rust unit tests cover:

- submit returns before ACK
- empty submit returns an API error without a receipt
- blocking submit drives only until local capacity frees
- blocking submit times out when capacity does not free
- blocking submit propagates non-backpressure errors
- `drive_once()` sends until `max_in_flight`
- wait drives until receipt ACK
- wait returns immediately for already completed receipts
- wait returns an already completed receipt before driving more work
- wait on an unknown receipt is an API error
- coalesced ACK completes multiple receipts
- disconnect replays from oldest unresolved with wire sequence reset to `0`
- retryable transport failure does not complete receipts
- ordered reject ACKs prior frame and leaves later frame unresolved
- later ACK after ordered reject completes the later receipt
- wait reports poisoned receipt
- wait timeout leaves the receipt valid and pending
- fake response before a connection exists is a protocol error

Targeted validation commands:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_queue
```

Result:

- driver: 18 passed
- queue: 26 passed

## Local reflection

- How does this particular step feel?

  The manual-driver shape is readable. `submit` as local publication and `wait`
  as delivery observation remain distinct under pressure from capacity,
  coalesced ACKs, retryable transport failures, and ordered rejection.

- What was simpler or more awkward than expected?

  Reconnect replay was simple because the queue already has `fsn_at_zero` and
  connection-local wire sequence state. Ordered rejection was more awkward: the
  queue needs a non-ACK terminal receipt state even before durable poison policy
  exists, otherwise `wait()` cannot report a rejected receipt cleanly.

- Did the API or implementation shape create accidental complexity?

  The main accidental-complexity risk is overloading one queue error path for
  local capacity, protocol errors, and delivery outcomes. Keeping
  `SubmitTimedOut`, `DeliveryOutcome::Timeout`, `Poisoned`, and queue protocol
  errors separate made the tests clearer.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It validates the threadless progress-owner model with realistic control flow:
  the same owner publishes, drives, waits, handles retryable failures, and maps
  server responses back to value receipts.

- Did this step strengthen or weaken the core assumptions?

  It strengthened them. The queue, receipt, and replay cursor model still holds
  when ACKs are coalesced and when transport failure forces replay from the
  oldest unresolved frame.

- Should the next step proceed, or should the design be adjusted first?

  Proceed to Step 7: a narrow real-server ACK/order/close probe. Before adding
  disk Store-and-Forward or public FFI, validate that the fake ordered server's
  assumptions match real QuestDB behavior when multiple frames are sent without
  waiting for per-frame responses.
