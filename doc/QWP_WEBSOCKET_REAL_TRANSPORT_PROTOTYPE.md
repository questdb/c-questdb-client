# QWP/WebSocket real transport prototype

Date: 2026-04-29

Status: Step 12 Rust-only transport slice.

This note records the first real WebSocket transport adapter behind the manual
driver seam. It does not make the new pipelined sender a public product API and
does not wire the C ABI shape stubs to the real queue/driver core.

## Implemented slice

- Added a blocking `BlockingQwpWsTransport` behind `ManualDriverTransport`.
- Reused the existing sync QWP/WebSocket TCP, TLS, HTTP upgrade, frame write,
  and frame read helpers.
- Kept the driver boundary in terms of borrowed unmasked QWP payload bytes.
- Preserved the two-phase send rule: a frame is committed `Sent` only after the
  local WebSocket write and flush succeeds.
- Parsed real QWP/WebSocket responses into driver `Ack`, `Reject`, retryable
  transport failure, or terminal transport failure.
- Covered plain WS, WSS, and a cumulative ACK after multiple sends against
  in-process mock servers.
- Fixed the existing sync and async QWP/WebSocket senders so an encode failure
  does not consume the next wire sequence.

## Validation run

```bash
cargo test --manifest-path questdb-rs/Cargo.toml encode_failure_does_not_consume_sequence
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml blocking_real_
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
cargo test --manifest-path questdb-rs/Cargo.toml --features async-sender-qwp-ws qwp_ws_async
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Observed result:

```text
encode_failure_does_not_consume_sequence: 1 passed
qwp_ws_driver: 43 passed
blocking_real_: 3 passed
qwp_ws: 113 passed, 3 ignored
qwp_ws_async with async-sender-qwp-ws: 8 passed
format and diff whitespace checks passed
```

The ignored `qwp_ws` tests are the existing real-server probes gated by
environment variables.

## Local reflection

- The real blocking transport fit the manual driver seam without changing the
  queue, receipt, or public API shape.
- Reusing the existing sync connection and frame helpers kept this slice small,
  but it required making the upgrade helper visible within the sender module.
- A blocking read in `poll_response` forced the real transport to prefer sending
  queued frames before polling, while fake transports keep poll-first behavior
  for protocol-error tests.
- The response parser had already been shaped for pipelined async use; sharing
  it with the manual transport was simpler than adding a sync-specific parser.
- The one unexpected implementation detail was the existing sequence-advance
  bug: both sync and async senders consumed a sequence before encoding could
  fail. Fixing that first made the transport tests less likely to preserve a
  bad invariant.
- This slice still submits opaque QWP payload bytes directly to the queue. The
  next product-path slice should insert the missing publication shell that
  encodes caller `Buffer` contents into self-sufficient replay payloads before
  queue publication.
- That publication shell should keep replay dictionary state simple and
  append-only. Failed submissions may reserve internal symbol IDs, but the
  externally visible commit point remains queue publication: no FSN, receipt,
  queued bytes, wire sequence, or caller-buffer clear before that succeeds.

## Global reflection

- Step 12 can continue without changing the core Store-and-Forward design.
- The earlier fake transport was predictive for the two-phase send boundary:
  real WebSocket I/O still fits `send_frame` followed by queue `commit_sent`.
- Local mock WS/WSS coverage validates client-side upgrade, masking, TLS,
  cumulative ACK dispatch, and response parsing, but it is not a substitute for
  a real QuestDB probe.
- The next useful gate is a real-server manual-driver probe for valid
  submit/wait and reconnect replay through `Buffer -> replay payload -> queue ->
  BlockingQwpWsTransport`.
