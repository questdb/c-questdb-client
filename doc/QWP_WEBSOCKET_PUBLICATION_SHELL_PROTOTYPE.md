# QWP/WebSocket publication shell prototype

Date: 2026-04-29

Status: validated Rust-only Step 12 slice.

## Scope

This slice adds the first real publication boundary above the manual
QWP/WebSocket driver.

`questdb-rs/src/ingress/sender/qwp_ws_publisher.rs` owns:

- `QwpWsEncodeScratch`,
- `SymbolGlobalDict`,
- negotiated QWP version,
- `ManualDriverPrototype<Q, T>`.

Its submit path is:

```text
QwpBuffer -> encode_ws_replay_message -> ManualDriverPrototype::try_submit
```

The driver remains payload-opaque. Stored and queued identity is still the
unmasked QWP application payload, not WebSocket frame bytes.

## Validated behavior

- The shell sends the exact replay payload produced by
  `encode_ws_replay_message` to the driver transport.
- Empty QWP buffers are rejected before encoding so `submit()` remains
  receipt-returning only for non-empty publications.
- A queue publication failure returns no receipt and does not consume an FSN.
- The next successful publication after a failed publication uses the next real
  FSN, not a skipped one.
- The local blocking WebSocket transport receives the exact replay payload from
  the shell and ACKs it through the existing manual driver wait path.

Focused tests:

```text
publisher_sends_replay_payload_to_driver_transport
publisher_rejects_empty_buffer_without_publication
publisher_failed_queue_publication_does_not_consume_fsn
blocking_real_ws_transport_sends_publication_replay_payload
```

Validation run:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml qwp_ws
cargo test --manifest-path questdb-rs/Cargo.toml \
    --no-default-features \
    --features _sender-qwp-ws,tls-webpki-certs,ring-crypto \
    qwp_ws_driver
cargo test --manifest-path questdb-rs/Cargo.toml \
    --features async-sender-qwp-ws \
    qwp_ws_async
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Observed result:

```text
qwp_ws_driver: 47 passed
qwp_ws: 126 passed, 6 ignored
minimal _sender-qwp-ws driver filter: 43 passed, with existing unused-code warnings
qwp_ws_async with async-sender-qwp-ws: 8 passed
format and whitespace checks passed
```

## Local reflection

- This is simpler than making the driver understand buffers. The driver owns
  ordering, receipts, reconnect, and transport progress; the shell owns replay
  materialization.
- The shell does not need dictionary checkpoint/rollback. A failed queue
  publication can reserve internal symbol IDs, but no bytes are published, no
  FSN is assigned, no receipt is returned, and no wire sequence is consumed.
- The old sync `qwpws` sender path is untouched. This keeps the prototype from
  becoming product integration before the architecture is proven.

## Global reflection

- The architecture still holds: `Buffer -> replay payload -> queue -> driver ->
  transport` is now an executable path.
- The remaining Step 12 uncertainty is not the local component boundary. It is
  real QuestDB behavior through this path: submit/wait, reconnect replay,
  close/EOF, auth/upgrade failure, and retryable/server-failure taxonomy.
- The product Store-and-Forward queue is still the largest structural gap. The
  current durable queue prototype uses the old custom journal; product work must
  move to the Java-compatible `.sfa` segment ring.

## Recommended next step

The real QuestDB submit/wait path is now covered by
`doc/QWP_WEBSOCKET_PUBLICATION_E2E_PROBE.md`.

Add a reconnect replay case through the same publication shell and
`BlockingQwpWsTransport`, using a fault proxy in front of real QuestDB. After
that, connect this publication shell to the Java-compatible `.sfa` queue design
rather than extending the old custom SF journal.
