# QWP/WebSocket publication real-server probe

Date: 2026-04-29

Status: real QuestDB e2e publication path validated.

## Scope

This probe validates the prototype publication path against a real QuestDB
server:

```text
Buffer -> replay payload -> volatile queue -> manual driver -> BlockingQwpWsTransport -> QuestDB
```

It does not use the old sync `qwpws` sender path and does not assert internal
driver state.

## Test

`questdb-rs/src/tests/qwp_ws_publication_probe.rs` contains the ignored,
environment-gated test:

```text
qwp_ws_publication_driver_submit_waits_and_row_is_queryable
```

The test:

- creates a unique table name,
- submits a real QWP buffer through `QwpWsPublicationDriver`,
- waits for the returned receipt through the manual driver,
- queries QuestDB over HTTP until the row is visible,
- verifies the inserted symbol, long, and double values.

Run command:

```bash
QDB_QWP_WS_PUBLICATION_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_publication_driver_submit_waits_and_row_is_queryable \
    -- --ignored --nocapture
```

Default environment:

```text
QDB_QWP_WS_HOST=127.0.0.1
QDB_QWP_WS_PORT=9000
QDB_QWP_WS_HTTP_PORT=$QDB_QWP_WS_PORT
```

`QDB_QWP_WS_AUTH_HEADER` is supported for authenticated servers.

## Observed Result

Run against a local QuestDB server:

```text
QuestDB build: Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown
qwp_ws_publication_driver_submit_waits_and_row_is_queryable ... ok
```

The probe passed: the row became queryable with the expected values.

## Local Reflection

- The publication shell works as a real client path, not only as a local mock
  boundary.
- The test asserts user-visible behavior: receipt wait succeeds and the row is
  queryable. It intentionally does not assert `sent_frames`, event order,
  `fsn_at_zero`, or other internal mechanics.
- The crate-private test hook is limited to prototype tests and does not change
  the public API.

## Global Reflection

- This removes the biggest uncertainty from the last slice: the publication
  shell and blocking transport can ingest through a real QuestDB server.
- Reconnect remains the next protocol-level uncertainty. The next e2e should
  use a fault proxy in front of real QuestDB to prove that ACKed frames are not
  replayed, unresolved frames are replayed, and the replayed frame is accepted
  on a fresh server connection with wire sequence `0`.
- Java-compatible `.sfa` integration should still wait until reconnect is proven
  through the same real publication path.
