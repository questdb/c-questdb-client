# QWP/WebSocket publication real-server probe

Date: 2026-04-29

Status: real QuestDB e2e publication and reconnect path validated.

## Scope

This probe validates the prototype publication path against a real QuestDB
server:

```text
Buffer -> replay payload -> volatile queue -> manual driver -> BlockingQwpWsTransport -> QuestDB
```

It does not use the old sync `qwpws` sender path and does not assert internal
driver state.

The reconnect variant places a small fault proxy between
`BlockingQwpWsTransport` and QuestDB. The proxy forwards the first frame and its
ACK, reads but drops the second frame before QuestDB sees it, closes the client
connection, then accepts the reconnect and forwards the replayed second frame to
QuestDB.

## Test

`questdb-rs/src/tests/qwp_ws_publication_probe.rs` contains the ignored,
environment-gated tests:

```text
qwp_ws_publication_driver_submit_waits_and_row_is_queryable
qwp_ws_publication_driver_reconnect_replays_only_unacked_rows
```

The submit/wait test:

- creates a unique table name,
- submits a real QWP buffer through `QwpWsPublicationDriver`,
- waits for the returned receipt through the manual driver,
- queries QuestDB over HTTP until the row is visible,
- verifies the inserted symbol, long, and double values.

The reconnect test:

- submits two real QWP buffers through `QwpWsPublicationDriver`,
- proves the first row is ACKed before the forced disconnect,
- drops the second frame before QuestDB receives it,
- lets the driver reconnect through the same transport seam,
- verifies the second receipt is ACKed after replay,
- queries QuestDB and verifies exactly two expected rows are visible.

Run commands:

```bash
QDB_QWP_WS_PUBLICATION_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_publication_driver_submit_waits_and_row_is_queryable \
    -- --ignored --nocapture

QDB_QWP_WS_RECONNECT_PROBE=1 \
    cargo test --manifest-path questdb-rs/Cargo.toml \
    qwp_ws_publication_driver_reconnect_replays_only_unacked_rows \
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
qwp_ws_publication_driver_reconnect_replays_only_unacked_rows ... ok
```

Both probes passed. The submit/wait row became queryable with the expected
values. The reconnect probe observed two ACKed receipts and exactly two
queryable rows, so the already-ACKed first row was not duplicated and the
unresolved second row was replayed after reconnect.

## Local Reflection

- The publication shell works as a real client path, not only as a local mock
  boundary.
- The tests assert user-visible behavior: receipt waits succeed and rows are
  queryable. They intentionally do not assert `sent_frames`, event order,
  `fsn_at_zero`, or other internal mechanics.
- The fault proxy is deliberately narrow. It proves the reconnect/replay
  behavior we need without becoming a second fake QuestDB implementation.
- The crate-private test hook is limited to prototype tests and does not change
  the public API.

## Global Reflection

- This removes the biggest uncertainty from the last slice: the publication
  shell, blocking transport, reconnect, and replay can ingest through a real
  QuestDB server.
- The next architecture risk is no longer the volatile publication path. It is
  wiring this path to the Java-compatible `.sfa` segment-ring queue without
  changing public API semantics or storing connection-local state.
