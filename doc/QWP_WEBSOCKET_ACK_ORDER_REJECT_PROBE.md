# QWP/WebSocket Step 7 ACK/order/reject probe

Date: 2026-04-28

Status: validation note for Step 7 of
`doc/QWP_WEBSOCKET_VALIDATION_PLAN.md`.

## Probe scope

Added an ignored real-server probe:

```text
tests::qwp_ws_protocol_probe::qwp_ws_real_server_ack_order_and_reject_probe
```

Source:

```text
questdb-rs/src/tests/qwp_ws_protocol_probe.rs
```

The probe uses raw QWP/WebSocket transport helpers and normal
connection-scoped QWP encoding. It intentionally does not use the volatile
queue, fake manual driver, disk Store-and-Forward, C FFI, threaded adapter, or
Tokio adapter.

The probe is enabled with:

```bash
QDB_QWP_WS_PROTOCOL_PROBE=1 cargo test \
  --manifest-path questdb-rs/Cargo.toml \
  qwp_ws_real_server_ack_order_and_reject_probe \
  -- --ignored --nocapture
```

Environment knobs:

- `QDB_QWP_WS_HOST`, default `127.0.0.1`
- `QDB_QWP_WS_PORT`, default `9000`
- `QDB_QWP_WS_HTTP_PORT`, default same as `QDB_QWP_WS_PORT`
- `QDB_QWP_WS_AUTH_HEADER`, optional
- `QDB_QWP_WS_KEEP_TABLE=1`, optional debugging aid

## Observed server

The probe ran against the local QuestDB server available during validation.

Observed build string:

```text
Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown
```

## Scenario 1: multiple successful frames in flight

The probe sends three valid QWP/WebSocket frames back-to-back on one connection
without reading between writes.

Observed OK sequences:

```text
[1, 2]
```

Interpretation:

- QuestDB can coalesce successful ACKs.
- `OK(sequence=1)` covered frames `0` and `1`.
- `OK(sequence=2)` covered frame `2`.
- All three rows became queryable.

This validates that a client may treat OK sequence `N` as cumulative ACK for
all lower unresolved successful frames on that connection.

## Scenario 2: good / malformed / good

The probe sends:

```text
sequence 0: valid QWP frame
sequence 1: malformed frame
sequence 2: valid QWP frame
```

Observed responses:

```text
before error: [Ok { sequence: 0 }]
error: status=0x05, sequence=1,
       message="message version 97 does not match negotiated version 1"
after error: Ok { sequence: 2 }
```

Both valid rows, before and after the malformed frame, became queryable.

Interpretation:

- QuestDB reports the malformed frame as an error for its own sequence.
- A later valid frame can still be accepted and ACKed after the error frame is
  resolved.
- The client must not treat a server error for sequence `N` as terminal for all
  later in-flight frames.
- Later receipts remain unresolved after the error until a later OK or error
  response resolves them.

This matches the Step 6 fake-driver test that ACKs a later receipt after an
ordered rejection.

## Close behavior

This probe did not establish a separate close-drain contract. In the malformed
frame scenario, the connection remained usable long enough for the server to
return `OK(sequence=2)` after `Error(sequence=1)`.

A later close-specific probe should still cover:

- client close after unresolved in-flight frames
- server close/EOF while frames are in flight
- whether close implies drained, retryable, or terminal state

## Local reflection

- How does this particular step feel?

  The ACK/order model is stronger after the real-server check. The server
  behavior is compatible with cumulative ACKs and ordered per-sequence errors,
  but it is less conservative than "error stops later frames": later valid
  frames can still complete.

- What was simpler or more awkward than expected?

  Successful pipelining was straightforward. The important awkwardness was the
  good/malformed/good scenario: the initial probe assertion expected no later
  ACK after the malformed frame, but the server correctly resolved the later
  frame with `OK(sequence=2)`.

- Did the API or implementation shape create accidental complexity?

  The fake driver already had the right shape after the prior test-gap fix:
  an error resolves only that receipt, prior frames can be ACKed, and later
  receipts remain pending until a later response resolves them.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It validates the core response-dispatch assumption needed before durable
  storage: receipt completion must be per sequence, with cumulative OK handling
  and non-terminal ordered errors.

- Did this step strengthen or weaken the core assumptions?

  It strengthened the cumulative ACK assumption and refined the rejection
  assumption. Server errors are not connection-terminal by definition.

- Should the next step proceed, or should the design be adjusted first?

  Proceed, but keep close semantics separate. Before disk Store-and-Forward is
  hardened, add either a close-specific real-server probe or treat close/EOF as
  retryable until proven drained or terminal by explicit protocol behavior.
