# QWP/WebSocket Step 10 error taxonomy probe

Date: 2026-04-28

Status: real-server probe passed against a local `questdb-arrays` QuestDB
development server after the server-side value/type taxonomy fix.

This probe validates server error status, frame sequence, and post-error
connection behavior before the Rust/FFI outcome enums harden.

## Probe scope

Added an ignored real-server probe:

```text
tests::qwp_ws_protocol_probe::qwp_ws_real_server_error_taxonomy_probe
```

Source:

```text
questdb-rs/src/tests/qwp_ws_protocol_probe.rs
```

Run command:

```bash
env QDB_QWP_WS_ERROR_TAXONOMY_PROBE=1 cargo test \
  --manifest-path questdb-rs/Cargo.toml \
  qwp_ws_real_server_error_taxonomy_probe \
  -- --ignored --nocapture
```

Server build reported by the probe:

```text
Build Information: unknown [DEVELOPMENT], JDK unknown, Commit Hash unknown
```

The probe also checked the current server source in `questdb-arrays`:

- `core/src/main/java/io/questdb/cutlass/qwp/protocol/QwpConstants.java`
- `core/src/main/java/io/questdb/cutlass/qwp/server/QwpProcessorState.java`
- `core/src/main/java/io/questdb/cutlass/qwp/server/QwpWebSocketUpgradeProcessor.java`
- `core/src/test/java/io/questdb/test/cutlass/qwp/e2e/QwpSenderE2ETest.java`

The source confirms the status constants. Server-side coverage also asserts that
deterministic string-to-DOUBLE coercion failure is surfaced as
`SCHEMA_MISMATCH`, not `WRITE_ERROR`.

## Observed cases

Each case sent three frames on one WebSocket connection:

```text
sequence 0: valid frame
sequence 1: bad frame for the case
sequence 2: valid frame
```

### Malformed QWP frame

Bad frame:

```text
not-a-qwp-frame
```

Observed:

```text
responses before error: [Ok { sequence: 0 }]
error: status=0x05, sequence=1
message: "message version 97 does not match negotiated version 1"
post-error observation: Response(Ok { sequence: 2 })
visible valid rows: 2
```

Conclusion: malformed QWP bytes are frame-local poison candidates. The server
reports frame sequence `1` and continues far enough to ACK a later valid frame.

### Parse-time schema mismatch

Bad frame:

```text
schema-reference payload with the table-header column count mutated from 4 to 5
```

Observed:

```text
responses before error: [Ok { sequence: 0 }]
error: status=0x03, sequence=1
message: "schema column count mismatch: header=5, schema=4"
post-error observation: Response(Ok { sequence: 2 })
visible valid rows: 2
```

Conclusion: parse-time schema mismatch is also a frame-local poison candidate.
The server reports frame sequence `1` and continues far enough to ACK a later
valid frame.

### Value/type coercion error

Bad frame:

```text
column `px` sent as STRING after the table established `px` as DOUBLE
```

Observed:

```text
responses before error: [Ok { sequence: 0 }]
error: status=0x03, sequence=1
message: "cannot parse DOUBLE from string [value=not-a-double, column=px]"
post-error observation: Response(Ok { sequence: 2 })
visible valid rows: 2
```

Conclusion: this deterministic value/type conflict is surfaced as
`SCHEMA_MISMATCH`. It is sequence-specific and the connection can continue to
resolve a later valid frame.

## Design impact

Confirmed for these cases:

- error responses identify the rejected frame by WebSocket/QWP sequence,
- successful prior frames can be ACKed before the error,
- a later valid in-flight frame can be ACKed after the error,
- parse/schema/coercion failures are not necessarily terminal to the connection.

Implications for the client design:

- `PARSE_ERROR` and `SCHEMA_MISMATCH` should be frame-level poison by default.
- The fixed server taxonomy keeps deterministic value/type bad data out of
  `WRITE_ERROR`, so `WRITE_ERROR` can remain a narrower operational write
  failure bucket.
- Without a server-provided `disposition`, v1 client policy should remain
  conservative for ambiguous statuses: surface the status/message/sequence and
  avoid inventing retry semantics.

Deferred:

- auth or upgrade rejection taxonomy,
- internal-error taxonomy,
- deterministic retryable write failure setup.

## Local reflection

- How does this particular step feel?

  The real-server behavior is stronger than the mock assumption in one useful
  way: deterministic value/type errors are now both correctly classified as
  schema mismatch and still sequence-local.

- What was simpler or more awkward than expected?

  Malformed parse and schema-reference mismatch were straightforward. The
  value/type conflict now surfaces as `SCHEMA_MISMATCH`, which makes the client
  policy simpler than the first server observation.

- Did the API or implementation shape create accidental complexity?

  No new API complexity appeared. The fix removes the need to special-case
  deterministic coercion failures under `WRITE_ERROR`, but low-level callers
  should still receive the raw status and message.

## Global reflection

- How does this fit into the bigger QWP/WebSocket Store-and-Forward design?

  It supports the frame-level quarantine model. The server can reject one frame,
  ACK prior frames, and still ACK later frames. SF recovery can therefore keep
  poison as a per-FSN completion fact rather than terminalizing the whole queue.

- Did this step strengthen or weaken the core assumptions?

  It strengthened the sequence, poison-gap, and schema-mismatch taxonomy
  assumptions.

- Should the next step proceed, or should the design be adjusted first?

  Proceed with the existing design direction. The FFI should still carry raw
  `qwp_status` and message details, but deterministic value/type failures no
  longer force `WRITE_ERROR` to be treated as poison-capable by default.
