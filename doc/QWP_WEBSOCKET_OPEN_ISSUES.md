# QWP/WebSocket — Open Issues

Single tracker for known QWP/WebSocket bugs, spec-compliance gaps,
intentionally-deferred features, and review nits. Replaces the older
per-topic tracker docs.

Closed items are not tracked here; consult `git log` for history.

---

## Bugs (code-side, actionable)

### B1. Orphan drainer trims on ordinary OK regardless of durable-ACK mode

When `request_durable_ack=on`, the orphan drainer still trims slot segments on
ordinary `STATUS_OK` instead of waiting for `STATUS_DURABLE_ACK`. Java parity
requires trim-on-durable-ACK only when durable-ACK is configured.

- Code: `questdb-rs/src/ingress/sender/qwp_ws_orphan.rs`
- Severity: blocks delivery parity with Java for durable-ACK senders.

### B2. FFI bookmark entrypoints do not null-check the buffer argument

`line_sender_buffer_bookmark`, `line_sender_buffer_rewind_to_bookmark`, and
`line_sender_buffer_clear_bookmark` dereference `buffer` via
`unwrap_buffer_mut(buffer)` without first null-checking it.
`line_sender_buffer_bookmark` checks the `out` param but not `buffer`.

- Code: `questdb-rs-ffi/src/lib.rs:949, 964, 977`

### B3. `SenderBuilder::protocol_version()` does not reject WebSocket transports

The setter rejects QWP/UDP but does not reject `qwpws`/`qwpwss`; the cfg-gate
covers only `_sender-qwp-udp`. WebSocket transports should error the same way.

- Code: `questdb-rs/src/ingress.rs:1158-1164`

### B4. `QwpWsSenderError` is missing fields claimed as Java-parity

The Rust struct omits `table_name` and `detected_at_nanos`/`detection_timestamp`
that the public docs and Java `SenderError` describe. Decide: add the fields
or correct the docs to describe the subset.

- Code: `questdb-rs/src/ingress/sender/qwp_ws_ownership.rs:49-67`
- Doc: `doc/QWP_WEBSOCKET_ERROR_HANDLING.md` already notes Rust mirrors the
  Java shape minus these two fields — keep that disclaimer in sync.

### B5. `QwpWsColumnarBuffer::len()` size hint can underestimate

The pre-encoding length estimate does not account for connection-global symbol
dictionary growth or varint length shifts. `max_buf_size` is enforced against
the estimate, so an encoded frame can exceed the limit after encoding.

- Code: `questdb-rs/src/ingress/buffer/qwp.rs:2234-2260`
- Sender preflight: same file, ~lines 260-270.

### B6. `crc32c` and `memmap2` are unconditional dependencies

These crates are only used by `_sender-qwp-ws`. They should be gated to the
feature so non-WS builds do not pull them.

- Code: `questdb-rs/Cargo.toml:44-45`

### B7. FFI flush family lacks `catch_unwind` panic guards

`line_sender_flush*` calls into Rust without `catch_unwind`. A Rust panic
unwinding across the FFI boundary is UB.

- Code: `questdb-rs-ffi/src/lib.rs` (flush entrypoints ~lines 2910-2930)

---

## Spec-compliance gaps still open

### S1. Durable OK coalescing semantics

Whether a single `STATUS_DURABLE_ACK` may coalesce multiple acknowledgments
and what the carried FSN means in that case still needs explicit live-server
validation. The Rust driver currently assumes the same coalescing rules as
ordinary OK.

- Code: `questdb-rs/src/ingress/sender/qwp_ws_driver.rs:361-465`

### S2. `close_flush_timeout_millis` close-drain parity with Java

The config key is parsed and routed, but the close-drain behavior does not
fully match Java's close-flush sequence (final flush within the timeout, then
explicit close handshake observation). Intentionally deferred.

- Code: `questdb-rs/src/ingress.rs:760, 1537-1552`
- Public surface: `Sender::close_drain` honors the timeout for the local
  publication wait only.

---

## Deferred features / known limitations

These are intentional. Listed so we do not relitigate them silently.

- **`sf_durability=flush|append` modes**: parsed but rejected. Append-deadline
  backpressure not implemented.
- **`max_schemas_per_connection`, `error_inbox_capacity`**: parsed but
  rejected.
- **`initial_connect_retry=async`**: implemented in background mode; manual
  mode still rejects it by design.
- **`drain_orphans=on`**: runtime exists, but Java-parity observability
  (counters, listeners) is not exposed.
- **Halting-server real-server coverage**: deliberately not part of the public
  test surface.
- **C example programs for QWP/WebSocket APIs**: no example covers
  `close_drain`, `await_acked_fsn`, or `poll_qwp_ws_error`. Only QWP/UDP
  examples exist under `examples/`.
- **High-level runner ergonomics (Step 13 of the validation plan)**:
  non-blocking socket send / reconnect / poll slices live outside the
  publication mutex. Deadline + backpressure surface and rejection
  observability on the high-level `flush()` are still in progress.
- **Connect/retry unification**: foreground reconnect and orphan-drainer
  reconnect share no helper. Each carries its own host-health tracker.
- **Broader dead-code audit**: `qwp_ws_driver.rs` and `qwp_ws_sfa_queue.rs`
  still use file-level `#![allow(dead_code)]`. Segment file already cleaned.

---

## Review-tracker leftovers

Open items from prior review passes (CodeRabbit / Vlad / self-review) that
are not bugs but still actionable. The original trackers are gone — `git log`
is the source of truth for review history.

### Documentation hygiene

- ~13 markdown files reference absolute machine-local paths (e.g.
  `/home/jara/devel/oss/questdb-arrays/...`). After this cleanup, surviving
  references are inside the three keeper docs. Adopt a shared placeholder
  convention (`${JAVA_CLIENT_DIR}`) before publishing externally.
- `peek()` docblock in `include/questdb/ingress/line_sender.h:521-528`
  documents QWP/UDP semantics only — extend to cover the QWP/WebSocket case.
- `poll_qwp_ws_error()` docblock (`line_sender.h:1433-1441`) should clarify
  ownership of the returned view.
- `close_drain` doc should state which config key sources the timeout and how
  timeout failures are reported.
- Config key spelling: confirm public surfaces use `qwp_ws_progress=manual`
  (the parsed form) consistently in user-facing docs.

### Test coverage gaps

- Schema-evolution coverage in `TestQwpWsProtocol` (system test) needs to be
  separated from durable-ACK-ordering coverage; the latter is still missing.
- Background-pool concurrency capping needs explicit test coverage
  (`max_background_drainers` boundary cases).
