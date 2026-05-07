# QWP/WebSocket columnar buffer review findings

Date: 2026-05-07

Status: open review findings for the current Rust working-copy
`QwpWsColumnarBuffer` implementation. This document is a handoff for the next
fixing pass; it is not a design proposal.

Related design:

- `doc/QWP_WEBSOCKET_COLUMNAR_BUFFER_DESIGN.md`

Relevant Rust paths:

- `questdb-rs/src/ingress/buffer.rs`
- `questdb-rs/src/ingress/buffer/qwp.rs`
- `questdb-rs/src/ingress/sender.rs`
- `questdb-rs/src/ingress/sender/qwp_ws.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_publisher.rs`

Relevant Java reference paths:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/protocol/QwpTableBuffer.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpColumnWriter.java`

## Summary

The columnar buffer is already wired into the production QWP/WebSocket sender
path. `Sender::new_buffer()` returns `BufferInner::QwpWs` for QWP/WebSocket
senders, and QWP/WebSocket flush expects `as_qwp_ws()`.

The main implementation shape is correct enough to continue: the new buffer
covers all public value APIs, the replay encoder emits full-schema replay
frames, and focused tests cover duplicate first-value-wins, case-insensitive
columns, row rollback, table grouping, and row-log parity.

Do not commit the current working copy until the findings below are resolved.

## Open Findings

### P1: cloned QWP/WS buffers accept source-buffer bookmarks

`QwpWsColumnarBuffer` currently derives `Clone`, so cloned buffers copy
`bookmark_meta`, `bookmark`, and `snapshots` as-is. `StoredBookmark::restore`
accepts a bookmark when origin and generation match, so a bookmark captured on
the source buffer can be used on the clone.

Evidence:

- `QwpWsColumnarBuffer` derives `Clone` and owns `bookmark_meta`, `bookmark`,
  and `snapshots`: `questdb-rs/src/ingress/buffer/qwp.rs:2013-2023`.
- Public `Buffer` derives `Clone`, so `BufferInner::QwpWs` is cloned through
  public/FFI buffer cloning: `questdb-rs/src/ingress/buffer.rs:180-197`.
- `StoredBookmark::restore()` trusts matching origin and generation:
  `questdb-rs/src/ingress/buffer.rs:130-152`.
- Existing ILP and QWP/UDP clones intentionally allocate a fresh
  `BufferBookmarkMeta` while preserving the stored rewind payload:
  `questdb-rs/src/ingress/buffer/ilp.rs:444-454` and
  `questdb-rs/src/ingress/buffer/qwp.rs:841-863`.

Expected fix:

- Replace derived `Clone` for `QwpWsColumnarBuffer` with a manual implementation.
- Clone live table data and snapshots as needed, but assign
  `bookmark_meta: BufferBookmarkMeta::new()`.
- Preserve `bookmark` state so marker-style rewind behavior on the clone stays
  consistent with ILP/QWP, while explicit bookmarks from the source buffer fail
  on the clone.
- Add a regression test matching the existing QWP/UDP cross-buffer bookmark
  behavior for a QWP/WebSocket buffer.

### P2: duplicate column with a different type is silently ignored

The QWP/WebSocket buffer implements Java-like first-value-wins duplicate
handling, but the type check happens after the duplicate early return. This
means a same-row duplicate with a different type is accepted and ignored.

Example:

```rust
buf.table("trades")?
    .column_i64("qty", 1)?
    .column_bool("QTY", true)?
    .at_now()?;
```

Current Rust behavior: succeeds and encodes only the first `qty` value.

Expected Java-like behavior: fail with a type mismatch. Java validates type
during lookup before duplicate skipping:

- `QwpTableBuffer.getOrCreateColumn(...)` calls `lookupColumn(...)` before the
  duplicate check.
- `lookupColumn(...)` calls `assertColumnType(...)` on both fast and slow paths.

Evidence:

- Rust duplicate early return occurs before type check:
  `questdb-rs/src/ingress/buffer/qwp.rs:2499-2513`.
- Java `getOrCreateColumn(...)` lookup-before-duplicate shape:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/protocol/QwpTableBuffer.java:208-220`.
- Java fast-path type assertion:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/protocol/QwpTableBuffer.java:420-428`.
- Java slow-path type assertion:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/protocol/QwpTableBuffer.java:432-437`.

Expected fix:

- Move the `table.columns[col_idx].kind != kind` check before the duplicate
  early return.
- Add a regression test for same-row, case-insensitive duplicate with different
  type.
- Keep same-type duplicates first-value-wins.

### P2: QWP/WS size hint is not the encoded replay frame size

`Sender::flush_qwp_ws_buffer()` enforces `max_buf_size` using
`QwpWsColumnarBuffer::len()` before encoding. The current `len()` is only a
local estimate and can differ from the replay payload actually written by
`QwpWsReplayEncoder`.

Known mismatches:

- `len()` starts with `QWP_MESSAGE_HEADER_SIZE + 2`, then later adds the two
  replay dictionary varints again.
- `len()` sizes schema IDs as `QWP_INLINE_SCHEMA_ID`, while replay encoding
  uses a per-message schema id from `intern_replay_schema_signature()`.
- `len()` estimates symbol column row ids from local column-local ids, while
  encoding writes connection-global ids.
- `len()` estimates only local symbol dictionary entries, while replay encoding
  writes a dense connection-global prefix from id 0 through the highest global
  id referenced by the frame.

Evidence:

- Sender max-size preflight uses `qwp.len()`:
  `questdb-rs/src/ingress/sender.rs:260-270`.
- `QwpWsColumnarBuffer::len()` local estimate:
  `questdb-rs/src/ingress/buffer/qwp.rs:2054-2079`.
- Replay encoder global symbol pre-pass and dense prefix:
  `questdb-rs/src/ingress/buffer/qwp.rs:2673-2700`.
- Symbol payload writes global ids, not local ids:
  `questdb-rs/src/ingress/buffer/qwp.rs:3414-3424`.
- Replay schema ids are assigned per message:
  `questdb-rs/src/ingress/buffer/qwp.rs:2726-2732` and
  `questdb-rs/src/ingress/buffer/qwp.rs:3661-3682`.

Impact:

- Valid frames can be rejected when the estimate overcounts.
- Frames can exceed `max_buf_size` when the estimate undercounts, especially
  after the connection-global symbol dictionary has grown.

Expected fix:

- Do not use a connection-independent local estimate as the final
  QWP/WebSocket max-size gate.
- Prefer checking the encoded payload length after `QwpWsReplayEncoder::encode`
  returns, because only the encoder knows the connection-global symbol state.
- Keep `Buffer::len()` as an approximate hint if needed, but update docs/tests
  so max-size enforcement is based on encoded replay payload length.
- Add tests for:
  - no-symbol frame size does not reject because of the old +2 overcount;
  - many schemas crossing schema-id varint boundaries;
  - a later frame whose local symbol ids are small but global ids are large.

### P3: hidden `_sender-qwp-ws` feature does not compile standalone

The public `sync-sender-qwp-ws` feature compiles, but the hidden
`_sender-qwp-ws` feature no longer checks by itself.

Reproduced command:

```bash
cargo check --manifest-path questdb-rs/Cargo.toml \
  --no-default-features \
  --features _sender-qwp-ws,ring-crypto,tls-webpki-certs
```

Observed failure:

```text
error[E0433]: failed to resolve: use of unresolved module or unlinked crate `error`
   --> src/ingress/sender/qwp_ws_driver.rs:711:9
```

Evidence:

- `qwp_ws_driver.rs` uses `error::fmt!` in a path enabled by `_sender-qwp-ws`.
- The `use crate::error` import is currently gated such that it is not present
  for that hidden-feature-only build.

Expected fix:

- Align the import cfg with every code path that uses `error::fmt!`.
- Add the hidden feature check to the validation list, or decide that hidden
  feature-only builds are unsupported and remove the unsupported cfg surface.

## Rejected Finding: retained schema after clear

One review pass flagged `QwpWsColumnarBuffer::clear()` retaining table/column
definitions as stale-schema publication. That is not a blocker if this slice is
following Java.

Java behavior:

- `QwpWebSocketSender.flushPendingRows()` calls `tableBuffer.reset()` after a
  successful flush:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java:2185-2195`.
- `QwpTableBuffer.reset()` keeps column definitions and allocated memory while
  resetting row data:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/protocol/QwpTableBuffer.java:314-325`.
- Encoding writes the retained schema for the current table buffer:
  `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpColumnWriter.java:343-357`.

Rust behavior:

- `Buffer::clear()` promises to clear contents and marker while retaining
  allocated capacity: `questdb-rs/src/ingress/buffer.rs:463-471`.
- The QWP/WebSocket implementation clears row data but keeps table/column
  definitions: `questdb-rs/src/ingress/buffer/qwp.rs:2149-2156` and
  `questdb-rs/src/ingress/buffer/qwp.rs:2771-2779`.

This is a behavior difference from old Rust `QwpBuffer`, but it is consistent
with Java's columnar table-buffer model. If this remains intentional, document
that QWP/WebSocket `clear()` retains learned schema definitions and may emit
those definitions with null/default values for omitted columns in later batches.

## Validation Already Run

Passed:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_columnar --lib
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_driver --lib
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwpws --lib
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-udp qwp --lib
cargo test --manifest-path questdb-rs/Cargo.toml --lib
cargo clippy --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib --tests -- -D warnings
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Failed:

```bash
cargo check --manifest-path questdb-rs/Cargo.toml \
  --no-default-features \
  --features _sender-qwp-ws,ring-crypto,tls-webpki-certs
```

Real-server probes were not run in this review pass; the relevant tests remain
ignored unless their `QDB_QWP_WS_*` environment flags are set.

## Suggested Fix Order

1. Add failing tests for the bookmark-clone and duplicate-type findings.
2. Fix clone behavior and duplicate type-check ordering.
3. Move QWP/WebSocket max-size enforcement to encoded payload length, then add
   regression coverage for symbol/global-id sizing.
4. Fix or explicitly drop support for hidden `_sender-qwp-ws` standalone
   compilation.
5. Re-run the validation list above plus at least one real-server QWP/WebSocket
   probe before commit.
