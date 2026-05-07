# QWP/WebSocket columnar buffer design

Date: 2026-05-07

Status: design handover. No production implementation is included in this
document. The goal is to replace the Rust QWP/WebSocket hot row path with a
Java-like columnar buffer while preserving the existing Rust public API.

## Purpose

Rust QWP/WebSocket ingestion is much slower than the Java client on the same
local QuestDB server. Profiling does not point at WebSocket transport, server
backpressure, lock contention, or close-drain behavior as the primary cause.
The dominant cost is producer-thread row construction.

The key architectural mismatch is:

- Java stores QWP data in table-local, column-oriented buffers as rows are
  built.
- Rust stores row-oriented entry metadata first, then later plans those entries
  into QWP columns before encoding.

QWP is a columnar wire format. The Rust WebSocket sender should store data in a
columnar shape from the start, like Java.

## Evidence

Measurements were taken against a local server on `127.0.0.1:9000` with the
same logical row shape:

- one table;
- one symbol column: `host`;
- two long columns: `v`, `w`;
- one string/varchar column: `msg`;
- `atNow`/`at_now`;
- flush every 1000 rows.

Observed timings:

| Path | Rows | Time | Throughput | Meaning |
| --- | ---: | ---: | ---: | --- |
| Java end-to-end build phase | 20M | 990 ms | ~20.2M rows/s | Public Java row API |
| Rust end-to-end raw build phase | 10M | 2388 ms | ~4.2M rows/s | Public Rust row API |
| Rust end-to-end prevalidated build phase | 10M | 1844 ms | ~5.4M rows/s | Public Rust row API, name validation mostly removed |
| Rust internal QWP build+encode raw | 10M | 1383 ms | ~7.2M rows/s | No sender/socket/runner |
| Rust internal QWP build+encode prevalidated | 10M | 1222 ms | ~8.2M rows/s | Best measured current Rust QWP buffer path |

End-to-end Rust split:

- raw: `build_ms=2388`, `flush_ms=95`, total `2484 ms`;
- prevalidated names: `build_ms=1844`, `flush_ms=108`, total `1954 ms`.

End-to-end Java split:

- `build_ms=990`, `flush_ms=0`, `close_ms=57`, total `1048 ms` for 20M rows.

CPU evidence:

- Rust end-to-end uses about one core (`~102%` CPU in `/usr/bin/time -v`).
- Java uses only modestly more CPU (`~135%` CPU), not the whole machine.
- Rust CPU samples are concentrated on the producer/main thread.
- Rust syscall trace showed small `futex` time and small total syscall time.
- Rust instruction count is several times higher per row:
  - Rust end-to-end: about 5.2k instructions/row including warmup;
  - Java end-to-end: about 1.26k instructions/row including warmup;
  - Rust internal prevalidated QWP path: about 3.6k instructions/row.

Conclusion: the leading performance problem is Rust producer-side row-buffer
architecture.

## Current Java Model

Reference implementation paths:

- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpWebSocketSender.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/protocol/QwpTableBuffer.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/QwpColumnWriter.java`
- `/home/jara/devel/oss/questdb-arrays/java-questdb-client/core/src/main/java/io/questdb/client/cutlass/qwp/client/MicrobatchBuffer.java`

Java's producer path is already columnar:

1. `QwpWebSocketSender.table(table)` selects a `QwpTableBuffer`.
2. `symbol`, `longColumn`, `stringColumn`, etc. call
   `QwpTableBuffer.getOrCreateColumn(...)`.
3. `QwpTableBuffer.lookupColumn(...)` has a stable-column-order fast path using
   `columnAccessCursor`.
4. The column value is appended directly into that `ColumnBuffer`.
5. `nextRow()`/`atNow()` advances the row and pads missing columns.
6. Flush encodes already-columnar buffers through `QwpColumnWriter`.

Important Java traits to preserve where practical:

- stable column order avoids hash lookup on the common path;
- duplicate column detection is a row-local column state check;
- fixed-width columns are contiguous buffers and encode with block copies;
- strings use offsets plus data bytes;
- symbols maintain dictionary state and append ids;
- row completion pads missing columns rather than rebuilding rows later.

Java decisions used by this design:

- table buffers are keyed by `CharSequenceObjHashMap` in
  `QwpWebSocketSender`, and the current-table fast path uses `Chars.equals`.
  Treat table identity as case-sensitive.
- column buffers are keyed by `LowerCaseCharSequenceIntHashMap`, and the
  ordered fast path uses `Chars.equalsIgnoreCase`. Treat column identity as
  case-insensitive inside one table.
- `QwpTableBuffer.getOrCreateColumn(...)` returns `null` when the column was
  already written in the current row. Callers skip the second write, so
  duplicate columns are first-value-wins.
- `QwpWebSocketSender.flushPendingRows()` iterates retained table buffers and
  emits one block per non-empty table. It groups interleaved rows by table
  rather than preserving the original alternation as separate table blocks.
- the global symbol dictionary is owned by `QwpWebSocketSender`, not
  `QwpTableBuffer`. Keep connection-scoped dictionary state out of the Rust
  batch buffer.

## Current Rust Model

Relevant Rust paths:

- `questdb-rs/src/ingress/buffer/qwp.rs`
- `questdb-rs/src/ingress/buffer.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_publisher.rs`
- `questdb-rs/src/ingress/sender/qwp_ws_driver.rs`
- `questdb-rs/src/ingress/sender/qwp_ws.rs`

The current Rust QWP path is row-oriented:

1. `table(...)` converts/validates the table name and appends bytes into
   `name_bytes`.
2. Each column call converts/validates the column name.
3. Each column call scans current-row entries for duplicate detection.
4. Column names are copied into `name_bytes`.
5. Variable values are copied into `value_bytes`.
6. Each field pushes an `EntryMeta`.
7. `at_now()` commits a `RowMeta`.
8. Flush/replay encoding uses `RowGroupPlanner::add_row(...)` to convert row
   entries into columns.
9. Encoding walks planner cells.

This supports both QWP/UDP datagram planning and QWP/WebSocket replay encoding,
but it is not Java-like and it does not match the columnar wire shape on the hot
row path.

## Target Shape

Keep the public Rust API unchanged:

```rust
buffer
    .table("trades")?
    .symbol("host", "host01")?
    .column_i64("v", 42)?
    .column_i64("w", 1302)?
    .column_str("msg", "payload")?
    .at_now()?;
```

Change the internal QWP/WebSocket buffer shape to columnar:

```text
QwpWsColumnarBuffer
  max_name_len
  current_table_idx: Option<usize>
  tables: Vec<TableBuffer>
  table_lookup: case-sensitive table name -> table index

TableBuffer
  table_name: Box<str> or bytes, preserving first spelling
  row_count: u32
  in_progress: bool
  in_progress_column_count: usize
  column_access_cursor: usize
  columns: Vec<ColumnBuffer>
  column_lookup: case-insensitive column name -> column index
  row_start_marks: RowRollbackMarks

ColumnBuffer
  name: Box<str> or bytes, preserving first spelling
  kind: ColumnKind
  last_written_row: u32
  non_null_count: u32
  null_state: only for sparse-null-capable kinds
  data storage by kind
```

The buffer owns only batch data: tables, columns, row counts, value storage,
and rollback marks. It must not own connection-scoped encoder state.

Connection-scoped state stays with the sender/encoder, matching both current
Rust and Java:

```text
QwpWsReplayEncoder
  scratch message buffer
  connection/global symbol dictionary
  any future connection-scoped schema state
```

Current Rust already keeps `SymbolGlobalDict` inside `QwpWsReplayEncoder`.
Java keeps the global dictionary and send state on `QwpWebSocketSender`, while
`QwpTableBuffer` owns only table/column batch data. The Rust redesign should
preserve that ownership boundary.

Column storage by kind:

```text
Bool:
  Vec<u8> or packed bits, depending on write/encode tradeoff

I64 / F64 / timestamp:
  Vec<i64> / Vec<f64> with sentinel filling for fixed non-bitmap columns

String:
  offsets: Vec<u32>
  data: Vec<u8>

Symbol:
  row_ids: Vec<u32 or varint-ready ids>
  local dictionary
  encoder maps local symbols to connection/global ids during replay encoding

Decimal / arrays / other QWP types:
  follow existing Rust semantics, but append into column-owned storage
```

Java lets `QwpTableBuffer.ColumnBuffer.addSymbol(...)` call back into
`QwpWebSocketSender` to allocate global symbol ids while appending. Rust should
not put that connection-scoped dictionary inside `Buffer`; keep the batch
buffer detached and perform local-to-global symbol mapping in
`QwpWsReplayEncoder`. That is a mechanical Rust deviation from Java, but it
preserves the same ownership rule: connection dictionary state belongs to the
sender/encoder, not to table batch storage.

The hot path becomes:

```text
table(): choose current table
column(): find expected next column, validate type, append directly
at_now(): complete row, pad missing columns if needed
flush(): encode already-columnar table buffers
```

## Fast Path Rules

The common case should be optimized first:

- Same table repeated across rows.
- Same columns in the same order across rows.
- No missing columns.
- No type changes.
- Small fixed schema.
- Flush every N rows.

Fast path behavior:

1. `table(name)`:
   - if current table name matches, return immediately;
   - otherwise look up/create the table buffer;
   - reject table switch while a row is in progress.

2. `column(name, kind, value)`:
   - use `column_access_cursor` to test the next expected column;
   - if it matches, avoid the hash map;
   - otherwise fall back to column lookup/create;
   - detect duplicates via `last_written_row == row_count`;
   - duplicates are a no-op and the first value wins, matching Java;
   - append the value directly into the column buffer.

3. `at_now()`:
   - require a selected table;
   - pad missing columns only when `in_progress_column_count != columns.len()`;
   - reset `column_access_cursor`;
   - increment row count.

4. `clear()`:
   - reset row counts and per-column write positions;
   - retain allocated capacity and schema definitions.

## Row Atomicity And Rollback

Direct column append must still preserve the existing row-level atomicity
contract. A failing API call must not leave a half-mutated row in the buffer.

Before the first column mutation in a row, the table buffer records rollback
marks for all state that can be extended during the row:

```text
RowRollbackMarks
  row_count
  in_progress_column_count
  column_access_cursor
  column_count
  per-column value lengths / offset lengths / dictionary lengths
  per-table lookup size if new columns may be created
```

Each mutating row API follows this shape:

```text
start row if needed and record marks
try lookup/create column
try append value
on error: rollback table and all touched columns to marks
on success: keep row in progress until at_now()/at(...)
```

`at_now()` / `at(...)` commits the row by advancing `row_count`, clearing
rollback marks, and resetting the ordered-column cursor for the next row.

This matches the current Rust row-log rollback discipline and Java's
`rollbackRow()` / `retainInProgressRow()` behavior. It is not optional; without
it, direct append would corrupt the next row after a mid-row validation,
allocation, or capacity error.

## Encoding Model

The first implementation should support only the production WebSocket replay
shape: self-sufficient, full-schema frames. Do not carry schema-reference/delta
mode into the first slice.

The WebSocket replay encoder should encode directly from columnar table
buffers:

```text
write QWP message header placeholder
write dense global symbol prefix
for each non-empty table:
  write table name
  write row count
  write full schema
  for each column:
    write null header / bitmap
    write column payload from column storage
patch QWP header length
```

Preserve the current Java-compatible self-sufficient frame rule:

- dense global symbol dictionary prefix starts at id 0;
- every table block carries full schema;
- frame bytes must be valid on a fresh connection.

Non-replay/schema-reference encoding is a later design, not part of this
performance slice. Current Rust production QWP/WebSocket publication already
uses replay encoding, and Java cursor Store-and-Forward forces full schema.

## Table And Name Semantics

This redesign intentionally follows Java table grouping for QWP/WebSocket:

- one retained `TableBuffer` per table name;
- rows for the same table accumulate in that table buffer across the batch;
- flush emits one table block per non-empty table buffer.

This differs from current Rust row-log segmentation, where consecutive table
segments can preserve `trades, quotes, trades` as three table blocks. Switching
to Java grouping is a wire-shape change for interleaved tables, but it preserves
the logical batch contents and matches the Java client.

Name identity:

- Table lookup is case-sensitive, matching Java's `CharSequenceObjHashMap`
  table map and `Chars.equals` current-table fast path.
- Column lookup is case-insensitive, matching Java's
  `LowerCaseCharSequenceIntHashMap` and ordered-column fast path.
- The first spelling used to create the table/column is retained for schema
  emission.
- A later column call whose name differs only by case resolves to the same
  column and must pass the same type check.
- A duplicate column in the same row is ignored after resolving identity; the
  first value wins.

This is a behavior change from current Rust QWP internals, which compare raw
name bytes for duplicate detection and planner lookup. The change is deliberate
Java parity and must be covered by tests.

First-value-wins duplicate handling is also a QWP/WebSocket behavior change
from Rust's current duplicate-column error path. Do not apply it to QWP/UDP
unless that transport is explicitly migrated to the same semantics.

## Buffer Integration

Do not rewrite the public sender API.

Recommended staged integration:

1. Keep the existing `Buffer` facade.
2. Add a new internal variant for QWP/WebSocket columnar buffering.
3. Make `Sender::new_buffer()` return the columnar variant for QWP/WebSocket.
4. Keep the existing row-log `QwpBuffer` for QWP/UDP initially.
5. Teach QWP/WebSocket flush to accept the new columnar variant.
6. Keep old `QwpBuffer` tests as an oracle during migration.

Possible internal enum shape:

```rust
enum BufferInner {
    Ilp(IlpBuffer),
    QwpUdp(Box<QwpBuffer>),
    QwpWs(Box<QwpWsColumnarBuffer>),
}
```

The exact naming is not important. The important boundary is that QWP/WebSocket
does not have to preserve the row-log representation just because QWP/UDP still
uses it.

## First Slice Scope And Fallback

There are two acceptable implementation scopes:

1. **Internal prototype scope**
   - Implement enough column kinds to exercise the measured hot benchmark.
   - Keep it behind tests or a private benchmark hook.
   - Do not return it from `Sender::new_buffer()`.

2. **Production sender integration scope**
   - Implement every column kind currently accepted by the public
     QWP/WebSocket `Buffer` path.
   - Return the columnar variant from `Sender::new_buffer()` for
     QWP/WebSocket senders.
   - Do not add a runtime fallback from the columnar buffer to the old row-log
     buffer.

The production path should be one coherent implementation. A hidden fallback
would keep the old slow path alive, complicate row rollback, and make
performance profiles hard to reason about. Keep the old row-log buffer as the
QWP/UDP implementation and as a test oracle during migration, not as a runtime
escape hatch for WebSocket.

## Correctness Requirements

The new buffer must preserve:

- API sequencing errors:
  - column before table;
  - table switch while row is in progress;
  - flush with incomplete row;
  - symbol-after-column ordering rules, if still required by Rust API.
- duplicate column semantics:
  - duplicate columns in one row are first-value-wins, matching Java;
  - a duplicate that differs only by case resolves to the same column and is
    also a no-op;
  - skipping a duplicate must not advance row state a second time.
- row atomicity:
  - a failed column/table/timestamp call rolls back every mutation from that
    in-progress row;
  - newly-created columns from a failed row are removed;
  - column value buffers, string offsets/data, symbol dictionaries, null state,
    cursors, and row counters are restored to the row-start marks.
- name validation and maximum name length;
- Java-like name identity:
  - table lookup is case-sensitive;
  - column lookup is case-insensitive;
  - first spelling is retained for emitted schema names.
- type mismatch detection within a batch and across retained schemas;
- Java-like table grouping:
  - one emitted table block per non-empty table buffer in insertion order;
  - interleaved rows for the same table are grouped together at flush.
- missing-value semantics:
  - fixed integer null sentinel where QWP expects it;
  - floating NaN where QWP expects it;
  - null bitmap for sparse/variable columns;
  - string offsets and empty/null distinction;
- full-schema replay frames for SFA;
- dense global symbol prefix for replay frames;
- durable ACK and SFA behavior above the encoded frame layer;
- zero or bounded allocation after warmup for the common stable-schema path.

## Test Strategy

Start with differential tests before deleting any old path.

Recommended tests:

1. **Stable schema semantic parity**
   - Build the same rows with old `QwpBuffer` and new `QwpWsColumnarBuffer`.
   - Decode both QWP messages with the existing QWP test decoder.
   - Assert semantic equality.

2. **Stable schema byte parity where possible**
   - For simple rows, assert byte-for-byte parity.
   - If dictionary/schema order differs intentionally, document and assert
     semantic parity instead.

3. **Missing columns**
   - First row has all columns.
   - Later rows omit fixed, string, symbol, timestamp columns.
   - Verify sentinel/null bitmap/offset behavior.

4. **Schema growth**
   - Add a new column after several rows.
   - Verify old rows are padded.
   - Verify schema is emitted correctly.

5. **Duplicate column**
   - Same column written twice in one row.
   - Verify first-value-wins: the first value is encoded, the second write is
     ignored, and row state remains usable.
   - Repeat with a case variant of the same column name.

6. **Type mismatch**
   - Same column name with a different type in the same table.
   - Verify rollback removes partial values and any newly-created columns.

7. **Multi-table batch**
   - Interleaved tables if the API allows it outside in-progress rows.
   - Verify Java-style grouping: one table block per table, in insertion order.

8. **Replay frame parity**
   - Full schema is emitted.
   - Dense symbol prefix starts at 0.
   - A later replay frame referencing a high symbol id includes lower ids.
   - Verify the buffer does not own or reset the connection/global symbol
     dictionary between flushes.

9. **Case-insensitive column identity**
   - `Host` and `host` resolve to the same column.
   - The first spelling is emitted in the schema.
   - Type mismatch across case variants fails.

10. **Rollback after mid-row failure**
    - Trigger validation/type/capacity errors after one or more successful
      column appends.
    - Verify the next row encodes correctly and no partial value leaks.

11. **Allocation regression**
    - Stable schema, warmed buffer, many rows.
    - Assert no allocations after warmup if the existing test harness can
      support it.

12. **Performance gate**
    - Add ignored benchmark-style tests or a bench harness for:
      - row build only;
      - encode only;
      - end-to-end QWP/WebSocket memory mode.

Expected validation commands for the implementation branch:

```bash
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_columnar --lib
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_publisher --lib
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws_driver --lib
cargo test --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws qwp_ws --lib
cargo clippy --manifest-path questdb-rs/Cargo.toml --features sync-sender-qwp-ws --lib --tests -- -D warnings
cargo fmt --manifest-path questdb-rs/Cargo.toml --check
git diff --check
```

Performance validation should use a measured run large enough to amortize setup
costs. Use the same shape as the profiling evidence: one table, stable schema,
batch size 1000, at least 20M measured rows, and a 50M-row run before claiming
parity. Report `build_ms`, `flush_ms`, `close_ms`, throughput, and
instructions/row.

## Migration Plan

### Milestone 1: Internal columnar model

- Add `QwpWsColumnarBuffer`.
- Implement table selection, column lookup, first-value-wins duplicate
  handling, row completion, clear, capacity retention, and basic
  fixed/string/symbol columns.
- Implement row rollback marks before any sender integration.
- Use Java-like table grouping and case-insensitive column identity.
- Add semantic parity tests against old `QwpBuffer`.
- Do not wire it into `Sender::new_buffer()` yet.

### Milestone 2: Replay encoder

- Encode self-sufficient replay frames directly from `QwpWsColumnarBuffer`.
- Keep connection-scoped state in `QwpWsReplayEncoder`, not in the buffer.
- Preserve dense global symbol prefix behavior.
- Preserve full-schema replay behavior.
- Differential-test against old `encode_ws_replay_message`.

### Milestone 3: Sender integration

- Add a WebSocket-specific `BufferInner` variant.
- Return it from `Sender::new_buffer()` for QWP/WebSocket senders.
- Wire QWP/WebSocket flush to the new encoder.
- Keep QWP/UDP on the existing row-log buffer.

### Milestone 4: Performance validation

- Re-run the same benchmark:
  - 20M or 50M measured rows;
  - batch size 1000;
  - raw names;
  - prevalidated names;
  - memory mode;
  - SFA mode.
- Collect:
  - `build_ms`, `flush_ms`, `close_ms`;
  - `perf stat` instructions/row;
  - CPU profile top symbols.

Target expectation:

- row build should move materially toward Java;
- `RowGroupPlanner::add_row` should disappear from WebSocket hot profiles;
- per-row name arena copying should disappear from stable-schema hot profiles;
- flush/transport should remain a minority cost.

### Milestone 5: Cleanup

- Remove WebSocket dependence on old row-log `QwpBuffer` where no longer used.
- Keep QWP/UDP code intact unless a separate UDP columnar migration is designed.
- Update parity and architecture docs.

## Non-Goals

This design does not attempt to:

- change WebSocket transport framing;
- change durable ACK semantics;
- change SFA segment format;
- change orphan draining;
- change public Rust sender API;
- optimize QWP/UDP in the first slice;
- introduce async Rust APIs;
- introduce a new user-facing buffer type unless the existing `Buffer` facade
  cannot reasonably hide the internal split.

## Risks

1. **Duplicating QWP encoders**

   During migration there may be old row-log and new columnar encoders. Keep the
   new encoder WebSocket replay-scoped and use differential tests to prevent
   drift. Do not implement schema-reference/delta mode in the first slice.

2. **Semantic drift from QWP/UDP**

   QWP/UDP and QWP/WebSocket may temporarily have different internal models.
   That is acceptable if public behavior and wire semantics remain tested.
   Do not hide missing WebSocket column kinds behind a runtime fallback to the
   old row-log buffer.

3. **Over-optimizing too early**

   The first win is removing row-log planning from the WebSocket producer path.
   Do not start with SIMD masking, socket batching, or SFA tuning.

4. **Name lifetime complexity**

   Store owned table/column names in the table/column buffers. Do not make the
   hot path depend on caller string lifetimes.

5. **Symbol dictionary correctness**

   Replay frames require a dense prefix from id 0, and that dictionary is
   connection-scoped. This is easy to regress while making symbols faster. Keep
   the dictionary in the replay encoder and keep dedicated tests.

6. **Missing-column cost**

   Java pads missing columns at row completion. Rust should copy that behavior,
   but avoid scanning all columns when the row used every column in order.

7. **Rollback complexity**

   Direct append is only safe if every mutable column/table state has a
   row-start mark. Keep the first implementation narrow enough that rollback is
   obvious and fully tested.

## Open Questions

- Should fixed-width column buffers store sentinel values eagerly on missing
  rows, or should encoding synthesize sentinels from a sparse write index?
- Should string offsets use `u32` internally from the start to match wire
  constraints?
- How much of the old `RowGroupPlanner` can remain QWP/UDP-only after this?

## Implementation Principle

The simplest faithful implementation is not a new transport abstraction. It is
a new WebSocket-specific in-memory buffer shape behind the existing `Buffer`
API.

The first successful patch should make the CPU profile boring:

- no `RowGroupPlanner::add_row` in WebSocket row-build profiles;
- no per-row column-name arena copies for stable schemas;
- most producer time in direct column append methods;
- flush still a small fraction of wall time.
