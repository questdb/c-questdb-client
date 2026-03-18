# QWP/UDP Buffer Redesign

## Scope

This document proposes a full internal redesign of the QWP/UDP buffering and
flush pipeline.

The only compatibility boundaries that matter are:

1. The public `Sender` and `Buffer` API surface.
2. The emitted QWP wire protocol bytes.

Everything else may change.

## Operating Assumption

This redesign is optimized for QWP/UDP deployments that keep each UDP datagram
under the path MTU to avoid fragmentation.

In practice, that usually means designing around a 1500-byte Ethernet MTU:

* IPv4 UDP payload budget is typically 1472 bytes
* IPv6 UDP payload budget is typically 1452 bytes
* a configured default around 1400 bytes leaves operational headroom

That assumption matters because it gives us a hard upper bound for hot-path
scratch:

* encoded datagrams are bounded by configured `max_datagram_size`, which should
  stay below the effective MTU budget
* rows, columns, symbols, and payload bytes per datagram are therefore bounded
* bounded small-cardinality scans are preferable to generic heap-backed hash
  tables in the hot path

The target is not merely "fewer allocations than today". The target is:

* no allocator calls in steady state after explicit prewarm or warmup
* predictable low-latency behavior within the configured MTU-safe datagram bound

## Problem Statement

The current QWP implementation is functionally correct, but its memory behavior
is not acceptable for a low-allocation client:

* The buffer stores a tree of owned objects:
  * `Vec<CommittedRow>`
  * each row owns `Vec<PendingEntry>`
  * each entry owns one or more `String`s
* `clear()` preserves only the outer row vector's capacity. The inner row,
  entry, and string allocations are dropped and must be rebuilt on the next
  batch.
* Flush performs another allocation-heavy transform by rebuilding the buffered
  rows into temporary batch/column structures.
* The send path materializes `Vec<Vec<u8>>`, which is exactly the wrong shape
  for a hot UDP path.

In short: the current code re-allocates while buffering, re-allocates while
encoding, and re-allocates again while collecting datagrams.

## Goals

* No allocator calls in steady state for bounded workloads after prewarm or
  warmup.
* `clear()` and marker rewind must reset lengths, not free inner storage.
* No `Vec<Vec<_>>` production path for encoded datagrams.
* No generic heap-backed hash tables in the QWP hot path.
* No dense `row_count * column_count` scratch structures in the QWP hot path.
* Preserve current wire semantics:
  * table-switch order
  * contiguous same-table batching
  * column first-seen order
  * type-change detection within a batched table
  * datagram splitting behavior
  * exact QWP bytes

## Non-goals

* Preserving the current internal `qwp.rs` types.
* Preserving helper functions such as `encode_datagrams()` as production APIs.
* Making `clone()` cheap.
* Extending QWP to currently unsupported value types as part of this rewrite.

## High-Level Design

The redesign has two parts:

1. Replace the current owned row tree with a flat, arena-backed `QwpBuffer`.
2. Move all datagram-building scratch into the sender and emit datagrams
   directly to the socket.

That gives us three important properties:

* buffered state is stored in a small number of reusable allocations
* `clear()` becomes truncation instead of destruction
* flush becomes a streaming encode/send loop instead of
  `rows -> temp columns -> Vec<Vec<u8>> -> socket`

This redesign is QWP-specific. The top-level `Buffer` enum dispatch between ILP
and QWP remains unchanged, and the ILP buffer implementation is not affected by
the QWP arena layout described below.

## Buffer Storage

### Core idea

Store buffered rows and values in flat arenas. Rows and entries become metadata
records referring into retained storage instead of owning nested heap objects.

### Proposed layout

```rust
struct QwpBuffer {
    name_bytes: Vec<u8>,
    value_bytes: Vec<u8>,
    rows: Vec<RowMeta>,
    entries: Vec<EntryMeta>,
    segments: Vec<SegmentMeta>,
    pending: PendingRowState,
    state: BufferState,
    size_hint: QwpSizeHint,
    marker: Option<QwpMarker>,
    max_name_len: usize,
}

struct NameSlice(ByteSlice);   // indexes into `name_bytes`
struct ValueSlice(ByteSlice);  // indexes into `value_bytes`

struct RowMeta {
    table: NameSlice,
    entry_start: u32,
    entry_count: u32,
    designated_ts: Option<PendingTimestamp>,
}

struct EntryMeta {
    name: NameSlice,
    kind: ColumnKind,
    value: ValueRef,
}

enum ValueRef {
    Bool(bool),
    I64(i64),
    F64(f64),
    Timestamp(PendingTimestamp),
    Symbol(ValueSlice),
    String(ValueSlice),
}

struct ByteSlice {
    offset: u32,
    len: u32,
}

struct SegmentMeta {
    table: NameSlice,
    row_start: u32,
    row_count: u32,
}
```

### Name storage

Table names and column names are stored in a retained `name_bytes` arena and
referred to by `NameSlice`.

Important constraints:

* there is no process-lifetime or buffer-lifetime global name interning table
  in the hot path
* `clear()` truncates `name_bytes`
* marker rewind truncates `name_bytes`
* any optional dedup cache must be scoped to currently live buffer contents and
  rewound together with the buffer

This is a deliberate tradeoff. Duplicating a small bounded number of names in a
retained arena is preferable to carrying an unbounded interning structure that
can grow forever in a long-lived low-latency process.

`ByteSlice` uses `u32` for both offset and length, which caps each arena below
4 GiB. That limit is far above any intended QWP/UDP workload, but the
implementation should still assert it on append so oversized arenas fail
explicitly rather than wrapping indices.

### Value storage

Symbols and strings are stored in a single append-only `value_bytes` arena and
referred to by `ValueSlice`.

When a row is built:

* booleans, integers, doubles, and timestamps are stored inline in `ValueRef`
* strings and symbols are copied once into `value_bytes`
* entries store a byte slice instead of owning a `String`

This means the hot path uses a few retained vectors rather than a new heap
object per value.

### Row grouping

`segments` tracks contiguous same-table runs in input order. This preserves the
 current batching behavior exactly:

* rows for the same table are batched only when they are contiguous
* switching to another table closes the previous segment
* a later return to the first table creates a new segment

This matches current wire behavior and makes flush simpler.

Row commit updates `segments` directly:

* when `at()` / `at_now()` finalizes a row, compare the pending row's table name
  bytes against the last segment's table bytes
* if they match, increment the last segment's `row_count`
* otherwise append a new `SegmentMeta`

That comparison is an ordinary bounded byte-slice equality check on commit, not
pointer equality or arena-offset equality. Table names are stored by value in
the arena rather than interned, so byte equality is the correct comparison and
is acceptable under the MTU-sized operating assumption.

An important invariant is that `segments` and `name_bytes` are rewound
together. After marker rewind, any surviving `SegmentMeta.table` slice must
still refer to live name data. This is a good candidate for debug assertions in
the implementation.

## Pending Row Handling

Pending row state should also be flat and reusable.

```rust
struct PendingRowState {
    table: Option<NameSlice>,
    entry_start: u32,
    name_bytes_start: u32,
    value_bytes_start: u32,
}
```

Proposed behavior:

* `table()` opens a pending row and records the start index in `entries`
* `symbol()` and `column_*()` append directly into the flat arenas
* duplicate-name detection scans only the current row's entries
* `at()` or `at_now()` finalizes the row by appending one `RowMeta`

This avoids building a separate temporary `PendingEntry` vector that is later
copied into committed storage.

Because rows are bounded by small datagram sizes, duplicate detection should
favor a bounded linear scan over current-row entries instead of a hash table.
That is more predictable and avoids another allocator-managed structure in the
hot path.

If a row is abandoned before `at()` / `at_now()`, the buffer rolls back to the
pending row's recorded `entry_start`, `name_bytes_start`, and
`value_bytes_start`. This same rollback path is used for row-construction
errors, preserving steady-state reuse without leaving partial row data live in
the arenas.

`PendingRowState.table.is_some()` is the only validity bit for pending-row
state. Rollback and `clear()` must set `table = None` before any future code can
observe that slice again.

## Clear, Marker, Rewind, Clone

### `clear()`

`clear()` should become a pure length-reset operation:

* `rows.clear()`
* `entries.clear()`
* `segments.clear()`
* `name_bytes.clear()`
* `value_bytes.clear()`
* reset pending state, marker, and state machine
* keep all retained capacities

This is the most important semantic change for steady-state reuse.

### Marker / rewind

The marker should snapshot lengths, not object graphs.

```rust
struct QwpMarker {
    rows_len: u32,
    entries_len: u32,
    segments_len: u32,
    tail_segment_row_count: Option<u32>,
    name_bytes_len: u32,
    value_bytes_len: u32,
    state: BufferState,
    size_hint: QwpSizeHint,
}
```

`rewind_to_marker()` then becomes:

* truncate all arenas back to the recorded lengths
* if the marker landed within an existing segment, restore that tail segment's
  previous `row_count`
* clear pending row state
* restore `BufferState`
* restore `QwpSizeHint`

Again, no inner allocations are dropped.

### `clone()`

`clone()` should copy only the live data ranges, not the current spare capacity.

That keeps semantics unchanged while avoiding accidental retention explosion
when cloning a previously warmed-up buffer.

If a row is currently pending, `clone()` should preserve that pending row state
as well. In practice that means copying live arena contents through the current
pending lengths and cloning `PendingRowState` so the clone can continue row
construction independently. This is intentional: public buffer cloning is
currently unconditional, so the redesign should preserve that behavior rather
than introducing a new "clone only between rows" restriction.

## Size Hint

The current `len()` semantics are acceptable:

* ILP returns exact pending bytes
* QWP returns a buffered size hint

Keep that contract, but make the implementation allocation-free.

The existing `QwpSizeHint` logic can survive conceptually, but it should operate
directly on `RowMeta` / `EntryMeta` slices instead of constructing temporary
`Vec<RowValueSpec>`.

Key requirement:

* all size estimation must work from borrowed views into the flat arenas

No temporary row-spec vectors should be created in the hot path.

### Datagrams size accounting

The flush path should not have a separate "estimate first, then encode later"
pass that re-walks the same data twice.

Instead, row-group planning and size accounting should be the same operation:

* as each row is tentatively added to planner scratch, the planner updates the
  exact encoded byte count for the current prefix
* byte accounting includes schema bytes, null bitmaps, string offsets/data,
  symbol dictionary growth, symbol row indexes, and varint size transitions
* before attempting to add a row, the planner records a checkpoint containing
  scratch lengths, current encoded byte count, and enough column-level state to
  undo mutations caused by that row
* if adding the row exceeds `max_datagram_size`, restore the checkpoint, emit
  the previous prefix, reset scratch, and retry the row as the first row of the
  next datagram

Because the datagram bound is MTU-sized, these checkpoints are cheap length
snapshots rather than expensive object copies.

In practice that means the checkpoint must be able to roll back:

* `columns.len()` when a row introduces a new column
* per-column mutable fields for any column touched by the row, such as
  `nullable`, `cell_count`, `symbol_value_count`, and `symbol_row_count`
* `cells.len()`, `symbol_values.len()`, and `symbol_row_indexes.len()`
* the running encoded byte count

The intended implementation is a preallocated rollback stack inside
`RowGroupScratch`: before processing a row, record `columns.len()` and push one
small undo record per touched column containing the old mutable counters and
flags. Under MTU-sized bounds this stack remains small and must be retained as
scratch rather than allocated per checkpoint.

Header-level schema costs are covered by the same checkpointed byte total. The
planner should maintain one exact running encoded-size `usize` for the current
prefix, including row-count and column-count varint widths. If adding a row
crosses a varint boundary or introduces a first-seen column, the row-add logic
updates that total immediately; rollback restores the prior total instead of
trying to undo header costs piecemeal.

## Sender-Owned Scratch

The sender should own all scratch state needed to plan and encode datagrams.

### Why the scratch belongs to the sender

The buffer is the long-lived reusable batch container.
The sender is the right place for encode/send scratch because:

* the scratch is transport-specific
* it is only needed during `flush`
* it can be reused across multiple buffer flushes

### Proposed sender state

```rust
struct SyncQwpUdpHandlerState {
    socket: UdpSocket,
    target_addr: SocketAddrV4,
    max_datagram_size: usize,
    multicast_ttl: u32,
    scratch: QwpSendScratch,
}

struct QwpSendScratch {
    planner: RowGroupScratch,
    datagram: Vec<u8>,
}
```

This implies `flush_qwp_udp()` should take `&mut SyncQwpUdpHandlerState`, not
`&SyncQwpUdpHandlerState`.

That is an internal change only.

At sender construction time, prewarm `scratch.datagram` to
`max_datagram_size`. The production flush path must never grow the datagram
buffer beyond that configured MTU-safe bound.

## Row Group Planning

The planner builds a reusable description of one encoded row group without
owning copies of values.

Because datagrams are intentionally small, the planner should use bounded
linear scans over preallocated vectors rather than generic hash tables.

### Proposed planner scratch

```rust
struct RowGroupScratch {
    columns: Vec<ColumnPlan>,
    cells: Vec<CellRef>,
    symbol_values: Vec<ValueSlice>,
    symbol_row_indexes: Vec<u16>,
}

struct ColumnPlan {
    name: NameSlice,
    kind: ColumnKind,
    nullable: bool,
    cell_start: u32,
    cell_count: u32,
    symbol_value_start: u32,
    symbol_value_count: u16,
    symbol_row_start: u32,
    symbol_row_count: u32,
}

struct CellRef {
    row_idx: u32,
    entry_idx: u32,
}
```

Notes:

* planner construction uses linear search over `columns` because column
  cardinality per datagram is bounded and small
* `cells` is sparse and append-only, so `cells.len()` equals the number of
  actual non-null entries in the current row group and planner cost stays
  O(actual entries)
  instead of O(rows * columns)
* `symbol_values` and `symbol_row_indexes` are shared flat scratch arenas with
  per-column ranges
* all scratch vectors are retained and reused across flushes
* `u16` for `symbol_row_indexes` is safe because an MTU-bounded datagram cannot
  approach 65535 rows; the effective row limit is orders of magnitude lower

This avoids both dense matrices and heap-backed lookup tables in the hot path.

Distinct symbol count per column is also MTU-bounded. The default design should
use bounded linear scans for symbol dedup. If profiling later shows that to be
insufficient, the acceptable upgrade is a fixed-capacity scratch index with no
heap growth, not a generic `HashMap`.

Symbol dictionaries are per-datagram, not per-segment. If one segment is split
across multiple datagrams, each datagram rebuilds its symbol dictionary from the
rows actually present in that datagram. This matches current wire behavior and
is the scope that planner reset logic must preserve.

Designated timestamps are handled as a synthetic planner column. While scanning
each row, the planner first visits user-provided entries in row order and then,
if `RowMeta.designated_ts` is present, injects a synthetic timestamp entry with
the reserved empty-column name used by the current QWP wire format.

This ordering is intentional and must match current wire behavior: the
designated timestamp column participates in first-seen column ordering exactly
where the existing encoder discovers it, which is after the row's user-provided
entries.

## Flush Pipeline

The production flush path should become a streaming loop:

1. Iterate `segments` in original input order.
2. For each segment, consider a growing prefix of rows for one datagram.
3. Use bounded planner scratch to incrementally track the exact encoded size for
   that prefix.
4. If adding the next row would exceed `max_datagram_size`, encode and send the
   current prefix, then reuse the scratch for the next one.
5. Encode directly into `scratch.datagram`.
6. Send directly to the UDP socket.
7. Reuse all scratch for the next datagram.

This removes `Vec<Vec<u8>>` from the hot path entirely.

### Partial failure semantics

This redesign should preserve current flush semantics:

* the buffer is cleared only after the full flush succeeds
* if a send fails after one or more earlier datagrams were already emitted,
  `flush()` returns an error and leaves the buffer intact
* the buffer does not track per-datagram progress or partially-flushed segments
* retrying after such an error may duplicate datagrams that were already sent

That ambiguity already exists in the current QWP/UDP implementation and is a
transport property of unacknowledged UDP sends, not something the buffer layer
can resolve internally.

### Test helper

If collecting datagrams is still useful in tests, keep it as a test-only helper:

* `collect_datagrams_for_test(...)`

That helper must not be used by the production send path.

## Encoding Strategy

### Header and schema

Build the datagram directly in `scratch.datagram`:

* write fixed QWP header
* write table name
* write row count
* write column count
* write schema mode
* write column name + wire type pairs

### Column payloads

Encode each column from planner references rather than copied values.

Examples:

* bool: write packed bits directly
* i64/f64/timestamp: write values directly from referenced entries
* string: write offsets and bytes directly from `value_bytes`
* symbol: build the dictionary in scratch using borrowed byte slices and
  bounded linear scans, then write dictionary and row indexes

The critical rule is:

* no column payload encoder is allowed to allocate fresh owned strings or fresh
  owned per-column vectors in steady state

For small datagrams this flush-local symbol planning is acceptable, provided it
stays within preallocated scratch and avoids heap-backed maps.

## `reserve()` and `capacity()`

The public docs already allow QWP capacity to be implementation-defined.

Proposed behavior:

* `reserve(additional)` must reserve all buffer-side hot-path storage, not just
  payload bytes
* at minimum it reserves `name_bytes`, `value_bytes`, `rows`, `entries`, and
  `segments`
* reserve calculations should use conservative worst-case bounds derived from
  `additional` bytes of eventual encoded payload
* sender construction must separately prewarm `scratch.datagram` and all
  planner-side vectors from configured `max_datagram_size`
* the intended operating point is that `max_datagram_size` is set to an
  MTU-safe value rather than relying on IP fragmentation
* `capacity()` returns an implementation-defined retained-capacity hint, for
  example the aggregate retained bytes across the major QWP arenas

The important guarantees are:

* `clear()` does not throw away retained QWP capacity
* after `reserve()` and sender prewarm, bounded hot-path workloads do not need
  further heap growth

Before prewarm or reserve, vector growth is still allowed. Those allocations are
acceptable outside steady state. Implementation may use `try_reserve` where it
helps surface predictable errors, but the key requirement is that hot-path
steady state is allocation-free after prewarm.

## Behavior That Must Stay Identical

The redesign must preserve all of the following:

* public `Sender` and `Buffer` method behavior
* QWP flush clearing semantics
* marker and rewind semantics
* transactional flag behavior
* maximum-name-length validation
* duplicate-column detection within a row
* type-change errors within a contiguous same-table batch
* split behavior when `max_datagram_size` is exceeded
* single rows that exceed `max_datagram_size` must fail with an error rather
  than being fragmented or sent oversized
* failed flushes do not clear the buffer, even if some earlier datagrams from
  the same flush attempt were already emitted
* wire encoding, byte for byte

## Threading

The threading contract does not change.

The redesign must not introduce internal locking or shared mutable state across
buffers or senders. Public buffer and sender types should preserve their current
single-owner usage model and should not gain broader `Send` / `Sync` behavior
accidentally as a side-effect of the internal rewrite.

## Migration Plan

### Phase 1: Replace buffer storage

* introduce flat arenas and arena-specific slice types
* switch row commit logic to produce `RowMeta` / `EntryMeta`
* make `clear()` and marker rewind length-based
* port `len()` / `row_count()` / `transactional()` to the new storage

### Phase 2: Replace flush scratch

* introduce sender-owned `QwpSendScratch`
* change flush to stream datagrams directly to the socket
* keep an internal test-only datagram collector if needed

### Phase 3: Remove legacy helpers

* delete temporary row-spec builders
* delete batch-column builders that allocate fresh vectors per flush
* delete production uses of `Vec<Vec<u8>>`

## Test Plan

Keep the existing QWP decode and behavior tests, then add:

* byte-for-byte golden tests for representative datagrams
* repeated `fill -> clear -> refill` tests asserting retained capacity is not
  discarded
* repeated `table/symbol/column/at/flush/clear` tests asserting no allocations
  after prewarm or warmup
* marker/rewind tests that verify truncation does not corrupt subsequent flushes
* marker/rewind tests that extend an existing segment after the marker and then
  verify the tail segment's `row_count` is restored correctly
* split-boundary tests near varint, bitmap, and symbol-dictionary size changes
* single-row-oversize tests that verify flush fails when one row alone exceeds
  `max_datagram_size`
* long-lived churn tests that verify unique-name traffic does not create
  unbounded retained metadata outside live buffer contents
* sparse and wide row-shape tests to confirm planner scratch stays bounded by
  actual entries and configured datagram size
* clone-while-pending tests that verify the original and clone diverge cleanly
  after subsequent row construction

Add an allocation-counting test harness for the Rust QWP path. This is
mandatory, not optional.

Those tests should not rely on a global allocator counter running concurrently
with the full test suite. Run them single-threaded or in a subprocess so the
measured allocation counts are attributable to the QWP hot path only.

## Acceptance Criteria

The redesign is complete when all of the following are true:

* existing QWP wire-level tests still pass
* the public `Sender` API behavior is unchanged
* the production send path no longer constructs `Vec<Vec<u8>>`
* `clear()` preserves reusable QWP capacity across batches
* after sender prewarm and buffer reserve, repeated bounded hot-path batches do
  not allocate in steady state
* repeated flushes reuse sender scratch instead of rebuilding fresh temporary
  containers
* the hot path uses no generic heap-backed hash tables

## Summary

The right fix is not to pool the current nested structures more aggressively.
The right fix is to remove those structures from the hot path.

The new design keeps compatibility only where it matters, uses flat retained
storage in the buffer, uses reusable sender-owned scratch at flush time, and
streams encoded datagrams directly to the socket while preserving the exact
wire protocol.
