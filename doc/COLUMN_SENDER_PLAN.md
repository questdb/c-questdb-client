# Column-Major Sender — Implementation Plan

**Status:** draft, pending approval
**Owner:** TBD
**Audience:** engineers implementing the Rust core, the C FFI, and the
separate Python wrapper repo.

---

## 1. Goal

Ship a column-major writer that ingests **Pandas and Polars DataFrames into
QuestDB at the maximum throughput the QWP/WebSocket wire allows.**

That is the whole goal. Every design choice in this plan is justified by
"does it make `df → QuestDB` faster?" Anything else is out of scope.

**This is a client for an existing server implementing the QWP ingress
(WebSocket) v1 wire specification.** The spec lives at
`questdb/documentation/connect/wire-protocols/qwp-ingress-websocket.md`
in the documentation repo. Wire framing, column types, null encoding
(bit = 1 NULL, dense values), schema model, symbol delta dictionary,
ack/sequence semantics, and protocol limits are all fixed by the spec.
We invent nothing the spec covers; the design freedom is purely in how
the FFI exposes the wire to Pandas/Polars callers efficiently.

### Non-goals

- A generic columnar ingestion library. No Arrow C Data Interface, no
  generic column-source traits, no support for "hypothetical other column
  formats." If/when those are needed they live above the FFI, in a
  language-specific wrapper.
- Replacing the row-major `Sender`/`Buffer` path. The row API stays as-is
  for users who think in rows.
- QWP/UDP support. UDP's internal buffer is row-major and unreliable; the
  column-major path targets QWP/WS only.
- A Python binding inside this repo. Python lives in its own repo and
  consumes the C ABI defined in `COLUMN_SENDER_FFI_ABI.md`.
- New wire-protocol work. The wire format already is column-major.

---

## 2. Why this is a small change to the wire and a big change to the API

The QWP/WS wire format is **already column-major.** The row-API path
(`Buffer` / `QwpWsColumnarBuffer`) pays per-cell name-lookup and
op-state validation: for 50M rows × 6 columns that's 300M name lookups
+ 300M op-state checks before any actual encoding happens. The
column-major API replaces all of that with **6 bulk appends per chunk
+ 1 encode pass**.

### 2.1 Decoupled from the existing row encoder *and the row publisher*

Performance is the goal; **code reuse is a non-goal**. The column
sender does **not** reuse `QwpWsColumnarBuffer`, the row API's
encoder, **or the row API's publisher / driver / queue stack**. It
owns its own QWP/WebSocket socket end-to-end via a dedicated
`ColumnConn` type (`questdb-rs/src/ingress/column_sender/conn.rs`):

- one write buffer reused across flushes (no per-frame allocation);
- the encoder writes the QWP frame body directly into that buffer at
  offset `WS_HEADER_RESERVE = 14`, leaving room to prepend the WS
  header in place once the payload length is known;
- the buffer is masked in place per RFC 6455 §5.3 and `write_all`'d to
  the socket — at most one frame in flight by construction;
- the ack reader synchronously parses the QWP response inline (no
  replay queue, no background thread).

What is shared with the row API is only what *must* stay coherent at
connection scope:

- `SymbolGlobalDict` (`questdb-rs/src/ingress/buffer/qwp.rs:5041`) —
  the connection-scoped symbol intern table the wire requires. A
  fresh instance per `ColumnConn`.
- The shared RFC 6455 WS plumbing in `crate::ws::{frame, mask,
  handshake, crypto}` (handshake, frame header parse,
  client-frame encode, mask key source).
- TCP connect + TLS setup + WS handshake, reached via
  `SenderBuilder::build_qwp_ws_raw_stream` which returns a
  `RawQwpWsStream` and never assembles the row-API publisher /
  driver / queue.

Note that the column sender carries **no schema cache**. QWP is
single-version with inline schemas (questdb #7200), so the column
definitions (name + wire type) travel inline on every frame — right
after the column count, with no schema-mode byte and no schema id —
exactly like the row API
(`QwpWsColumnarBuffer::encode_ws_replay_message`).

What is *not* shared, and is duplicated verbatim where simplest, is
the QWP response parser (one binary OK / DurableAck / error frame at
a time) and the wire-formatting helper surface (varint writers,
type-byte tables, schema-signature construction). These are stable per
the QWP v1 spec; duplicating costs ~150 lines and removes one layer
of indirection from the hot path.

### 2.1.1 Borrow-not-copy

`Chunk<'a>` holds **raw pointers** into the caller's column buffers,
not copied wire-shape bytes. Each `column_*` call validates input
(name, lengths, varchar offset monotonicity, symbol-code range) and
stores a descriptor; the encoder dereferences the pointers at flush
time. The caller's buffers must outlive flush.

On the Rust API, the lifetime parameter `'a` ties the chunk to every
borrowed buffer, so the borrow checker catches use-after-free at
compile time. The FFI layer carries the same shape via
`Chunk<'static>` and an explicit ABI contract — see
`doc/COLUMN_SENDER_FFI_ABI.md` §2.3.

### 2.2 Two code paths per type

For every numeric/fixed-width column, the bulk-append function
branches on validity at the top:

- **`validity == NULL`** (no nulls): single `extend_from_slice` /
  `memcpy` from the caller's buffer into the column's wire-shape
  storage. Emit `null_flag = 0x00`.
- **`validity != NULL`**: one pass that (a) inverts the Arrow bitmap
  to QWP wire semantics (bit=1 means NULL) and (b) gathers non-null
  values densely into the wire buffer. Emit `null_flag != 0x00` and
  the bitmap.

The first path is the common case for pandas/polars numeric columns
and should bottleneck on `memcpy` bandwidth. The second is a tight
loop with a branch on the validity bit, suitable for SIMD where the
types allow.

---

## 3. Architecture

```
Python repo (separate)                  c-questdb-client (this repo)
─────────────────────                   ─────────────────────────────
                                                Rust core
  pandas / polars DataFrame ──┐
       ▼                      │         ┌─────────────────────────────┐
  Python wrapper              │  C ABI  │  QuestDb  (pool, shareable) │
  - extract typed buffers     ├────────►│   ├─ conn #1 ┐              │
  - extract validity bitmap   │         │   ├─ conn #2 ├─ each owns:  │
  - extract category codes &  │         │   └─ ...     │  publisher,  │
    dict for symbols          │         │              │  SchemaReg,  │
                              │         │              │  SymbolDict  │
                              │         │   borrow_column_sender / return    │
                              │         │     │                       │
                              │         │     ▼                       │
                              │         │  ColumnSender (borrowed)    │
                              │         │   ├─ new_chunk              │
                              │         │   └─ flush (sync, blocks    │
                              │         │       until server ACK)     │
                              │         └─────────┬───────────────────┘
                                                  │
                                                  ▼  (BulkChunk encoder,
                                                      a new module)
                                              QWP/WS frame → server
```

Layering rules:

- **The C ABI must be expressible as a thin wrapper around typed Rust
  slices.** Per-column-append functions take `ptr + len + optional
  validity bitmap`. Nothing else.
- **The user thinks `DataFrame → Table`.** One chunk = one table = one
  DataFrame = one QWP frame = one FSN.
- **A `QuestDb` is shareable across threads; a borrowed `ColumnSender`
  is not.** The pool absorbs the per-connection thread-safety
  constraint.

---

## 4. Rust API (public surface)

New module: `questdb-rs/src/ingress/column_sender/` with submodules
`sender.rs`, `chunk.rs`, `validity.rs`, `encoder.rs`, `error.rs`. The
`QuestDb` pool handle lives in the top-level `questdb-rs/src/db.rs` module
(a peer of `ingress`/`egress`), re-exported as `questdb::QuestDb`; the
column types are re-exported under
`questdb::ingress::column_sender::{ColumnSender, Chunk, Validity}`.

```rust
/// Connection pool. Shareable across threads. One `QuestDb` per
/// connect string per process (typical usage).
pub struct QuestDb { /* pool of Connection (private) */ }

impl QuestDb {
    /// Open a pool. Eagerly opens `pool_size` connections (default 1).
    /// Pool knobs: `pool_size=N` (default 1), `pool_max=M` (default 64),
    /// `pool_idle_timeout_ms=T` (default 60000), `pool_reap=auto|manual`
    /// (default auto). Plus all standard `qwpws::` keys.
    pub fn connect(conf: &str) -> Result<Self>;

    /// Borrow a sender. If a previously-returned sender is free, hand
    /// it out; else, if pool size < `pool_max`, open a new connection
    /// and hand out a sender bound to it; else return InvalidApiCall
    /// (fail-fast at cap).
    pub fn borrow_column_sender(&self) -> Result<BorrowedColumnSender<'_>>;

    /// Manually reap idle connections (closes those above `pool_size`
    /// idle longer than `pool_idle_timeout_ms`). Returns the count
    /// closed. Background reaper does this for you under `pool_reap=auto`.
    pub fn reap_idle(&self) -> usize;

    pub fn close(self);
}

/// Borrowed sender. Returns to the pool on `Drop`. Not `Send`/`Sync` —
/// belongs to the borrowing thread.
pub struct BorrowedColumnSender<'a> { /* borrow handle into QuestDb */ }

impl<'a> std::ops::Deref     for BorrowedColumnSender<'a> { type Target = ColumnSender; … }
impl<'a> std::ops::DerefMut  for BorrowedColumnSender<'a> { … }
impl<'a> Drop                for BorrowedColumnSender<'a> { … }   // returns to pool

/// Thin handle over a borrowed connection.
pub struct ColumnSender { /* &mut Connection (lifetime-bound) */ }

impl ColumnSender {
    /// Create a chunk for a given table. Doesn't touch the connection
    /// — chunks are pure data until flushed.
    pub fn new_chunk(&self, table: TableName) -> Chunk;

    /// Synchronously flush a chunk: encode → publish → block until the
    /// server ACK at the requested level arrives. On success the chunk
    /// is cleared (allocations retained) ready for the next DataFrame.
    /// On failure the chunk is left untouched.
    ///
    /// `ack_level`:
    /// - `AckLevel::Ok` — wait for WAL-commit ACK (spec status `0x00`).
    ///   Always available.
    /// - `AckLevel::Durable` — wait for object-store durability ACK
    ///   (spec status `0x02`). Enterprise feature; requires the pool
    ///   to be opened with `request_durable_ack=on` in the connect
    ///   string. If the connection did not opt in, returns
    ///   `InvalidApiCall`.
    ///
    /// At most one frame in flight per sender; for parallel ingest,
    /// borrow multiple senders from the `QuestDb` pool.
    pub fn flush(&mut self, chunk: &mut Chunk, ack_level: AckLevel) -> Result<()>;

    pub fn must_close(&self) -> bool;
}

#[derive(Clone, Copy, Debug, Default)]
pub enum AckLevel {
    /// Server's WAL commit (spec status `0x00`). Always available.
    #[default]
    Ok,
    /// Server's object-store durability (spec status `0x02`).
    /// Enterprise + requires durable-ack opt-in at connect.
    Durable,
}

pub struct Chunk { /* table name + Vec<ChunkColumn> + row_count */ }

impl Chunk {
    /// First call locks `row_count`. All subsequent column appends
    /// MUST have the same length (counted in logical rows, not bytes).

    // Numeric columns — zero-copy from contiguous typed slice.
    pub fn column_i8 (&mut self, name: ColumnName, data: &[i8 ], v: Option<&Validity>) -> Result<()>;
    pub fn column_i16(&mut self, name: ColumnName, data: &[i16], v: Option<&Validity>) -> Result<()>;
    pub fn column_i32(&mut self, name: ColumnName, data: &[i32], v: Option<&Validity>) -> Result<()>;
    pub fn column_i64(&mut self, name: ColumnName, data: &[i64], v: Option<&Validity>) -> Result<()>;
    pub fn column_f32(&mut self, name: ColumnName, data: &[f32], v: Option<&Validity>) -> Result<()>;
    pub fn column_f64(&mut self, name: ColumnName, data: &[f64], v: Option<&Validity>) -> Result<()>;
    pub fn column_bool(&mut self, name: ColumnName, data: &[u8] /* arrow bitmap */, v: Option<&Validity>) -> Result<()>;

    // Fixed-width binary columns.
    pub fn column_uuid   (&mut self, name: ColumnName, data: &[[u8;16]], v: Option<&Validity>) -> Result<()>;
    pub fn column_long256(&mut self, name: ColumnName, data: &[[u8;32]], v: Option<&Validity>) -> Result<()>;
    pub fn column_ipv4   (&mut self, name: ColumnName, data: &[u32],     v: Option<&Validity>) -> Result<()>;

    // Time columns.
    pub fn column_ts_nanos (&mut self, name: ColumnName, data: &[i64], v: Option<&Validity>) -> Result<()>;
    pub fn column_ts_micros(&mut self, name: ColumnName, data: &[i64], v: Option<&Validity>) -> Result<()>;
    pub fn column_date_millis(&mut self, name: ColumnName, data: &[i64], v: Option<&Validity>) -> Result<()>;

    // Variable-width text — QWP has exactly one text type, VARCHAR
    // (wire 0x0F, uint32 offsets). The older STRING (0x08) was
    // removed from the spec.
    // Input is Arrow Utf8 shape: i32 offsets + bytes; library
    // compresses to dense uint32-offset layout on the wire.
    pub fn column_varchar(&mut self, name: ColumnName, offsets: &[i32], data: &[u8], v: Option<&Validity>) -> Result<()>;

    // Symbol fast path: dictionary-encoded.
    // `codes` are per-row indices into `dict_offsets`/`dict_data` (Arrow Utf8).
    // The implementation interns the dict against SymbolGlobalDict once
    // and remaps codes in bulk — no per-row HashMap probe.
    pub fn symbol_dict_i8 (&mut self, name: ColumnName, codes: &[i8 ], dict_offsets: &[i32], dict_data: &[u8], v: Option<&Validity>) -> Result<()>;
    pub fn symbol_dict_i16(&mut self, name: ColumnName, codes: &[i16], dict_offsets: &[i32], dict_data: &[u8], v: Option<&Validity>) -> Result<()>;
    pub fn symbol_dict_i32(&mut self, name: ColumnName, codes: &[i32], dict_offsets: &[i32], dict_data: &[u8], v: Option<&Validity>) -> Result<()>;

    // Designated timestamp (required, exactly once per chunk; pick one).
    // Emitted on the wire as an empty-name column of type
    // TIMESTAMP (0x0A) for micros, TIMESTAMP_NANOS (0x10) for nanos.
    pub fn designated_timestamp_micros(&mut self, data: &[i64]) -> Result<()>;
    pub fn designated_timestamp_nanos (&mut self, data: &[i64]) -> Result<()>;

    // Lifecycle.
    pub fn row_count(&self) -> usize;
    pub fn clear(&mut self);   // retains capacity for reuse
}

/// Validity bitmap. Public API accepts **Arrow semantics**
/// (bit = 1 means valid, LSB-first within each byte) to enable
/// zero-copy from PyArrow / Polars / Pandas buffers. Length in bits
/// must equal the chunk's row_count.
///
/// The QWP wire uses the inverted semantics (bit = 1 means NULL) and
/// dense data (only non-null values). The library inverts the bitmap
/// and gathers when encoding; callers never construct QWP-shaped
/// input.
pub struct Validity<'a> { bits: &'a [u8] }
impl<'a> Validity<'a> {
    pub fn from_bitmap(bits: &'a [u8], bit_len: usize) -> Result<Self>;
}
```

### What `column_*` does internally

1. Validate name (or skip when `ColumnName` already validated).
2. Look up or create the column slot in the chunk's `Vec<ChunkColumn>`.
   **Once per column per chunk, not per row.**
3. Append data to the column's storage:
   - For numeric/fixed-width columns where the chunk's internal storage
     is `Vec<T>` of the same `T`, this is a single `Vec::extend_from_slice`.
   - For columns with null-bitmap representation, also OR the validity
     bitmap into the column's null bitmap (bulk, byte-aligned where
     possible).
4. Bump the per-column row counter; assert it matches `chunk.row_count`.

### Symbol bulk-intern

The expensive part of symbol handling today is per-row
`SymbolGlobalDict::intern` (qwp.rs:5041). The fast path:

1. Walk `dict_offsets`/`dict_data` once: build a small
   `Vec<u64>` of length `dict_len` mapping each dict entry's local
   index → global id (one `intern()` per *unique* symbol value, not per
   row).
2. Walk `codes` once, writing the mapped global ids into the column's
   storage — a tight loop, branch-predictable, ~1ns/row.

For a 10M-row symbol column with cardinality 1000, this drops from 10M
HashMap probes to 1000.

---

## 5. Workstreams

Designed so multiple engineers can work in parallel after WS-0 + WS-1
land.

### WS-0 — QuestDb pool, sender borrow, idle reaper (blocking dependency)

- Create `questdb-rs/src/ingress/column_sender/db.rs` with the pool
  type, eagerly opening `pool_size` connections at `connect()`.
- Connect-string parsing: lift the existing `qwpws::` parser; add
  `pool_size` (default 1), `pool_max` (default 64),
  `pool_idle_timeout_ms` (default 60000), `pool_reap`
  (`auto`|`manual`, default `auto`). Reject configs with
  `pool_size > pool_max`.
- `borrow_column_sender()` semantics: pull from free list if any; else if
  pool size < `pool_max`, open a new connection; else return
  `InvalidApiCall` (fail-fast).
- `BorrowedColumnSender<'_>` returns the connection to the pool on `Drop`
  with a `last_idle_at = Instant::now()` stamp. If
  `must_close()` is true on return, drop the connection.
- **Idle reaper.** Under `pool_reap=auto`, the pool spawns one
  background `std::thread` on `connect`. The thread wakes on a ticker
  (~5s or `pool_idle_timeout_ms / 12`, whichever is larger), scans the
  free list, closes connections idle longer than
  `pool_idle_timeout_ms`, **never shrinking below `pool_size`**. The
  thread is joined on `close()`. Manual mode skips the thread entirely;
  `db.reap_idle()` runs the same scan on demand and is exposed on
  the FFI.
- Thread-safety: the pool's internal state (free list, total count,
  per-connection idle stamp) is guarded by a `Mutex`. Borrow/return/reap
  are safe to call concurrently while the owning handle stays alive.
  `close` (and `Drop`) is the final owner release, not a concurrent pool
  operation: callers must quiesce all db-level borrow/reap/config calls on
  that handle before closing. Outstanding owned handles still return/drop
  safely after close; new operations on them then fail with
  `InvalidApiCall`.
- Owner: 1 engineer.
- Done when:
  - multi-thread test borrows and returns N senders concurrently
    without deadlock or leak,
  - pool fails-fast at `pool_max`,
  - idle reaper (auto and manual) closes excess connections after the
    timeout while keeping `pool_size` warm,
  - `close()` joins the reaper cleanly.

### WS-1 — `ColumnSender` thin handle & synchronous flush plumbing

- Define `ColumnSender` as a `&mut Connection` lifetime-bound borrow
  handle. Implement `flush(chunk)` that calls the new encoder
  (WS-2/3/4), hands the encoded frame to the existing publisher
  (`questdb-rs/src/ingress/sender/qwp_ws_publisher.rs`), and blocks
  until the server ACK arrives.
- Internally the publisher still tracks the wire `sequence` (FSN);
  `flush` waits on that FSN. FSN is not exposed at the public API.
- Hook up `must_close`.
- Refuse `sf_dir` (and other `sf_*` keys) at `QuestDb::connect`-time
  with `ConfigError`. Update WS-0's connect-string parser
  accordingly.
- Stub `flush()` on an empty chunk: produces a header-only QWP frame
  end-to-end (no columns; pure framing), server accepts and ACKs.
- Owner: 1 engineer.
- Depends on: WS-0.
- Done when: empty-chunk `flush` round-trips against a real server and
  returns on ACK; `sf_dir` in the connect string is rejected with a
  clear error.

### WS-2 — `Chunk`, `BulkChunk` encoder, numeric/fixed-width columns

- Define `Chunk` (caller-owned, table-bound) and the internal
  `BulkChunk` wire-shape storage: per-column `Vec<u8>` already in QWP
  wire layout (dense values + optional null bitmap with QWP
  semantics) so encode is a header + `extend_from_slice` per column.
- Implement the **two code paths per type** (see §2.2): no-null
  fast-memcpy; nullable invert+gather. Both produce identical
  on-wire shape modulo the null_flag byte.
- Implement `column_i8`/`i16`/`i32`/`i64`/`f32`/`f64`/`bool`/`uuid`/
  `long256`/`ipv4`/`ts_nanos`/`ts_micros`/`date_millis` +
  `designated_timestamp_micros` + `designated_timestamp_nanos`.
- Implement `Validity` (Arrow-shape in: 1=valid, LSB-first). Library
  masks trailing bits beyond row_count.
- Implement the table-header + schema-section emit. The schema (column
  name + wire type per column) is written inline after the column count
  on every frame — no schema-mode byte, no schema id, no schema cache.
- Owner: 1 engineer.
- Depends on: WS-1.
- Done when: round-trip test for each type passes against a real
  server and a benchmark shows the per-row cost is dominated by
  memcpy bandwidth, not API overhead.

### WS-3 — VARCHAR column

- Implement `column_varchar`. Input is Arrow Utf8 shape (i32 offsets +
  bytes). Wire output is dense (only non-null) with uint32 offsets per
  QWP spec §VARCHAR.
- Two code paths per §2.2:
  - No-null: copy all `row_count + 1` offsets unchanged (caller's i32
    fits trivially in wire u32) + copy the full byte buffer.
  - Nullable: walk validity bitmap; for each non-null row, compute
    `slice_len = offsets[i+1] − offsets[i]`, append dense offsets and
    bytes for that slice. **Skip slicing for null rows** — do not
    trust caller's offset values for null rows.
- UTF-8 is trusted; server rejects invalid UTF-8 with PARSE_ERROR.
- Owner: 1 engineer.
- Depends on: WS-1, +reads WS-2's `Chunk` shape.
- Done when: round-trip + null handling test passes; benchmark within
  ~2× of f64 column throughput for short strings (varchar is
  fundamentally variable-width so equal-throughput is unrealistic).

### WS-4 — Symbol bulk-intern fast path

- Implement `symbol_dict_{i8,i16,i32}`.
- Share the connection-scoped `SymbolGlobalDict` (qwp.rs:5041). New
  code interns through it; emits the new symbols in the delta-dict
  prefix of the QWP frame.
- **Intern only referenced dict entries.** Pandas/polars `Categorical`
  carries every category ever observed (often 100k+) but a typical
  chunk references a small subset. The implementation:
  1. One pass over `codes` to mark referenced dict indices in a
     bitset (sized `dict_len`).
  2. One pass over the bitset: intern each referenced dict entry,
     build a `Vec<u64>` of length `dict_len` mapping local → global
     (unreferenced slots get `u64::MAX` sentinel).
  3. One pass over `codes` writing global IDs into the wire buffer.
  This protects the 1M-per-connection wire limit and avoids
  polluting `SymbolGlobalDict` with never-sent values.
- Validate codes are in `0..dict_len` for non-null rows; out-of-range
  is `InvalidApiCall`. Codes for null rows are not inspected.
- Owner: 1 engineer.
- Depends on: WS-1; can develop in parallel with WS-2/3.
- Done when: 10M-row × 1000-card benchmark shows symbol throughput
  within 2× of f64 throughput (today, symbol throughput is much worse).

### WS-5 — C FFI surface

- Implement the ABI defined in `COLUMN_SENDER_FFI_ABI.md`. Two FFI
  namespaces:
  - `questdb_db_*` — pool/borrow (`connect`, `close`, `borrow_column_sender`,
    `return_sender`). Lands once WS-0 lands.
  - `column_sender_chunk_*` + `column_sender_submit` /
    `_await_acked_fsn` — chunk fill and submit. Each column function
    ships the moment its Rust counterpart lands.
- Code lives in `questdb-rs-ffi/src/column_sender.rs`, re-exported from
  `lib.rs`.
- Header lives at `include/questdb/ingress/column_sender.h`. Defer the
  `.hpp` until someone needs a C++ wrapper — the Python wrapper does
  not.
- `cbindgen.toml` updates if the column sender is exposed by cbindgen.
- Owner: 1 engineer.
- Depends on: WS-0/2/3/4 land in parallel.
- Done when: a C test program (in `cpp_test/` or `system_test/`) opens
  a pool, borrows a sender, submits a chunk, returns the sender, and
  the server stores the rows.

### WS-6 — Benchmarks & soak tests

- Microbench (Criterion in `questdb-rs/benches/`):
  - per-column bulk append, vs the row-API equivalent, vs raw memcpy
    baseline, for each type;
  - symbol intern (dict path) vs per-row symbol intern (row API);
  - end-to-end "10M rows × N columns" chunk submit (in-memory, no
    network), to measure pure encoder + populate cost.
- End-to-end throughput test against a local QuestDB: Pandas DataFrame
  → submit → ack, varying row counts, column counts, dtypes. Report
  GB/s in and rows/s.
- Soak: 1-hour run sending random chunks; assert no leaks, no
  reconnects, latched-error handling works.
- Owner: 1 engineer.
- Depends on: WS-2 minimum.
- Done when: benchmark numbers documented in `doc/DEV_NOTES.md` or a
  new `doc/COLUMN_SENDER_PERF.md`.

### WS-7 — Python repo coordination (out-of-tree, tracked here)

- The Python repo wraps `column_sender.h`. The Python repo's agent
  works from `COLUMN_SENDER_FFI_ABI.md` alone.
- Python repo TODOs (tracked there, listed here for visibility):
  - Build a thin ctypes/cffi/pyo3 wrapper around the C ABI.
  - For Pandas: extract numpy buffers per column via `Series.to_numpy()`
    (zero-copy for native dtypes), build validity bitmaps from
    `Series.isna()` (LSB-first packing — provide a vectorised helper).
  - For Polars: extract Arrow buffers via `Series.to_arrow()`; the
    Arrow buffer pointers and validity bitmaps go straight to FFI.
  - For Pandas `Categorical` / Polars `Categorical`: use
    `symbol_dict_*`.
  - Document the slow paths (object-dtype strings, mixed dtypes,
    extension types) and the fallbacks (materialise to a contiguous
    typed array).

---

## 6. Type mapping reference

| QWP wire type | Rust API           | Pandas dtype                 | Polars / Arrow dtype       | FFI shape                |
|---------------|--------------------|------------------------------|----------------------------|--------------------------|
| BOOL          | `column_bool`      | `bool` (numpy)               | `Boolean` (Arrow bitmap)   | `uint8_t*` (bitmap)      |
| BYTE          | `column_i8`        | `int8`                       | `Int8`                     | `int8_t*`                |
| SHORT         | `column_i16`       | `int16`                      | `Int16`                    | `int16_t*`               |
| INT           | `column_i32`       | `int32`                      | `Int32`                    | `int32_t*`               |
| LONG          | `column_i64`       | `int64`                      | `Int64`                    | `int64_t*`               |
| FLOAT         | `column_f32`       | `float32`                    | `Float32`                  | `float*`                 |
| DOUBLE        | `column_f64`       | `float64`                    | `Float64`                  | `double*`                |
| VARCHAR       | `column_varchar`   | `string` / object (fallback) | `Utf8` (Polars `LargeUtf8` → wrapper splits) | `int32_t*` + `uint8_t*` |
| SYMBOL        | `symbol_dict_iN`   | `Categorical`                | `Categorical` / Dict<Utf8> | codes + dict offsets+bytes |
| TIMESTAMP     | `column_ts_nanos`/`_micros` | `datetime64[ns]`/`[us]` | `Datetime(ns/us)`      | `int64_t*`               |
| DATE          | `column_date_millis` | `datetime64[ms]`           | `Date` (after cast)        | `int64_t*`               |
| UUID          | `column_uuid`      | bytes (no native)            | Arrow `FixedSizeBinary(16)`| `uint8_t*` (16N)         |
| IPV4          | `column_ipv4`      | uint32 (no native)           | `UInt32`                   | `uint32_t*`              |
| LONG256       | `column_long256`   | bytes (no native)            | Arrow `FixedSizeBinary(32)`| `uint8_t*` (32N)         |

**Out of v1 scope:** `DECIMAL64/128/256`, `LONG_ARRAY`, `DOUBLE_ARRAY`,
`GEOHASH`, `CHAR`, `BINARY`. Add in a follow-up milestone driven by
actual user demand from the Python wrapper.

---

## 7. Threading & error model (inherited)

- One `ColumnSender` is bound to one connection. Not `Sync`. Use
  multiple senders for parallel ingestion.
- `Chunk` is owned by one thread. After `submit`, the chunk can be
  cleared and reused.
- Error model is identical to the existing QWP/WS sender (see
  `questdb-rs/src/ingress/mod.md` §"QWP/WebSocket"): drop-and-continue
  vs halt; `must_close()`; FSN ack semantics.
- The Java client (`../java-questdb-client`, see memory
  [[reference-java-questdb-client]]) is the posture reference for
  parser-vs-writer trust split. The column-major API is the *writer*
  side — it trusts its caller and panics nowhere
  (memory [[feedback-client-no-panic]]).

---

## 8. Decisions log

All architectural decisions are locked. Anyone implementing should
flag a deviation rather than re-litigate silently.

### Settled by the QWP/WS v1 spec (non-negotiable)

- Wire framing, column type codes, schema model, sequence numbering,
  symbol delta-dictionary, durable-ack opt-in, version negotiation,
  protocol limits.
- Null encoding on the wire: bit = 1 means NULL, LSB-first; data after
  the bitmap is dense. Internal encoder matches; FFI exposes the
  inverted (Arrow-style) semantics for zero-copy from Pandas/Polars
  and does the invert+gather internally.
- Wire is contiguous-per-column; strided input is the wrapper's
  problem.
- UTF-8 validation: server enforces; we trust by default.
- Text type: VARCHAR only (`0x0F`, uint32 offsets). STRING is gone.
- Designated timestamp: empty-name column of type TIMESTAMP (`0x0A`,
  µs) or TIMESTAMP_NANOS (`0x10`, ns).
- DATE on ingress is plain int64.
- FSN = wire `sequence` / `wireSeq`.

### Settled by user direction

- **API shape:** new top-level types, separate from `Buffer`/`Sender`.
  Naming: `QuestDb`, `ColumnSender`, `Chunk`, `Validity`.
- **Mental model:** `DataFrame → Table`. One chunk = one table = one
  DataFrame = one QWP frame = one FSN.
- **Send is synchronous.** `sender.flush(&mut chunk, ack_level)`
  blocks until the server ACK at the requested level arrives. Two
  levels: `Ok` (WAL commit, always available) and `Durable`
  (object-store durability — Enterprise; requires durable-ack opt-in
  at connect). At most one frame in flight per sender. Parallelism is
  expressed by borrowing multiple senders from the pool, one per
  thread. The wire's 128-in-flight cap is never reached. The QWP
  `sequence` / FSN is tracked internally and not exposed at the API
  or FFI surface.
- **Store-and-forward (`sf_dir`) is refused in v1.** Passing `sf_dir`
  or any other `sf_*` key to `QuestDb::connect` returns `ConfigError`.
  SF is single-writer per slot and interacts awkwardly with pool
  auto-grow. Users who need on-disk durability across crashes can use
  the existing row-major `Sender` API. Revisit if a real user needs
  both throughput and SF.
- **Connection layer:** pool (`QuestDb::connect`), borrow/return
  (`db.borrow_column_sender()` → drop returns to pool). Defaults:
  `pool_size=1`, `pool_max=64`, `pool_idle_timeout_ms=60000`. Eager
  open at connect, auto-grow on exhaustion, fail-fast at cap.
- **Idle shrinking:** Rust-side background reaper per pool
  (`pool_reap=auto`, default) closes excess-over-`pool_size`
  connections after `pool_idle_timeout_ms` idle. Manual mode
  (`pool_reap=manual`) disables the thread; `db.reap_idle()` /
  `questdb_db_reap_idle()` exposed for caller-driven reaping. Reaper
  lives in Rust so every binding (C/C++/Python) inherits the
  behaviour without re-implementing.
- **Encoder:** fresh `BulkChunk` encoder, no reuse of
  `QwpWsColumnarBuffer` or row-API encoder. Shares only connection-
  scoped state (`SymbolGlobalDict`, publisher); the schema travels
  inline per frame, so there is no schema cache. Code reuse is a
  non-goal; perf is the goal.
- **Two code paths per type:** no-null = `memcpy`; nullable = invert
  + gather in one pass.
- **Symbol intern:** scan codes first, intern only referenced dict
  entries.
- **Validity trailing bits:** library masks; caller need not zero.
- **VARCHAR null offsets:** library skips slicing; caller's value for
  null rows is ignored.
- **FFI:** raw pointers per column. No Arrow C Data Interface, no
  strides, no generic column-source traits.
- **Python:** lives in a separate repo; this repo provides the C ABI.

### Out of v1 scope (deferred)

- Multi-table-per-frame batching at the API. Wire supports it; v1 API
  is one chunk = one table. Revisit if the Python wrapper has a
  multi-table use case.
- DECIMAL64/128/256. Wire is defined (1-byte column-wide scale +
  dense unscaled ints). Defer until Polars-decimal demand surfaces.
- `LONG_ARRAY` / `DOUBLE_ARRAY` per-row, `GEOHASH`, `CHAR`, `BINARY`.
- C++ header wrapper (`column_sender.hpp`). Python wrapper does not
  need it.
- (Removed in this revision: durable-ack as deferred. See settled
  decisions for ack-level handling.)

