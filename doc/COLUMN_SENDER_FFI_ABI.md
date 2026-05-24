# Column-Major Sender — C ABI Specification

**Status:** draft, pending approval
**Header:** `include/questdb/ingress/column_sender.h` (to be added)
**Sibling header:** `include/questdb/ingress/line_sender.h` (existing,
shares error types)
**Audience:** the Python wrapper repo, and anyone writing a C/C++
client against this API.

This document is self-contained. It is the contract between
`c-questdb-client` (Rust core) and the Python wrapper repo. The Python
repo can be implemented from this spec without reading any Rust code.

---

## 1. Scope

This ABI exposes a column-major writer that ingests **per-column typed
buffers** into QuestDB via QWP/WebSocket. Optimised for sending
Pandas/Polars DataFrames at maximum throughput. One submission =
one QWP frame = one logical batch of rows for one table.

**This is a client for the existing QuestDB server implementing the QWP
ingress (WebSocket) v1 wire specification.** The spec is at
`questdb/documentation/connect/wire-protocols/qwp-ingress-websocket.md`
in the documentation repo. The protocol is fixed and the wire types,
null encoding, schema model, framing, and limits are not up for
negotiation in this API. The FFI's job is to expose that wire as
ergonomic, zero-overhead-where-possible calls for the Python wrapper.

Out of scope: the existing row-major `line_sender_*` ABI is unaffected;
this is an additional, orthogonal API. The two coexist on different
opaque types.

### 1.1 Spec-derived constraints (non-negotiable)

These come from the QWP/WS v1 wire spec and are enforced or surfaced
by this ABI. They are not API design choices.

| Limit                          | Value                                  | Enforcement                                              |
|--------------------------------|----------------------------------------|----------------------------------------------------------|
| Max batch (frame) size         | 16 MiB protocol ceiling; effectively `min(server recv buf − 14, 16 MiB)` advertised on upgrade via `X-QWP-Max-Batch-Size` | `column_sender_submit` returns an error if the encoded frame exceeds the negotiated cap. |
| Max tables per connection      | 10,000                                 | Server-enforced; client surfaces server rejections.       |
| Max rows per table block       | 1,000,000                              | `column_sender_chunk_*` calls fail if `row_count` exceeds. |
| Max columns per table          | 2,048                                  | `column_sender_chunk_column_*` fails after the 2048th column. |
| Max table / column name length | 127 bytes UTF-8                        | Rejected at name validation.                              |
| Max in-flight batches          | 128                                    | `column_sender_submit` blocks (or returns back-pressure) until an ack frees a slot. |
| Max symbol dictionary entries  | 1,000,000 per connection               | Server returns `PARSE_ERROR`; surfaced as `line_sender_error_server_rejection`. |

The wire pins protocol version 1; clients advertise
`X-QWP-Max-Version: 1`.

---

## 2. Universal conventions

### 2.1 Errors

Errors use the existing `line_sender_error*` type from
`line_sender.h` — same codes, same accessors (`line_sender_error_msg`,
`line_sender_error_get_code`, `line_sender_error_free`).

Every fallible function takes a trailing `line_sender_error** err_out`:

- On success, returns `true` and does not touch `*err_out`.
- On failure, returns `false` and, if `err_out != NULL`, sets
  `*err_out` to a heap-allocated error the caller must free with
  `line_sender_error_free`.

Pass `err_out = NULL` to discard the error.

### 2.2 Pointer conventions

Same as `line_sender.h`: opaque handles must be non-NULL. `err_out` may
be NULL. Lifecycle "free" functions accept NULL and no-op.

### 2.3 Buffer conventions

For every column-append function:

- `data` is a pointer to a **contiguous, full-length** typed array
  with one slot per row, **including null rows**. The slot value for
  a null row is ignored — it can hold anything. This matches the
  Arrow / Pandas / Polars layout, where data buffers are full-length
  and null status lives in a separate bitmap.
- Strided buffers are **not** supported in v1. The Python wrapper must
  materialise contiguous data before calling. (Pandas
  `Series.to_numpy(copy=False)` and Polars Arrow buffers are
  contiguous in the common case.)
- All column buffers passed in one chunk must have the same `row_count`
  — the chunk's row count, set by the first column-append call.
- **Buffer lifetime contract.** Buffers passed to a `column_sender_chunk_*`
  function (numeric columns, varchar offsets/bytes, symbol codes/dict
  offsets/dict bytes, designated timestamps, validity bitmaps) **must
  remain alive and unchanged until the next `column_sender_flush` call
  on the chunk returns** (or until `column_sender_chunk_free` /
  `column_sender_chunk_clear` is called without a flush). The FFI stores
  raw pointers into the caller's buffers; it does **not** copy at
  append time. This is required to hit memcpy-bandwidth throughput on
  the no-null hot path — see `doc/COLUMN_SENDER_PLAN.md` §2.
- For Python wrappers, the typical pattern is to fill the chunk from a
  live DataFrame's numpy / Arrow buffers and flush before letting the
  DataFrame go out of scope — the contract is naturally satisfied
  because flush is synchronous.

### 2.4 Validity bitmaps

The FFI accepts validity bitmaps in **Arrow semantics** (bit = 1 means
**valid**, bit = 0 means NULL). This is directly compatible with PyArrow
buffers, Polars Arrow buffers, and bitmaps produced by
`numpy.packbits(..., bitorder='little')`.

- Layout: one bit per row. Byte `i` holds rows `8*i .. 8*i+7`.
- Bit ordering is **LSB-first** within each byte (bit 0 of byte 0 is row 0).
- **Bit = 1 means VALID. Bit = 0 means NULL.**
- Buffer length in bytes must be at least `ceil(row_count / 8)`. Bits
  past `row_count` are ignored.
- Pass `validity = NULL` when the column has no nulls.

```c
typedef struct column_sender_validity {
    const uint8_t* bits;   // NULL = no nulls
    size_t bit_len;        // must equal chunk row_count
} column_sender_validity;
```

If `validity != NULL`, `validity->bit_len` must equal the chunk's row
count. Mismatches return `line_sender_error_invalid_api_call`.

**Wire-format note (informative).** The QWP wire format uses the
*inverted* semantics — bit = 1 means NULL — and column data after the
bitmap is **densely packed** (only non-null values, count =
`row_count − null_count`). See spec §Null handling. The FFI accepts
the Arrow shape so PyArrow / Pandas / Polars buffers hand off
zero-copy; the library inverts the bitmap and gathers non-null values
when encoding the QWP frame. Callers never construct QWP-shaped
inputs.

### 2.5 Threading

- A `questdb_db` (the pool) is **thread-safe**. Share it across
  threads. `questdb_db_borrow_sender` and `questdb_db_return_sender`
  are safe to call concurrently.
- A `column_sender` (a borrow) is **not thread-safe**. It belongs to
  the borrowing thread until returned. Do not pass it across threads.
- A `column_sender_chunk` is owned by one thread at a time. It is
  *not* tied to a particular sender; chunks can be built without a
  borrow and submitted on any sender borrowed from the same `db`.
- `line_sender_error` is thread-safe to read but not to share writes.

### 2.6 String / UTF-8

String and symbol-dict bytes must be valid UTF-8. The library trusts the
caller by default (no per-row validation). Invalid UTF-8 will be
detected by the server and rejected. The Python wrapper is responsible
for ensuring valid UTF-8 from Pandas/Polars.

---

## 3. Opaque types

```c
typedef struct questdb_db        questdb_db;        /* connection pool */
typedef struct column_sender     column_sender;     /* borrowed handle */
typedef struct column_sender_chunk column_sender_chunk;
```

Errors reuse `line_sender_error*` (from `line_sender.h`).

---

## 4. Connection pool and sender borrow

### 4.1 Conceptual shape

The user thinks `DataFrame → Table`: a script holds one connection to
the database and pushes DataFrames at it. Under the hood, sending is
not thread-safe per connection, so multi-threaded ingest needs
multiple connections. The pool absorbs both cases:

```
                          ┌──────────────────────────┐
  questdb_db_connect ───► │  questdb_db (pool)       │
                          │   ├─ connection #1        │
                          │   ├─ connection #2 (lazy) │
                          │   └─ ...                  │
                          └──────────┬────────────────┘
                                     │ borrow_sender / return_sender
                                     ▼
                          ┌──────────────────────────┐
                          │  column_sender (borrowed)│
                          │   ├─ new_chunk            │
                          │   ├─ submit / await       │
                          │   └─ ...                  │
                          └──────────────────────────┘
```

Single-threaded scripts get pool size 1 by default — one borrow held
for the lifetime of the script. Multi-threaded callers borrow and
return per work unit (or per thread).

### 4.2 Connect-string keys (pool)

| Key                    | Default | Description                                                                                                                                  |
|------------------------|---------|----------------------------------------------------------------------------------------------------------------------------------------------|
| `pool_size`            | 1       | Warm / minimum connections, opened eagerly at `questdb_db_connect`. All N go through the full WS upgrade before `connect` returns. The pool never shrinks below this. |
| `pool_max`             | 64      | Hard cap on auto-grow. When all current senders are checked out and pool size < `pool_max`, a new connection is opened on demand. When at `pool_max`, `borrow_sender` fails fast (see §4.3).                       |
| `pool_idle_timeout_ms` | 60000   | Connections *above* `pool_size` are closed after this much idle time in the pool's free list. Set to 0 to disable shrink (the pool only grows). |
| `pool_reap`            | `auto`  | `auto` — pool spawns a background thread that periodically reaps idle connections per `pool_idle_timeout_ms`. `manual` — no background thread; caller invokes `questdb_db_reap_idle` on its own cadence. |

All other connect-string keys are inherited from the existing
`qwpws::` configuration (auth, TLS, `auth_timeout_ms`, retry,
durable-ack opt-in, etc.). See `doc/CONSIDERATIONS.md` and the
row-API connect-string reference.

**Not accepted in v1:** `sf_dir` and the other `sf_*` store-and-
forward keys (`sender_id`, `sf_max_bytes`, `sf_max_total_bytes`,
`sf_durability`, `sf_append_deadline_millis`). Passing any of them to
`questdb_db_connect` returns `line_sender_error_config_error` with a
message pointing to the row-major `line_sender` API for users who
need SF semantics. SF is fundamentally single-writer per slot and
interacts awkwardly with the pool's auto-grow; revisit only if a
real user needs both throughput and on-disk durability.

Validity: `pool_size <= pool_max` must hold; otherwise
`questdb_db_connect` returns `line_sender_error_config_error`.

### 4.3 Pool functions

```c
/**
 * Open a connection pool. Eagerly opens `pool_size` connections; any
 * server/auth/TLS error during those opens fails the call.
 *
 * `conf` is a standard `qwpws::` connect string. Non-WS schemes return
 * line_sender_error_config_error — the column-sender path is QWP/WS
 * only.
 */
QUESTDB_CLIENT_API
questdb_db* questdb_db_connect(
    const char* conf,
    line_sender_error** err_out);

/**
 * Close the pool and all its connections. Accepts NULL and no-ops.
 * Senders still checked out are invalidated; calls on them return
 * line_sender_error_invalid_api_call. Callers must not call close()
 * while any thread is mid-submit on a borrowed sender.
 */
QUESTDB_CLIENT_API
void questdb_db_close(questdb_db* db);

/**
 * Borrow a sender from the pool.
 *
 * Selection rules:
 *  1. If a previously-returned sender is in the free list, hand it out.
 *  2. Otherwise, if pool size < `pool_max`, open a new connection on
 *     demand (auto-grow) and hand out a sender bound to it.
 *  3. Otherwise (at `pool_max` cap, all checked out), return
 *     line_sender_error_invalid_api_call. This is fail-fast: hitting
 *     the cap signals either a leaked borrow or a `pool_max` set too
 *     low — both want an error rather than silent blocking. Caller may
 *     retry after returning senders.
 *
 * The returned sender is bound to the calling thread until returned.
 * Do not share across threads.
 */
QUESTDB_CLIENT_API
column_sender* questdb_db_borrow_sender(
    questdb_db* db,
    line_sender_error** err_out);

/**
 * Manually reap idle connections. Closes connections in the pool's
 * free list whose idle time exceeds `pool_idle_timeout_ms`, never
 * shrinking pool size below `pool_size`.
 *
 * When `pool_reap=auto` (the default), the pool runs an internal
 * background thread that calls this logic periodically; calling this
 * function manually is harmless. When `pool_reap=manual`, callers that
 * want shrinking must invoke this function on their own cadence (e.g.
 * from a daemon thread in the host language).
 *
 * Returns the number of connections closed by this invocation.
 */
QUESTDB_CLIENT_API
size_t questdb_db_reap_idle(questdb_db* db);

/**
 * Return a sender to the pool. The sender pointer is invalidated and
 * must not be used again after this call. Any chunks created from the
 * sender remain valid (chunks are caller-owned, not sender-owned) but
 * cannot be submitted until borrowed again from a new sender.
 *
 * If the sender is in a latched-error state (must_close() == true),
 * its underlying connection is closed and dropped from the pool
 * instead of returned.
 */
QUESTDB_CLIENT_API
void questdb_db_return_sender(
    questdb_db* db,
    column_sender* sender);
```

### 4.4 Sender state inspection

```c
/**
 * True if the sender's underlying connection is in a permanently-
 * unusable state (a QWP halt rejection, terminal WS protocol
 * violation, etc.). On return to the pool, such senders are dropped,
 * not recycled.
 */
QUESTDB_CLIENT_API
bool column_sender_must_close(const column_sender* sender);
```

---

## 5. Chunk lifecycle

A chunk represents one DataFrame's worth of column buffers destined
for one table. It is the "one chunk = one table = one frame = one
FSN" unit. Chunks are caller-owned and **not bound to a particular
sender** — build a chunk on any thread, submit it on any sender
borrowed from the same `db`.

```c
/**
 * Create an empty chunk for the given table. The table name must be
 * valid (same rules as line_sender_table_name; max 127 bytes UTF-8).
 *
 * Does not require a sender — the chunk is pure data until submitted.
 *
 * The chunk is owned by the caller and must be either submitted with
 * column_sender_submit (which clears it for reuse) or freed with
 * column_sender_chunk_free.
 */
QUESTDB_CLIENT_API
column_sender_chunk* column_sender_chunk_new(
    const char* table_name,
    size_t table_name_len,
    line_sender_error** err_out);

/**
 * Discard the chunk and all retained capacity. Accepts NULL and no-ops.
 */
QUESTDB_CLIENT_API
void column_sender_chunk_free(column_sender_chunk* chunk);

/**
 * Clear the chunk's content, keeping retained capacity for reuse.
 */
QUESTDB_CLIENT_API
void column_sender_chunk_clear(column_sender_chunk* chunk);

/**
 * Current row count of the chunk, as locked in by the first column
 * append. Zero if no columns have been added yet.
 */
QUESTDB_CLIENT_API
size_t column_sender_chunk_row_count(const column_sender_chunk* chunk);
```

---

## 6. Numeric and fixed-width column appends

All have the shape:

```c
bool column_sender_chunk_column_<TYPE>(
    column_sender_chunk* chunk,
    const char* name,
    size_t name_len,
    const <CTYPE>* data,
    size_t row_count,
    const column_sender_validity* validity,   // NULL if no nulls
    line_sender_error** err_out);
```

The first column-append call locks the chunk's `row_count`. Subsequent
calls must pass the same `row_count` value or return
`line_sender_error_invalid_api_call`.

```c
QUESTDB_CLIENT_API
bool column_sender_chunk_column_i8(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int8_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_column_i16(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int16_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_column_i32(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int32_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_column_i64(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int64_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_column_f32(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const float* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_column_f64(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const double* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * Boolean column. `data` is an Arrow-style packed bitmap (LSB-first,
 * 1=true). Length is row_count bits, so `data` must be at least
 * ceil(row_count/8) bytes long.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_bool(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint8_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * UUID column. `data` points to row_count * 16 bytes. Each 16-byte
 * group is one UUID; bytes 0..8 are the lo half (little-endian),
 * bytes 8..16 are the hi half (little-endian). Matches the
 * existing line_sender_buffer_column_uuid layout.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_uuid(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint8_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * LONG256 column. `data` points to row_count * 32 bytes. Each
 * 32-byte group is one LONG256: four 64-bit limbs little-endian,
 * least-significant limb first.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_long256(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint8_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * IPv4 column. `data` is a packed uint32 per row, encoded as
 * u32::from(Ipv4Addr).to_le_bytes() (octet 0 in the high byte).
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_ipv4(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint32_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);
```

---

## 7. Timestamp columns

```c
/**
 * TIMESTAMP column, nanoseconds since the Unix epoch.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_ts_nanos(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int64_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * TIMESTAMP column, microseconds since the Unix epoch. Equivalent to
 * passing nanoseconds = micros * 1000 through ts_nanos, but the FFI
 * does the scale-up so the caller does not have to materialise a
 * second buffer.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_ts_micros(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int64_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * DATE column, milliseconds since the Unix epoch.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_date_millis(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int64_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);
```

---

## 8. Variable-width text column (VARCHAR)

QWP has exactly one variable-width text type: VARCHAR (wire code
`0x0F`). The wire format is `uint32` offsets + concatenated bytes. The
older STRING wire type (`0x08`) has been removed from the spec and is
not exposed here.

Input is in Arrow Utf8 shape: a full-length offsets array of
`row_count + 1` entries where `offsets[i]..offsets[i+1]` slices `bytes`
for row `i`. Null rows are signalled via the validity bitmap; their
offset slice is ignored (typically a zero-length slice, but the FFI
makes no assumption).

```c
/**
 * VARCHAR column (QWP wire type 0x0F).
 *
 * Input layout matches Arrow Utf8:
 *   - offsets has row_count + 1 entries. Monotonically non-decreasing.
 *     The first entry is typically 0 and the last is typically
 *     bytes_len; the FFI does not require those exactly, but every
 *     offset must be ≤ bytes_len.
 *   - bytes is a single contiguous UTF-8 buffer.
 *   - validity is Arrow-shape (1 = valid, see §2.4). NULL rows'
 *     offset slices are ignored.
 *
 * Wire output: the library compresses to QWP's dense layout
 * (only non-null values, uint32 offsets matching the wire spec).
 *
 * UTF-8 validity is the caller's responsibility; invalid UTF-8 is
 * detected by the server and surfaced as line_sender_error_server_rejection.
 *
 * Input offsets are int32_t because that is the Arrow Utf8 layout
 * (signed 32-bit). Negative values are rejected. Polars LargeUtf8
 * (int64 offsets, >2 GiB) is the Python wrapper's concern: split the
 * column or copy down to int32 offsets before calling.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_varchar(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int32_t* offsets,    // length = row_count + 1
    const uint8_t* bytes,
    size_t bytes_len,
    size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);
```

---

## 9. Symbol columns (dictionary fast path)

Symbol columns take dictionary-encoded input: a `codes` array of
per-row indices and a dict (`dict_offsets` + `dict_bytes` in Arrow
Utf8 layout).

This is **the canonical symbol input** because it matches:
- Pandas `Categorical` (`.codes` + `.categories`),
- Polars `Categorical` / Arrow `Dictionary<int32, Utf8>`.

The implementation interns the dict against the connection-scoped
symbol table once (cost ∝ dict cardinality, not row count) and then
remaps codes in bulk.

For each `symbol_dict_<IDX>` variant, `codes[i]` is the index into the
dict for row `i`. Codes must be in range `0..dict_len` for valid rows;
behaviour is undefined for out-of-range codes when validity is NULL.
When a row's validity bit is 0, its code is ignored.

`dict_offsets` has `dict_len + 1` entries; `dict_offsets[d]..dict_offsets[d+1]`
slices `dict_bytes` for dict entry `d`. `dict_len` is implicit:
`dict_len == (dict_offsets length) - 1`. The FFI takes
`dict_offsets_len` explicitly to compute `dict_len = dict_offsets_len - 1`.

```c
QUESTDB_CLIENT_API
bool column_sender_chunk_symbol_dict_i8(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int8_t* codes, size_t row_count,
    const int32_t* dict_offsets, size_t dict_offsets_len,
    const uint8_t* dict_bytes,   size_t dict_bytes_len,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_symbol_dict_i16(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int16_t* codes, size_t row_count,
    const int32_t* dict_offsets, size_t dict_offsets_len,
    const uint8_t* dict_bytes,   size_t dict_bytes_len,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_symbol_dict_i32(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int32_t* codes, size_t row_count,
    const int32_t* dict_offsets, size_t dict_offsets_len,
    const uint8_t* dict_bytes,   size_t dict_bytes_len,
    const column_sender_validity* validity,
    line_sender_error** err_out);
```

---

## 10. Designated timestamp

Required exactly once per chunk before `submit`. Two variants picking
the on-wire type:

- `..._micros` encodes the column on the wire as TIMESTAMP (`0x0A`,
  microseconds since Unix epoch).
- `..._nanos`  encodes the column on the wire as TIMESTAMP_NANOS
  (`0x10`, nanoseconds since Unix epoch).

Exactly one of the two may be called per chunk. The designated
timestamp is emitted on the wire as a schema column with an empty
name (per spec §Full schema mode).

```c
/**
 * Designated-timestamp column, microseconds since the Unix epoch.
 * Encoded on the wire as TIMESTAMP (0x0A).
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_designated_timestamp_micros(
    column_sender_chunk* chunk,
    const int64_t* data,
    size_t row_count,
    line_sender_error** err_out);

/**
 * Designated-timestamp column, nanoseconds since the Unix epoch.
 * Encoded on the wire as TIMESTAMP_NANOS (0x10).
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_designated_timestamp_nanos(
    column_sender_chunk* chunk,
    const int64_t* data,
    size_t row_count,
    line_sender_error** err_out);
```

(No `validity` parameter — the designated timestamp must be non-null
per row.)

---

## 11. Flush (synchronous)

```c
/**
 * Acknowledgement level the flush waits for.
 */
typedef enum column_sender_ack_level
{
    /** Wait for the server's WAL-commit ACK (spec status 0x00).
        Always available. */
    column_sender_ack_level_ok = 0,

    /** Wait for the server's object-store durability ACK
        (spec status 0x02). Enterprise only. Requires the pool to be
        opened with `request_durable_ack=on` in the connect string
        (and the server's 101 response confirming
        `X-QWP-Durable-Ack: enabled`). If the connection did not opt
        in, flush returns line_sender_error_invalid_api_call. */
    column_sender_ack_level_durable = 1,
} column_sender_ack_level;

/**
 * Encode the chunk into a QWP/WebSocket frame, publish it, and block
 * until the server acknowledges at the requested `ack_level`. Returns
 * true once the ACK is received; the chunk is then cleared (row count
 * → 0, allocations retained) and can be reused for the next DataFrame.
 *
 * Synchronous semantics: at most one frame in flight per sender. For
 * parallel ingest, borrow multiple senders from the pool — one per
 * thread — and flush concurrently. The 128-in-flight wire cap is
 * never reached.
 *
 * Ack level semantics:
 *  - `ok` — returns when the server has written the batch to its WAL.
 *  - `durable` — returns when the WAL segment is durably uploaded to
 *    the configured object store. Strictly later than the OK
 *    watermark; can be significantly later under upload pressure.
 *
 * On any failure (server rejection, transport error, latched-error
 * sender, or `durable` requested without opt-in), returns false and
 * sets *err_out. The chunk is left untouched so the caller can
 * inspect or recover its contents before freeing.
 *
 * Flush blocks until ack or until the underlying connection enters a
 * terminal failure state (must_close() becomes true). Transient
 * disconnects are absorbed by the existing reconnect machinery. No
 * separate per-call timeout in v1; if you need one, file a request.
 *
 * The QWP wire `sequence` (FSN) is tracked internally and is not
 * exposed at the FFI — synchronous flush makes it unnecessary.
 */
QUESTDB_CLIENT_API
bool column_sender_flush(
    column_sender* sender,
    column_sender_chunk* chunk,
    column_sender_ack_level ack_level,
    line_sender_error** err_out);
```

---

## 12. Versioning

This API is **draft / unstable** until first ship. Once shipped:

- The C ABI is versioned alongside the rest of `c-questdb-client`.
- Breaking changes follow the same SemVer policy as the existing
  `line_sender_*` ABI.
- The wire format is the existing QWP v1 spec (no new wire types
  introduced).

---

## 13. Minimal C example

Pool/borrow shape: one `questdb_db` per process, borrow a sender per
unit of work, return it when done.

```c
#include "questdb/ingress/line_sender.h"
#include "questdb/ingress/column_sender.h"

int send_one_chunk(questdb_db* db) {
    line_sender_error* err = NULL;
    column_sender* sender = NULL;
    column_sender_chunk* chunk = NULL;

    sender = questdb_db_borrow_sender(db, &err);
    if (!sender) goto fail;

    chunk = column_sender_chunk_new("trades", 6, &err);
    if (!chunk) goto fail;

    const double prices[]   = { 2615.54, 2615.60, 2615.50 };
    const double amounts[]  = { 0.00044, 0.00021, 0.00073 };
    const int64_t timestamps_ns[] = { 1700000000000000000LL,
                                       1700000000000001000LL,
                                       1700000000000002000LL };

    if (!column_sender_chunk_column_f64(
            chunk, "price", 5, prices, 3, NULL, &err)) goto fail;
    if (!column_sender_chunk_column_f64(
            chunk, "amount", 6, amounts, 3, NULL, &err)) goto fail;
    if (!column_sender_chunk_designated_timestamp_nanos(
            chunk, timestamps_ns, 3, &err)) goto fail;

    if (!column_sender_flush(
            sender, chunk, column_sender_ack_level_ok, &err)) goto fail;
    /* flush returned: server has WAL-committed; chunk cleared & reusable */

    column_sender_chunk_free(chunk);
    questdb_db_return_sender(db, sender);
    return 0;

fail:
    if (err) {
        fprintf(stderr, "%s\n", line_sender_error_msg(err, NULL));
        line_sender_error_free(err);
    }
    column_sender_chunk_free(chunk);
    if (sender) questdb_db_return_sender(db, sender);
    return 1;
}

int main(void) {
    line_sender_error* err = NULL;
    questdb_db* db = questdb_db_connect(
        "qwpws::addr=localhost:9000;pool_size=1;", &err);
    if (!db) {
        if (err) line_sender_error_free(err);
        return 1;
    }
    int rc = send_one_chunk(db);
    questdb_db_close(db);
    return rc;
}
```

---

## 14. Notes for the Python wrapper

These are not part of the C ABI; they are guidance for the Python repo
agent.

- **Pandas numeric columns** → `Series.to_numpy(copy=False)` gives a
  contiguous `np.ndarray` whose `.ctypes.data` pointer goes straight
  to FFI. No copy.
- **Pandas nulls** → `Series.isna().values` is a `np.ndarray[bool]`;
  pack it LSB-first into a `uint8_t*` bitmap (provide a vectorised
  helper using `numpy.packbits(... bitorder='little')`).
- **Pandas datetime64** → already an int64 view via
  `series.view('int64')`. For `[ns]` use `column_ts_nanos`; for
  `[us]` use `column_ts_micros`; for `[ms]` use `column_date_millis`
  (or scale up to ns).
- **Pandas `Categorical`** → `cat.codes.to_numpy()` for `codes`;
  `cat.categories.to_numpy()` then encode to Arrow Utf8 layout
  (build `offsets` + `bytes`) for the dict. Or roundtrip via PyArrow
  for less manual work.
- **Polars** → `series.to_arrow()` yields a `pyarrow.Array` whose
  buffers (`array.buffers()`) include the validity bitmap (already
  LSB-first 1=valid) and the data buffer. Direct pointer handoff.
- **Pandas object-dtype strings** are the slow path: materialise into
  Arrow Utf8 via `pyarrow.array(series)` then forward. The FFI
  does not have a fast path for object dtype — that's a deliberate
  choice. Document this.
- **Object lifetimes** — keep the source `np.ndarray` / `pa.Array`
  alive for the duration of the FFI call. Buffers are copied into the
  chunk during the call, so they can be dropped after the call
  returns.
