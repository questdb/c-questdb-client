/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/

/*
 * Column-major sender for QuestDB QWP/WebSocket.
 *
 * Mirrors doc/COLUMN_SENDER_FFI_ABI.md. Reuses `line_sender_error*` from
 * `line_sender.h` for fallible-call error reporting; all opaque handles
 * are heap-allocated and freed through their dedicated entry points.
 *
 * Conventions:
 *  - Opaque handles must be non-NULL unless the function documentation
 *    states otherwise.
 *  - `err_out` is optional on every fallible call: pass NULL to discard
 *    error information.
 *  - `column_sender_chunk` is owned by the caller and not bound to a
 *    particular sender; chunks can be built on any thread and flushed
 *    through any sender borrowed from the same `questdb_db`.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "line_sender.h"

/* -------------------------------------------------------------------------
 * Opaque handles
 * ------------------------------------------------------------------------- */

/** Connection pool. Thread-safe; share across threads. */
typedef struct questdb_db questdb_db;

/** Borrowed QWP/WS connection. Not thread-safe; belongs to the borrowing
 *  thread until returned via `questdb_db_return_conn`. Carries the
 *  per-connection schema registry and symbol-dictionary state used by all
 *  writer modes (per-type, Arrow, NumPy) and — in the future — by egress
 *  readers. */
typedef struct qwpws_conn qwpws_conn;

/** One DataFrame's worth of column buffers destined for one QuestDB table.
 *  Owned by the caller. */
typedef struct column_sender_chunk column_sender_chunk;

/* -------------------------------------------------------------------------
 * Validity bitmap
 *
 * Arrow shape: bit = 1 means VALID, bit = 0 means NULL. LSB-first within
 * each byte. `bit_len` must equal the chunk's row count; `bits` must
 * point to at least `ceil(bit_len / 8)` bytes. Pass `bits=NULL,
 * bit_len=0` to signal "no nulls" (or pass a `NULL` pointer to the
 * column function's `validity` parameter).
 * ------------------------------------------------------------------------- */

typedef struct column_sender_validity
{
    const uint8_t* bits;
    size_t bit_len;
} column_sender_validity;

/* -------------------------------------------------------------------------
 * Acknowledgement level for `column_sender_sync`.
 * ------------------------------------------------------------------------- */

typedef enum column_sender_ack_level
{
    /** Wait for the server's WAL-commit ACK (spec status 0x00). Always
     *  available. */
    column_sender_ack_level_ok = 0,

    /** Wait for the server's object-store durability ACK (spec status
     *  0x02). Enterprise only; requires the pool to be opened with
     *  `request_durable_ack=on` in the connect string. Sync returns
     *  `line_sender_error_invalid_api_call` otherwise. */
    column_sender_ack_level_durable = 1
} column_sender_ack_level;

/* -------------------------------------------------------------------------
 * Pool and sender borrow
 * ------------------------------------------------------------------------- */

/**
 * Open a connection pool. Eagerly opens `pool_size` connections (default
 * 1); any auth / TLS / connect error during those opens fails the call.
 *
 * `conf` is a `qwpws::` / `qwpwss::` connect string. Pool-specific keys:
 *   `pool_size`            (default 1)   warm/min connections;
 *   `pool_max`             (default 64)  hard cap on auto-grow;
 *   `pool_idle_timeout_ms` (default 60000)
 *                                       reap above-pool_size idle conns;
 *   `pool_reap`            (`auto`|`manual`, default `auto`)
 *                                       background reaper opt-in.
 *
 * Store-and-forward keys (`sf_*`, `sender_id`) are refused — use the
 * row-major `line_sender_*` API for on-disk durability.
 */
QUESTDB_CLIENT_API
questdb_db* questdb_db_connect(
    const char* conf,
    size_t conf_len,
    line_sender_error** err_out);

/**
 * Close the pool and all its connections. Accepts NULL and no-ops.
 * Outstanding `qwpws_conn` handles remain valid and return their
 * connections on `questdb_db_return_conn` — the pool's state is
 * reference-counted internally.
 */
QUESTDB_CLIENT_API
void questdb_db_close(questdb_db* db);

/**
 * Borrow a QWP/WS connection. Selection rules:
 *  1. If a previously-returned conn is in the free list, hand it out.
 *  2. Otherwise, if pool size < `pool_max`, open a new connection.
 *  3. Otherwise (at cap), return NULL + `line_sender_error_invalid_api_call`.
 *
 * The returned conn is bound to the calling thread until returned.
 */
QUESTDB_CLIENT_API
qwpws_conn* questdb_db_borrow_conn(
    questdb_db* db,
    line_sender_error** err_out);

/**
 * Return a conn to the pool. Accepts NULL `conn` and no-ops.
 * Invalidates the `conn` pointer; do not use it after this call.
 *
 * `db` is currently ignored — the conn carries its own reference to
 * the pool — but accepted for symmetry with the borrow call.
 */
QUESTDB_CLIENT_API
void questdb_db_return_conn(
    questdb_db* db,
    qwpws_conn* conn);

/**
 * Force-drop a borrowed conn instead of recycling it. Marks the conn
 * terminal (qwpws_conn_must_close becomes true) before the usual
 * pool-return path runs, so the underlying connection is closed and
 * dropped. Invalidates `conn`. Accepts NULL `conn` and no-ops.
 *
 * Use this in error-recovery paths where the conn may hold in-flight
 * uncommitted frames that the next borrower would otherwise commit
 * alongside their own (the round-3 dirty-sender concern).
 */
QUESTDB_CLIENT_API
void questdb_db_drop_conn(
    questdb_db* db,
    qwpws_conn* conn);

/* Reader-pool entry points (`questdb_db_borrow_reader`,
 * `questdb_db_return_reader`, `questdb_db_reader_*_count`) live in
 * `questdb/egress/line_reader.h` alongside the `line_reader` type
 * they wrap. */

/**
 * Manually reap idle connections (closes free-list entries idle longer
 * than `pool_idle_timeout_ms`, never shrinking below `pool_size`).
 * Returns the number of connections closed.
 */
QUESTDB_CLIENT_API
size_t questdb_db_reap_idle(questdb_db* db);

/* -------------------------------------------------------------------------
 * Connection state inspection
 * ------------------------------------------------------------------------- */

/**
 * `true` if the connection is in a permanently-unusable state (latched
 * by any writer that hits a transport or protocol error). On return to
 * the pool such conns are dropped, not recycled.
 */
QUESTDB_CLIENT_API
bool qwpws_conn_must_close(const qwpws_conn* conn);

/* -------------------------------------------------------------------------
 * Chunk lifecycle
 * ------------------------------------------------------------------------- */

/**
 * Create an empty chunk for the given table. The chunk is caller-owned
 * and must be freed with `column_sender_chunk_free` or flushed via
 * `column_sender_flush` (which clears but does not free it).
 */
QUESTDB_CLIENT_API
column_sender_chunk* column_sender_chunk_new(
    const char* table_name,
    size_t table_name_len,
    line_sender_error** err_out);

/** Discard the chunk and release its allocations. Accepts NULL. */
QUESTDB_CLIENT_API
void column_sender_chunk_free(column_sender_chunk* chunk);

/** Clear the chunk's content, keeping retained capacity for reuse. */
QUESTDB_CLIENT_API
void column_sender_chunk_clear(column_sender_chunk* chunk);

/** Current row count of the chunk; 0 if no column has been appended. */
QUESTDB_CLIENT_API
size_t column_sender_chunk_row_count(const column_sender_chunk* chunk);

/* -------------------------------------------------------------------------
 * Numeric / fixed-width column appends
 *
 * Every column-append function locks the chunk's row count on the first
 * call. Subsequent columns must agree on row count. `data` is a
 * contiguous, full-length typed array with one slot per row (including
 * null rows — their slot value is ignored). `validity` is optional;
 * pass NULL when the column has no nulls.
 * ------------------------------------------------------------------------- */

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
 * `BOOLEAN` column. `data` is an Arrow-style LSB-first packed bitmap
 * (1 = true). `data` must point to at least `ceil(row_count / 8)` bytes.
 *
 * Lower-level building block for callers (typically a Python wrapper's
 * PyObject sniff path) that already hold a packed bitmap with no Arrow
 * schema. Arrow-backed bool columns should go through
 * `column_sender_chunk_append_arrow_column`.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_bool(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint8_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * `UUID` column. `data` points to `row_count * 16` bytes; each 16-byte
 * group is one UUID (bytes 0..8 lo half LE, 8..16 hi half LE).
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_uuid(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint8_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * `LONG256` column. `data` points to `row_count * 32` bytes — four
 * little-endian 64-bit limbs per row, least-significant limb first.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_long256(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint8_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * `IPV4` column. Each `data[i]` is `u32::from(Ipv4Addr)` (octet 0 in
 * the high byte), encoded little-endian on the wire.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_ipv4(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const uint32_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Timestamp columns (non-designated)
 * ------------------------------------------------------------------------- */

/** `TIMESTAMP_NANOS` column, nanoseconds since the Unix epoch. */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_ts_nanos(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int64_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/** `TIMESTAMP` column, microseconds since the Unix epoch. */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_ts_micros(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int64_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/** `DATE` column, milliseconds since the Unix epoch. */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_date_millis(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int64_t* data, size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Variable-width text (VARCHAR)
 *
 * For callers that already hold an Arrow C Data Interface array, prefer
 * `column_sender_chunk_append_arrow_column` below — it dispatches by
 * schema format and handles both UTF-8 (`u`) and LargeUtf8 (`U`) in one
 * call. The per-type entry point here is the lower-level building block,
 * useful when the caller has raw int32 offsets + bytes and no Arrow
 * schema.
 * ------------------------------------------------------------------------- */

/**
 * `VARCHAR` column (QWP wire type 0x0F).
 *
 * Input layout matches Arrow Utf8:
 *  - `offsets` has `row_count + 1` entries, monotonically non-decreasing.
 *  - `bytes` is a single contiguous UTF-8 buffer; offsets are absolute
 *    byte offsets into it (the column encoder rebases to 0 on the wire
 *    when the first offset is non-zero).
 *  - `validity` is Arrow-shape; NULL-row offset slices are not
 *    inspected.
 *
 * Wire output: dense (only non-null values), `non_null_count + 1`
 * little-endian uint32 offsets followed by the concatenated bytes.
 *
 * UTF-8 validity is the caller's responsibility; invalid UTF-8 is
 * detected by the server and surfaced as
 * `line_sender_error_server_rejection`.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_varchar(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int32_t* offsets,
    const uint8_t* bytes,
    size_t bytes_len,
    size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/**
 * `BINARY` column. Same Arrow-Binary-shape `offsets` + `bytes` layout as
 * `column_sender_chunk_column_varchar`; differs only in the wire type
 * byte so the server creates a BINARY column. No UTF-8 validation.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_column_binary(
    column_sender_chunk* chunk,
    const char* name,
    size_t name_len,
    const int32_t* offsets,
    const uint8_t* bytes,
    size_t bytes_len,
    size_t row_count,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Symbol columns (dictionary fast path)
 *
 * `codes` is per-row dictionary indices. `dict_offsets` (length
 * `dict_offsets_len`) and `dict_bytes` (length `dict_bytes_len`)
 * describe the dictionary in Arrow Utf8 layout. The library interns
 * only referenced dict entries against the connection-scoped global
 * symbol table — `dict_offsets_len - 1` may be huge (Pandas
 * `Categorical`) without paying the cost for unused entries.
 *
 * `codes[i]` must be in `0 .. dict_len` for non-null rows; null-row
 * codes are not inspected.
 *
 * Callers passing an Arrow Dictionary array should prefer
 * `column_sender_chunk_append_arrow_column`, which dispatches on the
 * outer schema's index width (`c`/`s`/`i`) automatically. The per-type
 * entries here remain the lower-level building block.
 * ------------------------------------------------------------------------- */

QUESTDB_CLIENT_API
bool column_sender_chunk_symbol_dict_i8(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int8_t* codes, size_t row_count,
    const int32_t* dict_offsets, size_t dict_offsets_len,
    const uint8_t* dict_bytes, size_t dict_bytes_len,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_symbol_dict_i16(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int16_t* codes, size_t row_count,
    const int32_t* dict_offsets, size_t dict_offsets_len,
    const uint8_t* dict_bytes, size_t dict_bytes_len,
    const column_sender_validity* validity,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_chunk_symbol_dict_i32(
    column_sender_chunk* chunk,
    const char* name, size_t name_len,
    const int32_t* codes, size_t row_count,
    const int32_t* dict_offsets, size_t dict_offsets_len,
    const uint8_t* dict_bytes, size_t dict_bytes_len,
    const column_sender_validity* validity,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Generic Arrow column appender
 *
 * Single entry point that consumes an Apache Arrow C Data Interface
 * `ArrowArray` + `ArrowSchema` pair and routes to the same encoding
 * infrastructure as `column_sender_flush_arrow_batch`. Supports the
 * full Arrow type matrix (43 classifications including all primitives,
 * timestamps, dates, decimals, UUID, LONG256, geohash, dictionary-
 * encoded symbols across all key/value variants, and varlen
 * UTF8/Binary in three encodings).
 *
 * `row_offset` and `row_count` describe which slice of the array to
 * append. Use `row_offset=0, row_count=array->length` for the whole
 * array.
 *
 * Ownership:
 *  - On success, `array->release` is consumed (set to NULL); the chunk
 *    holds the array's buffer lifetime via an internal Arc until
 *    `column_sender_flush` returns. The caller may free the
 *    `ArrowArray` struct shell immediately after this call returns.
 *  - On failure, `array->release` may have been consumed (set to NULL)
 *    if the function reached the Arrow import step before failing. The
 *    underlying buffers are always released by the function in that
 *    case. Callers MUST check `array->release != NULL` before invoking
 *    it on the failure path. Early-fail paths (NULL pointer check,
 *    schema/array depth-cap rejection) leave `array->release` intact.
 *  - `schema` is borrowed; the caller retains `schema->release` in
 *    all cases.
 *
 * Constraints:
 *  - `array->offset` is honored as the Arrow C Data Interface logical
 *    offset; `row_offset` / `row_count` further sub-slice within this
 *    call.
 *  - The chunk's row-count lock applies as with any other appender:
 *    the first column to append sets the count; subsequent appends
 *    must agree.
 *
 * Type rejections (any Arrow type with no QuestDB mapping — `Null`,
 * `Struct`, `Map`, `RunEndEncoded`, `Interval(*)`, `FixedSizeBinary`
 * outside UUID/LONG256, non-Float64 `List` leaves) return
 * `line_sender_error_arrow_unsupported_column_kind`. Structural
 * failures (validity-count mismatch, ms→µs overflow, decimal scale
 * out of range, etc.) return `line_sender_error_arrow_ingest`.
 * ------------------------------------------------------------------------- */

/* Apache Arrow C Data Interface boilerplate. Guarded by
 * `ARROW_C_DATA_INTERFACE` so it composes safely with arrow.h,
 * nanoarrow, polars-arrow, and any other header that ships the same
 * canonical block. The caller owns lifetimes of `ArrowArray` /
 * `ArrowSchema`; we consume `array->release` on success in the
 * column_sender entry points below, and leave it intact on failure.
 * https://arrow.apache.org/docs/format/CDataInterface.html */
#ifndef ARROW_C_DATA_INTERFACE
#    define ARROW_C_DATA_INTERFACE

#    define ARROW_FLAG_DICTIONARY_ORDERED 1
#    define ARROW_FLAG_NULLABLE 2
#    define ARROW_FLAG_MAP_KEYS_SORTED 4

struct ArrowSchema
{
    const char* format;
    const char* name;
    const char* metadata;
    int64_t flags;
    int64_t n_children;
    struct ArrowSchema** children;
    struct ArrowSchema* dictionary;
    void (*release)(struct ArrowSchema*);
    void* private_data;
};

struct ArrowArray
{
    int64_t length;
    int64_t null_count;
    int64_t offset;
    int64_t n_buffers;
    int64_t n_children;
    const void** buffers;
    struct ArrowArray** children;
    struct ArrowArray* dictionary;
    void (*release)(struct ArrowArray*);
    void* private_data;
};

#endif /* ARROW_C_DATA_INTERFACE */

QUESTDB_CLIENT_API
bool column_sender_chunk_append_arrow_column(
    column_sender_chunk* chunk,
    const char* name,
    size_t name_len,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    size_t row_offset,
    size_t row_count,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Generic NumPy column appender
 *
 * Companion to `column_sender_chunk_append_arrow_column` for callers
 * holding a raw, contiguous, native-endian NumPy buffer. The buffer is
 * walked at flush time, single pass, straight into the connection's
 * outbound frame — no chunk-side scratch arena, no per-column heap copy.
 *
 * Caller contract: `data` (and `validity->bits`, if any) MUST stay alive
 * until the next `column_sender_flush` / `column_sender_sync` returns.
 *
 * Coverage matrix (dtype → wire kind):
 *   Direct (zero-copy at flush):
 *     i64          → LONG
 *     f64          → DOUBLE
 *     datetime64[ms] → DATE
 *     datetime64[us] → TIMESTAMP
 *     datetime64[ns] → TIMESTAMP_NANOS
 *     timedelta64[s/ms/us/ns] → LONG
 *     S16          → UUID            (16 bytes per row)
 *     S32          → LONG256         (32 bytes per row)
 *     u32_ipv4     → IPV4
 *     u16_char     → CHAR
 *   Widen (single pass at flush):
 *     u8/u16       → INT   (zero-extend)
 *     u32/u64      → LONG  (zero-extend / bit-reinterpret;
 *                           u64 values > i64::MAX wrap negative)
 *     f32          → DOUBLE
 *     f16          → FLOAT
 *     datetime64[s] → TIMESTAMP (×10^6)
 *   Packing:
 *     bool         → BOOLEAN (NumPy byte-per-row → LSB-first bitmap)
 *   Decimals (require `extras.decimal_scale`):
 *     decimal_s8   → DECIMAL64  (i64 mantissa, scale ∈ 0..=18)
 *     decimal_s16  → DECIMAL128 (i128 mantissa, scale ∈ 0..=38)
 *     decimal_s32  → DECIMAL256 (i256 mantissa, scale ∈ 0..=76)
 *   Geohash (require `extras.geohash_bits`):
 *     geohash_i8   → GEOHASH (bits ∈ 1..=8)
 *     geohash_i16  → GEOHASH (bits ∈ 1..=16)
 *     geohash_i32  → GEOHASH (bits ∈ 1..=32)
 *     geohash_i64  → GEOHASH (bits ∈ 1..=60)
 *   Multi-dim float64 (require `extras.array_ndim` + `extras.array_shape`):
 *     f64_ndarray  → DOUBLE_ARRAY (rectangular tensor; all rows share the
 *                    same per-row shape — ragged inputs must go through
 *                    Arrow `List<Float64>` via the Arrow appender)
 *
 * Constraints:
 *   - Strided and non-native-endian buffers are not supported; consolidate
 *     upstream.
 *   - `validity` follows the Arrow LSB-first convention (bit = 1 → valid).
 *   - The chunk's row-count lock applies as elsewhere.
 *   - VARCHAR / SYMBOL / BINARY wire kinds are not reachable from NumPy —
 *     use `column_sender_chunk_append_arrow_column` instead.
 * ------------------------------------------------------------------------- */

typedef enum column_sender_numpy_dtype
{
    /* Signed integers — emit at source width (identity, 1 memcpy/no-null).
       NOTE: BYTE / SHORT use value 0 as the wire null sentinel, so source
       values of 0 round-trip as NULL on the server side. Callers wanting
       0 to round-trip as 0 must widen to INT (i32) themselves. */
    column_sender_numpy_i8 = 0,  /* → BYTE  (1B/row, sentinel = 0)              */
    column_sender_numpy_i16 = 1, /* → SHORT (2B/row, sentinel = 0)              */
    column_sender_numpy_i32 = 2, /* → INT   (4B/row, sentinel = i32::MIN)       */
    column_sender_numpy_i64 = 3, /* → LONG  (8B/row, sentinel = i64::MIN)       */

    /* Unsigned integers — widen to the smallest signed wire that holds the
       source range WITHOUT colliding with the null sentinel. BYTE/SHORT
       use value 0 as null, so u8 cannot use either; INT (i32::MIN sentinel)
       is the minimum safe target for u8. */
    column_sender_numpy_u8 = 4,  /* → INT   (4B/row, widen u8→i32)              */
    column_sender_numpy_u16 = 5, /* → INT   (4B/row, widen u16→i32)             */
    column_sender_numpy_u32 = 6, /* → LONG  (8B/row, widen u32→i64)             */
    column_sender_numpy_u64 = 7, /* → LONG  (8B/row, bit-reinterpret u64→i64;
                                    values > i64::MAX wrap to negative)         */

    column_sender_numpy_f32 = 8, /* → DOUBLE (8B/row, widen f32→f64)            */
    column_sender_numpy_f64 = 9, /* → DOUBLE (8B/row, sentinel = NaN)           */
    column_sender_numpy_bool = 10, /* → BOOLEAN (bit-packed)                    */

    /* Half-precision + time */
    column_sender_numpy_f16 = 11,
    column_sender_numpy_datetime64_s = 12,
    column_sender_numpy_datetime64_ms = 13,
    column_sender_numpy_datetime64_us = 14,
    column_sender_numpy_datetime64_ns = 15,
    column_sender_numpy_timedelta64_s = 16,
    column_sender_numpy_timedelta64_ms = 17,
    column_sender_numpy_timedelta64_us = 18,
    column_sender_numpy_timedelta64_ns = 19,

    /* Fixed-size bytes */
    column_sender_numpy_s16 = 20, /* 16B/row → UUID */
    column_sender_numpy_s32 = 21, /* 32B/row → LONG256 */

    /* Decimals (read decimal_scale from column_sender_numpy_extras) */
    column_sender_numpy_decimal_s8 = 22,  /*  8B i64 mantissa  → DECIMAL64  */
    column_sender_numpy_decimal_s16 = 23, /* 16B i128 mantissa → DECIMAL128 */
    column_sender_numpy_decimal_s32 = 24, /* 32B i256 mantissa → DECIMAL256 */

    /* Metadata-disambiguated narrow ints */
    column_sender_numpy_u32_ipv4 = 25,
    column_sender_numpy_u16_char = 26,

    /* Geohash (read geohash_bits from column_sender_numpy_extras) */
    column_sender_numpy_geohash_i8 = 27,
    column_sender_numpy_geohash_i16 = 28,
    column_sender_numpy_geohash_i32 = 29,
    column_sender_numpy_geohash_i64 = 30,

    /* f64 ndarray: rectangular tensor (read array_ndim + array_shape from
       column_sender_numpy_extras). All rows share the same shape. */
    column_sender_numpy_f64_ndarray = 31,

    /* Coarser datetime64 units → TIMESTAMP (microseconds).
       Y / M are proleptic Gregorian, anchored at the start of the
       referenced year / month. D / h / m are constant multipliers. All
       reject overflow with InvalidApiCall. */
    column_sender_numpy_datetime64_m = 32, /* minute × 60_000_000          */
    column_sender_numpy_datetime64_h = 33, /* hour   × 3_600_000_000       */
    column_sender_numpy_datetime64_D = 34, /* day    × 86_400_000_000      */
    column_sender_numpy_datetime64_M = 35, /* month  → start of 1970-01+M  */
    column_sender_numpy_datetime64_Y = 36  /* year   → start of 1970+Y     */
} column_sender_numpy_dtype;

/* Companion struct for `column_sender_chunk_append_numpy_column` carrying
 * dtype-specific parameters. Pass NULL when the dtype needs none of these
 * (everything except `decimal_*`, `geohash_*`, and `f64_ndarray`).
 *
 *  - decimal_scale: digits to the right of the decimal point. Range
 *    0..=N where N is the dtype's cap (18 for s8 / DECIMAL64, 38 for s16
 *    / DECIMAL128, 76 for s32 / DECIMAL256). Signed type so an out-of-
 *    range negative value is rejected explicitly rather than wrapping.
 *  - geohash_bits: precision in bits. Range 1..=8 / 1..=16 / 1..=32 /
 *    1..=60 for i8 / i16 / i32 / i64 respectively.
 *  - array_ndim / array_shape: for `column_sender_numpy_f64_ndarray`
 *    only. `array_ndim` is the per-row tensor rank (1..=32, matching
 *    QuestDB's MAX_ARRAY_DIMS); `array_shape` points at `array_ndim`
 *    consecutive `uint32_t` dim sizes (each >= 1). The pointer is
 *    borrowed for the duration of the call only.
 *
 * Unused fields are ignored.
 */
typedef struct column_sender_numpy_extras
{
    int8_t decimal_scale;
    uint8_t geohash_bits;
    /* For column_sender_numpy_f64_ndarray only. */
    uint8_t array_ndim;          /* 1..=32 */
    const uint32_t* array_shape; /* array_ndim entries, each >= 1 */
} column_sender_numpy_extras;

QUESTDB_CLIENT_API
bool column_sender_chunk_append_numpy_column(
    column_sender_chunk* chunk,
    const char* name,
    size_t name_len,
    column_sender_numpy_dtype dtype,
    const uint8_t* data,
    size_t row_count,
    const column_sender_validity* validity,
    const column_sender_numpy_extras* extras,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Designated timestamp
 *
 * Required exactly once per chunk before flush. Always non-null per the
 * QWP wire spec — no `validity` parameter.
 * ------------------------------------------------------------------------- */

/** Designated timestamp in microseconds (wire type TIMESTAMP, 0x0A). */
QUESTDB_CLIENT_API
bool column_sender_chunk_designated_timestamp_micros(
    column_sender_chunk* chunk,
    const int64_t* data,
    size_t row_count,
    line_sender_error** err_out);

/** Designated timestamp in nanoseconds (wire type TIMESTAMP_NANOS, 0x10). */
QUESTDB_CLIENT_API
bool column_sender_chunk_designated_timestamp_nanos(
    column_sender_chunk* chunk,
    const int64_t* data,
    size_t row_count,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Flush / sync
 *
 * `column_sender_flush` encodes `chunk` into a QWP/WebSocket frame,
 * publishes it through `conn`, and returns without waiting for a server
 * ACK. On success, `chunk` is cleared (allocations retained) and `true`
 * is returned. On failure, `chunk` is left untouched.
 *
 * The first flush is sent as an immediate commit. Later flushes are sent
 * with QWP's deferred-commit flag so callers can pipeline many chunks.
 * Call `column_sender_sync` after the final flush to send the commit frame
 * and wait until all in-flight frames are acknowledged at `ack_level`.
 *
 * The connection keeps one protocol in-flight slot reserved for the sync
 * commit frame. If that reserve would be exhausted, flush returns
 * `line_sender_error_invalid_api_call`; call `column_sender_sync` before
 * flushing more chunks.
 * ------------------------------------------------------------------------- */

QUESTDB_CLIENT_API
bool column_sender_flush(
    qwpws_conn* conn,
    column_sender_chunk* chunk,
    line_sender_error** err_out);

QUESTDB_CLIENT_API
bool column_sender_sync(
    qwpws_conn* conn,
    column_sender_ack_level ack_level,
    line_sender_error** err_out);

#ifdef QUESTDB_CLIENT_ENABLE_ARROW

/**
 * Encode an Arrow C Data Interface `RecordBatch` (struct-typed
 * `ArrowArray`) and publish it as one QWP frame.
 *
 * Ownership: same contract as `column_sender_chunk_append_arrow_column`
 * — on success `array->release` is consumed (set to NULL); on failure
 * it may also have been consumed. Callers MUST check
 * `array->release != NULL` before invoking it on the failure path.
 * `schema` is borrowed in all cases.
 */
QUESTDB_CLIENT_API
bool column_sender_flush_arrow_batch(
    qwpws_conn* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    struct ArrowSchema* schema,
    line_sender_error** err_out);

/**
 * Same as `column_sender_flush_arrow_batch` but picks the designated
 * timestamp from a named column of the batch instead of from
 * `column_sender_chunk_designated_timestamp_*`. Same ownership
 * contract.
 */
QUESTDB_CLIENT_API
bool column_sender_flush_arrow_batch_at_column(
    qwpws_conn* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    struct ArrowSchema* schema,
    line_sender_column_name ts_column,
    line_sender_error** err_out);
#endif /* QUESTDB_CLIENT_ENABLE_ARROW */

#ifdef __cplusplus
} /* extern "C" */
#endif
