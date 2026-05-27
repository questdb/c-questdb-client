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
 * `ArrowArray` + `ArrowSchema` pair and routes to the appropriate
 * per-type writer. Avoids the per-column dispatch every Python /
 * Polars caller would otherwise have to write.
 *
 * Supported schema formats (see Apache Arrow C Data Interface spec):
 *   - "c", "s", "i", "l"       int8 / int16 / int32 / int64
 *   - "f", "g"                  float32 / float64
 *   - "b"                       bool (LSB-first bitmap)
 *   - "u"                       UTF-8 string (int32 offsets)
 *   - "U"                       LargeUtf8 string (int64 offsets;
 *                               narrowed to u32 at encode time, no
 *                               caller-side cast needed)
 *   - "tsn:..."                 timestamp nanos (timezone ignored)
 *   - "tsu:..."                 timestamp micros (timezone ignored)
 *   - dictionary-typed schema with the index format above and a
 *     UTF-8 "u" value type → routes to symbol_dict_i*.
 *
 * Constraints:
 *  - `array->offset` must be 0. Consolidate sliced arrays caller-side
 *    before passing them in.
 *  - The chunk's row-count lock applies as with any other appender:
 *    the first column to append sets the count; subsequent appends
 *    must agree.
 *  - LargeUtf8 column total bytes must fit in `uint32_t` (the QWP wire
 *    offset table). Larger columns fail with
 *    `line_sender_error_invalid_api_call` at chunk-build time.
 *
 * Other formats — decimal, struct, list, and non-UTF-8 dictionary
 * values — currently return `line_sender_error_invalid_api_call`.
 * Coverage broadens in subsequent patches.
 * ------------------------------------------------------------------------- */

/** Forward declarations of Apache Arrow C Data Interface structs.
 *  We never construct or release them — the caller owns lifetime —
 *  and consume them via opaque pointers in the appender call below. */
struct ArrowArray;
struct ArrowSchema;

QUESTDB_CLIENT_API
bool column_sender_chunk_append_arrow_column(
    column_sender_chunk* chunk,
    const char* name,
    size_t name_len,
    const struct ArrowArray* array,
    const struct ArrowSchema* schema,
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

#ifdef __cplusplus
} /* extern "C" */
#endif
