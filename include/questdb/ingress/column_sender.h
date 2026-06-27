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
 *    error information. If `err_out != NULL`, `*err_out` MUST be NULL on
 *    entry — fallible calls unconditionally store a freshly-allocated
 *    `line_sender_error*` into `*err_out` on failure, so reusing the slot
 *    across calls without first calling `line_sender_error_free` on the
 *    previous value silently leaks the prior error box.
 *  - `column_sender_chunk` is owned by the caller and not bound to a
 *    particular sender; chunks can be built on any thread and flushed
 *    through any sender borrowed from the same `questdb_db`. A single
 *    handle (chunk, conn) must not be used from more than one thread at
 *    a time: the caller must establish a happens-before ordering between
 *    calls on it. An *ordered* concurrent call is detected via a
 *    CAS-checked in-use latch and rejected with
 *    `line_sender_error_invalid_api_call`; a truly unordered call (or a
 *    free racing a call) is undefined behaviour.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <questdb/ingress/line_sender.h>

/* -------------------------------------------------------------------------
 * Opaque handles
 * ------------------------------------------------------------------------- */

/** Connection pool. Thread-safe for borrow/return/reap operations while the
 *  owning handle remains open. `questdb_db_close` is the final owner release:
 *  do not call it concurrently with other operations on the same `db`. */
typedef struct questdb_db questdb_db;

/** Borrowed store-and-forward QWP/WS connection. Not thread-safe; belongs to
 *  the borrowing thread until returned via `questdb_db_return_sf_column_sender`.
 *  Carries the per-connection symbol-dictionary state used by all writer modes
 *  (per-type, Arrow, NumPy). Freeing the handle concurrently with another
 *  call on it is undefined behaviour: callers must establish a
 *  happens-before ordering between the last use and the free (the internal
 *  latch only defers the drop for already-ordered interleavings).
 *
 *  Exposes publish-only `sf_column_sender_flush` plus the `sf_column_sender_wait`
 *  ack barrier; the store-and-forward queue owns delivery. */
typedef struct sf_column_sender sf_column_sender;

/** Borrowed direct (pipelined, non-store-and-forward) QWP/WS connection — the
 *  DataFrame-ingest sibling of `sf_column_sender`, returned via
 *  `questdb_db_return_direct_column_sender`. Same single-threaded / latch
 *  contract; exposes `direct_column_sender_flush` +
 *  `direct_column_sender_flush_and_wait` + `direct_column_sender_commit`. */
typedef struct direct_column_sender direct_column_sender;

/** Borrowed row-major QWP/WS sender. Not thread-safe; belongs to the
 *  borrowing thread until returned via `questdb_db_return_row_sender`.
 *  Builds rows through an ordinary `line_sender_buffer` and sends them with
 *  `row_sender_flush` / `row_sender_flush_and_keep`. Companion to the
 *  column-major senders (`sf_column_sender` / `direct_column_sender`) and
 *  `reader` (query). */
typedef struct row_sender row_sender;

/** One DataFrame's worth of column buffers destined for one QuestDB table.
 *  Owned by the caller. */
typedef struct column_sender_chunk column_sender_chunk;

/* -------------------------------------------------------------------------
 * Validity bitmap
 *
 * Arrow shape: bit = 1 means VALID, bit = 0 means NULL. LSB-first within
 * each byte. `bit_len` must equal the chunk's row count and is rejected
 * if it exceeds the per-chunk row cap; `bits` must point to at least
 * `ceil(bit_len / 8)` bytes. Pass `bits=NULL, bit_len=0` to signal "no
 * nulls" (or pass a `NULL` pointer to the column function's `validity`
 * parameter). A validity that marks every row valid is encoded exactly
 * like "no nulls" (no null bitmap is emitted on the wire).
 * ------------------------------------------------------------------------- */

typedef struct column_sender_validity
{
    const uint8_t* bits;
    size_t bit_len;
} column_sender_validity;

/* -------------------------------------------------------------------------
 * Acknowledgement level for `sf_column_sender_wait`.
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
 * Store-and-forward is opt-in: `sf_dir` selects the queue-backed column
 * sender, and `sender_id` / `sf_*` keys are accepted only with `sf_dir`.
 * In store-and-forward v1 the effective pool size is one active borrower:
 * explicit `pool_size > 1` or `pool_max > 1` is rejected, and an omitted
 * `pool_max` is treated as 1 for the column sender.
 */
QUESTDB_CLIENT_API
questdb_db* questdb_db_connect(
    const char* conf,
    size_t conf_len,
    line_sender_error** err_out);

/**
 * Close the pool. Accepts NULL and no-ops.
 *
 * Final owner release: callers must ensure no other thread is concurrently
 * using `db` for borrow/reap/config operations. This invalidates `db` for
 * new borrows and closes idle connections.
 * Outstanding `column_sender` handles are independent leases: returning or
 * dropping them after close is safe, but new operations on them fail with
 * `line_sender_error_invalid_api_call`. A handle returned after close is
 * closed, not recycled.
 */
QUESTDB_CLIENT_API
void questdb_db_close(questdb_db* db);

/**
 * Borrow a QWP/WS connection. Selection rules:
 *  1. If a previously-returned conn is in the free list, hand it out.
 *  2. Otherwise, if pool size < `pool_max`, open a new connection.
 *  3. Otherwise (at cap), return NULL + `line_sender_error_invalid_api_call`.
 *
 * In store-and-forward mode, v1 supports one active borrower. A second
 * concurrent borrow fails until the borrowed conn is returned. If the previous
 * SFA backend was force-dropped, the next borrow reopens the same slot.
 *
 * The returned conn is bound to the calling thread until returned.
 */
QUESTDB_CLIENT_API
sf_column_sender* questdb_db_borrow_sf_column_sender(
    questdb_db* db,
    line_sender_error** err_out);

/**
 * Borrow a direct (pipelined, non-store-and-forward) connection from the
 * always-direct pool, the DataFrame-ingest sibling of
 * `questdb_db_borrow_sf_column_sender`. Returns NULL on failure; sets
 * `*err_out` if provided.
 */
QUESTDB_CLIENT_API
direct_column_sender* questdb_db_borrow_direct_column_sender(
    questdb_db* db,
    line_sender_error** err_out);

/**
 * Like `questdb_db_borrow_sf_column_sender` but retries the connect within `budget_ms`
 * using the row sender's reconnect backoff (centered-jittered exponential with
 * a role-reject reset; authentication and protocol-version errors are
 * terminal). On a transient `line_sender_error_failover_retry`, drop the dead
 * conn with `questdb_db_drop_sf_column_sender` then call this to fail over with the same
 * budget and backoff as the row API. `budget_ms == 0` makes a single attempt.
 * Returns NULL on failure and sets `*err_out` if provided.
 */
QUESTDB_CLIENT_API
sf_column_sender* questdb_db_borrow_sf_column_sender_with_retry(
    questdb_db* db,
    uint64_t budget_ms,
    line_sender_error** err_out);

/** Direct-handle counterpart of `questdb_db_borrow_sf_column_sender_with_retry`. */
QUESTDB_CLIENT_API
direct_column_sender* questdb_db_borrow_direct_column_sender_with_retry(
    questdb_db* db,
    uint64_t budget_ms,
    line_sender_error** err_out);

/**
 * The pool's failover budget (`reconnect_max_duration`, default 300000 ms).
 * Callers tracking an overall failover deadline pass the remaining budget to
 * `questdb_db_borrow_sf_column_sender_with_retry`. Returns 0 if `db` is NULL.
 */
QUESTDB_CLIENT_API
uint64_t questdb_db_reconnect_max_duration_ms(const questdb_db* db);

/**
 * Return a conn to the pool. Accepts NULL `conn` and no-ops.
 * Invalidates the `conn` pointer; do not use it after this call.
 * If the pool has been closed, the conn is closed instead of recycled.
 *
 * `db` is currently ignored — the conn carries its own reference to
 * the pool — but accepted for symmetry with the borrow call.
 *
 * @warning Returning a conn that has flushed but not yet
 * `sf_column_sender_wait`'d silently discards every deferred (non-first) flush
 * since the last sync: in direct mode those flushes were sent with the
 * deferred-commit flag and their source chunks were already cleared, so the
 * data is unrecoverable. Call `sf_column_sender_wait` (or
 * `direct_column_sender_flush_and_wait` on the final chunk) before returning to
 * avoid data loss. This differs from the row sender, where every
 * `row_sender_flush` commits on its own — the column sender pipelines deferred
 * flushes for throughput and relies on an explicit sync to commit them, so the
 * trailing sync is mandatory, not optional.
 *
 * Mutually exclusive with `questdb_db_drop_sf_column_sender` on the same `conn`:
 * call exactly one of the two. Calling both (or either twice) is UB.
 */
QUESTDB_CLIENT_API
void questdb_db_return_sf_column_sender(
    questdb_db* db,
    sf_column_sender* conn);

/** Direct-handle counterpart of `questdb_db_return_sf_column_sender`. */
QUESTDB_CLIENT_API
void questdb_db_return_direct_column_sender(
    questdb_db* db,
    direct_column_sender* conn);

/**
 * Force-drop a borrowed conn instead of recycling it. Marks the conn terminal
 * (sf_column_sender_must_close becomes true) before the usual pool-return path runs.
 * Invalidates `conn`. Accepts NULL `conn` and no-ops.
 *
 * Use this in error-recovery paths where the conn may hold in-flight
 * uncommitted frames that the next borrower would otherwise commit
 * alongside their own (the round-3 dirty-sender concern). In
 * store-and-forward mode this removes the current backend from the pool and
 * releases the slot lock; unresolved frames remain in `sf_dir` for the next
 * owner to replay.
 *
 * @warning Dropping a conn that has flushed but not yet `sf_column_sender_wait`'d
 * silently discards every deferred (non-first) flush since the last sync: in
 * direct mode those flushes were sent with the deferred-commit flag and their
 * source chunks were already cleared, so the data is unrecoverable (it is not
 * persisted in `sf_dir` for replay either). If those flushes must not be lost,
 * call `sf_column_sender_wait` (or `direct_column_sender_flush_and_wait` on the final
 * chunk) before dropping.
 *
 * Mutually exclusive with `questdb_db_return_sf_column_sender` on the same `conn`:
 * call exactly one of the two. Calling both (or either twice) is UB.
 */
QUESTDB_CLIENT_API
void questdb_db_drop_sf_column_sender(
    questdb_db* db,
    sf_column_sender* conn);

/** Direct-handle counterpart of `questdb_db_drop_sf_column_sender`. */
QUESTDB_CLIENT_API
void questdb_db_drop_direct_column_sender(
    questdb_db* db,
    direct_column_sender* conn);

/* Reader-pool entry points (`questdb_db_borrow_reader`,
 * `questdb_db_return_reader`, `questdb_db_dbg_reader_*_count`) live in
 * `questdb/egress/reader.h` alongside the `reader` type
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
 * by any writer that hits a transport or protocol error), or if the
 * originating pool has been closed. On return to the pool such conns are
 * dropped, not recycled.
 */
QUESTDB_CLIENT_API
bool sf_column_sender_must_close(const sf_column_sender* conn);

/** Direct-handle counterpart of `sf_column_sender_must_close`. */
QUESTDB_CLIENT_API
bool direct_column_sender_must_close(const direct_column_sender* conn);

/* -------------------------------------------------------------------------
 * Row-major sender borrow
 *
 * The pool hands out three kinds of borrow: column-major senders
 * (`column_sender`, above), row-major senders (`row_sender`, here), and
 * query readers (`reader`, in `questdb/egress/reader.h`). A `row_sender`
 * builds rows with the ordinary `line_sender_buffer` API (from
 * `line_sender.h`) and flushes them with `row_sender_flush`.
 * ------------------------------------------------------------------------- */

/**
 * Borrow a row-major sender from the pool. Returns NULL on failure and
 * sets `*err_out` if provided. The row-sender pool is lazy and
 * independently capped (it shares `pool_max`); a borrow at the cap returns
 * `line_sender_error_invalid_api_call`. The returned sender is bound to the
 * calling thread until returned.
 */
QUESTDB_CLIENT_API
row_sender* questdb_db_borrow_row_sender(
    questdb_db* db,
    line_sender_error** err_out);

/**
 * Like `questdb_db_borrow_row_sender` but retries the connect within
 * `budget_ms` using the pool's reconnect backoff (authentication and
 * protocol-version errors are terminal). `budget_ms == 0` makes a single
 * attempt. Returns NULL on failure and sets `*err_out` if provided.
 */
QUESTDB_CLIENT_API
row_sender* questdb_db_borrow_row_sender_with_retry(
    questdb_db* db,
    uint64_t budget_ms,
    line_sender_error** err_out);

/**
 * Return a borrowed row sender to the pool. Invalidates `sender`. Accepts
 * NULL and no-ops. `db` is ignored (the sender carries its own pool
 * back-reference) but kept in the ABI for symmetry with the borrow call.
 *
 * Mutually exclusive with `questdb_db_drop_row_sender` on the same
 * `sender`: call exactly one of the two.
 */
QUESTDB_CLIENT_API
void questdb_db_return_row_sender(
    questdb_db* db,
    row_sender* sender);

/**
 * Force-drop a borrowed row sender instead of recycling it: the underlying
 * connection is closed and the next borrow opens a fresh one. Invalidates
 * `sender`. Accepts NULL and no-ops.
 *
 * Mutually exclusive with `questdb_db_return_row_sender` on the same
 * `sender`: call exactly one of the two.
 */
QUESTDB_CLIENT_API
void questdb_db_drop_row_sender(
    questdb_db* db,
    row_sender* sender);

/**
 * `true` if the row sender will be dropped rather than recycled on return
 * (it was force-marked, a flush left the connection unusable, or the
 * originating pool has been closed), or if `sender` is NULL. `false` only
 * when it is safely reusable.
 */
QUESTDB_CLIENT_API
bool row_sender_must_close(const row_sender* sender);

/**
 * Flush the buffer of rows through the borrowed row sender, then clear the
 * buffer. Returns `true` on success; on failure returns `false` and sets
 * `*err_out`. Mirrors `line_sender_flush` for the standalone sender.
 */
QUESTDB_CLIENT_API
bool row_sender_flush(
    row_sender* sender,
    line_sender_buffer* buffer,
    line_sender_error** err_out);

/**
 * Flush the buffer of rows through the borrowed row sender, keeping the
 * buffer intact (clear it before starting a new batch). Mirrors
 * `line_sender_flush_and_keep`.
 */
QUESTDB_CLIENT_API
bool row_sender_flush_and_keep(
    row_sender* sender,
    const line_sender_buffer* buffer,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Chunk lifecycle
 * ------------------------------------------------------------------------- */

/**
 * Create an empty chunk for the given table. The chunk is caller-owned
 * and must be freed with `column_sender_chunk_free` or flushed via
 * `sf_column_sender_flush` (which clears but does not free it).
 *
 * Name validation timing: this entrypoint takes the table name as a raw
 * `const char*` + length and validates ONLY that the bytes are UTF-8
 * here. Both the name grammar (illegal characters, dot placement, BOM)
 * AND the 127-byte length cap are DEFERRED to the first flush — a
 * malformed name is accepted here and only surfaces as an error from
 * `sf_column_sender_flush*`. This matches the deferred-validation contract
 * of the Rust `Chunk::new`.
 *
 * If you already hold a pre-validated `line_sender_table_name` (e.g.
 * because you also flush Arrow batches via
 * `sf_column_sender_flush_arrow_batch_at_column`, which requires that type),
 * prefer `column_sender_chunk_new_validated`: it takes the validated
 * handle directly and reports grammar errors EAGERLY at
 * `line_sender_table_name_init` time — the same type and timing as the
 * Arrow flush entrypoints — so a bad name does not surface at two
 * different points depending on which path you take.
 */
QUESTDB_CLIENT_API
column_sender_chunk* column_sender_chunk_new(
    const char* table_name,
    size_t table_name_len,
    line_sender_error** err_out);

/**
 * Create an empty chunk from a pre-validated `line_sender_table_name`.
 *
 * Typed, eager-grammar-validation counterpart to
 * `column_sender_chunk_new`. The name grammar was already checked when
 * the `line_sender_table_name` was built (`line_sender_table_name_init`
 * returns false for an illegal name), so this constructor cannot fail on
 * the name and never sets `*err_out`. The 127-byte length cap is still
 * applied at the first flush — identical type AND validation timing to
 * the Arrow flush entrypoints (`sf_column_sender_flush_arrow_batch_at_column`
 * / `_server_stamped`), which also take a `line_sender_table_name`.
 *
 * Use this when you validated the table name once and want to share it
 * between the chunk path and an Arrow flush, instead of being forced to
 * re-pass raw `const char*` bytes through `column_sender_chunk_new`. The
 * chunk is caller-owned and freed/flushed exactly like one returned by
 * `column_sender_chunk_new`.
 */
QUESTDB_CLIENT_API
column_sender_chunk* column_sender_chunk_new_validated(
    line_sender_table_name table,
    line_sender_error** err_out);

/**
 * Discard the chunk and release its allocations. Accepts NULL (no-op).
 *
 * Calling this twice on the same non-NULL chunk is undefined behaviour
 * (double free): the handle is freed in place and cannot be detected as
 * already-released. Drop your pointer after the call.
 */
QUESTDB_CLIENT_API
void column_sender_chunk_free(column_sender_chunk* chunk);

/**
 * Clear the chunk's content, keeping retained capacity for reuse.
 *
 * Returns true on success. Returns false and sets `*err_out` if `chunk`
 * is NULL, has already been freed, or another FFI call is currently
 * mutating the chunk. A NULL `err_out` is silently ignored.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_clear(
    column_sender_chunk* chunk,
    line_sender_error** err_out);

/**
 * Current row count of the chunk; 0 if no column has been appended.
 *
 * Returns `(size_t)-1` and sets `*err_out` if `chunk` is NULL, has been
 * freed, or another FFI call is in flight. A NULL `err_out` is silently
 * ignored.
 */
QUESTDB_CLIENT_API
size_t column_sender_chunk_row_count(
    const column_sender_chunk* chunk,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Numeric / fixed-width column appends
 *
 * Every column-append function locks the chunk's row count on the first
 * call. Subsequent columns must agree on row count. `data` is a
 * contiguous, full-length typed array with one slot per row (including
 * null rows — their slot value is ignored). `validity` is optional;
 * pass NULL when the column has no nulls.
 *
 * `name` / `name_len` are validated eagerly at this call: the bytes must be
 * UTF-8 and satisfy the column-name grammar (illegal characters, dot
 * placement, length cap) — the same rules the row API's
 * `line_sender_column_name` enforces. A bad name makes this append return
 * `false` with `*err_out` set and leaves the chunk unchanged, so check the
 * return value here rather than deferring error handling to
 * `sf_column_sender_flush*`. There is intentionally no separate pre-validated
 * column-name overload on the column-sender surface.
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
 * infrastructure as `sf_column_sender_flush_arrow_batch_server_stamped`. Supports the
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
 *    `sf_column_sender_flush` returns. The caller may free the
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
 *
 * Buffer-size trust boundary: the struct is validated for structural
 * sanity (non-NULL mandatory pointers, non-negative length/offset/child
 * counts, bounded nesting depth and `row_count`) so that a malformed
 * struct returns an error rather than aborting. It is NOT possible to
 * validate the *sizes* of the producer's buffers — the Arrow C Data
 * Interface carries no buffer byte-length. A producer that declares a
 * `length`/offsets inconsistent with its actual buffer allocations, or a
 * `metadata` blob whose internal key/value lengths run past its
 * allocation, causes out-of-bounds reads (undefined behavior) inside
 * arrow-rs that no consumer can pre-detect. The caller is responsible for
 * passing arrays whose buffers and metadata match their declared sizes.
 * First-party producers (pyarrow, polars) always satisfy this.
 * ------------------------------------------------------------------------- */

#ifdef QUESTDB_CLIENT_ENABLE_ARROW

/* Apache Arrow C Data Interface boilerplate. Guarded by
 * `ARROW_C_DATA_INTERFACE` so it composes safely with arrow.h,
 * nanoarrow, polars-arrow, and any other header that ships the same
 * canonical block. The caller owns lifetimes of `ArrowArray` /
 * `ArrowSchema`; we consume `array->release` on success in the
 * column-sender entry points below, and leave it intact on failure.
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

/**
 * Opaque handle wrapping an `ArrowArray` + `ArrowSchema` pair imported
 * from the Arrow C Data Interface. Lets a caller import a Polars /
 * Pandas / Arrow column once and then slice/append it across many
 * chunks (e.g. paginating a large DataFrame) without re-paying the
 * import cost per chunk.
 *
 * Not thread-safe. Bound to the importing thread until freed.
 */
typedef struct column_sender_arrow_import column_sender_arrow_import;

/**
 * `auto`: Dictionary(*, Utf8/LargeUtf8) -> SYMBOL, plain Utf8 -> VARCHAR.
 * `symbol`: force plain Utf8 -> SYMBOL. `not_symbol`: force Dictionary ->
 * VARCHAR. Used by `column_sender_arrow_import_new`.
 */
typedef enum column_sender_symbol_mode
{
    column_sender_symbol_mode_auto = 0,
    column_sender_symbol_mode_symbol = 1,
    column_sender_symbol_mode_not_symbol = 2,
} column_sender_symbol_mode;

/**
 * Import an `ArrowArray` + `ArrowSchema` pair into an opaque handle.
 *
 * Ownership of the array's buffers transfers into the returned handle.
 * On success, `array->release` is cleared to NULL — the caller MUST
 * NOT invoke it. On error, `array->release` may also have been
 * cleared if validation reached the Arrow import step; the caller
 * MUST check `array->release != NULL` before calling it on the
 * failure path. Depth-cap and NULL-pointer rejections leave it
 * intact. `schema` is borrowed only for the duration of this call.
 *
 * `symbol_mode` selects the SYMBOL-vs-VARCHAR disposition of a string
 * column; it carries a `column_sender_symbol_mode_*` constant and is a
 * no-op for non-string columns. The parameter is `uint32_t` rather than
 * `enum column_sender_symbol_mode` so an out-of-range value returns
 * `line_sender_error_invalid_api_call` instead of being undefined
 * behaviour at the language boundary.
 *
 * Returns NULL on error and writes a `line_sender_error*` to
 * `*err_out`. The returned handle (when non-NULL) MUST be freed with
 * `column_sender_arrow_import_free`.
 */
QUESTDB_CLIENT_API
column_sender_arrow_import* column_sender_arrow_import_new(
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    uint32_t symbol_mode,
    line_sender_error** err_out);

/**
 * Append a slice of a previously-imported Arrow column to `chunk`.
 *
 * `name` / `name_len` is the destination QuestDB column name (UTF-8,
 * not NUL-terminated). `row_offset` and `row_count` select a slice
 * within `imported`'s logical length; pass `row_offset = 0` and
 * `row_count = column_sender_arrow_import_len(imported)` for the
 * whole column. `imported` is borrowed; the chunk holds an internal
 * reference to its buffers until `sf_column_sender_flush` returns.
 *
 * Returns `true` on success; on failure returns `false`, writes a
 * `line_sender_error*` to `*err_out`, and leaves the chunk
 * unchanged.
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_append_arrow_import(
    column_sender_chunk* chunk,
    const char* name,
    size_t name_len,
    const column_sender_arrow_import* imported,
    size_t row_offset,
    size_t row_count,
    line_sender_error** err_out);

/**
 * Free a `column_sender_arrow_import` handle and its underlying
 * Arrow buffers. Accepts NULL `imported` and no-ops. Invalidates
 * `imported`; do not use it after this call.
 *
 * Calling this twice on the same non-NULL handle is undefined behaviour
 * (double free): the handle is freed in place and a stale pointer cannot
 * be detected. Drop your pointer after the call.
 *
 * Safe to call after every chunk that referenced this import has
 * been successfully flushed. Calling it while a chunk still
 * references the import is UB — the chunk's internal reference
 * extends the buffers' lifetime through the next `sf_column_sender_flush`,
 * not beyond.
 */
QUESTDB_CLIENT_API
void column_sender_arrow_import_free(column_sender_arrow_import* imported);

/**
 * Number of rows in an imported Arrow column. Returns `(size_t)-1`
 * (a.k.a. `SIZE_MAX`) if `imported` is NULL, has been freed, or is held
 * by a concurrent call; `0` is reserved for a logically-empty (0-row)
 * column.
 */
QUESTDB_CLIENT_API
size_t column_sender_arrow_import_len(const column_sender_arrow_import* imported);

/**
 * Append a slice of one column from an `ArrowArray` + `ArrowSchema`
 * pair directly to `chunk`, without going through
 * `column_sender_arrow_import_new`. Convenience for callers that
 * only need to ingest the column once.
 *
 * Ownership: on success, `array->release` is consumed (cleared to
 * NULL); the chunk holds the underlying buffers via an internal
 * reference until `sf_column_sender_flush` returns. On failure,
 * `array->release` may also have been consumed if the call reached
 * the Arrow import step before failing — callers MUST check
 * `array->release != NULL` before invoking it on the failure path.
 * Early-fail paths (NULL pointer, depth-cap rejection) leave it
 * intact. `schema` is borrowed in all cases.
 *
 * `array->offset` is honored (the Arrow C Data Interface logical
 * offset); `row_offset` further sub-slices within the call.
 */
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
#endif /* QUESTDB_CLIENT_ENABLE_ARROW */

/* -------------------------------------------------------------------------
 * Generic NumPy column appender
 *
 * Companion to `column_sender_chunk_append_arrow_column` for callers
 * holding a raw, contiguous, native-endian NumPy buffer. The buffer is
 * walked at flush time, single pass, straight into the connection's
 * outbound frame — no chunk-side scratch arena, no per-column heap copy.
 *
 * Caller contract: `data` (and `validity->bits`, if any) MUST stay alive
 * until the next `sf_column_sender_flush` / `sf_column_sender_wait` returns.
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
 *     u32/u64      → LONG  (zero-extend; u64 values > i64::MAX are rejected)
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
    /* Signed integers — widened one step up to a sentinel-safe wire so the
       source's full range (including value 0) round-trips faithfully. The
       widened wire's sentinel (i32::MIN / i64::MIN) lies outside the
       source's representable range, so no source value collides with it. */
    column_sender_numpy_i8 = 0,  /* → INT  (4B/row, widen i8→i32, sentinel-safe)  */
    column_sender_numpy_i16 = 1, /* → INT  (4B/row, widen i16→i32, sentinel-safe) */
    column_sender_numpy_i32 = 2, /* → LONG (8B/row, widen i32→i64, sentinel-safe) */
    column_sender_numpy_i64 = 3, /* → LONG (8B/row, sentinel = i64::MIN)          */

    /* Unsigned integers — widen to the smallest signed wire that holds the
       source range WITHOUT colliding with the null sentinel. BYTE/SHORT
       use value 0 as null, so u8 cannot use either; INT (i32::MIN sentinel)
       is the minimum safe target for u8. */
    column_sender_numpy_u8 = 4,  /* → INT   (4B/row, widen u8→i32)              */
    column_sender_numpy_u16 = 5, /* → INT   (4B/row, widen u16→i32)             */
    column_sender_numpy_u32 = 6, /* → LONG  (8B/row, widen u32→i64)             */
    column_sender_numpy_u64 = 7, /* → LONG  (8B/row, reject values > i64::MAX)  */

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
       referenced year / month. W / D / h / m are constant multipliers.
       All reject overflow with InvalidApiCall. */
    column_sender_numpy_datetime64_m = 32, /* minute × 60_000_000          */
    column_sender_numpy_datetime64_h = 33, /* hour   × 3_600_000_000       */
    column_sender_numpy_datetime64_D = 34, /* day    × 86_400_000_000      */
    column_sender_numpy_datetime64_M = 35, /* month  → start of 1970-01+M  */
    column_sender_numpy_datetime64_Y = 36, /* year   → start of 1970+Y     */
    column_sender_numpy_datetime64_W = 37, /* week   × 604_800_000_000     */

    /* Coarser timedelta64 units → LONG (raw i64, no unit normalisation).
       Mirrors the existing s / ms / us / ns dispatch — caller picks the
       unit, server stores the integer as-is. Calendar units (M / Y) have
       no fixed duration and are explicitly rejected. */
    column_sender_numpy_timedelta64_m = 38, /* minute  → raw i64 */
    column_sender_numpy_timedelta64_h = 39, /* hour    → raw i64 */
    column_sender_numpy_timedelta64_D = 40, /* day     → raw i64 */
    column_sender_numpy_timedelta64_M = 41, /* REJECTED: month length is variable */
    column_sender_numpy_timedelta64_Y = 42  /* REJECTED: year length is variable  */
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

/**
 * Append one column from a contiguous, native-endian NumPy buffer.
 *
 * `dtype` carries a `column_sender_numpy_*` constant from the enum
 * above. The parameter is `uint32_t` rather than `enum
 * column_sender_numpy_dtype` so an out-of-range value returns
 * `line_sender_error_invalid_api_call` instead of being undefined
 * behaviour at the language boundary.
 *
 * ZERO-COPY LIFETIME: this call parks the raw `data` (and
 * `validity->bits`, if any) pointer and walks it later, at flush time.
 * The caller MUST keep the backing buffer alive AND unmodified until the
 * next `sf_column_sender_flush` / `sf_column_sender_wait` on this chunk
 * returns. Freeing/reallocating/moving it before then is undefined
 * behaviour.
 *
 * `data_len_bytes` is the byte length of the buffer `data` points at. It
 * is validated against `row_count * source-stride(dtype)`; a buffer too
 * small for the declared dtype + row_count is rejected with
 * `line_sender_error_invalid_api_call` and nothing is appended. This is
 * the only guard against a mis-tagged `dtype` or an inflated `row_count`
 * reading past the real allocation (host-memory leak onto the wire, or a
 * crash). Pass `arr.nbytes` for a NumPy array; pass `0` when `data` is
 * NULL (only legal with `row_count == 0`).
 */
QUESTDB_CLIENT_API
bool column_sender_chunk_append_numpy_column(
    column_sender_chunk* chunk,
    const char* name,
    size_t name_len,
    uint32_t dtype,
    const uint8_t* data,
    size_t data_len_bytes,
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

/** Designated timestamp in milliseconds, widened to micros (wire type
 * TIMESTAMP, 0x0A). */
QUESTDB_CLIENT_API
bool column_sender_chunk_designated_timestamp_millis(
    column_sender_chunk* chunk,
    const int64_t* data,
    size_t row_count,
    line_sender_error** err_out);

/** Designated timestamp in seconds, widened to micros (wire type
 * TIMESTAMP, 0x0A). */
QUESTDB_CLIENT_API
bool column_sender_chunk_designated_timestamp_seconds(
    column_sender_chunk* chunk,
    const int64_t* data,
    size_t row_count,
    line_sender_error** err_out);

/* -------------------------------------------------------------------------
 * Flush / sync
 *
 * `sf_column_sender_flush` encodes `chunk` into a QWP/WebSocket frame,
 * publishes it through `conn`, and returns without waiting for a server
 * ACK. On success, `chunk` is cleared (allocations retained) and `true`
 * is returned. On failure, `chunk` is left untouched.
 *
 * Direct mode: the first flush is sent as an immediate commit. Later flushes
 * are sent with QWP's deferred-commit flag so callers can pipeline many
 * chunks. Call `sf_column_sender_wait` after the final flush to send the commit
 * frame and wait until all in-flight frames are acknowledged at `ack_level`.
 *
 * Store-and-forward mode: every flushed frame is non-deferred and is first
 * accepted into the local SFA queue. `sf_column_sender_wait` does not send a
 * commit frame; it waits for frames already published to the local queue up to
 * the sync-call boundary. `sf_column_sender_flush` success means local queue
 * acceptance, not server acknowledgement.
 *
 * In direct mode, the connection keeps one protocol in-flight slot reserved
 * for the sync commit frame. If that reserve would be exhausted, flush returns
 * `line_sender_error_invalid_api_call`; call `sf_column_sender_wait` before
 * flushing more chunks.
 *
 * No-progress timeout (both modes): `sf_column_sender_wait` returns
 * `line_sender_error_failover_retry` if the server stays connected but never
 * advances the ack/durable watermark for `request_timeout` (default 30s) — a
 * back-pressured WAL or stuck commit. The deadline resets on every watermark
 * advance, so a slow-but-progressing sync (e.g. a `durable` upload under
 * pressure) is not cut off. On this error the unacked frames are retained:
 * drop the conn and re-borrow to replay (store-and-forward) or re-drive from
 * source (direct). Raise `request_timeout` to wait longer.
 * ------------------------------------------------------------------------- */

QUESTDB_CLIENT_API
bool sf_column_sender_flush(
    sf_column_sender* conn,
    column_sender_chunk* chunk,
    line_sender_error** err_out);

/**
 * Pipeline a deferred frame on a direct connection. Not committed until
 * `direct_column_sender_commit` / `direct_column_sender_flush_and_wait`.
 */
QUESTDB_CLIENT_API
bool direct_column_sender_flush(
    direct_column_sender* conn,
    column_sender_chunk* chunk,
    line_sender_error** err_out);

/**
 * `ack_level` carries a `column_sender_ack_level_*` constant. The
 * parameter is `uint32_t` rather than `enum column_sender_ack_level` so
 * an out-of-range value returns `line_sender_error_invalid_api_call`
 * instead of being undefined behaviour at the language boundary.
 */
QUESTDB_CLIENT_API
bool sf_column_sender_wait(
    sf_column_sender* conn, uint32_t ack_level, line_sender_error** err_out);

/**
 * Direct commit: send the commit boundary for all pipelined frames and block
 * until they reach `ack_level`. The direct sender's durability checkpoint;
 * frames pipelined by `direct_column_sender_flush` are lost if the conn is
 * dropped before a successful commit.
 */
QUESTDB_CLIENT_API
bool direct_column_sender_commit(
    direct_column_sender* conn, uint32_t ack_level, line_sender_error** err_out);

/**
 * Publish `chunk` as a completion boundary, then wait until every frame
 * published before or by this call reaches `ack_level` (see
 * `sf_column_sender_wait` for the level meanings and the no-progress timeout).
 *
 * `ack_level` carries a `column_sender_ack_level_*` constant. An out-of-range
 * value, or `column_sender_ack_level_durable` without `request_durable_ack=on`,
 * returns `line_sender_error_invalid_api_call` before `chunk` is touched.
 *
 * Boundary: success acknowledges all prior no-wait flushes plus this one. An
 * empty `chunk` behaves like `sf_column_sender_wait`.
 *
 * Failure contract: on a pre-publication failure `chunk` is left untouched and
 * retryable. Once the frame is published `chunk` is cleared even if the ACK
 * wait then fails — delivery of that frame is then unknown, and the conn should
 * be dropped and re-borrowed per the error class. No internal failover retry.
 */
QUESTDB_CLIENT_API
bool direct_column_sender_flush_and_wait(
    direct_column_sender* conn,
    column_sender_chunk* chunk,
    uint32_t ack_level,
    line_sender_error** err_out);

#ifdef QUESTDB_CLIENT_ENABLE_ARROW

/**
 * Per-column wire-type hint kind, paired with
 * `column_sender_arrow_override::kind`.
 */
typedef enum column_sender_arrow_override_kind
{
    column_sender_arrow_override_symbol = 0,
    column_sender_arrow_override_ipv4 = 1,
    column_sender_arrow_override_char = 2,
    column_sender_arrow_override_geohash = 3,
    /** Force the column NOT to be SYMBOL: a Dictionary column is decoded
     *  to VARCHAR on emit; a no-op on plain Utf8 (already VARCHAR). */
    column_sender_arrow_override_not_symbol = 4,
} column_sender_arrow_override_kind;

/**
 * Per-column wire-type hint passed to
 * `sf_column_sender_flush_arrow_batch_server_stamped` (and `_at_column`) to
 * steer encoding without having to attach
 * `questdb.*` Field metadata to the Arrow schema. Caller owns `column`;
 * the bytes are borrowed for the duration of the call.
 *
 * `arg` carries the geohash precision (1..=60) when `kind ==
 * column_sender_arrow_override_geohash`, and is ignored for every other
 * kind (pass 0).
 */
typedef struct column_sender_arrow_override
{
    const char* column;
    size_t column_len;
    uint32_t kind;
    uint32_t arg;
} column_sender_arrow_override;

/**
 * Encode an Arrow C Data Interface `RecordBatch` (struct-typed
 * `ArrowArray`) and publish it as one QWP frame, **without** a per-row
 * designated timestamp: the server stamps each row on arrival.
 *
 * This is an explicit opt-in. If your batch carries a real event-time
 * column, use `sf_column_sender_flush_arrow_batch_at_column` instead —
 * reaching for this entry point would discard that column's role as the
 * designated timestamp and silently substitute server arrival time,
 * producing wrong partitions/order.
 *
 * Ownership: same contract as `column_sender_chunk_append_arrow_column`
 * — on success `array->release` is consumed (set to NULL); on failure
 * it may also have been consumed. Callers MUST check
 * `array->release != NULL` before invoking it on the failure path.
 * `schema` is borrowed in all cases.
 *
 * `overrides` (length `overrides_len`) optionally supplies per-column
 * wire-type hints. Pass `NULL, 0` for no overrides. Returns `false`
 * with `line_sender_error_invalid_api_call` if any override targets
 * an unknown column, duplicates another override, carries invalid
 * UTF-8 in `column`, has an unknown `kind`, or — for
 * `column_sender_arrow_override_geohash` — carries `arg` outside
 * `1..=60`.
 *
 * Name validation timing: `table` is a `line_sender_table_name`, so the
 * name grammar was validated EAGERLY at `line_sender_table_name_init`
 * time; only the 127-byte length cap is checked here at flush. The chunk
 * path's raw `column_sender_chunk_new` instead defers BOTH checks to
 * flush. To get this same eager/typed behaviour on the chunk path, build
 * the chunk with `column_sender_chunk_new_validated`.
 */
QUESTDB_CLIENT_API
bool sf_column_sender_flush_arrow_batch_server_stamped(
    sf_column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    line_sender_error** err_out);

/** Direct-handle publish-only Arrow flush (server-stamped). Pair with
 *  `direct_column_sender_commit`, or use
 *  `direct_column_sender_flush_arrow_batch_server_stamped_and_wait`. */
QUESTDB_CLIENT_API
bool direct_column_sender_flush_arrow_batch_server_stamped(
    direct_column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    line_sender_error** err_out);

/**
 * Same as `sf_column_sender_flush_arrow_batch_server_stamped` but picks the
 * designated timestamp from a named column of the batch instead of
 * letting the server stamp each row. Same ownership and `overrides`
 * contract.
 */
QUESTDB_CLIENT_API
bool sf_column_sender_flush_arrow_batch_at_column(
    sf_column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    line_sender_column_name ts_column,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    line_sender_error** err_out);

/** Direct-handle publish-only Arrow flush (column-stamped). Pair with
 *  `direct_column_sender_commit`, or use
 *  `direct_column_sender_flush_arrow_batch_at_column_and_wait`. */
QUESTDB_CLIENT_API
bool direct_column_sender_flush_arrow_batch_at_column(
    direct_column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    line_sender_column_name ts_column,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    line_sender_error** err_out);

/**
 * ACKing counterpart of `sf_column_sender_flush_arrow_batch_server_stamped`:
 * publish `array` as a boundary, then wait for `ack_level`.
 *
 * `ack_level` is validated before the Arrow C Data Interface import consumes
 * `array->release`, so a rejected level (out-of-range, or
 * `column_sender_ack_level_durable` without `request_durable_ack=on`) returns
 * `line_sender_error_invalid_api_call` and leaves `array` untouched.
 *
 * Ownership differs from the publish-only flush on the failure path. On a
 * provably pre-publication failure the batch is re-exported into `*array` (a
 * fresh `release`) so the caller can drop+re-borrow and retry. On any
 * post-publication failure — including an ACK-wait / store-and-forward
 * no-progress timeout reported as `line_sender_error_failover_retry` — the
 * batch is NOT re-exported (`array->release` stays NULL): delivery is unknown.
 * Callers MUST check `array->release != NULL` before invoking it on failure.
 */
QUESTDB_CLIENT_API
bool direct_column_sender_flush_arrow_batch_server_stamped_and_wait(
    direct_column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    uint32_t ack_level,
    line_sender_error** err_out);

/**
 * ACKing counterpart of `sf_column_sender_flush_arrow_batch_at_column`: publish
 * `array` (timestamp sourced from `ts_column`) as a boundary, then wait for
 * `ack_level`. Same ACK-validation preflight and phase-aware re-export contract
 * as `direct_column_sender_flush_arrow_batch_server_stamped_and_wait`.
 * Callers MUST check `array->release != NULL` before invoking it on failure.
 */
QUESTDB_CLIENT_API
bool direct_column_sender_flush_arrow_batch_at_column_and_wait(
    direct_column_sender* conn,
    line_sender_table_name table,
    struct ArrowArray* array,
    const struct ArrowSchema* schema,
    line_sender_column_name ts_column,
    const column_sender_arrow_override* overrides,
    size_t overrides_len,
    uint32_t ack_level,
    line_sender_error** err_out);
#endif /* QUESTDB_CLIENT_ENABLE_ARROW */

#ifdef __cplusplus
} /* extern "C" */
#endif
