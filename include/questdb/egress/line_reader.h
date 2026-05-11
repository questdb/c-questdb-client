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

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Reuse `line_sender_utf8` for validated UTF-8 strings. */
#include "../ingress/line_sender.h"

#if defined(LINESENDER_DYN_LIB) && defined(_MSC_VER)
#    define LINEREADER_API __declspec(dllimport)
#else
#    define LINEREADER_API
#endif

/////////// Thread safety.
//
// All four handles must be accessed by only one thread at a time. Beyond
// that, the four handle types have different thread-mobility rules:
//
//   `line_reader`         — may be migrated between threads (no concurrent
//                           access). The caller MUST establish a
//                           happens-before edge on every transfer — the
//                           reader's internal state is non-atomic and the
//                           library does not insert a fence for you. A
//                           pthread mutex hand-off, a thread spawn/join,
//                           or a `std::atomic` with release/acquire on
//                           the handle pointer are all sufficient. The
//                           library does maintain an internal AtomicBool
//                           that guards the reader-vs-query/cursor
//                           lifecycle and pairs Release with Acquire on
//                           every lifecycle event, but that pairing is an
//                           implementation detail — it cannot publish the
//                           reader's state on the very first migration
//                           after `_from_conf` / `_from_env` (no
//                           lifecycle event has happened yet). Concurrent
//                           operations from two threads are always
//                           undefined behaviour — only sequential
//                           migration is supported.
//
//   `line_reader_query`   — MUST stay on the thread that created it.
//   `line_reader_cursor`     The query/cursor wraps an internal failover
//                           callback closure that is `!Send` (it can
//                           legitimately capture `!Send` user state in a
//                           future revision), so handing the handle to
//                           another thread — even with a happens-before
//                           edge and no concurrent access — is undefined
//                           behaviour.
//
//   `line_reader_error`   — has no thread affinity. May be created on one
//                           thread and freed/inspected on another, but
//                           must not be used from two threads at once.
//
// Borrowed pointers returned by this API — `line_reader_server_info*`,
// `line_reader_failover_event*`, host byte slices, varchar/binary/symbol
// values, validity bitmaps, and array views — are invalidated by any
// concurrent operation on their owning handle, with no library-side
// synchronisation. A reader/cursor mutation on one thread can free or
// move the storage that another thread is reading. Never share a
// borrowed pointer across threads without explicit external locking that
// also serialises every operation on the owning handle.
//
// Concurrent-stat exception: a narrow set of `line_reader` getters are
// safe to call from a monitoring thread while another thread is driving
// a query/cursor on the same reader, because they touch only atomic
// counters:
//
//   `line_reader_bytes_received`
//   `line_reader_credit_granted_total`
//   `line_reader_read_ns`
//   `line_reader_decode_ns`
//   `line_reader_reset_timing`
//
// All other reader getters — including `line_reader_server_version`,
// `line_reader_current_addr_host`, `line_reader_current_addr_port`, and
// `line_reader_current_server_info` — read non-atomic state that the
// cursor thread mutates during failover, and remain bound by the
// one-thread-at-a-time rule.

/////////// Pointer preconditions.
//
// Unless explicitly documented as "idempotent on NULL" (e.g. the various
// `_close` / `_free` functions), every pointer parameter on this API —
// handle pointers (`line_reader*`, `line_reader_query*`, `line_reader_cursor*`,
// `line_reader_error*`), the `err_out` slot, and every `out_*` output pointer
// — MUST be non-NULL. Passing NULL is undefined behaviour: the library does
// not check, and dereferencing the NULL slot will SIGSEGV (or worse, silently
// corrupt memory if the page happens to be mapped).

/////////// Error handling.

/** An error that occurred when using the line reader. */
typedef struct line_reader_error line_reader_error;

/**
 * Category of egress error.
 *
 * Discriminants are explicit and append-only across releases — inserting
 * a new variant in the middle would silently renumber later ones across
 * recompiles, breaking ABI for shared-library consumers. New error codes
 * MUST be added at the end with the next free integer.
 */
typedef enum line_reader_error_code
{
    /** Bad URL, host, or interface in the connect string. */
    line_reader_error_could_not_resolve_addr = 0,
    /** Bad configuration string or builder argument. */
    line_reader_error_config_error = 1,
    /** Methods called in the wrong order (e.g. `execute` while a cursor is live). */
    line_reader_error_invalid_api_call = 2,
    /** Network-level failure (connect, read, write, close). */
    line_reader_error_socket_error = 3,
    /** TLS handshake failure. */
    line_reader_error_tls_error = 4,
    /** HTTP-upgrade or WebSocket handshake failure. */
    line_reader_error_handshake_error = 5,
    /** Authentication or authorization failure. */
    line_reader_error_auth_error = 6,
    /** Server returned an unsupported QWP version, encoding, or capability. */
    line_reader_error_unsupported_server = 7,
    /** All endpoints connected, but none advertised a role matching the
     *  configured `target` filter (e.g. `target=replica` against a
     *  single-node OSS server emitting `STANDALONE`). */
    line_reader_error_role_mismatch = 8,
    /** Wire-format violation: bad magic, truncated frame, unknown
     *  discriminant, invalid varint, schema/symbol-dict reference miss, etc. */
    line_reader_error_protocol_error = 9,
    /** String or symbol field was not valid UTF-8. */
    line_reader_error_invalid_utf8 = 10,
    /** Bind parameter index, count, or value rejected client-side
     *  (before the QUERY_REQUEST hits the wire). */
    line_reader_error_invalid_bind = 11,
    /** Invalid timestamp value. */
    line_reader_error_invalid_timestamp = 12,
    /** Invalid decimal value. */
    line_reader_error_invalid_decimal = 13,
    /** Server-reported QWP `SCHEMA_MISMATCH` (status `0x03`). */
    line_reader_error_server_schema_mismatch = 14,
    /** Server-reported QWP `PARSE_ERROR` (status `0x05`). */
    line_reader_error_server_parse_error = 15,
    /** Server-reported QWP `INTERNAL_ERROR` (status `0x06`). */
    line_reader_error_server_internal_error = 16,
    /** Server-reported QWP `SECURITY_ERROR` (status `0x08`). */
    line_reader_error_server_security_error = 17,
    /** Client-side limit hit (e.g. an array row exceeds the configured
     *  per-row element cap). */
    line_reader_error_limit_exceeded = 18,
    /** Server-reported QWP `LIMIT_EXCEEDED` (status `0x0B`). */
    line_reader_error_server_limit_exceeded = 19,
    /** Query was cancelled (locally or via server `CANCELLED` status `0x0A`). */
    line_reader_error_cancelled = 20,
} line_reader_error_code;

/**
 * Error code categorising the error.
 * NULL-safe: returns `line_reader_error_invalid_api_call` for a NULL input.
 */
LINEREADER_API
line_reader_error_code line_reader_error_get_code(const line_reader_error*);

/**
 * UTF-8 encoded error message. Never returns NULL.
 * The `len_out` argument is set to the number of bytes in the string.
 * The string is NOT null-terminated.
 *
 * NULL-safe on both arguments. A NULL `error` returns a static empty
 * string and writes `*len_out = 0` (if `len_out` is non-NULL); a NULL
 * `len_out` is silently ignored. The combination matches `_free`'s
 * NULL-safety so the canonical "log + free" pattern stays sound even
 * if a caller's bookkeeping leaves `err` as NULL on a particular path.
 */
LINEREADER_API
const char* line_reader_error_msg(const line_reader_error*, size_t* len_out);

/** Free the error returned via an `err_out` parameter. Idempotent on NULL. */
LINEREADER_API
void line_reader_error_free(line_reader_error*);

/////////// Column kinds.

/**
 * Column kind discriminant. Numeric values match the QWP wire codes.
 * Returned by `line_reader_cursor_column_kind`.
 */
typedef enum line_reader_column_kind
{
    line_reader_column_kind_boolean         = 0x01,
    line_reader_column_kind_byte            = 0x02,
    line_reader_column_kind_short           = 0x03,
    line_reader_column_kind_int             = 0x04,
    line_reader_column_kind_long            = 0x05,
    line_reader_column_kind_float           = 0x06,
    line_reader_column_kind_double          = 0x07,
    line_reader_column_kind_symbol          = 0x09,
    line_reader_column_kind_timestamp       = 0x0A,
    line_reader_column_kind_date            = 0x0B,
    line_reader_column_kind_uuid            = 0x0C,
    line_reader_column_kind_long256         = 0x0D,
    line_reader_column_kind_geohash         = 0x0E,
    line_reader_column_kind_varchar         = 0x0F,
    line_reader_column_kind_timestamp_nanos = 0x10,
    line_reader_column_kind_double_array    = 0x11,
    line_reader_column_kind_long_array      = 0x12,
    line_reader_column_kind_decimal64       = 0x13,
    line_reader_column_kind_decimal128      = 0x14,
    line_reader_column_kind_decimal256      = 0x15,
    line_reader_column_kind_char            = 0x16,
    line_reader_column_kind_binary          = 0x17,
    line_reader_column_kind_ipv4            = 0x18,
} line_reader_column_kind;

/////////// Reader.

/** Opaque QWP egress reader. */
typedef struct line_reader line_reader;

/* Forward declarations — see the corresponding sections below. */
typedef struct line_reader_cursor line_reader_cursor;
typedef struct line_reader_query line_reader_query;

/**
 * Construct a reader from a QuestDB config string.
 *
 * The config string follows the same format as the Rust `ReaderConfig::from_conf`
 * API (e.g. `"qwp::addr=localhost:9000;"`). On success returns a non-NULL handle
 * that must be released with `line_reader_close`. On failure returns NULL and
 * sets `*err_out`.
 *
 * The `config` payload is re-validated as UTF-8 on entry; a hand-rolled
 * `line_sender_utf8` carrying invalid bytes (i.e. one not built via
 * `line_sender_utf8_init`) surfaces as `line_reader_error_invalid_utf8`
 * instead of triggering undefined behaviour.
 *
 * @param[in] config UTF-8 config string.
 * @param[out] err_out Set on error.
 * @return Reader handle or NULL.
 */
LINEREADER_API
line_reader* line_reader_from_conf(
    line_sender_utf8 config,
    line_reader_error** err_out);

/**
 * Construct a reader from the configuration stored in the
 * `QDB_CLIENT_CONF` environment variable. The variable's value follows
 * the same format as `line_reader_from_conf`.
 *
 * Returns NULL and sets `*err_out` with one of:
 *   - `line_reader_error_config_error` — `QDB_CLIENT_CONF` is not set,
 *     or its value is set but malformed (the parser's error code is
 *     used for the latter).
 *   - `line_reader_error_invalid_utf8` — `QDB_CLIENT_CONF` is set but
 *     its bytes are not valid UTF-8.
 *
 * On success returns a non-NULL handle that must be released with
 * `line_reader_close`.
 *
 * @param[out] err_out Set on error.
 * @return Reader handle or NULL.
 */
LINEREADER_API
line_reader* line_reader_from_env(
    line_reader_error** err_out);

/**
 * Close the reader and release all associated resources. Idempotent on NULL.
 *
 * Any `line_reader_query` or `line_reader_cursor` obtained from this reader
 * MUST be freed/closed first. Closing the reader while a query or cursor is
 * still live is a contract violation: a cursor holds an internal reference
 * to the reader that would otherwise dangle.
 *
 * As defense-in-depth, the library detects this via an atomic active-flag
 * compare-and-swap. On detection it prints a diagnostic to stderr and
 * **leaks the reader** (handle and underlying socket) rather than freeing
 * it — leaking is finite and safe; freeing here would let the next
 * allocation alias the live cursor's reference and cause silent memory
 * corruption. Free the cursor / query first to avoid the leak.
 */
LINEREADER_API
void line_reader_close(line_reader* reader);

/////////// Reader stats and connection info.

/** Cumulative bytes received from the wire (header + payload). */
LINEREADER_API uint64_t line_reader_bytes_received(const line_reader*);

/** Cumulative CREDIT bytes granted to the server across this reader. */
LINEREADER_API uint64_t line_reader_credit_granted_total(const line_reader*);

/** Cumulative wall-clock nanoseconds spent in `read` calls (saturating). */
LINEREADER_API uint64_t line_reader_read_ns(const line_reader*);

/** Cumulative wall-clock nanoseconds spent decoding (saturating). */
LINEREADER_API uint64_t line_reader_decode_ns(const line_reader*);

/** Reset the cumulative `read_ns` / `decode_ns` counters to zero. */
LINEREADER_API void line_reader_reset_timing(line_reader*);

/**
 * Get the negotiated QWP server version.
 *
 * Returns `false` and sets `*err_out` on failure: the connection is not
 * established yet (no `SERVER_INFO` received), or the `reader` handle is
 * NULL (surfaced as `line_reader_error_invalid_api_call` rather than
 * dereferenced). On success returns `true` and writes the version to
 * `*out_version`.
 */
LINEREADER_API
bool line_reader_server_version(
    const line_reader* reader,
    uint8_t* out_version,
    line_reader_error** err_out);

/**
 * Borrow the current endpoint host as a UTF-8 byte slice. The pointer is
 * invalidated by any reader operation that may reconnect.
 */
LINEREADER_API
void line_reader_current_addr_host(
    const line_reader* reader,
    const char** out_buf,
    size_t* out_len);

/** Port of the endpoint the reader is currently connected to. */
LINEREADER_API
uint16_t line_reader_current_addr_port(const line_reader* reader);

/////////// SERVER_INFO.

/**
 * Opaque borrowed handle to a `SERVER_INFO` body. Returned by
 * `line_reader_server_info` and `line_reader_failover_event_server_info`.
 * Never free — the underlying storage is owned by the reader / failover
 * event respectively.
 */
typedef struct line_reader_server_info line_reader_server_info;

/** Cluster role advertised by `SERVER_INFO`. */
typedef enum line_reader_server_role
{
    line_reader_server_role_standalone       = 0,
    line_reader_server_role_primary          = 1,
    line_reader_server_role_replica          = 2,
    line_reader_server_role_primary_catchup  = 3,
    /** Forward-compat: a server role this client doesn't recognise. The
     *  raw byte is available via `line_reader_server_info_role_byte`. */
    line_reader_server_role_other            = 0xFF,
} line_reader_server_role;

/**
 * Get the reader's last-seen `SERVER_INFO`, or NULL on v1 servers. The
 * pointer is invalidated by any reader operation that may reconnect.
 */
LINEREADER_API
const line_reader_server_info* line_reader_current_server_info(const line_reader* reader);

/** Cluster role advertised by `SERVER_INFO`. */
LINEREADER_API line_reader_server_role line_reader_server_info_role(
    const line_reader_server_info*);

/** Raw role byte (useful when role() returns OTHER). */
LINEREADER_API uint8_t line_reader_server_info_role_byte(
    const line_reader_server_info*);

/** Monotonic generation counter advertised by the server. Increases on
 *  failover/role transitions; useful for fencing replayed batches. */
LINEREADER_API uint64_t line_reader_server_info_epoch(
    const line_reader_server_info*);

/** Bitset of QWP capability flags negotiated with the server. */
LINEREADER_API uint32_t line_reader_server_info_capabilities(
    const line_reader_server_info*);

/** Server's wall-clock time at handshake, in nanoseconds since the Unix
 *  epoch. Useful for skew detection. */
LINEREADER_API int64_t line_reader_server_info_server_wall_ns(
    const line_reader_server_info*);

/** Cluster identifier as a UTF-8 byte slice. The buffer is borrowed and
 *  invalidated by any reader operation that may reconnect. */
LINEREADER_API void line_reader_server_info_cluster_id(
    const line_reader_server_info*, const char** out_buf, size_t* out_len);

/** Node identifier as a UTF-8 byte slice. Same lifetime contract as
 *  `_cluster_id`. */
LINEREADER_API void line_reader_server_info_node_id(
    const line_reader_server_info*, const char** out_buf, size_t* out_len);

/////////// Failover callback.

/**
 * Opaque borrowed handle to a failover event. The pointer passed to your
 * callback is valid only for the duration of that callback invocation.
 */
typedef struct line_reader_failover_event line_reader_failover_event;

/**
 * User callback fired after each successful mid-query failover. The
 * `event` pointer is valid only for the duration of the call.
 *
 * Reentrancy contract — the callback MUST NOT:
 *
 *  - Call any function on the originating `line_reader`, the
 *    `line_reader_query` it produced, or the `line_reader_cursor` whose
 *    `next_batch` is in flight. The trampoline runs synchronously inside
 *    `line_reader_cursor_next_batch` (or `_cursor_cancel` /
 *    `_cursor_add_credit`) while the upstream code is mid-mutation of
 *    the underlying `Reader` and `Cursor`. Any reentrant FFI call would
 *    alias the in-flight `&mut Reader` and corrupt internal state — this
 *    is undefined behaviour. Read-only stat getters
 *    (`line_reader_bytes_received`, `_cursor_request_id`, etc.) are NOT
 *    safe from inside the callback for the same aliasing reason.
 *
 *  - Throw a C++ exception, `longjmp`, or otherwise unwind out of the
 *    callback. The trampoline crosses the C -> Rust boundary; unwinding
 *    through Rust frames is undefined behaviour. The trampoline wraps
 *    the user callback in `catch_unwind` and `abort()`s the process if
 *    an unwind escapes — that is the safest containable response to a
 *    boundary violation, but it terminates the entire process. Catch
 *    all exceptions inside the callback (or use an error-flag the
 *    surrounding code polls).
 *
 *  - Block indefinitely or perform long-running work. The callback
 *    runs synchronously on the thread driving the in-flight cursor
 *    operation; while it is executing, no batch is being read, no
 *    CREDIT is being granted to the server, the WebSocket is held
 *    open, and `line_reader_cursor_cancel` cannot make progress (the
 *    cursor is single-threaded). Keep the callback bounded — clear an
 *    accumulator, set a flag, signal a condition variable — and do
 *    any heavy work outside the cursor's drive thread.
 *
 * The callback may freely touch `event` and `user_data`; both are
 * owned by the caller's logic, not by the in-flight cursor.
 *
 * The callback runs on the thread driving the in-flight cursor
 * operation.
 */
typedef void (*line_reader_failover_callback)(
    const line_reader_failover_event* event,
    void* user_data);

/** Host of the previously-connected endpoint that failed. UTF-8 byte slice
 *  borrowed for the duration of the callback. */
LINEREADER_API void line_reader_failover_event_failed_host(
    const line_reader_failover_event*, const char** out_buf, size_t* out_len);
/** Port of the previously-connected endpoint that failed. */
LINEREADER_API uint16_t line_reader_failover_event_failed_port(
    const line_reader_failover_event*);
/** Host of the new endpoint the cursor is reconnecting to. UTF-8 byte slice
 *  borrowed for the duration of the callback. */
LINEREADER_API void line_reader_failover_event_new_host(
    const line_reader_failover_event*, const char** out_buf, size_t* out_len);
/** Port of the new endpoint the cursor is reconnecting to. */
LINEREADER_API uint16_t line_reader_failover_event_new_port(
    const line_reader_failover_event*);
/** Request_id reissued on the new connection (the original request_id is
 *  invalidated by the failover; the cursor's request_id is updated). */
LINEREADER_API int64_t line_reader_failover_event_new_request_id(
    const line_reader_failover_event*);
/** Number of reconnect attempts that preceded this success (1 on the first
 *  retry, etc.). */
LINEREADER_API uint32_t line_reader_failover_event_attempts(
    const line_reader_failover_event*);
/** Wall-clock nanoseconds spent reconnecting — sleep + dial + handshake +
 *  `SERVER_INFO` read. Saturating. */
LINEREADER_API uint64_t line_reader_failover_event_elapsed_ns(
    const line_reader_failover_event*);
/** Error code that triggered the failover (cause-of-death of the previous
 *  connection). */
LINEREADER_API line_reader_error_code line_reader_failover_event_trigger_code(
    const line_reader_failover_event*);
/** Trigger error message (UTF-8). Borrowed for the duration of the call. */
LINEREADER_API void line_reader_failover_event_trigger_msg(
    const line_reader_failover_event*, const char** out_buf, size_t* out_len);
/** `SERVER_INFO` for the new endpoint, or NULL on v1 servers. */
LINEREADER_API const line_reader_server_info* line_reader_failover_event_server_info(
    const line_reader_failover_event*);

/////////// Query builder.

/**
 * Opaque query builder. Created by `line_reader_query_new`, consumed by
 * `line_reader_query_execute` (which produces a cursor) or released by
 * `line_reader_query_free`. The originating reader MUST outlive the query.
 *
 * The `line_reader_query` type is forward-declared above.
 */

/**
 * Begin a new query against `reader` for the given SQL.
 *
 * Returns NULL and sets `*err_out` if a query or cursor against this
 * reader is already in flight (only one may be live per reader at a
 * time), or if `sql` carries invalid UTF-8 (re-validated on entry —
 * `line_reader_error_invalid_utf8`). Server-side validation of the SQL
 * itself is deferred to `line_reader_query_execute`.
 *
 * @return Query handle, or NULL on error.
 */
LINEREADER_API
line_reader_query* line_reader_query_new(
    line_reader* reader,
    line_sender_utf8 sql,
    line_reader_error** err_out);

/**
 * Free a query without executing it. Idempotent on NULL.
 *
 * Safe to call on the error path even after `_query_execute`:
 * `_query_execute` nulls the caller's `line_reader_query*` on
 * consumption, so `_query_free(query)` afterwards is a NULL no-op.
 */
LINEREADER_API
void line_reader_query_free(line_reader_query* query);

/**
 * Consume the query and return a streaming cursor.
 *
 * `query_inout` is the address of the caller's `line_reader_query*`
 * variable. The query is consumed regardless of outcome; on return,
 * `*query_inout` is set to NULL so that a defensive
 * `line_reader_query_free(*query_inout)` becomes a no-op. Passing NULL
 * for `query_inout` itself, or for `*query_inout`, is a contract
 * violation: the call sets `*err_out` to
 * `line_reader_error_invalid_api_call` and returns NULL.
 *
 * On success, ownership transfers to the returned cursor; on failure,
 * `*err_out` is set and NULL is returned.
 */
LINEREADER_API
line_reader_cursor* line_reader_query_execute(
    line_reader_query** query_inout,
    line_reader_error** err_out);

/* Bind parameters. All `line_reader_query_bind_*` functions append a bind
 * to the query in declaration order, matching the SQL placeholders
 * (`$1`, `$2`, …). They return void.
 *
 * Deferred-error contract: the only bind that can fail client-side is
 * `_bind_varchar` (UTF-8 re-validation). When it does, the failing bind
 * is NOT pushed and every subsequent `_bind_*` call on the same query is
 * a no-op — the upstream builder is frozen. This keeps placeholder
 * indices stable: a caller that ignores the deferred error and continues
 * binding will get a clean `line_reader_error_invalid_utf8` from
 * `_query_execute` rather than a confusing "wrong parameter type at $K"
 * caused by index drift. To recover, drop the query and rebuild. */

/** Bind a BOOLEAN positional parameter. */
LINEREADER_API void line_reader_query_bind_bool(line_reader_query*, bool v);

/** Bind a BYTE (signed 8-bit) positional parameter. */
LINEREADER_API void line_reader_query_bind_i8(line_reader_query*, int8_t v);

/** Bind a SHORT (signed 16-bit) positional parameter. */
LINEREADER_API void line_reader_query_bind_i16(line_reader_query*, int16_t v);

/** Bind an INT (signed 32-bit) positional parameter. */
LINEREADER_API void line_reader_query_bind_i32(line_reader_query*, int32_t v);

/** Bind a LONG (signed 64-bit) positional parameter. */
LINEREADER_API void line_reader_query_bind_i64(line_reader_query*, int64_t v);

/** Bind a FLOAT (32-bit IEEE-754) positional parameter. */
LINEREADER_API void line_reader_query_bind_f32(line_reader_query*, float v);

/** Bind a DOUBLE (64-bit IEEE-754) positional parameter. */
LINEREADER_API void line_reader_query_bind_f64(line_reader_query*, double v);

/** Bind a TIMESTAMP positional parameter as microseconds since the Unix epoch. */
LINEREADER_API void line_reader_query_bind_timestamp_micros(
    line_reader_query*, int64_t v);

/** Bind a TIMESTAMP_NANOS positional parameter as nanoseconds since the Unix epoch. */
LINEREADER_API void line_reader_query_bind_timestamp_nanos(
    line_reader_query*, int64_t v);

/** Bind a DATE positional parameter as milliseconds since the Unix epoch. */
LINEREADER_API void line_reader_query_bind_date_millis(
    line_reader_query*, int64_t v);

/** Bind a CHAR positional parameter as a UTF-16 code unit. */
LINEREADER_API void line_reader_query_bind_char(line_reader_query*, uint16_t v);

/** Bind a DECIMAL64 positional parameter: signed 64-bit mantissa `v` and
 *  column `scale` (number of fractional digits). The decimal value is
 *  `v * 10^(-scale)`. */
LINEREADER_API void line_reader_query_bind_decimal64(
    line_reader_query*, int64_t v, int8_t scale);

/** Bind a GEOHASH positional parameter. `v` is the bit-packed geohash payload
 *  (LSB-aligned); `precision_bits` is the number of significant bits
 *  (1–60 inclusive, per the QuestDB type system). */
LINEREADER_API void line_reader_query_bind_geohash(
    line_reader_query*, uint64_t v, uint8_t precision_bits);

/** Bind a UTF-8 VARCHAR value. The bytes are copied.
 *
 *  The `v` payload is re-validated as UTF-8 on entry. This function returns
 *  void, so an invalid-UTF-8 contract violation is stored on the query and
 *  surfaced from `line_reader_query_execute` as
 *  `line_reader_error_invalid_utf8` (first-error-wins; later binds and the
 *  builder state are not touched once a deferred error is set). */
LINEREADER_API void line_reader_query_bind_varchar(
    line_reader_query*, line_sender_utf8 v);

/** Bind a BINARY value. The bytes are copied. `buf` may be NULL when
 *  `len == 0` (binds an empty byte slice). For any non-zero `len`, `buf`
 *  must be non-NULL and point to at least `len` readable bytes — a NULL
 *  `buf` with non-zero `len` aborts the process, matching the policy of
 *  `line_reader_query_bind_uuid`. */
LINEREADER_API void line_reader_query_bind_binary(
    line_reader_query*, const uint8_t* buf, size_t len);

/** Bind a 16-byte UUID value (raw bytes). `value` MUST be non-NULL and point
 *  to at least 16 readable bytes. A NULL `value` aborts the process — silently
 *  binding all-zero bytes would produce a valid-looking
 *  `00000000-0000-0000-0000-000000000000` UUID and corrupt the query. To bind
 *  SQL NULL, call `line_reader_query_bind_null` with
 *  `line_reader_column_kind_uuid` instead. */
LINEREADER_API void line_reader_query_bind_uuid(
    line_reader_query*, const uint8_t value[16]);

/** Bind a 32-byte LONG256 value (raw little-endian bytes). `value` MUST be
 *  non-NULL and point to at least 32 readable bytes. A NULL `value` aborts the
 *  process for the same reason as `line_reader_query_bind_uuid`. To bind SQL
 *  NULL, call `line_reader_query_bind_null` with
 *  `line_reader_column_kind_long256`. */
LINEREADER_API void line_reader_query_bind_long256(
    line_reader_query*, const uint8_t value[32]);

/** Bind an IPv4 address as a host-order `uint32_t`. */
LINEREADER_API void line_reader_query_bind_ipv4(
    line_reader_query*, uint32_t host_order);

/**
 * Bind a DECIMAL128 mantissa as two limbs of the standard two's-complement
 * `int128_t` representation, plus the column's `scale`.
 *
 * `mantissa_lo` is the unsigned low 64 bits; `mantissa_hi` is the signed upper
 * 64 bits. The combined i128 value is
 * `(int128_t)((uint128_t)mantissa_hi << 64) | mantissa_lo`.
 *
 * The high limb is `int64_t` so the sign extends naturally into the i128:
 * e.g. `int128_t = -1` is `(mantissa_lo = UINT64_MAX, mantissa_hi = -1)`.
 * Always pass the high limb as `int64_t` — using `uint64_t` zero-extends
 * and corrupts negative values.
 */
LINEREADER_API void line_reader_query_bind_decimal128(
    line_reader_query*,
    uint64_t mantissa_lo,
    int64_t mantissa_hi,
    int8_t scale);

/** Bind a DECIMAL256 mantissa as 32 little-endian raw bytes plus column scale.
 *  `value` MUST be non-NULL and point to at least 32 readable bytes. A NULL
 *  `value` aborts the process for the same reason as
 *  `line_reader_query_bind_uuid`. To bind SQL NULL, call
 *  `line_reader_query_bind_null_decimal256(query, scale)`. */
LINEREADER_API void line_reader_query_bind_decimal256(
    line_reader_query*,
    const uint8_t value[32],
    int8_t scale);

/**
 * Bind a typed NULL for one of the simple column kinds (numeric, temporal,
 * UUID, etc.). For VARCHAR / BINARY / DECIMAL* / GEOHASH use the
 * dedicated `_null_*` variants below since those carry extra column metadata.
 */
LINEREADER_API void line_reader_query_bind_null(
    line_reader_query*, line_reader_column_kind kind);

/** Bind a SQL NULL of column kind VARCHAR. */
LINEREADER_API void line_reader_query_bind_null_varchar(line_reader_query*);

/** Bind a SQL NULL of column kind BINARY. */
LINEREADER_API void line_reader_query_bind_null_binary(line_reader_query*);

/** Bind a SQL NULL of column kind DECIMAL64 with the given column `scale`. */
LINEREADER_API void line_reader_query_bind_null_decimal64(
    line_reader_query*, int8_t scale);

/** Bind a SQL NULL of column kind DECIMAL128 with the given column `scale`. */
LINEREADER_API void line_reader_query_bind_null_decimal128(
    line_reader_query*, int8_t scale);

/** Bind a SQL NULL of column kind DECIMAL256 with the given column `scale`. */
LINEREADER_API void line_reader_query_bind_null_decimal256(
    line_reader_query*, int8_t scale);

/** Bind a SQL NULL of column kind GEOHASH with the given `precision_bits`. */
LINEREADER_API void line_reader_query_bind_null_geohash(
    line_reader_query*, uint8_t precision_bits);

/**
 * Set the initial CREDIT (in bytes; `0` = unbounded). Mirrors
 * `ReaderQuery::initial_credit`.
 */
LINEREADER_API void line_reader_query_initial_credit(
    line_reader_query*, uint64_t credit);

/**
 * Install a failover-reset callback on the query. Replaces any previously
 * installed callback. `user_data` is opaque to the library; pass NULL if
 * not needed. The callback fires on the thread driving
 * `line_reader_cursor_next_batch`, *before* any replayed batch arrives on
 * a new connection.
 *
 * See `line_reader_failover_callback` for the full reentrancy contract:
 * the callback MUST NOT call back into the originating reader / query /
 * cursor, MUST NOT throw or `longjmp` (an escaping unwind aborts the
 * process), and MUST NOT block — it runs synchronously in the cursor's
 * drive thread and stalls the whole stream while it executes.
 */
LINEREADER_API void line_reader_query_on_failover_reset(
    line_reader_query* query,
    line_reader_failover_callback callback,
    void* user_data);

/////////// Cursor.

/*
 * Opaque cursor handle. Borrows from the originating `line_reader` for its
 * entire lifetime — the reader MUST outlive the cursor. Single-threaded.
 *
 * The `line_reader_cursor` type is forward-declared near the top of this
 * header.
 */

/**
 * Free the cursor and release its resources. Drops any in-flight batch
 * view; if the stream has not reached its terminal (the cursor was
 * abandoned mid-stream), tears down the underlying WebSocket transport
 * (bounded by ~200ms) so the server stops streaming and releases
 * request-scoped state. On a fully-drained cursor the reader's
 * connection is preserved and reused for the next query. No CANCEL
 * frame is sent — the server learns about a mid-stream abort only when
 * the socket goes away. Call `line_reader_cursor_cancel` first if you
 * need a cooperative cancellation handshake before the connection is
 * closed. Idempotent on NULL.
 *
 * Naming note: aligns with `line_reader_query_free` / `line_reader_error_free`
 * (and ingress `line_sender_buffer_free` / `_opts_free`) — the persistent
 * network transport is the reader, freed via `line_reader_close`; every
 * other handle, including this per-query cursor, uses `_free`.
 */
LINEREADER_API
void line_reader_cursor_free(line_reader_cursor* cursor);

/**
 * Advance to the next batch.
 *
 * @return  1 — a new batch is available; column accessors are now valid.
 * @return  0 — the stream has terminated normally; no batch is available.
 * @return -1 — an error occurred; `*err_out` is set and the cursor must be freed.
 */
LINEREADER_API
int line_reader_cursor_next_batch(
    line_reader_cursor* cursor,
    line_reader_error** err_out);

/** Number of rows in the current batch. Returns 0 when no batch is loaded. */
LINEREADER_API
size_t line_reader_cursor_row_count(const line_reader_cursor* cursor);

/** Number of columns in the current batch. Returns 0 when no batch is loaded. */
LINEREADER_API
size_t line_reader_cursor_column_count(const line_reader_cursor* cursor);

/**
 * Get the kind discriminant for a column in the current batch.
 *
 * @param[in] cursor Cursor with a loaded batch.
 * @param[in] col_idx Column index in `[0, column_count)`.
 * @param[out] out_kind Set to the column kind on success.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINEREADER_API
bool line_reader_cursor_column_kind(
    const line_reader_cursor* cursor,
    size_t col_idx,
    line_reader_column_kind* out_kind,
    line_reader_error** err_out);

/**
 * Borrowed UTF-8 column name for the column at `col_idx` in the current
 * batch's schema. The string is NOT null-terminated; use `*out_len`.
 *
 * The pointer is borrowed from the currently-loaded batch and is invalidated
 * by any subsequent call to `line_reader_cursor_next_batch`,
 * `line_reader_cursor_cancel`, or `line_reader_cursor_free` on this cursor.
 * Mid-query failover (transparently triggered by `line_reader_cursor_next_batch`)
 * also invalidates the pointer, because the per-connection schema registry
 * is replaced with the reconnected endpoint's. Re-derive the pointer from
 * `line_reader_cursor_column_name` on every batch — do not cache it.
 *
 * @param[in] cursor Cursor with a loaded batch.
 * @param[in] col_idx Column index in `[0, column_count)`.
 * @param[out] out_buf Set to a pointer to the borrowed bytes on success.
 * @param[out] out_len Set to the byte length on success.
 * @param[out] err_out Set on error.
 * @return true on success, false on error (no batch loaded or
 *         out-of-range index).
 */
LINEREADER_API
bool line_reader_cursor_column_name(
    const line_reader_cursor* cursor,
    size_t col_idx,
    const char** out_buf,
    size_t* out_len,
    line_reader_error** err_out);

/////////// Per-kind getters (vertical-slice subset).
//
// All getters return a (value, is_null) pair for `(col_idx, row_idx)`. They
// fail with `line_reader_error_invalid_api_call` if the column kind doesn't
// match, the cursor has no loaded batch, or the indices are out of range.

/** Read a `BOOLEAN` value. */
LINEREADER_API
bool line_reader_cursor_get_bool(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    bool* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a 64-bit integer value. Accepts `LONG`, `TIMESTAMP` (μs),
 * `DATE` (ms), and `TIMESTAMP_NANOS` (ns) — call
 * `line_reader_cursor_column_kind` to disambiguate units.
 */
LINEREADER_API
bool line_reader_cursor_get_i64(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    int64_t* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/** Read a `DOUBLE` value. */
LINEREADER_API
bool line_reader_cursor_get_f64(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    double* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/** Read a `BYTE` value. */
LINEREADER_API
bool line_reader_cursor_get_i8(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    int8_t* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/** Read a `SHORT` value. */
LINEREADER_API
bool line_reader_cursor_get_i16(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    int16_t* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read an `INT` (signed 32-bit) value. Rejects `IPV4` columns — use
 * `line_reader_cursor_get_ipv4` for those. Reinterpreting an IPv4
 * address through a signed 32-bit getter would silently flip the sign
 * for any address ≥ 128.0.0.0.
 */
LINEREADER_API
bool line_reader_cursor_get_i32(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    int32_t* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read an `IPV4` value as a `uint32_t` packed `(a<<24)|(b<<16)|(c<<8)|d`
 * for `a.b.c.d`. Round-trip safe with `line_reader_query_bind_ipv4`.
 */
LINEREADER_API
bool line_reader_cursor_get_ipv4(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    uint32_t* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/** Read a `FLOAT` value. */
LINEREADER_API
bool line_reader_cursor_get_f32(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    float* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/** Read a `CHAR` value (16-bit UTF-16 code unit, per QuestDB semantics). */
LINEREADER_API
bool line_reader_cursor_get_char(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    uint16_t* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `UUID` value as 16 raw bytes. `out_value` must point to at least
 * 16 writable bytes. On a NULL row, `out_value` is zeroed.
 */
LINEREADER_API
bool line_reader_cursor_get_uuid(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    uint8_t out_value[16],
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `LONG256` value as 32 raw little-endian bytes. `out_value` must
 * point to at least 32 writable bytes. On a NULL row, `out_value` is zeroed.
 */
LINEREADER_API
bool line_reader_cursor_get_long256(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    uint8_t out_value[32],
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `VARCHAR` value as a borrowed UTF-8 byte slice. The returned
 * pointer is valid until the next `line_reader_cursor_next_batch`,
 * `line_reader_cursor_cancel`, or `line_reader_cursor_add_credit` call,
 * or until the cursor is closed. The string is NOT null-terminated.
 * On a NULL row, `*out_buf` is set to NULL.
 */
LINEREADER_API
bool line_reader_cursor_get_varchar(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    const char** out_buf,
    size_t* out_len,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `BINARY` value as a borrowed byte slice. Same lifetime contract
 * as `line_reader_cursor_get_varchar`.
 */
LINEREADER_API
bool line_reader_cursor_get_binary(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    const uint8_t** out_buf,
    size_t* out_len,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `SYMBOL` value as a UTF-8 byte slice resolved through the
 * connection-scoped symbol dictionary. Same lifetime contract as
 * `line_reader_cursor_get_varchar`.
 */
LINEREADER_API
bool line_reader_cursor_get_symbol(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    const char** out_buf,
    size_t* out_len,
    bool* out_is_null,
    line_reader_error** err_out);

/** Read a `DECIMAL64` mantissa plus the column's scale. */
LINEREADER_API
bool line_reader_cursor_get_decimal64(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    int64_t* out_mantissa,
    int8_t* out_scale,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `DECIMAL128` mantissa as two limbs (`uint64_t` low + `int64_t`
 * high) plus column scale. The mantissa is split bit-for-bit: `*out_low`
 * is the low 64 bits, `*out_high` is the upper 64 bits reinterpreted as
 * `int64_t` so the sign of the original i128 is preserved by the C type
 * itself. Reconstruct as
 * `(int128_t)(((uint128_t)(uint64_t)*out_high << 64) | *out_low)` — the
 * cast-through-`uint64_t` avoids sign-extending the high limb a second
 * time during the shift.
 */
LINEREADER_API
bool line_reader_cursor_get_decimal128(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    uint64_t* out_low,
    int64_t* out_high,
    int8_t* out_scale,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `DECIMAL256` mantissa as 32 raw little-endian bytes plus column
 * scale. `out_value` must point to at least 32 writable bytes. On a NULL
 * row, `out_value` is zeroed.
 */
LINEREADER_API
bool line_reader_cursor_get_decimal256(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    uint8_t out_value[32],
    int8_t* out_scale,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `GEOHASH` value zero-extended to a `uint64_t`, plus the column's
 * `precision_bits` (in `1..=60`).
 */
LINEREADER_API
bool line_reader_cursor_get_geohash(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    uint64_t* out_value,
    uint8_t* out_precision_bits,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Borrowed view over a single `DOUBLE_ARRAY` row.
 *
 * All pointers are valid until the next `line_reader_cursor_next_batch`,
 * `line_reader_cursor_cancel`, or `line_reader_cursor_add_credit` call,
 * or until the cursor is closed. `shape` is row-major (innermost
 * dimension last). `data` is concatenated little-endian `double` bytes
 * (`element_count == data_len / 8`).
 *
 * Pointer/length symmetry: `data_len == 0` implies `data == NULL`, and
 * `ndim == 0` implies `shape == NULL` (so a defensive `if (view.data)`
 * check is sound). Both empty cases are unambiguous: a NULL row sets
 * `*out_is_null = true` and zeroes every field; a non-null row whose
 * shape produces zero elements (e.g. `[2, 0, 3]`) leaves `*out_is_null
 * = false` but still writes `data == NULL` and `data_len == 0`.
 */
typedef struct line_reader_double_array_view
{
    const uint32_t* shape;
    size_t ndim;
    const uint8_t* data;
    size_t data_len;
    size_t element_count;
} line_reader_double_array_view;

/**
 * Borrowed view over a single `LONG_ARRAY` row. Same layout, lifetime,
 * and pointer/length symmetry contract as `line_reader_double_array_view`;
 * `data` is concatenated little-endian `int64_t` bytes.
 */
typedef struct line_reader_long_array_view
{
    const uint32_t* shape;
    size_t ndim;
    const uint8_t* data;
    size_t data_len;
    size_t element_count;
} line_reader_long_array_view;

/**
 * Read a `DOUBLE_ARRAY` row into a borrowed view. On a NULL row, all
 * `out_view` fields are zeroed and `*out_is_null` is set to true.
 */
LINEREADER_API
bool line_reader_cursor_get_double_array(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    line_reader_double_array_view* out_view,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a single `double` element at flat row-major index `flat_idx` of a
 * `DOUBLE_ARRAY` row.
 *
 * On a NULL row sets `*out_is_null` to true, zeroes `*out_value`, and
 * returns true. On a non-null row in range writes `*out_value`, sets
 * `*out_is_null` to false, and returns true. Returns false and sets
 * `*err_out` only on real errors (type mismatch, out-of-range row, or
 * out-of-range `flat_idx`) — NULL rows are not treated as errors.
 */
LINEREADER_API
bool line_reader_cursor_get_double_array_element(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    size_t flat_idx,
    double* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a `LONG_ARRAY` row into a borrowed view.
 */
LINEREADER_API
bool line_reader_cursor_get_long_array(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    line_reader_long_array_view* out_view,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Read a single `int64_t` element of a `LONG_ARRAY` row.
 *
 * On a NULL row sets `*out_is_null` to true, zeroes `*out_value`, and
 * returns true. On a non-null row in range writes `*out_value`, sets
 * `*out_is_null` to false, and returns true. Returns false and sets
 * `*err_out` only on real errors (type mismatch, out-of-range row, or
 * out-of-range `flat_idx`) — NULL rows are not treated as errors.
 */
LINEREADER_API
bool line_reader_cursor_get_long_array_element(
    const line_reader_cursor* cursor,
    size_t col_idx,
    size_t row_idx,
    size_t flat_idx,
    int64_t* out_value,
    bool* out_is_null,
    line_reader_error** err_out);

/**
 * Borrow the raw LSB-first validity bitmap (bit `1` = null) for a column.
 * On a column with no nulls, `*out_buf` is set to NULL and `*out_len` to 0.
 * Otherwise the pointer is valid until the next `line_reader_cursor_next_batch`,
 * `line_reader_cursor_cancel`, or `line_reader_cursor_add_credit` call, or
 * until the cursor is closed.
 */
LINEREADER_API
bool line_reader_cursor_column_validity(
    const line_reader_cursor* cursor,
    size_t col_idx,
    const uint8_t** out_buf,
    size_t* out_len,
    line_reader_error** err_out);

/////////// Cursor introspection and lifecycle.

/** The cursor's `request_id` (refreshed on failover). */
LINEREADER_API int64_t line_reader_cursor_request_id(const line_reader_cursor*);

/** Bytes of CREDIT this cursor has granted via the underlying reader. */
LINEREADER_API uint64_t line_reader_cursor_credit_granted_total(
    const line_reader_cursor*);

/** Number of failover resets observed by this cursor since `execute()`. */
LINEREADER_API uint32_t line_reader_cursor_failover_resets(
    const line_reader_cursor*);

/** Host of the endpoint the cursor is currently connected to (borrowed). */
LINEREADER_API void line_reader_cursor_current_addr_host(
    const line_reader_cursor*, const char** out_buf, size_t* out_len);

/** Port of the endpoint the cursor is currently connected to. */
LINEREADER_API uint16_t line_reader_cursor_current_addr_port(
    const line_reader_cursor*);

/**
 * `request_id` from the most recently decoded batch's frame header (the
 * batch header's request_id may differ from the cursor's after failover
 * for already-buffered frames). Returns true and writes `*out_request_id`
 * if a batch is currently loaded; otherwise returns false and zeroes the
 * output.
 */
LINEREADER_API bool line_reader_cursor_batch_request_id(
    const line_reader_cursor* cursor,
    int64_t* out_request_id);

/**
 * `batch_seq` of the current batch (0-based, monotonically increasing within
 * a single cursor lifecycle). Returns true and writes `*out_batch_seq` if a
 * batch is currently loaded; otherwise returns false and zeroes the output.
 */
LINEREADER_API bool line_reader_cursor_batch_seq(
    const line_reader_cursor* cursor,
    uint64_t* out_batch_seq);

/**
 * Per-batch wire flags. Returns true and writes `*out_flags` if a batch is
 * currently loaded; otherwise returns false and zeroes the output.
 */
LINEREADER_API bool line_reader_cursor_batch_flags(
    const line_reader_cursor* cursor,
    uint8_t* out_flags);

/** Discriminant of the cursor's terminal frame. */
typedef enum line_reader_terminal_kind
{
    line_reader_terminal_kind_none      = 0,
    line_reader_terminal_kind_end       = 1,
    line_reader_terminal_kind_exec_done = 2,
} line_reader_terminal_kind;

LINEREADER_API line_reader_terminal_kind line_reader_cursor_terminal_kind(
    const line_reader_cursor*);

/**
 * If the terminal is `RESULT_END`, fill the output parameters and return
 * true; otherwise zeroes both outputs and returns false.
 */
LINEREADER_API bool line_reader_cursor_terminal_end(
    const line_reader_cursor* cursor,
    uint64_t* out_final_seq,
    uint64_t* out_total_rows);

/**
 * If the terminal is `EXEC_DONE`, fill the output parameters and return
 * true; otherwise zeroes both outputs and returns false.
 */
LINEREADER_API bool line_reader_cursor_terminal_exec_done(
    const line_reader_cursor* cursor,
    uint8_t* out_op_type,
    uint64_t* out_rows_affected);

/**
 * Send a CANCEL frame and drain the stream until the server's terminal
 * reply. Idempotent once terminal. Returns false and sets `*err_out` on
 * transport failure.
 */
LINEREADER_API bool line_reader_cursor_cancel(
    line_reader_cursor* cursor,
    line_reader_error** err_out);

/**
 * Grant additional CREDIT to the server. Only valid when the cursor was
 * started with `initial_credit > 0`.
 */
LINEREADER_API bool line_reader_cursor_add_credit(
    line_reader_cursor* cursor,
    uint64_t additional_bytes,
    line_reader_error** err_out);

#ifdef __cplusplus
}
#endif
