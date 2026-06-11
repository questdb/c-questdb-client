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
#include <string.h>

/* Reuse `line_sender_utf8` for validated UTF-8 strings, and the
   `QUESTDB_CLIENT_API` / `QUESTDB_CLIENT_DYN_LIB` linkage macros. */
#include "../ingress/line_sender.h"

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
// one-thread-at-a-time rule. They additionally reject (error / NULL / 0,
// see each function) while a `line_reader_query` or `line_reader_cursor`
// produced by the reader is still live: the reader's connection state is
// borrowed by that query/cursor. Either release it before reading
// metadata, or read the same metadata through the cursor handle
// (`line_reader_cursor_server_version`, `line_reader_cursor_current_server_info`,
// `line_reader_cursor_current_addr_host` / `_port`).

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
     *  (before the QUERY_REQUEST hits the wire). Covers timestamp /
     *  decimal / geohash range failures too — every reachable
     *  client-side validation flows through bind encoding. */
    line_reader_error_invalid_bind = 11,
    /* Values 12 and 13 are intentionally reserved (formerly
     * `invalid_timestamp` / `invalid_decimal`, removed before
     * release because no egress path ever emitted them). Do not
     * reuse without ABI co-ordination — Cython / external consumers
     * may have cached the prior numbering. */
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
    /** Mid-query failover was eligible but at least one batch had
     *  already been delivered to the caller and no
     *  `on_failover_reset` callback was installed; replay would
     *  silently double-deliver rows already consumed, so the cursor
     *  was terminated instead. Install a failover-reset callback via
     *  `line_reader_query_on_failover_reset` (and discard partial
     *  state on each invocation) to opt in to replays, or re-execute
     *  the query from scratch when this code surfaces. Initial-
     *  connect failover (before any batch is yielded) is unaffected
     *  and remains transparent. */
    line_reader_error_failover_would_duplicate = 21,
} line_reader_error_code;

/**
 * Error code categorising the error.
 * NULL-safe: returns `line_reader_error_invalid_api_call` for a NULL input.
 */
QUESTDB_CLIENT_API
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
QUESTDB_CLIENT_API
const char* line_reader_error_msg(const line_reader_error*, size_t* len_out);

/** Free the error returned via an `err_out` parameter. Idempotent on NULL. */
QUESTDB_CLIENT_API
void line_reader_error_free(line_reader_error*);

/////////// Column kinds.

/**
 * Column kind discriminant. Numeric values match the QWP wire codes.
 * Returned in `line_reader_column_data.kind` /
 * `line_reader_array_data.kind` and by `line_reader_batch_column_kind`.
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
    /** Sentinel for column kinds the running FFI build doesn't
     *  recognise. Emitted when the upstream Rust crate adds a new
     *  `ColumnKind` variant the C ABI hasn't been recompiled against
     *  yet. Treat as opaque: skip / log / surface to ops rather than
     *  route on it. */
    line_reader_column_kind_unknown         = 0xFF,
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
 * API (e.g. `"ws::addr=localhost:9000;"`). On success returns a non-NULL handle
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
QUESTDB_CLIENT_API
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
QUESTDB_CLIENT_API
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
QUESTDB_CLIENT_API
void line_reader_close(line_reader* reader);

/**
 * Peek at the reader's active-query flag.
 *
 * Returns `1` when a `line_reader_query` or `line_reader_cursor` produced
 * by this reader is still live (i.e. `line_reader_close` would refuse to
 * free and leak the reader instead), `0` otherwise. Returns `0` for a
 * NULL handle.
 *
 * Intended for higher-level language bindings that want to surface
 * "close while a query/cursor is live" as a programmable error before it
 * silently triggers the leak-on-active branch in `line_reader_close`.
 */
QUESTDB_CLIENT_API
uint8_t line_reader_has_active_query(const line_reader* reader);

/////////// Reader stats and connection info.

/** Cumulative bytes received from the wire (header + payload). */
QUESTDB_CLIENT_API uint64_t line_reader_bytes_received(const line_reader*);

/** Cumulative CREDIT bytes granted to the server across this reader. */
QUESTDB_CLIENT_API uint64_t
line_reader_credit_granted_total(const line_reader*);

/** Cumulative wall-clock nanoseconds spent in `read` calls (saturating). */
QUESTDB_CLIENT_API uint64_t line_reader_read_ns(const line_reader*);

/** Cumulative wall-clock nanoseconds spent decoding (saturating). */
QUESTDB_CLIENT_API uint64_t line_reader_decode_ns(const line_reader*);

/** Reset the cumulative `read_ns` / `decode_ns` counters to zero. */
QUESTDB_CLIENT_API void line_reader_reset_timing(line_reader*);

/**
 * Get the negotiated QWP server version.
 *
 * Returns `false` and sets `*err_out` on failure: the connection is not
 * established yet (no `SERVER_INFO` received), the `reader` handle is
 * NULL, or a `line_reader_query` / `line_reader_cursor` produced by this
 * reader is still live — all surfaced as
 * `line_reader_error_invalid_api_call`. On success returns `true` and
 * writes the version to `*out_version`.
 */
QUESTDB_CLIENT_API
bool line_reader_server_version(
    const line_reader* reader,
    uint8_t* out_version,
    line_reader_error** err_out);

/**
 * Borrow the current endpoint host as a UTF-8 byte slice. The pointer is
 * invalidated by any reader operation that may reconnect.
 *
 * Writes an empty `(NULL, 0)` pair for a NULL handle, and also while a
 * `line_reader_query` / `line_reader_cursor` produced by this reader is
 * still live (release it first to read connection metadata).
 */
QUESTDB_CLIENT_API
void line_reader_current_addr_host(
    const line_reader* reader,
    const char** out_buf,
    size_t* out_len);

/**
 * Port of the endpoint the reader is currently connected to.
 *
 * Returns `0` for a NULL handle, and also `0` while a `line_reader_query`
 * / `line_reader_cursor` produced by this reader is still live (release it
 * first to read connection metadata).
 */
QUESTDB_CLIENT_API
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
 *
 * Also returns NULL while a `line_reader_query` / `line_reader_cursor`
 * produced by this reader is still live (release it first to read
 * connection metadata).
 */
QUESTDB_CLIENT_API
const line_reader_server_info* line_reader_current_server_info(const line_reader* reader);

/** Cluster role advertised by `SERVER_INFO`. */
QUESTDB_CLIENT_API line_reader_server_role
line_reader_server_info_role(const line_reader_server_info*);

/** Raw role byte (useful when role() returns OTHER). */
QUESTDB_CLIENT_API uint8_t
line_reader_server_info_role_byte(const line_reader_server_info*);

/** Monotonic generation counter advertised by the server. Increases on
 *  failover/role transitions; useful for fencing replayed batches. */
QUESTDB_CLIENT_API uint64_t
line_reader_server_info_epoch(const line_reader_server_info*);

/** Bitset of QWP capability flags negotiated with the server. */
QUESTDB_CLIENT_API uint32_t
line_reader_server_info_capabilities(const line_reader_server_info*);

/** Server's wall-clock time at handshake, in nanoseconds since the Unix
 *  epoch. Useful for skew detection. */
QUESTDB_CLIENT_API int64_t
line_reader_server_info_server_wall_ns(const line_reader_server_info*);

/** Cluster identifier as a UTF-8 byte slice. The buffer is borrowed and
 *  invalidated by any reader operation that may reconnect. */
QUESTDB_CLIENT_API void line_reader_server_info_cluster_id(
    const line_reader_server_info*, const char** out_buf, size_t* out_len);

/** Node identifier as a UTF-8 byte slice. Same lifetime contract as
 *  `_cluster_id`. */
QUESTDB_CLIENT_API void line_reader_server_info_node_id(
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
QUESTDB_CLIENT_API void line_reader_failover_event_failed_host(
    const line_reader_failover_event*, const char** out_buf, size_t* out_len);
/** Port of the previously-connected endpoint that failed. */
QUESTDB_CLIENT_API uint16_t
line_reader_failover_event_failed_port(const line_reader_failover_event*);
/** Host of the new endpoint the cursor is reconnecting to. UTF-8 byte slice
 *  borrowed for the duration of the callback. */
QUESTDB_CLIENT_API void line_reader_failover_event_new_host(
    const line_reader_failover_event*, const char** out_buf, size_t* out_len);
/** Port of the new endpoint the cursor is reconnecting to. */
QUESTDB_CLIENT_API uint16_t
line_reader_failover_event_new_port(const line_reader_failover_event*);
/** Request_id reissued on the new connection (the original request_id is
 *  invalidated by the failover; the cursor's request_id is updated). */
QUESTDB_CLIENT_API int64_t
line_reader_failover_event_new_request_id(const line_reader_failover_event*);
/** Number of reconnect attempts that preceded this success (1 on the first
 *  retry, etc.). */
QUESTDB_CLIENT_API uint32_t
line_reader_failover_event_attempts(const line_reader_failover_event*);
/** Wall-clock nanoseconds spent reconnecting — sleep + dial + handshake +
 *  `SERVER_INFO` read. Saturating. */
QUESTDB_CLIENT_API uint64_t
line_reader_failover_event_elapsed_ns(const line_reader_failover_event*);
/** Error code that triggered the failover (cause-of-death of the previous
 *  connection). */
QUESTDB_CLIENT_API line_reader_error_code
line_reader_failover_event_trigger_code(const line_reader_failover_event*);
/** Trigger error message (UTF-8). Borrowed for the duration of the call. */
QUESTDB_CLIENT_API void line_reader_failover_event_trigger_msg(
    const line_reader_failover_event*, const char** out_buf, size_t* out_len);
/** `SERVER_INFO` for the new endpoint, or NULL on v1 servers. */
QUESTDB_CLIENT_API const line_reader_server_info*
line_reader_failover_event_server_info(const line_reader_failover_event*);

/////////// Failover progress callback.

/**
 * Phase discriminant on `line_reader_failover_progress_event`. The
 * same callback fires for every phase of a mid-query failover
 * lifecycle — operators can route on the phase to feed SLO dashboards
 * ("unreachable for N seconds" alerts), per-attempt retry telemetry,
 * or a one-shot "gave up" notifier.
 *
 * Discriminants are explicit and append-only across releases —
 * inserting a new phase in the middle would silently renumber later
 * ones across recompiles, breaking ABI for shared-library consumers.
 */
typedef enum line_reader_failover_phase
{
    /** The cursor's connection just died. Fires once, BEFORE the retry
     *  loop runs, so observers see the outage "now" rather than
     *  retroactively when reconnect lands. */
    line_reader_failover_phase_disconnected = 0,
    /** A reconnect dial is about to be attempted. Fires once per
     *  outer-loop iteration of the retry walk, AFTER the inter-attempt
     *  backoff sleep, so `_elapsed_ns` already includes the backoff
     *  wall-clock cost. */
    line_reader_failover_phase_retrying = 1,
    /** A reconnect succeeded; replayed batches will start arriving on
     *  the new connection. Fires immediately BEFORE the
     *  `line_reader_failover_callback` registered via
     *  `line_reader_query_on_failover_reset` (when both are installed)
     *  so a single sink sees the entire lifecycle in order. */
    line_reader_failover_phase_reset = 2,
    /** The retry budget is exhausted. The cursor is terminal; the
     *  error returned to the caller is available via
     *  `line_reader_failover_progress_event_final_error_*`. */
    line_reader_failover_phase_gave_up = 3,
    /** Sentinel for phases the running FFI build doesn't recognise.
     *  Emitted when the upstream Rust crate adds a new
     *  `FailoverPhase` variant the C ABI hasn't been recompiled
     *  against yet. Treat as opaque: skip / log / surface to ops
     *  rather than route on it. */
    line_reader_failover_phase_unknown = 0xFF,
} line_reader_failover_phase;

/**
 * Opaque borrowed handle to a failover-progress event. The pointer
 * passed to your callback is valid only for the duration of that
 * callback invocation.
 */
typedef struct line_reader_failover_progress_event line_reader_failover_progress_event;

/**
 * User callback fired at every phase of a mid-query failover
 * lifecycle. The `event` pointer is valid only for the duration of
 * the call.
 *
 * Reentrancy contract — identical to `line_reader_failover_callback`.
 * The callback MUST NOT:
 *
 *  - Call any function on the originating `line_reader`, the
 *    `line_reader_query` it produced, or the `line_reader_cursor`
 *    whose operation is in flight. The trampoline runs synchronously
 *    inside `line_reader_cursor_next_batch` (or `_cursor_cancel` /
 *    `_cursor_add_credit`) while the upstream code is mid-mutation of
 *    the underlying `Reader` and `Cursor`. Any reentrant FFI call
 *    would alias the in-flight `&mut Reader` and corrupt internal
 *    state — this is undefined behaviour. Read-only stat getters are
 *    NOT safe from inside the callback for the same aliasing reason.
 *
 *  - Throw a C++ exception, `longjmp`, or otherwise unwind out of the
 *    callback. The trampoline wraps the user callback in
 *    `catch_unwind` and `abort()`s the process if an unwind escapes.
 *
 *  - Block indefinitely or perform long-running work. The callback
 *    runs synchronously on the thread driving the in-flight cursor
 *    operation; while it is executing, no batch is being read, no
 *    CREDIT is being granted to the server, and the failover loop
 *    cannot make progress. Keep the callback bounded — clear an
 *    accumulator, set a flag, signal a condition variable — and do
 *    any heavy work outside the cursor's drive thread.
 *
 * The callback runs on the thread driving the in-flight cursor
 * operation.
 */
typedef void (*line_reader_failover_progress_callback)(
    const line_reader_failover_progress_event* event,
    void* user_data);

/** Phase of this event. NULL-safe: returns
 *  `line_reader_failover_phase_disconnected` for a NULL handle. */
QUESTDB_CLIENT_API line_reader_failover_phase
line_reader_failover_progress_event_phase(
    const line_reader_failover_progress_event*);

/** Host of the endpoint that died. UTF-8 byte slice borrowed for the
 *  duration of the callback. Set on every phase. */
QUESTDB_CLIENT_API void line_reader_failover_progress_event_failed_host(
    const line_reader_failover_progress_event*,
    const char** out_buf,
    size_t* out_len);

/** Port of the endpoint that died. Set on every phase. */
QUESTDB_CLIENT_API uint16_t line_reader_failover_progress_event_failed_port(
    const line_reader_failover_progress_event*);

/** Host of the new endpoint (Reset phase only). UTF-8 byte slice
 *  borrowed for the duration of the callback. Writes `(NULL, 0)` in
 *  every other phase. */
QUESTDB_CLIENT_API void line_reader_failover_progress_event_new_host(
    const line_reader_failover_progress_event*,
    const char** out_buf,
    size_t* out_len);

/** Port of the new endpoint (Reset phase only). Returns `0` in every
 *  other phase. */
QUESTDB_CLIENT_API uint16_t line_reader_failover_progress_event_new_port(
    const line_reader_failover_progress_event*);

/** New `request_id` (Reset phase only). Returns `true` and writes the
 *  id to `*out_request_id` on Reset; returns `false` and writes `0` in
 *  every other phase. */
QUESTDB_CLIENT_API bool line_reader_failover_progress_event_new_request_id(
    const line_reader_failover_progress_event*,
    int64_t* out_request_id);

/** 1-based attempt counter:
 *  - `0` on Disconnected (no attempt yet).
 *  - `N >= 1` on Retrying for the Nth dial.
 *  - On Reset, the attempt that landed.
 *  - On GaveUp, the total number of attempts burned. May be `0` when
 *    the wall-clock deadline was already exhausted before any dial. */
QUESTDB_CLIENT_API uint32_t line_reader_failover_progress_event_attempt(
    const line_reader_failover_progress_event*);

/** Error code that triggered the failover (the original cause-of-
 *  death). Preserved across every phase so subscribers see consistent
 *  context regardless of when they latch on. */
QUESTDB_CLIENT_API line_reader_error_code
line_reader_failover_progress_event_trigger_code(
    const line_reader_failover_progress_event*);

/** Trigger error message (UTF-8). Borrowed for the duration of the
 *  callback. */
QUESTDB_CLIENT_API void line_reader_failover_progress_event_trigger_msg(
    const line_reader_failover_progress_event*,
    const char** out_buf,
    size_t* out_len);

/** Wall-clock nanoseconds since the disconnect was observed (the
 *  start of the failover cycle). Monotonically non-decreasing across
 *  phases of the same event. Saturating. */
QUESTDB_CLIENT_API uint64_t line_reader_failover_progress_event_elapsed_ns(
    const line_reader_failover_progress_event*);

/** `SERVER_INFO` for the new endpoint, or NULL outside the Reset
 *  phase / on v1 servers. */
QUESTDB_CLIENT_API const line_reader_server_info*
line_reader_failover_progress_event_server_info(
    const line_reader_failover_progress_event*);

/** Final error code (GaveUp phase only). Returns `true` and writes
 *  the code to `*out_code` on GaveUp; returns `false` and writes
 *  `line_reader_error_invalid_api_call` in every other phase. The
 *  code matches what the cursor's next `_next_batch` / `_add_credit`
 *  call will surface. */
QUESTDB_CLIENT_API bool line_reader_failover_progress_event_final_error_code(
    const line_reader_failover_progress_event*,
    line_reader_error_code* out_code);

/** Final error message (GaveUp phase only). Returns `true` and writes
 *  the borrowed UTF-8 message on GaveUp; returns `false` and writes
 *  `(NULL, 0)` in every other phase. */
QUESTDB_CLIENT_API bool line_reader_failover_progress_event_final_error_msg(
    const line_reader_failover_progress_event*,
    const char** out_buf,
    size_t* out_len);

/////////// Query builder.

/**
 * Opaque query builder. Created by `line_reader_prepare`, consumed by
 * `line_reader_query_execute` (which produces a cursor) or released by
 * `line_reader_query_free`. The originating reader MUST outlive the query.
 *
 * The verb is "prepare" across all three language surfaces: Rust
 * `Reader::prepare`, C `line_reader_prepare`, C++ `reader::prepare`.
 * The noun (builder type) is "query" — `ReaderQuery`,
 * `line_reader_query`, and `query` respectively.
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
QUESTDB_CLIENT_API
line_reader_query* line_reader_prepare(
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
QUESTDB_CLIENT_API
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
QUESTDB_CLIENT_API
line_reader_cursor* line_reader_query_execute(
    line_reader_query** query_inout,
    line_reader_error** err_out);

/**
 * Convenience: prepare + execute in one call, for SQL with no binds.
 * Equivalent to `line_reader_prepare` followed immediately by
 * `line_reader_query_execute`; no query handle is exposed to the
 * caller. The originating reader MUST outlive the returned cursor.
 *
 * Returns NULL and sets `*err_out` if `reader` is NULL, `sql` carries
 * invalid UTF-8 (`line_reader_error_invalid_utf8`), another query or
 * cursor is already in flight on this reader
 * (`line_reader_error_invalid_api_call`), or the server rejects the
 * statement.
 */
QUESTDB_CLIENT_API
line_reader_cursor* line_reader_execute(
    line_reader* reader,
    line_sender_utf8 sql,
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
QUESTDB_CLIENT_API void line_reader_query_bind_bool(line_reader_query*, bool v);

/** Bind a BYTE (signed 8-bit) positional parameter. */
QUESTDB_CLIENT_API void line_reader_query_bind_i8(line_reader_query*, int8_t v);

/** Bind a SHORT (signed 16-bit) positional parameter. */
QUESTDB_CLIENT_API void line_reader_query_bind_i16(
    line_reader_query*, int16_t v);

/** Bind an INT (signed 32-bit) positional parameter. */
QUESTDB_CLIENT_API void line_reader_query_bind_i32(
    line_reader_query*, int32_t v);

/** Bind a LONG (signed 64-bit) positional parameter. */
QUESTDB_CLIENT_API void line_reader_query_bind_i64(
    line_reader_query*, int64_t v);

/** Bind a FLOAT (32-bit IEEE-754) positional parameter. */
QUESTDB_CLIENT_API void line_reader_query_bind_f32(line_reader_query*, float v);

/** Bind a DOUBLE (64-bit IEEE-754) positional parameter. */
QUESTDB_CLIENT_API void line_reader_query_bind_f64(
    line_reader_query*, double v);

/** Bind a TIMESTAMP positional parameter as microseconds since the Unix epoch. */
QUESTDB_CLIENT_API void line_reader_query_bind_timestamp_micros(
    line_reader_query*, int64_t v);

/** Bind a TIMESTAMP_NANOS positional parameter as nanoseconds since the Unix epoch. */
QUESTDB_CLIENT_API void line_reader_query_bind_timestamp_nanos(
    line_reader_query*, int64_t v);

/** Bind a DATE positional parameter as milliseconds since the Unix epoch. */
QUESTDB_CLIENT_API void line_reader_query_bind_date_millis(
    line_reader_query*, int64_t v);

/** Bind a CHAR positional parameter as a UTF-16 code unit. */
QUESTDB_CLIENT_API void line_reader_query_bind_char(
    line_reader_query*, uint16_t v);

/** Bind a DECIMAL64 positional parameter: signed 64-bit mantissa `v` and
 *  column `scale` (number of fractional digits). The decimal value is
 *  `v * 10^(-scale)`. */
QUESTDB_CLIENT_API void line_reader_query_bind_decimal64(
    line_reader_query*, int64_t v, int8_t scale);

/** Bind a GEOHASH positional parameter. `v` is the bit-packed geohash payload
 *  (LSB-aligned); `precision_bits` is the number of significant bits
 *  (1–60 inclusive, per the QuestDB type system). */
QUESTDB_CLIENT_API void line_reader_query_bind_geohash(
    line_reader_query*, uint64_t v, uint8_t precision_bits);

/** Bind a UTF-8 VARCHAR value. The bytes are copied.
 *
 *  The `v` payload is re-validated as UTF-8 on entry. This function returns
 *  void, so an invalid-UTF-8 contract violation is stored on the query and
 *  surfaced from `line_reader_query_execute` as
 *  `line_reader_error_invalid_utf8` (first-error-wins; later binds and the
 *  builder state are not touched once a deferred error is set). */
QUESTDB_CLIENT_API void line_reader_query_bind_varchar(
    line_reader_query*, line_sender_utf8 v);

/** Bind a BINARY value. The bytes are copied. `buf` may be NULL when
 *  `len == 0` (binds an empty byte slice). For any non-zero `len`, `buf`
 *  must be non-NULL and point to at least `len` readable bytes — a NULL
 *  `buf` with non-zero `len` stores a deferred
 *  `line_reader_error_invalid_bind` on the query that surfaces from
 *  `line_reader_query_execute`, matching the policy of
 *  `line_reader_query_bind_uuid`.
 *
 *  Not supported by Phase 1 servers: the call records the value, but
 *  `line_reader_query_execute` will fail with
 *  `line_reader_error_invalid_bind` because the server has no decoder
 *  for the BINARY wire type. Listed in the public ABI for
 *  forward-compatibility — when the server adds support, no client
 *  change is needed. */
QUESTDB_CLIENT_API void line_reader_query_bind_binary(
    line_reader_query*, const uint8_t* buf, size_t len);

/** Bind a 16-byte UUID value (raw bytes). `value` MUST be non-NULL and point
 *  to at least 16 readable bytes. A NULL `value` stores a deferred
 *  `line_reader_error_invalid_bind` on the query that surfaces from
 *  `line_reader_query_execute` — silently binding all-zero bytes would
 *  produce a valid-looking `00000000-0000-0000-0000-000000000000` UUID and
 *  corrupt the query. To bind SQL NULL, call `line_reader_query_bind_null`
 *  with `line_reader_column_kind_uuid` instead. */
QUESTDB_CLIENT_API void line_reader_query_bind_uuid(
    line_reader_query*, const uint8_t value[16]);

/** Bind a 32-byte LONG256 value (raw little-endian bytes). `value` MUST be
 *  non-NULL and point to at least 32 readable bytes. A NULL `value` stores
 *  a deferred `line_reader_error_invalid_bind` on the query that surfaces
 *  from `line_reader_query_execute`, for the same reason as
 *  `line_reader_query_bind_uuid`. To bind SQL NULL, call
 *  `line_reader_query_bind_null` with `line_reader_column_kind_long256`. */
QUESTDB_CLIENT_API void line_reader_query_bind_long256(
    line_reader_query*, const uint8_t value[32]);

/** Bind an IPv4 address as a host-order `uint32_t`.
 *
 *  Not supported by Phase 1 servers: the call records the value, but
 *  `line_reader_query_execute` will fail with
 *  `line_reader_error_invalid_bind` because the server has no decoder
 *  for the IPv4 wire type. Listed in the public ABI for
 *  forward-compatibility — when the server adds support, no client
 *  change is needed. */
QUESTDB_CLIENT_API void line_reader_query_bind_ipv4(
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
QUESTDB_CLIENT_API void line_reader_query_bind_decimal128(
    line_reader_query*,
    uint64_t mantissa_lo,
    int64_t mantissa_hi,
    int8_t scale);

/** Bind a DECIMAL256 mantissa as 32 little-endian raw bytes plus column scale.
 *  `value` MUST be non-NULL and point to at least 32 readable bytes. A NULL
 *  `value` stores a deferred `line_reader_error_invalid_bind` on the query
 *  that surfaces from `line_reader_query_execute`, for the same reason as
 *  `line_reader_query_bind_uuid`. To bind SQL NULL, call
 *  `line_reader_query_bind_null_decimal256(query, scale)`. */
QUESTDB_CLIENT_API void line_reader_query_bind_decimal256(
    line_reader_query*, const uint8_t value[32], int8_t scale);

/**
 * Bind a typed NULL for one of the simple column kinds (numeric, temporal,
 * UUID, etc.). For VARCHAR / BINARY / DECIMAL* / GEOHASH use the
 * dedicated `_null_*` variants below since those carry extra column metadata.
 *
 * `kind` is a `line_reader_column_kind` discriminant passed as a raw
 * `uint32_t` (typed-enum constants implicitly convert). The integer ABI
 * keeps the FFI boundary sound when a caller hands across a value outside
 * the declared discriminants — out-of-range values surface as a deferred
 * `line_reader_error_invalid_bind` on `line_reader_query_execute` rather
 * than triggering undefined behaviour.
 *
 * Phase 1 servers don't accept all in-range kinds. Passing
 * `line_reader_column_kind_ipv4` is accepted by this call but
 * `line_reader_query_execute` will fail with
 * `line_reader_error_invalid_bind` — see `line_reader_query_bind_ipv4`.
 * The IPv4 discriminant stays in the public ABI for
 * forward-compatibility.
 */
QUESTDB_CLIENT_API void line_reader_query_bind_null(
    line_reader_query*, uint32_t kind);

/** Bind a SQL NULL of column kind VARCHAR. */
QUESTDB_CLIENT_API void line_reader_query_bind_null_varchar(line_reader_query*);

/** Bind a SQL NULL of column kind BINARY.
 *
 *  Not supported by Phase 1 servers — see
 *  `line_reader_query_bind_binary` for the rationale. The call records
 *  the null, but `line_reader_query_execute` will fail with
 *  `line_reader_error_invalid_bind`. */
QUESTDB_CLIENT_API void line_reader_query_bind_null_binary(line_reader_query*);

/** Bind a SQL NULL of column kind DECIMAL64 with the given column `scale`. */
QUESTDB_CLIENT_API void line_reader_query_bind_null_decimal64(
    line_reader_query*, int8_t scale);

/** Bind a SQL NULL of column kind DECIMAL128 with the given column `scale`. */
QUESTDB_CLIENT_API void line_reader_query_bind_null_decimal128(
    line_reader_query*, int8_t scale);

/** Bind a SQL NULL of column kind DECIMAL256 with the given column `scale`. */
QUESTDB_CLIENT_API void line_reader_query_bind_null_decimal256(
    line_reader_query*, int8_t scale);

/** Bind a SQL NULL of column kind GEOHASH with the given `precision_bits`. */
QUESTDB_CLIENT_API void line_reader_query_bind_null_geohash(
    line_reader_query*, uint8_t precision_bits);

/**
 * Set the initial CREDIT (in bytes; `0` = unbounded). Mirrors
 * `ReaderQuery::initial_credit`.
 */
QUESTDB_CLIENT_API void line_reader_query_initial_credit(
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
QUESTDB_CLIENT_API void line_reader_query_on_failover_reset(
    line_reader_query* query,
    line_reader_failover_callback callback,
    void* user_data);

/**
 * Install a failover-progress callback on the query. Replaces any
 * previously installed progress callback. `user_data` is opaque to
 * the library; pass NULL if not needed. The callback fires at every
 * phase of a mid-query failover lifecycle — see
 * `line_reader_failover_phase`.
 *
 * Installing this callback also opts the cursor in to "I will handle
 * replay-after-data-delivered correctly," the same way
 * `line_reader_query_on_failover_reset` does — either being installed
 * clears the silent-duplicate guard documented on
 * `line_reader_cursor_next_batch`. If you only want telemetry and not
 * replay semantics, set `failover=off` instead.
 *
 * See `line_reader_failover_progress_callback` for the full
 * reentrancy contract: the callback MUST NOT call back into the
 * originating reader / query / cursor, MUST NOT throw or `longjmp`
 * (an escaping unwind aborts the process), and MUST NOT block — it
 * runs synchronously in the cursor's drive thread and stalls the
 * whole failover loop while it executes.
 */
QUESTDB_CLIENT_API void line_reader_query_on_failover_progress(
    line_reader_query* query,
    line_reader_failover_progress_callback callback,
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
 * abandoned mid-stream), sends a best-effort CANCEL frame (bounded by
 * the WS write timeout, errors swallowed) and then tears down the
 * underlying WebSocket transport (bounded by ~200ms) so the server
 * promptly stops streaming and releases request-scoped state. On a
 * fully-drained cursor the reader's connection is preserved and reused
 * for the next query and no CANCEL is sent. Call
 * `line_reader_cursor_cancel` first if you need a synchronous
 * cancellation that surfaces errors and drains pending frames before
 * the connection is closed. Idempotent on NULL.
 *
 * Naming note: aligns with `line_reader_query_free` / `line_reader_error_free`
 * (and ingress `line_sender_buffer_free` / `_opts_free`) — the persistent
 * network transport is the reader, freed via `line_reader_close`; every
 * other handle, including this per-query cursor, uses `_free`.
 */
QUESTDB_CLIENT_API
void line_reader_cursor_free(line_reader_cursor* cursor);

/////////// Batch and column access.
//
// `line_reader_batch` is a borrowed handle for the cursor's
// currently-loaded batch. The columnar entry point: a caller projects a
// whole column into a contiguous descriptor with a single FFI call, then
// indexes the dense buffer by row. For casual single-cell reads, the
// inline helpers in `line_reader_helpers.h` package the index + validity
// probe + typed load over a filled descriptor.
//
// Lifetime: the handle and every pointer reachable through its descriptors
// borrow from the batch. They are invalidated by the next
// `line_reader_cursor_next_batch`, `line_reader_cursor_cancel`,
// `line_reader_cursor_add_credit`, or `line_reader_cursor_free` on the
// owning cursor, and by mid-query failover (transparently triggered by
// `line_reader_cursor_next_batch` or `line_reader_cursor_add_credit`). Do
// not cache them across batches; re-derive after every `next_batch`. The
// handle is never freed by the caller.

/** Opaque handle for the batch currently loaded in a cursor. */
typedef struct line_reader_batch line_reader_batch;

/**
 * Advance to the next batch.
 *
 * @return Non-NULL borrowed batch handle on a new batch. The pointer is
 *         invalidated by the next `line_reader_cursor_next_batch`,
 *         `line_reader_cursor_cancel`, `line_reader_cursor_add_credit`,
 *         `line_reader_cursor_free`, or mid-query failover.
 * @return NULL with `*err_out` left untouched when the stream has
 *         terminated normally — no batch is available.
 * @return NULL with `*err_out` set on error; the cursor must be freed.
 */
QUESTDB_CLIENT_API
const line_reader_batch* line_reader_cursor_next_batch(
    line_reader_cursor* cursor,
    line_reader_error** err_out);

/** Rows in the batch. Returns 0 on a NULL handle. */
QUESTDB_CLIENT_API
size_t line_reader_batch_row_count(const line_reader_batch* batch);

/** Columns in the batch. Returns 0 on a NULL handle. */
QUESTDB_CLIENT_API
size_t line_reader_batch_column_count(const line_reader_batch* batch);

/** `request_id` echoed from the originating QUERY_REQUEST. 0 on a NULL handle.
 */
QUESTDB_CLIENT_API
int64_t line_reader_batch_request_id(const line_reader_batch* batch);

/** Monotonic per-request batch sequence number. 0 on a NULL handle. */
QUESTDB_CLIENT_API
uint64_t line_reader_batch_seq(const line_reader_batch* batch);

/** Per-batch wire flags from the frame header. 0 on a NULL handle. */
QUESTDB_CLIENT_API
uint8_t line_reader_batch_flags(const line_reader_batch* batch);

/**
 * Kind discriminant for the column at `col_idx`.
 *
 * @param[in] batch Batch handle.
 * @param[in] col_idx Column index in `[0, column_count)`.
 * @param[out] out_kind Set to the column kind on success.
 * @param[out] err_out Set on error.
 * @return true on success, false on a NULL handle / out-param or an
 *         out-of-range index.
 */
QUESTDB_CLIENT_API
bool line_reader_batch_column_kind(
    const line_reader_batch* batch,
    size_t col_idx,
    line_reader_column_kind* out_kind,
    line_reader_error** err_out);

/**
 * Borrowed UTF-8 column name for `col_idx`. NOT null-terminated; use
 * `*out_len`. Borrowed from the batch — see the section-level lifetime note.
 *
 * @return true on success, false on a NULL handle / out-param or an
 *         out-of-range index.
 */
QUESTDB_CLIENT_API
bool line_reader_batch_column_name(
    const line_reader_batch* batch,
    size_t col_idx,
    const char** out_buf,
    size_t* out_len,
    line_reader_error** err_out);

/**
 * Bulk descriptor for one scalar / variable-width column. Every pointer
 * borrows from the batch (see the section-level lifetime note).
 *
 * `values` holds the wire's little-endian bytes — the decoder does not
 * byte-swap. A fixed-width slot whose `validity` bit is set still contains
 * a value (QuestDB's NULL sentinel); consult `validity` first.
 */
typedef struct line_reader_column_data
{
    /** Wire kind of the column. */
    line_reader_column_kind kind;
    /** Rows in the batch (equals `line_reader_batch_row_count`). */
    size_t row_count;
    /** LSB-first null bitmap, `ceil(row_count / 8)` bytes; bit 1 = NULL.
        NULL when the column carries no nulls. */
    const uint8_t* validity;
    /** Dense little-endian values, `row_count * value_stride` bytes.
        NULL for variable-width kinds (VARCHAR / BINARY / SYMBOL). */
    const void* values;
    /** Bytes per fixed-width value; 0 for variable-width kinds. */
    size_t value_stride;
    /** VARCHAR / BINARY offset table, `row_count + 1` entries; value `r`
        spans `[var_offsets[r], var_offsets[r + 1])`. NULL for other kinds. */
    const uint32_t* var_offsets;
    /** VARCHAR / BINARY concatenated data blob. NULL for other kinds. */
    const uint8_t* var_data;
    size_t var_data_len;
    /** SYMBOL per-row dictionary codes, `row_count` entries; resolve with
        `line_reader_batch_symbol`. NULL for other kinds. */
    const uint32_t* symbol_codes;
    /** DECIMAL64/128/256 shared scale; 0 otherwise. */
    int8_t decimal_scale;
    /** GEOHASH precision in bits (1..60); 0 otherwise. */
    uint8_t geohash_precision_bits;
} line_reader_column_data;

/**
 * Project a scalar / variable-width column at `col_idx` into `*out`.
 *
 * @return true on success, false on a NULL handle / out-param, an
 *         out-of-range index, or an array column — use
 *         `line_reader_batch_array_column_data` for those.
 */
QUESTDB_CLIENT_API
bool line_reader_batch_column_data(
    const line_reader_batch* batch,
    size_t col_idx,
    line_reader_column_data* out,
    line_reader_error** err_out);

/**
 * Bulk descriptor for a `DOUBLE_ARRAY` column. Four-buffer ragged layout
 * — each row's array may have a different shape. Every pointer borrows
 * from the batch.
 *
 * Element-level NULLs inside an array are `NaN`; there is no per-element
 * bitmap.
 */
typedef struct line_reader_array_data
{
    /** Always `line_reader_column_kind_double_array` in this revision. */
    line_reader_column_kind kind;
    size_t row_count;
    /** Row-level null bitmap (the whole array cell is NULL),
        `ceil(row_count / 8)` bytes. NULL if no row is a null array.
        Distinct from a non-null empty array (zero-length / rank 0). */
    const uint8_t* validity;
    /** Flattened row-major little-endian `double` element bytes for every
        row; 8 bytes per element. Row `r` spans
        `[data_offsets[r], data_offsets[r + 1])`. */
    const uint8_t* data;
    size_t data_len;
    /** Per-row byte offsets into `data`, `row_count + 1` entries. */
    const uint32_t* data_offsets;
    /** Concatenated per-row shapes; row `r`'s shape is
        `shapes[shape_offsets[r] .. shape_offsets[r + 1])` — that slice's
        length is the array rank, each entry one dimension length. */
    const uint32_t* shapes;
    size_t shapes_len;
    /** Per-row offsets into `shapes`, `row_count + 1` entries. */
    const uint32_t* shape_offsets;
} line_reader_array_data;

/**
 * Project a `DOUBLE_ARRAY` column at `col_idx` into `*out`.
 *
 * @return true on success, false on a NULL handle / out-param, an
 *         out-of-range index, or a non-DOUBLE_ARRAY column.
 */
QUESTDB_CLIENT_API
bool line_reader_batch_array_column_data(
    const line_reader_batch* batch,
    size_t col_idx,
    line_reader_array_data* out,
    line_reader_error** err_out);

/** One symbol-dictionary entry: a byte range into
 * `line_reader_symbol_dict.heap`. */
typedef struct line_reader_symbol_entry
{
    uint32_t offset;
    uint32_t length;
} line_reader_symbol_entry;

/**
 * Snapshot of the connection-scoped symbol dictionary, shared by every
 * SYMBOL column in the batch. Code `i` (a `symbol_codes` entry) resolves to
 * `heap[entries[i].offset .. entries[i].offset + entries[i].length]`.
 * Borrowed from the batch.
 */
typedef struct line_reader_symbol_dict
{
    /** Entry count; an entry's index is its dictionary code. */
    size_t entry_count;
    /** Concatenated UTF-8 bytes for every entry. */
    const uint8_t* heap;
    size_t heap_len;
    /** `entry_count` entries addressing `heap`. */
    const line_reader_symbol_entry* entries;
} line_reader_symbol_dict;

/**
 * Resolve a SYMBOL dictionary `code` to its borrowed, non-null-terminated
 * UTF-8 bytes. Convenience for scalar use; for bulk (categorical)
 * construction use `line_reader_batch_symbol_dict`.
 *
 * @return true on success, false on a NULL handle / out-param, a non-SYMBOL
 *         column, or a code outside the dictionary.
 */
QUESTDB_CLIENT_API
bool line_reader_batch_symbol(
    const line_reader_batch* batch,
    size_t col_idx,
    uint32_t code,
    const char** out_buf,
    size_t* out_len,
    line_reader_error** err_out);

/**
 * Snapshot the connection-scoped symbol dictionary into `*out`.
 *
 * @return true on success, false on a NULL handle / out-param.
 */
QUESTDB_CLIENT_API
bool line_reader_batch_symbol_dict(
    const line_reader_batch* batch,
    line_reader_symbol_dict* out,
    line_reader_error** err_out);

/////////// Cursor introspection and lifecycle.

/** The cursor's `request_id` (refreshed on failover). */
QUESTDB_CLIENT_API int64_t
line_reader_cursor_request_id(const line_reader_cursor*);

/**
 * Bytes of CREDIT this cursor has granted via the underlying reader.
 *
 * Single-thread only: bound by the cursor's one-thread-at-a-time
 * contract. Cross-thread monitoring (e.g. a stats dashboard polling
 * from a separate thread) must use `line_reader_credit_granted_total`
 * on the reader handle instead — it reads the same connection-level
 * counter via an atomic and is explicitly cross-thread safe.
 */
QUESTDB_CLIENT_API uint64_t
line_reader_cursor_credit_granted_total(const line_reader_cursor*);

/** Number of failover resets observed by this cursor since `execute()`. */
QUESTDB_CLIENT_API uint32_t
line_reader_cursor_failover_resets(const line_reader_cursor*);

/** Host of the endpoint the cursor is currently connected to (borrowed). */
QUESTDB_CLIENT_API void line_reader_cursor_current_addr_host(
    const line_reader_cursor*, const char** out_buf, size_t* out_len);

/** Port of the endpoint the cursor is currently connected to. */
QUESTDB_CLIENT_API uint16_t
line_reader_cursor_current_addr_port(const line_reader_cursor*);

/**
 * Negotiated QWP version of the cursor's underlying connection. The
 * in-cursor counterpart to `line_reader_server_version` (which rejects
 * while a cursor is live).
 *
 * Returns `false` and sets `*err_out` on failure: the cursor handle is
 * NULL, or the underlying connection is poisoned after a failed mid-query
 * failover. On success returns `true` and writes `*out_version`.
 */
QUESTDB_CLIENT_API bool line_reader_cursor_server_version(
    const line_reader_cursor* cursor,
    uint8_t* out_version,
    line_reader_error** err_out);

/**
 * Last-seen `SERVER_INFO` of the cursor's currently connected endpoint, or
 * NULL on v1 servers. The pointer is invalidated by any cursor operation
 * that may reconnect. The in-cursor counterpart to
 * `line_reader_current_server_info` (which rejects while a cursor is live).
 */
QUESTDB_CLIENT_API const line_reader_server_info*
line_reader_cursor_current_server_info(const line_reader_cursor* cursor);

/** Discriminant of the cursor's terminal frame. */
typedef enum line_reader_terminal_kind
{
    line_reader_terminal_kind_none      = 0,
    line_reader_terminal_kind_end       = 1,
    line_reader_terminal_kind_exec_done = 2,
} line_reader_terminal_kind;

QUESTDB_CLIENT_API line_reader_terminal_kind
line_reader_cursor_terminal_kind(const line_reader_cursor*);

/**
 * If the terminal is `RESULT_END`, fill the output parameters and return
 * true; otherwise zeroes both outputs and returns false.
 */
QUESTDB_CLIENT_API bool line_reader_cursor_terminal_end(
    const line_reader_cursor* cursor,
    uint64_t* out_final_seq,
    uint64_t* out_total_rows);

/**
 * If the terminal is `EXEC_DONE`, fill the output parameters and return
 * true; otherwise zeroes both outputs and returns false.
 */
QUESTDB_CLIENT_API bool line_reader_cursor_terminal_exec_done(
    const line_reader_cursor* cursor,
    uint8_t* out_op_type,
    uint64_t* out_rows_affected);

/**
 * Send a CANCEL frame and drain the stream until the server's terminal
 * reply. Idempotent once terminal. Returns false and sets `*err_out` on
 * transport failure.
 */
QUESTDB_CLIENT_API bool line_reader_cursor_cancel(
    line_reader_cursor* cursor, line_reader_error** err_out);

/**
 * Grant additional CREDIT to the server. Only valid when the cursor was
 * started with `initial_credit > 0`. Invalidates the current batch handle
 * and every pointer borrowed from it, and may transparently trigger
 * mid-query failover when the CREDIT write hits a transport failure.
 */
QUESTDB_CLIENT_API bool line_reader_cursor_add_credit(
    line_reader_cursor* cursor,
    uint64_t additional_bytes,
    line_reader_error** err_out);

/* =========================================================================
 * Inline single-cell read helpers for `line_reader_column_data`.
 *
 * The egress C ABI is bulk-only at the symbol level: every reader call
 * fills a `line_reader_column_data` descriptor (one FFI crossing per
 * column), and the caller indexes its dense buffer to read individual
 * rows.
 *
 * This header is the opt-in convenience layer for the opposite pattern:
 * a casual C caller that wants to read one cell with one line of code
 * instead of three (row index + validity-bitmap probe + typed
 * little-endian load).
 *
 *     // Without these helpers (verbose AND undefined behaviour):
 *     const int64_t v = ((const int64_t*)d.values)[row];
 *     const bool   is_null =
 *         d.validity && ((d.validity[row >> 3] >> (row & 7)) & 1);
 *
 *     // With them:
 *     bool is_null;
 *     int64_t v = line_reader_column_data_get_i64(&d, row, &is_null);
 *
 * The "without" form is not only verbose — it is unsafe. `d.values` may
 * not be aligned to `alignof(int64_t)`: densified column slices borrow
 * from the wire payload at offsets that don't satisfy `T`'s alignment,
 * and forming `((const T*)d.values)[row]` is undefined behaviour on
 * strict-alignment targets. The helpers' `memcpy` is the safe
 * equivalent (and the compiler lowers it to a single unaligned MOV
 * at `-O1+`, so zero performance cost).
 *
 * All helpers are `static inline` — no new exported symbols, no added
 * ABI surface.
 *
 * Scope:
 *   - Covered: every fixed-width scalar (BOOLEAN..DOUBLE, TIMESTAMP /
 *     TIMESTAMP_NS / DATE, IPv4, CHAR, UUID, LONG256, DECIMAL64 / 128,
 *     GEOHASH), plus VARCHAR / BINARY and SYMBOL.
 *   - Not covered: `DOUBLE_ARRAY`. Arrays use a separate descriptor
 *     (`line_reader_array_data`) populated by
 *     `line_reader_batch_array_column_data`.
 *
 * Convention:
 *   Every `_get_<type>` helper writes `*out_is_null` separately from
 *   the typed return. On a NULL row:
 *     - scalar helpers (`_get_i8` .. `_get_f64`, `_get_bool`,
 *       `_get_char`, `_get_ipv4`, `_get_geohash`,
 *       `_get_decimal64_mantissa`) return zero.
 *     - `_get_bytes` zero-fills the caller-supplied buffer.
 *     - `_get_decimal128` writes `0` to both limbs.
 *     - `_get_varlen` and `_get_symbol` set `*out_buf = NULL` and
 *       `*out_len = 0`.
 *   In every case `*out_is_null` is `true`. Always branch on
 *   `out_is_null`; a literal `0` or empty slice is a valid value, not
 *   a NULL marker.
 *
 * Preconditions (every helper unless its own doc says otherwise):
 *   - `d` is a non-NULL, fully-filled descriptor from a successful
 *     `line_reader_batch_column_data` against the CURRENT batch.
 *   - `row < d->row_count`. The helpers DO NOT bounds-check; reading
 *     past `row_count` reads past the validity bitmap and values buffer.
 *   - `_get_symbol` additionally takes a `line_reader_symbol_dict*` —
 *     it MUST be the snapshot from the SAME batch as `d`. A stale dict
 *     from a previous batch silently resolves codes against the wrong
 *     heap.
 *
 * Lifetime:
 *   Every pointer or byte slice reachable through `d`, the dict, and
 *   the `_get_varlen` / `_get_symbol` out-params borrows from the
 *   current batch. They are invalidated by the next
 *   `line_reader_cursor_next_batch`, `line_reader_cursor_cancel`, or
 *   `line_reader_cursor_free`. Copy out anything you need to keep.
 *
 * Idiom — scan one column:
 *
 *     line_reader_column_data d;
 *     if (!line_reader_batch_column_data(batch, col, &d, &err))
 *         goto on_error;
 *     for (size_t row = 0; row < d.row_count; ++row) {
 *         bool is_null;
 *         int64_t v = line_reader_column_data_get_i64(&d, row, &is_null);
 *         if (is_null) { ... }     // SQL NULL
 *         else         { use(v); } // real value
 *     }
 *
 * Idiom — SYMBOL column:
 *
 *     line_reader_symbol_dict dict;
 *     if (!line_reader_batch_symbol_dict(batch, &dict, &err))
 *         goto on_error;
 *     for (size_t row = 0; row < d.row_count; ++row) {
 *         const char* buf;
 *         size_t      len;
 *         bool        is_null;
 *         line_reader_column_data_get_symbol(
 *             &d, &dict, row, &buf, &len, &is_null);
 *         if (is_null) { ... }
 *         else         { use_utf8(buf, len); }
 *     }
 * ========================================================================= */

static inline bool line_reader_column_data_is_null(
    const line_reader_column_data* d, size_t row)
{
    return d->validity != NULL && ((d->validity[row >> 3] >> (row & 7)) & 1);
}

static inline bool line_reader_column_data_get_bool(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return false;
    /* BOOLEAN is dense-1-byte-per-row on the C side (FFI decoder writes
     * `value_stride == 1` for ColumnView::Boolean); honour the stride so
     * the helper stays robust if the descriptor representation ever
     * changes. */
    return ((const uint8_t*)d->values)[row * d->value_stride] != 0;
}

static inline int8_t line_reader_column_data_get_i8(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    return *out_is_null ? 0 : ((const int8_t*)d->values)[row];
}

static inline int16_t line_reader_column_data_get_i16(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    int16_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 2, sizeof(v));
    return v;
}

static inline uint16_t line_reader_column_data_get_char(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    uint16_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 2, sizeof(v));
    return v;
}

static inline int32_t line_reader_column_data_get_i32(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    int32_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 4, sizeof(v));
    return v;
}

static inline uint32_t line_reader_column_data_get_ipv4(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    uint32_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 4, sizeof(v));
    return v;
}

static inline float line_reader_column_data_get_f32(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0.0f;
    float v;
    memcpy(&v, (const uint8_t*)d->values + row * 4, sizeof(v));
    return v;
}

static inline int64_t line_reader_column_data_get_i64(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    int64_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 8, sizeof(v));
    return v;
}

static inline double line_reader_column_data_get_f64(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0.0;
    double v;
    memcpy(&v, (const uint8_t*)d->values + row * 8, sizeof(v));
    return v;
}

/* UUID / LONG256: copy `value_stride` bytes (16 or 32) into out. */
static inline void line_reader_column_data_get_bytes(
    const line_reader_column_data* d,
    size_t row,
    uint8_t* out,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        memset(out, 0, d->value_stride);
        return;
    }
    memcpy(
        out,
        (const uint8_t*)d->values + row * d->value_stride,
        d->value_stride);
}

/* DECIMAL64: returns the mantissa; scale is on `d->decimal_scale`. */
static inline int64_t line_reader_column_data_get_decimal64_mantissa(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    return line_reader_column_data_get_i64(d, row, out_is_null);
}

/* DECIMAL128: split as (low u64, high i64); scale on `d->decimal_scale`. */
static inline void line_reader_column_data_get_decimal128(
    const line_reader_column_data* d,
    size_t row,
    uint64_t* out_low,
    int64_t* out_high,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        *out_low = 0;
        *out_high = 0;
        return;
    }
    const uint8_t* p = (const uint8_t*)d->values + row * 16;
    memcpy(out_low, p, 8);
    memcpy(out_high, p + 8, 8);
}

/* GEOHASH: returns the value zero-extended into a u64. */
static inline uint64_t line_reader_column_data_get_geohash(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    uint64_t v = 0;
    memcpy(
        &v, (const uint8_t*)d->values + row * d->value_stride, d->value_stride);
    return v;
}

/* VARCHAR / BINARY: per-row borrowed slice into `d->var_data`. NULL row
 * yields `*out_buf == NULL && *out_len == 0`. */
static inline void line_reader_column_data_get_varlen(
    const line_reader_column_data* d,
    size_t row,
    const uint8_t** out_buf,
    size_t* out_len,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        *out_buf = NULL;
        *out_len = 0;
        return;
    }
    const uint32_t s = d->var_offsets[row];
    const uint32_t e = d->var_offsets[row + 1];
    *out_buf = d->var_data + s;
    *out_len = (size_t)(e - s);
}

/* SYMBOL: resolve the row's dictionary code into a borrowed UTF-8 slice
 * over the supplied dict snapshot. Returns false on a code out of range
 * (corrupt batch) — caller's responsibility to surface as an error. */
static inline bool line_reader_column_data_get_symbol(
    const line_reader_column_data* d,
    const line_reader_symbol_dict* dict,
    size_t row,
    const char** out_buf,
    size_t* out_len,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        *out_buf = NULL;
        *out_len = 0;
        return true;
    }
    const uint32_t code = d->symbol_codes[row];
    if (code >= dict->entry_count)
    {
        *out_buf = NULL;
        *out_len = 0;
        return false;
    }
    const line_reader_symbol_entry e = dict->entries[code];
    *out_buf = (const char*)dict->heap + e.offset;
    *out_len = (size_t)e.length;
    return true;
}

#ifdef __cplusplus
}
#endif
