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

/* `LINESENDER_DYN_LIB` is the historical name of this toggle, from when the
   library shipped only the line sender. Accepted as an alias so consumers
   predating the `QUESTDB_CLIENT_*` naming keep linking unchanged. */
#if defined(LINESENDER_DYN_LIB) && !defined(QUESTDB_CLIENT_DYN_LIB)
#    define QUESTDB_CLIENT_DYN_LIB
#endif

#if defined(QUESTDB_CLIENT_DYN_LIB) && defined(_MSC_VER)
#    define QUESTDB_CLIENT_API __declspec(dllimport)
#else
#    define QUESTDB_CLIENT_API
#endif

/* `LINESENDER_API` is the historical name of this export attribute,
   kept as an alias for one major-version cycle so downstream wrappers
   that reference the old macro continue to build. New code should use
   `QUESTDB_CLIENT_API`; this alias will be removed in the next major
   release. */
#ifndef LINESENDER_API
#    define LINESENDER_API QUESTDB_CLIENT_API
#endif

/////////// Pointer argument conventions.
/**
 * Unless a function's documentation states otherwise, every pointer
 * parameter must be non-NULL. Passing NULL where non-NULL is required
 * is undefined behaviour and will typically crash the process. This
 * applies to opaque handle types in particular — `line_sender*`,
 * `line_sender_buffer*`, `line_sender_opts*`, `line_sender_error*`,
 * `line_sender_qwpws_error*` — and is not re-asserted on each
 * function. The library does not insert defensive NULL checks for
 * opaque handles; treat them like `this` in C++.
 *
 * Two narrow exceptions:
 *
 *   - `err_out` (the trailing `line_sender_error**` on fallible
 *     functions) is always optional: pass NULL to discard error
 *     information on failure.
 *
 *   - `line_sender_close()` and `line_sender_buffer_free()` accept
 *     NULL and silently no-op, mirroring `free(3)`.
 */

/////////// Error handling.
/** An error that occurred when using the line sender. */
typedef struct line_sender_error line_sender_error;

/** Category of error.
 *
 * Append-only: reordering or inserting in the middle breaks ABI. */
typedef enum line_sender_error_code
{
    /** The host, port, or interface was incorrect. */
    line_sender_error_could_not_resolve_addr = 0,

    /** Called methods in the wrong order. E.g. `symbol` after `column`. */
    line_sender_error_invalid_api_call = 1,

    /** A network error connecting or flushing data out. */
    line_sender_error_socket_error = 2,

    /** The string or symbol field is not encoded in valid UTF-8. */
    line_sender_error_invalid_utf8 = 3,

    /** The table name or column name contains bad characters. */
    line_sender_error_invalid_name = 4,

    /** The supplied timestamp is invalid. */
    line_sender_error_invalid_timestamp = 5,

    /** Error during the authentication process. */
    line_sender_error_auth_error = 6,

    /** Error during TLS handshake. */
    line_sender_error_tls_error = 7,

    /** The server does not support ILP over HTTP. */
    line_sender_error_http_not_supported = 8,

    /** Error sent back from the server during flush. */
    line_sender_error_server_flush_error = 9,

    /** Bad configuration. */
    line_sender_error_config_error = 10,

    /** There was an error serializing an array. */
    line_sender_error_array_error = 11,

    /**  Line sender protocol version error. */
    line_sender_error_protocol_version_error = 12,

    /** The supplied decimal is invalid. */
    line_sender_error_invalid_decimal = 13,

    /** QWP/WebSocket server rejection or terminal protocol violation. */
    line_sender_error_server_rejection = 14,

    /** Arrow column whose kind cannot be persisted (e.g.
     *  `FixedSizeBinary(16)` without `arrow.uuid` extension metadata;
     *  `ARRAY(LONG, N-D)` is egress-only; nested-list leaf must be
     *  `Float64`). `arrow` feature only. */
    line_sender_error_arrow_unsupported_column_kind = 15,

    /** RecordBatch failed client-side structural validation
     *  (column count, name encoding, C Data Interface contract).
     *  `arrow` feature only. */
    line_sender_error_arrow_ingest = 16,

    /** Reconnectable failure on the QWP sender's flush/sync
     *  path (transport error, EOF, closed connection). The operation
     *  has not committed: drop the connection with `questdb_db_drop_sender`,
     *  re-acquire one with `questdb_db_borrow_sender_with_retry` (shared
     *  reconnect backoff, bounded by `reconnect_max_duration`), and re-drive
     *  from your source. */
    line_sender_error_failover_retry = 17,

    /** Every reachable endpoint handshook but none matched the configured
     *  `target=` role filter (e.g. `target=primary` against an all-replica
     *  address list). Distinct from `line_sender_error_socket_error`
     *  ("all endpoints unreachable") so callers can tell "no primary
     *  elected" from "all down". */
    line_sender_error_role_mismatch = 18,
    /** The TCP connect (dial) to the server exceeded the configured
     *  `connect_timeout`. Distinct from `line_sender_error_socket_error` so a
     *  caller can tell a timed-out dial apart from a refused / reset
     *  connection. Produced by the QWP/WebSocket transport. */
    line_sender_error_connect_timeout = 19,

    /* Query / reader (egress) categories. The error model is unified across
     * ingest and query: these are emitted by the reader. Appended at 20..34
     * so the ingress discriminants 0..19 stay frozen. */

    /** HTTP-upgrade or WebSocket handshake failure. */
    line_sender_error_handshake_error = 20,

    /** Server returned an unsupported QWP version, encoding, or capability. */
    line_sender_error_unsupported_server = 21,

    /** Wire-format violation: bad magic, truncated frame, unknown
     *  discriminant, invalid varint, symbol-dict reference miss, etc. */
    line_sender_error_protocol_error = 22,

    /** Bind parameter index, count, or value rejected client-side (covers
     *  timestamp / decimal / geohash range failures on the query path too). */
    line_sender_error_invalid_bind = 23,

    /** Server-reported QWP `SCHEMA_MISMATCH` (status `0x03`). */
    line_sender_error_server_schema_mismatch = 24,

    /** Server-reported QWP `PARSE_ERROR` (status `0x05`). */
    line_sender_error_server_parse_error = 25,

    /** Server-reported QWP `INTERNAL_ERROR` (status `0x06`). */
    line_sender_error_server_internal_error = 26,

    /** Server-reported QWP `SECURITY_ERROR` (status `0x08`). */
    line_sender_error_server_security_error = 27,

    /** Client-side limit hit (e.g. an array row exceeds the configured cap). */
    line_sender_error_limit_exceeded = 28,

    /** Server-reported QWP `LIMIT_EXCEEDED` (status `0x0B`). */
    line_sender_error_server_limit_exceeded = 29,

    /** Query was cancelled (locally or via server `CANCELLED` status `0x0A`). */
    line_sender_error_cancelled = 30,

    /** Mid-query failover was eligible but a batch had already been delivered
     *  and no `on_failover_reset` callback was installed; the cursor
     *  terminated rather than silently double-deliver rows. */
    line_sender_error_failover_would_duplicate = 31,

    /** Streaming Arrow adapter saw a mid-stream schema change. `arrow`
     *  feature only. */
    line_sender_error_schema_drift = 32,

    /** A streaming Arrow adapter was asked for a schema on a stream that
     *  ended before any batch was produced. `arrow` feature only. */
    line_sender_error_no_schema = 33,

    /** Arrow C Data Interface export failed. `arrow` feature only. */
    line_sender_error_arrow_export = 34,

    /** An irreducible QWP/WebSocket unit (the table schema plus a single row
     *  block) exceeds the negotiated per-batch cap. Chunk publication splits
     *  oversize inputs into smaller frames automatically, so this only surfaces
     *  when splitting cannot make a frame fit. Distinct from
     *  `line_sender_error_invalid_api_call` so callers can recognise it without
     *  matching on the error message text. */
    line_sender_error_batch_too_large = 35,

    /** The QWP/WebSocket store-and-forward persisted symbol dictionary is
     *  unrecoverable (a host/power crash tore the `.symbol-dict` side-file
     *  relative to the queued frames), so the queued frames cannot be replayed
     *  and the affected rows must be re-ingested from their source. Terminal.
     *  Distinct from `line_sender_error_socket_error` (a transient, retryable
     *  socket drop) so a caller can tell "resend from source" apart from
     *  "reconnect and retry" by code, without matching on the message text. */
    line_sender_error_store_resend_required = 36,
} line_sender_error_code;

/**
 * Client-wide error object and category.
 *
 * These are the neutral spellings used by APIs that span ingest and query.
 * They alias the released `line_sender_error` ABI so existing line-sender
 * binaries and source keep working unchanged.
 */
typedef line_sender_error questdb_error;
typedef line_sender_error_code questdb_error_code;

/* Neutral names for the unified error-code constants. The underlying
 * `line_sender_error_code` enum and its enumerators are retained because they
 * shipped before the client-wide error vocabulary was introduced. */
#define questdb_error_could_not_resolve_addr line_sender_error_could_not_resolve_addr
#define questdb_error_invalid_api_call line_sender_error_invalid_api_call
#define questdb_error_socket_error line_sender_error_socket_error
#define questdb_error_invalid_utf8 line_sender_error_invalid_utf8
#define questdb_error_invalid_name line_sender_error_invalid_name
#define questdb_error_invalid_timestamp line_sender_error_invalid_timestamp
#define questdb_error_auth_error line_sender_error_auth_error
#define questdb_error_tls_error line_sender_error_tls_error
#define questdb_error_http_not_supported line_sender_error_http_not_supported
#define questdb_error_server_flush_error line_sender_error_server_flush_error
#define questdb_error_config_error line_sender_error_config_error
#define questdb_error_array_error line_sender_error_array_error
#define questdb_error_protocol_version_error line_sender_error_protocol_version_error
#define questdb_error_invalid_decimal line_sender_error_invalid_decimal
#define questdb_error_server_rejection line_sender_error_server_rejection
#define questdb_error_arrow_unsupported_column_kind line_sender_error_arrow_unsupported_column_kind
#define questdb_error_arrow_ingest line_sender_error_arrow_ingest
#define questdb_error_failover_retry line_sender_error_failover_retry
#define questdb_error_role_mismatch line_sender_error_role_mismatch
#define questdb_error_connect_timeout line_sender_error_connect_timeout
#define questdb_error_handshake_error line_sender_error_handshake_error
#define questdb_error_unsupported_server line_sender_error_unsupported_server
#define questdb_error_protocol_error line_sender_error_protocol_error
#define questdb_error_invalid_bind line_sender_error_invalid_bind
#define questdb_error_server_schema_mismatch line_sender_error_server_schema_mismatch
#define questdb_error_server_parse_error line_sender_error_server_parse_error
#define questdb_error_server_internal_error line_sender_error_server_internal_error
#define questdb_error_server_security_error line_sender_error_server_security_error
#define questdb_error_limit_exceeded line_sender_error_limit_exceeded
#define questdb_error_server_limit_exceeded line_sender_error_server_limit_exceeded
#define questdb_error_cancelled line_sender_error_cancelled
#define questdb_error_failover_would_duplicate line_sender_error_failover_would_duplicate
#define questdb_error_schema_drift line_sender_error_schema_drift
#define questdb_error_no_schema line_sender_error_no_schema
#define questdb_error_arrow_export line_sender_error_arrow_export
#define questdb_error_batch_too_large line_sender_error_batch_too_large
#define questdb_error_store_resend_required line_sender_error_store_resend_required

/** The protocol used to connect with. */
typedef enum line_sender_protocol
{
    /** InfluxDB Line Protocol over TCP. */
    line_sender_protocol_tcp,

    /** InfluxDB Line Protocol over TCP with TLS. */
    line_sender_protocol_tcps,

    /** InfluxDB Line Protocol over HTTP. */
    line_sender_protocol_http,

    /** InfluxDB Line Protocol over HTTP with TLS. */
    line_sender_protocol_https,

    /** QuestWire Protocol over UDP (IPv4-only). */
    line_sender_protocol_udp,

    /** QuestWire Protocol over WebSocket. */
    line_sender_protocol_ws,

    /** QuestWire Protocol over WebSocket Secure (TLS). */
    line_sender_protocol_wss,

    /**
     * Sentinel for a protocol the Rust `Protocol` enum knows about but
     * this FFI build does not. Returned by `line_sender_get_protocol`
     * for future `Protocol` variants added after this FFI was compiled.
     * Passing this value to `line_sender_opts_new` /
     * `line_sender_opts_new_service` causes them to return NULL.
     */
    line_sender_protocol_unknown,
} line_sender_protocol;

/** The line protocol version used to write data to buffer. */
typedef enum line_sender_protocol_version
{
    /**
     * Version 1 of InfluxDB Line Protocol.
     * This version is compatible with the InfluxDB database.
     */
    line_sender_protocol_version_1 = 1,

    /**
     * Version 2 of InfluxDB Line Protocol.
     * Uses a binary format serialization for f64, and supports
     * the array data type.
     * This version is specific to QuestDB and not compatible with InfluxDB.
     * QuestDB server version 9.0.0 or later is required for
     * `line_sender_protocol_version_2` support.
     */
    line_sender_protocol_version_2 = 2,

    /**
     * Version 3 of InfluxDB Line Protocol.
     * Supports the decimal data type in text and binary formats.
     * This version is specific to QuestDB and not compatible with InfluxDB.
     * QuestDB server version 9.2.0 or later is required for
     * `line_sender_protocol_version_3` support.
     */
    line_sender_protocol_version_3 = 3,
} line_sender_protocol_version;

/** Possible sources of the root certificates used to validate the server's
 * TLS certificate. */
typedef enum line_sender_ca
{
    /** Use the set of root certificates provided by the `webpki` crate. */
    line_sender_ca_webpki_roots,

    /** Use the set of root certificates provided by the operating system.
     */
    line_sender_ca_os_roots,

    /** Combine the set of root certificates provided by the `webpki` crate
     * and the operating system. */
    line_sender_ca_webpki_and_os_roots,

    /** Use the root certificates provided in a PEM-encoded file. */
    line_sender_ca_pem_file,
} line_sender_ca;

/** Error code categorizing a client-wide error. NULL-safe: a NULL input
 *  returns `questdb_error_invalid_api_call`. */
QUESTDB_CLIENT_API
questdb_error_code questdb_error_get_code(const questdb_error*);

/**
 * UTF-8 encoded client-wide error message. Never returns NULL. The returned
 * string is not null-terminated; `len_out` receives its byte length.
 * NULL-safe on both arguments: a NULL error returns an empty string and writes
 * zero when `len_out` is non-NULL; a NULL `len_out` is ignored.
 */
QUESTDB_CLIENT_API
const char* questdb_error_msg(const questdb_error*, size_t* len_out);

/** Whether the failed operation may already have delivered its input. A true
 *  result means replay can duplicate data unless the application has its own
 *  deduplication guarantee. NULL-safe: a NULL input returns false. */
QUESTDB_CLIENT_API
bool questdb_error_in_doubt(const questdb_error*);

/** Clean up a client-wide error. Idempotent on NULL. */
QUESTDB_CLIENT_API
void questdb_error_free(questdb_error*);

/** Error code categorizing a line-sender error. */
QUESTDB_CLIENT_API
line_sender_error_code line_sender_error_get_code(const line_sender_error*);

/**
 * UTF-8 encoded error message. Never returns NULL.
 * The `len_out` argument is set to the number of bytes in the string.
 * The string is NOT null-terminated.
 */
QUESTDB_CLIENT_API
const char* line_sender_error_msg(const line_sender_error*, size_t* len_out);

/**
 * Whether the failed operation is *delivery-unknown* ("in doubt"): the current
 * input's bytes may already have reached the server even though the call
 * returned an error (e.g. a socket write that failed mid-frame, or a
 * post-publish ACK wait that failed).
 *
 * Independent of `line_sender_error_get_code`: a delivery-unknown failure
 * typically reports `line_sender_error_failover_retry`, yet that code alone
 * does NOT mean the input is safe to resend. When this returns `true`, only
 * replay the same input if table-level dedup/upsert keys make duplicate rows
 * harmless. NULL-safe: passing NULL returns `false`.
 */
QUESTDB_CLIENT_API
bool line_sender_error_in_doubt(const line_sender_error*);

/** Clean up the error. */
QUESTDB_CLIENT_API
void line_sender_error_free(line_sender_error*);

/////////// Preparing strings and names

/**
 * Non-owning validated UTF-8 encoded string.
 * The string need not be null-terminated.
 */
typedef struct line_sender_utf8
{
    // Don't initialize fields directly.
    // Call `line_sender_utf8_init()` instead.
    size_t len;
    const char* buf;
} line_sender_utf8;

/**
 * Check the provided buffer is a valid UTF-8 encoded string.
 *
 * @param[out] str The object to be initialized.
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer. Need not be null-terminated.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_utf8_init(
    line_sender_utf8* str,
    size_t len,
    const char* buf,
    line_sender_error** err_out);

/**
 * Construct a UTF-8 object from UTF-8 encoded buffer and length.
 * If the passed in buffer is not valid UTF-8, the program will abort.
 *
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer.
 */
QUESTDB_CLIENT_API
line_sender_utf8 line_sender_utf8_assert(size_t len, const char* buf);

#define QDB_UTF8_LITERAL(literal)                                              \
    line_sender_utf8_assert(sizeof(literal) - 1, (literal))

/**
 * Non-owning view of sender buffer, Modifying the buffer will invalidate
 * the borrowed buffer. Callers must not read from `buf` when `len` is zero;
 * empty views may use a NULL `buf`.
 */
typedef struct line_sender_buffer_view
{
    size_t len;
    const uint8_t* buf;
} line_sender_buffer_view;

/**
 * Non-owning validated table, symbol or column name. UTF-8 encoded.
 * Need not be null-terminated.
 */
typedef struct line_sender_table_name
{
    // Don't initialize fields directly.
    // Call `line_sender_table_name_init()` instead.
    size_t len;
    const char* buf;
} line_sender_table_name;

/**
 * Check the provided buffer is a valid UTF-8 encoded string that can be
 * used as a table name.
 *
 * @param[out] name The object to be initialized.
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer. Need not be null-terminated.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_table_name_init(
    line_sender_table_name* name,
    size_t len,
    const char* buf,
    line_sender_error** err_out);

/**
 * Construct a table name object from UTF-8 encoded buffer and length.
 * If the passed in buffer is not valid UTF-8, or is not a valid table name,
 * the program will abort.
 *
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer.
 */
QUESTDB_CLIENT_API
line_sender_table_name line_sender_table_name_assert(
    size_t len, const char* buf);

#define QDB_TABLE_NAME_LITERAL(literal)                                        \
    line_sender_table_name_assert(sizeof(literal) - 1, (literal))

/**
 * Non-owning validated table, symbol or column name. UTF-8 encoded.
 * Need not be null-terminated.
 */
typedef struct line_sender_column_name
{
    // Don't initialize fields directly.
    // Call `line_sender_column_name_init()` instead.
    size_t len;
    const char* buf;
} line_sender_column_name;

/**
 * Check the provided buffer is a valid UTF-8 encoded string that can be
 * used as a symbol name or column name.
 *
 * @param[out] name The object to be initialized.
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer. Need not be null-terminated.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_column_name_init(
    line_sender_column_name* name,
    size_t len,
    const char* buf,
    line_sender_error** err_out);

/**
 * Construct a column name object from UTF-8 encoded buffer and length.
 * If the passed in buffer is not valid UTF-8, or is not a valid column
 * name, the program will abort.
 *
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer.
 */
QUESTDB_CLIENT_API
line_sender_column_name line_sender_column_name_assert(
    size_t len, const char* buf);

#define QDB_COLUMN_NAME_LITERAL(literal)                                       \
    line_sender_column_name_assert(sizeof(literal) - 1, (literal))

/////////// Constructing ILP messages.

/**
 * Accumulates a batch of rows to be sent via `line_sender_flush()` or its
 * variants. A buffer object can be reused after flushing and clearing.
 */
typedef struct line_sender_buffer line_sender_buffer;

/**
 * Rollback handle captured from a sender buffer.
 *
 * Treat the fields as opaque implementation details.
 *
 * This is the stable C ABI v1 layout. Do not change field order or width
 * without a breaking version bump.
 */
typedef struct line_sender_bookmark
{
    uint64_t origin;
    uint64_t generation;
} line_sender_bookmark;

/**
 * Construct an ILP `line_sender_buffer` with explicitly set
 * `protocol_version` and fixed 127-byte name length limit.
 *
 * This constructor is ILP-only. It does not create QWP/UDP buffers.
 * For protocol-neutral construction, especially when using QWP/UDP, prefer
 * `line_sender_buffer_new_for_sender(...)`.
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_new(
    line_sender_protocol_version version);

/**
 * Construct an ILP `line_sender_buffer` with explicitly set
 * `protocol_version` and a max name length limit.
 *
 * This constructor is ILP-only. It does not create QWP/UDP buffers.
 * For protocol-neutral construction, especially when using QWP/UDP, prefer
 * `line_sender_buffer_new_for_sender(...)`.
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_with_max_name_len(
    line_sender_protocol_version version, size_t max_name_len);

/**
 * Construct a QWP/UDP `line_sender_buffer` with fixed 127-byte name length
 * limit.
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_new_qwp(void);

/**
 * Construct a QWP/UDP `line_sender_buffer` with a max name length limit.
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_new_qwp_with_max_name_len(
    size_t max_name_len);

/**
 * Construct a QWP/WebSocket `line_sender_buffer` with a fixed 127-byte name
 * length limit. For pooled ingestion, prefer `questdb_db_new_buffer` so the
 * buffer inherits the pool's configured name-length limit (see
 * `qwp_sender.h`).
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_new_qwp_ws(void);

/**
 * Construct a QWP/WebSocket columnar `line_sender_buffer` with a max name
 * length limit.
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_new_qwp_ws_with_max_name_len(
    size_t max_name_len);

/** Release the `line_sender_buffer` object. */
QUESTDB_CLIENT_API
void line_sender_buffer_free(line_sender_buffer* buffer);

/**
 * Create a new copy of the buffer.
 *
 * Returns NULL and populates `err_out` if `buffer` is NULL or if the
 * underlying clone panics (e.g. allocation failure).
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_clone(
    const line_sender_buffer* buffer, line_sender_error** err_out);

/**
 * Pre-allocate to ensure the buffer has enough capacity for at least the
 * specified additional byte count. This may be rounded up.
 * This does not allocate if such additional capacity is already satisfied.
 *
 * For ILP buffers this is expressed in bytes. For QWP buffers this is only a
 * best-effort hint and may be ignored.
 *
 * Returns true on success. Returns false and populates `err_out` if `buffer`
 * is NULL or if the underlying allocator panics (e.g. capacity overflow).
 * See: `capacity`.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_reserve(
    line_sender_buffer* buffer,
    size_t additional,
    line_sender_error** err_out);

/**
 * Get the current buffer capacity.
 *
 * For ILP buffers this is byte capacity. For QWP buffers this is an
 * implementation-defined capacity hint and should not be interpreted as byte
 * capacity.
 */
QUESTDB_CLIENT_API
size_t line_sender_buffer_capacity(const line_sender_buffer* buffer);

/**
 * Capture a bookmark for the current buffer state.
 *
 * Capturing a new bookmark replaces the previously stored bookmark or marker.
 *
 * @param[in] buffer Buffer to bookmark. Must be non-NULL.
 * @param[out] out Receives the captured bookmark on success. Passing NULL
 * returns false and sets `err_out` if provided.
 * @param[out] err_out Set to an error object on failure (if non-NULL).
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_bookmark(
    line_sender_buffer* buffer,
    line_sender_bookmark* out,
    line_sender_error** err_out);

/**
 * Rewind the buffer to a previously captured bookmark.
 *
 * On success, the stored bookmark is consumed.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_rewind_to_bookmark(
    line_sender_buffer* buffer,
    line_sender_bookmark bookmark,
    line_sender_error** err_out);

/**
 * Discard a previously captured bookmark if it is still current.
 */
QUESTDB_CLIENT_API
void line_sender_buffer_clear_bookmark(
    line_sender_buffer* buffer,
    line_sender_bookmark bookmark);

/**
 * Mark a rewind point.
 * This allows undoing accumulated changes to the buffer for one or more
 * rows by calling `rewind_to_marker()`.
 * Any previously stored rewind point will be discarded, including one
 * established by `line_sender_buffer_bookmark()`.
 * Once the marker is no longer needed, call `clear_marker()`.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_set_marker(
    line_sender_buffer* buffer, line_sender_error** err_out);

/**
 * Undo all changes since the currently stored rewind point was captured.
 *
 * This may rewind a state established by either
 * `line_sender_buffer_set_marker()` or `line_sender_buffer_bookmark()`.
 *
 * As a side-effect, this also clears the stored rewind point.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_rewind_to_marker(
    line_sender_buffer* buffer, line_sender_error** err_out);

/**
 * Discard the currently stored rewind point, including one established by
 * `line_sender_buffer_bookmark()`.
 */
QUESTDB_CLIENT_API
void line_sender_buffer_clear_marker(line_sender_buffer* buffer);

/**
 * Remove all accumulated data and prepare the buffer for new lines.
 * This does not affect the buffer's capacity.
 */
QUESTDB_CLIENT_API
void line_sender_buffer_clear(line_sender_buffer* buffer);

/**
 * The current encoded size of the buffered data.
 *
 * For ILP buffers this is the exact pending byte length. For QWP buffers this
 * is a buffered size hint, not the exact size of an eventual UDP datagram or
 * WebSocket replay frame.
 */
QUESTDB_CLIENT_API
size_t line_sender_buffer_size(const line_sender_buffer* buffer);

/** The number of rows accumulated in the buffer. */
QUESTDB_CLIENT_API
size_t line_sender_buffer_row_count(const line_sender_buffer* buffer);

/**
 * Tell whether the buffer is transactional.
 *
 * ILP buffers are transactional iff they contain data for at most one
 * table. QWP/UDP does not support transactional flushes, so QWP buffers
 * always return `false`.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_transactional(const line_sender_buffer* buffer);

/**
 * Get a read-only view into the buffer's bytes contents.
 *
 * This is only meaningful for ILP buffers, where rows are accumulated in
 * serialized form. For QWP buffers the return value is currently empty because
 * rows are encoded into UDP datagrams only during `flush`.
 *
 * @param[in] buffer Line sender buffer object.
 * @return read_only view with the byte representation of the line
 *         sender buffer's contents for ILP, or an empty view with `len == 0`
 *         and `buf == NULL` for QWP.
 */
QUESTDB_CLIENT_API
line_sender_buffer_view line_sender_buffer_peek(
    const line_sender_buffer* buffer);

/**
 * Start recording a new row for the given table.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Table name.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_table(
    line_sender_buffer* buffer,
    line_sender_table_name name,
    line_sender_error** err_out);

/**
 * Record a symbol value for the given column.
 * Make sure you record all the symbol columns before any other column type.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_symbol(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    line_sender_utf8 value,
    line_sender_error** err_out);

/**
 * Record a boolean value for the given column.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_bool(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    bool value,
    line_sender_error** err_out);

/**
 * Record an integer value for the given column.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_i64(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int64_t value,
    line_sender_error** err_out);

/**
 * Record a floating-point value for the given column.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_f64(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    double value,
    line_sender_error** err_out);

/**
 * Record an 8-bit signed integer for the given column. QWP-only.
 *
 * On ILP buffers this returns line_sender_error_invalid_api_call.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_i8(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int8_t value,
    line_sender_error** err_out);

/**
 * Record a 16-bit signed integer for the given column. QWP-only.
 *
 * On ILP buffers this returns line_sender_error_invalid_api_call.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_i16(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int16_t value,
    line_sender_error** err_out);

/**
 * Record a 32-bit signed integer for the given column. QWP-only.
 *
 * On ILP buffers this returns line_sender_error_invalid_api_call.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_i32(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int32_t value,
    line_sender_error** err_out);

/**
 * Record a 32-bit floating-point value for the given column. QWP-only.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_f32(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    float value,
    line_sender_error** err_out);

/**
 * Record a string value for the given column.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_str(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    line_sender_utf8 value,
    line_sender_error** err_out);

/**
 * Record a decimal string value for the given column.
 *
 * When specifying a decimal as a string, use a '.' to separate the whole from the
 * fractional parts. For example, "12.20".
 * Infinity is encoded as "+Infinity" or "-Infinity", while NaN as "NaN".
 * Note that Infinity and NaN values decay to nulls when stored in the database.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_dec_str(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const char *value,
    size_t value_len,
    line_sender_error** err_out);

/**
 * Record a decimal value for the given column.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] scale Number of digits after the decimal point
 * @param[in] data Unscaled value in two's complement format, big-endian
 * @param[in] data_len Length of the unscaled value array
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_dec(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const unsigned int scale,
    const uint8_t* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a decimal string value as DECIMAL64. QWP-only.
 *
 * Same string format as line_sender_buffer_column_dec_str. The unscaled
 * magnitude must fit a signed 64-bit integer at the column's pinned scale;
 * values that do not fit return line_sender_error_invalid_api_call.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_dec64_str(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const char *value,
    size_t value_len,
    line_sender_error** err_out);

/**
 * Record an unscaled-int decimal value as DECIMAL64. QWP-only.
 *
 * Same scale + two's-complement big-endian format as
 * line_sender_buffer_column_dec. Values that do not fit a signed 64-bit
 * integer at the chosen scale return line_sender_error_invalid_api_call.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_dec64(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const unsigned int scale,
    const uint8_t* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a decimal string value as DECIMAL128. QWP-only.
 *
 * Same string format as line_sender_buffer_column_dec_str. Values that do
 * not fit a signed 128-bit integer at the column's pinned scale return
 * line_sender_error_invalid_api_call.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_dec128_str(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const char *value,
    size_t value_len,
    line_sender_error** err_out);

/**
 * Record an unscaled-int decimal value as DECIMAL128. QWP-only.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_dec128(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const unsigned int scale,
    const uint8_t* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a UUID column value. QWP-only.
 *
 * The wire encoding writes `lo` (8 bytes LE) followed by `hi` (8 bytes LE).
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_uuid(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    uint64_t lo,
    uint64_t hi,
    line_sender_error** err_out);

/**
 * Record a LONG256 column value. QWP-only.
 *
 * `value` must point to exactly 32 bytes: four 64-bit limbs encoded
 * little-endian, least-significant limb first.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_long256(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const uint8_t* value,
    line_sender_error** err_out);

/**
 * Record an IPv4 column value. QWP-only.
 *
 * `value` is the address packed as a u32 with octet 0 in the high byte:
 *   `addr = ((uint32_t)a << 24) | (b << 16) | (c << 8) | d`
 * The encoder writes `addr.to_le_bytes()` so the wire bytes appear as
 * `[d, c, b, a]`.
 *
 * IPv4 (`0x18`) is part of the QWP v1 spec. Server-side ingest does not
 * currently implement this wire type; batches using it will be rejected
 * with a descriptive error. This may change in future server releases.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_ipv4(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    uint32_t value,
    line_sender_error** err_out);

/**
 * Record a DATE column value (milliseconds since the Unix epoch). QWP-only.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_date(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int64_t millis,
    line_sender_error** err_out);

/**
 * Record a CHAR column value (single UTF-16 code unit). QWP-only.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_char(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    uint16_t value,
    line_sender_error** err_out);

/**
 * Record a BINARY column value (opaque byte sequence). QWP-only.
 *
 * BINARY (`0x17`) is part of the QWP v1 spec. Server-side ingest does not
 * currently implement this wire type; batches using it will be rejected
 * with a descriptive error. This may change in future server releases.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_binary(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    const uint8_t* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a GEOHASH column value. QWP-only.
 *
 * `precision_bits` must be in `1..=60` and is pinned per column.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_geohash(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    uint64_t bits,
    uint8_t precision_bits,
    line_sender_error** err_out);

/**
 * Record a multidimensional array of `int64` values in C-major order. QWP-only.
 *
 * LONG_ARRAY (`0x12`) is part of the QWP v1 spec. Server-side ingest does
 * not currently implement this wire type; batches using it will be rejected
 * with a descriptive error. This may change in future server releases.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] rank Number of dimensions of the array.
 * @param[in] shape Array of dimension sizes (length = `rank`).
 *                  Each element must be a positive integer.
 * @param[in] data First array element data.
 * @param[in] data_len Element length of the array.
 * @param[out] err_out Set to an error object on failure (if non-NULL).
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_i64_arr_c_major(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    size_t rank,
    const uintptr_t* shape,
    const int64_t* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a multidimensional array of `int64` values with byte strides. QWP-only.
 *
 * LONG_ARRAY (`0x12`) is part of the QWP v1 spec. Server-side ingest does
 * not currently implement this wire type; batches using it will be rejected
 * with a descriptive error. This may change in future server releases.
 *
 * @param[in] strides Array strides, in the unit of bytes. Strides can be
 *                    negative.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_i64_arr_byte_strides(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    size_t rank,
    const uintptr_t* shape,
    const intptr_t* strides,
    const int64_t* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a multidimensional array of `int64` values with element strides. QWP-only.
 *
 * LONG_ARRAY (`0x12`) is part of the QWP v1 spec. Server-side ingest does
 * not currently implement this wire type; batches using it will be rejected
 * with a descriptive error. This may change in future server releases.
 *
 * @param[in] strides Array strides, in the unit of elements. Strides can be
 *                    negative.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_i64_arr_elem_strides(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    size_t rank,
    const uintptr_t* shape,
    const intptr_t* strides,
    const int64_t* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a multidimensional array of `double` values in C-major order.
 *
 * QuestDB server version 9.0.0 or later is required for array support.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] rank Number of dimensions of the array.
 * @param[in] shape Array of dimension sizes (length = `rank`).
 *                   Each element must be a positive integer.
 * @param[in] data First array element data.
 * @param[in] data_len Element length of the array.
 * @param[out] err_out Set to an error object on failure (if non-NULL).
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_f64_arr_c_major(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    size_t rank,
    const uintptr_t* shape,
    const double* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a multidimensional array of `double` values for the given column.
 *
 * The values in the `strides` parameter represent the number of bytes
 * between consecutive elements along each dimension.
 *
 * QuestDB server version 9.0.0 or later is required for array support.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] rank Number of dimensions of the array.
 * @param[in] shape Array of dimension sizes (length = `rank`).
 *                  Each element must be a positive integer.
 * @param[in] strides Array strides, in the unit of bytes. Strides can be
 * negative.
 * @param[in] data Array data, laid out according to the provided shape
 * and strides.
 * @param[in] data_len Element length of the array.
 * @param[out] err_out Set to an error object on failure (if non-NULL).
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_f64_arr_byte_strides(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    size_t rank,
    const uintptr_t* shape,
    const intptr_t* strides,
    const double* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a multidimensional array of `double` values for the given column.
 *
 * The values in the `strides` parameter represent the number of elements
 * between consecutive elements along each dimension.
 *
 * QuestDB server version 9.0.0 or later is required for array support.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] rank Number of dimensions of the array.
 * @param[in] shape Array of dimension sizes (length = `rank`).
 *                   Each element must be a positive integer.
 * @param[in] strides Array strides, in the unit of elements. Strides can be
 * negative.
 * @param[in] data Array data, laid out according to the provided shape
 * and strides.
 * @param[in] data_len Element length of the array.
 * @param[out] err_out Set to an error object on failure (if non-NULL).
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_f64_arr_elem_strides(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    size_t rank,
    const uintptr_t* shape,
    const intptr_t* strides,
    const double* data,
    size_t data_len,
    line_sender_error** err_out);

/**
 * Record a nanosecond timestamp value for the given column.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] nanos The timestamp in nanoseconds since the Unix epoch.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_ts_nanos(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int64_t nanos,
    line_sender_error** err_out);

/**
 * Record a microsecond timestamp value for the given column.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] micros The timestamp in microseconds since the Unix epoch.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_column_ts_micros(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int64_t micros,
    line_sender_error** err_out);

/**
 * Complete the current row with the designated timestamp in nanoseconds.
 *
 * After this call, you can start recording the next row by calling
 * `line_sender_buffer_table()` again, or you can send the accumulated batch
 * by calling `line_sender_flush()` or one of its variants.
 *
 * If you want to pass the current system timestamp, see
 * `line_sender_now_nanos()`.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] epoch_nanos Number of nanoseconds since the Unix epoch.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_at_nanos(
    line_sender_buffer* buffer,
    int64_t epoch_nanos,
    line_sender_error** err_out);

/**
 * Complete the current row with the designated timestamp in microseconds.
 *
 * After this call, you can start recording the next row by calling
 * `line_sender_buffer_table()` again, or you can send the accumulated batch
 * by calling `line_sender_flush()` or one of its variants.
 *
 * If you want to pass the current system timestamp, see
 * `line_sender_now_micros()`.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] epoch_micros Number of microseconds since the Unix epoch.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_at_micros(
    line_sender_buffer* buffer,
    int64_t epoch_micros,
    line_sender_error** err_out);

/**
 * Complete the current row without providing a timestamp. The QuestDB
 * instance will insert its own timestamp.
 *
 * Letting the server assign the timestamp can be faster since it a reliable
 * way to avoid out-of-order operations in the database for maximum
 * ingestion throughput. However, it removes the ability to deduplicate
 * rows.
 *
 * This is NOT equivalent to calling `line_sender_buffer_at_nanos()` or
 * `line_sender_buffer_at_micros()` with the current time: the QuestDB
 * server will set the timestamp only after receiving the row. If you're
 * flushing infrequently, the server-assigned timestamp may be significantly
 * behind the time the data was recorded in the buffer.
 *
 * In almost all cases, you should prefer the `line_sender_buffer_at_*()`
 * functions.
 *
 * After this call, you can start recording the next row by calling
 * `table()` again, or you can send the accumulated batch by calling
 * `flush()` or one of its variants.
 *
 * @param[in] buffer Line buffer object.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_at_now(
    line_sender_buffer* buffer, line_sender_error** err_out);

/**
 * Check whether the buffer is ready to be flushed.
 * If this returns false, the buffer is incomplete and cannot be sent,
 * and an error message is set to indicate the problem.
 */
QUESTDB_CLIENT_API
bool line_sender_buffer_check_can_flush(
    const line_sender_buffer* buffer, line_sender_error** err_out);

/////////// Connecting, sending and disconnecting.

/**
 * Inserts data into QuestDB via the InfluxDB Line Protocol.
 *
 * Batch up rows in a `line_sender_buffer`, then call `line_sender_flush()`
 * or one of its variants with this object to send them.
 */
typedef struct line_sender line_sender;

typedef enum line_sender_qwpws_progress
{
    LINE_SENDER_QWPWS_PROGRESS_BACKGROUND = 0,
    LINE_SENDER_QWPWS_PROGRESS_MANUAL = 1,
} line_sender_qwpws_progress;

typedef struct line_sender_qwpws_fsn
{
    bool has_value;
    uint64_t value;
} line_sender_qwpws_fsn;

typedef enum line_sender_qwpws_error_category
{
    LINE_SENDER_QWPWS_ERROR_SCHEMA_MISMATCH = 0,
    LINE_SENDER_QWPWS_ERROR_PARSE_ERROR = 1,
    LINE_SENDER_QWPWS_ERROR_INTERNAL_ERROR = 2,
    LINE_SENDER_QWPWS_ERROR_SECURITY_ERROR = 3,
    LINE_SENDER_QWPWS_ERROR_WRITE_ERROR = 4,
    LINE_SENDER_QWPWS_ERROR_NOT_WRITABLE = 5,
    LINE_SENDER_QWPWS_ERROR_PROTOCOL_VIOLATION = 6,
    LINE_SENDER_QWPWS_ERROR_UNKNOWN = 7,
} line_sender_qwpws_error_category;

typedef enum line_sender_qwpws_error_policy
{
    LINE_SENDER_QWPWS_ERROR_RETRIABLE = 0,
    LINE_SENDER_QWPWS_ERROR_RETRIABLE_OTHER = 1,
    LINE_SENDER_QWPWS_ERROR_TERMINAL = 2,
} line_sender_qwpws_error_policy;

typedef struct line_sender_qwpws_error line_sender_qwpws_error;

typedef struct line_sender_qwpws_error_view
{
    line_sender_qwpws_error_category category;
    line_sender_qwpws_error_policy applied_policy;
    bool has_status;
    uint8_t status;
    bool has_message_sequence;
    uint64_t message_sequence;
    uint64_t from_fsn;
    uint64_t to_fsn;
    const char* message;
    size_t message_len;
} line_sender_qwpws_error_view;

/**
 * QWP/WebSocket server-diagnostic callback.
 *
 * The callback runs synchronously from sender API calls such as
 * `line_sender_flush`. The `event` view is valid only for the duration of the
 * callback call. The callback must not call methods on the same sender.
 */
typedef void (*line_sender_qwpws_error_cb)(
    void* user_data,
    const line_sender_qwpws_error_view* event);

/**
 * Accumulates parameters for a new `line_sender` object.
 */
typedef struct line_sender_opts line_sender_opts;

/**
 * Create a new `line_sender_opts` instance from the given configuration
 * string. The format of the string is: "tcp::addr=host:port;key=value;...;"
 * Instead of "tcp" you can also specify "tcps", "http", "https", "udp",
 * "ws", and "wss".
 *
 * The accepted keys match one-for-one with the functions on
 * `line_sender_opts`. For example, this is a valid configuration string:
 *
 * "https::addr=host:port;username=alice;password=secret;"
 *
 * and there are matching functions `line_sender_opts_username()` and
 * `line_sender_opts_password()`. The value for `addr=` is supplied directly
 * to `line_sender_opts_new`, so there's no function with a matching name.
 *
 * For the full list of keys, search this header for `bool
 * line_sender_opts_`.
 */
QUESTDB_CLIENT_API
line_sender_opts* line_sender_opts_from_conf(
    line_sender_utf8 config, line_sender_error** err_out);

/**
 * Create a new `line_sender_opts` instance from the configuration stored in
 * the `QDB_CLIENT_CONF` environment variable.
 */
QUESTDB_CLIENT_API
line_sender_opts* line_sender_opts_from_env(line_sender_error** err_out);

/**
 * Create a new `line_sender_opts` instance with the given protocol,
 * hostname and port.
 *
 * @param[in] protocol The protocol to use.
 * @param[in] host The QuestDB database host.
 * @param[in] port The QuestDB port for the selected protocol.
 */
QUESTDB_CLIENT_API
line_sender_opts* line_sender_opts_new(
    line_sender_protocol protocol, line_sender_utf8 host, uint16_t port);

/**
 * Create a new `line_sender_opts` instance with the given protocol,
 * hostname and service name.
 */
QUESTDB_CLIENT_API
line_sender_opts* line_sender_opts_new_service(
    line_sender_protocol protocol,
    line_sender_utf8 host,
    line_sender_utf8 port);

/**
 * Select local outbound network "bind" interface.
 *
 * This may be relevant if your machine has multiple network interfaces.
 *
 * The default is `0.0.0.0`.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_bind_interface(
    line_sender_opts* opts,
    line_sender_utf8 bind_interface,
    line_sender_error** err_out);

/**
 * Set the maximum QWP/UDP datagram size in bytes.
 *
 * `max_datagram_size` must be between 1 and 65,507 bytes, inclusive.
 * Values outside this range are rejected.
 * The upper bound is the UDP/IPv4 payload limit, not a recommended
 * operating size. The default is 1,400 bytes, leaving room for IPv4 and
 * UDP headers under a common 1,500-byte Ethernet MTU. If you raise this
 * value, keep it within the effective UDP payload budget for the path MTU.
 * Oversized IPv4 packets may be fragmented when fragmentation is allowed,
 * or dropped when it is not; fragmented UDP is fragile because losing any
 * fragment loses the whole datagram.
 *
 * This setting is only supported for `line_sender_protocol_udp`.
 * Returns `false` and sets `err_out` on constraint violation or
 * protocol mismatch.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_max_datagram_size(
    line_sender_opts* opts,
    size_t max_datagram_size,
    line_sender_error** err_out);

/**
 * Set the multicast TTL used for QWP/UDP sends.
 *
 * The default is 1. Use a value greater than 0 when sending to a multicast
 * address. A value of 0 prevents multicast datagrams from leaving the local
 * host.
 *
 * `multicast_ttl` must be in the 0–255 range (inclusive).
 * Values greater than 255 are treated as an error.
 *
 * This setting is only supported for `line_sender_protocol_udp`.
 * Returns `false` and sets `err_out` on constraint violation or
 * protocol mismatch.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_multicast_ttl(
    line_sender_opts* opts,
    uint32_t multicast_ttl,
    line_sender_error** err_out);

/**
 * Control whether QWP/WebSocket progress is driven by a background thread or
 * manually by the caller. The default is background progress. This setting is
 * only supported for `line_sender_protocol_ws` and
 * `line_sender_protocol_wss`.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_qwpws_progress(
    line_sender_opts* opts,
    line_sender_qwpws_progress progress,
    line_sender_error** err_out);

/**
 * Install a QWP/WebSocket server-diagnostic callback. Passing NULL restores the
 * default C callback, which writes one structured line to stderr per
 * diagnostic.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_qwpws_error_handler(
    line_sender_opts* opts,
    line_sender_qwpws_error_cb cb,
    void* user_data,
    line_sender_error** err_out);

/**
 * Set the username for authentication.
 *
 * For TCP, this is the `kid` part of the ECDSA key set.
 * The other fields are `token` `token_x` and `token_y`.
 *
 * For HTTP, this is part of basic authentication.
 * See also: `line_sender_opts_password()`.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_username(
    line_sender_opts* opts,
    line_sender_utf8 username,
    line_sender_error** err_out);

/**
 * Set the password for basic HTTP authentication.
 * See also: `line_sender_opts_username()`.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_password(
    line_sender_opts* opts,
    line_sender_utf8 password,
    line_sender_error** err_out);

/**
 * Set the bearer-token authentication parameter for HTTP or QWP/WebSocket,
 * which requires QuestDB Enterprise, or set the ECDSA private key for TCP
 * authentication.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_token(
    line_sender_opts* opts,
    line_sender_utf8 token,
    line_sender_error** err_out);

/**
 * Set the ECDSA public key X for TCP authentication.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_token_x(
    line_sender_opts* opts,
    line_sender_utf8 token_x,
    line_sender_error** err_out);

/**
 * Set the ECDSA public key Y for TCP authentication.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_token_y(
    line_sender_opts* opts,
    line_sender_utf8 token_y,
    line_sender_error** err_out);

/**
 * Sets the ingestion protocol version.
 *
 * HTTP transport automatically negotiates the protocol version by
 * default(unset strong recommended). You can explicitlyconfigure the
 * protocol version to avoid the slight latency cost at connection time.
 *
 * TCP transport does not negotiate the protocol version and uses
 * `line_sender_protocol_version_1` by default. You must explicitly set
 * `line_sender_protocol_version_2` in order to ingest arrays.
 *
 * QWP/UDP does not support explicit protocol version configuration.
 * Calling this function on QWP/UDP opts will return an error.
 *
 * QuestDB server version 9.0.0 or later is required for
 * `line_sender_protocol_version_2` support.
 *
 * QuestDB server version 9.2.0 or later is required for
 * `line_sender_protocol_version_3` support.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_protocol_version(
    line_sender_opts* opts,
    line_sender_protocol_version version,
    line_sender_error** err_out);

/**
 * Configure how long to wait for messages from the QuestDB server during
 * the TLS handshake and authentication process.
 * The value is in milliseconds, and the default is 15 seconds.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_auth_timeout(
    line_sender_opts* opts, uint64_t millis, line_sender_error** err_out);

/**
 * Set to `false` to disable TLS certificate verification.
 * This should only be used for debugging purposes as it reduces security.
 *
 * For testing, consider specifying a path to a `.pem` file instead via
 * the `tls_roots` setting.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_tls_verify(
    line_sender_opts* opts, bool verify, line_sender_error** err_out);

/**
 * Specify where to find the root certificates used to validate the
 * server's TLS certificate.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_tls_ca(
    line_sender_opts* opts, line_sender_ca ca, line_sender_error** err_out);

/**
 * Set the path to a custom root certificate `.pem` file.
 * This is used to validate the server's certificate during the TLS
 * handshake.
 *
 * On QWP/WebSocket (`wss::`) the same path may instead point at a
 * JKS or PKCS#12 keystore; pair it with
 * `line_sender_opts_tls_roots_password` to unlock it.
 *
 * See notes on how to test with self-signed certificates:
 * https://github.com/questdb/c-questdb-client/tree/main/tls_certs.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_tls_roots(
    line_sender_opts* opts, line_sender_utf8 path, line_sender_error** err_out);

/**
 * Set the password unlocking the JKS / PKCS#12 keystore named by
 * `line_sender_opts_tls_roots`.
 *
 * QWP/WebSocket only (`wss::`). Calling this on an ILP/TCP or
 * ILP/HTTP sender returns an `invalid_api_call` error: those
 * transports read unencrypted PEM via rustls and have no keystore
 * concept.
 *
 * The file's format is auto-detected: JKS magic `0xFEEDFEED`, or
 * PKCS#12 (ASN.1 SEQUENCE). Trusted-certificate entries become
 * rustls roots; private-key entries are ignored — this is the trust
 * store half of the Java reference's
 * `KeyStore.getInstance(...).load(stream, pwd)` flow.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_tls_roots_password(
    line_sender_opts* opts,
    line_sender_utf8 password,
    line_sender_error** err_out);

/**
 * Set the maximum buffered size that the client will flush to the server.
 * The default is 100 MiB.
 *
 * For ILP this applies to the exact pending byte length.
 * For QWP/UDP this applies to the buffer size hint returned by
 * `line_sender_buffer_size()`. For QWP/WebSocket it caps the exact encoded
 * replay frame.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_max_buf_size(
    line_sender_opts* opts, size_t max_buf_size, line_sender_error** err_out);

/**
 * Set the maximum length of a table or column name in bytes.
 * The default is 127 bytes.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_max_name_len(
    line_sender_opts* opts, size_t max_name_len, line_sender_error** err_out);

/**
 * Set the cumulative duration spent in retries.
 * The value is in milliseconds, and the default is 10 seconds.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_retry_timeout(
    line_sender_opts* opts, uint64_t millis, line_sender_error** err_out);

/**
 * Cap on per-attempt backoff in the HTTP retry loop, in milliseconds.
 * Default is 1000 ms. The retry loop starts at 10 ms and doubles each
 * attempt up to this cap; the total retry budget is independently
 * bounded by `line_sender_opts_retry_timeout()`. ILP-over-HTTP only.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_retry_max_backoff(
    line_sender_opts* opts, uint64_t millis, line_sender_error** err_out);

/**
 * Set the minimum acceptable throughput while sending a buffer to the
 * server. The sender will divide the payload size by this number to
 * determine for how long to keep sending the payload before timing out. The
 * value is in bytes per second, and the default is 100 KiB/s. The timeout
 * calculated from minimum throughput is adedd to the value of
 * `request_timeout`.
 *
 * See also: `line_sender_opts_request_timeout()`
 */
QUESTDB_CLIENT_API
bool line_sender_opts_request_min_throughput(
    line_sender_opts* opts,
    uint64_t bytes_per_sec,
    line_sender_error** err_out);

/**
 * Set the additional time to wait on top of that calculated from the
 * minimum throughput. This accounts for the fixed latency of the HTTP
 * request-response roundtrip. The value is in milliseconds, and the default
 * is 10 seconds.
 *
 * See also: `line_sender_opts_request_min_throughput()`
 */
QUESTDB_CLIENT_API
bool line_sender_opts_request_timeout(
    line_sender_opts* opts, uint64_t millis, line_sender_error** err_out);

// Do not call: Private API for the C++ and Python bindings.
bool line_sender_opts_user_agent(
    line_sender_opts* opts,
    line_sender_utf8 user_agent,
    line_sender_error** err_out);

/**
 * Duplicate the `line_sender_opts` object.
 * Both old and new objects will have to be freed.
 * Returns NULL if `opts` is NULL.
 */
QUESTDB_CLIENT_API
line_sender_opts* line_sender_opts_clone(line_sender_opts* opts);

/**
 * Release the `line_sender_opts` object.
 * Passing NULL is a no-op.
 */
QUESTDB_CLIENT_API
void line_sender_opts_free(line_sender_opts* opts);

/**
 * Create a new line sender instance from the given options object.
 *
 * In the case of TCP, this synchronously establishes the TCP connection,
 * and returns once the connection is fully established. If the connection
 * requires authentication or TLS, these will also be completed before
 * returning.
 *
 * The sender should be accessed by only a single thread a time.
 * @param[in] opts Options for the connection. Must be non-NULL.
 * @note The caller retains ownership of `opts` and must release it with
 * `line_sender_opts_free()` when it is no longer needed.
 */
QUESTDB_CLIENT_API
line_sender* line_sender_build(
    const line_sender_opts* opts, line_sender_error** err_out);

/**
 * Create a new line sender instance from the given configuration string.
 * The format of the string is: "tcp::addr=host:port;key=value;...;"
 * Instead of "tcp" you can also specify "tcps", "http", "https",
 * "udp", "ws", and "wss".
 *
 * The accepted keys match one-for-one with the functions on
 * `line_sender_opts`. For example, this is a valid configuration string:
 *
 * "https::addr=host:port;username=alice;password=secret;"
 *
 * and there are matching functions `line_sender_opts_username()` and
 * `line_sender_opts_password()`. The value for `addr=` is supplied directly
 * to `line_sender_opts_new`, so there's no function with a matching name.
 *
 * For the full list of keys, search this header for `bool
 * line_sender_opts_`.
 *
 * In the case of TCP, this synchronously establishes the TCP connection,
 * and returns once the connection is fully established. If the connection
 * requires authentication or TLS, these will also be completed before
 * returning.
 *
 * The sender should be accessed by only a single thread a time.
 */
QUESTDB_CLIENT_API
line_sender* line_sender_from_conf(
    line_sender_utf8 config, line_sender_error** err_out);

/**
 * Create a new `line_sender` instance from the configuration stored in the
 * `QDB_CLIENT_CONF` environment variable.
 *
 * In the case of TCP, this synchronously establishes the TCP connection,
 * and returns once the connection is fully established. If the connection
 * requires authentication or TLS, these will also be completed before
 * returning.
 *
 * The sender should be accessed by only a single thread a time.
 */
QUESTDB_CLIENT_API
line_sender* line_sender_from_env(line_sender_error** err_out);

/**
 * Return the sender's configured transport protocol.
 */
QUESTDB_CLIENT_API
line_sender_protocol line_sender_get_protocol(const line_sender* sender);

/**
 * Return the sender's ILP protocol version.
 *
 * This is meaningful for ILP senders. For protocol-neutral inspection, use
 * `line_sender_get_protocol(...)`.
 * Do not use this value to construct QWP/UDP buffers; use
 * `line_sender_buffer_new_for_sender(...)` instead.
 * For QWP/UDP senders this reports the QWP datagram version, currently
 * represented as `line_sender_protocol_version_1`; it is not an ILP feature
 * version.
 *
 * This is either the protocol version that was set explicitly,
 * or the one that was auto-detected during the connection process(Only for
 * HTTP). If connecting via TCP and not overridden, the value is
 * `line_sender_protocol_version_1`.
 */
QUESTDB_CLIENT_API
line_sender_protocol_version line_sender_get_protocol_version(
    const line_sender* sender);

/**
 * Returns the configured max_name_len, or the default value of 127.
 */
QUESTDB_CLIENT_API
size_t line_sender_get_max_name_len(const line_sender* sender);

/**
 * Construct a `line_sender_buffer` with the sender's configured settings.
 *
 * This is the preferred protocol-neutral constructor. It may produce a
 * different buffer implementation than `line_sender_buffer_new(...)`, for
 * example when the sender uses QWP-over-UDP or QWP-over-WebSocket.
 */
QUESTDB_CLIENT_API
line_sender_buffer* line_sender_buffer_new_for_sender(
    const line_sender* sender);

/**
 * Tell whether the sender is no longer usable and must be closed.
 * Returns true after an unrecoverable failure. For ILP-over-TCP this is any
 * socket error. For QWP/WebSocket this also covers a server rejection or
 * protocol violation that latches the publication lifecycle to its terminal
 * state. ILP-over-HTTP and QWP/UDP never transition into a
 * permanently-unusable state and always return false.
 * @param[in] sender Line sender object.
 * @return true if an error occurred with a sender and it must be closed.
 */
QUESTDB_CLIENT_API
bool line_sender_must_close(const line_sender* sender);

/**
 * Close the connection. Does not flush. Non-idempotent.
 * @param[in] sender Line sender object.
 */
QUESTDB_CLIENT_API
void line_sender_close(line_sender* sender);

/**
 * Publish a QWP/WebSocket buffer locally, clear it on success, and return the
 * assigned frame sequence number. Empty buffers succeed with
 * `fsn_out->has_value == false`.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_flush_and_get_fsn(
    line_sender* sender,
    line_sender_buffer* buffer,
    line_sender_qwpws_fsn* fsn_out,
    line_sender_error** err_out);

/**
 * Publish a QWP/WebSocket buffer locally without clearing it and return the
 * assigned frame sequence number. Empty buffers succeed with
 * `fsn_out->has_value == false`.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_flush_and_keep_and_get_fsn(
    line_sender* sender,
    const line_sender_buffer* buffer,
    line_sender_qwpws_fsn* fsn_out,
    line_sender_error** err_out);

/**
 * Drive one QWP/WebSocket progress step for a sender built with
 * `qwp_ws_progress=manual`.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_drive_once(
    line_sender* sender,
    bool* progressed_out,
    line_sender_error** err_out);

/**
 * Return the highest QWP/WebSocket frame sequence number published locally, or
 * no value if no frame has been published.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_published_fsn(
    const line_sender* sender,
    line_sender_qwpws_fsn* fsn_out,
    line_sender_error** err_out);

/**
 * Return the highest QWP/WebSocket frame sequence number completed by ACK, or
 * no value if no frame has completed.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_acked_fsn(
    const line_sender* sender,
    line_sender_qwpws_fsn* fsn_out,
    line_sender_error** err_out);

/**
 * Acknowledgement level for QWP/WebSocket wait/sync APIs.
 */
typedef enum qwpws_ack_level
{
    /** Wait for the server to accept every published frame. */
    qwpws_ack_level_ok = 0,

    /** Wait for durable-ACK coverage. This level requires QuestDB Enterprise;
     * APIs accepting it also require the `request_durable_ack=on` opt-in. */
    qwpws_ack_level_durable = 1,
} qwpws_ack_level;

/**
 * Wait until every QWP/WebSocket frame published so far reaches `ack_level`
 * (a `qwpws_ack_level` value). This is the row-major counterpart
 * to `qwp_sender_wait`.
 *
 * `timeout_millis` is a no-progress deadline (it fires only if the ack
 * watermark fails to advance for that long); `0` waits indefinitely.
 * `qwpws_ack_level_durable` requires QuestDB Enterprise and
 * `request_durable_ack=on`; otherwise this returns
 * `line_sender_error_invalid_api_call` even when nothing has been published.
 *
 * Returns `false` and sets `err_out` on the no-progress timeout
 * (`line_sender_error_failover_retry`), a server rejection, a transport
 * failure, or an invalid `ack_level`. With nothing published yet it succeeds
 * immediately.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_wait(
    line_sender* sender,
    uint32_t ack_level,
    uint64_t timeout_millis,
    line_sender_error** err_out);

/**
 * Poll the next structured QWP/WebSocket diagnostic. No diagnostic is a
 * successful result with `*error_out == NULL`.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_poll_error(
    line_sender* sender,
    line_sender_qwpws_error** error_out,
    line_sender_error** err_out);

/**
 * Return a borrowed view into an owned QWP/WebSocket diagnostic.
 *
 * The view's `message` pointer is valid until `error` is freed.
 */
QUESTDB_CLIENT_API
line_sender_qwpws_error_view line_sender_qwpws_error_get_view(
    const line_sender_qwpws_error* error);

/**
 * If `error` carries a terminal QWP/WebSocket diagnostic, write a borrowed
 * view into `view_out` and return true.
 *
 * The view's `message` pointer is valid until `error` is freed. Returns false
 * when `error` has no QWP/WebSocket diagnostic, or when either pointer is NULL.
 */
QUESTDB_CLIENT_API
bool line_sender_error_qwpws_get_view(
    const line_sender_error* error,
    line_sender_qwpws_error_view* view_out);

/**
 * Free an owned QWP/WebSocket diagnostic. Passing NULL is a no-op.
 */
QUESTDB_CLIENT_API
void line_sender_qwpws_error_free(line_sender_qwpws_error* error);

/**
 * Return how many QWP/WebSocket diagnostics were dropped because the sender's
 * unified bounded diagnostic log was full.
 *
 * The same log feeds line_sender_qwpws_poll_error() and error-handler
 * notification delivery through independent cursors. A lagging cursor can keep
 * entries live long enough for later diagnostics to overwrite them and
 * increment this count.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_errors_dropped(
    const line_sender* sender,
    uint64_t* dropped_out,
    line_sender_error** err_out);

/**
 * Stop accepting new QWP/WebSocket publications and wait for already-published
 * frames to resolve. The timeout is configured with the QWP/WebSocket
 * `close_flush_timeout_millis` config key; the default is 5000 ms, and values
 * less than or equal to 0 configure a zero-timeout fast close. Timeout and
 * terminal failure are reported through `err_out`.
 */
QUESTDB_CLIENT_API
bool line_sender_qwpws_close_drain(
    line_sender* sender,
    line_sender_error** err_out);

/**
 * Send the given buffer of rows to the QuestDB server, clearing the buffer.
 *
 * After this function returns, the buffer is empty and ready for the next
 * batch. If you want to preserve the buffer contents, call
 * `line_sender_flush_and_keep`. If you want to ensure the flush is
 * transactional, call `line_sender_flush_and_keep_with_flags`.
 *
 * With ILP-over-HTTP, this function sends an HTTP request and waits for the
 * response. If the server responds with an error, it returns a descriptive
 * error. In the case of a network error, it retries until it has exhausted
 * the retry time budget.
 *
 * With ILP-over-TCP, the function blocks only until the buffer is flushed
 * to the underlying OS-level network socket, without waiting to actually
 * send it to the server. In the case of an error, the server will quietly
 * disconnect: consult the server logs for error messages.
 *
 * With QWP-over-UDP, the function sends one or more UDP datagrams and returns
 * local socket errors only. A successful return does not guarantee delivery,
 * and when a flush spans multiple datagrams there is no all-or-nothing
 * guarantee for the logical batch.
 *
 * With QWP-over-WebSocket, the function publishes the buffer into the local
 * sender queue and returns before the server necessarily ACKs the frame. Later
 * terminal diagnostics fail subsequent sender calls and are also observable
 * through the QWP/WebSocket diagnostic polling API.
 *
 * HTTP should be the first choice, but use TCP if you need to continuously
 * send data to the server at a high rate.
 *
 * To improve the HTTP performance, send larger buffers (with more rows),
 * and consider parallelizing writes using multiple senders from multiple
 * threads.
 *
 * @param[in] sender Line sender object.
 * @param[in] buffer Line buffer object.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_flush(
    line_sender* sender,
    line_sender_buffer* buffer,
    line_sender_error** err_out);

/**
 * Send the given buffer of rows to the QuestDB server.
 *
 * All the data stays in the buffer. Clear the buffer before starting a new
 * batch.
 *
 * To send and clear in one step, call `line_sender_flush` instead. Also,
 * see the docs on that function for more important details on flushing.
 *
 * @param[in] sender Line sender object.
 * @param[in] buffer Line buffer object.
 * @return true on success, false on error.
 */
QUESTDB_CLIENT_API
bool line_sender_flush_and_keep(
    line_sender* sender,
    const line_sender_buffer* buffer,
    line_sender_error** err_out);

/**
 * Send the batch of rows in the buffer to the QuestDB server, and, if the
 * parameter `transactional` is true, ensure the flush will be
 * transactional.
 *
 * A flush is transactional iff all the rows belong to the same table. This
 * allows QuestDB to treat the flush as a single database transaction,
 * because it doesn't support transactions spanning multiple tables.
 * Additionally, only ILP-over-HTTP supports transactional flushes;
 * QWP/UDP is a best-effort datagram transport and has no flush-level
 * atomicity guarantee.
 *
 * If the flush wouldn't be transactional, this function returns an error
 * and doesn't flush any data.
 *
 * The function sends an HTTP request and waits for the response. If the
 * server responds with an error, it returns a descriptive error. In the
 * case of a network error, it retries until it has exhausted the retry time
 * budget.
 *
 * All the data stays in the buffer. Clear the buffer before starting a new
 * batch.
 */
QUESTDB_CLIENT_API
bool line_sender_flush_and_keep_with_flags(
    line_sender* sender,
    line_sender_buffer* buffer,
    bool transactional,
    line_sender_error** err_out);

/////////// Getting the current timestamp.

/** Get the current time in nanoseconds since the Unix epoch (UTC). */
QUESTDB_CLIENT_API
int64_t line_sender_now_nanos(void);

/** Get the current time in microseconds since the Unix epoch (UTC). */
QUESTDB_CLIENT_API
int64_t line_sender_now_micros(void);

/* -------------------------------------------------------------------------
 * Connection lifecycle events (QWP/WebSocket senders and pools)
 * ------------------------------------------------------------------------- */

/** Connection lifecycle event kinds. */
#define questdb_connection_event_connected 0u
#define questdb_connection_event_disconnected 1u
#define questdb_connection_event_reconnected 2u
#define questdb_connection_event_failed_over 3u
#define questdb_connection_event_endpoint_attempt_failed 4u
#define questdb_connection_event_all_endpoints_unreachable 5u
#define questdb_connection_event_auth_failed 6u

/** One connection-state transition. String fields are borrowed UTF-8
 * slices valid only for the duration of the callback; absent strings are
 * NULL with length 0. */
typedef struct questdb_connection_event
{
    /** One of the `questdb_connection_event_*` kind constants. */
    uint32_t kind;
    const char* host;
    size_t host_len;
    const char* port;
    size_t port_len;
    const char* previous_host;
    size_t previous_host_len;
    const char* previous_port;
    size_t previous_port_len;
    bool has_attempt;
    uint64_t attempt_number;
    bool has_cause;
    line_sender_error_code cause_code;
    const char* cause_msg;
    size_t cause_msg_len;
    /** Wall-clock time of the event, milliseconds since the Unix epoch. */
    int64_t timestamp_millis;
} questdb_connection_event;

/** Callback invoked once per connection event on the dispatcher thread.
 * The `event` pointer and every string it references are valid only for
 * the duration of the call. Must not unwind. */
typedef void (*questdb_connection_event_cb)(
    void* user_data,
    const questdb_connection_event* event);

/** Register a connection lifecycle listener on the sender being built.
 * Events are delivered on a dedicated dispatcher thread through a bounded
 * inbox (`inbox_capacity`; 0 = default 64) with a drop-oldest overflow
 * policy. The caller guarantees `user_data` is safe to use from that
 * thread. QWP/WebSocket only; at most one listener per builder. */
QUESTDB_CLIENT_API
bool line_sender_opts_connection_event_handler(
    line_sender_opts* opts,
    questdb_connection_event_cb cb,
    void* user_data,
    size_t inbox_capacity,
    line_sender_error** err_out);

/** Total connection events dropped by the sender listener inbox. */
QUESTDB_CLIENT_API
uint64_t line_sender_connection_events_dropped(const line_sender* sender);

/** Total connection events delivered to the sender listener. */
QUESTDB_CLIENT_API
uint64_t line_sender_connection_events_delivered(const line_sender* sender);

#ifdef __cplusplus
}
#endif
