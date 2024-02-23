/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2024 QuestDB
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

#if defined(LINESENDER_DYN_LIB) && defined(_MSC_VER)
#    define LINESENDER_API __declspec(dllimport)
#else
#    define LINESENDER_API
#endif


/////////// Error handling.
/** An error that occurred when using the line sender. */
typedef struct line_sender_error line_sender_error;

/** Category of error. */
typedef enum line_sender_error_code
{
    /** The host, port, or interface was incorrect. */
    line_sender_error_could_not_resolve_addr,

    /** Called methods in the wrong order. E.g. `symbol` after `column`. */
    line_sender_error_invalid_api_call,

    /** A network error connecting or flushing data out. */
    line_sender_error_socket_error,

    /** The string or symbol field is not encoded in valid UTF-8. */
    line_sender_error_invalid_utf8,

    /** The table name or column name contains bad characters. */
    line_sender_error_invalid_name,

    /** The supplied timestamp is invalid. */
    line_sender_error_invalid_timestamp,

    /** Error during the authentication process. */
    line_sender_error_auth_error,

    /** Error during TLS handshake. */
    line_sender_error_tls_error,

    /** The server does not support ILP over HTTP. */
    line_sender_error_http_not_supported,

    /** Error sent back from the server during flush. */
    line_sender_error_server_flush_error,

    /** Bad configuration. */
    line_sender_error_config_error,
} line_sender_error_code;

/* Certificate authority used to determine how to validate the server's TLS certificate. */
typedef enum line_sender_ca {
    /** Use the set of root certificates provided by the `webpki` crate. */
    line_sender_ca_webpki_roots,

    /** Use the set of root certificates provided by the operating system. */
    line_sender_ca_os_roots,

    /** Use the set of root certificates provided by both the `webpki` crate and the operating system. */
    line_sender_ca_webpki_and_os_roots,

    /** Use a custom root certificate `.pem` file. */
    line_sender_ca_pem_file,
} line_sender_ca;

/** Error code categorizing the error. */
LINESENDER_API
line_sender_error_code line_sender_error_get_code(const line_sender_error*);

/**
 * UTF-8 encoded error message. Never returns NULL.
 * The `len_out` argument is set to the number of bytes in the string.
 * The string is NOT null-terminated.
 */
LINESENDER_API
const char* line_sender_error_msg(const line_sender_error*, size_t* len_out);

/** Clean up the error. */
LINESENDER_API
void line_sender_error_free(line_sender_error*);


/////////// Preparing strings and names

/**
 * Non-owning validated UTF-8 encoded string.
 * The string need not be null-terminated.
 */
typedef struct line_sender_utf8
{
    // Don't initialize fields directly.
    // Call `line_sender_utf8_init` instead.
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
LINESENDER_API
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
LINESENDER_API
line_sender_utf8 line_sender_utf8_assert(size_t len, const char* buf);

#define QDB_UTF8_LITERAL(literal)                                              \
    line_sender_utf8_assert(sizeof(literal) - 1, (literal))

/**
 * Non-owning validated table, symbol or column name. UTF-8 encoded.
 * Need not be null-terminated.
 */
typedef struct line_sender_table_name
{
    // Don't initialize fields directly.
    // Call `line_sender_table_name_init` instead.
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
LINESENDER_API
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
LINESENDER_API
line_sender_table_name line_sender_table_name_assert(
    size_t len,
    const char* buf);

#define QDB_TABLE_NAME_LITERAL(literal)                                        \
    line_sender_table_name_assert(sizeof(literal) - 1, (literal))

/**
 * Non-owning validated table, symbol or column name. UTF-8 encoded.
 * Need not be null-terminated.
 */
typedef struct line_sender_column_name
{
    // Don't initialize fields directly.
    // Call `line_sender_column_name_init` instead.
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
LINESENDER_API
bool line_sender_column_name_init(
    line_sender_column_name* name,
    size_t len,
    const char* buf,
    line_sender_error** err_out);

/**
 * Construct a column name object from UTF-8 encoded buffer and length.
 * If the passed in buffer is not valid UTF-8, or is not a valid column name,
 * the program will abort.
 *
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer.
 */
LINESENDER_API
line_sender_column_name line_sender_column_name_assert(
    size_t len,
    const char* buf);

#define QDB_COLUMN_NAME_LITERAL(literal)                                       \
    line_sender_column_name_assert(sizeof(literal) - 1, (literal))


/////////// Constructing ILP messages.

/**
 * Prepare rows for sending via the line sender's `flush` function.
 * Buffer objects are re-usable and cleared automatically when flushing.
 */
typedef struct line_sender_buffer line_sender_buffer;

/** Create a buffer for serializing ILP messages. */
LINESENDER_API
line_sender_buffer* line_sender_buffer_new();

/** Create a buffer for serializing ILP messages. */
LINESENDER_API
line_sender_buffer* line_sender_buffer_with_max_name_len(size_t max_name_len);

/** Release the buffer object. */
LINESENDER_API
void line_sender_buffer_free(line_sender_buffer* buffer);

/** Create a new copy of the buffer. */
LINESENDER_API
line_sender_buffer* line_sender_buffer_clone(const line_sender_buffer* buffer);

/**
 * Pre-allocate to ensure the buffer has enough capacity for at least the
 * specified additional byte count. This may be rounded up.
 * This does not allocate if such additional capacity is already satisfied.
 * See: `capacity`.
 */
LINESENDER_API
void line_sender_buffer_reserve(
    line_sender_buffer* buffer,
    size_t additional);

/** Get the current capacity of the buffer. */
LINESENDER_API
size_t line_sender_buffer_capacity(const line_sender_buffer* buffer);

/**
 * Mark a rewind point.
 * This allows undoing accumulated changes to the buffer for one or more
 * rows by calling `rewind_to_marker`.
 * Any previous marker will be discarded.
 * Once the marker is no longer needed, call `clear_marker`.
 */
LINESENDER_API
bool line_sender_buffer_set_marker(
    line_sender_buffer* buffer,
    line_sender_error** err_out);

/**
 * Undo all changes since the last `set_marker` call.
 * As a side-effect, this also clears the marker.
 */
LINESENDER_API
bool line_sender_buffer_rewind_to_marker(
    line_sender_buffer* buffer,
    line_sender_error** err_out);

/** Discard the marker. */
LINESENDER_API
void line_sender_buffer_clear_marker(
    line_sender_buffer* buffer);

/**
 * Remove all accumulated data and prepare the buffer for new lines.
 * This does not affect the buffer's capacity.
 */
LINESENDER_API
void line_sender_buffer_clear(line_sender_buffer* buffer);

/** Number of bytes in the accumulated buffer. */
LINESENDER_API
size_t line_sender_buffer_size(const line_sender_buffer* buffer);

/** The number of rows accumulated in the buffer. */
LINESENDER_API
size_t line_sender_buffer_row_count(const line_sender_buffer* buffer);

/**
 * The buffer is transactional if sent over HTTP.
 * A buffer stops being transactional if it contains rows for multiple tables.
 */
LINESENDER_API
bool line_sender_buffer_transactional(const line_sender_buffer* buffer);

/**
 * Peek into the accumulated buffer that is to be sent out at the next `flush`.
 *
 * @param[in] buffer Line buffer object.
 * @param[out] len_out The length in bytes of the accumulated buffer.
 * @return UTF-8 encoded buffer. The buffer is not nul-terminated.
 */
LINESENDER_API
const char* line_sender_buffer_peek(
    const line_sender_buffer* buffer,
    size_t* len_out);

/**
 * Start batching the next row of input for the named table.
 * @param[in] buffer Line buffer object.
 * @param[in] name Table name.
 */
LINESENDER_API
bool line_sender_buffer_table(
    line_sender_buffer* buffer,
    line_sender_table_name name,
    line_sender_error** err_out);

/**
 * Append a value for a SYMBOL column.
 * Symbol columns must always be written before other columns for any given
 * row.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_symbol(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    line_sender_utf8 value,
    line_sender_error** err_out);

/**
 * Append a value for a BOOLEAN column.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_column_bool(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    bool value,
    line_sender_error** err_out);

/**
 * Append a value for a LONG column.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_column_i64(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int64_t value,
    line_sender_error** err_out);

/**
 * Append a value for a DOUBLE column.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_column_f64(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    double value,
    line_sender_error** err_out);

/**
 * Append a value for a STRING column.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_column_str(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    line_sender_utf8 value,
    line_sender_error** err_out);

/**
 * Append a value for a TIMESTAMP column from nanoseconds.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] nanos The timestamp in nanoseconds since the unix epoch.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_column_ts_nanos(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int64_t nanos,
    line_sender_error** err_out);

/**
 * Append a value for a TIMESTAMP column from microseconds.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] micros The timestamp in microseconds since the unix epoch.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_column_ts_micros(
    line_sender_buffer* buffer,
    line_sender_column_name name,
    int64_t micros,
    line_sender_error** err_out);

/**
 * Complete the row with a timestamp specified as nanoseconds.
 *
 * After this call, you can start batching the next row by calling
 * `table` again, or you can send the accumulated batch by
 * calling `flush`.
 *
 * If you want to pass the current system timestamp,
 * see `line_sender_now_nanos`.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] epoch_nanos Number of nanoseconds since 1st Jan 1970 UTC.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_at_nanos(
    line_sender_buffer *buffer,
    int64_t epoch_nanos,
    line_sender_error** err_out);

/**
 * Complete the row with a timestamp specified as microseconds.
 *
 * After this call, you can start batching the next row by calling
 * `table` again, or you can send the accumulated batch by
 * calling `flush`.
 *
 * If you want to pass the current system timestamp,
 * see `line_sender_now_micros`.
 *
 * @param[in] buffer Line buffer object.
 * @param[in] epoch_micros Number of microseconds since 1st Jan 1970 UTC.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_at_micros(
    line_sender_buffer *buffer,
    int64_t epoch_micros,
    line_sender_error** err_out);

/**
 * Complete the row without providing a timestamp.
 * The QuestDB instance will insert its own timestamp.
 *
 * This is NOT equivalent to calling `line_sender_buffer_at_nanos` or
 * `line_sender_buffer_at_micros` with the current time.
 * There's a trade-off: Letting the server assign the timestamp can be faster
 * since it a reliable way to avoid out-of-order operations in the database
 * for maximum ingestion throughput.
 * On the other hand, it removes the ability to deduplicate rows.
 *
 * In almost all cases, you should prefer the `line_sender_at_*` functions.
 *
 * After this call, you can start batching the next row by calling
 * `table` again, or you can send the accumulated batch by
 * calling `flush`.
 *
 * @param[in] buffer Line buffer object.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_buffer_at_now(
    line_sender_buffer* buffer,
    line_sender_error** err_out);

/////////// Connecting, sending and disconnecting.

/**
 * Insert data into QuestDB via the InfluxDB Line Protocol.
 *
 * Batch up rows in `buffer` objects, then call `flush` to send them.
 */
typedef struct line_sender line_sender;

/**
 * Accumulates parameters for creating a line sender connection.
 */
typedef struct line_sender_opts line_sender_opts;

/**
 * Create a new `ops` instance from configuration string.
 * The format of the string is: "tcp::addr=host:port;key=value;...;"
 * Alongside "tcp" you can also specify "tcps", "http", and "https".
 * The accepted set of keys and values is the same as for the opt's API.
 * E.g. "tcp::addr=host:port;user=alice;password=secret;tls_ca=os_roots;"
 */
LINESENDER_API
line_sender_opts* line_sender_opts_from_conf(
    line_sender_utf8 config,
    line_sender_error** err_out);

/**
 * Create a new `ops` instance from configuration string read from the
 * `QDB_CLIENT_CONF` environment variable.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_from_env(
    line_sender_error** err_out);

/**
 * A new set of options for a line sender connection for ILP/TCP.
 * @param[in] host The QuestDB database host.
 * @param[in] port The QuestDB ILP TCP port.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_new_tcp(
    line_sender_utf8 host,
    uint16_t port);

/**
 * Variant of line_sender_opts_new_tcp that takes a service name for port.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_new_tcp_service(
    line_sender_utf8 host,
    line_sender_utf8 port);

/**
 * A new set of options for a line sender connection for ILP/HTTP.
 * @param[in] host The QuestDB database host.
 * @param[in] port The QuestDB HTTP port.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_new_http(
    line_sender_utf8 host,
    uint16_t port);

/**
 * Variant of line_sender_opts_new_http that takes a service name for port.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_new_http_service(
    line_sender_utf8 host,
    line_sender_utf8 port);

/** 
 * Select local outbound network "bind" interface.
 *
 * This may be relevant if your machine has multiple network interfaces.
 *
 * The default is `0.0.0.0``.
 */
LINESENDER_API
bool line_sender_opts_bind_interface(
    line_sender_opts* opts,
    line_sender_utf8 bind_interface,
    line_sender_error** err_out);

/**
 * Set the username for authentication.
 * 
 * For TCP this is the `kid` part of the ECDSA key set.
 * The other fields are `token` `token_x` and `token_y`.
 * 
 * For HTTP this is part of basic authentication.
 * Also see `pass`.
 */
LINESENDER_API
bool line_sender_opts_user(
    line_sender_opts* opts,
    line_sender_utf8 user,
    line_sender_error** err_out);

/**
 * Set the password for basic HTTP authentication.
 * Also see `user`.
 */
LINESENDER_API
bool line_sender_opts_pass(
    line_sender_opts* opts,
    line_sender_utf8 pass,
    line_sender_error** err_out);

/**
 * Token (Bearer) Authentication Parameters for ILP over HTTP,
 * or the ECDSA private key for ILP over TCP authentication.
 */
LINESENDER_API
bool line_sender_opts_token(
    line_sender_opts* opts,
    line_sender_utf8 token,
    line_sender_error** err_out);

/**
 * The ECDSA public key X for ILP over TCP authentication.
 */
LINESENDER_API
bool line_sender_opts_token_x(
    line_sender_opts* opts,
    line_sender_utf8 token_x,
    line_sender_error** err_out);

/**
 * The ECDSA public key Y for ILP over TCP authentication.
 */
LINESENDER_API
bool line_sender_opts_token_y(
    line_sender_opts* opts,
    line_sender_utf8 token_y,
    line_sender_error** err_out);

/**
 * Configure how long to wait for messages from the QuestDB server during
 * the TLS handshake and authentication process.
 * The default is 15 seconds.
 */
LINESENDER_API
bool line_sender_opts_auth_timeout(
    line_sender_opts* opts,
    uint64_t millis,
    line_sender_error** err_out);

/**
 * Enable or disable TLS.
 */
LINESENDER_API
bool line_sender_opts_tls_enabled(
    line_sender_opts* opts,
    bool enabled,
    line_sender_error** err_out);

/**
 * Set to `false` to disable TLS certificate verification.
 * This should only be used for debugging purposes as it reduces security.
 * 
 * For testing consider specifying a path to a `.pem` file instead via
 * the `tls_roots` setting.
 */
LINESENDER_API
bool line_sender_opts_tls_verify(
    line_sender_opts* opts,
    bool verify,
    line_sender_error** err_out);

/**
 * Set the certificate authority used to determine how to validate the server's TLS certificate.
 */
LINESENDER_API
bool line_sender_opts_tls_ca(
    line_sender_opts* opts,
    line_sender_ca ca,
    line_sender_error** err_out);

/**
 * Set the path to a custom root certificate `.pem` file.
 * This is used to validate the server's certificate during the TLS handshake.
 * The file may be password-protected, if so, also specify the password.
 * via the `tls_roots_password` method.
 *
 * See notes on how to test with self-signed certificates:
 * https://github.com/questdb/c-questdb-client/tree/main/tls_certs.
 */
LINESENDER_API
bool line_sender_opts_tls_roots(
    line_sender_opts* opts,
    line_sender_utf8 path,
    line_sender_error** err_out);

/**
 * The maximum buffer size that the client will flush to the server.
 * The default is 100 MiB.
 */
LINESENDER_API
bool line_sender_opts_max_buf_size(
    line_sender_opts* opts,
    size_t max_buf_size,
    line_sender_error** err_out);

/**
 * Cumulative duration spent in retries.
 * Default is 10 seconds.
 */
LINESENDER_API
bool line_sender_opts_retry_timeout(
    line_sender_opts* opts,
    uint64_t millis,
    line_sender_error** err_out);

/**
 * Minimum expected throughput in bytes per second for HTTP requests.
 * If the throughput is lower than this value, the connection will time out.
 * The default is 100 KiB/s.
 * The value is expressed as a number of bytes per second.
 */
LINESENDER_API
bool line_sender_opts_min_throughput(
    line_sender_opts* opts,
    uint64_t bytes_per_sec,
    line_sender_error** err_out);

/**
 * Grace request timeout before relying on the minimum throughput logic.
 * The default is 5 seconds.
 */
LINESENDER_API
bool line_sender_opts_grace_timeout(
    line_sender_opts* opts,
    uint64_t millis,
    line_sender_error** err_out);

/**
 * Duplicate the opts object.
 * Both old and new objects will have to be freed.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_clone(
    line_sender_opts* opts);

/** Release the opts object. */
LINESENDER_API
void line_sender_opts_free(line_sender_opts* opts);

/**
 * Synchronously connect to the QuestDB database.
 * The connection should be accessed by only a single thread a time.
 * @param[in] opts Options for the connection.
 * @note The opts object is freed.
 */
LINESENDER_API
line_sender* line_sender_build(
    const line_sender_opts* opts,
    line_sender_error** err_out);

/**
 * Check if an error occurred previously and the sender must be closed.
 * @param[in] sender Line sender object.
 * @return true if an error occurred with a sender and it must be closed.
 */
LINESENDER_API
bool line_sender_must_close(const line_sender* sender);

/**
 * Close the connection. Does not flush. Non-idempotent.
 * @param[in] sender Line sender object.
 */
LINESENDER_API
void line_sender_close(line_sender* sender);

/**
 * Send buffer of rows to the QuestDB server.
 *
 * The buffer will be automatically cleared, ready for re-use.
 * If instead you want to preserve the buffer contents, call `flush_and_keep`.
 *
 * @param[in] sender Line sender object.
 * @param[in] buffer Line buffer object.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_flush(
    line_sender* sender,
    line_sender_buffer* buffer,
    line_sender_error** err_out);

/**
 * Send buffer of rows to the QuestDB server.
 *
 * The buffer will left untouched and must be cleared before re-use.
 * To send and clear in one single step, `flush` instead.
 * @param[in] sender Line sender object.
 * @param[in] buffer Line buffer object.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_flush_and_keep(
    line_sender *sender,
    const line_sender_buffer* buffer,
    line_sender_error** err_out);

/// Variant of `.flush()` that does not clear the buffer and allows for
/// transactional flushes.
///
/// A transactional flush is simply a flush that ensures that all rows in
/// the ILP buffer refer to the same table, thus allowing the server to
/// treat the flush request as a single transaction.
///
/// This is because QuestDB does not support transactions spanning multiple
/// tables.

/**
 * Variant of `.flush()` that does not clear the buffer and allows for
 * transactional flushes.
 * 
 * A transactional flush is simply a flush that ensures that all rows in
 * the ILP buffer refer to the same table, thus allowing the server to
 * treat the flush request as a single transaction.
 * 
 * This is because QuestDB does not support transactions spanning multiple
 * tables.
 */
LINESENDER_API
bool line_sender_flush_and_keep_with_flags(
    line_sender* sender,
    line_sender_buffer* buffer,
    bool transactional,
    line_sender_error** err_out);

/////////// Getting the current timestamp.

/** Get the current time in nanoseconds since the unix epoch (UTC). */
LINESENDER_API
int64_t line_sender_now_nanos();

/** Get the current time in microseconds since the unix epoch (UTC). */
LINESENDER_API
int64_t line_sender_now_micros();


#ifdef __cplusplus
}
#endif
