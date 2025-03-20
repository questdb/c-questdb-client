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
} line_sender_protocol;

/** Possible sources of the root certificates used to validate the server's TLS certificate. */
typedef enum line_sender_ca {
    /** Use the set of root certificates provided by the `webpki` crate. */
    line_sender_ca_webpki_roots,

    /** Use the set of root certificates provided by the operating system. */
    line_sender_ca_os_roots,

    /** Combine the set of root certificates provided by the `webpki` crate and the operating system. */
    line_sender_ca_webpki_and_os_roots,

    /** Use the root certificates provided in a PEM-encoded file. */
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
 * Non-owning view of sender buffer, Modifying the buffer will invalidate the
 * borrowed buffer
 */
typedef struct line_sender_buffer_view {
  size_t len;
  // clang-format off
  const uint8_t* buf;
  // clang-format on
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
 * Accumulates a batch of rows to be sent via `line_sender_flush()` or its
 * variants. A buffer object can be reused after flushing and clearing.
 */
typedef struct line_sender_buffer line_sender_buffer;

/**
 * Construct a `line_sender_buffer` with a `max_name_len` of `127`, which is the
 * same as the QuestDB server default.
 */
LINESENDER_API
line_sender_buffer* line_sender_buffer_new();

/**
 * Construct a `line_sender_buffer` with a custom maximum length for table and
 * column names. This should match the `cairo.max.file.name.length` setting of
 * the QuestDB  server you're connecting to.
 * If the server does not configure it, the default is `127`, and you can
 * call `line_sender_buffer_new()` instead.
 */
LINESENDER_API
line_sender_buffer* line_sender_buffer_with_max_name_len(size_t max_name_len);

/** Release the `line_sender_buffer` object. */
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
 * rows by calling `rewind_to_marker()`.
 * Any previous marker will be discarded.
 * Once the marker is no longer needed, call `clear_marker()`.
 */
LINESENDER_API
bool line_sender_buffer_set_marker(
    line_sender_buffer* buffer,
    line_sender_error** err_out);

/**
 * Undo all changes since the last `set_marker()` call.
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

/** The number of bytes accumulated in the buffer. */
LINESENDER_API
size_t line_sender_buffer_size(const line_sender_buffer* buffer);

/** The number of rows accumulated in the buffer. */
LINESENDER_API
size_t line_sender_buffer_row_count(const line_sender_buffer* buffer);

/**
 * Tell whether the buffer is transactional. It is transactional iff it contains
 * data for at most one table. Additionally, you must send the buffer over HTTP to
 * get transactional behavior.
 */
LINESENDER_API
bool line_sender_buffer_transactional(const line_sender_buffer* buffer);

/**
 * Get a read-only view into the buffer's bytes contents.
 *
 * @param[in] buffer Line sender buffer object.
 * @return read_only view with the byte representation of the line
 *         sender buffer's contents.
 */
LINESENDER_API
line_sender_buffer_view
line_sender_buffer_peek(const line_sender_buffer *buffer);

/**
 * Start recording a new row for the given table.
 * @param[in] buffer Line buffer object.
 * @param[in] name Table name.
 */
LINESENDER_API
bool line_sender_buffer_table(
    line_sender_buffer* buffer,
    line_sender_table_name name,
    line_sender_error** err_out);

/**
 * Record a symbol value for the given column.
 * Make sure you record all the symbol columns before any other column type.
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
 * Record a boolean value for the given column.
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
 * Record an integer value for the given column.
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
 * Record a floating-point value for the given column.
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
 * Record a string value for the given column.
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
 * Record a nanosecond timestamp value for the given column.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] nanos The timestamp in nanoseconds since the Unix epoch.
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
 * Record a microsecond timestamp value for the given column.
 * @param[in] buffer Line buffer object.
 * @param[in] name Column name.
 * @param[in] micros The timestamp in microseconds since the Unix epoch.
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
LINESENDER_API
bool line_sender_buffer_at_nanos(
    line_sender_buffer *buffer,
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
LINESENDER_API
bool line_sender_buffer_at_micros(
    line_sender_buffer *buffer,
    int64_t epoch_micros,
    line_sender_error** err_out);

/**
 * Complete the current row without providing a timestamp. The QuestDB instance
 * will insert its own timestamp.
 *
 * Letting the server assign the timestamp can be faster since it a reliable way
 * to avoid out-of-order operations in the database for maximum ingestion
 * throughput. However, it removes the ability to deduplicate rows.
 *
 * This is NOT equivalent to calling `line_sender_buffer_at_nanos()` or
 * `line_sender_buffer_at_micros()` with the current time: the QuestDB server
 * will set the timestamp only after receiving the row. If you're flushing
 * infrequently, the server-assigned timestamp may be significantly behind the
 * time the data was recorded in the buffer.
 *
 * In almost all cases, you should prefer the `line_sender_buffer_at_*()` functions.
 *
 * After this call, you can start recording the next row by calling `table()`
 * again, or you can send the accumulated batch by calling `flush()` or one of
 * its variants.
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
 * Inserts data into QuestDB via the InfluxDB Line Protocol.
 *
 * Batch up rows in a `line_sender_buffer`, then call `line_sender_flush()` or
 * one of its variants with this object to send them.
 */
typedef struct line_sender line_sender;

/**
 * Accumulates parameters for a new `line_sender` object.
 */
typedef struct line_sender_opts line_sender_opts;

/**
 * Create a new `line_sender_opts` instance from the given configuration string.
 * The format of the string is: "tcp::addr=host:port;key=value;...;"
 * Instead of "tcp" you can also specify "tcps", "http", and "https".
 *
 * The accepted keys match one-for-one with the functions on `line_sender_opts`.
 * For example, this is a valid configuration string:
 *
 * "https::addr=host:port;username=alice;password=secret;"
 *
 * and there are matching functions `line_sender_opts_username()` and
 * `line_sender_opts_password()`. The value for `addr=` is supplied directly to
 * `line_sender_opts_new`, so there's no function with a matching name.
 *
 * For the full list of keys, search this header for `bool line_sender_opts_`.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_from_conf(
    line_sender_utf8 config,
    line_sender_error** err_out);

/**
 * Create a new `line_sender_opts` instance from the configuration stored in the
 * `QDB_CLIENT_CONF` environment variable.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_from_env(
    line_sender_error** err_out);

/**
 * Create a new `line_sender_opts` instance with the given protocol, hostname and
 * port.
 * @param[in] protocol The protocol to use.
 * @param[in] host The QuestDB database host.
 * @param[in] port The QuestDB ILP TCP port.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_new(
    line_sender_protocol protocol,
    line_sender_utf8 host,
    uint16_t port);

/**
 * Create a new `line_sender_opts` instance with the given protocol, hostname and
 * service name.
 */
LINESENDER_API
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
LINESENDER_API
bool line_sender_opts_bind_interface(
    line_sender_opts* opts,
    line_sender_utf8 bind_interface,
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
LINESENDER_API
bool line_sender_opts_username(
    line_sender_opts* opts,
    line_sender_utf8 username,
    line_sender_error** err_out);

/**
 * Set the password for basic HTTP authentication.
 * See also: `line_sender_opts_username()`.
 */
LINESENDER_API
bool line_sender_opts_password(
    line_sender_opts* opts,
    line_sender_utf8 password,
    line_sender_error** err_out);

/**
 * Set the Token (Bearer) Authentication parameter for HTTP,
 * or the ECDSA private key for TCP authentication.
 */
LINESENDER_API
bool line_sender_opts_token(
    line_sender_opts* opts,
    line_sender_utf8 token,
    line_sender_error** err_out);

/**
 * Set the ECDSA public key X for TCP authentication.
 */
LINESENDER_API
bool line_sender_opts_token_x(
    line_sender_opts* opts,
    line_sender_utf8 token_x,
    line_sender_error** err_out);

/**
 * Set the ECDSA public key Y for TCP authentication.
 */
LINESENDER_API
bool line_sender_opts_token_y(
    line_sender_opts* opts,
    line_sender_utf8 token_y,
    line_sender_error** err_out);

/**
 * Configure how long to wait for messages from the QuestDB server during
 * the TLS handshake and authentication process.
 * The value is in milliseconds, and the default is 15 seconds.
 */
LINESENDER_API
bool line_sender_opts_auth_timeout(
    line_sender_opts* opts,
    uint64_t millis,
    line_sender_error** err_out);

/**
 * Set to `false` to disable TLS certificate verification.
 * This should only be used for debugging purposes as it reduces security.
 *
 * For testing, consider specifying a path to a `.pem` file instead via
 * the `tls_roots` setting.
 */
LINESENDER_API
bool line_sender_opts_tls_verify(
    line_sender_opts* opts,
    bool verify,
    line_sender_error** err_out);

/**
 * Specify where to find the root certificates used to validate the
 * server's TLS certificate.
 */
LINESENDER_API
bool line_sender_opts_tls_ca(
    line_sender_opts* opts,
    line_sender_ca ca,
    line_sender_error** err_out);

/**
 * Set the path to a custom root certificate `.pem` file.
 * This is used to validate the server's certificate during the TLS handshake.
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
 * Set the maximum buffer size in bytes that the client will flush to the server.
 * The default is 100 MiB.
 */
LINESENDER_API
bool line_sender_opts_max_buf_size(
    line_sender_opts* opts,
    size_t max_buf_size,
    line_sender_error** err_out);

/**
 * Set the cumulative duration spent in retries.
 * The value is in milliseconds, and the default is 10 seconds.
 */
LINESENDER_API
bool line_sender_opts_retry_timeout(
    line_sender_opts* opts,
    uint64_t millis,
    line_sender_error** err_out);

/**
 * Set the minimum acceptable throughput while sending a buffer to the server.
 * The sender will divide the payload size by this number to determine for how
 * long to keep sending the payload before timing out.
 * The value is in bytes per second, and the default is 100 KiB/s.
 * The timeout calculated from minimum throughput is adedd to the value of
 * `request_timeout`.
 *
 * See also: `line_sender_opts_request_timeout()`
 */
LINESENDER_API
bool line_sender_opts_request_min_throughput(
    line_sender_opts* opts,
    uint64_t bytes_per_sec,
    line_sender_error** err_out);

/**
 * Set the additional time to wait on top of that calculated from the minimum
 * throughput. This accounts for the fixed latency of the HTTP request-response
 * roundtrip. The value is in milliseconds, and the default is 10 seconds.
 *
 * See also: `line_sender_opts_request_min_throughput()`
 */
LINESENDER_API
bool line_sender_opts_request_timeout(
    line_sender_opts* opts,
    uint64_t millis,
    line_sender_error** err_out);

// Do not call: Private API for the C++ and Python bindings.
bool line_sender_opts_user_agent(
    line_sender_opts* opts,
    line_sender_utf8 user_agent,
    line_sender_error** err_out);

/**
 * Duplicate the `line_sender_opts` object.
 * Both old and new objects will have to be freed.
 */
LINESENDER_API
line_sender_opts* line_sender_opts_clone(
    line_sender_opts* opts);

/** Release the `line_sender_opts` object. */
LINESENDER_API
void line_sender_opts_free(line_sender_opts* opts);

/**
 * Create a new line sender instance from the given options object.
 *
 * In the case of TCP, this synchronously establishes the TCP connection, and
 * returns once the connection is fully established. If the connection
 * requires authentication or TLS, these will also be completed before
 * returning.
 *
 * The sender should be accessed by only a single thread a time.
 * @param[in] opts Options for the connection.
 * @note The opts object is freed.
 */
LINESENDER_API
line_sender* line_sender_build(
    const line_sender_opts* opts,
    line_sender_error** err_out);

/**
 * Create a new line sender instance from the given configuration string.
 * The format of the string is: "tcp::addr=host:port;key=value;...;"
 * Instead of "tcp" you can also specify "tcps", "http", and "https".
 *
 * The accepted keys match one-for-one with the functions on `line_sender_opts`.
 * For example, this is a valid configuration string:
 *
 * "https::addr=host:port;username=alice;password=secret;"
 *
 * and there are matching functions `line_sender_opts_username()` and
 * `line_sender_opts_password()`. The value for `addr=` is supplied directly to
 * `line_sender_opts_new`, so there's no function with a matching name.
 *
 * For the full list of keys, search this header for `bool line_sender_opts_`.
 *
 * In the case of TCP, this synchronously establishes the TCP connection, and
 * returns once the connection is fully established. If the connection
 * requires authentication or TLS, these will also be completed before
 * returning.
 *
 * The sender should be accessed by only a single thread a time.
 */
LINESENDER_API
line_sender* line_sender_from_conf(
    line_sender_utf8 config,
    line_sender_error** err_out);

/**
 * Create a new `line_sender` instance from the configuration stored in the
 * `QDB_CLIENT_CONF` environment variable.
 *
 * In the case of TCP, this synchronously establishes the TCP connection, and
 * returns once the connection is fully established. If the connection
 * requires authentication or TLS, these will also be completed before
 * returning.
 *
 * The sender should be accessed by only a single thread a time.
 */
LINESENDER_API
line_sender* line_sender_from_env(
    line_sender_error** err_out);

/**
 * Tell whether the sender is no longer usable and must be closed.
 * This happens when there was an earlier failure.
 * This fuction is specific to TCP and is not relevant for HTTP.
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
 * Send the given buffer of rows to the QuestDB server, clearing the buffer.
 *
 * After this function returns, the buffer is empty and ready for the next batch.
 * If you want to preserve the buffer contents, call `line_sender_flush_and_keep`.
 * If you want to ensure the flush is transactional, call
 * `line_sender_flush_and_keep_with_flags`.
 *
 * With ILP-over-HTTP, this function sends an HTTP request and waits for the
 * response. If the server responds with an error, it returns a descriptive error.
 * In the case of a network error, it retries until it has exhausted the retry time
 * budget.
 *
 * With ILP-over-TCP, the function blocks only until the buffer is flushed to the
 * underlying OS-level network socket, without waiting to actually send it to the
 * server. In the case of an error, the server will quietly disconnect: consult the
 * server logs for error messages.
 *
 * HTTP should be the first choice, but use TCP if you need to continuously send
 * data to the server at a high rate.
 *
 * To improve the HTTP performance, send larger buffers (with more rows), and
 * consider parallelizing writes using multiple senders from multiple threads.
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
 * Send the given buffer of rows to the QuestDB server.
 *
 * All the data stays in the buffer. Clear the buffer before starting a new batch.
 *
 * To send and clear in one step, call `line_sender_flush` instead. Also, see the docs
 * on that function for more important details on flushing.
 * @param[in] sender Line sender object.
 * @param[in] buffer Line buffer object.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_flush_and_keep(
    line_sender *sender,
    const line_sender_buffer* buffer,
    line_sender_error** err_out);

/**
 * Send the batch of rows in the buffer to the QuestDB server, and, if the parameter
 * `transactional` is true, ensure the flush will be transactional.
 *
 * A flush is transactional iff all the rows belong to the same table. This allows
 * QuestDB to treat the flush as a single database transaction, because it doesn't
 * support transactions spanning multiple tables. Additionally, only ILP-over-HTTP
 * supports transactional flushes.
 *
 * If the flush wouldn't be transactional, this function returns an error and
 * doesn't flush any data.
 *
 * The function sends an HTTP request and waits for the response. If the server
 * responds with an error, it returns a descriptive error. In the case of a network
 * error, it retries until it has exhausted the retry time budget.
 *
 * All the data stays in the buffer. Clear the buffer before starting a new batch.
 */
LINESENDER_API
bool line_sender_flush_and_keep_with_flags(
    line_sender* sender,
    line_sender_buffer* buffer,
    bool transactional,
    line_sender_error** err_out);

/////////// Getting the current timestamp.

/** Get the current time in nanoseconds since the Unix epoch (UTC). */
LINESENDER_API
int64_t line_sender_now_nanos();

/** Get the current time in microseconds since the Unix epoch (UTC). */
LINESENDER_API
int64_t line_sender_now_micros();


#ifdef __cplusplus
}
#endif
