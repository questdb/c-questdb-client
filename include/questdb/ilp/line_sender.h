/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2022 QuestDB
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

#if defined(LINESENDER_DYN_LIB)
#    if defined(_MSC_VER)
#        if defined(LINESENDER_EXPORTS)
#            define LINESENDER_API __declspec(dllexport)
#        else
#            define LINESENDER_API __declspec(dllimport)
#        endif
#    elif (__GNUC__ >= 4)
#        define LINESENDER_API __attribute__ ((visibility("default")))
#    else
#        error "Compiler unsupported or badly detected."
#    endif
#else
#    define LINESENDER_API
#endif


/////////// Error handling.
/** An error that occured when using the line sender. */
typedef struct line_sender_error line_sender_error;

/** Category of error. */
typedef enum line_sender_error_code
{
    /** The host, port, or interface was incorrect. */
    line_sender_error_could_not_resolve_addr,

    /** Called methods in the wrong order. E.g. `symbol` after `column`. */
    line_sender_error_invalid_api_call,

    /** A network error connecting of flushing data out. */
    line_sender_error_socket_error,

    /** The string or symbol field is not encoded in valid UTF-8. */
    line_sender_error_invalid_utf8,

    /** The table name, symbol name or column name contains bad characters. */
    line_sender_error_invalid_name
} line_sender_error_code;

/** Error code categorising the error. */
LINESENDER_API
line_sender_error_code line_sender_error_get_code(const line_sender_error*);

/** ASCII encoded error message. Never returns NULL. */
LINESENDER_API
const char* line_sender_error_msg(const line_sender_error*, size_t* len_out);

/** Clean up the error. */
LINESENDER_API
void line_sender_error_free(line_sender_error*);


/////////// Preparing strings and names

/** Non-owning validated UTF-8 encoded string. */
typedef struct line_sender_utf8
{
    // Don't initialize fields directly.
    // Call `line_sender_utf8_validate` instead.
    size_t len;
    const char* buf;
} line_sender_utf8;

/**
 * Check the provided buffer is a valid UTF-8 encoded string.
 *
 * @param[out] str The object to be initialized.
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_utf8_init(
    line_sender_utf8* str,
    size_t len,
    const char* buf,
    line_sender_error** err_out);

/** Non-owning validated table, symbol or column name. UTF-8 encoded. */
typedef struct line_sender_name
{
    // Don't initialize fields directly.
    // Call `line_sender_name_validate` instead.
    size_t len;
    const char* buf;
} line_sender_name;

/**
 * Check the provided buffer is a valid UTF-8 encoded string that can be
 * used as a table name, symbol name or column name.
 *
 * The string must not contain the following characters:
 * `?`, `.`,  `,`, `'`, `"`, `\`, `/`, `:`, `(`, `)`, `+`, `-`, `*`, `%`, `~`,
 * `' '` (space), `\0` (nul terminator), \uFEFF (ZERO WIDTH NO-BREAK SPACE).
 *
 * @param[out] name The object to be initialized.
 * @param[in] len Length in bytes of the buffer.
 * @param[in] buf UTF-8 encoded buffer.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_name_init(
    line_sender_name* name,
    size_t len,
    const char* buf,
    line_sender_error** err_out);


/////////// Connecting and disconnecting.

/**
 * Insert data into QuestDB via the InfluxDB Line Protocol.
 *
 * Batch up rows, then call `line_sender_flush` to send.
 */
typedef struct line_sender line_sender;

/**
 * Synchronously connect to the QuestDB database.
 * @param[in] net_interface Network interface to bind to.
 * If unsure, to bind to all specify "0.0.0.0".
 * @param[in] host QuestDB host, e.g. "localhost". nul-terminated.
 * @param[in] port QuestDB port, e.g. "9009". nul-terminated.
 * @param[out] err_out Set on error.
 * @return Connected sender object or NULL on error.
 */
LINESENDER_API
line_sender* line_sender_connect(
    const char* net_interface,
    const char* host,
    const char* port,
    line_sender_error** err_out);

/**
 * Check if an error occured previously and the sender must be closed.
 * @param[in] sender Line sender object.
 * @return true if an error occured with a sender and it must be closed.
 */
LINESENDER_API
bool line_sender_must_close(const line_sender* sender);

/**
 * Close the connection. Does not flush. Non-idempotent.
 * @param[in] sender Line sender object.
 */
LINESENDER_API
void line_sender_close(line_sender* sender);


/////////// Preparing line messages.

/**
 * Start batching the next row of input for the named table.
 * @param[in] sender Line sender object.
 * @param[in] name Table name.
 */
LINESENDER_API
bool line_sender_table(
    line_sender* sender,
    line_sender_name name,
    line_sender_error** err_out);

/**
 * Append a value for a SYMBOL column.
 * Symbol columns must always be written before other columns for any given row.
 * @param[in] sender Line sender object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_symbol(
    line_sender* sender,
    line_sender_name name,
    line_sender_utf8 value,
    line_sender_error** err_out);

/**
 * Append a value for a BOOLEAN column.
 * @param[in] sender Line sender object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_column_bool(
    line_sender* sender,
    line_sender_name name,
    bool value,
    line_sender_error** err_out);

/**
 * Append a value for a LONG column.
 * @param[in] sender Line sender object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_column_i64(
    line_sender* sender,
    line_sender_name name,
    int64_t value,
    line_sender_error** err_out);

/**
 * Append a value for a DOUBLE column.
 * @param[in] sender Line sender object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_column_f64(
    line_sender* sender,
    line_sender_name name,
    double value,
    line_sender_error** err_out);

/**
 * Append a value for a STRING column.
 * @param[in] sender Line sender object.
 * @param[in] name Column name.
 * @param[in] value Column value.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_column_str(
    line_sender* sender,
    line_sender_name name,
    line_sender_utf8 value,
    line_sender_error** err_out);

/**
 * Complete the row with a specified timestamp.
 *
 * After this call, you can start batching the next row by calling
 * `line_sender_table` again, or you can send the accumulated batch by
 * calling `line_sender_flush`.
 *
 * @param[in] sender Line sender object.
 * @param[in] epoch_nanos Number of nanoseconds since 1st Jan 1970 UTC.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_at(
    line_sender* sender,
    int64_t epoch_nanos,
    line_sender_error** err_out);

/**
 * Complete the row without providing a timestamp.
 * The QuestDB instance will insert its own timestamp.
 *
 * After this call, you can start batching the next row by calling
 * `line_sender_table` again, or you can send the accumulated batch by
 * calling `line_sender_flush`.
 *
 * @param[in] sender Line sender object.
 * @param[out] err_out Set on error.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_at_now(
    line_sender* sender,
    line_sender_error** err_out);


/////////// Committing to network.

/**
 * Number of bytes that will be sent at next call to `line_sender_flush`.
 *
 * @param[in] sender Line sender object.
 * @return Accumulated batch size.
 */
LINESENDER_API
size_t line_sender_pending_size(const line_sender* sender);

/**
 * Send batch-up rows messages to the QuestDB server.
 *
 * After sending a batch, you can close the connection or begin preparing
 * a new batch by calling `line_sender_table`.
 *
 * @param[in] sender Line sender object.
 * @return true on success, false on error.
 */
LINESENDER_API
bool line_sender_flush(
    line_sender* sender,
    line_sender_error** err_out);

#ifdef __cplusplus
}
#endif
