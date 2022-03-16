#pragma once

/**
 * Connect to QuestDB and send data using the InfluxDB Line Protocol.
 *
 * Functions return `true` to indicate success.
 * In case of errors, you must always follow-up any error-yeilding call
 * with `line_sender_close`.
 * 
 * Don't forget to call `flush()` or no data will be sent.
 */

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
typedef struct line_sender_error line_sender_error;

typedef enum line_sender_error_code
{
    line_sender_error_could_not_resolve_addr,
    line_sender_error_invalid_api_call,
    line_sender_error_socket_error,
    line_sender_error_invalid_utf8,
    line_sender_error_invalid_identifier
} line_sender_error_code;

/** Error code describing the error. */
LINESENDER_API
line_sender_error_code line_sender_error_get_code(const line_sender_error*);

/** ASCII encoded error message. Never returns NULL. */
LINESENDER_API
const char* line_sender_error_msg(const line_sender_error*, size_t* len_out);

LINESENDER_API
void line_sender_error_free(line_sender_error*);

/////////// Connecting and disconnecting.
typedef struct line_sender line_sender;

LINESENDER_API
line_sender* line_sender_connect(
    const char* interface,  // if unsure pass "0.0.0.0"
    const char* host,
    const char* port,
    line_sender_error** err_out);

/** True indicates an error occured previously and the sender must be closed. */
LINESENDER_API
bool line_sender_must_close(line_sender*);

/** Close the connection. Does not flush. Non-idempotent. */
LINESENDER_API
void line_sender_close(line_sender*);


/////////// Preparing line messages.
LINESENDER_API
bool line_sender_table(
    line_sender*,
    size_t name_len,
    const char* name,
    line_sender_error** err_out);

LINESENDER_API
bool line_sender_symbol(
    line_sender*,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    line_sender_error** err_out);

LINESENDER_API
bool line_sender_column_bool(
    line_sender*,
    size_t name_len,
    const char* name,
    bool value,
    line_sender_error** err_out);

LINESENDER_API
bool line_sender_column_i64(
    line_sender*,
    size_t name_len,
    const char* name,
    int64_t value,
    line_sender_error** err_out);

LINESENDER_API
bool line_sender_column_f64(
    line_sender*,
    size_t name_len,
    const char* name,
    double value,
    line_sender_error** err_out);

LINESENDER_API
bool line_sender_column_str(
    line_sender*,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    line_sender_error** err_out);

LINESENDER_API
bool line_sender_at(
    line_sender*,
    int64_t epoch_nanos,
    line_sender_error** err_out);

LINESENDER_API
bool line_sender_at_now(
    line_sender*,
    line_sender_error** err_out);


/////////// Committing to network.

/** Number of bytes that will be sent at next call to `line_sender_flush`. */
LINESENDER_API
size_t line_sender_pending_size(line_sender*);

/**
 * Send prepared line messages to the QuestDB server.
 */
LINESENDER_API
bool line_sender_flush(
    line_sender*,
    line_sender_error** err_out);

#ifdef __cplusplus
}
#endif
