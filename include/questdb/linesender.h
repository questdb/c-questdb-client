#pragma once

/**
 * Connect to QuestDB and send data using the InfluxDB Line Protocol.
 *
 * Functions return `true` to indicate success.
 * In case of errors, you must always follow-up any error-yeilding call
 * with `linesender_close`.
 * 
 * Don't forget to call `flush()` or no data will be sent.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/////////// Error handling.
typedef struct linesender_error linesender_error;

/**
 * An error message may optionally be associated with an OS error.
 * Such error can then be looked up with library functions such as `strerror`.
 * An errnum of 0 indicates there was no associated OS error and it does not
 * indicate there is no error.
 */
int linesender_error_errnum(const linesender_error*);  // Returns 0 if unset.

/** ASCII encoded error message. Never returns NULL. */
const char* linesender_error_msg(const linesender_error*, size_t* len_out);

void linesender_error_free(linesender_error*);

/////////// Connecting and disconnecting.
typedef enum
{
    linesender_tcp = 1,
    linesender_udp = 2
} linesender_transport;

typedef struct linesender linesender;

linesender* linesender_connect(
    linesender_transport transport,
    const char* interface,
    const char* host,
    const char* port,
    int udp_multicast_ttl,  // UDP-only param. Ignored if `transport` is TCP.
    linesender_error** err_out);

/** True indicates an error occured previously and the sender must be closed. */
bool linesender_must_close(linesender*);

/** Close the connection. Does not flush. Non-idempotent. */
void linesender_close(linesender*);


/////////// Preparing line messages.
bool linesender_table(
    linesender*,
    size_t name_len,
    const char* name,
    linesender_error** err_out);

bool linesender_symbol(
    linesender*,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    linesender_error** err_out);

bool linesender_column_bool(
    linesender*,
    size_t name_len,
    const char* name,
    bool value,
    linesender_error** err_out);

bool linesender_column_i64(
    linesender*,
    size_t name_len,
    const char* name,
    int64_t value,
    linesender_error** err_out);

bool linesender_column_f64(
    linesender*,
    size_t name_len,
    const char* name,
    double value,
    linesender_error** err_out);

bool linesender_column_str(
    linesender*,
    size_t name_len,
    const char* name,
    size_t value_len,
    const char* value,
    linesender_error** err_out);

bool linesender_at(
    linesender*,
    int64_t epoch_nanos,
    linesender_error** err_out);

bool linesender_at_now(
    linesender*,
    linesender_error** err_out);


/////////// Committing to network.

/** Number of bytes that will be sent at next call to `linesender_flush`. */
size_t linesender_pending_size(linesender*);

/**
 * Send prepared line messages to the QuestDB server.
 *
 * When the connection was established with `linesender_udp`,
 * no single line can exceed 64000 bytes.
 */
bool linesender_flush(
    linesender*,
    linesender_error** err_out);

#ifdef __cplusplus
}
#endif
