#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct utf8_error
{
    /** Count of valid bytes before error. */
    size_t valid_up_to;

    /** Reached end of string, more input required. */
    bool need_more;

    /**
     * Index of first invalid byte (0, 1, 2 or 3) as offset from
     * `valid_up_to`.
     * This value is only set if `need_more == false` and set to
     * 0 otherwise.
     */
    uint8_t error_len;
} utf8_error;

/**
 * Check if the buffer is decodable as valid UTF-8.
 *
 * @param len Length in bytes of the buffer.
 * @param buf Buffer
 * @param err_out Error details.
 * @return true If the string could be valid UTF-8.
 */
bool utf8_check(size_t len, const char* buf, utf8_error* err_out);

#ifdef __cplusplus
}
#endif
