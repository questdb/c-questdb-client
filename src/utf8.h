/**
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without
 * limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software
 * is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions
 * of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
 * ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
 * SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

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
