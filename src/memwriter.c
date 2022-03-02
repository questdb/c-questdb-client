#include "memwriter.h"
#include "aborting_malloc.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

/**
 * Calculate the next power of two.
 *
 * Here are some example inputs / outputs to understand behaviour:
 *     next_pow2(0): 1
 *     next_pow2(1): 2
 *     next_pow2(2): 2
 *     next_pow2(3): 4
 *     next_pow2(4): 4
 *     next_pow2(5): 8
 *     next_pow2(6): 8
 *     next_pow2(7): 8
 *     next_pow2(8): 8
 *
 * Note that 0 is a special case that returns 1.
 */
static size_t next_pow2(size_t n)
{
    // See: https://jameshfisher.com/2018/03/30/round-up-power-2/
    // We don't care about the 0 case as we ensure our malloc
    // size is never below 64.
    _Static_assert(sizeof(size_t) == 8, "64-bit only support");
    return ((size_t)1) << (64 - __builtin_clzl(n - 1));
}

void memwriter_open(memwriter* writer, size_t capacity)
{
    if (capacity < 64)
        capacity = 64;
    capacity = next_pow2(capacity);
    writer->head = writer->tail = aborting_malloc(capacity);
    writer->end = writer->head + capacity;
}

size_t memwriter_len(memwriter* writer)
{
    return (size_t)(writer->tail - writer->head);
}

const char* memwriter_peek(memwriter* writer, size_t* len_out)
{
    *len_out = memwriter_len(writer);
    return writer->head;
}

char* memwriter_steal_and_close(memwriter* writer, size_t* len_out)
{
    *len_out = memwriter_len(writer);
    char* buf = writer->head;
    writer->head = writer->tail = writer->end = NULL;
    return buf;
}

void memwriter_close(memwriter* writer)
{
    size_t len = 0;
    free(memwriter_steal_and_close(writer, &len));
}

void memwriter_rewind(memwriter* writer)
{
    writer->tail = writer->head;
}

#define unlikely(x) __builtin_expect((x),0)

char* memwriter_book(memwriter* writer, size_t needed)
{
    if (unlikely((writer->tail + needed) >= writer->end))
    {
        const size_t len = memwriter_len(writer);
        const size_t required_len = len + needed;
        const size_t new_capacity = next_pow2(required_len);
        writer->head = aborting_realloc(writer->head, new_capacity);
        writer->tail = writer->head + len;
        writer->end = writer->head + new_capacity;
    }
    return writer->tail;
}

void memwriter_advance(memwriter* writer, size_t written)
{
    writer->tail += written;
}

void memwriter_char(memwriter* writer, char c)
{
    *memwriter_book(writer, 1) = c;
    memwriter_advance(writer, 1);
}

void memwriter_str(memwriter* writer, size_t len, const char* buf)
{
    memcpy(memwriter_book(writer, len), buf, len);
    memwriter_advance(writer, len);
}

void memwriter_vprintf(memwriter* writer, const char* fmt, va_list ap)
{
    va_list args2;
    va_copy(args2, ap);
    size_t len = (size_t)vsnprintf(NULL, (size_t)0, fmt, ap);
    vsnprintf(memwriter_book(writer, len + 1), len + 1, fmt, args2);
    memwriter_advance(writer, len);
    va_end(args2);
}

void memwriter_printf(memwriter* writer, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    memwriter_vprintf(writer, fmt, args);
    va_end(args);
}

void memwriter_i64(memwriter* writer, int64_t num)
{
    // TODO: This is a candidate for optimisation by avoiding printf.
    // The "sse2" algorithm from https://github.com/miloyip/itoa-benchmark
    // looks pretty promising. Would want to tweak signature to return len.
    memwriter_printf(writer, "%" PRIu64, num);
}

void memwriter_f64(memwriter* writer, double num)
{
    // TODO: This is a candidate for optimisation by avoiding printf.
    // The Ryu project sees appropriate here: https://github.com/ulfjack/ryu
    // Specifically the `int d2s_buffered_n(double f, char* result);` function.
    memwriter_printf(writer, "%g", num);
}
