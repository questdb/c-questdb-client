#include "memwriter.h"
#include "aborting_malloc.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "next_pow2.inc.c"

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

#if defined(COMPILER_GNUC)
#define unlikely(x) __builtin_expect((x), 0)
#elif defined(COMPILER_MSVC)
#define unlikely(x) (x)
#endif

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
