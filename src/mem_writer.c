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

#include "mem_writer.h"
#include "aborting_malloc.h"

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "next_pow2.inc.c"

void mem_writer_open(mem_writer* writer, size_t capacity)
{
    if (capacity < 64)
        capacity = 64;
    capacity = next_pow2(capacity);
    writer->head = writer->tail = aborting_malloc(capacity);
    writer->end = writer->head + capacity;
}

size_t mem_writer_len(mem_writer* writer)
{
    return (size_t)(writer->tail - writer->head);
}

const char* mem_writer_peek(mem_writer* writer, size_t* len_out)
{
    *len_out = mem_writer_len(writer);
    return writer->head;
}

char* mem_writer_steal_and_close(mem_writer* writer, size_t* len_out)
{
    *len_out = mem_writer_len(writer);
    char* buf = writer->head;
    writer->head = writer->tail = writer->end = NULL;
    return buf;
}

void mem_writer_close(mem_writer* writer)
{
    size_t len = 0;
    free(mem_writer_steal_and_close(writer, &len));
}

void mem_writer_rewind(mem_writer* writer)
{
    writer->tail = writer->head;
}

#if defined(COMPILER_GNUC)
#define unlikely(x) __builtin_expect((x), 0)
#elif defined(COMPILER_MSVC)
#define unlikely(x) (x)
#endif

char* mem_writer_book(mem_writer* writer, size_t needed)
{
    if (unlikely((writer->tail + needed) >= writer->end))
    {
        const size_t len = mem_writer_len(writer);
        const size_t required_len = len + needed;
        const size_t new_capacity = next_pow2(required_len);
        writer->head = aborting_realloc(writer->head, new_capacity);
        writer->tail = writer->head + len;
        writer->end = writer->head + new_capacity;
    }
    return writer->tail;
}

void mem_writer_advance(mem_writer* writer, size_t written)
{
    writer->tail += written;
}

void mem_writer_char(mem_writer* writer, char c)
{
    *mem_writer_book(writer, 1) = c;
    mem_writer_advance(writer, 1);
}

void mem_writer_str(mem_writer* writer, size_t len, const char* buf)
{
    memcpy(mem_writer_book(writer, len), buf, len);
    mem_writer_advance(writer, len);
}

void mem_writer_vprintf(mem_writer* writer, const char* fmt, va_list ap)
{
    va_list args2;
    va_copy(args2, ap);
    size_t len = (size_t)vsnprintf(NULL, (size_t)0, fmt, ap);
    vsnprintf(mem_writer_book(writer, len + 1), len + 1, fmt, args2);
    mem_writer_advance(writer, len);
    va_end(args2);
}

void mem_writer_printf(mem_writer* writer, const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    mem_writer_vprintf(writer, fmt, args);
    va_end(args);
}

void mem_writer_i64(mem_writer* writer, int64_t num)
{
    // TODO: This is a candidate for optimisation by avoiding printf.
    // The "sse2" algorithm from https://github.com/miloyip/itoa-benchmark
    // looks pretty promising. Would want to tweak signature to return len.
    mem_writer_printf(writer, "%" PRIu64, num);
}

void mem_writer_f64(mem_writer* writer, double num)
{
    // TODO: This is a candidate for optimisation by avoiding printf.
    // The Ryu project sees appropriate here: https://github.com/ulfjack/ryu
    // Specifically the `int d2s_buffered_n(double f, char* result);` function.
    mem_writer_printf(writer, "%g", num);
}
