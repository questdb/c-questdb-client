#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

typedef struct memwriter {
    char* head;
    char* tail;
    char* end;
} memwriter;

void memwriter_open(memwriter* writer, size_t capacity);

size_t memwriter_len(memwriter* writer);

const char* memwriter_peek(memwriter* writer, size_t* len_out);

char* memwriter_steal_and_close(memwriter* writer, size_t* len_out);

void memwriter_close(memwriter* writer);

void memwriter_rewind(memwriter* writer);

char* memwriter_book(memwriter* writer, size_t needed);

void memwriter_advance(memwriter* writer, size_t written);

void memwriter_char(memwriter* writer, char c);

void memwriter_str(memwriter* writer, size_t len, const char* buf);

void memwriter_printf(memwriter* writer, const char* fmt, ...)
    __attribute__ ((format (printf, 2, 3)));

void memwriter_vprintf(memwriter* writer, const char* fmt, va_list ap);

void memwriter_i64(memwriter* writer, int64_t num);

void memwriter_f64(memwriter* writer, double num);
