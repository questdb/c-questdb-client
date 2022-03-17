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

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

typedef struct mem_writer {
    char* head;
    char* tail;
    char* end;
} mem_writer;

void mem_writer_open(mem_writer* writer, size_t capacity);

size_t mem_writer_len(mem_writer* writer);

const char* mem_writer_peek(mem_writer* writer, size_t* len_out);

char* mem_writer_steal_and_close(mem_writer* writer, size_t* len_out);

void mem_writer_close(mem_writer* writer);

void mem_writer_rewind(mem_writer* writer);

char* mem_writer_book(mem_writer* writer, size_t needed);

void mem_writer_advance(mem_writer* writer, size_t written);

void mem_writer_char(mem_writer* writer, char c);

void mem_writer_str(mem_writer* writer, size_t len, const char* buf);

void mem_writer_printf(mem_writer* writer, const char* fmt, ...)
#ifndef _MSC_VER
    __attribute__ ((format (printf, 2, 3)))
#endif
    ;

void mem_writer_vprintf(mem_writer* writer, const char* fmt, va_list ap);

void mem_writer_i64(mem_writer* writer, int64_t num);

void mem_writer_f64(mem_writer* writer, double num);
