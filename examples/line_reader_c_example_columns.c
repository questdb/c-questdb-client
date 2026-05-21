/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2026 QuestDB
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

/* Columnar bulk-read example for the QWP egress reader (C).
 *
 * Demonstrates `line_reader_cursor_next_batch` +
 * `line_reader_batch_column_data` / `_array_column_data` / `_symbol_dict`.
 * One FFI call per column rather than one per cell — the path Cython /
 * numpy / pandas bindings should use for zero-copy column construction.
 * Per-cell reads go through the `line_reader_column_data_get_*` inline
 * helpers declared in the same header (alignment-safe `memcpy` under the
 * hood; the compiler lowers each call to a single unaligned MOV). */

#include <questdb/egress/line_reader.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t* p, size_t n)
{
    for (size_t i = 0; i < n; ++i) printf("%02x", p[i]);
}

static int print_scalar_column(
    const line_reader_batch* batch, size_t col_idx, line_reader_error** err)
{
    line_reader_column_data d = {0};
    if (!line_reader_batch_column_data(batch, col_idx, &d, err)) return -1;

    /* For SYMBOL columns we resolve dict codes per row; fetch the dict
     * snapshot once outside the row loop. */
    line_reader_symbol_dict dict = {0};
    if (d.kind == line_reader_column_kind_symbol
        && !line_reader_batch_symbol_dict(batch, &dict, err))
        return -1;

    for (size_t r = 0; r < d.row_count; ++r)
    {
        if (line_reader_column_data_is_null(&d, r))
        {
            printf("NULL\t");
            continue;
        }
        bool is_null;
        switch (d.kind)
        {
        case line_reader_column_kind_boolean:
            printf("%s\t",
                   line_reader_column_data_get_bool(&d, r, &is_null)
                       ? "true" : "false");
            break;
        case line_reader_column_kind_byte:
            printf("%d\t", line_reader_column_data_get_i8(&d, r, &is_null));
            break;
        case line_reader_column_kind_short:
            printf("%d\t", line_reader_column_data_get_i16(&d, r, &is_null));
            break;
        case line_reader_column_kind_char:
            printf("U+%04X\t",
                   line_reader_column_data_get_char(&d, r, &is_null));
            break;
        case line_reader_column_kind_int:
            printf("%" PRId32 "\t",
                   line_reader_column_data_get_i32(&d, r, &is_null));
            break;
        case line_reader_column_kind_ipv4:
        {
            const uint32_t v =
                line_reader_column_data_get_ipv4(&d, r, &is_null);
            printf("%u.%u.%u.%u\t",
                   (v >> 24) & 0xFF, (v >> 16) & 0xFF,
                   (v >> 8) & 0xFF, v & 0xFF);
            break;
        }
        case line_reader_column_kind_float:
            printf("%g\t", (double)line_reader_column_data_get_f32(
                                &d, r, &is_null));
            break;
        case line_reader_column_kind_double:
            printf("%g\t", line_reader_column_data_get_f64(&d, r, &is_null));
            break;
        case line_reader_column_kind_long:
        case line_reader_column_kind_timestamp:
        case line_reader_column_kind_date:
        case line_reader_column_kind_timestamp_nanos:
            printf("%" PRId64 "\t",
                   line_reader_column_data_get_i64(&d, r, &is_null));
            break;
        case line_reader_column_kind_decimal64:
            printf("%" PRId64 "e%d\t",
                   line_reader_column_data_get_decimal64_mantissa(
                       &d, r, &is_null),
                   -(int)d.decimal_scale);
            break;
        case line_reader_column_kind_decimal128:
        case line_reader_column_kind_decimal256:
        case line_reader_column_kind_uuid:
        case line_reader_column_kind_long256:
        {
            uint8_t bytes[32];
            line_reader_column_data_get_bytes(&d, r, bytes, &is_null);
            print_hex(bytes, d.value_stride);
            if (d.kind == line_reader_column_kind_decimal128
                || d.kind == line_reader_column_kind_decimal256)
                printf("e%d", -(int)d.decimal_scale);
            printf("\t");
            break;
        }
        case line_reader_column_kind_geohash:
            printf("%" PRIx64 "/%u\t",
                   line_reader_column_data_get_geohash(&d, r, &is_null),
                   (unsigned)d.geohash_precision_bits);
            break;
        case line_reader_column_kind_varchar:
        case line_reader_column_kind_binary:
        {
            const uint8_t* buf = NULL;
            size_t len = 0;
            line_reader_column_data_get_varlen(
                &d, r, &buf, &len, &is_null);
            if (d.kind == line_reader_column_kind_varchar)
                printf("%.*s\t", (int)len, (const char*)buf);
            else
            {
                print_hex(buf, len);
                printf("\t");
            }
            break;
        }
        case line_reader_column_kind_symbol:
        {
            const char* sym_buf = NULL;
            size_t sym_len = 0;
            if (!line_reader_column_data_get_symbol(
                    &d, &dict, r, &sym_buf, &sym_len, &is_null))
            {
                fprintf(stderr, "symbol code out of dict range\n");
                return -1;
            }
            printf("%.*s\t", (int)sym_len, sym_buf);
            break;
        }
        default:
            printf("(kind=0x%02X)\t", (unsigned)d.kind);
            break;
        }
    }
    return 0;
}

static int print_double_array_column(
    const line_reader_batch* batch, size_t col_idx, line_reader_error** err)
{
    line_reader_array_data d = {0};
    if (!line_reader_batch_array_column_data(batch, col_idx, &d, err))
        return -1;

    for (size_t r = 0; r < d.row_count; ++r)
    {
        if (d.validity != NULL
            && ((d.validity[r >> 3] >> (r & 7)) & 1))
        {
            printf("NULL\t");
            continue;
        }
        const uint32_t b = d.data_offsets[r];
        const uint32_t e = d.data_offsets[r + 1];
        printf("[");
        const size_t n_elems = (e - b) / 8;
        for (size_t i = 0; i < n_elems; ++i)
        {
            if (i != 0)
                printf(" ");
            double v = 0.0;
            memcpy(&v, d.data + b + i * 8, 8);
            printf("%g", v);
        }
        printf("]\t");
    }
    return 0;
}

int main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;

    line_reader_error* err = NULL;
    line_reader* reader = NULL;
    line_reader_cursor* cursor = NULL;

    line_sender_utf8 conf = QDB_UTF8_LITERAL("ws::addr=localhost:9000;");
    reader = line_reader_from_conf(conf, &err);
    if (!reader) goto on_error;

    line_sender_utf8 sql = QDB_UTF8_LITERAL(
        "SELECT x AS n, x * 1.5 AS d FROM long_sequence(5)");
    cursor = line_reader_execute(reader, sql, &err);
    if (!cursor) goto on_error;

    const line_reader_batch* batch;
    while ((batch = line_reader_cursor_next_batch(cursor, &err)) != NULL)
    {
        const size_t cols = line_reader_batch_column_count(batch);
        for (size_t c = 0; c < cols; ++c)
        {
            const char* name = NULL;
            size_t name_len = 0;
            if (!line_reader_batch_column_name(batch, c, &name, &name_len, &err))
                goto on_error;
            printf("%.*s\t", (int)name_len, name);
        }
        printf("\n");

        for (size_t c = 0; c < cols; ++c)
        {
            line_reader_column_kind k;
            if (!line_reader_batch_column_kind(batch, c, &k, &err))
                goto on_error;
            const int prc = (k == line_reader_column_kind_double_array)
                                ? print_double_array_column(batch, c, &err)
                                : print_scalar_column(batch, c, &err);
            if (prc != 0) goto on_error;
        }
        printf("\n");
    }
    if (err)
        goto on_error;

    line_reader_cursor_free(cursor);
    line_reader_close(reader);
    return 0;

on_error:;
    size_t err_len = 0;
    const char* err_msg = line_reader_error_msg(err, &err_len);
    fprintf(stderr, "Error: %.*s\n", (int)err_len, err_msg);
    line_reader_error_free(err);
    line_reader_cursor_free(cursor);
    line_reader_close(reader);
    return 1;
}
