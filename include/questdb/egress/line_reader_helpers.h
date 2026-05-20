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

/*
 * Header-only inline helpers on top of `line_reader_column_data`. The egress
 * C ABI is bulk-only at the symbol level — fill a descriptor once per column,
 * then index by row. These helpers package the per-row index + validity-bitmap
 * probe + typed little-endian load into one call, so casual C code can read a
 * single cell with one line instead of three.
 *
 * Nothing here adds new exported symbols; everything is `static inline`.
 * Tight loops over many rows should still inline-index the descriptor
 * directly — these helpers exist for ergonomics, not performance.
 *
 * Preconditions (every helper, unless noted otherwise):
 *   - `d` is a non-NULL, fully-filled descriptor from
 *     `line_reader_batch_column_data` against the CURRENT batch.
 *   - `row < d->row_count`. The helpers DO NOT bounds-check; reading past
 *     `row_count` reads past the validity bitmap / values buffer.
 *   - For `_get_symbol`: the `line_reader_symbol_dict` snapshot MUST be from
 *     the same batch as `d`. A stale snapshot from a previous batch silently
 *     resolves codes against the wrong heap.
 *
 * Idiom:
 *
 *     line_reader_column_data d;
 *     if (!line_reader_batch_column_data(batch, col, &d, &err)) {...}
 *     bool is_null;
 *     int64_t v = line_reader_column_data_get_i64(&d, row, &is_null);
 *
 * For SYMBOL columns the resolver also needs the dict snapshot:
 *
 *     line_reader_symbol_dict dict;
 *     line_reader_batch_symbol_dict(batch, &dict, &err);
 *     const char* buf; size_t len; bool is_null;
 *     line_reader_column_data_get_symbol(&d, &dict, row, &buf, &len, &is_null);
 */

#pragma once

#include "line_reader.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline bool line_reader_column_data_is_null(
    const line_reader_column_data* d, size_t row)
{
    return d->validity != NULL && ((d->validity[row >> 3] >> (row & 7)) & 1);
}

static inline bool line_reader_column_data_get_bool(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return false;
    /* BOOLEAN is dense-1-byte-per-row on the C side (FFI decoder writes
     * `value_stride == 1` for ColumnView::Boolean); honour the stride so
     * the helper stays robust if the descriptor representation ever
     * changes. */
    return ((const uint8_t*)d->values)[row * d->value_stride] != 0;
}

static inline int8_t line_reader_column_data_get_i8(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    return *out_is_null ? 0 : ((const int8_t*)d->values)[row];
}

static inline int16_t line_reader_column_data_get_i16(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    int16_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 2, sizeof(v));
    return v;
}

static inline uint16_t line_reader_column_data_get_char(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    uint16_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 2, sizeof(v));
    return v;
}

static inline int32_t line_reader_column_data_get_i32(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    int32_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 4, sizeof(v));
    return v;
}

static inline uint32_t line_reader_column_data_get_ipv4(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    uint32_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 4, sizeof(v));
    return v;
}

static inline float line_reader_column_data_get_f32(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0.0f;
    float v;
    memcpy(&v, (const uint8_t*)d->values + row * 4, sizeof(v));
    return v;
}

static inline int64_t line_reader_column_data_get_i64(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    int64_t v;
    memcpy(&v, (const uint8_t*)d->values + row * 8, sizeof(v));
    return v;
}

static inline double line_reader_column_data_get_f64(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0.0;
    double v;
    memcpy(&v, (const uint8_t*)d->values + row * 8, sizeof(v));
    return v;
}

/* UUID / LONG256: copy `value_stride` bytes (16 or 32) into out. */
static inline void line_reader_column_data_get_bytes(
    const line_reader_column_data* d,
    size_t row,
    uint8_t* out,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        memset(out, 0, d->value_stride);
        return;
    }
    memcpy(out, (const uint8_t*)d->values + row * d->value_stride,
           d->value_stride);
}

/* DECIMAL64: returns the mantissa; scale is on `d->decimal_scale`. */
static inline int64_t line_reader_column_data_get_decimal64_mantissa(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    return line_reader_column_data_get_i64(d, row, out_is_null);
}

/* DECIMAL128: split as (low u64, high i64); scale on `d->decimal_scale`. */
static inline void line_reader_column_data_get_decimal128(
    const line_reader_column_data* d,
    size_t row,
    uint64_t* out_low,
    int64_t* out_high,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        *out_low = 0;
        *out_high = 0;
        return;
    }
    const uint8_t* p = (const uint8_t*)d->values + row * 16;
    memcpy(out_low, p, 8);
    memcpy(out_high, p + 8, 8);
}

/* GEOHASH: returns the value zero-extended into a u64. */
static inline uint64_t line_reader_column_data_get_geohash(
    const line_reader_column_data* d, size_t row, bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
        return 0;
    uint64_t v = 0;
    memcpy(&v, (const uint8_t*)d->values + row * d->value_stride,
           d->value_stride);
    return v;
}

/* VARCHAR / BINARY: row-row borrowed slice into `d->var_data`. NULL row
 * yields `*out_buf == NULL && *out_len == 0`. */
static inline void line_reader_column_data_get_varlen(
    const line_reader_column_data* d,
    size_t row,
    const uint8_t** out_buf,
    size_t* out_len,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        *out_buf = NULL;
        *out_len = 0;
        return;
    }
    const uint32_t s = d->var_offsets[row];
    const uint32_t e = d->var_offsets[row + 1];
    *out_buf = d->var_data + s;
    *out_len = (size_t)(e - s);
}

/* SYMBOL: resolve the row's dictionary code into a borrowed UTF-8 slice
 * over the supplied dict snapshot. Returns false on a code out of range
 * (corrupt batch) — caller's responsibility to surface as an error. */
static inline bool line_reader_column_data_get_symbol(
    const line_reader_column_data* d,
    const line_reader_symbol_dict* dict,
    size_t row,
    const char** out_buf,
    size_t* out_len,
    bool* out_is_null)
{
    *out_is_null = line_reader_column_data_is_null(d, row);
    if (*out_is_null)
    {
        *out_buf = NULL;
        *out_len = 0;
        return true;
    }
    const uint32_t code = d->symbol_codes[row];
    if (code >= dict->entry_count)
    {
        *out_buf = NULL;
        *out_len = 0;
        return false;
    }
    const line_reader_symbol_entry e = dict->entries[code];
    *out_buf = (const char*)dict->heap + e.offset;
    *out_len = (size_t)e.length;
    return true;
}

#ifdef __cplusplus
} /* extern "C" */
#endif
