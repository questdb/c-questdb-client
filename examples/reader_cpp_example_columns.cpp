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

// Columnar bulk-read example for the QWP egress reader (C++).
//
// Demonstrates `cursor::next_batch()` + `batch::column()` + `column::visit`.
// `visit` dispatches on column kind and hands the visitor the matching typed
// view (`fixed_view<T>` / `decimal_view` / `varlen_view` / ...), eliminating
// the per-kind `switch` users would otherwise need.

#include <questdb/egress/reader.hpp>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string_view>

namespace eg = questdb::egress;
using namespace questdb::ingress::literals;

namespace
{

template <typename T>
T load_unaligned(const T* p)
{
    T v;
    std::memcpy(&v, p, sizeof(T));
    return v;
}

void print_hex(const uint8_t* p, size_t n)
{
    static constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i)
    {
        std::putchar(hex[p[i] >> 4]);
        std::putchar(hex[p[i] & 0xF]);
    }
}

void print_column(const eg::column& col)
{
    col.visit(
        eg::overload{
            // Fixed-width primitives — one lambda per `T`.
            [](eg::fixed_view<uint8_t> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL";
                    else
                        std::cout << (*v.value(r) ? "true" : "false");
                    std::cout << '\t';
                }
            },
            [](eg::fixed_view<int8_t> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL";
                    else
                        std::cout << static_cast<int>(*v.value(r));
                    std::cout << '\t';
                }
            },
            [](eg::fixed_view<int16_t> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL";
                    else
                        std::cout << *v.value(r);
                    std::cout << '\t';
                }
            },
            [](eg::fixed_view<uint16_t> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL\t";
                    else
                        std::printf("U+%04X\t", *v.value(r));
                }
            },
            [](eg::fixed_view<int32_t> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL";
                    else
                        std::cout << *v.value(r);
                    std::cout << '\t';
                }
            },
            [](eg::fixed_view<uint32_t> v) { // IPV4
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                    {
                        std::cout << "NULL\t";
                        continue;
                    }
                    const uint32_t x = *v.value(r);
                    std::printf(
                        "%u.%u.%u.%u\t",
                        (x >> 24) & 0xFF,
                        (x >> 16) & 0xFF,
                        (x >> 8) & 0xFF,
                        x & 0xFF);
                }
            },
            [](eg::fixed_view<int64_t> v) {
                // Covers LONG / TIMESTAMP / DATE / TIMESTAMP_NANOS;
                // `v.kind` distinguishes if unit matters.
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL";
                    else
                        std::cout << *v.value(r);
                    std::cout << '\t';
                }
            },
            [](eg::fixed_view<float> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL";
                    else
                        std::cout << *v.value(r);
                    std::cout << '\t';
                }
            },
            [](eg::fixed_view<double> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                        std::cout << "NULL";
                    else
                        std::cout << *v.value(r);
                    std::cout << '\t';
                }
            },
            [](eg::decimal_view v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                    {
                        std::cout << "NULL\t";
                        continue;
                    }
                    print_hex(v.values + r * v.value_stride, v.value_stride);
                    std::printf("E%d\t", -static_cast<int>(v.scale));
                }
            },
            [](eg::bytes_view v) { // UUID / LONG256
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                    {
                        std::cout << "NULL\t";
                        continue;
                    }
                    print_hex(v.values + r * v.value_stride, v.value_stride);
                    std::cout << '\t';
                }
            },
            [](eg::geohash_view v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                    {
                        std::cout << "NULL\t";
                        continue;
                    }
                    print_hex(v.values + r * v.value_stride, v.value_stride);
                    std::printf(
                        "/%u\t", static_cast<unsigned>(v.precision_bits));
                }
            },
            [](eg::varlen_view v) { // VARCHAR / BINARY
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.kind == eg::column_kind::binary)
                    {
                        const auto x = v.as_binary(r);
                        if (!x)
                        {
                            std::cout << "NULL\t";
                            continue;
                        }
                        print_hex(x->data, x->size);
                        std::cout << '\t';
                    }
                    else
                    {
                        const auto x = v.as_string_view(r);
                        std::cout << (x ? *x : std::string_view{"NULL"})
                                  << '\t';
                    }
                }
            },
            [](eg::symbol_view v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    const auto x = v.resolve(r);
                    std::cout << (x ? *x : std::string_view{"NULL"}) << '\t';
                }
            },
            [](eg::array_view<double> v) {
                for (size_t r = 0; r < v.row_count; ++r)
                {
                    if (v.is_null(r))
                    {
                        std::cout << "NULL\t";
                        continue;
                    }
                    const auto e = v.elements(r);
                    std::cout << '[';
                    for (size_t i = 0; i < e->second; ++i)
                    {
                        if (i != 0)
                            std::cout << ' ';
                        std::cout << load_unaligned(e->first + i);
                    }
                    std::cout << "]\t";
                }
            },
        });
}

} // namespace

int main()
{
    try
    {
        eg::reader reader{"ws::addr=localhost:9000;"_utf8};
        auto cur = reader.execute(
            "SELECT x AS n, x * 1.5 AS d FROM long_sequence(5)"_utf8);

        while (auto batch_opt = cur.next_batch())
        {
            auto& batch = *batch_opt;
            const size_t cols = batch.column_count();

            for (size_t c = 0; c < cols; ++c)
                std::cout << batch.column_name(c) << '\t';
            std::cout << '\n';

            for (size_t c = 0; c < cols; ++c)
                print_column(batch.column(c));
            std::cout << '\n';
        }
        return 0;
    }
    catch (const questdb::error& e)
    {
        std::cerr << "Error (code " << static_cast<int>(e.code())
                  << "): " << e.what() << '\n';
        return 1;
    }
}
