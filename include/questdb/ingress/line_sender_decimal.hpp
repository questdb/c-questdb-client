/*******************************************************************************
 *     ___                  _   ____  ____
 *    / _ \ _   _  ___  ___| |_|  _ \| __ )
 *   | | | | | | |/ _ \/ __| __| | | |  _ \
 *   | |_| | |_| |  __/\__ \ |_| |_| | |_) |
 *    \__\_\\__,_|\___||___/\__|____/|____/
 *
 *  Copyright (c) 2014-2019 Appsicle
 *  Copyright (c) 2019-2025 QuestDB
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

#include "line_sender_core.hpp"

/**
 * Types and utilities for working with arbitrary-precision decimal numbers.
 *
 * Decimals are represented as an unscaled integer value (mantissa) and a scale.
 * For example, the decimal "123.45" with scale 2 is represented as:
 * - Unscaled value: 12345
 * - Scale: 2 (meaning divide by 10^2 = 100)
 *
 * QuestDB supports decimal values with:
 * - Maximum scale: 76 (QuestDB server limitation)
 * - Maximum mantissa size: 127 bytes in binary format
 *
 * QuestDB server version 9.2.0 or later is required for decimal support.
 */
namespace questdb::ingress::decimal
{

/**
 * A unvalidated UTF-8 string view for text-based decimal representation.
 *
 * This is a wrapper around utf8_view that allows the compiler to distinguish
 * between regular strings and decimal strings.
 *
 * Use this to send decimal values as strings (e.g., "123.456").
 * The string will be parsed by the QuestDB server as a decimal column type.
 */
class decimal_str_view
{
public:
    decimal_str_view(const char* buf, size_t len)
        : buf{buf}, len{len}
    {
    }

    template <size_t N>
    decimal_str_view(const char (&buf)[N])
        : decimal_str_view{buf, N}
    {
    }

    decimal_str_view(std::string_view s_view)
        : decimal_str_view{s_view.data(), s_view.size()}
    {
    }

    decimal_str_view(const std::string& s)
        : decimal_str_view{s.data(), s.size()}
    {
    }

    const char* data() const noexcept
    {
        return buf;
    }

    size_t size() const noexcept
    {
        return len;
    }

private:
    const char* buf;
    size_t len;

    friend class line_sender_buffer;
};

/**
 * Literal suffix to construct `decimal_str_view` objects from string literals.
 *
 * @code {.cpp}
 * using namespace questdb::ingress::decimal;
 * buffer.column("price"_cn, "123.456"_decimal);
 * @endcode
 */
inline decimal_str_view operator"" _decimal(const char* buf, size_t len)
{
    return decimal_str_view{buf, len};
}

/**
 * A view over a decimal number in binary format.
 *
 * The decimal is represented as:
 * - A scale (number of decimal places)
 * - An unscaled value (mantissa) encoded as bytes in two's complement
 * big-endian format
 *
 * # Example
 *
 * To represent the decimal "123.45":
 * - Scale: 2
 * - Unscaled value: 12345 = 0x3039 in big-endian format
 *
 * ```c++
 * // Represent 123.45 with scale 2 (unscaled value is 12345)
 * uint8_t mantissa[] = {0x30, 0x39};  // 12345 in two's complement big-endian
 * auto decimal = questdb::ingress::decimal::decimal_view(2, mantissa,
 * sizeof(mantissa)); buffer.column("price"_cn, decimal);
 * ```
 *
 * # Constraints
 *
 * - Maximum scale: 76 (QuestDB server limitation)
 * - Maximum mantissa size: 127 bytes (protocol limitation)
 */
class decimal_view
{
public:
    /**
     * Construct a binary decimal view from raw bytes.
     *
     * @param scale Number of decimal places (must be ≤ 76)
     * @param data Pointer to unscaled value in two's complement big-endian
     * format
     * @param data_size Number of bytes in the mantissa (must be ≤ 127)
     */
    decimal_view(uint32_t scale, const uint8_t* data, size_t data_size)
        : _scale{scale}
        , _data{data}
        , _data_size{data_size}
    {
    }

    /**
     * Construct a binary decimal view from a fixed-size array.
     *
     * @param scale Number of decimal places (must be ≤ 76)
     * @param data Fixed-size array containing the unscaled value
     */
    template <std::size_t N>
    decimal_view(uint32_t scale, const uint8_t (&data)[N])
        : _scale{scale}
        , _data{data}
        , _data_size{N}
    {
    }

    /**
     * Construct a binary decimal view from a std::array.
     *
     * @param scale Number of decimal places (must be ≤ 76)
     * @param data std::array containing the unscaled value
     */
    template <std::size_t N>
    decimal_view(uint32_t scale, const std::array<uint8_t, N>& data)
        : _scale{scale}
        , _data{data.data()}
        , _data_size{N}
    {
    }

    /**
     * Construct a binary decimal view from a std::vector.
     *
     * @param scale Number of decimal places (must be ≤ 76)
     * @param vec Vector containing the unscaled value
     */
    decimal_view(uint32_t scale, const std::vector<uint8_t>& vec)
        : _scale{scale}
        , _data{vec.data()}
        , _data_size{vec.size()}
    {
    }

#if __cplusplus >= 202002L
    /**
     * Construct a binary decimal view from a std::span (C++20).
     *
     * @param scale Number of decimal places (must be ≤ 76)
     * @param span Span containing the unscaled value
     */
    decimal_view(uint32_t scale, const std::span<uint8_t>& span)
        : _scale{scale}
        , _data{span.data()}
        , _data_size{span.size()}
    {
    }
#endif

    /** Get the scale (number of decimal places). */
    uint32_t scale() const
    {
        return _scale;
    }

    /** Get a pointer to the unscaled value bytes. */
    const uint8_t* data() const
    {
        return _data;
    }

    /** Get the size of the unscaled value in bytes. */
    size_t data_size() const
    {
        return _data_size;
    }

    /** Get a const reference to this view (for customization point
     * compatibility). */
    const decimal_view& view() const
    {
        return *this;
    }

private:
    uint32_t _scale;
    const uint8_t* _data;
    size_t _data_size;
};
/**
 * Customization point to enable serialization of additional types as decimals.
 *
 * This allows you to support custom decimal types by implementing a conversion
 * function. The customized `to_decimal_view_state_impl` for your type can be
 * placed in either:
 * - The namespace of the type in question (ADL/Koenig lookup)
 * - The `questdb::ingress::decimal` namespace
 *
 * The function can either:
 * - Return a `decimal_view` object directly, or
 * - Return an object with a `.view()` method that returns `const decimal_view&`
 *   (useful if you need to store temporary data like shape/strides on the
stack)
 */
struct to_decimal_view_state_fn
{
    template <typename T>
    auto operator()(const T& decimal) const
    {
        // Implement your own `to_decimal_view_state_impl` as needed.
        // ADL lookup for user-defined to_decimal_view_state_impl
        return to_decimal_view_state_impl(decimal);
    }
};

inline constexpr to_decimal_view_state_fn to_decimal_view_state{};

template <typename T, typename = void>
struct has_decimal_view_state : std::false_type
{
};

template <typename T>
struct has_decimal_view_state<
    T,
    std::void_t<decltype(to_decimal_view_state_impl(std::declval<T>()))>>
    : std::true_type
{
};

template <typename T>
inline constexpr bool has_decimal_view_state_v =
    has_decimal_view_state<T>::value;
} // namespace questdb::ingress::decimal

namespace questdb::ingress
{
using decimal::decimal_view;
} // namespace questdb::ingress