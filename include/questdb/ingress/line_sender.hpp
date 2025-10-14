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

#include "line_sender.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>
#if __cplusplus >= 202002L
#    include <span>
#endif

namespace questdb::ingress
{
constexpr const char* inaddr_any = "0.0.0.0";

class line_sender;
class line_sender_buffer;
class opts;

/** Category of error. */
enum class line_sender_error_code
{
    /** The host, port, or interface was incorrect. */
    could_not_resolve_addr,

    /** Called methods in the wrong order. E.g. `symbol` after `column`. */
    invalid_api_call,

    /** A network error connecting or flushing data out. */
    socket_error,

    /** The string or symbol field is not encoded in valid UTF-8. */
    invalid_utf8,

    /** The table name or column name contains bad characters. */
    invalid_name,

    /** The supplied timestamp is invalid. */
    invalid_timestamp,

    /** Error during the authentication process. */
    auth_error,

    /** Error during TLS handshake. */
    tls_error,

    /** The server does not support ILP over HTTP. */
    http_not_supported,

    /** Error sent back from the server during flush. */
    server_flush_error,

    /** Bad configuration. */
    config_error,

    /** There was an error serializing an array. */
    array_error,

    /**  Line sender protocol version error. */
    protocol_version_error,

    /** The supplied decimal is invalid. */
    invalid_decimal,
};

/** The protocol used to connect with. */
enum class protocol
{
    /** InfluxDB Line Protocol over TCP. */
    tcp,

    /** InfluxDB Line Protocol over TCP with TLS. */
    tcps,

    /** InfluxDB Line Protocol over HTTP. */
    http,

    /** InfluxDB Line Protocol over HTTP with TLS. */
    https,
};

enum class protocol_version
{
    /** InfluxDB Line Protocol v1. */
    v1 = 1,

    /**
     * InfluxDB Line Protocol v2.
     * QuestDB server version 9.0.0 or later is required for
     * `v2` support.
     */
    v2 = 2,
};

/* Possible sources of the root certificates used to validate the server's TLS
 * certificate. */
enum class ca
{
    /** Use the set of root certificates provided by the `webpki` crate. */
    webpki_roots,

    /** Use the set of root certificates provided by the operating system. */
    os_roots,

    /** Combine the set of root certificates provided by the `webpki` crate and
     * the operating system. */
    webpki_and_os_roots,

    /** Use the root certificates provided in a PEM-encoded file. */
    pem_file,
};

/**
 * An error that occurred when using the line sender.
 *
 * Call `.what()` to obtain the ASCII-encoded error message.
 */
class line_sender_error : public std::runtime_error
{
public:
    line_sender_error(line_sender_error_code code, const std::string& what)
        : std::runtime_error{what}
        , _code{code}
    {
    }

    /** Error code categorizing the error. */
    line_sender_error_code code() const noexcept
    {
        return _code;
    }

private:
    inline static line_sender_error from_c(::line_sender_error* c_err)
    {
        line_sender_error_code code = static_cast<line_sender_error_code>(
            static_cast<int>(::line_sender_error_get_code(c_err)));
        size_t c_len{0};
        const char* c_msg{::line_sender_error_msg(c_err, &c_len)};
        std::string msg{c_msg, c_len};
        line_sender_error err{code, msg};
        ::line_sender_error_free(c_err);
        return err;
    }

    template <typename F, typename... Args>
    inline static auto wrapped_call(F&& f, Args&&... args)
    {
        ::line_sender_error* c_err{nullptr};
        auto obj = f(std::forward<Args>(args)..., &c_err);
        if (obj)
            return obj;
        else
            throw from_c(c_err);
    }

    friend class line_sender;
    friend class line_sender_buffer;
    friend class opts;

    template <
        typename T,
        bool (*F)(T*, size_t, const char*, ::line_sender_error**)>
    friend class basic_view;

    line_sender_error_code _code;
};

/**
 * Non-owning validated string.
 *
 * See `table_name_view`, `column_name_view` and `utf8_view` along with the
 * `_utf8`, `_tn` and `_cn` literal suffixes in the `literals` namespace.
 */
template <typename T, bool (*F)(T*, size_t, const char*, ::line_sender_error**)>
class basic_view
{
public:
    basic_view(const char* buf, size_t len)
        : _impl{0, nullptr}
    {
        line_sender_error::wrapped_call(F, &_impl, len, buf);
    }

    template <size_t N>
    basic_view(const char (&buf)[N])
        : basic_view{buf, N - 1}
    {
    }

    basic_view(std::string_view s_view)
        : basic_view{s_view.data(), s_view.size()}
    {
    }

    basic_view(const std::string& s)
        : basic_view{s.data(), s.size()}
    {
    }

    size_t size() const noexcept
    {
        return _impl.len;
    }

    const char* data() const noexcept
    {
        return _impl.buf;
    }

    std::string_view to_string_view() const noexcept
    {
        return std::string_view{_impl.buf, _impl.len};
    }

private:
    T _impl;

    friend class line_sender;
    friend class line_sender_buffer;
    friend class opts;
};

using utf8_view = basic_view<::line_sender_utf8, ::line_sender_utf8_init>;

using table_name_view =
    basic_view<::line_sender_table_name, ::line_sender_table_name_init>;

using column_name_view =
    basic_view<::line_sender_column_name, ::line_sender_column_name_init>;

namespace literals
{
/**
 * Utility to construct `utf8_view` objects from string literals.
 * @code {.cpp}
 * auto validated = "A UTF-8 encoded string"_utf8;
 * @endcode
 */
inline utf8_view operator"" _utf8(const char* buf, size_t len)
{
    return utf8_view{buf, len};
}

/**
 * Utility to construct `table_name_view` objects from string literals.
 * @code {.cpp}
 * auto table_name = "events"_tn;
 * @endcode
 */
inline table_name_view operator"" _tn(const char* buf, size_t len)
{
    return table_name_view{buf, len};
}

/**
 * Utility to construct `column_name_view` objects from string literals.
 * @code {.cpp}
 * auto column_name = "events"_cn;
 * @endcode
 */
inline column_name_view operator"" _cn(const char* buf, size_t len)
{
    return column_name_view{buf, len};
}
} // namespace literals

class timestamp_micros
{
public:
    template <typename ClockT, typename DurationT>
    explicit timestamp_micros(std::chrono::time_point<ClockT, DurationT> tp)
        : _ts{std::chrono::duration_cast<std::chrono::microseconds>(
                  tp.time_since_epoch())
                  .count()}
    {
    }

    explicit timestamp_micros(int64_t ts) noexcept
        : _ts{ts}
    {
    }

    int64_t as_micros() const noexcept
    {
        return _ts;
    }

    static inline timestamp_micros now() noexcept
    {
        return timestamp_micros{::line_sender_now_micros()};
    }

private:
    int64_t _ts;
};

class timestamp_nanos
{
public:
    template <typename ClockT, typename DurationT>
    explicit timestamp_nanos(std::chrono::time_point<ClockT, DurationT> tp)
        : _ts{std::chrono::duration_cast<std::chrono::nanoseconds>(
                  tp.time_since_epoch())
                  .count()}
    {
    }

    explicit timestamp_nanos(int64_t ts) noexcept
        : _ts{ts}
    {
    }

    int64_t as_nanos() const noexcept
    {
        return _ts;
    }

    static inline timestamp_nanos now() noexcept
    {
        return timestamp_nanos{::line_sender_now_nanos()};
    }

private:
    int64_t _ts;
};

#if __cplusplus < 202002L
class buffer_view final
{
public:
    /**
     * Default constructor. Creates an empty buffer view.
     */
    buffer_view() noexcept = default;

    /**
     * Construct a buffer view from raw byte data.
     * @param data Pointer to the underlying byte array (may be nullptr if
     * length=0).
     * @param length Number of bytes in the array.
     */
    constexpr buffer_view(const std::byte* data, size_t length) noexcept
        : buf(data)
        , len(length)
    {
    }

    /**
     * Obtain a pointer to the underlying byte array.
     *
     * @return Const pointer to the data (may be nullptr if empty()).
     */
    constexpr const std::byte* data() const noexcept
    {
        return buf;
    }

    /**
     * Obtain the number of bytes in the view.
     *
     * @return Size of the view in bytes.
     */
    constexpr size_t size() const noexcept
    {
        return len;
    }

    /**
     * Check if the buffer view is empty.
     * @return true if the view has no bytes (size() == 0).
     */
    constexpr bool empty() const noexcept
    {
        return len == 0;
    }

    /**
     * Check byte-wise if two buffer views are equal.
     * @return true if both views have the same size and
     *         the same byte content.
     */
    friend bool operator==(
        const buffer_view& lhs, const buffer_view& rhs) noexcept
    {
        return lhs.size() == rhs.size() &&
               std::equal(lhs.buf, lhs.buf + lhs.len, rhs.buf);
    }

private:
    const std::byte* buf{nullptr};
    size_t len{0};
};
#endif

namespace array
{
enum class strides_mode
{
    /** Strides are provided in bytes */
    bytes,

    /** Strides are provided in elements */
    elements,
};

/**
 * A view over a multi-dimensional array with custom strides.
 *
 * The strides can be expressed as bytes offsets or as element counts.
 * The `rank` is the number of dimensions in the array, and the `shape`
 * describes the size of each dimension.
 *
 * If the data is stored in a row-major order, it may be more convenient and
 * efficient to use the `row_major_view` instead of `strided_view`.
 *
 * The `data` pointer must point to a contiguous block of memory that contains
 * the array data.
 */
template <typename T, strides_mode M>
class strided_view
{
public:
    using element_type = T;
    static constexpr strides_mode stride_size_mode = M;

    strided_view(
        size_t rank,
        const uintptr_t* shape,
        const intptr_t* strides,
        const T* data,
        size_t data_size)
        : _rank{rank}
        , _shape{shape}
        , _strides{strides}
        , _data{data}
        , _data_size{data_size}
    {
    }

    size_t rank() const
    {
        return _rank;
    }

    const uintptr_t* shape() const
    {
        return _shape;
    }

    const intptr_t* strides() const
    {
        return _strides;
    }

    const T* data() const
    {
        return _data;
    }

    size_t data_size() const
    {
        return _data_size;
    }

    const strided_view<T, M>& view() const
    {
        return *this;
    }

private:
    size_t _rank;
    const uintptr_t* _shape;
    const intptr_t* _strides;
    const T* _data;
    size_t _data_size;
};

/**
 * A view over a multi-dimensional array in row-major order.
 *
 * The `rank` is the number of dimensions in the array, and the `shape`
 * describes the size of each dimension.
 *
 * The `data` pointer must point to a contiguous block of memory that contains
 * the array data.
 *
 * If the source array is not stored in a row-major order, you may express
 * the strides explicitly using the `strided_view` class.
 *
 * This class provides a simpler and more efficient interface for row-major
 * arrays.
 */
template <typename T>
class row_major_view
{
public:
    using element_type = T;

    row_major_view(
        size_t rank, const uintptr_t* shape, const T* data, size_t data_size)
        : _rank{rank}
        , _shape{shape}
        , _data{data}
        , _data_size{data_size}
    {
    }

    size_t rank() const
    {
        return _rank;
    }
    const uintptr_t* shape() const
    {
        return _shape;
    }
    const T* data() const
    {
        return _data;
    }

    size_t data_size() const
    {
        return _data_size;
    }

    const row_major_view<T>& view() const
    {
        return *this;
    }

private:
    size_t _rank;
    const uintptr_t* _shape;
    const T* _data;
    size_t _data_size;
};

template <typename T>
struct row_major_1d_holder
{
    uintptr_t shape[1];
    const T* data;
    size_t size;

    row_major_1d_holder(const T* d, size_t s)
        : data(d)
        , size(s)
    {
        shape[0] = static_cast<uintptr_t>(s);
    }

    array::row_major_view<T> view() const
    {
        return {1, shape, data, size};
    }
};

template <typename T>
inline auto to_array_view_state_impl(const std::vector<T>& vec)
{
    return row_major_1d_holder<typename std::remove_cv<T>::type>(
        vec.data(), vec.size());
}

#if __cplusplus >= 202002L
template <typename T>
inline auto to_array_view_state_impl(const std::span<T>& span)
{
    return row_major_1d_holder<typename std::remove_cv<T>::type>(
        span.data(), span.size());
}
#endif

template <typename T, size_t N>
inline auto to_array_view_state_impl(const std::array<T, N>& arr)
{
    return row_major_1d_holder<typename std::remove_cv<T>::type>(arr.data(), N);
}

/**
 * Customization point to enable serialization of additional types as arrays.
 *
 * Forwards to a namespace or ADL (König) lookup function.
 * The customized `to_array_view_state_impl` for your custom type can be placed
 * in either:
 *  * The namespace of the type in question.
 *  * In the `questdb::ingress::array` namespace.
///
 * The function can either return a view object directly (either
 * `row_major_view` or `strided_view`), or, if you need to place some fields on
 * the stack, an object with a `.view()` method which returns a `const&` to one
 * "materialize" shape or strides information into contiguous memory.
 * of the two view types. Returning an object may be useful if you need to
 */
struct to_array_view_state_fn
{
    template <typename T>
    auto operator()(const T& array) const
    {
        // Implement your own `to_array_view_state_impl` as needed.
        return to_array_view_state_impl(array);
    }
};

inline constexpr to_array_view_state_fn to_array_view_state{};

} // namespace array

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
namespace decimal
{

/**
 * A validated UTF-8 string view for text-based decimal representation.
 *
 * This is a wrapper around utf8_view that allows the compiler to distinguish
 * between regular strings and decimal strings.
 *
 * Use this to send decimal values as strings (e.g., "123.456").
 * The string will be parsed by the QuestDB server as a decimal column type.
 */
class text_view
{
public:
    text_view(const char* buf, size_t len)
        : _view{buf, len}
    {
    }

    template <size_t N>
    text_view(const char (&buf)[N])
        : _view{buf}
    {
    }

    text_view(std::string_view s_view)
        : _view{s_view}
    {
    }

    text_view(const std::string& s)
        : _view{s}
    {
    }

    const utf8_view& view() const noexcept
    {
        return _view;
    }

private:
    utf8_view _view;

    friend class line_sender_buffer;
};

/**
 * Literal suffix to construct `text_view` objects from string literals.
 *
 * @code {.cpp}
 * using namespace questdb::ingress::decimal;
 * buffer.column("price"_cn, "123.456"_decimal);
 * @endcode
 */
inline text_view operator"" _decimal(const char* buf, size_t len)
{
    return text_view{buf, len};
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
 * auto decimal = questdb::ingress::decimal::binary_view(2, mantissa,
 * sizeof(mantissa)); buffer.column("price"_cn, decimal);
 * ```
 *
 * # Constraints
 *
 * - Maximum scale: 76 (QuestDB server limitation)
 * - Maximum mantissa size: 127 bytes (protocol limitation)
 */
class binary_view
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
    binary_view(uint32_t scale, const uint8_t* data, size_t data_size)
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
    binary_view(uint32_t scale, const uint8_t (&data)[N])
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
    binary_view(uint32_t scale, const std::array<uint8_t, N>& data)
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
    binary_view(uint32_t scale, const std::vector<uint8_t>& vec)
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
    binary_view(uint32_t scale, const std::span<uint8_t>& span)
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
    const binary_view& view() const
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
 * - Return a `binary_view` object directly, or
 * - Return an object with a `.view()` method that returns `const binary_view&`
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

} // namespace decimal

class line_sender_buffer
{
public:
    explicit line_sender_buffer(
        protocol_version version,
        size_t init_buf_size = 64 * 1024,
        size_t max_name_len = 127) noexcept
        : _impl{nullptr}
        , _protocol_version{version}
        , _init_buf_size{init_buf_size}
        , _max_name_len{max_name_len}
    {
    }

    line_sender_buffer(const line_sender_buffer& other) noexcept
        : _impl{::line_sender_buffer_clone(other._impl)}
        , _protocol_version{other._protocol_version}
        , _init_buf_size{other._init_buf_size}
        , _max_name_len{other._max_name_len}

    {
    }

    line_sender_buffer(line_sender_buffer&& other) noexcept
        : _impl{other._impl}
        , _protocol_version{other._protocol_version}
        , _init_buf_size{other._init_buf_size}
        , _max_name_len{other._max_name_len}

    {
        other._impl = nullptr;
    }

    line_sender_buffer& operator=(const line_sender_buffer& other) noexcept
    {
        if (this != &other)
        {
            ::line_sender_buffer_free(_impl);
            if (other._impl)
                _impl = ::line_sender_buffer_clone(other._impl);
            else
                _impl = nullptr;
            _init_buf_size = other._init_buf_size;
            _max_name_len = other._max_name_len;
            _protocol_version = other._protocol_version;
        }
        return *this;
    }

    line_sender_buffer& operator=(line_sender_buffer&& other) noexcept
    {
        if (this != &other)
        {
            ::line_sender_buffer_free(_impl);
            _impl = other._impl;
            _init_buf_size = other._init_buf_size;
            _max_name_len = other._max_name_len;
            _protocol_version = other._protocol_version;
            other._impl = nullptr;
        }
        return *this;
    }

    /**
     * Pre-allocate to ensure the buffer has enough capacity for at least
     * the specified additional byte count. This may be rounded up.
     * This does not allocate if such additional capacity is already
     * satisfied.
     * See: `capacity`.
     */
    void reserve(size_t additional)
    {
        may_init();
        ::line_sender_buffer_reserve(_impl, additional);
    }

    /** Get the current capacity of the buffer. */
    size_t capacity() const noexcept
    {
        if (_impl)
            return ::line_sender_buffer_capacity(_impl);
        else
            return 0;
    }

    /** The number of bytes accumulated in the buffer. */
    size_t size() const noexcept
    {
        if (_impl)
            return ::line_sender_buffer_size(_impl);
        else
            return 0;
    }

    /** The number of rows accumulated in the buffer. */
    size_t row_count() const noexcept
    {
        if (_impl)
            return ::line_sender_buffer_row_count(_impl);
        else
            return 0;
    }

    /**
     * Tell whether the buffer is transactional. It is transactional iff it
     * contains data for at most one table. Additionally, you must send the
     * buffer over HTTP to get transactional behavior.
     */
    bool transactional() const noexcept
    {
        if (_impl)
            return ::line_sender_buffer_transactional(_impl);
        else
            return 0;
    }

#if __cplusplus >= 202002L
    using buffer_view = std::span<const std::byte>;
#endif

    /**
     * Get a bytes view of the contents of the buffer
     * (not guaranteed to be an encoded string)
     */
    buffer_view peek() const noexcept
    {
        if (_impl)
        {
            auto view = ::line_sender_buffer_peek(_impl);
            return {reinterpret_cast<const std::byte*>(view.buf), view.len};
        }
        return {};
    }

    /**
     * Mark a rewind point.
     * This allows undoing accumulated changes to the buffer for one or more
     * rows by calling `rewind_to_marker`.
     * Any previous marker will be discarded.
     * Once the marker is no longer needed, call `clear_marker`.
     */
    void set_marker()
    {
        may_init();
        line_sender_error::wrapped_call(::line_sender_buffer_set_marker, _impl);
    }

    /**
     * Undo all changes since the last `set_marker` call.
     * As a side-effect, this also clears the marker.
     */
    void rewind_to_marker()
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_rewind_to_marker, _impl);
    }

    /** Discard the marker. */
    void clear_marker() noexcept
    {
        if (_impl)
            ::line_sender_buffer_clear_marker(_impl);
    }

    /**
     * Remove all accumulated data and prepare the buffer for new lines.
     * This does not affect the buffer's capacity.
     */
    void clear() noexcept
    {
        if (_impl)
            ::line_sender_buffer_clear(_impl);
    }

    /**
     * Start recording a new row for the given table.
     * @param name Table name.
     */
    line_sender_buffer& table(table_name_view name)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_table, _impl, name._impl);
        return *this;
    }

    /**
     * Record a symbol value for the given column.
     * Make sure you record all the symbol columns before any other column type.
     * @param name Column name.
     * @param value Column value.
     */
    line_sender_buffer& symbol(column_name_view name, utf8_view value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_symbol, _impl, name._impl, value._impl);
        return *this;
    }

    // Require specific overloads of `column` to avoid
    // involuntary usage of the `bool` overload or similar.
    template <
        typename T,
        typename std::enable_if_t<
            // Integral types that are NOT bool or int64_t
            (std::is_integral_v<std::decay_t<T>> &&
             !std::is_same_v<std::decay_t<T>, bool> &&
             !std::is_same_v<std::decay_t<T>, int64_t>) ||

                // Floating-point types that are NOT double
                (std::is_floating_point_v<std::decay_t<T>> &&
                 !std::is_same_v<std::decay_t<T>, double>) ||

                // Pointer types (which can implicitly convert to bool)
                std::is_pointer_v<std::decay_t<T>>

            ,
            int> = 0>
    line_sender_buffer& column(column_name_view name, T value) = delete;

    /**
     * Record a boolean value for the given column.
     * @param name Column name.
     * @param value Column value.
     */
    line_sender_buffer& column(column_name_view name, bool value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_bool, _impl, name._impl, value);
        return *this;
    }

    /**
     * Record an integer value for the given column.
     * @param name Column name.
     * @param value Column value.
     */
    line_sender_buffer& column(column_name_view name, int64_t value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_i64, _impl, name._impl, value);
        return *this;
    }

    /**
     * Record a floating-point value for the given column.
     * @param name Column name.
     * @param value Column value.
     */
    line_sender_buffer& column(column_name_view name, double value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_f64, _impl, name._impl, value);
        return *this;
    }

    /**
     * Record a multidimensional array of `double` values.
     *
     * QuestDB server version 9.0.0 or later is required for array support.
     *
     * @tparam T    Element type (current only `double` is supported).
     * @tparam M    Array stride size mode (bytes or elements).
     *
     * @param name    Column name.
     * @param data    Multi-dimensional array.
     */
    template <typename T, array::strides_mode M>
    line_sender_buffer& column(
        column_name_view name, const array::strided_view<T, M>& array)
    {
        static_assert(
            std::is_same_v<T, double>,
            "Only double types are supported for arrays");
        may_init();
        switch (M)
        {
        case array::strides_mode::bytes:
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_f64_arr_byte_strides,
                _impl,
                name._impl,
                array.rank(),
                array.shape(),
                array.strides(),
                array.data(),
                array.data_size());
            break;
        case array::strides_mode::elements:
            line_sender_error::wrapped_call(
                ::line_sender_buffer_column_f64_arr_elem_strides,
                _impl,
                name._impl,
                array.rank(),
                array.shape(),
                array.strides(),
                array.data(),
                array.data_size());
            break;
        }
        return *this;
    }

    /**
     * Records a multidimensional array of double-precision values with c_major
     * layout.
     *
     * QuestDB server version 9.0.0 or later is required for array support.
     *
     * @tparam T    Element type (current only `double` is supported).
     * @tparam N    Number of elements in the flat data array
     *
     * @param name    Column name.
     * @param array   Multi-dimensional array.
     */
    template <typename T>
    line_sender_buffer& column(
        column_name_view name, const array::row_major_view<T>& array)
    {
        static_assert(
            std::is_same_v<T, double>,
            "Only double types are supported for arrays");
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_f64_arr_c_major,
            _impl,
            name._impl,
            array.rank(),
            array.shape(),
            array.data(),
            array.data_size());
        return *this;
    }

    /**
     * Record a multidimensional array of double-precision values.
     *
     * QuestDB server version 9.0.0 or later is required for array support.
     *
     * Use this method to record arrays of common or custom types such as
     * `std::vector`, `std::span`, `std::array`, or custom types that can be
     * converted to an array view.
     *
     * This overload uses a customization point to support additional types:
     * If you need to support your additional types you may implement a
     * `to_array_view_state_impl` function in the object's namespace (via ADL)
     * or in the `questdb::ingress::array` namespace.
     * Ensure that any additional customization points are included before
     * `line_sender.hpp`.
     *
     * @tparam ToArrayViewT  Type convertible to a custom object instance which
     *                       can be converted to an array view.
     * @param name           Column name.
     * @param array          Multi-dimensional array.
     */
    template <typename ToArrayViewT>
    line_sender_buffer& column(column_name_view name, ToArrayViewT array)
    {
        may_init();
        const auto array_view_state =
            questdb::ingress::array::to_array_view_state(array);
        return column(name, array_view_state.view());
    }

    /**
     * Record a string value for the given column.
     * @param name Column name.
     * @param value Column value.
     */
    line_sender_buffer& column(column_name_view name, utf8_view value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_str, _impl, name._impl, value._impl);
        return *this;
    }

    template <size_t N>
    line_sender_buffer& column(column_name_view name, const char (&value)[N])
    {
        return column(name, utf8_view{value});
    }

    line_sender_buffer& column(column_name_view name, std::string_view value)
    {
        return column(name, utf8_view{value});
    }

    line_sender_buffer& column(column_name_view name, const std::string& value)
    {
        return column(name, utf8_view{value});
    }

    /**
     * Record an arbitrary-precision decimal value from a text representation.
     *
     * This sends the decimal as a string (e.g., "123.456") to be parsed by
     * the QuestDB server.
     *
     * For better performance and precision control, consider using the binary
     * format via `decimal::binary_view` instead.
     *
     * QuestDB server version 9.2.0 or later is required for decimal support.
     *
     * @param name  Column name.
     * @param value Decimal value as a validated UTF-8 string.
     */
    line_sender_buffer& column(column_name_view name, decimal::text_view value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_dec_str,
            _impl,
            name._impl,
            value.view()._impl);
        return *this;
    }

    /**
     * Record an arbitrary-precision decimal value in binary format.
     *
     * The decimal is represented as an unscaled integer (mantissa) and a scale.
     * This provides precise control over the decimal representation and is more
     * efficient than text-based serialization.
     *
     * QuestDB server version 9.2.0 or later is required for decimal support.
     *
     * # Constraints
     *
     * - Maximum scale: 76 (QuestDB server limitation)
     * - Maximum mantissa size: 127 bytes (protocol limitation)
     *
     * @param name    Column name.
     * @param decimal Binary decimal view with scale and mantissa bytes.
     */
    line_sender_buffer& column(
        column_name_view name, const decimal::binary_view& decimal)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_dec,
            _impl,
            name._impl,
            decimal.scale(),
            decimal.data(),
            decimal.data_size());
        return *this;
    }

    /**
     * Record a decimal value using a custom type via a customization point.
     *
     * This overload allows you to serialize custom decimal types by
     * implementing a `to_decimal_view_state_impl` function for your type.
     *
     * QuestDB server version 9.2.0 or later is required for decimal support.
     *
     * # Customization
     *
     * To support your custom decimal type, implement
     * `to_decimal_view_state_impl` in either:
     * - The namespace of your type (ADL/Koenig lookup)
     * - The `questdb::ingress::decimal` namespace
     *
     * The function should return either:
     * - A `decimal::binary_view` directly, or
     * - An object with a `.view()` method returning `const
     * decimal::binary_view&`
     *
     * Include your customization point before including `line_sender.hpp`.
     *
     * @tparam ToDecimalViewT Type convertible to decimal::binary_view.
     * @param name            Column name.
     * @param decimal         Custom decimal value.
     */
    template <typename ToDecimalViewT>
    line_sender_buffer& column(column_name_view name, ToDecimalViewT decimal)
    {
        may_init();
        const auto decimal_view_state =
            questdb::ingress::decimal::to_decimal_view_state(decimal);
        return column(name, decimal_view_state.view());
    }

    /** Record a nanosecond timestamp value for the given column. */
    template <typename ClockT>
    line_sender_buffer& column(
        column_name_view name,
        std::chrono::time_point<ClockT, std::chrono::nanoseconds> tp)
    {
        timestamp_nanos nanos{tp};
        return column(name, nanos);
    }

    /** Record a timestamp value for the given column, specified as a
     * `DurationT`. */
    template <typename ClockT, typename DurationT>
    line_sender_buffer& column(
        column_name_view name, std::chrono::time_point<ClockT, DurationT> tp)
    {
        timestamp_micros micros{tp};
        return column(name, micros);
    }

    line_sender_buffer& column(column_name_view name, timestamp_nanos value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_ts_nanos,
            _impl,
            name._impl,
            value.as_nanos());
        return *this;
    }

    line_sender_buffer& column(column_name_view name, timestamp_micros value)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_column_ts_micros,
            _impl,
            name._impl,
            value.as_micros());
        return *this;
    }

    /**
     * Complete the current row with the designated timestamp in nanoseconds.
     *
     * After this call, you can start recording the next row by calling
     * `table()` again, or you can send the accumulated batch by calling
     * `flush()` or one of its variants.
     *
     * If you want to pass the current system timestamp, call `at_now()`.
     *
     * @param timestamp Number of nanoseconds since the Unix epoch.
     */
    void at(timestamp_nanos timestamp)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_at_nanos, _impl, timestamp.as_nanos());
    }

    /**
     * Complete the current row with the designated timestamp in microseconds.
     *
     * After this call, you can start recording the next row by calling
     * `table()` again, or you can send the accumulated batch by calling
     * `flush()` or one of its variants.
     *
     * @param timestamp Number of microseconds since the Unix epoch.
     */
    void at(timestamp_micros timestamp)
    {
        may_init();
        line_sender_error::wrapped_call(
            ::line_sender_buffer_at_micros, _impl, timestamp.as_micros());
    }

    /**
     * Complete the current row without providing a timestamp. The QuestDB
     * instance will insert its own timestamp.
     *
     * Letting the server assign the timestamp can be faster since it a reliable
     * way to avoid out-of-order operations in the database for maximum
     * ingestion throughput. However, it removes the ability to deduplicate
     * rows.
     *
     * This is NOT equivalent to calling `line_sender_buffer_at_nanos()` or
     * `line_sender_buffer_at_micros()` with the current time: the QuestDB
     * server will set the timestamp only after receiving the row. If you're
     * flushing infrequently, the server-assigned timestamp may be significantly
     * behind the time the data was recorded in the buffer.
     *
     * In almost all cases, you should prefer the `at()`/`at_now()` methods.
     *
     * After this call, you can start recording the next row by calling
     * `table()` again, or you can send the accumulated batch by calling
     * `flush()` or one of its variants.
     */
    void at_now()
    {
        may_init();
        line_sender_error::wrapped_call(::line_sender_buffer_at_now, _impl);
    }

    void check_can_flush() const
    {
        if (!_impl)
        {
            throw line_sender_error{
                line_sender_error_code::invalid_api_call,
                "State error: Bad call to `flush`, should have called `table` "
                "instead."};
        }
        line_sender_error::wrapped_call(
            ::line_sender_buffer_check_can_flush, _impl);
    }

    ~line_sender_buffer() noexcept
    {
        if (_impl)
            ::line_sender_buffer_free(_impl);
    }

private:
    inline void may_init()
    {
        if (!_impl)
        {
            _impl = ::line_sender_buffer_with_max_name_len(
                static_cast<::line_sender_protocol_version>(
                    static_cast<int>(_protocol_version)),
                _max_name_len);
            ::line_sender_buffer_reserve(_impl, _init_buf_size);
        }
    }

    ::line_sender_buffer* _impl;
    protocol_version _protocol_version;
    size_t _init_buf_size;
    size_t _max_name_len;

    friend class line_sender;
};

class _user_agent
{
private:
    static inline ::line_sender_utf8 name()
    {
        // Maintained by .bumpversion.cfg
        static const char user_agent[] = "questdb/c++/5.1.0";
        ::line_sender_utf8 utf8 =
            ::line_sender_utf8_assert(sizeof(user_agent) - 1, user_agent);
        return utf8;
    }

    friend class opts;
};

class opts
{
public:
    /**
     * Create a new `opts` instance from the given configuration string.
     * The format of the string is: "tcp::addr=host:port;key=value;...;"
     * Instead of "tcp" you can also specify "tcps", "http", and "https".
     *
     * The accepted keys match one-for-one with the methods on `opts`.
     * For example, this is a valid configuration string:
     *
     * "https::addr=host:port;username=alice;password=secret;"
     *
     * and there are matching methods `opts.username()` and `opts.password()`.
     * The value for `addr=` is supplied directly to `opts()`, so there's no
     * function with a matching name.
     */
    static inline opts from_conf(utf8_view conf)
    {
        return {line_sender_error::wrapped_call(
            ::line_sender_opts_from_conf, conf._impl)};
    }

    /**
     * Create a new `opts` instance from the configuration stored in the
     * `QDB_CLIENT_CONF` environment variable.
     */
    static inline opts from_env()
    {
        opts impl{line_sender_error::wrapped_call(::line_sender_opts_from_env)};
        line_sender_error::wrapped_call(
            ::line_sender_opts_user_agent, impl._impl, _user_agent::name());
        return impl;
    }

    /**
     * Create a new `opts` instance with the given protocol, hostname and port.
     * @param[in] protocol The protocol to use.
     * @param[in] host The QuestDB database host.
     * @param[in] port The QuestDB tcp or http port.
     * validation.
     */
    opts(protocol protocol, utf8_view host, uint16_t port) noexcept
        : _impl{::line_sender_opts_new(
              static_cast<::line_sender_protocol>(protocol), host._impl, port)}
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_user_agent, _impl, _user_agent::name());
    }

    /**
     * Create a new `opts` instance with the given protocol, hostname and
     * service name.
     * @param[in] protocol The protocol to use.
     * @param[in] host The QuestDB database host.
     * @param[in] port The QuestDB tcp or http port as service name.
     */
    opts(protocol protocol, utf8_view host, utf8_view port) noexcept
        : _impl{::line_sender_opts_new_service(
              static_cast<::line_sender_protocol>(protocol),
              host._impl,
              port._impl)}
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_user_agent, _impl, _user_agent::name());
    }

    opts(const opts& other) noexcept
        : _impl{::line_sender_opts_clone(other._impl)}
    {
    }

    opts(opts&& other) noexcept
        : _impl{other._impl}
    {
        other._impl = nullptr;
    }

    opts& operator=(const opts& other) noexcept
    {
        if (this != &other)
        {
            reset();
            _impl = ::line_sender_opts_clone(other._impl);
        }
        return *this;
    }

    opts& operator=(opts&& other) noexcept
    {
        if (this != &other)
        {
            reset();
            _impl = other._impl;
            other._impl = nullptr;
        }
        return *this;
    }

    /**
     * Select local outbound network "bind" interface.
     *
     * This may be relevant if your machine has multiple network interfaces.
     *
     * The default is `0.0.0.0`.
     */
    opts& bind_interface(utf8_view bind_interface)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_bind_interface, _impl, bind_interface._impl);
        return *this;
    }

    /**
     * Set the username for authentication.
     *
     * For TCP this is the `kid` part of the ECDSA key set.
     * The other fields are `token` `token_x` and `token_y`.
     *
     * For HTTP this is part of basic authentication.
     * See also: `password()`.
     */
    opts& username(utf8_view username)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_username, _impl, username._impl);
        return *this;
    }

    /**
     * Set the password for basic HTTP authentication.
     * See also: `username()`.
     */
    opts& password(utf8_view password)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_password, _impl, password._impl);
        return *this;
    }

    /**
     * Set the Token (Bearer) Authentication parameter for HTTP,
     * or the ECDSA private key for TCP authentication.
     */
    opts& token(utf8_view token)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_token, _impl, token._impl);
        return *this;
    }

    /**
     * Set the ECDSA public key X for TCP authentication.
     */
    opts& token_x(utf8_view token_x)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_token_x, _impl, token_x._impl);
        return *this;
    }

    /**
     * Set the ECDSA public key Y for TCP authentication.
     */
    opts& token_y(utf8_view token_y)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_token_y, _impl, token_y._impl);
        return *this;
    }

    /**
     * Configure how long to wait for messages from the QuestDB server during
     * the TLS handshake and authentication process.
     * The value is in milliseconds, and the default is 15 seconds.
     */
    opts& auth_timeout(uint64_t millis)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_auth_timeout, _impl, millis);
        return *this;
    }

    /**
     * Set to `false` to disable TLS certificate verification.
     * This should only be used for debugging purposes as it reduces security.
     *
     * For testing, consider specifying a path to a `.pem` file instead via
     * the `tls_roots` setting.
     */
    opts& tls_verify(bool verify)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_tls_verify, _impl, verify);
        return *this;
    }

    /**
     * Specify where to find the certificate authority used to validate the
     * server's TLS certificate.
     */
    opts& tls_ca(ca ca)
    {
        ::line_sender_ca ca_impl = static_cast<::line_sender_ca>(ca);
        line_sender_error::wrapped_call(
            ::line_sender_opts_tls_ca, _impl, ca_impl);
        return *this;
    }

    /**
     * Set the path to a custom root certificate `.pem` file.
     * This is used to validate the server's certificate during the TLS
     * handshake.
     *
     * See notes on how to test with self-signed certificates:
     * https://github.com/questdb/c-questdb-client/tree/main/tls_certs.
     */
    opts& tls_roots(utf8_view path)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_tls_roots, _impl, path._impl);
        return *this;
    }

    /**
     * The maximum buffer size in bytes that the client will flush to the
     * server. The default is 100 MiB.
     */
    opts& max_buf_size(size_t max_buf_size)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_max_buf_size, _impl, max_buf_size);
        return *this;
    }

    /**
     * The maximum length of a table or column name in bytes.
     * The default is 127 bytes.
     */
    opts& max_name_len(size_t max_name_len)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_max_name_len, _impl, max_name_len);
        return *this;
    }

    /**
     * Set the cumulative duration spent in retries.
     * The value is in milliseconds, and the default is 10 seconds.
     */
    opts& retry_timeout(uint64_t millis)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_retry_timeout, _impl, millis);
        return *this;
    }

    /**
     * Set the minimum acceptable throughput while sending a buffer to the
     * server. The sender will divide the payload size by this number to
     * determine for how long to keep sending the payload before timing out. The
     * value is in bytes per second, and the default is 100 KiB/s. The timeout
     * calculated from minimum throughput is adedd to the value of
     * `request_timeout`.
     *
     * See also: `request_timeout()`
     */
    opts& request_min_throughput(uint64_t bytes_per_sec)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_request_min_throughput, _impl, bytes_per_sec);
        return *this;
    }

    /**
     * Additional time to wait on top of that calculated from the minimum
     * throughput. This accounts for the fixed latency of the HTTP
     * request-response roundtrip. The value is in milliseconds, and the default
     * is 10 seconds.
     *
     * See also: `request_min_throughput()`
     */
    opts& request_timeout(uint64_t millis)
    {
        line_sender_error::wrapped_call(
            ::line_sender_opts_request_timeout, _impl, millis);
        return *this;
    }

    /**
     * Sets the ingestion protocol version.
     *
     * HTTP transport automatically negotiates the protocol version by
     * default(unset, strong recommended). You can explicitlyconfigure the
     * protocol version to avoid the slight latency cost at connection time.
     *
     * TCP transport does not negotiate the protocol version and uses
     * `protocol_version::v1` by default. You must explicitly set
     * `protocol_version::v2` in order to ingest arrays.
     *
     * QuestDB server version 9.0.0 or later is required for
     * `protocol_version::v2` support.
     */
    opts& protocol_version(protocol_version version) noexcept
    {
        const auto c_protocol_version =
            static_cast<::line_sender_protocol_version>(
                static_cast<int>(version));
        line_sender_error::wrapped_call(
            ::line_sender_opts_protocol_version, _impl, c_protocol_version);
        return *this;
    }

    ~opts() noexcept
    {
        reset();
    }

private:
    opts(::line_sender_opts* impl)
        : _impl{impl}
    {
    }

    void reset() noexcept
    {
        if (_impl)
        {
            ::line_sender_opts_free(_impl);
            _impl = nullptr;
        }
    }

    friend class line_sender;

    ::line_sender_opts* _impl;
};

/**
 * Inserts data into QuestDB via the InfluxDB Line Protocol.
 *
 * Batch up rows in a `line_sender_buffer` object, then call
 * `.flush()` or one of its variants to send.
 *
 * When you use ILP-over-TCP, the `line_sender` object connects on construction.
 * If you want to connect later, wrap it in an std::optional.
 */
class line_sender
{
public:
    /**
     * Create a new line sender instance from the given configuration string.
     * The format of the string is: "tcp::addr=host:port;key=value;...;"
     * Instead of "tcp" you can also specify "tcps", "http", and "https".
     *
     * The accepted keys match one-for-one with the methods on `opts`.
     * For example, this is a valid configuration string:
     *
     * "https::addr=host:port;username=alice;password=secret;"
     *
     * and there are matching methods `opts.username()` and `opts.password()`.
     * The value for `addr=` is supplied directly to `opts()`, so there's no
     * function with a matching name.
     *
     * In the case of TCP, this synchronously establishes the TCP connection,
     * and returns once the connection is fully established. If the connection
     * requires authentication or TLS, these will also be completed before
     * returning.
     *
     * The sender should be accessed by only a single thread a time.
     */
    static inline line_sender from_conf(utf8_view conf)
    {
        return {opts::from_conf(conf)};
    }

    /**
     * Create a new `line_sender` instance from the configuration stored in the
     * `QDB_CLIENT_CONF` environment variable.
     *
     * In the case of TCP, this synchronously establishes the TCP connection,
     * and returns once the connection is fully established. If the connection
     * requires authentication or TLS, these will also be completed before
     * returning.
     *
     * The sender should be accessed by only a single thread a time.
     */
    static inline line_sender from_env()
    {
        return {opts::from_env()};
    }

    line_sender(const opts& opts)
        : _impl{
              line_sender_error::wrapped_call(::line_sender_build, opts._impl)}
    {
    }

    line_sender(const line_sender&) = delete;

    line_sender(line_sender&& other) noexcept
        : _impl{other._impl}
    {
        other._impl = nullptr;
    }

    line_sender& operator=(const line_sender&) = delete;

    line_sender& operator=(line_sender&& other) noexcept
    {
        if (this != &other)
        {
            close();
            _impl = other._impl;
            other._impl = nullptr;
        }
        return *this;
    }

    /**
     * Get the current protocol version used by the sender.
     */
    questdb::ingress::protocol_version protocol_version() const noexcept
    {
        ensure_impl();
        return static_cast<enum protocol_version>(
            static_cast<int>(::line_sender_get_protocol_version(_impl)));
    }

    line_sender_buffer new_buffer(size_t init_buf_size = 64 * 1024) noexcept
    {
        ensure_impl();
        return line_sender_buffer{
            this->protocol_version(),
            init_buf_size,
            ::line_sender_get_max_name_len(_impl)};
    }

    /**
     * Send the given buffer of rows to the QuestDB server, clearing the buffer.
     *
     * After this function returns, the buffer is empty and ready for the next
     * batch. If you want to preserve the buffer contents, call
     * `flush_and_keep()`. If you want to ensure the flush is transactional,
     * call `flush_and_keep_with_flags()`.
     *
     * With ILP-over-HTTP, this function sends an HTTP request and waits for the
     * response. If the server responds with an error, it returns a descriptive
     * error. In the case of a network error, it retries until it has exhausted
     * the retry time budget.
     *
     * With ILP-over-TCP, the function blocks only until the buffer is flushed
     * to the underlying OS-level network socket, without waiting to actually
     * send it to the server. In the case of an error, the server will quietly
     * disconnect: consult the server logs for error messages.
     *
     * HTTP should be the first choice, but use TCP if you need to continuously
     * send data to the server at a high rate.
     *
     * To improve the HTTP performance, send larger buffers (with more rows),
     * and consider parallelizing writes using multiple senders from multiple
     * threads.
     */
    void flush(line_sender_buffer& buffer)
    {
        buffer.may_init();
        ensure_impl();
        line_sender_error::wrapped_call(
            ::line_sender_flush, _impl, buffer._impl);
    }

    /**
     * Send the given buffer of rows to the QuestDB server.
     *
     * All the data stays in the buffer. Clear the buffer before starting a new
     * batch.
     *
     * To send and clear in one step, call `flush()` instead. Also, see the docs
     * on that method for more important details on flushing.
     */
    void flush_and_keep(const line_sender_buffer& buffer)
    {
        if (buffer._impl)
        {
            ensure_impl();
            line_sender_error::wrapped_call(
                ::line_sender_flush_and_keep, _impl, buffer._impl);
        }
        else
        {
            line_sender_buffer buffer2{this->protocol_version(), 0};
            buffer2.may_init();
            line_sender_error::wrapped_call(
                ::line_sender_flush_and_keep, _impl, buffer2._impl);
        }
    }

    /**
     * Send the batch of rows in the buffer to the QuestDB server, and, if the
     * parameter `transactional` is true, ensure the flush will be
     * transactional.
     *
     * A flush is transactional iff all the rows belong to the same table. This
     * allows QuestDB to treat the flush as a single database transaction,
     * because it doesn't support transactions spanning multiple tables.
     * Additionally, only ILP-over-HTTP supports transactional flushes.
     *
     * If the flush wouldn't be transactional, this function returns an error
     * and doesn't flush any data.
     *
     * The function sends an HTTP request and waits for the response. If the
     * server responds with an error, it returns a descriptive error. In the
     * case of a network error, it retries until it has exhausted the retry time
     * budget.
     *
     * All the data stays in the buffer. Clear the buffer before starting a new
     * batch.
     */
    void flush_and_keep_with_flags(
        const line_sender_buffer& buffer, bool transactional)
    {
        if (buffer._impl)
        {
            ensure_impl();
            line_sender_error::wrapped_call(
                ::line_sender_flush_and_keep_with_flags,
                _impl,
                buffer._impl,
                transactional);
        }
        else
        {
            line_sender_buffer buffer2{this->protocol_version(), 0};
            buffer2.may_init();
            line_sender_error::wrapped_call(
                ::line_sender_flush_and_keep_with_flags,
                _impl,
                buffer2._impl,
                transactional);
        }
    }

    /**
     * Check if an error occurred previously and the sender must be closed.
     * This happens when there was an earlier failure.
     * This method is specific to ILP-over-TCP and is not relevant for
     * ILP-over-HTTP.
     * @return true if an error occurred with a sender and it must be
     * closed.
     */
    bool must_close() const noexcept
    {
        return _impl ? ::line_sender_must_close(_impl) : false;
    }

    /**
     * Close the connection. Does not flush. Idempotent.
     */
    void close() noexcept
    {
        if (_impl)
        {
            ::line_sender_close(_impl);
            _impl = nullptr;
        }
    }

    ~line_sender() noexcept
    {
        close();
    }

private:
    void ensure_impl() const
    {
        if (!_impl)
            throw line_sender_error{
                line_sender_error_code::invalid_api_call, "Sender closed."};
    }

    ::line_sender* _impl;
};

} // namespace questdb::ingress
