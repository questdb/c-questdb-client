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

#include <cstddef>
#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <type_traits>
#include <utility>
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

    /**
     * InfluxDB Line Protocol v3.
     * QuestDB server version 9.2.0 or later is required for
     * `v3` support.
     */
    v3 = 3,
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

} // namespace questdb::ingress