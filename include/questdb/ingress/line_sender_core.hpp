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
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <stdexcept>
#include <type_traits>
#include <utility>
#include <vector>
#if __cplusplus >= 202002L
#    include <span>
#endif

namespace questdb
{

// Forward declaration of the connection pool. `pool` lives in the top-level
// `questdb` namespace — it is cross-cutting, handing out both write-side
// senders and read-side readers — while the sender/error machinery lives in
// `questdb::ingress`. Declared here so `ingress` classes can befriend
// `::questdb::pool` and the egress reader can reference it, without its
// definition (which lives in `column_sender.hpp`).
class pool;

/**
 * Category of error. Single, unified enum for the whole client: it spans both
 * ingest and query. Pinned to the C ABI enum `::line_sender_error_code`
 * (include/questdb/ingress/line_sender.h), which the Rust test
 * `c_header_line_sender_enum_matches_rust` cross-checks against the library.
 * The released `questdb::ingress::line_sender_error_code` remains an alias of
 * this type.
 */
enum class error_code : int
{
    could_not_resolve_addr = ::line_sender_error_could_not_resolve_addr,
    invalid_api_call = ::line_sender_error_invalid_api_call,
    socket_error = ::line_sender_error_socket_error,
    invalid_utf8 = ::line_sender_error_invalid_utf8,
    invalid_name = ::line_sender_error_invalid_name,
    invalid_timestamp = ::line_sender_error_invalid_timestamp,
    auth_error = ::line_sender_error_auth_error,
    tls_error = ::line_sender_error_tls_error,
    http_not_supported = ::line_sender_error_http_not_supported,
    server_flush_error = ::line_sender_error_server_flush_error,
    config_error = ::line_sender_error_config_error,
    array_error = ::line_sender_error_array_error,
    protocol_version_error = ::line_sender_error_protocol_version_error,
    invalid_decimal = ::line_sender_error_invalid_decimal,
    server_rejection = ::line_sender_error_server_rejection,
    arrow_unsupported_column_kind = ::line_sender_error_arrow_unsupported_column_kind,
    arrow_ingest = ::line_sender_error_arrow_ingest,
    failover_retry = ::line_sender_error_failover_retry,
    role_mismatch = ::line_sender_error_role_mismatch,
    connect_timeout = ::line_sender_error_connect_timeout,
    // Query / reader (egress) categories.
    handshake_error = ::line_sender_error_handshake_error,
    unsupported_server = ::line_sender_error_unsupported_server,
    protocol_error = ::line_sender_error_protocol_error,
    invalid_bind = ::line_sender_error_invalid_bind,
    server_schema_mismatch = ::line_sender_error_server_schema_mismatch,
    server_parse_error = ::line_sender_error_server_parse_error,
    server_internal_error = ::line_sender_error_server_internal_error,
    server_security_error = ::line_sender_error_server_security_error,
    limit_exceeded = ::line_sender_error_limit_exceeded,
    server_limit_exceeded = ::line_sender_error_server_limit_exceeded,
    cancelled = ::line_sender_error_cancelled,
    failover_would_duplicate = ::line_sender_error_failover_would_duplicate,
    schema_drift = ::line_sender_error_schema_drift,
    no_schema = ::line_sender_error_no_schema,
    arrow_export = ::line_sender_error_arrow_export,
    batch_too_large = ::line_sender_error_batch_too_large,
    store_resend_required = ::line_sender_error_store_resend_required,
};

// Bridge equality between the C++ `questdb::error_code` and the released C ABI
// enum `::line_sender_error_code` (identical `int` values), so existing
// comparisons like `e.code() == line_sender_error_socket_error` keep compiling.
// Lives in `namespace questdb` so ADL on `error_code` finds it from both
// `questdb::ingress` and `questdb::egress`.
inline bool operator==(error_code l, ::line_sender_error_code r) noexcept
{
    return static_cast<int>(l) == static_cast<int>(r);
}
inline bool operator==(::line_sender_error_code l, error_code r) noexcept
{
    return r == l;
}
inline bool operator!=(error_code l, ::line_sender_error_code r) noexcept
{
    return !(l == r);
}
inline bool operator!=(::line_sender_error_code l, error_code r) noexcept
{
    return !(l == r);
}

/**
 * Base class for every QuestDB client error, ingest or query.
 *
 * `catch (const questdb::error&)` handles a failure from either direction.
 * The released `questdb::ingress::line_sender_error` subclass additionally
 * exposes `in_doubt()` / `qwp_ws_diagnostic()` for sender operations.
 */
class error : public std::runtime_error
{
public:
    error(error_code code, const std::string& what)
        : std::runtime_error{what}
        , _code{code}
    {
    }

    /** Error code categorising the error. */
    error_code code() const noexcept
    {
        return _code;
    }

    /** Convert and take ownership of a C client error. */
    static error from_c(::questdb_error* c_err)
    {
        const std::unique_ptr<::questdb_error, decltype(&::questdb_error_free)>
            owned_err{c_err, ::questdb_error_free};
        const auto code = static_cast<error_code>(
            static_cast<int>(::questdb_error_get_code(owned_err.get())));
        size_t len{0};
        const char* msg{::questdb_error_msg(owned_err.get(), &len)};
        return error{code, std::string{msg, len}};
    }

    /** Call a C function whose final argument is `questdb_error**`. */
    template <typename F, typename... Args>
    static auto wrapped_call(F&& f, Args&&... args)
    {
        ::questdb_error* c_err{nullptr};
        auto result = f(std::forward<Args>(args)..., &c_err);
        if (c_err) throw from_c(c_err);
        return result;
    }

private:
    error_code _code;
};

} // namespace questdb

namespace questdb::ingress
{
constexpr const char* inaddr_any = "0.0.0.0";

class line_sender;
class line_sender_buffer;
class opts;

/** Category of error. Alias of the unified `questdb::error_code`
 *  (`line_sender_error_code` is the sender-facing spelling). */
using line_sender_error_code = ::questdb::error_code;

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

    /** QuestWire Protocol over UDP. */
    udp,

    /** QuestWire Protocol over WebSocket. */
    ws,

    /** QuestWire Protocol over WebSocket Secure (TLS). */
    wss,

    /**
     * Sentinel for a protocol the Rust `Protocol` enum knows about but
     * this FFI build does not. Returned by `line_sender::protocol()` for
     * future variants added after this FFI was compiled; constructing
     * `opts(protocol::unknown, ...)` yields a null-impl opts (same
     * failure path as other constructor errors).
     */
    unknown,
};

enum class qwp_ws_progress
{
    background,
    manual,
};

enum class qwp_ws_error_category
{
    schema_mismatch,
    parse_error,
    internal_error,
    security_error,
    write_error,
    not_writable,
    protocol_violation,
    unknown,
};

enum class qwp_ws_error_policy
{
    retriable,
    retriable_other,
    terminal,
};

struct qwp_ws_error
{
    qwp_ws_error_category category;
    qwp_ws_error_policy applied_policy;
    std::optional<uint8_t> status;
    std::string message;
    std::optional<uint64_t> message_sequence;
    uint64_t from_fsn;
    uint64_t to_fsn;
};

inline qwp_ws_error qwp_ws_error_from_view(
    const ::line_sender_qwpws_error_view& view)
{
    return qwp_ws_error{
        static_cast<qwp_ws_error_category>(
            static_cast<int>(view.category)),
        static_cast<qwp_ws_error_policy>(
            static_cast<int>(view.applied_policy)),
        view.has_status
            ? std::optional<uint8_t>{view.status}
            : std::optional<uint8_t>{},
        std::string{
            view.message ? view.message : "",
            view.message ? view.message_len : 0},
        view.has_message_sequence
            ? std::optional<uint64_t>{view.message_sequence}
            : std::optional<uint64_t>{},
        view.from_fsn,
        view.to_fsn};
}

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
 * For QWP/WebSocket terminal diagnostics, `.qwp_ws_diagnostic()` returns the
 * structured server or protocol error that halted the sender.
 */
class line_sender_error : public ::questdb::error
{
public:
    line_sender_error(
        line_sender_error_code code,
        const std::string& what,
        bool in_doubt = false,
        std::optional<qwp_ws_error> qwp_ws_diagnostic = std::nullopt)
        : ::questdb::error{code, what}
        , _in_doubt{in_doubt}
        , _qwp_ws_diagnostic{std::move(qwp_ws_diagnostic)}
    {
    }

    // `code()` is inherited from `questdb::error` (returns the unified
    // `error_code`, aliased here as `line_sender_error_code`).

    /**
     * Whether the failed operation is *delivery-unknown* ("in doubt"): the
     * current input may already have reached the server even though the call
     * failed. Independent of `code()` — a delivery-unknown failure typically
     * reports `failover_retry`, yet that code alone does not make the input
     * safe to resend. When `true`, only replay the same input if table-level
     * dedup/upsert keys make duplicate rows harmless.
     */
    bool in_doubt() const noexcept
    {
        return _in_doubt;
    }

    /** Structured diagnostic for a QWP/WebSocket server error, if available. */
    const std::optional<qwp_ws_error>& qwp_ws_diagnostic() const noexcept
    {
        return _qwp_ws_diagnostic;
    }

private:
    inline static line_sender_error from_c(::line_sender_error* c_err)
    {
        const std::unique_ptr<
            ::line_sender_error,
            decltype(&::line_sender_error_free)>
            owned_err{c_err, ::line_sender_error_free};
        line_sender_error_code code = static_cast<line_sender_error_code>(
            static_cast<int>(::line_sender_error_get_code(owned_err.get())));
        size_t c_len{0};
        const char* c_msg{::line_sender_error_msg(owned_err.get(), &c_len)};
        std::string msg{c_msg, c_len};
        const bool in_doubt{::line_sender_error_in_doubt(owned_err.get())};

        std::optional<qwp_ws_error> qwp_ws_diagnostic;
        line_sender_qwpws_error_view view{};
        if (::line_sender_error_qwpws_get_view(owned_err.get(), &view))
        {
            qwp_ws_diagnostic = qwp_ws_error_from_view(view);
        }

        return line_sender_error{
            code, msg, in_doubt, std::move(qwp_ws_diagnostic)};
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
    friend class column_sender_view;
    friend class column_chunk;
    friend class arrow_import;
    friend class ::questdb::pool;
    friend class borrowed_column_sender;
    friend class borrowed_row_sender;

    template <
        typename T,
        bool (*F)(T*, size_t, const char*, ::line_sender_error**)>
    friend class basic_view;

    bool _in_doubt;
    std::optional<qwp_ws_error> _qwp_ws_diagnostic;
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

    template <
        typename CharPtr,
        std::enable_if_t<
            std::is_pointer_v<std::remove_reference_t<CharPtr>> &&
                std::is_convertible_v<
                    std::remove_reference_t<CharPtr>,
                    const char*>,
            int> = 0>
    explicit basic_view(CharPtr&& buf)
        : basic_view{buf, std::char_traits<char>::length(buf)}
    {
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
inline utf8_view operator""_utf8(const char* buf, size_t len)
{
    return utf8_view{buf, len};
}

/**
 * Utility to construct `table_name_view` objects from string literals.
 * @code {.cpp}
 * auto table_name = "events"_tn;
 * @endcode
 */
inline table_name_view operator""_tn(const char* buf, size_t len)
{
    return table_name_view{buf, len};
}

/**
 * Utility to construct `column_name_view` objects from string literals.
 * @code {.cpp}
 * auto column_name = "events"_cn;
 * @endcode
 */
inline column_name_view operator""_cn(const char* buf, size_t len)
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
