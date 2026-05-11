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

#include "line_reader.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include "../ingress/line_sender_core.hpp" // utf8_view

namespace questdb::egress
{

// ---------------------------------------------------------------------------
// Thread safety (mirrors the contract documented in `line_reader.h`).
//
// All four wrapper handles (`reader`, `query`, `cursor`, `line_reader_error`)
// are move-only — `std::move` lets you transfer ownership, but the
// destination thread inherits the same per-handle access rules:
//
//   `reader`               — may be moved between threads (no concurrent
//                            access). Insert a happens-before edge on
//                            transfer; the underlying C handle uses non-
//                            atomic state with no automatic visibility.
//   `query` / `cursor`     — MUST stay on the thread that created them.
//                            Even with external synchronisation, moving
//                            either across threads is undefined behaviour
//                            (their internal failover-callback closure is
//                            `!Send`).
//   `line_reader_error`    — has no thread affinity; may be created on
//                            one thread and destroyed/inspected on
//                            another, but must not be used concurrently.
//
// The wrappers cannot statically enforce these rules; they document the
// same contract the C API does.
// ---------------------------------------------------------------------------

/**
 * Stripped-prefix `enum class` mirroring `::line_reader_error_code`. The
 * underlying type is `int` and each variant has the same discriminant as
 * its C counterpart, so the two are reinterpret-castable. Matches the
 * style of `questdb::ingress::line_sender_error_code`.
 */
enum class error_code : int
{
    could_not_resolve_addr = ::line_reader_error_could_not_resolve_addr,
    config_error           = ::line_reader_error_config_error,
    invalid_api_call       = ::line_reader_error_invalid_api_call,
    socket_error           = ::line_reader_error_socket_error,
    tls_error              = ::line_reader_error_tls_error,
    handshake_error        = ::line_reader_error_handshake_error,
    auth_error             = ::line_reader_error_auth_error,
    unsupported_server     = ::line_reader_error_unsupported_server,
    role_mismatch          = ::line_reader_error_role_mismatch,
    protocol_error         = ::line_reader_error_protocol_error,
    invalid_utf8           = ::line_reader_error_invalid_utf8,
    invalid_bind           = ::line_reader_error_invalid_bind,
    invalid_timestamp      = ::line_reader_error_invalid_timestamp,
    invalid_decimal        = ::line_reader_error_invalid_decimal,
    server_schema_mismatch = ::line_reader_error_server_schema_mismatch,
    server_parse_error     = ::line_reader_error_server_parse_error,
    server_internal_error  = ::line_reader_error_server_internal_error,
    server_security_error  = ::line_reader_error_server_security_error,
    limit_exceeded         = ::line_reader_error_limit_exceeded,
    server_limit_exceeded  = ::line_reader_error_server_limit_exceeded,
    cancelled              = ::line_reader_error_cancelled,
};

/**
 * Stripped-prefix `enum class` mirroring `::line_reader_column_kind`. The
 * discriminants match the QWP wire bytes (so reinterpret-casting between
 * the two is sound).
 */
enum class column_kind : int
{
    boolean         = ::line_reader_column_kind_boolean,
    byte            = ::line_reader_column_kind_byte,
    short_          = ::line_reader_column_kind_short,
    int_            = ::line_reader_column_kind_int,
    long_           = ::line_reader_column_kind_long,
    float_          = ::line_reader_column_kind_float,
    double_         = ::line_reader_column_kind_double,
    symbol          = ::line_reader_column_kind_symbol,
    timestamp       = ::line_reader_column_kind_timestamp,
    date            = ::line_reader_column_kind_date,
    uuid            = ::line_reader_column_kind_uuid,
    long256         = ::line_reader_column_kind_long256,
    geohash         = ::line_reader_column_kind_geohash,
    varchar         = ::line_reader_column_kind_varchar,
    timestamp_nanos = ::line_reader_column_kind_timestamp_nanos,
    double_array    = ::line_reader_column_kind_double_array,
    long_array      = ::line_reader_column_kind_long_array,
    decimal64       = ::line_reader_column_kind_decimal64,
    decimal128      = ::line_reader_column_kind_decimal128,
    decimal256      = ::line_reader_column_kind_decimal256,
    char_           = ::line_reader_column_kind_char,
    binary          = ::line_reader_column_kind_binary,
    ipv4            = ::line_reader_column_kind_ipv4,
};

/**
 * Stripped-prefix `enum class` mirroring `::line_reader_server_role`.
 */
enum class server_role : int
{
    standalone       = ::line_reader_server_role_standalone,
    primary          = ::line_reader_server_role_primary,
    replica          = ::line_reader_server_role_replica,
    primary_catchup  = ::line_reader_server_role_primary_catchup,
    other            = ::line_reader_server_role_other,
};

/**
 * Stripped-prefix `enum class` mirroring `::line_reader_terminal_kind`.
 */
enum class terminal_kind : int
{
    none      = ::line_reader_terminal_kind_none,
    end       = ::line_reader_terminal_kind_end,
    exec_done = ::line_reader_terminal_kind_exec_done,
};

// ---------------------------------------------------------------------------
// Bridging equality operators between the C enums and their stripped-prefix
// `enum class` counterparts. The discriminants match (same `int` underlying
// type, same values), so a `static_cast<int>` round-trip is exact. This
// keeps existing C-prefix usage (`e.code() == line_reader_error_config_error`)
// compiling while new code can prefer `error_code::config_error`.
// ---------------------------------------------------------------------------
inline bool operator==(error_code l, ::line_reader_error_code r) noexcept
{ return static_cast<int>(l) == static_cast<int>(r); }
inline bool operator==(::line_reader_error_code l, error_code r) noexcept
{ return r == l; }
inline bool operator!=(error_code l, ::line_reader_error_code r) noexcept
{ return !(l == r); }
inline bool operator!=(::line_reader_error_code l, error_code r) noexcept
{ return !(l == r); }

inline bool operator==(column_kind l, ::line_reader_column_kind r) noexcept
{ return static_cast<int>(l) == static_cast<int>(r); }
inline bool operator==(::line_reader_column_kind l, column_kind r) noexcept
{ return r == l; }
inline bool operator!=(column_kind l, ::line_reader_column_kind r) noexcept
{ return !(l == r); }
inline bool operator!=(::line_reader_column_kind l, column_kind r) noexcept
{ return !(l == r); }

inline bool operator==(server_role l, ::line_reader_server_role r) noexcept
{ return static_cast<int>(l) == static_cast<int>(r); }
inline bool operator==(::line_reader_server_role l, server_role r) noexcept
{ return r == l; }
inline bool operator!=(server_role l, ::line_reader_server_role r) noexcept
{ return !(l == r); }
inline bool operator!=(::line_reader_server_role l, server_role r) noexcept
{ return !(l == r); }

inline bool operator==(terminal_kind l, ::line_reader_terminal_kind r) noexcept
{ return static_cast<int>(l) == static_cast<int>(r); }
inline bool operator==(::line_reader_terminal_kind l, terminal_kind r) noexcept
{ return r == l; }
inline bool operator!=(terminal_kind l, ::line_reader_terminal_kind r) noexcept
{ return !(l == r); }
inline bool operator!=(::line_reader_terminal_kind l, terminal_kind r) noexcept
{ return !(l == r); }

/**
 * Egress error. Mirrors `line_reader_error` from the C API.
 *
 * Thrown by `reader` and `cursor` methods on failure. The raw error code is
 * available via `code()`; the human-readable message via `what()`.
 */
class line_reader_error : public std::runtime_error
{
public:
    line_reader_error(error_code code, const std::string& what)
        : std::runtime_error{what}
        , _code{code}
    {
    }

    /** Error code categorising the error. */
    error_code code() const noexcept { return _code; }

private:
    static line_reader_error from_c(::line_reader_error* c_err)
    {
        const auto c_code = ::line_reader_error_get_code(c_err);
        size_t c_len = 0;
        const char* c_msg = ::line_reader_error_msg(c_err, &c_len);
        std::string msg{c_msg, c_len};
        ::line_reader_error_free(c_err);
        return line_reader_error{static_cast<error_code>(c_code), msg};
    }

    template <typename F, typename... Args>
    static auto wrapped_call(F&& f, Args&&... args)
    {
        ::line_reader_error* c_err{nullptr};
        auto result = f(std::forward<Args>(args)..., &c_err);
        if (c_err) throw from_c(c_err);
        return result;
    }

    error_code _code;

    friend class reader;
    friend class cursor;
    friend class query;
};

/**
 * Optional value for nullable cells. Returned by the typed getters on
 * `cursor`. `std::nullopt` represents a NULL cell on the wire.
 */
template <typename T>
using nullable = std::optional<T>;

class cursor;  // fwd
class query;   // fwd

// ---------------------------------------------------------------------------
// Borrowed views and value types returned by `cursor` getters. These are
// declared at namespace scope (rather than nested in `class cursor`) so
// that callers can name them directly and forward-declare them where
// needed.
// ---------------------------------------------------------------------------

/**
 * Read a `BINARY` value as a borrowed byte span. The view is valid until
 * the next `cursor::next_batch()`, `cursor::cancel()`, or
 * `cursor::add_credit()` call, or until the cursor is closed.
 */
struct binary_view
{
    const uint8_t* data;
    size_t size;
};

struct decimal64
{
    int64_t mantissa;
    int8_t scale;
};

struct decimal128
{
    uint64_t low;
    int64_t high;
    int8_t scale;
};

struct decimal256
{
    std::array<uint8_t, 32> bytes;
    int8_t scale;
};

struct geohash
{
    uint64_t value;
    uint8_t precision_bits;
};

/**
 * Borrowed view over a single `DOUBLE_ARRAY` row. Same lifetime contract
 * as `binary_view`. `data` is concatenated little-endian `double` bytes.
 * The `element(idx)` helper does the LE decode safely via `std::memcpy`.
 */
struct double_array_view
{
    const uint32_t* shape;
    size_t ndim;
    const uint8_t* data;
    size_t data_len;
    size_t element_count;

    double element(size_t flat_idx) const noexcept
    {
        double v = 0.0;
        std::memcpy(&v, data + flat_idx * sizeof(double), sizeof(double));
        return v;
    }
};

/** Same shape as `double_array_view`; `data` holds little-endian
 *  `int64_t` bytes. */
struct long_array_view
{
    const uint32_t* shape;
    size_t ndim;
    const uint8_t* data;
    size_t data_len;
    size_t element_count;

    int64_t element(size_t flat_idx) const noexcept
    {
        int64_t v = 0;
        std::memcpy(&v, data + flat_idx * sizeof(int64_t), sizeof(int64_t));
        return v;
    }
};

/**
 * Borrowed raw LSB-first validity bitmap (bit 1 = null) for a column.
 * Empty when the column has no nulls. Invalidated by `cursor::next_batch()`,
 * `cursor::cancel()`, `cursor::add_credit()`, and by closing the cursor.
 */
struct validity_view
{
    const uint8_t* data;
    size_t size;
    bool empty() const noexcept { return size == 0; }
};

struct terminal_end_info
{
    uint64_t final_seq;
    uint64_t total_rows;
};

struct terminal_exec_done_info
{
    uint8_t op_type;
    uint64_t rows_affected;
};

/**
 * Borrowed `SERVER_INFO` of an endpoint. Returned by `reader::server_info`
 * and `failover_event::server_info`. Never owned by the C++ wrapper —
 * underlying storage is the reader / failover event.
 */
class server_info_view
{
public:
    explicit server_info_view(const ::line_reader_server_info* impl) noexcept
        : _impl{impl} {}

    /** True if a `SERVER_INFO` is available (false for v1 servers). */
    explicit operator bool() const noexcept { return _impl != nullptr; }

    server_role role() const noexcept
    {
        return static_cast<server_role>(::line_reader_server_info_role(_impl));
    }
    uint8_t role_byte() const noexcept
    {
        return ::line_reader_server_info_role_byte(_impl);
    }
    uint64_t epoch() const noexcept
    {
        return ::line_reader_server_info_epoch(_impl);
    }
    uint32_t capabilities() const noexcept
    {
        return ::line_reader_server_info_capabilities(_impl);
    }
    int64_t server_wall_ns() const noexcept
    {
        return ::line_reader_server_info_server_wall_ns(_impl);
    }
    std::string_view cluster_id() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_server_info_cluster_id(_impl, &buf, &len);
        return {buf, len};
    }
    std::string_view node_id() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_server_info_node_id(_impl, &buf, &len);
        return {buf, len};
    }

private:
    const ::line_reader_server_info* _impl;
};

/**
 * Borrowed view over a failover event passed to a user callback. Valid
 * only for the duration of the callback invocation.
 */
class failover_event_view
{
public:
    explicit failover_event_view(const ::line_reader_failover_event* impl) noexcept
        : _impl{impl} {}

    std::string_view failed_host() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_failover_event_failed_host(_impl, &buf, &len);
        return {buf, len};
    }
    uint16_t failed_port() const noexcept
    {
        return ::line_reader_failover_event_failed_port(_impl);
    }
    std::string_view new_host() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_failover_event_new_host(_impl, &buf, &len);
        return {buf, len};
    }
    uint16_t new_port() const noexcept
    {
        return ::line_reader_failover_event_new_port(_impl);
    }
    int64_t new_request_id() const noexcept
    {
        return ::line_reader_failover_event_new_request_id(_impl);
    }
    uint32_t attempts() const noexcept
    {
        return ::line_reader_failover_event_attempts(_impl);
    }
    uint64_t elapsed_ns() const noexcept
    {
        return ::line_reader_failover_event_elapsed_ns(_impl);
    }
    error_code trigger_code() const noexcept
    {
        return static_cast<error_code>(
            ::line_reader_failover_event_trigger_code(_impl));
    }
    std::string_view trigger_msg() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_failover_event_trigger_msg(_impl, &buf, &len);
        return {buf, len};
    }
    server_info_view server_info() const noexcept
    {
        return server_info_view{
            ::line_reader_failover_event_server_info(_impl)};
    }

private:
    const ::line_reader_failover_event* _impl;
};

/** User callback type for failover-reset notifications. */
using failover_callback = std::function<void(const failover_event_view&)>;

inline ::line_sender_utf8 to_c_utf8(::questdb::ingress::utf8_view view) noexcept
{
    ::line_sender_utf8 raw;
    raw.len = view.size();
    raw.buf = view.data();
    return raw;
}

/**
 * RAII handle for a QWP egress reader.
 *
 * Construct from a config string (`Reader::from_conf` form), then call
 * `execute(sql)` to obtain a `cursor`. The reader MUST outlive any cursor
 * obtained from it.
 */
class reader
{
public:
    /**
     * Open a reader using the given config string (e.g.
     * `"qwp::addr=localhost:9000;"`).
     * @throws line_reader_error on failure.
     */
    explicit reader(::questdb::ingress::utf8_view config)
        : _impl{line_reader_error::wrapped_call(
              ::line_reader_from_conf, to_c_utf8(config))}
    {
    }

    /**
     * Open a reader using the config string stored in the
     * `QDB_CLIENT_CONF` environment variable. The variable's value
     * follows the same format as the constructor's `config` argument.
     * @throws line_reader_error with `config_error` if the variable is
     *         unset or its value is malformed; with `invalid_utf8` if
     *         the variable is set but its bytes are not valid UTF-8.
     */
    static reader from_env()
    {
        return reader{
            line_reader_error::wrapped_call(::line_reader_from_env)};
    }

    reader(const reader&) = delete;
    reader& operator=(const reader&) = delete;

    reader(reader&& other) noexcept : _impl{other._impl}
    {
        other._impl = nullptr;
    }

    reader& operator=(reader&& other) noexcept
    {
        if (this != &other)
        {
            ::line_reader_close(_impl);
            _impl = other._impl;
            other._impl = nullptr;
        }
        return *this;
    }

    ~reader() noexcept { ::line_reader_close(_impl); }

    /**
     * Execute a SQL statement with no binds and return a streaming cursor.
     * Convenience for `prepare(sql).execute()`. The cursor borrows from
     * this reader; this reader MUST outlive the cursor. Only one cursor
     * may be live at a time.
     * @throws line_reader_error on failure.
     */
    cursor execute(::questdb::ingress::utf8_view sql);

    /**
     * Begin building a parametrised query. Append binds in placeholder
     * order, then call `.execute()` to obtain a cursor. The reader MUST
     * outlive the query and the cursor. Validation of the SQL is
     * deferred to `query::execute`.
     * @throws line_reader_error if a query or cursor is already in flight
     *         on this reader.
     */
    query prepare(::questdb::ingress::utf8_view sql);

    /** Cumulative bytes successfully read from the wire.
     *  @throws line_reader_error if this reader has been moved from. */
    uint64_t bytes_received() const
    {
        ensure_impl();
        return ::line_reader_bytes_received(_impl);
    }
    /** Cumulative CREDIT bytes granted to the server on this connection.
     *  @throws line_reader_error if this reader has been moved from. */
    uint64_t credit_granted_total() const
    {
        ensure_impl();
        return ::line_reader_credit_granted_total(_impl);
    }
    /** Cumulative `read` time in nanoseconds (saturating).
     *  @throws line_reader_error if this reader has been moved from. */
    uint64_t read_ns() const
    {
        ensure_impl();
        return ::line_reader_read_ns(_impl);
    }
    /** Cumulative decode time in nanoseconds (saturating).
     *  @throws line_reader_error if this reader has been moved from. */
    uint64_t decode_ns() const
    {
        ensure_impl();
        return ::line_reader_decode_ns(_impl);
    }
    /** @throws line_reader_error if this reader has been moved from. */
    void reset_timing()
    {
        ensure_impl();
        ::line_reader_reset_timing(_impl);
    }

    /** Negotiated QWP server version.
     *  @throws line_reader_error if the connection is not yet established
     *          or this reader has been moved from. */
    uint8_t server_version() const
    {
        ensure_impl();
        uint8_t v = 0;
        line_reader_error::wrapped_call(
            ::line_reader_server_version, _impl, &v);
        return v;
    }

    /** Last-seen `SERVER_INFO`, or empty for v1 servers. The view is
     *  invalidated by any reader operation that may reconnect.
     *  @throws line_reader_error if this reader has been moved from. */
    server_info_view server_info() const
    {
        ensure_impl();
        return server_info_view{::line_reader_current_server_info(_impl)};
    }

    /** Host of the endpoint the reader is currently connected to.
     *  @throws line_reader_error if this reader has been moved from. */
    std::string_view current_host() const
    {
        ensure_impl();
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_current_addr_host(_impl, &buf, &len);
        return {buf, len};
    }
    /** Port of the endpoint the reader is currently connected to.
     *  @throws line_reader_error if this reader has been moved from. */
    uint16_t current_port() const
    {
        ensure_impl();
        return ::line_reader_current_addr_port(_impl);
    }

private:
    explicit reader(::line_reader* impl) noexcept : _impl{impl} {}

    /// Throw `line_reader_error{invalid_api_call}` if `_impl` is null.
    /// A null `_impl` means the reader has been moved from or already
    /// closed — calling any method that derefs it would pass `nullptr`
    /// into the C layer where `(*reader).0.get()` is instant UB. Throwing
    /// instead keeps the C++ surface defined for misuse.
    void ensure_impl() const
    {
        if (!_impl)
            throw line_reader_error{
                error_code::invalid_api_call,
                "reader has been closed or moved from."};
    }

    ::line_reader* _impl;
    friend class cursor;
    friend class ::questdb::egress::query;
};

/**
 * RAII query builder. Created by `reader::prepare`, consumed by `execute()`
 * (returns a `cursor`). On destruction without execution, the underlying
 * query is freed.
 */
class query
{
public:
    query(const query&) = delete;
    query& operator=(const query&) = delete;

    query(query&& other) noexcept
        : _impl{other._impl}
        , _callback{std::move(other._callback)}
    {
        other._impl = nullptr;
    }

    query& operator=(query&& other) noexcept
    {
        if (this != &other)
        {
            ::line_reader_query_free(_impl);
            _impl = other._impl;
            _callback = std::move(other._callback);
            other._impl = nullptr;
        }
        return *this;
    }

    ~query() noexcept { ::line_reader_query_free(_impl); }

    query& bind_bool(bool v)
    {
        ensure_impl();
        ::line_reader_query_bind_bool(_impl, v);
        return *this;
    }

    query& bind_i8(int8_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_i8(_impl, v);
        return *this;
    }
    query& bind_i16(int16_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_i16(_impl, v);
        return *this;
    }
    query& bind_i32(int32_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_i32(_impl, v);
        return *this;
    }
    query& bind_i64(int64_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_i64(_impl, v);
        return *this;
    }
    query& bind_f32(float v)
    {
        ensure_impl();
        ::line_reader_query_bind_f32(_impl, v);
        return *this;
    }
    query& bind_f64(double v)
    {
        ensure_impl();
        ::line_reader_query_bind_f64(_impl, v);
        return *this;
    }
    query& bind_timestamp_micros(int64_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_timestamp_micros(_impl, v);
        return *this;
    }
    query& bind_timestamp_nanos(int64_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_timestamp_nanos(_impl, v);
        return *this;
    }
    query& bind_date_millis(int64_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_date_millis(_impl, v);
        return *this;
    }
    query& bind_char(uint16_t v)
    {
        ensure_impl();
        ::line_reader_query_bind_char(_impl, v);
        return *this;
    }
    query& bind_decimal64(int64_t v, int8_t scale)
    {
        ensure_impl();
        ::line_reader_query_bind_decimal64(_impl, v, scale);
        return *this;
    }
    /**
     * Bind a `DECIMAL128` mantissa as two limbs of the standard
     * two's-complement i128 representation, plus the column's `scale`.
     *
     * `mantissa_lo` is the unsigned low 64 bits; `mantissa_hi` is the
     * signed upper 64 bits. `i128 = -1` is
     * `(mantissa_lo = UINT64_MAX, mantissa_hi = -1)` — always cast the
     * high limb through `int64_t` so the sign extends correctly.
     */
    query& bind_decimal128(uint64_t mantissa_lo, int64_t mantissa_hi, int8_t scale)
    {
        ensure_impl();
        ::line_reader_query_bind_decimal128(_impl, mantissa_lo, mantissa_hi, scale);
        return *this;
    }
    query& bind_decimal256(const std::array<uint8_t, 32>& bytes, int8_t scale)
    {
        ensure_impl();
        ::line_reader_query_bind_decimal256(_impl, bytes.data(), scale);
        return *this;
    }
    query& bind_geohash(uint64_t v, uint8_t precision_bits)
    {
        ensure_impl();
        ::line_reader_query_bind_geohash(_impl, v, precision_bits);
        return *this;
    }
    query& bind_varchar(::questdb::ingress::utf8_view v)
    {
        ensure_impl();
        ::line_reader_query_bind_varchar(_impl, to_c_utf8(v));
        return *this;
    }
    query& bind_binary(const uint8_t* buf, size_t len)
    {
        ensure_impl();
        ::line_reader_query_bind_binary(_impl, buf, len);
        return *this;
    }
    query& bind_uuid(const std::array<uint8_t, 16>& bytes)
    {
        ensure_impl();
        ::line_reader_query_bind_uuid(_impl, bytes.data());
        return *this;
    }
    query& bind_long256(const std::array<uint8_t, 32>& bytes)
    {
        ensure_impl();
        ::line_reader_query_bind_long256(_impl, bytes.data());
        return *this;
    }
    query& bind_ipv4(uint32_t host_order)
    {
        ensure_impl();
        ::line_reader_query_bind_ipv4(_impl, host_order);
        return *this;
    }
    query& bind_null(column_kind kind)
    {
        ensure_impl();
        ::line_reader_query_bind_null(
            _impl, static_cast<::line_reader_column_kind>(kind));
        return *this;
    }
    query& bind_null_varchar()
    {
        ensure_impl();
        ::line_reader_query_bind_null_varchar(_impl);
        return *this;
    }
    query& bind_null_binary()
    {
        ensure_impl();
        ::line_reader_query_bind_null_binary(_impl);
        return *this;
    }
    query& bind_null_decimal64(int8_t scale)
    {
        ensure_impl();
        ::line_reader_query_bind_null_decimal64(_impl, scale);
        return *this;
    }
    query& bind_null_decimal128(int8_t scale)
    {
        ensure_impl();
        ::line_reader_query_bind_null_decimal128(_impl, scale);
        return *this;
    }
    query& bind_null_decimal256(int8_t scale)
    {
        ensure_impl();
        ::line_reader_query_bind_null_decimal256(_impl, scale);
        return *this;
    }
    query& bind_null_geohash(uint8_t precision_bits)
    {
        ensure_impl();
        ::line_reader_query_bind_null_geohash(_impl, precision_bits);
        return *this;
    }

    /** Set the initial CREDIT (in bytes; 0 = unbounded). */
    query& initial_credit(uint64_t credit)
    {
        ensure_impl();
        ::line_reader_query_initial_credit(_impl, credit);
        return *this;
    }

    /**
     * Install a failover-reset callback. Replaces any previously installed
     * callback. The closure is stored on the heap and remains alive for
     * the lifetime of the cursor produced by `execute()`.
     *
     * Reentrancy contract — the callback MUST NOT touch the originating
     * `reader`, this `query`, or the `cursor` whose `next_batch` /
     * `cancel` / `add_credit` is in flight. The trampoline runs
     * synchronously while the upstream code holds an exclusive borrow on
     * the underlying `Reader`; any reentrant call (including read-only
     * stat getters) would alias that borrow and is undefined behaviour.
     * Restrict the callback to inspecting `event` and your own
     * `user_data` (captured in the closure).
     *
     * Any exception thrown by `cb` is caught and silently discarded — it
     * cannot propagate, because unwinding across the C FFI boundary is
     * undefined behaviour. Handle errors inside the callback (log, set a
     * flag the surrounding code can poll, etc.); a thrown exception will
     * not abort the query, will not be reported to the caller, and will
     * not leave any visible side effect outside the callback itself.
     *
     * The callback runs on the thread driving the in-flight cursor
     * operation.
     */
    query& on_failover_reset(failover_callback cb)
    {
        ensure_impl();
        // Store the callback on the heap so its address is stable when we
        // hand the raw pointer to the C layer as `user_data`. Ownership is
        // tracked here in `_callback`; on `execute()` we transfer it to
        // the cursor. On query free without execute, the unique_ptr drops
        // the closure.
        //
        // Allocation order matters: build the new unique_ptr into a
        // local first, register it with the C side, and only then swap
        // it into `_callback`. A previous version assigned to `_callback`
        // first, which would destroy the prior payload before allocating
        // the new one — if `make_unique` then threw (OOM under a strict
        // allocator), the C side would be left holding a dangling
        // pointer to the destroyed callback.
        auto new_callback =
            std::make_unique<failover_callback>(std::move(cb));
        ::line_reader_query_on_failover_reset(
            _impl,
            &query::trampoline,
            new_callback.get());
        _callback = std::move(new_callback);
        return *this;
    }

    /** Consume the query and return a streaming cursor.
     *  @throws line_reader_error with `invalid_api_call` if the query has
     *  already been consumed (by a previous `execute()`) or moved from.
     *  @throws line_reader_error on transport / protocol failure. */
    cursor execute();

private:
    explicit query(::line_reader_query* impl) noexcept : _impl{impl} {}

    /// Throw `line_reader_error{invalid_api_call}` if `_impl` is null.
    /// A null `_impl` means the query has been moved from or already
    /// consumed by `execute()` — calling any method that derefs it would
    /// pass `nullptr` into the C layer, where `Box::from_raw(nullptr)` /
    /// `(*query).deferred_err` is instant UB. Throwing instead keeps the
    /// C++ surface defined for misuse.
    void ensure_impl() const
    {
        if (!_impl)
            throw line_reader_error{
                error_code::invalid_api_call,
                "query has been consumed by execute() or moved from."};
    }

    static void trampoline(
        const ::line_reader_failover_event* ev, void* user_data) noexcept
    {
        auto* cb = static_cast<failover_callback*>(user_data);
        if (cb && *cb)
        {
            try
            {
                (*cb)(failover_event_view{ev});
            }
            catch (...)
            {
                // Swallow exceptions — they would unwind across the C FFI
                // boundary which is undefined behaviour. The user must
                // handle errors inside their callback.
            }
        }
    }

    ::line_reader_query* _impl;
    std::unique_ptr<failover_callback> _callback;
    friend class reader;
    friend class cursor;
};

/**
 * RAII handle for a streaming cursor.
 *
 * Obtained from `reader::execute`. Iterate batches with `next_batch()`,
 * which returns `false` when the stream terminates. Per-row scalar values
 * are read with the typed getters; each getter returns `std::nullopt` for
 * NULL cells.
 */
class cursor
{
public:
    cursor(const cursor&) = delete;
    cursor& operator=(const cursor&) = delete;

    cursor(cursor&& other) noexcept
        : _impl{other._impl}
        , _failover_callback{std::move(other._failover_callback)}
    {
        other._impl = nullptr;
    }

    cursor& operator=(cursor&& other) noexcept
    {
        if (this != &other)
        {
            ::line_reader_cursor_free(_impl);
            _impl = other._impl;
            _failover_callback = std::move(other._failover_callback);
            other._impl = nullptr;
        }
        return *this;
    }

    ~cursor() noexcept { ::line_reader_cursor_free(_impl); }

    /**
     * Advance to the next batch.
     * @return true if a new batch is available; false if the stream ended.
     * @throws line_reader_error on failure.
     */
    bool next_batch()
    {
        ensure_impl();
        ::line_reader_error* c_err{nullptr};
        const int rc = ::line_reader_cursor_next_batch(_impl, &c_err);
        if (rc < 0) throw line_reader_error::from_c(c_err);
        return rc > 0;
    }

    /** @throws line_reader_error if this cursor has been moved from. */
    size_t row_count() const
    {
        ensure_impl();
        return ::line_reader_cursor_row_count(_impl);
    }

    /** @throws line_reader_error if this cursor has been moved from. */
    size_t column_count() const
    {
        ensure_impl();
        return ::line_reader_cursor_column_count(_impl);
    }

    egress::column_kind column_kind(size_t col_idx) const
    {
        ensure_impl();
        ::line_reader_column_kind k{};
        line_reader_error::wrapped_call(
            ::line_reader_cursor_column_kind, _impl, col_idx, &k);
        return static_cast<egress::column_kind>(k);
    }

    /**
     * Borrowed UTF-8 column name for `col_idx` in the current batch's
     * schema.
     *
     * The returned `string_view` is invalidated by `next_batch()`,
     * `cancel()`, cursor destruction, and mid-query failover (which can
     * be triggered transparently by `next_batch()`). Do not cache it
     * across batches — re-derive on every batch.
     *
     * @throws line_reader_error if no batch is loaded or `col_idx` is out
     *         of range.
     */
    std::string_view column_name(size_t col_idx) const
    {
        ensure_impl();
        const char* buf = nullptr;
        size_t len = 0;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_column_name, _impl, col_idx, &buf, &len);
        return std::string_view{buf, len};
    }

    /** Read a `BOOLEAN` value; `std::nullopt` if NULL. */
    nullable<bool> get_bool(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        bool v = false, is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_bool,
            _impl,
            col_idx,
            row_idx,
            &v,
            &is_null);
        return is_null ? std::nullopt : std::optional<bool>{v};
    }

    /**
     * Read a 64-bit integer value; `std::nullopt` if NULL. Accepts `LONG`,
     * `TIMESTAMP` (μs), `DATE` (ms), and `TIMESTAMP_NANOS` (ns) — call
     * `column_kind` to disambiguate units.
     */
    nullable<int64_t> get_i64(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        int64_t v = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_i64,
            _impl,
            col_idx,
            row_idx,
            &v,
            &is_null);
        return is_null ? std::nullopt : std::optional<int64_t>{v};
    }

    /** Read a `DOUBLE` value; `std::nullopt` if NULL. */
    nullable<double> get_f64(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        double v = 0.0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_f64,
            _impl,
            col_idx,
            row_idx,
            &v,
            &is_null);
        return is_null ? std::nullopt : std::optional<double>{v};
    }

    /** Read a `BYTE` value. */
    nullable<int8_t> get_i8(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        int8_t v = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_i8, _impl, col_idx, row_idx, &v, &is_null);
        return is_null ? std::nullopt : std::optional<int8_t>{v};
    }

    /** Read a `SHORT` value. */
    nullable<int16_t> get_i16(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        int16_t v = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_i16, _impl, col_idx, row_idx, &v, &is_null);
        return is_null ? std::nullopt : std::optional<int16_t>{v};
    }

    /** Read an `INT` value. Throws on `IPV4` — use `get_ipv4`. */
    nullable<int32_t> get_i32(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        int32_t v = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_i32, _impl, col_idx, row_idx, &v, &is_null);
        return is_null ? std::nullopt : std::optional<int32_t>{v};
    }

    /** Read an `IPV4` value as `uint32_t` packed
     *  `(a<<24)|(b<<16)|(c<<8)|d`. */
    nullable<uint32_t> get_ipv4(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        uint32_t v = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_ipv4, _impl, col_idx, row_idx, &v, &is_null);
        return is_null ? std::nullopt : std::optional<uint32_t>{v};
    }

    /** Read a `FLOAT` value. */
    nullable<float> get_f32(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        float v = 0.0f;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_f32, _impl, col_idx, row_idx, &v, &is_null);
        return is_null ? std::nullopt : std::optional<float>{v};
    }

    /** Read a `CHAR` value (16-bit UTF-16 code unit). */
    nullable<uint16_t> get_char(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        uint16_t v = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_char, _impl, col_idx, row_idx, &v, &is_null);
        return is_null ? std::nullopt : std::optional<uint16_t>{v};
    }

    /** Read a `UUID` value as 16 raw bytes. */
    nullable<std::array<uint8_t, 16>> get_uuid(
        size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        std::array<uint8_t, 16> v{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_uuid,
            _impl,
            col_idx,
            row_idx,
            v.data(),
            &is_null);
        if (is_null) return std::nullopt;
        return v;
    }

    /** Read a `LONG256` value as 32 raw little-endian bytes. */
    nullable<std::array<uint8_t, 32>> get_long256(
        size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        std::array<uint8_t, 32> v{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_long256,
            _impl,
            col_idx,
            row_idx,
            v.data(),
            &is_null);
        if (is_null) return std::nullopt;
        return v;
    }

    /**
     * Read a `VARCHAR` value as a borrowed UTF-8 view. The view is valid
     * until the next `next_batch()`, `cancel()`, or `add_credit()` call,
     * or until this cursor is closed.
     */
    nullable<std::string_view> get_varchar(
        size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        const char* buf = nullptr;
        size_t len = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_varchar,
            _impl,
            col_idx,
            row_idx,
            &buf,
            &len,
            &is_null);
        if (is_null) return std::nullopt;
        return std::string_view{buf, len};
    }

    nullable<binary_view> get_binary(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        const uint8_t* buf = nullptr;
        size_t len = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_binary,
            _impl,
            col_idx,
            row_idx,
            &buf,
            &len,
            &is_null);
        if (is_null) return std::nullopt;
        return binary_view{buf, len};
    }

    /** Read a `SYMBOL` resolved through the dictionary. Same lifetime
     *  contract as `get_varchar`. */
    nullable<std::string_view> get_symbol(
        size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        const char* buf = nullptr;
        size_t len = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_symbol,
            _impl,
            col_idx,
            row_idx,
            &buf,
            &len,
            &is_null);
        if (is_null) return std::nullopt;
        return std::string_view{buf, len};
    }

    /** Read a `DECIMAL64` value (mantissa + scale). */
    nullable<decimal64> get_decimal64(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        decimal64 d{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_decimal64,
            _impl,
            col_idx,
            row_idx,
            &d.mantissa,
            &d.scale,
            &is_null);
        if (is_null) return std::nullopt;
        return d;
    }

    /** Read a `DECIMAL128` value (i64 limbs low/high + scale). */
    nullable<decimal128> get_decimal128(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        decimal128 d{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_decimal128,
            _impl,
            col_idx,
            row_idx,
            &d.low,
            &d.high,
            &d.scale,
            &is_null);
        if (is_null) return std::nullopt;
        return d;
    }

    /** Read a `DECIMAL256` value (32 LE bytes + scale). */
    nullable<decimal256> get_decimal256(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        decimal256 d{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_decimal256,
            _impl,
            col_idx,
            row_idx,
            d.bytes.data(),
            &d.scale,
            &is_null);
        if (is_null) return std::nullopt;
        return d;
    }

    /** Read a `GEOHASH` value (zero-extended u64 + precision_bits). */
    nullable<geohash> get_geohash(size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        geohash g{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_geohash,
            _impl,
            col_idx,
            row_idx,
            &g.value,
            &g.precision_bits,
            &is_null);
        if (is_null) return std::nullopt;
        return g;
    }

    /** Read a `DOUBLE_ARRAY` row; `std::nullopt` if NULL. */
    nullable<double_array_view> get_double_array(
        size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        ::line_reader_double_array_view raw{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_double_array,
            _impl,
            col_idx,
            row_idx,
            &raw,
            &is_null);
        if (is_null) return std::nullopt;
        return double_array_view{
            raw.shape, raw.ndim, raw.data, raw.data_len, raw.element_count};
    }

    /** Read a single `double` element at flat row-major index `flat_idx`;
     *  `std::nullopt` if the row is NULL. Throws on type mismatch or
     *  out-of-range indices. */
    nullable<double> get_double_array_element(
        size_t col_idx, size_t row_idx, size_t flat_idx) const
    {
        ensure_impl();
        double v = 0.0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_double_array_element,
            _impl,
            col_idx,
            row_idx,
            flat_idx,
            &v,
            &is_null);
        if (is_null) return std::nullopt;
        return v;
    }

    /** Read a `LONG_ARRAY` row; `std::nullopt` if NULL. */
    nullable<long_array_view> get_long_array(
        size_t col_idx, size_t row_idx) const
    {
        ensure_impl();
        ::line_reader_long_array_view raw{};
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_long_array,
            _impl,
            col_idx,
            row_idx,
            &raw,
            &is_null);
        if (is_null) return std::nullopt;
        return long_array_view{
            raw.shape, raw.ndim, raw.data, raw.data_len, raw.element_count};
    }

    /** Read a single `int64_t` element at flat row-major index `flat_idx`;
     *  `std::nullopt` if the row is NULL. Throws on type mismatch or
     *  out-of-range indices. */
    nullable<int64_t> get_long_array_element(
        size_t col_idx, size_t row_idx, size_t flat_idx) const
    {
        ensure_impl();
        int64_t v = 0;
        bool is_null = false;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_get_long_array_element,
            _impl,
            col_idx,
            row_idx,
            flat_idx,
            &v,
            &is_null);
        if (is_null) return std::nullopt;
        return v;
    }

    /**
     * Borrow the raw LSB-first validity bitmap (bit 1 = null) for a column.
     * Empty when the column has no nulls. The view is invalidated by
     * `next_batch()`, `cancel()`, `add_credit()`, and by closing the cursor.
     */
    validity_view column_validity(size_t col_idx) const
    {
        ensure_impl();
        const uint8_t* buf = nullptr;
        size_t len = 0;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_column_validity, _impl, col_idx, &buf, &len);
        return {buf, len};
    }

    // ---- Introspection -----------------------------------------------------

    /** @throws line_reader_error if this cursor has been moved from. */
    int64_t request_id() const
    {
        ensure_impl();
        return ::line_reader_cursor_request_id(_impl);
    }
    /**
     * Single-thread only: bound by the cursor's one-thread-at-a-time
     * contract. For cross-thread monitoring, use
     * `reader::credit_granted_total()` instead — same counter, served
     * by an atomic on the reader handle.
     *
     * @throws line_reader_error if this cursor has been moved from.
     */
    uint64_t credit_granted_total() const
    {
        ensure_impl();
        return ::line_reader_cursor_credit_granted_total(_impl);
    }
    /** @throws line_reader_error if this cursor has been moved from. */
    uint32_t failover_resets() const
    {
        ensure_impl();
        return ::line_reader_cursor_failover_resets(_impl);
    }
    /** @throws line_reader_error if this cursor has been moved from. */
    std::string_view current_host() const
    {
        ensure_impl();
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_cursor_current_addr_host(_impl, &buf, &len);
        return {buf, len};
    }
    /** @throws line_reader_error if this cursor has been moved from. */
    uint16_t current_port() const
    {
        ensure_impl();
        return ::line_reader_cursor_current_addr_port(_impl);
    }

    /** `request_id` of the current batch; `std::nullopt` if no batch loaded.
     *  @throws line_reader_error if this cursor has been moved from. */
    nullable<int64_t> batch_request_id() const
    {
        ensure_impl();
        int64_t v = 0;
        if (!::line_reader_cursor_batch_request_id(_impl, &v))
            return std::nullopt;
        return v;
    }
    /** `batch_seq` of the current batch; `std::nullopt` if no batch loaded.
     *  @throws line_reader_error if this cursor has been moved from. */
    nullable<uint64_t> batch_seq() const
    {
        ensure_impl();
        uint64_t v = 0;
        if (!::line_reader_cursor_batch_seq(_impl, &v))
            return std::nullopt;
        return v;
    }
    /** Per-batch wire flags; `std::nullopt` if no batch loaded.
     *  @throws line_reader_error if this cursor has been moved from. */
    nullable<uint8_t> batch_flags() const
    {
        ensure_impl();
        uint8_t v = 0;
        if (!::line_reader_cursor_batch_flags(_impl, &v))
            return std::nullopt;
        return v;
    }

    /** @throws line_reader_error if this cursor has been moved from. */
    egress::terminal_kind terminal_kind() const
    {
        ensure_impl();
        return static_cast<egress::terminal_kind>(
            ::line_reader_cursor_terminal_kind(_impl));
    }

    /** If the terminal is `RESULT_END`, return its info; otherwise nullopt.
     *  @throws line_reader_error if this cursor has been moved from. */
    nullable<terminal_end_info> terminal_end() const
    {
        ensure_impl();
        terminal_end_info info{};
        if (!::line_reader_cursor_terminal_end(
                _impl, &info.final_seq, &info.total_rows))
            return std::nullopt;
        return info;
    }
    /** If the terminal is `EXEC_DONE`, return its info; otherwise nullopt.
     *  @throws line_reader_error if this cursor has been moved from. */
    nullable<terminal_exec_done_info> terminal_exec_done() const
    {
        ensure_impl();
        terminal_exec_done_info info{};
        if (!::line_reader_cursor_terminal_exec_done(
                _impl, &info.op_type, &info.rows_affected))
            return std::nullopt;
        return info;
    }

    // ---- Lifecycle ---------------------------------------------------------

    /** Send a CANCEL frame and drain the stream until terminal.
     *  @throws line_reader_error on transport failure or if this cursor
     *          has been moved from. */
    void cancel()
    {
        ensure_impl();
        line_reader_error::wrapped_call(::line_reader_cursor_cancel, _impl);
    }

    /** Grant additional CREDIT to the server.
     *  @throws line_reader_error on transport failure or if this cursor
     *          has been moved from. */
    void add_credit(uint64_t additional_bytes)
    {
        ensure_impl();
        line_reader_error::wrapped_call(
            ::line_reader_cursor_add_credit, _impl, additional_bytes);
    }

private:
    explicit cursor(::line_reader_cursor* impl) noexcept : _impl{impl} {}

    /// Throw `line_reader_error{invalid_api_call}` if `_impl` is null.
    /// A null `_impl` means the cursor has been moved from or already
    /// closed — calling any method that derefs it would pass `nullptr`
    /// into the C layer where `&mut *cursor` is instant UB. Throwing
    /// instead keeps the C++ surface defined for misuse.
    void ensure_impl() const
    {
        if (!_impl)
            throw line_reader_error{
                error_code::invalid_api_call,
                "cursor has been closed or moved from."};
    }

    ::line_reader_cursor* _impl;
    /// Heap-stored failover callback transferred from `query::execute()`.
    /// The C trampoline holds a raw pointer to this object via `user_data`,
    /// so it MUST live as long as the cursor.
    std::unique_ptr<failover_callback> _failover_callback;
    friend class reader;
    friend class query;
};

inline query reader::prepare(::questdb::ingress::utf8_view sql)
{
    ensure_impl();
    return query{line_reader_error::wrapped_call(
        ::line_reader_query_new, _impl, to_c_utf8(sql))};
}

inline cursor reader::execute(::questdb::ingress::utf8_view sql)
{
    return prepare(sql).execute();
}

inline cursor query::execute()
{
    ensure_impl();
    auto cb = std::move(_callback); // transfer to cursor (or drop on error)
    ::line_reader_error* c_err = nullptr;
    // The C call consumes `_impl` regardless of outcome and sets it to
    // NULL on return — so a subsequent `~query()` calling `_query_free`
    // is a NULL no-op without us having to clear `_impl` explicitly here.
    auto* c = ::line_reader_query_execute(&_impl, &c_err);
    if (!c) throw line_reader_error::from_c(c_err);
    cursor result{c};
    result._failover_callback = std::move(cb);
    return result;
}

} // namespace questdb::egress
