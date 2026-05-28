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
    // Values 12 and 13 are reserved (formerly invalid_timestamp /
    // invalid_decimal — removed; see line_reader.h).
    server_schema_mismatch = ::line_reader_error_server_schema_mismatch,
    server_parse_error     = ::line_reader_error_server_parse_error,
    server_internal_error  = ::line_reader_error_server_internal_error,
    server_security_error  = ::line_reader_error_server_security_error,
    limit_exceeded         = ::line_reader_error_limit_exceeded,
    server_limit_exceeded     = ::line_reader_error_server_limit_exceeded,
    cancelled                 = ::line_reader_error_cancelled,
    failover_would_duplicate  = ::line_reader_error_failover_would_duplicate,

    /** Streaming Arrow adapter observed a mid-stream schema change. The
     *  cursor is still usable; re-call `next_arrow_batch` after dropping
     *  any partial state to snapshot the new schema. Only raised with
     *  the `arrow` feature enabled. */
    schema_drift     = ::line_reader_error_schema_drift,
    /** `next_arrow_batch` was called on a stream that terminated before
     *  any batch was produced — no schema to snapshot. Only raised with
     *  the `arrow` feature enabled. */
    no_schema        = ::line_reader_error_no_schema,
    /** Arrow C Data Interface export failed (arrow-rs rejected the
     *  produced `ArrayData`'s invariants). Indicates a client bug —
     *  not user-recoverable. Only raised with the `arrow` feature
     *  enabled. */
    arrow_export     = ::line_reader_error_arrow_export,
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
        std::string msg;
        try
        {
            msg.assign(c_msg, c_len);
        }
        catch (...)
        {
            ::line_reader_error_free(c_err);
            throw;
        }
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
    friend class batch;
};

/**
 * Optional value for nullable cells. Returned by the typed getters on
 * `cursor`. `std::nullopt` represents a NULL cell on the wire.
 */
template <typename T>
using nullable = std::optional<T>;

/**
 * Variant-style visitor helper for `column::visit`. Combines several
 * lambdas into a single callable whose `operator()` resolves by
 * argument type:
 *
 *     col.visit(eg::overload{
 *         [](eg::fixed_view<int32_t> v) { ... },
 *         [](eg::varlen_view v)         { ... },
 *         [](auto&&)                    { ... }, // catch-all
 *     });
 *
 * C++17 deduction-guided. Equivalent to the textbook
 * `template<class... Fs> struct overload : Fs... { using Fs::operator()...; };`
 * pattern but spelled once here so callers don't have to re-declare it.
 */
template <typename... Fs>
struct overload : Fs...
{
    using Fs::operator()...;
};
template <typename... Fs>
overload(Fs...) -> overload<Fs...>;

class cursor;           // fwd
class query;            // fwd
class batch;            // fwd
class column;           // fwd
class symbol_dict_view; // fwd

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

    // Non-copyable: `_impl` is borrowed, valid only during the callback.
    failover_event_view(const failover_event_view&) = delete;
    failover_event_view& operator=(const failover_event_view&) = delete;
    failover_event_view(failover_event_view&&) = delete;
    failover_event_view& operator=(failover_event_view&&) = delete;

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

/**
 * Lifecycle phase of a failover-progress event. Numeric values match
 * `line_reader_failover_phase` and the Rust `FailoverPhase` enum.
 */
enum class failover_phase : int
{
    disconnected =
        ::line_reader_failover_phase::line_reader_failover_phase_disconnected,
    retrying =
        ::line_reader_failover_phase::line_reader_failover_phase_retrying,
    reset =
        ::line_reader_failover_phase::line_reader_failover_phase_reset,
    gave_up =
        ::line_reader_failover_phase::line_reader_failover_phase_gave_up,
};

/**
 * Borrowed view over a failover-progress event passed to the user's
 * `on_failover_progress` callback. Valid only for the duration of the
 * callback invocation.
 *
 * Several accessors are populated only in certain phases — see the
 * per-method docs.
 */
class failover_progress_event_view
{
public:
    explicit failover_progress_event_view(
        const ::line_reader_failover_progress_event* impl) noexcept
        : _impl{impl} {}

    // Non-copyable: `_impl` is borrowed, valid only during the callback.
    failover_progress_event_view(const failover_progress_event_view&) = delete;
    failover_progress_event_view& operator=(
        const failover_progress_event_view&) = delete;
    failover_progress_event_view(failover_progress_event_view&&) = delete;
    failover_progress_event_view& operator=(
        failover_progress_event_view&&) = delete;

    failover_phase phase() const noexcept
    {
        return static_cast<failover_phase>(
            ::line_reader_failover_progress_event_phase(_impl));
    }

    /** Endpoint that died. Set on every phase. */
    std::string_view failed_host() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_failover_progress_event_failed_host(_impl, &buf, &len);
        return {buf, len};
    }
    uint16_t failed_port() const noexcept
    {
        return ::line_reader_failover_progress_event_failed_port(_impl);
    }

    /** New-endpoint host (Reset phase only). Returns empty otherwise. */
    std::string_view new_host() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_failover_progress_event_new_host(_impl, &buf, &len);
        return {buf, len};
    }
    /** New-endpoint port (Reset phase only). Returns 0 otherwise. */
    uint16_t new_port() const noexcept
    {
        return ::line_reader_failover_progress_event_new_port(_impl);
    }

    /** New `request_id` (Reset phase only). `std::nullopt` otherwise. */
    std::optional<int64_t> new_request_id() const noexcept
    {
        int64_t out = 0;
        if (::line_reader_failover_progress_event_new_request_id(_impl, &out))
            return out;
        return std::nullopt;
    }

    /** 1-based attempt counter. See header docs for per-phase semantics. */
    uint32_t attempt() const noexcept
    {
        return ::line_reader_failover_progress_event_attempt(_impl);
    }

    /** Trigger (original cause-of-death) error code. */
    error_code trigger_code() const noexcept
    {
        return static_cast<error_code>(
            ::line_reader_failover_progress_event_trigger_code(_impl));
    }
    /** Trigger error message (UTF-8). */
    std::string_view trigger_msg() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_failover_progress_event_trigger_msg(_impl, &buf, &len);
        return {buf, len};
    }

    /** Wall-clock nanoseconds since the disconnect. */
    uint64_t elapsed_ns() const noexcept
    {
        return ::line_reader_failover_progress_event_elapsed_ns(_impl);
    }

    /** `SERVER_INFO` for the new endpoint (Reset phase only, v2+ servers). */
    server_info_view server_info() const noexcept
    {
        return server_info_view{
            ::line_reader_failover_progress_event_server_info(_impl)};
    }

    /** Final error code (GaveUp phase only). `std::nullopt` otherwise. */
    std::optional<error_code> final_error_code() const noexcept
    {
        ::line_reader_error_code raw =
            ::line_reader_error_code::line_reader_error_invalid_api_call;
        if (::line_reader_failover_progress_event_final_error_code(_impl, &raw))
            return static_cast<error_code>(raw);
        return std::nullopt;
    }
    /** Final error message (GaveUp phase only). Empty otherwise. */
    std::string_view final_error_msg() const noexcept
    {
        const char* buf = nullptr;
        size_t len = 0;
        ::line_reader_failover_progress_event_final_error_msg(
            _impl, &buf, &len);
        return {buf, len};
    }

private:
    const ::line_reader_failover_progress_event* _impl;
};

/** User callback type for failover-progress notifications. */
using failover_progress_callback =
    std::function<void(const failover_progress_event_view&)>;

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
     * `"ws::addr=localhost:9000;"`).
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

    /**
     * Move-assign. Closes the previously-held reader before adopting
     * `other`'s impl.
     *
     * @throws line_reader_error with `invalid_api_call` if a `query` or
     *         `cursor` produced by this reader is still live. Replacing
     *         the impl in that state would force `line_reader_close` down
     *         its defense-in-depth branch and silently leak the underlying
     *         reader (so the live cursor's internal `&mut Reader` stays
     *         valid rather than dangling). Surfacing it here as an
     *         exception keeps the leak visible to the application; close
     *         the outstanding cursor / query first.
     */
    reader& operator=(reader&& other) noexcept(false)
    {
        if (this != &other)
        {
            if (_impl && ::line_reader_has_active_query(_impl))
            {
                throw line_reader_error{
                    error_code::invalid_api_call,
                    "reader::operator=(reader&&): a query or cursor is "
                    "still live on the destination reader. Move-assigning "
                    "now would leak the underlying reader (see "
                    "line_reader_close). Destroy the outstanding cursor / "
                    "query first."};
            }
            ::line_reader_close(_impl);
            _impl = other._impl;
            other._impl = nullptr;
        }
        return *this;
    }

    ~reader() noexcept { ::line_reader_close(_impl); }

    /**
     * Execute a SQL statement with no binds and return a streaming cursor.
     * Convenience for `query(sql).execute()`. The cursor borrows from
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
     *
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
        , _progress_callback{std::move(other._progress_callback)}
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
            _progress_callback = std::move(other._progress_callback);
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
    /**
     * Bind a `BINARY` value. The bytes are copied.
     *
     * Not supported by Phase 1 servers — `execute()` will throw
     * `error_code::invalid_bind`. The method is part of the public ABI
     * for forward-compatibility; see
     * `::line_reader_query_bind_binary` in the C header for the
     * server-side rationale.
     */
    query& bind_binary(const uint8_t* buf, size_t len)
    {
        ensure_impl();
        if (buf == nullptr && len != 0)
            throw line_reader_error{
                error_code::invalid_api_call,
                "bind_binary: NULL buffer with non-zero length"};
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
    /**
     * Bind an IPv4 address as a host-order `uint32_t`.
     *
     * Not supported by Phase 1 servers — `execute()` will throw
     * `error_code::invalid_bind`. The method is part of the public ABI
     * for forward-compatibility; see `::line_reader_query_bind_ipv4`
     * in the C header for the server-side rationale.
     */
    query& bind_ipv4(uint32_t host_order)
    {
        ensure_impl();
        ::line_reader_query_bind_ipv4(_impl, host_order);
        return *this;
    }
    /**
     * Bind a typed `NULL` for a simple column kind (numeric, temporal,
     * UUID, etc.). For `VARCHAR` / `BINARY` / `DECIMAL*` / `GEOHASH`
     * use the dedicated `bind_null_*` methods below.
     *
     * Phase 1 servers don't accept all in-range kinds: passing
     * `column_kind::ipv4` is accepted here but `execute()` will throw
     * `error_code::invalid_bind` — see `bind_ipv4` above. The
     * discriminant stays in the public ABI for forward-compatibility.
     */
    query& bind_null(column_kind kind)
    {
        ensure_impl();
        ::line_reader_query_bind_null(
            _impl, static_cast<uint32_t>(kind));
        return *this;
    }
    query& bind_null_varchar()
    {
        ensure_impl();
        ::line_reader_query_bind_null_varchar(_impl);
        return *this;
    }
    /**
     * Bind a SQL `NULL` of column kind `BINARY`.
     *
     * Not supported by Phase 1 servers — `execute()` will throw
     * `error_code::invalid_bind`. See `bind_binary` above.
     */
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

    /**
     * Install a failover-progress callback. Fires at every phase of a
     * mid-query failover lifecycle (Disconnected, Retrying, Reset,
     * GaveUp). The view passed to the callback is borrowed and valid
     * only for the duration of the call.
     *
     * Installing this callback also opts the cursor in to replay-after-
     * data-delivered, the same way `on_failover_reset` does — either
     * being installed clears the silent-duplicate guard.
     *
     * Reentrancy contract is identical to `on_failover_reset`: the
     * callback MUST NOT touch the originating reader / query / cursor,
     * MUST NOT block, and any thrown exception is swallowed (an
     * unwind across the C boundary would be undefined behaviour).
     */
    query& on_failover_progress(failover_progress_callback cb)
    {
        ensure_impl();
        auto new_callback =
            std::make_unique<failover_progress_callback>(std::move(cb));
        ::line_reader_query_on_failover_progress(
            _impl,
            &query::progress_trampoline,
            new_callback.get());
        _progress_callback = std::move(new_callback);
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

    static void progress_trampoline(
        const ::line_reader_failover_progress_event* ev,
        void* user_data) noexcept
    {
        auto* cb = static_cast<failover_progress_callback*>(user_data);
        if (cb && *cb)
        {
            try
            {
                (*cb)(failover_progress_event_view{ev});
            }
            catch (...)
            {
                // Swallow exceptions — see `trampoline` above.
            }
        }
    }

    ::line_reader_query* _impl;
    std::unique_ptr<failover_callback> _callback;
    std::unique_ptr<failover_progress_callback> _progress_callback;
    friend class reader;
    friend class cursor;
};

// ---------------------------------------------------------------------------
// Batch & column bulk access.
//
// `batch`, `column`, and `symbol_dict_view` form the columnar
// counterpart to `cursor`'s per-cell `get_*` getters: project a whole column
// to contiguous buffers in one call. Recommended path for any column-oriented
// or perf-sensitive code (scans, dataframes, Cython zero-copy). The per-cell
// getters on `cursor` remain the convenience path for scalar lookups.
//
// Every view here is BORROWED from the cursor's current batch and invalidated
// by the next `cursor::next_batch()`, `cursor::cancel()`,
// `cursor::add_credit()`, cursor destruction, or mid-query failover
// (transparently triggered by `next_batch()`). Do not cache across batches —
// re-derive after every `next_batch()`.
//
// Value bytes are wire-order little-endian. On a big-endian host, the caller
// must byte-swap.
// ---------------------------------------------------------------------------

/**
 * Snapshot of the connection-scoped symbol dictionary. Index by dictionary
 * code (== entry index) to get the UTF-8 string for that symbol.
 */
class symbol_dict_view
{
public:
    symbol_dict_view() noexcept
        : _d{}
    {
    }
    explicit symbol_dict_view(::line_reader_symbol_dict d) noexcept
        : _d{d}
    {
    }

    /** True when populated by a `batch::symbol_dict()` call (vs
     * default-constructed). */
    bool valid() const noexcept
    {
        return _d.entries != nullptr;
    }

    /** Number of entries; an entry's index is its dictionary code. */
    size_t entry_count() const noexcept
    {
        return _d.entry_count;
    }

    /** Concatenated UTF-8 bytes; `heap_len()` long. */
    const uint8_t* heap() const noexcept
    {
        return _d.heap;
    }
    size_t heap_len() const noexcept
    {
        return _d.heap_len;
    }

    /** Entry table: `entry_count()` entries addressing `heap()`. */
    const ::line_reader_symbol_entry* entries() const noexcept
    {
        return _d.entries;
    }

    /** Decode entry `i` to a UTF-8 view. Throws on out-of-range `i`. */
    std::string_view operator[](size_t i) const
    {
        if (i >= _d.entry_count)
            throw line_reader_error{
                error_code::invalid_api_call,
                "symbol_dict_view: index out of range"};
        const auto& e = _d.entries[i];
        return std::string_view{
            reinterpret_cast<const char*>(_d.heap + e.offset), e.length};
    }

    const ::line_reader_symbol_dict& c_data() const noexcept
    {
        return _d;
    }

private:
    ::line_reader_symbol_dict _d;
};

// Typed views handed to `column::visit`. `kind` disambiguates within a
// group (e.g. `fixed_view<int64_t>` covers LONG / TIMESTAMP / DATE /
// TIMESTAMP_NANOS).
namespace detail
{
inline bool bitmap_is_null(
    const uint8_t* validity, size_t row, size_t row_count) noexcept
{
    return validity && row < row_count &&
           ((validity[row >> 3] >> (row & 7)) & 1);
}
} // namespace detail

/** Fixed-width primitive view: BOOLEAN, BYTE, SHORT, CHAR, INT, IPV4,
 *  LONG, FLOAT, DOUBLE, TIMESTAMP, DATE, TIMESTAMP_NANOS.
 *
 *  `values` may not be aligned to `alignof(T)` — densified column
 *  slices may borrow from the wire payload at offsets that don't
 *  satisfy `T`'s alignment. Use `value(row)` for safe per-row access;
 *  for bulk reads use `std::memcpy` or unaligned-load intrinsics
 *  rather than `values[row]`. */
template <typename T>
struct fixed_view
{
    egress::column_kind kind;
    const T* values;
    size_t row_count;
    const uint8_t* validity; // null when no nulls

    bool is_null(size_t row) const noexcept
    {
        return detail::bitmap_is_null(validity, row, row_count);
    }
    nullable<T> value(size_t row) const noexcept
    {
        if (row >= row_count || is_null(row))
            return std::nullopt;
        T v;
        std::memcpy(&v, values + row, sizeof(T));
        return v;
    }
};

/** DECIMAL64 / DECIMAL128 / DECIMAL256 view. `values` is the dense raw
 *  little-endian mantissa bytes; cast to `int64_t*` for DECIMAL64. */
struct decimal_view
{
    egress::column_kind kind;
    const uint8_t* values;
    size_t value_stride; // 8 / 16 / 32
    size_t row_count;
    int8_t scale;
    const uint8_t* validity;

    bool is_null(size_t row) const noexcept
    {
        return detail::bitmap_is_null(validity, row, row_count);
    }
};

/** UUID / LONG256 view. `values` is dense raw little-endian bytes;
 *  `value_stride` is 16 (UUID) or 32 (LONG256). */
struct bytes_view
{
    egress::column_kind kind;
    const uint8_t* values;
    size_t value_stride;
    size_t row_count;
    const uint8_t* validity;

    bool is_null(size_t row) const noexcept
    {
        return detail::bitmap_is_null(validity, row, row_count);
    }
};

/** GEOHASH view. `values` is dense raw little-endian bytes;
 *  `value_stride` = `ceil(precision_bits / 8)`. */
struct geohash_view
{
    const uint8_t* values;
    size_t value_stride;
    size_t row_count;
    uint8_t precision_bits;
    const uint8_t* validity;

    bool is_null(size_t row) const noexcept
    {
        return detail::bitmap_is_null(validity, row, row_count);
    }
};

/** VARCHAR / BINARY view. `kind` disambiguates. */
struct varlen_view
{
    egress::column_kind kind;
    const uint32_t* offsets; // row_count + 1 entries
    const uint8_t* data;
    size_t data_len;
    size_t row_count;
    const uint8_t* validity;

    bool is_null(size_t row) const noexcept
    {
        return detail::bitmap_is_null(validity, row, row_count);
    }

    /** Row `row` as a borrowed `std::string_view` (interpret bytes as UTF-8).
     */
    nullable<std::string_view> as_string_view(size_t row) const
    {
        if (row >= row_count || is_null(row))
            return std::nullopt;
        const auto s = offsets[row];
        const auto e = offsets[row + 1];
        return std::string_view{
            reinterpret_cast<const char*>(data + s),
            static_cast<size_t>(e - s)};
    }

    /** Row `row` as a borrowed byte span. */
    nullable<binary_view> as_binary(size_t row) const
    {
        if (row >= row_count || is_null(row))
            return std::nullopt;
        const auto s = offsets[row];
        const auto e = offsets[row + 1];
        return binary_view{data + s, static_cast<size_t>(e - s)};
    }
};

/** SYMBOL view: dictionary-encoded UTF-8. */
struct symbol_view
{
    const uint32_t* codes;
    size_t row_count;
    const uint8_t* validity;
    symbol_dict_view dict;

    bool is_null(size_t row) const noexcept
    {
        return detail::bitmap_is_null(validity, row, row_count);
    }

    nullable<std::string_view> resolve(size_t row) const
    {
        if (row >= row_count || is_null(row))
            return std::nullopt;
        const uint32_t code = codes[row];
        if (code >= dict.entry_count())
            throw line_reader_error{
                error_code::invalid_api_call,
                "symbol_view::resolve: code out of dictionary range"};
        return dict[code];
    }
};

/** Ragged array view (DOUBLE_ARRAY in this revision). `T == double`. */
template <typename T>
struct array_view
{
    egress::column_kind kind;
    const T* data;                // flat row-major, all rows
    const uint32_t* data_offsets; // row_count + 1, byte offsets into data
    size_t data_len;              // bytes
    const uint32_t* shapes;
    const uint32_t* shape_offsets;
    size_t row_count;
    const uint8_t* validity;

    bool is_null(size_t row) const noexcept
    {
        return detail::bitmap_is_null(validity, row, row_count);
    }

    /** Per-row shape (dimension lengths). Returns `nullopt` for out-of-range.
     */
    nullable<std::pair<const uint32_t*, size_t>> shape(size_t row) const
    {
        if (row >= row_count)
            return std::nullopt;
        const auto s = shape_offsets[row];
        const auto e = shape_offsets[row + 1];
        return std::make_pair(shapes + s, static_cast<size_t>(e - s));
    }

    /** Per-row typed elements (count). Returns `nullopt` for out-of-range. */
    nullable<std::pair<const T*, size_t>> elements(size_t row) const
    {
        if (row >= row_count)
            return std::nullopt;
        const auto s = data_offsets[row];
        const auto e = data_offsets[row + 1];
        return std::make_pair(
            reinterpret_cast<const T*>(
                reinterpret_cast<const uint8_t*>(data) + s),
            static_cast<size_t>((e - s) / sizeof(T)));
    }
};

/**
 * Borrowed projection of one column. Polymorphic over the column kinds:
 * scalar / variable-width / SYMBOL / DOUBLE_ARRAY. `kind()` distinguishes.
 *
 * Scalar-family accessors (`values<T>()`, `varchar(row)`, `decimal_scale()`,
 * `symbol(row)`, …) throw on array columns; array-family accessors
 * (`shape(...)`, `elements<T>(...)`, `data_offsets()`, …) throw on scalar
 * columns. `is_array()` lets callers probe in advance.
 *
 * Obtain from `batch::column(i)`. Every pointer reachable through this
 * object borrows from the batch and shares its lifetime.
 */
class column
{
public:
    egress::column_kind kind() const noexcept
    {
        return _is_array ? static_cast<egress::column_kind>(_array.kind)
                         : static_cast<egress::column_kind>(_scalar.kind);
    }
    size_t row_count() const noexcept
    {
        return _is_array ? _array.row_count : _scalar.row_count;
    }
    bool is_array() const noexcept
    {
        return _is_array;
    }

    // ---- Validity (shared by both families) ----
    /** Raw LSB-first validity bitmap (bit 1 = NULL); null when no nulls. */
    const uint8_t* validity() const noexcept
    {
        return _is_array ? _array.validity : _scalar.validity;
    }
    size_t validity_bytes() const noexcept
    {
        return validity() ? (row_count() + 7) / 8 : 0;
    }
    bool has_nulls() const noexcept
    {
        return validity() != nullptr;
    }
    /** True if `row` is NULL. False for out-of-range rows. */
    bool is_null(size_t row) const noexcept
    {
        const auto* v = validity();
        return v && row < row_count() && ((v[row >> 3] >> (row & 7)) & 1);
    }

    // ---- Scalar family ----
    /** DECIMAL64/128/256 shared scale; 0 otherwise. */
    int8_t decimal_scale() const noexcept
    {
        return _is_array ? 0 : _scalar.decimal_scale;
    }
    /** GEOHASH precision (1..60); 0 otherwise. */
    uint8_t geohash_precision_bits() const noexcept
    {
        return _is_array ? 0 : _scalar.geohash_precision_bits;
    }
    /** Dense little-endian value bytes; null for variable-width / SYMBOL /
     *  array. */
    const void* values_raw() const noexcept
    {
        return _is_array ? nullptr : _scalar.values;
    }
    /** Bytes per fixed-width value; 0 for variable-width / SYMBOL / array. */
    size_t value_stride() const noexcept
    {
        return _is_array ? 0 : _scalar.value_stride;
    }

    /**
     * Typed contiguous pointer over the column's `row_count()` dense values.
     *
     * Throws on (a) array columns, (b) `sizeof(T) != value_stride()`,
     * (c) columns without dense values (variable-width / SYMBOL), or
     * (d) `T` not in the kind whitelist for this column's `kind()`. The
     * whitelist rejects same-stride / different-semantics combinations
     * (e.g. `values<int64_t>()` on a DECIMAL64 column, or `values<int32_t>()`
     * on an IPV4 column). Use the strict overload `values<T>(kind)` to
     * bypass when you know what you're doing.
     *
     * **Alignment:** the returned pointer is NOT guaranteed to be aligned
     * to `alignof(T)`. Densified column slices may borrow from the wire
     * payload starting at an offset that doesn't satisfy `T`'s alignment
     * (e.g. an INT column whose data begins right after a validity
     * bitmap of odd byte length). Dereferencing the pointer as
     * `base[row]` or forming a `const T&` from it is undefined behaviour.
     * For per-row access use `get<T>(row)` (already alignment-safe). For
     * bulk access read via `std::memcpy` or unaligned-load intrinsics
     * (`_mm_loadu_si128`, `vld1q_u32`, ...).
     */
    template <typename T>
    const T* values() const
    {
        ensure_scalar("column::values<T>");
        if (!_scalar.values)
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::values<T>: column has no dense values "
                "(variable-width or SYMBOL)"};
        if (sizeof(T) != _scalar.value_stride)
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::values<T>: sizeof(T) != value_stride"};
        if (!is_kind_compatible<T>(kind()))
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::values<T>: T is not in the kind whitelist for this "
                "column kind (stride matches but semantics differ); use the "
                "strict overload values<T>(kind) to bypass"};
        return static_cast<const T*>(_scalar.values);
    }

    /**
     * Strict overload: caller asserts an exact `required` kind, bypassing
     * the whitelist. For deliberate reinterpretation (e.g. reading a
     * DECIMAL64's raw mantissa as `int64_t`). Same alignment caveat as
     * the whitelist overload: returned pointer may not be `alignof(T)`.
     */
    template <typename T>
    const T* values(egress::column_kind required) const
    {
        ensure_scalar("column::values<T>(kind)");
        if (kind() != required)
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::values<T>(kind): column kind mismatch"};
        if (!_scalar.values)
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::values<T>(kind): column has no dense values"};
        if (sizeof(T) != _scalar.value_stride)
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::values<T>(kind): sizeof(T) != value_stride"};
        return static_cast<const T*>(_scalar.values);
    }

    /** VARCHAR / BINARY offset table (`row_count + 1` entries); null
     *  otherwise. */
    const uint32_t* var_offsets() const noexcept
    {
        return _is_array ? nullptr : _scalar.var_offsets;
    }
    /** VARCHAR / BINARY concatenated data blob; null otherwise. */
    const uint8_t* var_data() const noexcept
    {
        return _is_array ? nullptr : _scalar.var_data;
    }
    size_t var_data_len() const noexcept
    {
        return _is_array ? 0 : _scalar.var_data_len;
    }

    /** SYMBOL per-row dictionary codes (`row_count` entries); null
     *  otherwise. */
    const uint32_t* symbol_codes() const noexcept
    {
        return _is_array ? nullptr : _scalar.symbol_codes;
    }

    /** Snapshot of the symbol dictionary; populated only for SYMBOL columns. */
    const symbol_dict_view& symbol_dict() const noexcept
    {
        return _dict;
    }

    /** Resolve a VARCHAR row to a borrowed UTF-8 view. */
    nullable<std::string_view> varchar(size_t row) const
    {
        ensure_kind(column_kind::varchar, "column::varchar");
        ensure_row_in_range(row, "column::varchar");
        if (is_null(row))
            return std::nullopt;
        const auto s = _scalar.var_offsets[row];
        const auto e = _scalar.var_offsets[row + 1];
        return std::string_view{
            reinterpret_cast<const char*>(_scalar.var_data + s),
            static_cast<size_t>(e - s)};
    }

    /** Resolve a BINARY row to a borrowed byte view. */
    nullable<binary_view> binary(size_t row) const
    {
        ensure_kind(column_kind::binary, "column::binary");
        ensure_row_in_range(row, "column::binary");
        if (is_null(row))
            return std::nullopt;
        const auto s = _scalar.var_offsets[row];
        const auto e = _scalar.var_offsets[row + 1];
        return binary_view{_scalar.var_data + s, static_cast<size_t>(e - s)};
    }

    /** Resolve a SYMBOL row through the dictionary. */
    nullable<std::string_view> symbol(size_t row) const
    {
        ensure_kind(column_kind::symbol, "column::symbol");
        ensure_row_in_range(row, "column::symbol");
        if (is_null(row))
            return std::nullopt;
        const uint32_t code = _scalar.symbol_codes[row];
        if (code >= _dict.entry_count())
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::symbol: code out of dictionary range"};
        return _dict[code];
    }

    /** Fixed-width scalar row → `nullable<T>`. Same kind-whitelist as
     *  `values<T>()`; use the strict overload to bypass. */
    template <typename T>
    nullable<T> get(size_t row) const
    {
        const T* base = values<T>();
        ensure_row_in_range(row, "column::get");
        if (is_null(row))
            return std::nullopt;
        T value;
        std::memcpy(&value, base + row, sizeof(T));
        return value;
    }

    /** Strict overload: explicit `required` kind, bypasses the whitelist. */
    template <typename T>
    nullable<T> get(size_t row, egress::column_kind required) const
    {
        const T* base = values<T>(required);
        ensure_row_in_range(row, "column::get(kind)");
        if (is_null(row))
            return std::nullopt;
        T value;
        std::memcpy(&value, base + row, sizeof(T));
        return value;
    }

    /** DECIMAL64 row → `nullable<decimal64>`. */
    nullable<egress::decimal64> get_decimal64(size_t row) const
    {
        ensure_kind(column_kind::decimal64, "column::get_decimal64");
        ensure_row_in_range(row, "column::get_decimal64");
        if (is_null(row))
            return std::nullopt;
        int64_t mantissa = 0;
        std::memcpy(
            &mantissa,
            static_cast<const uint8_t*>(_scalar.values) + row * 8,
            8);
        return egress::decimal64{mantissa, _scalar.decimal_scale};
    }

    /** DECIMAL128 row → `nullable<decimal128>`. */
    nullable<egress::decimal128> get_decimal128(size_t row) const
    {
        ensure_kind(column_kind::decimal128, "column::get_decimal128");
        ensure_row_in_range(row, "column::get_decimal128");
        if (is_null(row))
            return std::nullopt;
        const auto* p = static_cast<const uint8_t*>(_scalar.values) + row * 16;
        uint64_t lo = 0;
        int64_t hi = 0;
        std::memcpy(&lo, p, 8);
        std::memcpy(&hi, p + 8, 8);
        return egress::decimal128{lo, hi, _scalar.decimal_scale};
    }

    /** DECIMAL256 row → `nullable<decimal256>`. */
    nullable<egress::decimal256> get_decimal256(size_t row) const
    {
        ensure_kind(column_kind::decimal256, "column::get_decimal256");
        ensure_row_in_range(row, "column::get_decimal256");
        if (is_null(row))
            return std::nullopt;
        std::array<uint8_t, 32> out{};
        std::memcpy(
            out.data(),
            static_cast<const uint8_t*>(_scalar.values) + row * 32,
            32);
        return egress::decimal256{out, _scalar.decimal_scale};
    }

    /** UUID row → `nullable<array<uint8_t, 16>>` (LE bytes). */
    nullable<std::array<uint8_t, 16>> get_uuid(size_t row) const
    {
        ensure_kind(column_kind::uuid, "column::get_uuid");
        ensure_row_in_range(row, "column::get_uuid");
        if (is_null(row))
            return std::nullopt;
        std::array<uint8_t, 16> out{};
        std::memcpy(
            out.data(),
            static_cast<const uint8_t*>(_scalar.values) + row * 16,
            16);
        return out;
    }

    /** LONG256 row → `nullable<array<uint8_t, 32>>` (LE bytes). */
    nullable<std::array<uint8_t, 32>> get_long256(size_t row) const
    {
        ensure_kind(column_kind::long256, "column::get_long256");
        ensure_row_in_range(row, "column::get_long256");
        if (is_null(row))
            return std::nullopt;
        std::array<uint8_t, 32> out{};
        std::memcpy(
            out.data(),
            static_cast<const uint8_t*>(_scalar.values) + row * 32,
            32);
        return out;
    }

    /** GEOHASH row → `nullable<geohash>`. Decodes the LE stride bytes into
     *  a `uint64_t`. */
    nullable<egress::geohash> get_geohash(size_t row) const
    {
        ensure_kind(column_kind::geohash, "column::get_geohash");
        ensure_row_in_range(row, "column::get_geohash");
        if (is_null(row))
            return std::nullopt;
        const auto stride = _scalar.value_stride;
        uint64_t v = 0;
        std::memcpy(
            &v,
            static_cast<const uint8_t*>(_scalar.values) + row * stride,
            stride);
        return egress::geohash{
            v, static_cast<uint8_t>(_scalar.geohash_precision_bits)};
    }

    // ---- Array family (throws on scalar columns) ----
    /** Flat row-major little-endian element bytes for every row. */
    const uint8_t* data() const noexcept
    {
        return _is_array ? _array.data : nullptr;
    }
    size_t data_len() const noexcept
    {
        return _is_array ? _array.data_len : 0;
    }
    /** Per-row byte offsets into `data()`, `row_count + 1` entries. */
    const uint32_t* data_offsets() const noexcept
    {
        return _is_array ? _array.data_offsets : nullptr;
    }
    /** Concatenated per-row shapes (dimension lengths). */
    const uint32_t* shapes() const noexcept
    {
        return _is_array ? _array.shapes : nullptr;
    }
    size_t shapes_len() const noexcept
    {
        return _is_array ? _array.shapes_len : 0;
    }
    /** Per-row offsets into `shapes()`, `row_count + 1` entries. */
    const uint32_t* shape_offsets() const noexcept
    {
        return _is_array ? _array.shape_offsets : nullptr;
    }

    /**
     * Per-row dimension lengths. `*out_rank` is set to the row's rank on
     * success. Returns null and sets `*out_rank = 0` for out-of-range rows.
     * For a null row the shape is empty (rank 0) — distinct from a
     * non-null empty array (rank 0 with zero elements).
     */
    const uint32_t* shape(size_t row, size_t* out_rank) const
    {
        ensure_array("column::shape");
        if (row >= _array.row_count)
        {
            if (out_rank)
                *out_rank = 0;
            return nullptr;
        }
        const auto s = _array.shape_offsets[row];
        const auto e = _array.shape_offsets[row + 1];
        if (out_rank)
            *out_rank = static_cast<size_t>(e - s);
        return _array.shapes + s;
    }

    /**
     * Per-row flat element bytes. `*out_len` set to the byte length on
     * success. Returns null / 0 for out-of-range rows.
     */
    const uint8_t* row_bytes(size_t row, size_t* out_len) const
    {
        ensure_array("column::row_bytes");
        if (row >= _array.row_count)
        {
            if (out_len)
                *out_len = 0;
            return nullptr;
        }
        const auto s = _array.data_offsets[row];
        const auto e = _array.data_offsets[row + 1];
        if (out_len)
            *out_len = static_cast<size_t>(e - s);
        return _array.data + s;
    }

    /**
     * Per-row typed element pointer. `*out_count` is set to the element
     * count on success. Only `T == double` is supported in this revision
     * (DOUBLE_ARRAY).
     */
    template <typename T>
    const T* elements(size_t row, size_t* out_count) const;

    /**
     * Kind-dispatched visitor entry. Calls `v(view)` with the typed view
     * matching `kind()`: `fixed_view<T>` for fixed-width primitives,
     * `decimal_view` / `bytes_view` / `geohash_view` / `varlen_view` /
     * `symbol_view` / `array_view<T>` for the rest. All overloads must
     * return the same type, same contract as `std::visit`.
     */
    template <typename Visitor>
    decltype(auto) visit(Visitor&& v) const
    {
        switch (kind())
        {
        case column_kind::boolean:
            return std::forward<Visitor>(v)(
                make_fixed_view<uint8_t>(column_kind::boolean));
        case column_kind::byte:
            return std::forward<Visitor>(v)(
                make_fixed_view<int8_t>(column_kind::byte));
        case column_kind::short_:
            return std::forward<Visitor>(v)(
                make_fixed_view<int16_t>(column_kind::short_));
        case column_kind::char_:
            return std::forward<Visitor>(v)(
                make_fixed_view<uint16_t>(column_kind::char_));
        case column_kind::int_:
            return std::forward<Visitor>(v)(
                make_fixed_view<int32_t>(column_kind::int_));
        case column_kind::ipv4:
            return std::forward<Visitor>(v)(
                make_fixed_view<uint32_t>(column_kind::ipv4));
        case column_kind::long_:
        case column_kind::timestamp:
        case column_kind::date:
        case column_kind::timestamp_nanos:
            return std::forward<Visitor>(v)(make_fixed_view<int64_t>(kind()));
        case column_kind::float_:
            return std::forward<Visitor>(v)(
                make_fixed_view<float>(column_kind::float_));
        case column_kind::double_:
            return std::forward<Visitor>(v)(
                make_fixed_view<double>(column_kind::double_));
        case column_kind::decimal64:
        case column_kind::decimal128:
        case column_kind::decimal256:
            return std::forward<Visitor>(v)(make_decimal_view());
        case column_kind::uuid:
        case column_kind::long256:
            return std::forward<Visitor>(v)(make_bytes_view());
        case column_kind::geohash:
            return std::forward<Visitor>(v)(make_geohash_view());
        case column_kind::varchar:
        case column_kind::binary:
            return std::forward<Visitor>(v)(make_varlen_view());
        case column_kind::symbol:
            return std::forward<Visitor>(v)(make_symbol_view());
        case column_kind::double_array:
            return std::forward<Visitor>(v)(make_array_view<double>());
        case column_kind::long_array:
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::visit: LONG_ARRAY is not supported in this revision"};
        default:
            throw line_reader_error{
                error_code::invalid_api_call,
                "column::visit: unknown column kind"};
        }
    }

    // ---- Raw C-side data (escape hatches) ----
    const ::line_reader_column_data& c_scalar_data() const noexcept
    {
        return _scalar;
    }
    const ::line_reader_array_data& c_array_data() const noexcept
    {
        return _array;
    }

private:
    friend class batch;

    static column make_scalar(
        ::line_reader_column_data d, symbol_dict_view dict) noexcept
    {
        column c;
        c._scalar = d;
        c._dict = dict;
        c._is_array = false;
        return c;
    }
    static column make_array(::line_reader_array_data d) noexcept
    {
        column c;
        c._array = d;
        c._is_array = true;
        return c;
    }

    template <typename T>
    fixed_view<T> make_fixed_view(egress::column_kind k) const noexcept
    {
        return fixed_view<T>{
            k,
            static_cast<const T*>(_scalar.values),
            _scalar.row_count,
            _scalar.validity};
    }
    decimal_view make_decimal_view() const noexcept
    {
        return decimal_view{
            kind(),
            static_cast<const uint8_t*>(_scalar.values),
            _scalar.value_stride,
            _scalar.row_count,
            _scalar.decimal_scale,
            _scalar.validity};
    }
    bytes_view make_bytes_view() const noexcept
    {
        return bytes_view{
            kind(),
            static_cast<const uint8_t*>(_scalar.values),
            _scalar.value_stride,
            _scalar.row_count,
            _scalar.validity};
    }
    geohash_view make_geohash_view() const noexcept
    {
        return geohash_view{
            static_cast<const uint8_t*>(_scalar.values),
            _scalar.value_stride,
            _scalar.row_count,
            _scalar.geohash_precision_bits,
            _scalar.validity};
    }
    varlen_view make_varlen_view() const noexcept
    {
        return varlen_view{
            kind(),
            _scalar.var_offsets,
            _scalar.var_data,
            _scalar.var_data_len,
            _scalar.row_count,
            _scalar.validity};
    }
    symbol_view make_symbol_view() const noexcept
    {
        return symbol_view{
            _scalar.symbol_codes, _scalar.row_count, _scalar.validity, _dict};
    }
    template <typename T>
    array_view<T> make_array_view() const noexcept
    {
        static_assert(
            alignof(T) <= 8,
            "array_view<T>: alignment > 8 would exceed the Rust allocator's "
            "de-facto alignment guarantee for the underlying buffer");
        return array_view<T>{
            static_cast<egress::column_kind>(_array.kind),
            reinterpret_cast<const T*>(_array.data),
            _array.data_offsets,
            _array.data_len,
            _array.shapes,
            _array.shape_offsets,
            _array.row_count,
            _array.validity};
    }

    void ensure_scalar(const char* what) const
    {
        if (_is_array)
            throw line_reader_error{
                error_code::invalid_api_call,
                std::string{what} +
                    ": column is an array; use the array "
                    "accessors (shape / elements / data_offsets / ...)"};
    }
    void ensure_array(const char* what) const
    {
        if (!_is_array)
            throw line_reader_error{
                error_code::invalid_api_call,
                std::string{what} +
                    ": column is not an array; use the "
                    "scalar accessors (values<T> / varchar / symbol / ...)"};
    }
    void ensure_kind(egress::column_kind expected, const char* what) const
    {
        if (kind() != expected)
            throw line_reader_error{
                error_code::invalid_api_call,
                std::string{what} + ": column kind mismatch"};
    }
    void ensure_row_in_range(size_t row, const char* what) const
    {
        if (row >= row_count())
            throw line_reader_error{
                error_code::invalid_api_call,
                std::string{what} + ": row index out of range"};
    }

    template <typename T>
    static constexpr bool is_kind_compatible(egress::column_kind) noexcept
    {
        static_assert(
            sizeof(T) == 0,
            "column::values<T>: T is not a supported scalar type. "
            "Supported: bool, uint8_t, int8_t, int16_t, uint16_t, int32_t, "
            "uint32_t, int64_t, float, double. Use the strict overload "
            "values<T>(kind) to bypass the whitelist with an explicit kind "
            "assertion.");
        return false;
    }

    ::line_reader_column_data _scalar{};
    ::line_reader_array_data _array{};
    symbol_dict_view _dict{};
    bool _is_array{false};
};

// Whitelist of column kinds each scalar `T` may read via `values<T>()`. The
// compatibility groups are deliberately tight: shared-stride / different-
// semantics combinations (DECIMAL64 vs LONG; IPV4 unsigned vs INT signed)
// are rejected here so a `values<int64_t>()` slip on a DECIMAL64 column
// surfaces as a clean error instead of silently returning the scaled
// mantissa as a "plain" i64. Use `values<T>(kind)` to opt out.
template <>
constexpr bool column::is_kind_compatible<bool>(column_kind k) noexcept
{
    return k == column_kind::boolean;
}
template <>
constexpr bool column::is_kind_compatible<uint8_t>(column_kind k) noexcept
{
    return k == column_kind::boolean;
}
template <>
constexpr bool column::is_kind_compatible<int8_t>(column_kind k) noexcept
{
    return k == column_kind::byte;
}
template <>
constexpr bool column::is_kind_compatible<int16_t>(column_kind k) noexcept
{
    return k == column_kind::short_;
}
template <>
constexpr bool column::is_kind_compatible<uint16_t>(column_kind k) noexcept
{
    return k == column_kind::char_;
}
template <>
constexpr bool column::is_kind_compatible<int32_t>(column_kind k) noexcept
{
    return k == column_kind::int_;
}
template <>
constexpr bool column::is_kind_compatible<uint32_t>(column_kind k) noexcept
{
    return k == column_kind::ipv4;
}
template <>
constexpr bool column::is_kind_compatible<int64_t>(column_kind k) noexcept
{
    return k == column_kind::long_ || k == column_kind::timestamp ||
           k == column_kind::date || k == column_kind::timestamp_nanos;
}
template <>
constexpr bool column::is_kind_compatible<float>(column_kind k) noexcept
{
    return k == column_kind::float_;
}
template <>
constexpr bool column::is_kind_compatible<double>(column_kind k) noexcept
{
    return k == column_kind::double_;
}

template <>
inline const double* column::elements<double>(
    size_t row, size_t* out_count) const
{
    ensure_array("column::elements<double>");
    if (kind() != column_kind::double_array)
        throw line_reader_error{
            error_code::invalid_api_call,
            "column::elements<double>: column is not DOUBLE_ARRAY"};
    size_t bytes = 0;
    const auto* p = row_bytes(row, &bytes);
    if (out_count)
        *out_count = bytes / sizeof(double);
    return reinterpret_cast<const double*>(p);
}

/**
 * Borrowed handle for the cursor's currently-loaded batch. The columnar
 * entry point: `batch::column(i)` projects a column (scalar or array —
 * the returned `column` is polymorphic).
 *
 * Obtain from `cursor::next_batch()`. Invalidated by the next
 * `cursor::next_batch()`, `cursor::cancel()`, `cursor::add_credit()`, cursor
 * destruction, or mid-query failover.
 */
class batch
{
public:
    batch() noexcept
        : _impl{nullptr}
    {
    }
    explicit batch(const ::line_reader_batch* impl) noexcept
        : _impl{impl}
    {
    }

    bool valid() const noexcept
    {
        return _impl != nullptr;
    }
    explicit operator bool() const noexcept
    {
        return valid();
    }

    size_t row_count() const noexcept
    {
        return _impl ? ::line_reader_batch_row_count(_impl) : 0;
    }
    size_t column_count() const noexcept
    {
        return _impl ? ::line_reader_batch_column_count(_impl) : 0;
    }
    int64_t request_id() const noexcept
    {
        return _impl ? ::line_reader_batch_request_id(_impl) : 0;
    }
    uint64_t seq() const noexcept
    {
        return _impl ? ::line_reader_batch_seq(_impl) : 0;
    }
    uint8_t flags() const noexcept
    {
        return _impl ? ::line_reader_batch_flags(_impl) : 0;
    }

    egress::column_kind column_kind(size_t col_idx) const
    {
        ensure_impl();
        ::line_reader_column_kind k{};
        line_reader_error::wrapped_call(
            ::line_reader_batch_column_kind, _impl, col_idx, &k);
        return static_cast<egress::column_kind>(k);
    }

    std::string_view column_name(size_t col_idx) const
    {
        ensure_impl();
        const char* buf = nullptr;
        size_t len = 0;
        line_reader_error::wrapped_call(
            ::line_reader_batch_column_name, _impl, col_idx, &buf, &len);
        return std::string_view{buf, len};
    }

    /**
     * Project the column at `col_idx`. Works for every kind — including
     * `DOUBLE_ARRAY`. The returned `column` is polymorphic; check
     * `col.kind()` or `col.is_array()` before calling kind-specific
     * accessors. Internally probes the kind once, then calls the
     * appropriate descriptor-fill C function.
     */
    egress::column column(size_t col_idx) const
    {
        ensure_impl();
        ::line_reader_column_kind k_raw{};
        line_reader_error::wrapped_call(
            ::line_reader_batch_column_kind, _impl, col_idx, &k_raw);
        if (k_raw == ::line_reader_column_kind_double_array)
        {
            ::line_reader_array_data d{};
            line_reader_error::wrapped_call(
                ::line_reader_batch_array_column_data, _impl, col_idx, &d);
            return egress::column::make_array(d);
        }
        if (k_raw == ::line_reader_column_kind_long_array)
            throw line_reader_error{
                error_code::invalid_api_call,
                "batch::column: LONG_ARRAY is not supported in this revision"};
        ::line_reader_column_data d{};
        line_reader_error::wrapped_call(
            ::line_reader_batch_column_data, _impl, col_idx, &d);
        symbol_dict_view dict{};
        if (d.kind == ::line_reader_column_kind_symbol)
            dict = symbol_dict();
        return egress::column::make_scalar(d, dict);
    }

    /**
     * Look up a column by name. O(N) over `column_count()`, intended
     * for the common case where N is small (typically < 50). For tight
     * loops cache the index from a one-time lookup.
     * @throws line_reader_error with `invalid_api_call` if no column
     *         matches `name`.
     */
    egress::column column_by_name(std::string_view name) const
    {
        const size_t n = column_count();
        for (size_t i = 0; i < n; ++i)
        {
            if (column_name(i) == name)
                return column(i);
        }
        throw line_reader_error{
            error_code::invalid_api_call,
            "batch::column_by_name: no column named '" + std::string{name} +
                "'"};
    }

    /**
     * Look up a column by name without throwing. Returns `std::nullopt`
     * when no column matches.
     */
    nullable<egress::column> try_column_by_name(std::string_view name) const
    {
        const size_t n = column_count();
        for (size_t i = 0; i < n; ++i)
        {
            if (column_name(i) == name)
                return column(i);
        }
        return std::nullopt;
    }

    /** Snapshot the connection-scoped symbol dictionary. */
    egress::symbol_dict_view symbol_dict() const
    {
        ensure_impl();
        ::line_reader_symbol_dict d{};
        line_reader_error::wrapped_call(
            ::line_reader_batch_symbol_dict, _impl, &d);
        return egress::symbol_dict_view{d};
    }

    /**
     * Resolve a SYMBOL `code` in `col_idx` to its UTF-8 view. Convenience
     * for scalar use; for bulk categorical construction use `symbol_dict()`.
     */
    std::string_view symbol(size_t col_idx, uint32_t code) const
    {
        ensure_impl();
        const char* buf = nullptr;
        size_t len = 0;
        line_reader_error::wrapped_call(
            ::line_reader_batch_symbol, _impl, col_idx, code, &buf, &len);
        return std::string_view{buf, len};
    }

    const ::line_reader_batch* c_impl() const noexcept
    {
        return _impl;
    }

private:
    void ensure_impl() const
    {
        if (!_impl)
            throw line_reader_error{
                error_code::invalid_api_call,
                "batch handle is invalid (no batch loaded)"};
    }

    const ::line_reader_batch* _impl;
};

/**
 * RAII handle for a streaming cursor.
 *
 * Obtained from `reader::execute`. Iterate batches with
 * `while (auto batch = cur.next_batch()) { ... }` — `next_batch()` returns
 * `std::optional<batch>` (empty when the stream terminates). Per-row scalar
 * values are read with the typed getters; each getter returns
 * `std::nullopt` for NULL cells.
 */
class cursor
{
public:
    cursor(const cursor&) = delete;
    cursor& operator=(const cursor&) = delete;

    cursor(cursor&& other) noexcept
        : _impl{other._impl}
        , _failover_callback{std::move(other._failover_callback)}
        , _failover_progress_callback{
              std::move(other._failover_progress_callback)}
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
            _failover_progress_callback =
                std::move(other._failover_progress_callback);
            other._impl = nullptr;
        }
        return *this;
    }

    ~cursor() noexcept { ::line_reader_cursor_free(_impl); }

    /**
     * Advance to the next batch.
     *
     * @return `std::nullopt` when the stream terminates normally.
     * @return A borrowed `egress::batch` on success — the entry point to
     *         the columnar bulk access API (`batch::column`,
     *         `batch::symbol_dict`). Invalidated by the next `next_batch`,
     *         `cancel`, `add_credit`, cursor destruction, or mid-query
     *         failover; do not cache across batches.
     * @throws line_reader_error on transport / protocol failure.
     */
    std::optional<egress::batch> next_batch()
    {
        ensure_impl();
        ::line_reader_error* c_err{nullptr};
        const ::line_reader_batch* p =
            ::line_reader_cursor_next_batch(_impl, &c_err);
        if (!p)
        {
            if (c_err)
                throw line_reader_error::from_c(c_err);
            return std::nullopt;
        }
        return egress::batch{p};
    }

#ifdef QUESTDB_CLIENT_HAS_ARROW
    /**
     * Result of `next_arrow_batch`. Aggregate of the two Apache Arrow
     * C Data Interface structs the C entry point fills in.
     *
     * Ownership: the caller of `next_arrow_batch` owns the `array` and
     * `schema` returned here. After processing, the caller MUST either:
     *   - Invoke `array.release(&array)` and `schema.release(&schema)`
     *     directly, or
     *   - Transfer ownership to an Arrow consumer such as
     *     `arrow::ImportRecordBatch(&array, &schema)`, which zeros the
     *     release callbacks on success so subsequent manual release
     *     calls become no-ops.
     */
    struct arrow_batch
    {
        ::ArrowArray array;
        ::ArrowSchema schema;
    };

    /**
     * Advance to the next batch and export it via the Apache Arrow
     * C Data Interface.
     *
     * @return `std::nullopt` when the stream terminates normally
     *         (no further batches).
     * @return An owned `arrow_batch` on success. See the struct's
     *         documentation for release responsibilities.
     * @throws line_reader_error on transport / protocol failure or any
     *         Arrow-specific error (`schema_drift`, `no_schema`,
     *         `arrow_export`).
     *
     * Unlike `next_batch`, the returned `arrow_batch` is NOT invalidated
     * by subsequent cursor operations — it owns its release callbacks
     * and is independent of the cursor lifetime.
     */
    std::optional<arrow_batch> next_arrow_batch()
    {
        ensure_impl();
        ::line_reader_error* c_err{nullptr};
        arrow_batch out{};
        const auto rc = ::line_reader_cursor_next_arrow_batch(
            _impl, &out.array, &out.schema, &c_err);
        switch (rc)
        {
            case ::line_reader_arrow_batch_ok:
                return out;
            case ::line_reader_arrow_batch_end:
                return std::nullopt;
            case ::line_reader_arrow_batch_error:
            default:
                throw line_reader_error::from_c(c_err);
        }
    }
#endif /* QUESTDB_CLIENT_HAS_ARROW */

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
    /** Negotiated QWP version of the cursor's underlying connection.
     *  @throws line_reader_error if the connection is poisoned after a
     *          failed failover, or this cursor has been moved from. */
    uint8_t server_version() const
    {
        ensure_impl();
        uint8_t v = 0;
        line_reader_error::wrapped_call(
            ::line_reader_cursor_server_version, _impl, &v);
        return v;
    }
    /** Last-seen `SERVER_INFO`, or empty for v1 servers. The view is
     *  invalidated by any cursor operation that may reconnect.
     *  @throws line_reader_error if this cursor has been moved from. */
    server_info_view server_info() const
    {
        ensure_impl();
        return server_info_view{
            ::line_reader_cursor_current_server_info(_impl)};
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
    /// Same lifetime contract as `_failover_callback` but for the
    /// progress callback registered via `query::on_failover_progress`.
    std::unique_ptr<failover_progress_callback> _failover_progress_callback;
    friend class reader;
    friend class query;
};

inline query reader::prepare(::questdb::ingress::utf8_view sql)
{
    ensure_impl();
    return query{line_reader_error::wrapped_call(
        ::line_reader_prepare, _impl, to_c_utf8(sql))};
}

inline cursor reader::execute(::questdb::ingress::utf8_view sql)
{
    ensure_impl();
    return cursor{line_reader_error::wrapped_call(
        ::line_reader_execute, _impl, to_c_utf8(sql))};
}

inline cursor query::execute()
{
    ensure_impl();
    auto cb = std::move(_callback); // transfer to cursor (or drop on error)
    auto pcb = std::move(_progress_callback);
    ::line_reader_error* c_err = nullptr;
    // The C call consumes `_impl` regardless of outcome and sets it to
    // NULL on return — so a subsequent `~query()` calling `_query_free`
    // is a NULL no-op without us having to clear `_impl` explicitly here.
    auto* c = ::line_reader_query_execute(&_impl, &c_err);
    if (!c) throw line_reader_error::from_c(c_err);
    cursor result{c};
    result._failover_callback = std::move(cb);
    result._failover_progress_callback = std::move(pcb);
    return result;
}

} // namespace questdb::egress
