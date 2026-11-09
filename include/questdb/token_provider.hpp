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

#include "token_provider.h"
#include "ingress/line_sender_core.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace questdb
{

/** A token and its expiry: the result of one token-source fetch. */
struct expiring_token
{
    /** The token, without the `Bearer ` prefix. */
    std::string token;
    /** When the token expires. For a relative lifetime (OAuth's `expires_in`),
     *  add it to the local time of receipt. For a token that does not expire,
     *  use `std::chrono::system_clock::time_point::max()`. */
    std::chrono::system_clock::time_point expires_at;
    /** The platform's suggested refresh time, if it gave one. */
    std::optional<std::chrono::system_clock::time_point> refresh_at{};
};

/**
 * Throw from a token source or a `bearer_token_provider` to classify a
 * failure: whether retrying can succeed (network failures, timeouts, 429 and
 * 5xx are retryable; missing or wrong configuration is not), and a suggested
 * wait. A `questdb::error` that carries a classification, such as one thrown
 * by `token_provider::token()`, keeps it. Any other exception counts as
 * retryable, except the failures `bearer_token_provider::token()` lists as
 * stopping background reconnects (see there). Never put a token in the
 * message.
 *
 * An `oidc::error` thrown by `oidc::device_auth::token()` carries no
 * classification. A `bearer_token_provider` passes it on as
 * `bearer_token_provider::token()` describes. From a token source it is a
 * failed fetch that counts as retryable, and its OIDC detail does not reach
 * clients: see `questdb_token_sink_set_error_from`.
 */
class token_unavailable : public std::runtime_error
{
public:
    explicit token_unavailable(
        const std::string& msg,
        bool retryable = true,
        std::optional<std::chrono::milliseconds> retry_after = std::nullopt)
        : std::runtime_error{msg}
        , _retryable{retryable}
        , _retry_after{retry_after}
    {
    }

    bool retryable() const noexcept
    {
        return _retryable;
    }

    std::optional<std::chrono::milliseconds> retry_after() const noexcept
    {
        return _retry_after;
    }

private:
    bool _retryable;
    std::optional<std::chrono::milliseconds> _retry_after;
};

/**
 * A provider implemented by the application: the counterpart of the Java
 * client's `HttpTokenProvider`. `token()` runs on every connect round of a
 * QWP/WebSocket sender, reader or pool, on a connect thread or an isolated
 * worker, and on every flush of an ILP/HTTP sender, synchronously on the
 * flushing thread. Calls may run concurrently. Prefer a refreshing provider
 * unless you already cache tokens.
 */
class bearer_token_provider
{
public:
    virtual ~bearer_token_provider() = default;

    /**
     * The current token, without the `Bearer ` prefix.
     *
     * Clients keep retrying a failure in the background, whatever
     * `token_unavailable` says. To stop them on a failure that retrying can
     * never clear, throw `questdb::error` with `error_code::invalid_api_call`,
     * as a Rust provider returns `InvalidApiCall`: a QWP/WebSocket sender,
     * reader or pool then reports `config_error` and stops reconnecting, and
     * an ILP/HTTP flush fails with it at once. A token source cannot do this;
     * close a refreshing provider instead.
     *
     * A QuestDB error that carries a classification
     * (`questdb::error::token_unavailable_diagnostic()`), such as one
     * `token_provider::token()` threw, is passed on unchanged, as a Rust
     * provider passes on the error it returns, and the client's error keeps
     * the classification. A `questdb::ingress::line_sender_error` that
     * carries a classification or OIDC detail is passed on the same way. The
     * failure of a closed `token_provider` stops them too, still reported as
     * `auth_error` with `provider_closed` set: closing one ends every client
     * that uses it, through this provider too.
     *
     * An `oidc::error` that `oidc::device_auth::token()` threw is passed on
     * unchanged the same way, and the client's error keeps its OIDC detail
     * (`line_sender_error::oidc_diagnostic()`). One of kind `cancelled` (a
     * closed `oidc::device_auth`, reported as `auth_error`) or `config`
     * (`config_error`) stops the clients, as it cannot clear. On any other,
     * a connect the caller waits for ends at once unless the acquisition was
     * busy, and an ILP/HTTP flush resolves the token again after a transient
     * failure within its `retry_timeout`.
     */
    virtual std::string token() = 0;

    /** A server rejected `token` with `http_status` (401): one whose
     *  `WWW-Authenticate` Bearer challenge names no error, or
     *  `invalid_token`. Stop serving it if it has not rotated already. May be
     *  called more than once. */
    virtual void on_rejected(std::string_view token, uint16_t http_status)
    {
        (void)token;
        (void)http_status;
    }
};

/** Parameters of a refreshing provider. Durations must not be negative.
 *  Unset fields keep the defaults. */
struct refreshing_token_provider_options
{
    /** Non-secret label for log lines and errors. */
    std::string name{};
    std::optional<std::chrono::milliseconds> refresh_margin{};
    std::optional<std::chrono::milliseconds> min_refresh_interval{};
    std::optional<std::chrono::milliseconds> handout_floor{};
    std::optional<std::chrono::milliseconds> cold_wait{};
    std::optional<std::chrono::milliseconds> backoff_initial{};
    std::optional<std::chrono::milliseconds> backoff_max{};
    std::optional<std::chrono::milliseconds> retry_after_max{};
    std::optional<std::chrono::milliseconds> forced_min_interval{};
    std::optional<std::chrono::milliseconds> forced_wait{};
};

namespace detail
{
inline uint64_t duration_ms(std::chrono::milliseconds value, const char* name)
{
    if (value.count() < 0)
        throw std::invalid_argument{
            std::string{name} + " must not be negative"};
    return static_cast<uint64_t>(value.count());
}

inline int64_t epoch_ms(std::chrono::system_clock::time_point t) noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               t.time_since_epoch())
        .count();
}

/** The instant `ms` milliseconds after the Unix epoch, saturated to the
 *  clock's range: a token that does not expire is reported as expiring in
 *  9999, which lies past the end of a nanosecond `system_clock`. */
inline std::chrono::system_clock::time_point from_epoch_ms(int64_t ms) noexcept
{
    // `(f)()` keeps `max` and `min` safe from `<windows.h>` macros.
    using clock = std::chrono::system_clock;
    constexpr int64_t max_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            (clock::time_point::max)().time_since_epoch())
            .count();
    constexpr int64_t min_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            (clock::time_point::min)().time_since_epoch())
            .count();
    if (ms >= max_ms)
        return (clock::time_point::max)();
    if (ms <= min_ms)
        return (clock::time_point::min)();
    return clock::time_point{std::chrono::duration_cast<clock::duration>(
        std::chrono::milliseconds{ms})};
}

inline void set_sink_error(
    ::questdb_token_sink* sink,
    bool retryable,
    int64_t retry_after_ms,
    const char* msg) noexcept
{
    ::questdb_token_sink_set_error(
        sink, retryable, retry_after_ms, msg, std::strlen(msg));
}

/** False when `sink` refuses a terminal failure, as a source's sink does. */
inline bool set_sink_terminal_error(
    ::questdb_token_sink* sink, const char* msg) noexcept
{
    return ::questdb_token_sink_set_terminal_error(sink, msg, std::strlen(msg));
}

/**
 * Report a QuestDB error through `sink`, as a Rust provider that returns it
 * is classified (`classify_provider_error`): a failure retrying can never
 * clear (`terminal`) as terminal, anything else with the classification it
 * carries, and as retryable when it carries none. A token source's sink
 * refuses a terminal failure, which then counts as its classification says.
 */
inline void report_questdb_error(
    ::questdb_token_sink* sink,
    const ::questdb::error& e,
    bool terminal) noexcept
{
    if (terminal && set_sink_terminal_error(sink, e.what()))
        return;
    const auto& classification = e.token_unavailable_diagnostic();
    if (!classification)
    {
        set_sink_error(sink, true, -1, e.what());
        return;
    }
    set_sink_error(
        sink,
        classification->retryable,
        classification->retry_after ? classification->retry_after->count() : -1,
        e.what());
}

/** Reads the C error a `questdb::error` was converted from. */
struct error_access
{
    static const ::questdb_error* c_error(const ::questdb::error& e) noexcept
    {
        return e._c_error.get();
    }
};

/** Report the exception being handled through `sink`. */
inline void report_current_exception(::questdb_token_sink* sink) noexcept
{
    try
    {
        throw;
    }
    catch (const token_unavailable& e)
    {
        set_sink_error(
            sink,
            e.retryable(),
            e.retry_after() ? e.retry_after()->count() : -1,
            e.what());
    }
    catch (const ::questdb::oidc::error& e)
    {
        // Pass a failure the library raised on unchanged, as a Rust provider
        // passes on an `OidcError`: the client classifies it as that
        // provider's error and keeps its OIDC detail. A closed
        // `oidc::device_auth` (`cancelled`) and a misconfiguration (`config`)
        // then stop the clients, and any other kind carries no classification
        // to report: reported as retryable, a sign-in failure kept a connect
        // the caller waits for retrying for its whole budget, and the
        // client's error lost the OIDC detail. From a token source it is a
        // failed fetch either way (see `questdb_token_sink_set_error_from`).
        const ::questdb_error* const raw = error_access::c_error(e);
        if (raw && ::questdb_token_sink_set_error_from(sink, raw))
            return;
        // An `oidc::error` constructed in C++ has no C error to pass on. A
        // closed auth and a misconfiguration fail every later request alike,
        // as for a Rust provider.
        const bool terminal =
            e.code() == ::questdb::error_code::invalid_api_call ||
            e.kind() == ::questdb::oidc::error_kind::cancelled ||
            e.kind() == ::questdb::oidc::error_kind::config;
        report_questdb_error(sink, e, terminal);
    }
    catch (const ::questdb::error& e)
    {
        // Pass the failure of a QuestDB token API on unchanged, as a Rust
        // provider passes on the error it returns: it carries a
        // classification, which the client keeps. A closed provider's failure
        // then stops the clients with its own code and `provider_closed`
        // still set. Reported as terminal instead, it reached them as
        // `config_error`, without the classification. The same holds for a
        // `line_sender_error` -- the one attaching a closed provider to
        // `ingress::opts` throws, say -- and for one carrying OIDC detail,
        // which the client then keeps as it does an `oidc::error`'s.
        const auto& classification = e.token_unavailable_diagnostic();
        const ::questdb_error* const raw = error_access::c_error(e);
        if (raw && (classification || ::questdb::error::has_oidc_detail(raw)) &&
            ::questdb_token_sink_set_error_from(sink, raw))
            return;
        // A QuestDB error with no C error to pass on, or no classification.
        // `invalid_api_call` is a failure retrying can never clear, as for a
        // Rust provider, and so is a closed provider's: closing one ends every
        // client that uses it, through this application provider too.
        report_questdb_error(
            sink,
            e,
            e.code() == ::questdb::error_code::invalid_api_call ||
                (classification && classification->provider_closed));
    }
    catch (const std::exception& e)
    {
        set_sink_error(sink, true, -1, e.what());
    }
    catch (...)
    {
        set_sink_error(sink, true, -1, "the token callback threw");
    }
}

template <typename Source>
void source_trampoline(void* user_data, ::questdb_token_sink* sink) noexcept
{
    try
    {
        expiring_token result = (*static_cast<Source*>(user_data))();
        // A token the sink refuses, one that is not UTF-8, is recorded as
        // this callback's failure, so the result needs no check.
        ::questdb_token_sink_set_token(
            sink,
            result.token.data(),
            result.token.size(),
            epoch_ms(result.expires_at),
            result.refresh_at ? epoch_ms(*result.refresh_at) : 0);
    }
    catch (...)
    {
        report_current_exception(sink);
    }
}

template <typename T>
void delete_trampoline(void* user_data) noexcept
{
    delete static_cast<T*>(user_data);
}

using shared_provider = std::shared_ptr<bearer_token_provider>;

inline void provider_get_token(
    void* user_data, ::questdb_token_sink* sink) noexcept
{
    try
    {
        const std::string token =
            (*static_cast<shared_provider*>(user_data))->token();
        // A refused token is recorded as this callback's failure.
        ::questdb_token_sink_set_token(sink, token.data(), token.size(), 0, 0);
    }
    catch (...)
    {
        report_current_exception(sink);
    }
}

inline void provider_on_rejected(
    void* user_data,
    const char* token,
    size_t token_len,
    uint16_t http_status) noexcept
{
    try
    {
        (*static_cast<shared_provider*>(user_data))
            ->on_rejected(std::string_view{token, token_len}, http_status);
    }
    catch (...)
    {
    }
}
} // namespace detail

/** The most recent failed fetch of a refreshing provider; see
 *  `token_provider_status`. */
struct token_fetch_failure
{
    /** Whether the source classified the failure as retryable. */
    bool retryable{false};
    /** The source's suggested wait before retrying, if it gave one. */
    std::optional<std::chrono::milliseconds> retry_after{};
    /** When the fetch failed. */
    std::chrono::system_clock::time_point at{};
    /** The failure message, sanitized and at most 256 characters. */
    std::string message{};
};

/**
 * A snapshot of a refreshing provider's state, from `token_provider::status()`.
 * Never contains the token. The same snapshot is
 * `questdb_token_provider_get_status` in C and
 * `RefreshingTokenProvider::status` in Rust.
 */
struct token_provider_status
{
    /** Whether the provider is closed. */
    bool closed{false};
    /** Failed fetches since the last successful one. */
    uint32_t consecutive_failures{0};
    /** When the held token expires, if one is held. */
    std::optional<std::chrono::system_clock::time_point> token_expires_at{};
    /** When the last successful fetch completed. */
    std::optional<std::chrono::system_clock::time_point> last_success_at{};
    /** The most recent failed fetch, kept after the source recovers. */
    std::optional<token_fetch_failure> last_failure{};
};

/**
 * A rotating Bearer-token provider for senders, readers and pools; see
 * `questdb/token_provider.h`. Not copyable, like `oidc::device_auth`: take
 * another handle to the same provider with `share()`, or pass
 * `const token_provider&`.
 *
 * ```cpp
 * auto tokens = questdb::token_provider::refreshing([] {
 *     auto [token, lifetime] = fetch_from_my_idp(); // any way you like
 *     return questdb::expiring_token{
 *         token, std::chrono::system_clock::now() + lifetime};
 * });
 * auto sender = questdb::ingress::line_sender{
 *     questdb::ingress::opts::from_conf("wss::addr=db.example.com:9000;")
 *         .token_provider(tokens)};
 * ```
 */
class token_provider
{
public:
    /**
     * A refreshing provider around `source`, any callable returning an
     * `expiring_token`. It runs only on the provider's refresher thread, never
     * concurrently with itself. Its first fetch starts at once.
     *
     * The provider keeps its own copy of `source`. Closing the provider, or
     * destroying its last handle, does not wait for a fetch already running:
     * that call finishes on the refresher thread, and only then is the copy
     * destroyed. Capture by value, or keep whatever `source` refers to alive
     * until then.
     */
    template <typename Source>
    static token_provider refreshing(
        Source source, const refreshing_token_provider_options& options = {})
    {
        ::questdb_refreshing_token_provider_options c_options;
        ::questdb_refreshing_token_provider_options_init(
            &c_options, sizeof c_options);
        if (!options.name.empty())
        {
            c_options.name = options.name.data();
            c_options.name_len = options.name.size();
        }
        const auto set = [](uint64_t& field,
                            const std::optional<std::chrono::milliseconds>& v,
                            const char* name) {
            if (v)
                field = detail::duration_ms(*v, name);
        };
        set(c_options.refresh_margin_ms,
            options.refresh_margin,
            "refresh_margin");
        set(c_options.min_refresh_interval_ms,
            options.min_refresh_interval,
            "min_refresh_interval");
        set(c_options.handout_floor_ms, options.handout_floor, "handout_floor");
        set(c_options.cold_wait_ms, options.cold_wait, "cold_wait");
        set(c_options.backoff_initial_ms,
            options.backoff_initial,
            "backoff_initial");
        set(c_options.backoff_max_ms, options.backoff_max, "backoff_max");
        set(c_options.retry_after_max_ms,
            options.retry_after_max,
            "retry_after_max");
        set(c_options.forced_min_interval_ms,
            options.forced_min_interval,
            "forced_min_interval");
        set(c_options.forced_wait_ms, options.forced_wait, "forced_wait");
        // The provider owns the copy once it is created; a failed call leaves
        // it here, to be freed by `heap`.
        auto heap = std::make_unique<Source>(std::move(source));
        ::questdb_token_provider* raw = ::questdb::error::wrapped_call(
            ::questdb_refreshing_token_provider_new,
            &detail::source_trampoline<Source>,
            static_cast<void*>(heap.get()),
            &detail::delete_trampoline<Source>,
            &c_options);
        heap.release();
        return token_provider{raw};
    }

    /** A provider implemented by the application. */
    static token_provider from(std::shared_ptr<bearer_token_provider> provider)
    {
        if (!provider)
            throw std::invalid_argument{"bearer_token_provider is null"};
        static const ::questdb_token_provider_vtable vtable{
            sizeof(::questdb_token_provider_vtable),
            &detail::provider_get_token,
            &detail::provider_on_rejected,
            &detail::delete_trampoline<detail::shared_provider>};
        auto heap =
            std::make_unique<detail::shared_provider>(std::move(provider));
        ::questdb_token_provider* raw = ::questdb::error::wrapped_call(
            ::questdb_token_provider_new,
            &vtable,
            static_cast<void*>(heap.get()));
        heap.release();
        return token_provider{raw};
    }

    /**
     * Not copyable: copying would read as a value copy and alias instead.
     *
     * `questdb_token_provider_clone` does not duplicate the provider. It takes
     * another handle on ONE shared provider, whose cached token and closed
     * state are common to every handle and to every sender, reader and pool
     * attached to any of them. So `close()` on a copy would permanently end
     * the clients the original was attached to, as `close()` on a copy of an
     * `oidc::device_auth` would. Use `share()` when an additional handle is
     * what you want, or pass `const token_provider&`.
     */
    token_provider(const token_provider&) = delete;
    token_provider& operator=(const token_provider&) = delete;

    token_provider(token_provider&& other) noexcept
        : _raw{other._raw}
    {
        other._raw = nullptr;
    }

    token_provider& operator=(token_provider&& other) noexcept
    {
        if (this != &other)
        {
            ::questdb_token_provider_free(_raw);
            _raw = other._raw;
            other._raw = nullptr;
        }
        return *this;
    }

    /** Release this handle; clients using the provider keep it. A fetch
     *  already running finishes afterwards (see `refreshing()`). */
    ~token_provider()
    {
        ::questdb_token_provider_free(_raw);
    }

    /**
     * Take an additional handle on the SAME provider.
     *
     * Not a copy: every handle `share()` produces, and every sender, reader
     * and pool attached to any of them, uses one provider, so `close()` on one
     * ends them all. Each handle must be destroyed independently; destroying
     * one leaves the others usable.
     * @throws questdb::error with `invalid_api_call` if this handle is empty
     *         or moved from, or was inherited across `fork()`.
     */
    token_provider share() const
    {
        if (!_raw)
        {
            throw ::questdb::error{
                ::questdb::error_code::invalid_api_call,
                "Cannot share an empty or moved-from questdb::token_provider."};
        }
        ::questdb_token_provider* shared = ::questdb_token_provider_clone(_raw);
        if (!shared)
        {
            throw ::questdb::error{
                ::questdb::error_code::invalid_api_call,
                "This token provider was inherited across fork() and cannot "
                "be shared in this process."};
        }
        return token_provider{shared};
    }

    /**
     * The current token, for a client of your own. A refreshing provider may
     * wait up to its `cold_wait` for one.
     * @throws questdb::error on failure.
     */
    std::string token() const
    {
        std::unique_ptr<::questdb_token, decltype(&::questdb_token_free)> raw{
            ::questdb::error::wrapped_call(
                ::questdb_token_provider_token, _raw),
            &::questdb_token_free};
        return std::string{
            ::questdb_token_data(raw.get()), ::questdb_token_len(raw.get())};
    }

    /** A server rejected `token` with `http_status`; see `on_rejected`. */
    void on_rejected(std::string_view token, uint16_t http_status) const
    {
        ::questdb_token_provider_on_rejected(
            _raw, token.data(), token.size(), http_status);
    }

    /** Wait for a refreshing provider's first usable token.
     *  @throws std::invalid_argument if timeout is negative. */
    bool await_ready(std::chrono::milliseconds timeout) const
    {
        return ::questdb_token_provider_await_ready(
            _raw, detail::duration_ms(timeout, "timeout"));
    }

    /** Close a refreshing provider, ending every client that uses it,
     *  through this handle or any `share()` handle. Attaching it to a new
     *  sender, pool or reader then fails. A fetch already running finishes
     *  after this returns (see `refreshing()`). */
    void close() const
    {
        ::questdb_token_provider_close(_raw);
    }

    /**
     * A refreshing provider's state: whether it is closed, when its token
     * expires, its last successful fetch and its most recent failure. Never
     * contains the token. `std::nullopt` for a provider implemented by the
     * application, which keeps no such state.
     * @throws questdb::error with `invalid_api_call` if this handle is empty
     *         or moved from.
     */
    std::optional<token_provider_status> status() const
    {
        if (!_raw)
        {
            throw ::questdb::error{
                ::questdb::error_code::invalid_api_call,
                "Cannot read the status of an empty or moved-from "
                "questdb::token_provider."};
        }
        // 1024 bytes hold any message (`questdb_token_provider_get_status`);
        // a longer one is read again into a buffer of its reported length.
        std::string message(1024, '\0');
        ::questdb_token_provider_status raw{};
        for (;;)
        {
            raw = ::questdb_token_provider_status{};
            raw.struct_size = sizeof raw;
            raw.last_failure_msg = message.data();
            raw.last_failure_msg_capacity = message.size();
            if (!::questdb_token_provider_get_status(_raw, &raw))
                return std::nullopt;
            if (raw.last_failure_msg_len <= message.size())
                break;
            message.resize(raw.last_failure_msg_len);
        }
        token_provider_status status;
        status.closed = raw.closed;
        status.consecutive_failures = raw.consecutive_failures;
        if (raw.token_expires_at_ms != -1)
            status.token_expires_at =
                detail::from_epoch_ms(raw.token_expires_at_ms);
        if (raw.last_success_at_ms != -1)
            status.last_success_at =
                detail::from_epoch_ms(raw.last_success_at_ms);
        if (raw.has_last_failure)
        {
            token_fetch_failure failure;
            failure.retryable = raw.last_failure_retryable;
            if (raw.last_failure_retry_after_ms != -1)
                failure.retry_after =
                    std::chrono::milliseconds{raw.last_failure_retry_after_ms};
            failure.at = detail::from_epoch_ms(raw.last_failure_at_ms);
            message.resize(raw.last_failure_msg_len);
            failure.message = std::move(message);
            status.last_failure = std::move(failure);
        }
        return status;
    }

    const ::questdb_token_provider* raw() const noexcept
    {
        return _raw;
    }

private:
    explicit token_provider(::questdb_token_provider* raw) noexcept
        : _raw{raw}
    {
    }

    ::questdb_token_provider* _raw;
};

} // namespace questdb
