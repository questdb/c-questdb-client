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
 * wait. Any other exception counts as retryable, except a
 * `questdb::error` with `error_code::invalid_api_call` thrown from
 * `bearer_token_provider::token()`, which stops background reconnects (see
 * there). Never put a token in the message.
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
    catch (const ::questdb::error& e)
    {
        // `invalid_api_call` is a failure retrying can never clear, as for a
        // Rust provider. A token source's sink refuses it, and it then counts
        // as retryable like any other exception.
        if (e.code() != ::questdb::error_code::invalid_api_call ||
            !set_sink_terminal_error(sink, e.what()))
            set_sink_error(sink, true, -1, e.what());
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
        // The provider owns the copy from here on, failed calls included.
        auto* heap = new Source{std::move(source)};
        return token_provider{::questdb::error::wrapped_call(
            ::questdb_refreshing_token_provider_new,
            &detail::source_trampoline<Source>,
            static_cast<void*>(heap),
            &detail::delete_trampoline<Source>,
            &c_options)};
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
        auto* heap = new detail::shared_provider{std::move(provider)};
        return token_provider{::questdb::error::wrapped_call(
            ::questdb_token_provider_new, &vtable, static_cast<void*>(heap))};
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

    /** Release this handle; clients using the provider keep it. */
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
        ::questdb_token* raw = ::questdb::error::wrapped_call(
            ::questdb_token_provider_token, _raw);
        std::string value{::questdb_token_data(raw), ::questdb_token_len(raw)};
        ::questdb_token_free(raw);
        return value;
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
     *  sender, pool or reader then fails. */
    void close() const
    {
        ::questdb_token_provider_close(_raw);
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
