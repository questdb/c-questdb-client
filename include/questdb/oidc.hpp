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
 ******************************************************************************/

#pragma once

#include <questdb/oidc.h>
#include <questdb/ingress/line_sender_core.hpp>

#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace questdb
{
class pool;
}

namespace questdb::ingress
{
class opts;
}

namespace questdb::egress
{
class reader;
}

namespace questdb::oidc
{

enum class event_kind : int
{
    prompt = QUESTDB_OIDC_EVENT_PROMPT,
    waiting = QUESTDB_OIDC_EVENT_WAITING,
    success = QUESTDB_OIDC_EVENT_SUCCESS,
    failure = QUESTDB_OIDC_EVENT_FAILURE,
};

class event_view
{
public:
    // Non-copyable: `_event` and all returned string_views are valid only
    // during the callback invocation.
    event_view(const event_view&) = delete;
    event_view& operator=(const event_view&) = delete;
    event_view(event_view&&) = delete;
    event_view& operator=(event_view&&) = delete;

    event_kind kind() const noexcept
    {
        return static_cast<event_kind>(static_cast<int>(_event->kind));
    }
    std::string_view user_code() const noexcept
    {
        return view(_event->user_code, _event->user_code_len);
    }
    std::string_view verification_uri() const noexcept
    {
        return view(_event->verification_uri, _event->verification_uri_len);
    }
    std::string_view verification_uri_complete() const noexcept
    {
        return view(
            _event->verification_uri_complete,
            _event->verification_uri_complete_len);
    }
    std::string_view identity() const noexcept
    {
        return view(_event->identity, _event->identity_len);
    }
    std::string_view message() const noexcept
    {
        return view(_event->message, _event->message_len);
    }
    double seconds_left() const noexcept
    {
        return _event->seconds_left;
    }
    double expires_in_seconds() const noexcept
    {
        return _event->expires_in_seconds;
    }
    /** The only prompt URL vetted for opening or making clickable. */
    std::string_view browser_target() const noexcept
    {
        constexpr size_t required_size =
            offsetof(::questdb_oidc_event, browser_target_len) + sizeof(size_t);
        if (_event->struct_size < required_size)
            return {};
        return view(_event->browser_target, _event->browser_target_len);
    }

private:
    explicit event_view(const ::questdb_oidc_event* event) noexcept
        : _event{event}
    {
    }

    static std::string_view view(const char* data, size_t size) noexcept
    {
        return data ? std::string_view{data, size} : std::string_view{};
    }

    const ::questdb_oidc_event* _event;
    friend class builder;
};

namespace detail
{
[[noreturn]] inline void throw_error(::questdb_error* raw)
{
    ::questdb::error::throw_from_c(raw);
}

template <typename F, typename... Args>
auto wrapped_call(F&& function, Args&&... args)
{
    ::questdb_error* raw_error = nullptr;
    auto result = function(std::forward<Args>(args)..., &raw_error);
    if (raw_error)
        throw_error(raw_error);
    return result;
}
} // namespace detail

class token
{
public:
    token(const token&) = delete;
    token& operator=(const token&) = delete;

    token(token&& other) noexcept
        : _raw{other._raw}
    {
        other._raw = nullptr;
    }
    token& operator=(token&& other) noexcept
    {
        if (this != &other)
        {
            ::questdb_oidc_token_free(_raw);
            _raw = other._raw;
            other._raw = nullptr;
        }
        return *this;
    }
    ~token() noexcept
    {
        ::questdb_oidc_token_free(_raw);
    }

    /** Borrowed bytes; valid only while this token object remains alive. */
    std::string_view view() const& noexcept
    {
        return {
            ::questdb_oidc_token_data(_raw), ::questdb_oidc_token_len(_raw)};
    }
    std::string_view view() const&& = delete;

private:
    explicit token(::questdb_oidc_token* raw) noexcept
        : _raw{raw}
    {
    }
    ::questdb_oidc_token* _raw;
    friend class device_auth;
};

/**
 * Borrowed configuration strings. The source device_auth must remain alive
 * while any field is used.
 */
struct config_view
{
    std::string_view client_id;
    std::string_view token_endpoint;
    std::string_view device_authorization_endpoint;
    std::string_view scope;
    std::string_view audience;
    std::string_view issuer;
    bool groups_in_token;
};

/**
 * Interactive OIDC device-flow sign-in handle.
 *
 * `sign_in()`, `token()`, and `clear()` throw `questdb::oidc::error` on
 * failure. Note that when this same auth state is attached to an ingest sender
 * via `opts::oidc_auth`, a later token-acquisition failure surfaces from
 * `flush()` as a `questdb::ingress::line_sender_error` (with the OIDC detail on
 * its `oidc_diagnostic()` member), **not** as a `questdb::oidc::error` — so an
 * `oidc::error` handler written for this API does not transfer to a sender.
 * Catch the common base `const questdb::error&` to handle both. See
 * `questdb::oidc::error` for the full cross-surface exception model.
 */
class device_auth
{
public:
    device_auth(const device_auth& other)
        : _raw{detail::wrapped_call(::questdb_oidc_auth_clone, other.raw())}
    {
    }
    device_auth& operator=(const device_auth& other)
    {
        if (this != &other)
        {
            auto* replacement =
                detail::wrapped_call(::questdb_oidc_auth_clone, other.raw());
            ::questdb_oidc_auth_free(_raw);
            _raw = replacement;
        }
        return *this;
    }
    device_auth(device_auth&& other) noexcept
        : _raw{other._raw}
    {
        other._raw = nullptr;
    }
    device_auth& operator=(device_auth&& other) noexcept
    {
        if (this != &other)
        {
            ::questdb_oidc_auth_free(_raw);
            _raw = other._raw;
            other._raw = nullptr;
        }
        return *this;
    }
    ~device_auth() noexcept
    {
        ::questdb_oidc_auth_free(_raw);
    }

    /**
     * Run the interactive device flow if needed. This is the only operation
     * that may invoke prompt callbacks and wait for user authorization.
     * @throws questdb::oidc::error on sign-in failure (see the class note for
     *         how OIDC failures surface across the sender/reader/device APIs).
     */
    void sign_in() const
    {
        detail::wrapped_call(::questdb_oidc_auth_sign_in, raw());
    }
    /**
     * Return a cached, persisted, or silently refreshed QuestDB bearer token.
     * This is the access token by default, or the ID token when
     * `groups_in_token` is enabled. Never prompts; throws oidc::error with
     * interaction_required when sign_in() is needed.
     */
    ::questdb::oidc::token token() const
    {
        return ::questdb::oidc::token{
            detail::wrapped_call(::questdb_oidc_auth_token, raw())};
    }

    /**
     * Clear the in-memory credential and delete its persisted local entry.
     * Throws oidc::error if persisted deletion fails; memory is still cleared.
     * This does not revoke any token at the identity provider.
     */
    void clear() const
    {
        detail::wrapped_call(::questdb_oidc_auth_clear, raw());
    }

    config_view config() const&
    {
        ::questdb_oidc_config_view raw{};
        raw.struct_size = sizeof raw;
        ::questdb_oidc_auth_get_config(this->raw(), &raw);
        return {
            view(raw.client_id, raw.client_id_len),
            view(raw.token_endpoint, raw.token_endpoint_len),
            view(
                raw.device_authorization_endpoint,
                raw.device_authorization_endpoint_len),
            view(raw.scope, raw.scope_len),
            view(raw.audience, raw.audience_len),
            view(raw.issuer, raw.issuer_len),
            raw.groups_in_token};
    }
    config_view config() const&& = delete;

    /** Borrowed FFI handle; valid only while this device_auth remains alive. */
    const ::questdb_oidc_auth* c_ptr() const& noexcept
    {
        return _raw;
    }
    const ::questdb_oidc_auth* c_ptr() const&& = delete;

private:
    explicit device_auth(::questdb_oidc_auth* raw) noexcept
        : _raw{raw}
    {
    }
    const ::questdb_oidc_auth* raw() const
    {
        if (!_raw)
        {
            throw error{
                ::questdb::error_code::invalid_api_call,
                "Cannot use an empty or moved-from OIDC device_auth.",
                error_kind::unknown,
                {},
                {},
                std::nullopt,
                std::nullopt};
        }
        return _raw;
    }
    static std::string_view view(const char* data, size_t size) noexcept
    {
        return data ? std::string_view{data, size} : std::string_view{};
    }

    ::questdb_oidc_auth* _raw;
    friend class builder;
    friend class ::questdb::pool;
    friend class ::questdb::ingress::opts;
    friend class ::questdb::egress::reader;
};

class builder
{
public:
    builder()
        : _raw{::questdb_oidc_builder_new()}
    {
    }

    static builder from_questdb(std::string_view url)
    {
        return builder{detail::wrapped_call(
            ::questdb_oidc_builder_from_questdb, url.data(), url.size())};
    }

    builder(const builder&) = delete;
    builder& operator=(const builder&) = delete;
    builder(builder&& other) noexcept
        : _raw{other._raw}
    {
        other._raw = nullptr;
    }
    builder& operator=(builder&& other) noexcept
    {
        if (this != &other)
        {
            ::questdb_oidc_builder_free(_raw);
            _raw = other._raw;
            other._raw = nullptr;
        }
        return *this;
    }
    ~builder() noexcept
    {
        ::questdb_oidc_builder_free(_raw);
    }

#define QUESTDB_OIDC_CPP_STRING_SETTER(method, c_function)                     \
    builder& method(std::string_view value)                                    \
    {                                                                          \
        detail::wrapped_call(c_function, _raw, value.data(), value.size());    \
        return *this;                                                          \
    }

    QUESTDB_OIDC_CPP_STRING_SETTER(client_id, ::questdb_oidc_builder_client_id)
    QUESTDB_OIDC_CPP_STRING_SETTER(scope, ::questdb_oidc_builder_scope)
    QUESTDB_OIDC_CPP_STRING_SETTER(audience, ::questdb_oidc_builder_audience)
    QUESTDB_OIDC_CPP_STRING_SETTER(issuer, ::questdb_oidc_builder_issuer)
    QUESTDB_OIDC_CPP_STRING_SETTER(
        token_endpoint, ::questdb_oidc_builder_token_endpoint)
    QUESTDB_OIDC_CPP_STRING_SETTER(
        device_authorization_endpoint,
        ::questdb_oidc_builder_device_authorization_endpoint)
    QUESTDB_OIDC_CPP_STRING_SETTER(ca_bundle, ::questdb_oidc_builder_ca_bundle)

#undef QUESTDB_OIDC_CPP_STRING_SETTER

    /**
     * Explicitly persist access, ID, and long-lived refresh tokens as
     * unencrypted JSON in `directory`. Unix uses `0600` token files and a
     * `0700` store directory; other platforms depend on the directory's
     * default ACL. Without this opt-in, credentials remain in memory only.
     */
    builder& file_token_store(std::string_view directory)
    {
        detail::wrapped_call(
            ::questdb_oidc_builder_file_token_store,
            _raw,
            directory.data(),
            directory.size());
        return *this;
    }

#define QUESTDB_OIDC_CPP_BOOL_SETTER(method, c_function)                       \
    builder& method(bool enabled)                                              \
    {                                                                          \
        detail::wrapped_call(c_function, _raw, enabled);                       \
        return *this;                                                          \
    }

    QUESTDB_OIDC_CPP_BOOL_SETTER(
        groups_in_token, ::questdb_oidc_builder_groups_in_token)
    QUESTDB_OIDC_CPP_BOOL_SETTER(
        allow_insecure_transport,
        ::questdb_oidc_builder_allow_insecure_transport)
    QUESTDB_OIDC_CPP_BOOL_SETTER(
        open_browser, ::questdb_oidc_builder_open_browser)
    QUESTDB_OIDC_CPP_BOOL_SETTER(
        interactive, ::questdb_oidc_builder_interactive)

#undef QUESTDB_OIDC_CPP_BOOL_SETTER

    builder& default_interval_seconds(uint64_t seconds)
    {
        detail::wrapped_call(
            ::questdb_oidc_builder_default_interval_seconds, _raw, seconds);
        return *this;
    }
    builder& timeout_ms(uint64_t milliseconds)
    {
        detail::wrapped_call(
            ::questdb_oidc_builder_timeout_ms, _raw, milliseconds);
        return *this;
    }
    /**
     * Explicitly persist access, ID, and long-lived refresh tokens as
     * unencrypted JSON under `$QUESTDB_CLIENT_OIDC_TOKEN_STORE_DIR`, or
     * `${HOME}/.questdb/oidc-tokens/` when unset. Unix uses owner-only modes;
     * other platforms depend on the directory's default ACL.
     */
    builder& default_file_token_store()
    {
        detail::wrapped_call(
            ::questdb_oidc_builder_default_file_token_store, _raw);
        return *this;
    }

    /**
     * Install an event handler. It may run on any token-acquisition thread;
     * calls are serialized across auth objects built by this builder. Starting
     * another auth operation that shares this handler from inside the callback
     * fails with invalid_api_call. Destruction of captured state may occur on
     * whichever thread releases the final auth/transport reference.
     *
     * An empty std::function is rejected synchronously. Exceptions thrown by
     * the handler are contained at the C boundary and ignored; handle callback
     * failures inside the handler if they need to be observed.
     */
    builder& event_handler(std::function<void(const event_view&)> handler)
    {
        using handler_type = std::function<void(const event_view&)>;
        if (!handler)
        {
            throw ::questdb::error{
                ::questdb::error_code::invalid_api_call,
                "OIDC event handler must not be empty."};
        }
        auto owned = std::make_unique<handler_type>(std::move(handler));
        detail::wrapped_call(
            ::questdb_oidc_builder_event_handler,
            _raw,
            &builder::event_trampoline,
            owned.get(),
            &builder::release_handler);
        owned.release();
        return *this;
    }

    device_auth build() const
    {
        return device_auth{
            detail::wrapped_call(::questdb_oidc_builder_build, _raw)};
    }

private:
    explicit builder(::questdb_oidc_builder* raw) noexcept
        : _raw{raw}
    {
    }

    static void event_trampoline(
        void* user_data, const ::questdb_oidc_event* event) noexcept
    {
        try
        {
            auto* handler =
                static_cast<std::function<void(const event_view&)>*>(user_data);
            if (handler && *handler && event)
            {
                const event_view view{event};
                (*handler)(view);
            }
        }
        catch (...)
        {
            // Exceptions must not unwind across the C FFI boundary. Match the
            // reader callback convention: contain them and let the auth flow
            // continue. Users who need reporting must catch inside the handler.
        }
    }
    static void release_handler(void* user_data) noexcept
    {
        delete static_cast<std::function<void(const event_view&)>*>(user_data);
    }

    ::questdb_oidc_builder* _raw;
};

} // namespace questdb::oidc
