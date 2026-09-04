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
    /** Device-code lifetime on a prompt; token lifetime on success. */
    double expires_in_seconds() const noexcept
    {
        return _event->expires_in_seconds;
    }
    /** The prompt's bounded initial polling interval, or zero for other events.
     */
    uint64_t interval_seconds() const noexcept
    {
        constexpr size_t required_size =
            offsetof(::questdb_oidc_event, interval_seconds) + sizeof(uint64_t);
        if (_event->struct_size < required_size)
            return 0;
        return _event->interval_seconds;
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
 * `sign_in()`, `token()`, `clear()`, and `close()` throw `questdb::oidc::error`
 * on failure. Note that when this same auth state is attached to an ingest
 * sender via `opts::oidc_auth`, a later token-acquisition failure surfaces from
 * `flush()` as a `questdb::ingress::line_sender_error` (with the OIDC detail on
 * its `oidc_diagnostic()` member), **not** as a `questdb::oidc::error` — so an
 * `oidc::error` handler written for this API does not transfer to a sender.
 * Catch the common base `const questdb::error&` to handle both. See
 * `questdb::oidc::error` for the full cross-surface exception model.
 */
class device_auth
{
public:
    /**
     * Not copyable: copying would read as a value copy and alias instead.
     *
     * `questdb_oidc_auth_clone` does not duplicate the provider, unlike
     * `line_sender_opts_clone`. It takes another handle on ONE shared state:
     * the token cache, the persisted entry and the closed flag are common to
     * every handle and to every attached sender, reader and pool. So
     * `clear()` on the copy deletes the credential the original's transports
     * are using -- including the on-disk refresh token -- and `close()` on it
     * permanently closes them. Every other handle in this header (`builder`,
     * `token`, `event_view`, `pool`, `reader`) is likewise non-copyable, so a
     * silently aliasing copy here would be the odd one out in exactly the
     * place the mistake is most expensive.
     *
     * Use `share()` when an additional handle is what you want, or pass
     * `const device_auth&`.
     */
    device_auth(const device_auth&) = delete;
    device_auth& operator=(const device_auth&) = delete;
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
    /**
     * Releases THIS handle only.
     *
     * It neither closes the shared provider nor removes a persisted
     * credential, unlike `~pool` and `~reader`, whose destructors do terminate
     * what they own. Dropping the last handle cancels nothing: work already
     * started -- a device poll on a worker, say -- runs to its own completion,
     * because `sign_in` holds its own reference. Call `close()` to stop it, and
     * `clear()` to remove a persisted refresh token.
     */
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
     * Take an additional handle on the SAME shared provider.
     *
     * Not a copy. The token cache, the persisted entry and the closed state are
     * shared by every handle `share()` produces and by every sender, reader and
     * pool attached to any of them, so `clear()` on one removes the credential
     * for all, and `close()` on one closes all. Contrast
     * `line_sender_opts::clone`, which does produce an independent value.
     *
     * Each handle must be destroyed independently; destroying one leaves the
     * others usable.
     */
    device_auth share() const
    {
        return device_auth{
            detail::wrapped_call(::questdb_oidc_auth_clone, raw())};
    }

    /**
     * Clear the in-memory credential and delete its persisted local entry.
     * Throws oidc::error if persisted deletion fails; memory is still cleared.
     * This does not revoke any token at the identity provider.
     *
     * Affects the SHARED state, not just this handle: every handle from
     * `share()`, and every attached sender, reader and pool, loses the
     * credential too.
     *
     * Remains available after `close()`, which drops the in-memory credential
     * but deliberately leaves the persisted entry behind -- clearing is the
     * only way to remove that, so it has to outlive the close.
     */
    void clear() const
    {
        detail::wrapped_call(::questdb_oidc_auth_clear, raw());
    }

    /**
     * Permanently close the shared provider and cancel a device-poll or bundled
     * file-token-store lock wait running on another thread. Every handle from
     * `share()` and every attached transport observes the same closed state.
     * Idempotent. The persisted entry is left behind -- see `clear()`.
     *
     * Safe from any thread, including this provider's own event callback: it
     * publishes the close without blocking, and only skips the wait for the
     * running operation to finish when called from inside a callback.
     */
    void close() const
    {
        detail::wrapped_call(::questdb_oidc_auth_close, raw());
    }

    /**
     * The resolved configuration. Each `string_view` borrows from this handle.
     *
     * WARNING: not display-sanitized. With `from_questdb` these values come
     * from the QuestDB server's unauthenticated `/settings` response (and a
     * discovered endpoint from the provider's discovery document), so strip
     * control, bidi and zero-width characters before writing any of them to a
     * terminal, a log, or an HTML sink. Only the device-flow event text is
     * filtered for you.
     */
    config_view config() const&
    {
        ::questdb_oidc_config_view raw{};
        raw.struct_size = sizeof raw;
        // Check the return: `questdb_oidc_auth_get_config` reports false for a
        // NULL auth or an undersized `struct_size`, and discarding it returned
        // a config_view of empty string_views that reads as a provider with no
        // client id rather than as the failure it is. The Python binding
        // raises for the same condition.
        if (!::questdb_oidc_auth_get_config(this->raw(), &raw))
        {
            throw error{
                ::questdb::error_code::invalid_api_call,
                "Could not read the OIDC configuration.",
                error_kind::unknown,
                {},
                {},
                std::nullopt,
                std::nullopt};
        }
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

    /**
     * Record a QuestDB server URL to discover OIDC settings from.
     *
     * Performs no network I/O: it only stores the URL. The `/settings`
     * request, and any follow-up IdP discovery it triggers, run inside
     * `build()` -- see the blocking note there before deciding which thread to
     * call each of these on.
     */
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

    /** Select the ID token instead of the access token. See
     *  `questdb_oidc_builder_groups_in_token`. */
    QUESTDB_OIDC_CPP_BOOL_SETTER(
        groups_in_token, ::questdb_oidc_builder_groups_in_token)
    /** Permit plaintext `http` for the QuestDB `/settings` request only; the
     *  identity provider is always held to `https` (or loopback). See
     *  `questdb_oidc_builder_allow_insecure_transport`. */
    QUESTDB_OIDC_CPP_BOOL_SETTER(
        allow_insecure_transport,
        ::questdb_oidc_builder_allow_insecure_transport)
    /** Whether `sign_in` launches a browser at the verification URL. */
    QUESTDB_OIDC_CPP_BOOL_SETTER(
        open_browser, ::questdb_oidc_builder_open_browser)
    /**
     * Whether `sign_in` may prompt at all (default `true`).
     *
     * `false` fails immediately instead of printing a device code nobody will
     * read and polling until it expires -- what a headless service or a CI job
     * wants. There is deliberately NO TTY auto-detection: a missing TTY is not
     * evidence of a missing human, so a caller that wants to fail fast has to
     * ask for it. See `questdb_oidc_builder_interactive`.
     */
    QUESTDB_OIDC_CPP_BOOL_SETTER(
        interactive, ::questdb_oidc_builder_interactive)

#undef QUESTDB_OIDC_CPP_BOOL_SETTER

    /**
     * Fallback seconds between device-code polls, used only when the identity
     * provider advertises no `interval` (default 5). A server-supplied
     * interval and any `Retry-After` take precedence; the value is clamped to
     * [5, 1800]. See `questdb_oidc_builder_default_interval_seconds`.
     */
    builder& default_interval_seconds(uint64_t seconds)
    {
        detail::wrapped_call(
            ::questdb_oidc_builder_default_interval_seconds, _raw, seconds);
        return *this;
    }
    /**
     * Timeout for each individual HTTP request (default 30000, maximum
     * 120000). NOT a deadline for the sign-in as a whole, which the device
     * code's own lifetime bounds. An out-of-range value is reported by
     * `build()`, not here. See `questdb_oidc_builder_timeout_ms`.
     */
    builder& timeout_ms(uint64_t milliseconds)
    {
        detail::wrapped_call(
            ::questdb_oidc_builder_timeout_ms, _raw, milliseconds);
        return *this;
    }
    /**
     * Explicitly persist access, ID, and long-lived refresh tokens as
     * unencrypted JSON under the directory named by the
     * `questdb.client.oidc.token.store.dir` environment variable, or
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

    /**
     * Resolve the configuration and create an auth state.
     *
     * **This call blocks on the network** when the builder came from
     * `from_questdb`: it issues the QuestDB `/settings` request here, and may
     * follow it with the identity provider's own discovery document to confirm
     * the advertised endpoints. Each request is bounded by `timeout_ms`
     * (default 30s, maximum 120s), so a call can take twice that before
     * returning. Do not call it on a UI thread.
     *
     * A builder configured with explicit endpoints performs no I/O here.
     *
     * The builder is reusable; each call creates an independent auth state.
     */
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
