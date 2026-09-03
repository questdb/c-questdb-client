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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include <questdb/ingress/line_sender.h>

/** Reusable device-flow builder, shared authentication state, and owned token.
 */
typedef struct questdb_oidc_builder questdb_oidc_builder;
#ifndef QUESTDB_OIDC_AUTH_DEFINED
#    define QUESTDB_OIDC_AUTH_DEFINED
typedef struct questdb_oidc_auth questdb_oidc_auth;
#endif
typedef struct questdb_oidc_token questdb_oidc_token;

typedef enum questdb_oidc_event_kind
{
    QUESTDB_OIDC_EVENT_PROMPT = 0,
    QUESTDB_OIDC_EVENT_WAITING = 1,
    QUESTDB_OIDC_EVENT_SUCCESS = 2,
    QUESTDB_OIDC_EVENT_FAILURE = 3,
} questdb_oidc_event_kind;

/**
 * Borrowed renderer event. Its strings are valid only during the callback.
 * Each string is a pointer-plus-length byte span and is not NUL-terminated;
 * always use the corresponding `_len` field.
 *
 * All textual fields are display-safe, inert, single-line text: terminal
 * controls, bidi/zero-width characters, and other invisible formatting are
 * removed. Non-ASCII characters in the display-only prompt code/URLs are
 * visibly escaped. `verification_uri` and `verification_uri_complete` are for
 * display only.
 * `browser_target`, when non-NULL, is the sole URL vetted for opening or making
 * clickable (HTTP(S), no userinfo, non-empty ASCII host).
 *
 * Event-specific numeric fields:
 * - PROMPT: `expires_in_seconds` is the bounded device-code lifetime and
 *   `interval_seconds` is the bounded initial polling interval.
 * - WAITING: `seconds_left` is the remaining device-code lifetime.
 * - SUCCESS: `expires_in_seconds` is the token's remaining lifetime.
 *
 * `interval_seconds` was appended to this struct. Code that can load an older
 * shared library should check `struct_size` before reading it.
 */
typedef struct questdb_oidc_event
{
    size_t struct_size;
    questdb_oidc_event_kind kind;
    const char* user_code;
    size_t user_code_len;
    const char* verification_uri;
    size_t verification_uri_len;
    const char* verification_uri_complete;
    size_t verification_uri_complete_len;
    const char* identity;
    size_t identity_len;
    const char* message;
    size_t message_len;
    double seconds_left;
    double expires_in_seconds;
    const char* browser_target;
    size_t browser_target_len;
    uint64_t interval_seconds;
} questdb_oidc_event;

/**
 * May run on any thread that acquires or refreshes a token and must not
 * unwind. Invocations of one installed handler are serialized across every
 * auth object built from that builder, so its `user_data` is never entered
 * concurrently by OIDC events.
 *
 * While the callback is running, `sign_in` and `clear` on an auth object
 * sharing this handler fail with `questdb_error_invalid_api_call`, as does
 * `token` when no valid cached token is available -- including token
 * acquisition through an attached sender, reader, or pool, which surfaces it
 * through that transport's provider-error path. `token` DOES succeed from a
 * valid cache: that path consults no lock the callback holds. The rejection
 * applies to any thread, not only the callback's own, because a callback may
 * dispatch to a worker and wait for it. Return from the callback before
 * starting another auth operation.
 *
 * The two cases are distinguished in the error message: a caller on the
 * callback's own thread is told it re-entered, while a caller on another thread
 * is told the provider is busy. `close` is never rejected either way.
 */
typedef void (*questdb_oidc_event_cb)(
    void* user_data, const questdb_oidc_event* event);
/**
 * May run on whichever thread releases the final builder/auth/transport ref.
 * Must return normally: it must not throw, unwind, or perform a non-local jump
 * such as `longjmp` across the callback boundary.
 */
typedef void (*questdb_oidc_user_data_release_cb)(void* user_data);

/** Explicit configuration; set client id and both OAuth endpoints before build.
 */
QUESTDB_CLIENT_API
questdb_oidc_builder* questdb_oidc_builder_new(void);

/** Discover OIDC settings from the QuestDB server's `/settings` endpoint. */
QUESTDB_CLIENT_API
questdb_oidc_builder* questdb_oidc_builder_from_questdb(
    const char* url, size_t url_len, questdb_error** err_out);

QUESTDB_CLIENT_API
void questdb_oidc_builder_free(questdb_oidc_builder* builder);

#define QUESTDB_OIDC_STRING_BUILDER_FN(name)                                   \
    QUESTDB_CLIENT_API bool name(                                              \
        questdb_oidc_builder* builder,                                         \
        const char* value,                                                     \
        size_t value_len,                                                      \
        questdb_error** err_out)

QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_client_id);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_scope);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_audience);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_issuer);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_token_endpoint);
QUESTDB_OIDC_STRING_BUILDER_FN(
    questdb_oidc_builder_device_authorization_endpoint);

#undef QUESTDB_OIDC_STRING_BUILDER_FN

QUESTDB_CLIENT_API
bool questdb_oidc_builder_groups_in_token(
    questdb_oidc_builder* builder, bool enabled, questdb_error** err_out);
/**
 * Permit plaintext `http` to the QuestDB server whose `/settings` endpoint
 * supplies the OIDC configuration (local development only).
 *
 * Despite the name, this relaxes ONLY that one link. The identity provider's
 * device-authorization and token endpoints are always held to `https`, so the
 * device code and the refresh token are never sent in cleartext, and enabling
 * this cannot change that.
 *
 * Plaintext `http` to a loopback host is allowed with or without this flag: the
 * request never leaves the machine. (`localhost` is accepted only if it actually
 * resolves to a loopback address.)
 *
 * A tampered `/settings` response can redirect where you sign in, so over a
 * plaintext channel the client refuses settings-sourced values it cannot
 * otherwise protect: pin the provider with `questdb_oidc_builder_issuer`, and
 * pass any client id, scope, audience or groups flag you rely on explicitly.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_allow_insecure_transport(
    questdb_oidc_builder* builder, bool enabled, questdb_error** err_out);
QUESTDB_CLIENT_API
bool questdb_oidc_builder_open_browser(
    questdb_oidc_builder* builder, bool enabled, questdb_error** err_out);
QUESTDB_CLIENT_API
bool questdb_oidc_builder_interactive(
    questdb_oidc_builder* builder, bool enabled, questdb_error** err_out);
QUESTDB_CLIENT_API
bool questdb_oidc_builder_default_interval_seconds(
    questdb_oidc_builder* builder, uint64_t seconds, questdb_error** err_out);
QUESTDB_CLIENT_API
bool questdb_oidc_builder_timeout_ms(
    questdb_oidc_builder* builder,
    uint64_t timeout_ms,
    questdb_error** err_out);
QUESTDB_CLIENT_API
bool questdb_oidc_builder_ca_bundle(
    questdb_oidc_builder* builder,
    const char* path,
    size_t path_len,
    questdb_error** err_out);

/**
 * Explicitly enable plaintext file persistence in `directory`.
 *
 * The store writes access, ID, and long-lived refresh tokens as unencrypted
 * JSON. On Unix, the library creates token files with mode `0600` and store
 * directories with mode `0700`; on other platforms protection depends on the
 * directory's default ACL. The caller must ensure that the directory is
 * accessible only to the intended account and accept the at-rest exposure.
 * Without this call, credentials remain in memory only.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_file_token_store(
    questdb_oidc_builder* builder,
    const char* directory,
    size_t directory_len,
    questdb_error** err_out);

/**
 * Explicitly enable plaintext file persistence at
 * the directory named by the `questdb.client.oidc.token.store.dir` environment
 * variable, or `${HOME}/.questdb/oidc-tokens/` when it is unset.
 *
 * The store writes access, ID, and long-lived refresh tokens as unencrypted
 * JSON. On Unix, the library creates token files with mode `0600` and store
 * directories with mode `0700`; on other platforms protection depends on the
 * directory's default ACL. Use this only when that at-rest security tradeoff is
 * acceptable. Without this call, credentials remain in memory only.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_default_file_token_store(
    questdb_oidc_builder* builder, questdb_error** err_out);

/**
 * Install a renderer callback. If `user_data` is non-NULL, `release` must also
 * be non-NULL. On success ownership of `user_data` transfers to the builder
 * and `release` runs exactly once after the builder and all auth handles and
 * attached transports built from it have released their last reference. On
 * failure ownership remains with the caller. A stateless callback may pass
 * both `user_data` and `release` as NULL. Final release has no thread-affinity
 * guarantee and must return normally without throwing, unwinding, or
 * performing a non-local jump.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_event_handler(
    questdb_oidc_builder* builder,
    questdb_oidc_event_cb callback,
    void* user_data,
    questdb_oidc_user_data_release_cb release,
    questdb_error** err_out);

/** The builder is reusable; each call creates an independent auth state. */
QUESTDB_CLIENT_API
questdb_oidc_auth* questdb_oidc_builder_build(
    const questdb_oidc_builder* builder, questdb_error** err_out);

/**
 * Take an additional handle on the SAME shared auth state.
 *
 * Unlike `line_sender_opts_clone`, which produces an independent copy, this is
 * a reference to one underlying provider: the token cache, the persisted entry
 * and the closed state are shared by every handle and by every attached sender,
 * reader and pool. `questdb_oidc_auth_clear` on any handle therefore removes
 * the credential for all of them, and `questdb_oidc_auth_close` on any handle
 * permanently closes all of them.
 *
 * Both the original and the clone must be freed with
 * `questdb_oidc_auth_free`; freeing one does not disturb the other.
 */
QUESTDB_CLIENT_API
questdb_oidc_auth* questdb_oidc_auth_clone(
    const questdb_oidc_auth* auth, questdb_error** err_out);
QUESTDB_CLIENT_API
void questdb_oidc_auth_free(questdb_oidc_auth* auth);

/**
 * Permanently close this shared auth state. Cancels a device flow or bundled
 * file-token-store lock wait running on another thread. All cloned handles and
 * attached transports share the closed state. Idempotent. This is distinct from
 * `questdb_oidc_auth_free`, which releases only one handle and does not cancel
 * shared work.
 *
 * Safe to call from any thread, including this auth's own event callback and
 * while a callback is running on another thread -- publishing the close never
 * blocks. It additionally waits for the running operation to leave the
 * authentication critical section, except when called *on the thread currently
 * executing a callback*, which runs inside that very section: only there does
 * it return as soon as the close is published. A call from any other thread
 * waits, even while a callback is in flight elsewhere. Unlike `sign_in`,
 * `token` and `clear`, it is never rejected as callback re-entry.
 *
 * The in-memory credential is dropped on every path, including the
 * skipped-drain one; only the wait is skipped. The persisted entry is
 * left behind either way -- see `questdb_oidc_auth_clear`.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_auth_close(
    const questdb_oidc_auth* auth, questdb_error** err_out);

/**
 * Run the interactive device flow when no cached or silently refreshable token
 * is available. This is the only auth operation that may display a prompt and
 * wait for user authorization; call it on a suitable UI thread before starting
 * attached transports.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_auth_sign_in(
    const questdb_oidc_auth* auth, questdb_error** err_out);

/**
 * Return an owned copy of a cached, persisted, or silently refreshed token.
 * Returns the access token by default, or the ID token when the auth
 * configuration has `groups_in_token` enabled. Never starts an interactive
 * device flow. Returns an OIDC
 * QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED error when explicit sign-in is
 * needed, including when another sign-in is in progress and no valid token is
 * cached.
 */
QUESTDB_CLIENT_API
questdb_oidc_token* questdb_oidc_auth_token(
    const questdb_oidc_auth* auth, questdb_error** err_out);

/**
 * Clear the in-memory credential and delete its persisted local entry, if any.
 * The in-memory credential is always cleared. Returns false with an OIDC error
 * when persisted deletion fails, because the credential may remain usable by a
 * new auth object or after process restart. This does not revoke any token at
 * the identity provider.
 *
 * Remains available after `questdb_oidc_auth_close`, which drops the in-memory
 * credential but leaves the persisted entry: clearing is the only way to remove
 * that, so it must outlive the close.
 *
 * Affects the SHARED state, not just this handle: every handle obtained from
 * `questdb_oidc_auth_clone`, and every attached sender, reader and pool, loses
 * the credential too. See `questdb_oidc_auth_clone`.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_auth_clear(
    const questdb_oidc_auth* auth, questdb_error** err_out);

/** Token bytes borrow from `token`; they are not NUL-terminated and must be
 *  read using `questdb_oidc_token_len`. A NULL token returns NULL data and a
 *  zero length. */
QUESTDB_CLIENT_API
const char* questdb_oidc_token_data(const questdb_oidc_token* token);
QUESTDB_CLIENT_API
size_t questdb_oidc_token_len(const questdb_oidc_token* token);
/** Frees and zeroizes the owned token allocation. */
QUESTDB_CLIENT_API
void questdb_oidc_token_free(questdb_oidc_token* token);

/**
 * Resolved configuration view. Strings borrow from the auth handle.
 * Each string is a pointer-plus-length byte span and is not NUL-terminated;
 * always use the corresponding `_len` field.
 * Zero-initialize the struct and set `struct_size = sizeof(view)` before
 * calling `questdb_oidc_auth_get_config`. On success `struct_size` is replaced
 * with the prefix written by the library; fields beyond that prefix remain at
 * their zero defaults when using an older library.
 */
typedef struct questdb_oidc_config_view
{
    size_t struct_size;
    bool groups_in_token;
    const char* client_id;
    size_t client_id_len;
    const char* token_endpoint;
    size_t token_endpoint_len;
    const char* device_authorization_endpoint;
    size_t device_authorization_endpoint_len;
    const char* scope;
    size_t scope_len;
    const char* audience;
    size_t audience_len;
    const char* issuer;
    size_t issuer_len;
} questdb_oidc_config_view;

/**
 * Read the resolved configuration into `*out`. See `questdb_oidc_config_view`
 * for the zero-initialize-and-set-`struct_size` contract.
 *
 * WARNING: the strings are returned verbatim and are NOT display-sanitized.
 * Unlike the device-flow event text, which the library filters before it
 * reaches a renderer, these are raw bytes: with
 * `questdb_oidc_builder_from_questdb` they come from the QuestDB server's
 * unauthenticated `/settings` response (and, for a discovered endpoint, the
 * provider's discovery document), so a hostile or MITM'd server can plant ANSI
 * escapes, bidi overrides or zero-width characters in them. Strip control,
 * bidi and zero-width characters yourself before writing any of them to a
 * terminal, a log, or an HTML sink. They are also not NUL-terminated: read each
 * with its `_len`.
 *
 * Returns `false` if `auth` is NULL, or if `out` is NULL or its `struct_size`
 * is smaller than the library's v1 layout.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_auth_get_config(
    const questdb_oidc_auth* auth, questdb_oidc_config_view* out);

typedef enum questdb_oidc_error_kind
{
    QUESTDB_OIDC_ERROR_CONFIG = 0,
    QUESTDB_OIDC_ERROR_NETWORK = 1,
    QUESTDB_OIDC_ERROR_DEVICE_FLOW = 2,
    QUESTDB_OIDC_ERROR_TIMEOUT = 3,
    QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED = 4,
    QUESTDB_OIDC_ERROR_CANCELLED = 5,
    QUESTDB_OIDC_ERROR_UNKNOWN = 255,
} questdb_oidc_error_kind;

/**
 * Structured OIDC details borrowed from a live `questdb_error`. Zero-initialize
 * the struct and set `struct_size = sizeof(view)` before calling
 * `questdb_error_oidc_get_view`. On success `struct_size` is replaced with the
 * prefix written by the library.
 */
typedef struct questdb_oidc_error_view
{
    size_t struct_size;
    questdb_oidc_error_kind kind;
    const char* idp_error;
    size_t idp_error_len;
    const char* idp_error_description;
    size_t idp_error_description_len;
    bool has_status;
    uint16_t status;
    bool has_retry_after;
    uint64_t retry_after_seconds;
} questdb_oidc_error_view;

/**
 * Fill `out` when an OIDC failure is present in this error's causal chain.
 *
 * True does NOT mean the error *is* the OIDC failure, only that one caused it.
 * `questdb_error_get_code` and `questdb_error_msg` still describe the outermost
 * failure, and a transport that re-classifies an error on its way out keeps the
 * OIDC payload attached: a token-provider failure surfacing as a retryable
 * `line_sender_error_socket_error`, or a failover giving up after several
 * attempts, both answer true here while their code and message are the
 * transport's. Bindings that pick an exception type from this predicate should
 * therefore keep it a subtype of their ordinary error type, and must not drop
 * the outer code or message on the strength of it.
 *
 * Returns false for an error with no OIDC failure anywhere in its chain, or an
 * undersized output view. On the undersized path `out->struct_size` is
 * overwritten with the minimum this library requires, and no other field is
 * written.
 */
QUESTDB_CLIENT_API
bool questdb_error_oidc_get_view(
    const questdb_error* error, questdb_oidc_error_view* out);

/**
 * Attach rotating OIDC Bearer authentication to HTTP(S) or QWP/WS opts.
 * Token lookup may use persistence or silent refresh but never starts an
 * interactive device flow from flush/connect/reconnect. Call
 * questdb_oidc_auth_sign_in before starting the sender; if another explicit
 * sign-in later becomes necessary, the transport reports
 * QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_oidc_auth(
    line_sender_opts* opts,
    const questdb_oidc_auth* auth,
    questdb_error** err_out);

#ifdef __cplusplus
}
#endif
