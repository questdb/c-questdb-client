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

/**
 * Rotating Bearer-token providers.
 *
 * A `questdb_token_provider` supplies the current Bearer token to a sender
 * (ILP/HTTP or QWP/WebSocket), a reader or a pool. Create one of two kinds:
 *
 * - a **refreshing provider** (`questdb_refreshing_token_provider_new`): a
 *   proactively refreshing cache in front of a token *source* callback that
 *   fetches a token and its expiry however you like -- Azure Identity, an
 *   OAuth2 client-credentials or PKCE flow, a device flow, a secrets vault.
 *   Clients read the cached token; the provider refreshes it on its own thread
 *   at about half its lifetime, retries failures with backoff, and refreshes
 *   early when a server rejects the token with HTTP 401;
 * - an **application provider** (`questdb_token_provider_new`): a function
 *   table whose `get_token` returns the current token. Prefer a refreshing
 *   provider unless you already cache tokens: `get_token` runs on every
 *   connect round.
 *
 * Attach it with `line_sender_opts_token_provider`,
 * `questdb_db_connect_options.token_provider` or
 * `qwp_reader_from_conf_with_token_provider`. Each client keeps its own
 * reference, so the handle may be freed afterwards. Clients never close a
 * provider: close a refreshing provider yourself once no client needs it.
 *
 * Behaviour follows the cross-language dynamic-credential specification
 * (design/qwp-token-provider-spec.md v0.7 in the Java client). This client
 * selects no provider from a connect string: the `token_provider` key and the
 * `azure_*` keys are rejected.
 *
 * Callback contract:
 * - A source runs only on the provider's refresher thread, never concurrently
 *   with itself. It may block, but should bound its own network calls (30 s
 *   per attempt is recommended).
 * - `get_token` and `on_rejected` run on a connect thread or an isolated
 *   worker, possibly concurrently.
 * - A callback must report through the sink it is given, which is valid only
 *   during the call, and must not call into a client that uses the same
 *   provider.
 * - `release` runs once, on any thread, when the provider no longer needs
 *   `user_data`. It may run after the call that created the provider returns.
 * - Providers and clients must not be used across `fork()`. Use spawn/exec
 *   workers and create providers there, or fork before creating any providers
 *   or clients. A fresh provider alone cannot repair a multithreaded parent's
 *   inherited runtime state and isolated-worker accounting.
 * - Never put a token in an error message.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ingress/line_sender.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef QUESTDB_TOKEN_PROVIDER_DEFINED
#    define QUESTDB_TOKEN_PROVIDER_DEFINED
/** A rotating Bearer-token provider. */
typedef struct questdb_token_provider questdb_token_provider;
#endif

/** Where a callback reports its result; valid only during the callback. */
typedef struct questdb_token_sink questdb_token_sink;

/** An owned token, zeroized when freed with `questdb_token_free`. */
typedef struct questdb_token questdb_token;

/**
 * Report a token from a source or `get_token` callback. The token (UTF-8,
 * without the `Bearer ` prefix) is copied.
 *
 * `expires_at_ms` is the token's expiry in epoch milliseconds: a source must
 * give it; `get_token` may pass 0. If the platform gave a relative lifetime
 * (OAuth's `expires_in`), compute the expiry from the local time of receipt.
 * For a token that does not expire, pass `INT64_MAX`: on every platform, an
 * instant after 9999-12-31T23:59:59.999Z is treated as that instant.
 * `refresh_at_ms` is the platform's suggested refresh time, or 0 for none.
 *
 * Returns false, recording nothing, when `sink` is NULL, a result was already
 * reported, or the token is not valid UTF-8.
 */
QUESTDB_CLIENT_API
bool questdb_token_sink_set_token(
    questdb_token_sink* sink,
    const char* token,
    size_t token_len,
    int64_t expires_at_ms,
    int64_t refresh_at_ms);

/**
 * Report a failure from a source or `get_token` callback.
 *
 * `retryable` says whether retrying can succeed: network failures, timeouts,
 * HTTP 429 and 5xx are retryable; missing or wrong configuration is not. When
 * unsure, report retryable. `retry_after_ms` is a suggested wait (such as a
 * `Retry-After` header), or negative for none. The message (UTF-8, copied)
 * must not contain a token or a raw response body.
 *
 * A connect the caller waits for -- the synchronous initial connect, a pool
 * borrow with retry -- retries only a retryable failure. Background reconnects
 * retry either kind.
 *
 * Returns false when `sink` is NULL or a result was already reported.
 */
QUESTDB_CLIENT_API
bool questdb_token_sink_set_error(
    questdb_token_sink* sink,
    bool retryable,
    int64_t retry_after_ms,
    const char* msg,
    size_t msg_len);

/** Fetch a new token: report it with exactly one sink call. */
typedef void (*questdb_token_source_fn)(
    void* user_data, questdb_token_sink* sink);

/** Supply the current token: report it with exactly one sink call. */
typedef void (*questdb_token_get_fn)(void* user_data, questdb_token_sink* sink);

/**
 * A server rejected `token` (`token_len` bytes, not NUL-terminated) with
 * `http_status`, currently always 401. The client then calls `get_token`
 * again and retries once if the token changed. A provider with a cache should
 * stop serving `token`. May be called more than once for one rejection.
 */
typedef void (*questdb_token_rejected_fn)(
    void* user_data, const char* token, size_t token_len, uint16_t http_status);

/** Release `user_data` once the provider no longer needs it. */
typedef void (*questdb_token_release_fn)(void* user_data);

/**
 * Parameters of a refreshing provider. Initialize with
 * `questdb_refreshing_token_provider_options_init(&options, sizeof options)`,
 * which fills in the specification's defaults, then override what you need.
 * `struct_size` records the caller's allocation size; do not modify it.
 */
typedef struct questdb_refreshing_token_provider_options
{
    size_t struct_size;
    /** Non-secret label for log lines and errors (UTF-8); NULL for the
     *  default, `token-provider`. */
    const char* name;
    size_t name_len;
    /** Upper bound on how close to expiry a scheduled refresh may run.
     *  Default 300000. */
    uint64_t refresh_margin_ms;
    /** Lower bound on the time between a fetch and the next scheduled
     *  refresh. Default 30000. */
    uint64_t min_refresh_interval_ms;
    /** A token is usable only while now < expiry - handout_floor. A fetched
     *  token that is not usable on arrival is a failed fetch, so a source
     *  whose tokens live no longer than this needs a lower value. Default
     *  60000. */
    uint64_t handout_floor_ms;
    /** The longest a client waits when no usable token is held. Default
     *  30000. */
    uint64_t cold_wait_ms;
    /** First retry delay after a failed fetch; must be positive. Default
     *  500. */
    uint64_t backoff_initial_ms;
    /** Largest retry delay; at least backoff_initial_ms. Default 60000. */
    uint64_t backoff_max_ms;
    /** Cap applied to a source's retry_after. Default 300000. */
    uint64_t retry_after_max_ms;
    /** Minimum spacing between refreshes forced by a 401. Default 30000. */
    uint64_t forced_min_interval_ms;
    /** The longest a 401 waits for its forced refresh. Default 5000. */
    uint64_t forced_wait_ms;
} questdb_refreshing_token_provider_options;

/** Fill `options` with the defaults. `struct_size` is `sizeof *options`. */
QUESTDB_CLIENT_API
void questdb_refreshing_token_provider_options_init(
    questdb_refreshing_token_provider_options* options, size_t struct_size);

/**
 * Create a refreshing provider around `source`. Its first fetch starts at
 * once, on the provider's own thread. `options` may be NULL for the defaults.
 *
 * The provider owns `user_data` from this call on, failed calls included:
 * `release` (may be NULL) runs once when it is no longer needed. Free the
 * handle with `questdb_token_provider_free`.
 *
 * Returns NULL and sets `*err_out` on invalid arguments.
 */
QUESTDB_CLIENT_API
questdb_token_provider* questdb_refreshing_token_provider_new(
    questdb_token_source_fn source,
    void* user_data,
    questdb_token_release_fn release,
    const questdb_refreshing_token_provider_options* options,
    questdb_error** err_out);

/**
 * Function table of an application-implemented provider. Set `struct_size` to
 * `sizeof(questdb_token_provider_vtable)`. `get_token` is required; the other
 * entries may be NULL.
 */
typedef struct questdb_token_provider_vtable
{
    size_t struct_size;
    questdb_token_get_fn get_token;
    questdb_token_rejected_fn on_rejected;
    questdb_token_release_fn release;
} questdb_token_provider_vtable;

/**
 * Create a provider from an application-implemented function table. Free the
 * handle with `questdb_token_provider_free`.
 *
 * Once `vtable` is readable -- non-NULL, with a sufficient `struct_size` --
 * the provider owns `user_data`, failed calls included: `vtable->release` (may
 * be NULL) runs once when it is no longer needed. For a NULL or undersized
 * `vtable`, `user_data` stays with the caller.
 *
 * Returns NULL and sets `*err_out` on invalid arguments.
 */
QUESTDB_CLIENT_API
questdb_token_provider* questdb_token_provider_new(
    const questdb_token_provider_vtable* vtable,
    void* user_data,
    questdb_error** err_out);

/** Another handle to the same provider; NULL for NULL. */
QUESTDB_CLIENT_API
questdb_token_provider* questdb_token_provider_clone(
    const questdb_token_provider* provider);

/**
 * Release this handle. Clients the provider is attached to keep using it, and
 * a refreshing provider keeps refreshing until it is closed or every handle
 * and client using it is gone. NULL-tolerant.
 */
QUESTDB_CLIENT_API
void questdb_token_provider_free(questdb_token_provider* provider);

/**
 * Close a refreshing provider: stop its refresher and fail every later token
 * request as permanent, which ends every client that uses it. Attaching a
 * closed provider to a new sender, pool or reader then fails at once with
 * that same permanent error (`line_sender_error_auth_error`). Idempotent.
 * No-op for an application provider and for NULL.
 */
QUESTDB_CLIENT_API
void questdb_token_provider_close(const questdb_token_provider* provider);

/**
 * Wait up to `timeout_ms` for a refreshing provider to hold a usable token;
 * use it to gate startup on the first fetch. False on timeout, for a closed
 * provider and for NULL. True at once for an application provider.
 */
QUESTDB_CLIENT_API
bool questdb_token_provider_await_ready(
    const questdb_token_provider* provider, uint64_t timeout_ms);

/**
 * The current token, for a client of your own (PG-wire, say). A refreshing
 * provider returns its cached token, or waits up to its `cold_wait_ms` for
 * one. Returns NULL and sets `*err_out` on failure; read the classification
 * with `questdb_error_token_unavailable_get_view`.
 */
QUESTDB_CLIENT_API
questdb_token* questdb_token_provider_token(
    const questdb_token_provider* provider, questdb_error** err_out);

/** The token bytes (UTF-8, not NUL-terminated). NULL for NULL. */
QUESTDB_CLIENT_API
const char* questdb_token_data(const questdb_token* token);

/** The token length in bytes. 0 for NULL. */
QUESTDB_CLIENT_API
size_t questdb_token_len(const questdb_token* token);

/** Zeroize and free a token. NULL-tolerant. */
QUESTDB_CLIENT_API
void questdb_token_free(questdb_token* token);

/**
 * Tell the provider that a server rejected `token` with `http_status`, for a
 * client of your own. A refreshing provider refreshes early on a 401 for its
 * current token -- at most once per `forced_min_interval_ms` -- and waits up
 * to `forced_wait_ms` for the result.
 */
QUESTDB_CLIENT_API
void questdb_token_provider_on_rejected(
    const questdb_token_provider* provider,
    const char* token,
    size_t token_len,
    uint16_t http_status);

/**
 * A snapshot of a refreshing provider. Never contains the token. Times are
 * epoch milliseconds, -1 for none.
 */
typedef struct questdb_token_provider_status
{
    size_t struct_size;
    bool closed;
    bool has_last_failure;
    bool last_failure_retryable;
    uint32_t consecutive_failures;
    int64_t token_expires_at_ms;
    int64_t last_success_at_ms;
    int64_t last_failure_retry_after_ms;
    int64_t last_failure_at_ms;
    /** Caller buffer for the last failure's message (UTF-8, not
     *  NUL-terminated), or NULL. */
    char* last_failure_msg;
    size_t last_failure_msg_capacity;
    /** The message length in bytes before any truncation. */
    size_t last_failure_msg_len;
} questdb_token_provider_status;

/**
 * Read a refreshing provider's status. Set `out->struct_size` to
 * `sizeof *out`, and `last_failure_msg` / `last_failure_msg_capacity` to a
 * buffer for the message (1024 bytes always suffice), which is truncated at a
 * character boundary to fit. Returns false for NULL, an application provider,
 * or an undersized `out`, whose `struct_size` is then set to the size this
 * library requires.
 */
QUESTDB_CLIENT_API
bool questdb_token_provider_get_status(
    const questdb_token_provider* provider, questdb_token_provider_status* out);

/** How a token source or provider classified a failure. */
typedef struct questdb_token_unavailable_view
{
    size_t struct_size;
    bool retryable;
    /** The suggested wait before retrying in milliseconds, -1 for none. */
    int64_t retry_after_ms;
} questdb_token_unavailable_view;

/**
 * The token-unavailable classification carried by `error`, when a token
 * source or provider failed to supply a token. Set `out->struct_size` to
 * `sizeof *out`. Returns false when the error carries none, or for an
 * undersized `out`, whose `struct_size` is then set to the size this library
 * requires.
 */
QUESTDB_CLIENT_API
bool questdb_error_token_unavailable_get_view(
    const questdb_error* error, questdb_token_unavailable_view* out);

/**
 * Attach `provider` to HTTP(S) or QWP/WebSocket sender options. The options
 * keep their own reference. On a 401 the sender calls the provider's
 * `on_rejected`, pulls again, and retries once if the token changed and the
 * `WWW-Authenticate` challenge allows it (no Bearer error, or
 * `invalid_token`).
 *
 * Mutually exclusive with `username`/`password`, `token` and
 * `line_sender_opts_oidc_auth`: one opts take one rotating provider, so a
 * second token provider or an OIDC auth fails with
 * `line_sender_error_config_error` instead of replacing the first. A
 * refreshing provider already closed with `questdb_token_provider_close` is
 * rejected with its permanent `line_sender_error_auth_error`. On failure the
 * opts are left unchanged. Use `https::` or `wss::`: over plain `http::` or
 * `ws::` to a non-loopback host the token travels in cleartext.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_token_provider(
    line_sender_opts* opts,
    const questdb_token_provider* provider,
    questdb_error** err_out);

#ifdef __cplusplus
}
#endif
