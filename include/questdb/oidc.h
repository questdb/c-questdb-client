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

/** Maximum accepted byte length for any single pointer-plus-length textual
 *  OIDC builder input. The bound is applied before UTF-8 validation. */
#define QUESTDB_OIDC_MAX_INPUT_BYTES ((size_t)1048576)

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
 * Runs on the thread inside `questdb_oidc_auth_sign_in`, and must not unwind.
 *
 * Every event is emitted by the interactive device flow, which is reachable
 * only through `questdb_oidc_auth_sign_in`. A silent refresh does not render:
 * `questdb_oidc_auth_token` -- and so every token pull an attached sender,
 * reader or pool makes on a background reconnect -- returns
 * `QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED` rather than prompting. A binding
 * that must enter a managed runtime from this callback may rely on that: no
 * background or otherwise unmanaged thread reaches it.
 *
 * Invocations of one installed handler are serialized across every auth object
 * built from that builder, so its `user_data` is never entered concurrently by
 * OIDC events.
 *
 * While the callback is running, `sign_in` and `clear` on an auth object
 * sharing this handler fail with `questdb_error_invalid_api_call`.
 *
 * `token` also fails when no valid cached token is available -- including
 * token acquisition through an attached sender, reader, or pool, which
 * surfaces it through that transport's provider-error path -- but it fails
 * with the RETRYABLE `questdb_error_socket_error`, not
 * `questdb_error_invalid_api_call`, on EITHER thread. The condition clears as
 * soon as the callback returns, so a transport must retry rather than
 * terminalize: a terminal class here stopped a background reconnect
 * permanently and stranded a store-and-forward queue over a prompt that was
 * still being painted, which is as unrecoverable for a caller who re-entered
 * by mistake as for one that did nothing wrong.
 *
 * The two still differ in what a transport does with the retryable failure.
 * From ANOTHER thread the wait can clear on its own, so a transport holding an
 * intact batch re-resolves within its retry budget. On the callback's OWN
 * thread the blocked caller *is* the callback, so no wait inside that call can
 * release the lock and the operation fails immediately instead of spending the
 * budget. Either way the error carries the structured OIDC payload, so
 * `questdb_error_oidc_get_view` answers true.
 *
 * `token` DOES succeed from a valid cache: that path consults no lock the
 * callback holds. The rejection applies to any thread, not only the callback's
 * own, because a callback may dispatch to a worker and wait for it. Return
 * from the callback before starting another auth operation.
 *
 * The two cases are distinguished in the error message: a caller on the
 * callback's own thread is told it re-entered, while a caller on another thread
 * is told the provider is busy. `questdb_oidc_auth_cancel_sign_in` and `close`
 * are never rejected either way. Use the former for an ordinary UI "cancel":
 * it aborts only this device flow and leaves the shared provider usable.
 */
typedef void (*questdb_oidc_event_cb)(
    void* user_data, const questdb_oidc_event* event);
/**
 * May run on whichever thread releases the final builder/auth/transport ref.
 * Must return normally: it must not throw, unwind, or perform a non-local jump
 * such as `longjmp` across the callback boundary.
 */
typedef void (*questdb_oidc_user_data_release_cb)(void* user_data);

typedef enum questdb_oidc_diagnostic_kind
{
    QUESTDB_OIDC_DIAGNOSTIC_PERSISTENCE_WARNING = 0,
} questdb_oidc_diagnostic_kind;

/** Borrowed best-effort diagnostic view, valid only during the callback. */
typedef struct questdb_oidc_diagnostic
{
    size_t struct_size;
    questdb_oidc_diagnostic_kind kind;
    const char* message;
    size_t message_len;
} questdb_oidc_diagnostic;

/**
 * Persistence diagnostic callback. It may run on a token-provider or transport
 * thread during silent refresh. Invocations are serialized. Return promptly;
 * do not re-enter the auth or transport operation that emitted it, and never
 * throw, unwind, or perform a non-local jump across this boundary.
 */
typedef void (*questdb_oidc_diagnostic_cb)(
    void* user_data, const questdb_oidc_diagnostic* diagnostic);

/** Explicit configuration; set client id and both OAuth endpoints before build.
 */
QUESTDB_CLIENT_API
questdb_oidc_builder* questdb_oidc_builder_new(void);

/**
 * Record a QuestDB server URL to discover OIDC settings from.
 *
 * This performs NO network I/O: it only stores the URL. The `/settings`
 * request, and any follow-up IdP discovery it triggers, run inside
 * `questdb_oidc_builder_build` -- see the blocking note there before deciding
 * which thread to call each of these on.
 */
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

/** Every setter below must be non-empty when set -- `client_id`, `scope`,
 *  `audience`, `issuer`, and both endpoint overrides;
 *  `questdb_oidc_builder_build` reports an OIDC configuration error otherwise.
 *  An empty endpoint override is rejected rather than treated as "discover it":
 *  it would otherwise suppress both the `/settings` value and the IdP discovery
 *  fallback, then fail much later with an unrelated message. Leave an override
 *  unset to discover that endpoint.
 */
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_client_id);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_scope);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_audience);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_issuer);
QUESTDB_OIDC_STRING_BUILDER_FN(questdb_oidc_builder_token_endpoint);
QUESTDB_OIDC_STRING_BUILDER_FN(
    questdb_oidc_builder_device_authorization_endpoint);

#undef QUESTDB_OIDC_STRING_BUILDER_FN

/**
 * Override the discovered groups-in-token mode. `true` selects the `id_token`
 * as the token presented to QuestDB; otherwise the `access_token` is used.
 *
 * This does NOT modify the configured scope. The scope is sent verbatim on the
 * device-authorization request and retained for token selection and persisted
 * identity. Refresh requests intentionally omit it per RFC 6749 section 6, so
 * they cannot request scope beyond the original grant. Include `openid` in
 * `questdb_oidc_builder_scope` explicitly when the identity
 * provider requires it to issue an ID token, or the flow fails with an OIDC
 * configuration error that no retry inside this process can clear.
 */
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
 * request never leaves the machine. (`localhost` is accepted only if it
 * actually resolves to a loopback address.)
 *
 * A tampered `/settings` response can redirect where you sign in, so over a
 * plaintext channel the client refuses settings-sourced values it cannot
 * otherwise protect: pin the provider with `questdb_oidc_builder_issuer`, and
 * pass any client id, scope, audience or groups flag you rely on explicitly.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_allow_insecure_transport(
    questdb_oidc_builder* builder, bool enabled, questdb_error** err_out);
/**
 * Whether `questdb_oidc_auth_sign_in` opens a browser at the verification URL
 * (default `true`).
 *
 * The default spawns a detached child process (`xdg-open` / `open` /
 * `rundll32`) once per sign-in. Spawn failure is ignored, so on a host with no
 * opener this costs nothing -- but set it to `false` on a headless or shared
 * host where launching a browser is not wanted. The device code and URL are
 * still reported through the event handler either way.
 *
 * A binding may narrow this: the Python client defaults to opening a browser
 * except inside a Jupyter kernel, where the reader may be on another machine.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_open_browser(
    questdb_oidc_builder* builder, bool enabled, questdb_error** err_out);
/**
 * Whether `questdb_oidc_auth_sign_in` may prompt at all (default `true`).
 *
 * `false` makes it fail immediately with
 * `QUESTDB_OIDC_ERROR_INTERACTION_REQUIRED` instead of printing a device code
 * nobody will read and polling until the code expires -- what a headless
 * service or a CI job wants.
 *
 * There is deliberately no TTY auto-detection: a missing TTY is not evidence of
 * a missing human (a pipe into `tee`, a supervisor or an IDE that captures
 * stderr and displays it), so refusing on it turned away sign-ins that would
 * have worked. A binding with a stronger signal can pass `false` itself.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_interactive(
    questdb_oidc_builder* builder, bool enabled, questdb_error** err_out);
/**
 * Seconds to wait between device-code polls when the identity provider does
 * not advertise an `interval` of its own (default 5).
 *
 * This is only a fallback. A server-supplied `interval`, and any `Retry-After`
 * the provider sends, both take precedence, and the value is clamped to
 * [5, 1800] seconds -- the latter being the longest a device code may live.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_default_interval_seconds(
    questdb_oidc_builder* builder, uint64_t seconds, questdb_error** err_out);
/**
 * Timeout for each individual HTTP request, in milliseconds (default 30000,
 * maximum 120000).
 *
 * This is NOT a deadline for the sign-in as a whole, which is bounded by the
 * device code's own lifetime: a device flow makes many requests and may run
 * for minutes. It bounds one request -- discovery, the device-authorization
 * call, or a single poll.
 *
 * Note the value is not validated here; an out-of-range one is reported by
 * `questdb_oidc_builder_build`.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_timeout_ms(
    questdb_oidc_builder* builder,
    uint64_t timeout_ms,
    questdb_error** err_out);
/**
 * PEM CA bundle used to verify TLS for BOTH the QuestDB `/settings` discovery
 * request and every identity-provider request. Unset means the platform trust
 * store. The path is read at `questdb_oidc_builder_build` time, not here. No
 * home-directory expansion is performed: a path beginning with `~`, `~/` or
 * `~\\` is rejected; pass an already-expanded absolute path.
 */
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
 *
 * `directory` is used verbatim. Nothing here expands `~` -- a shell does that,
 * a runtime does not -- so a value starting with `~` is REJECTED rather than
 * creating a directory literally named `~` under the working directory and
 * leaving a plaintext refresh token in it. A relative path is accepted but is
 * resolved afresh at every use, so a chdir moves the store; prefer an absolute
 * path. Pass an already-expanded absolute path for `~`-style locations.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_file_token_store(
    questdb_oidc_builder* builder,
    const char* directory,
    size_t directory_len,
    questdb_error** err_out);

/**
 * Explicitly enable plaintext file persistence at
 * the directory named by the `QUESTDB_CLIENT_OIDC_TOKEN_STORE_DIR` environment
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
 *
 * Installing a handler removes the builder's reference to the one it replaces.
 * Auth handles/transports already built with the old handler retain it until
 * their final reference is released; future builds use the replacement. If the
 * builder held the last reference, `release` runs after this function's
 * internal borrow of the builder ends, so it MAY call back into this function
 * on the same builder. One exception to the ordering above follows: if it does,
 * its own registration supersedes the one this call just installed, and the
 * superseded `user_data` is therefore released BEFORE this call returns
 * `true`. Each `release` still runs exactly once, so nothing leaks or is
 * double-freed, but a caller must not read `true` as a promise that the
 * `user_data` it just passed is still installed. Re-registering from a
 * `release` callback is the only way to reach this.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_event_handler(
    questdb_oidc_builder* builder,
    questdb_oidc_event_cb callback,
    void* user_data,
    questdb_oidc_user_data_release_cb release,
    questdb_error** err_out);

/**
 * Install a best-effort persistence diagnostic callback. Ownership and release
 * rules match `questdb_oidc_builder_event_handler`; unlike renderer events,
 * diagnostics may originate on background token-provider threads.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_builder_diagnostic_handler(
    questdb_oidc_builder* builder,
    questdb_oidc_diagnostic_cb callback,
    void* user_data,
    questdb_oidc_user_data_release_cb release,
    questdb_error** err_out);

/**
 * Resolve the configuration and create an auth state.
 *
 * **This call blocks on the network** when the builder came from
 * `questdb_oidc_builder_from_questdb`: it issues the QuestDB `/settings`
 * request here, and may follow it with the identity provider's own discovery
 * document to confirm the advertised endpoints. Each request is bounded by
 * `questdb_oidc_builder_timeout_ms` (default 30s, maximum 120s), so a call can
 * take twice that before returning. Do not call it on a UI thread; a language
 * binding holding a runtime lock should release it around this call, as the
 * Python binding does with the GIL.
 *
 * A builder configured with explicit endpoints performs no I/O here.
 *
 * The builder is reusable; each call creates an independent auth state.
 */
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

/**
 * Permanently stop renderer-event delivery for this auth without closing the
 * provider. Returns after any event callback already in flight has finished.
 * From that callback itself it publishes suppression and returns without
 * waiting for its own frame. From inside a DIFFERENT auth's event callback the
 * drain is bounded and best-effort, because an exact cross-target drain can
 * deadlock two threads against each other's callback gates; suppression remains
 * exact. Idempotent, NULL-tolerant, and callable from any thread. Auths built
 * from the same reusable builder are unaffected.
 *
 * Use this form only when the caller can wait for arbitrary user callback
 * code to return. The caller must not delegate this call to another thread and
 * wait for that thread from inside the callback, because the delegate cannot
 * identify itself as the callback's stack. A finalizer or managed-runtime
 * shutdown hook must use `questdb_oidc_auth_detach_events_nowait` instead.
 */
QUESTDB_CLIENT_API
void questdb_oidc_auth_detach_events(const questdb_oidc_auth* auth);

/**
 * As `questdb_oidc_auth_detach_events`, but never waits for a renderer callback
 * that is already running.
 *
 * Later events are suppressed exactly as with the waiting form; only the "no
 * callback is still running on return" guarantee is given up. Idempotent,
 * NULL-tolerant, and callable from any thread, including from inside a
 * renderer callback. This is the safe form for finalizers, garbage-collection
 * hooks, interpreter shutdown hooks, and other contexts that cannot wait for
 * arbitrary user callback code.
 *
 * Auths built from the same reusable builder are unaffected.
 */
QUESTDB_CLIENT_API
void questdb_oidc_auth_detach_events_nowait(const questdb_oidc_auth* auth);

/**
 * Permanently stop delivering this auth's persistence diagnostics.
 *
 * Returns once no diagnostic callback is running for this auth and no later
 * one can start. Idempotent, NULL-tolerant, and callable from any thread.
 *
 * Called from inside this auth's own diagnostic callback it degrades to
 * suppressing later diagnostics without waiting, because the only invocation
 * it could wait for is the caller's own frame. Called from inside a DIFFERENT
 * auth's callback the wait becomes bounded and best-effort, because blocking
 * there would deadlock two threads against each other's callback gates.
 * Suppression is exact in both cases; only the "no callback is still running"
 * guarantee is downgraded.
 *
 * A binding does not have to prove it is outside a callback before calling
 * this -- a callback that runs managed code can destroy a handle without the
 * user writing such a call.
 *
 * It DOES have to be outside every lock the diagnostic callback itself might
 * acquire. Releasing the binding's global runtime lock is not sufficient
 * evidence of that: the callback runs binding code that can take
 * finer-grained locks -- Python's `logging` handler lock is the worked
 * example -- and a thread that reaches a finalizer may already own one, since
 * it runs wherever a collection happened to fire. A caller that cannot
 * establish this must use `questdb_oidc_auth_detach_diagnostics_nowait`.
 *
 * Most callers do not need either form: `questdb_oidc_auth_close` also ends
 * diagnostics, because a closed auth performs no further token-store writes.
 * These are for an owner that is going away without being able to wait for
 * that -- a binding whose callback enters a managed runtime being torn down (a
 * garbage-collected handle, or an interpreter beginning to shut down) while a
 * background token-provider or transport thread may still hold a clone of this
 * auth and reach a store write.
 *
 * Auths built from the same builder are unaffected and keep delivering.
 */
QUESTDB_CLIENT_API
void questdb_oidc_auth_detach_diagnostics(const questdb_oidc_auth* auth);

/**
 * As `questdb_oidc_auth_detach_diagnostics`, but never waits for a diagnostic
 * callback that is already running.
 *
 * Later diagnostics are suppressed exactly as with the waiting form; only the
 * "no callback is still running on return" guarantee is given up. Idempotent,
 * NULL-tolerant, and callable from any thread, including from inside the
 * callback.
 *
 * This is the form for a finalizer or garbage-collection hook: it runs
 * wherever a collection happened to fire, so it cannot prove which locks the
 * thread already holds, and the waiting form would deadlock against any of
 * them that the callback also needs.
 */
QUESTDB_CLIENT_API
void questdb_oidc_auth_detach_diagnostics_nowait(const questdb_oidc_auth* auth);

QUESTDB_CLIENT_API
void questdb_oidc_auth_free(questdb_oidc_auth* auth);

/**
 * Cancel only the interactive device flow currently running in
 * `questdb_oidc_auth_sign_in`.
 *
 * This is attempt-scoped: the active sign-in returns a
 * `QUESTDB_OIDC_ERROR_CANCELLED` error, but the shared provider remains open,
 * cached credentials are not discarded, and attached senders, readers and
 * pools remain usable. A later sign-in on the same provider can succeed. If no
 * device flow is running, this is an idempotent no-op that does not affect the
 * next sign-in.
 *
 * Safe to call from any thread, including this auth's own event callback and
 * while that callback is waiting behind a sibling built from the same reusable
 * builder. An HTTP request already in flight is not cancelled at the transport
 * layer, so the sign-in stops after that bounded request returns.
 *
 * Use `questdb_oidc_auth_close` instead only to permanently disable the shared
 * provider and every attached transport.
 */
QUESTDB_CLIENT_API
bool questdb_oidc_auth_cancel_sign_in(
    const questdb_oidc_auth* auth, questdb_error** err_out);

/**
 * Permanently close this shared auth state. Cancels a device flow or bundled
 * file-token-store lock wait running on another thread. All cloned handles and
 * attached transports share the closed state. Idempotent. This is distinct from
 * `questdb_oidc_auth_free`, which releases only one handle and does not cancel
 * shared work.
 *
 * Safe to call from any thread, including this auth's own event or persistence
 * diagnostic callback and while that callback is running on another thread.
 * Publishing the close does not wait for the authentication critical section,
 * though it may briefly contend with a waiter registering for cancellation. It
 * ordinarily waits for the running operation to leave the authentication
 * critical section. While this auth's event or diagnostic callback is active
 * it instead returns as soon as close is published, regardless of which thread
 * calls it: a callback may delegate close to a worker and join that worker, so
 * draining there would deadlock just as it would on the callback thread itself.
 * Activity on an independent auth built from the same reusable builder does not
 * skip this auth's drain. Unlike `sign_in`, `token` and `clear`, close is never
 * rejected as callback re-entry.
 *
 * The in-memory credential is dropped on every path, including the
 * skipped-drain one; only the wait is skipped. The persisted entry is
 * left behind either way -- see `questdb_oidc_auth_clear`.
 *
 * Closing is TERMINAL for every attached transport, not merely a state they
 * observe. Closing is monotonic, so each sender, reader and pool built from
 * this auth (or from any `questdb_oidc_auth_clone` handle) fails its next
 * token pull with a non-retryable error: reconnect loops stop rather than
 * retry, a QWP/WebSocket publication store is terminalized with accepted
 * frames still queued, and no replacement auth can be attached to an existing
 * handle. Disk-backed store-and-forward slots are not deleted and stay
 * drainable by a later process, but this one will not send them.
 *
 * Recovery is to build a new auth and rebuild every sender, reader and pool
 * that used the old one. Where that matters, sign in on an auth before
 * attaching it and keep re-authentication on a separate, unattached one.
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
 * prefix written by the library; consumers that can load an older shared
 * library must re-read it before accessing fields beyond that prefix.
 *
 * Token-endpoint diagnostics are untrusted. If an identity provider reflects
 * the submitted device code or refresh token in any non-issued-token string,
 * the library replaces that credential with `[redacted credential]` before it
 * reaches `idp_error`, `idp_error_description`, a renderer, or a formatted
 * error message. Issued `access_token`, `id_token`, and `refresh_token` fields
 * remain byte-for-byte intact so a non-rotating refresh token stays usable.
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
 *
 * Mutually exclusive with static credentials: the opts must not also carry
 * `username`/`password` or `token` (whether set through the config string or
 * through `line_sender_opts_username` and friends). Setting both fails with
 * `questdb_error_config_error`.
 *
 * A flush or connect that needs a fresh credential resolves it BEFORE its
 * first request, and that resolution can wait behind a refresh already running
 * on another thread for up to six times `questdb_oidc_builder_timeout_ms` --
 * three minutes at the 30000 default, twelve at the 120000 maximum. That wait
 * is bounded by the OIDC timeout alone: the sender's `request_timeout` and
 * `retry_timeout` do not cap it, so size `timeout_ms` for the longest stall a
 * flush may absorb. Calling `questdb_oidc_auth_sign_in` before starting the
 * sender avoids the first, longest acquisition entirely.
 */
QUESTDB_CLIENT_API
bool line_sender_opts_oidc_auth(
    line_sender_opts* opts,
    const questdb_oidc_auth* auth,
    questdb_error** err_out);

#ifdef __cplusplus
}
#endif
